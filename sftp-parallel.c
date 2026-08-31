/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library or code is free software; you can redistribute it and/or
 * modify it under the terms of the BSD 2 Clause License.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the BSD 2-Clause License
 * for more details.
 *
 * You should have received a copy of the BSD 2-Clause License along with this
 * code, if not, see https://opensource.org/license/bsd-2-clause.
 *
 */

/* sftp-parallel.c - the orchestrator for parallel SFTP transfers.
 *
 * Owns the fleet: it starts the workers, accepts the files a command wants
 * moved, waits for them to drain, runs the post-transfer verify phase, and
 * tears everything down. The per-worker execution lives in
 * sftp-parallel-worker.c and the health policy in the reporter and watchdog.
 *
 * Nothing in this subsystem calls fatal() on an I/O failure. sftp-client.c's
 * send and receive helpers return -1 and mark the connection dead instead,
 * because a fatal in one worker would take down the whole fleet. A dead
 * connection travels back up to the worker loop, which requeues the unit it
 * was holding and exits so the reporter can replace it. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"
#include "utf8.h"
#include "progressmeter.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_watchdog_pause_until_ms */
#include "sftp-hpn-verify.h"		/* sftp_hpn_verify_repair[_resolve] */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-hpn-client.h"	/* deferred dir attrs */
#include "sftp-parallel-internal.h"

extern int showprogress;

/* Single definition; declared extern in sftp-parallel-internal.h. */
volatile sig_atomic_t parallel_user_abort_flag;

/* How many objects the work queue can hold. Without bundling an object is one
 * file, so the depth is just enough units to keep every worker's batch loop
 * fed. With bundling a single queued object can carry thousands of files, so
 * counting files would either starve the workers or let the queue grow without
 * bound; the depth is derived from how many files fit in a bundle instead. */
static size_t
work_queue_depth(const struct sftp_parallel_config *cfg)
{
	size_t base, per_bundle, depth;
	uint64_t target;

	base = (size_t)cfg->num_streams * UPLOAD_BATCH_SIZE * 4 +
	    UPLOAD_BATCH_SIZE;
	if (!cfg->use_bundle)
		return base;

	/* get the size of our bundle */
	if (cfg->bundle_size > 0)
		target = cfg->bundle_size;
	else
		target = BUNDLE_TARGET_BYTES_DEFAULT;

	/* per bundle = estimate of number of files in a bundle */
	per_bundle = (size_t)(target / BUNDLE_QUEUE_FILE_HINT);
	if (per_bundle < UPLOAD_BATCH_SIZE)
		per_bundle = UPLOAD_BATCH_SIZE;

	/* Two rounds of full bundles per worker, so the walker can stay a round
	 * ahead while every worker is assembling, plus one batch of slack. */
	depth = (size_t)cfg->num_streams * per_bundle * 2 +
	    UPLOAD_BATCH_SIZE;
	if (depth < base)
		depth = base;
	if (depth > WORK_QUEUE_DEPTH_MAX)
		depth = WORK_QUEUE_DEPTH_MAX;
	return depth;
}

/* Ceiling on outstanding FILES, for a producer that enumerates far faster
 * than the fleet drains (the discover-tree walk). Counted in files rather
 * than queued objects because the queue is heterogeneous: a bundle is one
 * object carrying thousands of files, while a file too large to bundle is one
 * object carrying one. Only a file count is meaningful for both.
 *
 * Sized from the MAXIMUM a bundle can hold. Real packing varies with the workload.
 * The byte target, the member cap, and the download path-list limit each
 * bind in different cases. A ceiling derived from any one of them starves the
 * others. Against the hard maximum every worker is guaranteed its two
 * bundles whatever the packing, so the ceiling bounds memory without ever
 * being the thing that limits throughput.
 *
 * Without bundling a queued object is already a single file, so the queue's
 * own depth is the same quantity and is used as-is.
 *
 * This is what bounds peak unit memory: each outstanding file is a work unit
 * plus its two path strings, so the ceiling here times that cost is the most
 * the submit side can hold at once. Note: this can get large.
 * At -j8 this is 8 x 2 x 8192 = 131,072 outstanding files, and
 * at -j16, 262,144. Since each is a struct sftp_work_unit plus its
 * two path strings, that's a memory ceiling in the hundreds of megabytes
 * for a deep tree.
 *
 * TODO: the path strings, not the struct, are what this ceiling multiplies.
 * struct sftp_work_unit is 160 bytes and carries two full paths of about 100
 * bytes each, so factoring them into a shared directory prefix plus a
 * per-unit relative path would cut the peak by most of it. The verify prefix
 * pool already does exactly this for parked verify items. Note that streaming
 * the submit instead of queueing was tried and reverted: it collided on the
 * control connection under parallel timing. */
static size_t
outstanding_file_cap(const struct sftp_parallel_config *cfg)
{
	if (!cfg->use_bundle)
		return work_queue_depth(cfg);

	/* Two bundles per worker: one in flight, one being assembled. */
	return (size_t)cfg->num_streams * 2 * BUNDLE_BATCH_MAX_FILES;
}

/* Walker-side failure recorder: bumps the aggregate counter and adds
 * "path: error" to the failed-paths list in one shot. `err` may be
 * NULL when no errno-style message is available (e.g. depth limit,
 * "not a directory"). Single-call helper because every walker
 * skip-on-error site does both - bump + list. */
void
sftp_parallel_walker_record_failure(struct sftp_parallel *fleet, const char *path,
    const char *err)
{
	char buf[PATH_MAX + 256];

	/* The walker bumps this on the main thread while get_stats reads it
	 * from another, so the access is atomic even though nothing contends
	 * for it. Relaxed: it is a counter, ordered against nothing. */
	__atomic_fetch_add(&fleet->walker_failures, 1, __ATOMIC_RELAXED);
	if (path == NULL)
		path = "(unknown path)";
	if (err != NULL && *err != '\0')
		snprintf(buf, sizeof(buf), "%s: %s", path, err);
	else
		snprintf(buf, sizeof(buf), "%s", path);
	hpn_strlist_append(&fleet->failed_paths, buf);
}

/* Publish the walker's current phase (enum sftp_walker_phase). Public so the
 * walker in sftp-parallel-walk.c can mark itself blocked/enumerating without
 * seeing struct sftp_parallel's internals. Relaxed atomic; observability only. */
void
sftp_parallel_set_walker_phase(struct sftp_parallel *fleet, int phase)
{
	if (fleet != NULL)
		__atomic_store_n(&fleet->walker_phase, phase, __ATOMIC_RELAXED);
}

/* Bounded thread-safe string list - see comment on struct hpn_strlist. */
void
hpn_strlist_init(struct hpn_strlist *list, size_t cap)
{
	pthread_mutex_init(&list->mu, NULL);
	list->cap   = cap;
	list->used  = 0;
	list->total = 0;
	if (cap > 0)
		list->items = xcalloc(cap, sizeof(*list->items));
	else
		list->items = NULL;
}

/* free the string list used to hold the failures */
void
hpn_strlist_free(struct hpn_strlist *list)
{
	if (list->items != NULL) {
		for (size_t i = 0; i < list->used; i++)
			free(list->items[i]);
		free(list->items);
		list->items = NULL;
	}
	pthread_mutex_destroy(&list->mu);
	list->used = 0;
	list->cap  = 0;
}

/* Append `entry` to the list. Always bumps `total`; only allocates a
 * new entry if `used < cap`. Silently drops the string contents when
 * over cap so memory stays bounded; the count is preserved so the
 * user knows how many were dropped. */
void
hpn_strlist_append(struct hpn_strlist *list, const char *entry)
{
	if (list == NULL || entry == NULL)
		return;
	pthread_mutex_lock(&list->mu);
	list->total++;
	if (list->used < list->cap)
		list->items[list->used++] = xstrdup(entry);
	pthread_mutex_unlock(&list->mu);
}

/* Drain the list. Returns the number of appends seen since the last drain,
 * and, when out is non-NULL, transfers ownership of the held strings to the
 * caller via *out and *out_used; the caller frees each string and the array.
 * Passing NULL for out frees them instead.
 *
 * The list is reset to empty and stays usable, and that reset includes the
 * total, so a second drain reports only what arrived after the first. */
uint64_t
hpn_strlist_drain(struct hpn_strlist *list, char ***out, size_t *out_used)
{
	uint64_t total;
	pthread_mutex_lock(&list->mu);
	total = list->total;
	if (out != NULL && out_used != NULL) {
		*out_used = list->used;
		if (list->used > 0) {
			*out = xcalloc(list->used, sizeof(**out));
			for (size_t i = 0; i < list->used; i++)
				(*out)[i] = list->items[i];   /* transfer ownership */
		} else {
			*out = NULL;
		}
	} else {
		/* Nobody is taking the strings, so free them here rather
		 * than losing them in the reset below. */
		for (size_t i = 0; i < list->used; i++)
			free(list->items[i]);
	}
	/* Reset the list so subsequent appends start fresh. */
	if (list->items != NULL)
		memset(list->items, 0, list->cap * sizeof(*list->items));
	list->used  = 0;
	list->total = 0;
	pthread_mutex_unlock(&list->mu);
	return total;
}

/* ---------- Fleet lifecycle: start, submit, wait, abort, stop ---------- */

/* Builds a fleet and starts it running. Validates the config, takes its own
 * copy of anything the caller might not keep alive, resolves the ssh_config
 * policies the fleet needs at runtime, sizes the work queue, and spawns the
 * workers and the reporter.
 *
 * Workers are spawned in parallel so their SSH handshakes overlap, but only
 * max_auth_concurrent of them may be unauthenticated at once, which keeps
 * the fleet under the server's MaxStartups limit. Every spawn thread is
 * joined before this returns, because they share stack locals from this
 * frame.
 *
 * Returns NULL on failure with errno set for a bad config; any later failure
 * tears down whatever was built through sftp_parallel_stop. */
struct sftp_parallel *
sftp_parallel_start(const struct sftp_parallel_config *cfg)
{
	if (cfg == NULL || cfg->host == NULL || cfg->num_streams < 1 ||
	    cfg->num_streams > SFTP_PARALLEL_MAX_WORKERS) {
		errno = EINVAL;
		return NULL;
	}

	struct sftp_parallel *fleet = xcalloc(1, sizeof(*fleet));

	/* Fresh fleet: clear the process-wide user-abort mirror left by a
	 * previous orchestrator's interrupt (the post-interrupt rebuild). */
	parallel_user_abort_flag = 0;

	fleet->cfg = *cfg;
	/* cfg.port may point to a stack buffer in the caller that is only
	 * valid until the enclosing scope exits. Copy it into fleet->cfg_port_buf
	 * so the orchestrator owns the string for its entire lifetime. */
	if (cfg->port && cfg->port[0]) {
		strlcpy(fleet->cfg_port_buf, cfg->port, sizeof(fleet->cfg_port_buf));
		fleet->cfg.port = fleet->cfg_port_buf;
	}

	/* instantiate mutexs and the like */
	pthread_mutex_init(&fleet->pending_mu, NULL);
	pthread_cond_init(&fleet->pending_cv, NULL);
	pthread_mutex_init(&fleet->workers_mu, NULL);
	pthread_mutex_init(&fleet->verify_pending_mu, NULL);
	pthread_mutex_init(&fleet->retry_overflow_mu, NULL);

	/* Parked-verify memory gate: fleet-wide budget on parked-path bytes.
	 * When the parked set crosses this the submitter runs a verify wave
	 * (parallel_verify_maybe_wave). 64 MiB, validated across a range of
	 * values as a reasonable batching-vs-RAM balance. Basically, if we are
	 * doing verification then do it occasionally during the transfer.*/
	fleet->verify_park_budget = 64 * 1024 * 1024;

	fleet->session_start_ms = monotime_ms();

	/* Fleet-abort zero-progress window, resolved from ssh_config
	 * HPNStallAbortTimeout (default 60 s). The abort also requires no worker
	 * heartbeating and FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams
	 * unproductive respawns (see parallel_watchdog_sync_check); this knob
	 * only sizes the window. 0 disables the abort entirely. */
	fleet->noprogress_abort_s = cfg->stall_abort_timeout;
	if (fleet->noprogress_abort_s < 0)
		fleet->noprogress_abort_s = 0;

	/* Enable tail redistribution (cooperative yield of a confirmed-lagging
	 * endgame holder) from HPNTailRedistribute. Default ON.
	 * off leaves the tail detector as telemetry only. */
	fleet->tail_redistribute = cfg->tail_redistribute;

	/* Auto-repair: on a post-transfer verify mismatch, re-transfer the
	 * bad ranges and re-verify, bounded by a per-range attempt cap. ON by
	 * default; disabled by the -X VerifyRepair=no CLI token
	 * (cfg->no_verify_repair). The attempt cap is fixed at 3. */
	sftp_hpn_verify_repair_resolve(cfg->no_verify_repair,
	    &fleet->verify_repair_enabled, &fleet->verify_repair_attempts);
	fleet->last_worker_exit_code = -1;	/* no worker reaped yet */

	/* Born-dead 0-bytes kill threshold. This is when a worker starts but there
	 * is no data transmission for whatever reason. This can happen in lossy
	 * environments. RTT-derived once the path RTT is
	 * registered (sftp_parallel_set_path_rtt); BORN_DEAD_KILL_SEC until then. */
	fleet->born_dead_sec = BORN_DEAD_KILL_SEC;
	fleet->born_dead_stuck_offset = -1;	/* 0 is a valid range_offset */

	/* List of failures. Cap chosen so the worst-case allocation is
	 * bounded but the "show me what failed" list is still useful for moderately
	 * broken transfers. Really broken ones could potentially spam the interface.
	 * TODO: This might need to be revisited. HPN_FAILED_PATHS_MAX x ~256 bytes
	 * typical = ~25 KiB at the default cap. */
	hpn_strlist_init(&fleet->failed_paths, HPN_FAILED_PATHS_MAX);
	hpn_strlist_init(&fleet->verify_failed_paths, HPN_FAILED_PATHS_MAX);

	/* Suppress per-file progress in the workers; the orchestrator drives
	 * aggregate progress when asked, through sftp_parallel_progress_*.
	 * Saved before anything below can goto fail, because sftp_parallel_stop
	 * restores this unconditionally and would otherwise restore a zero that
	 * was never the user's setting. */
	fleet->saved_showprogress = showprogress;
	showprogress = 0;

	/* Workqueue, sized for cfg->num_streams. Respawned workers reuse the
	 * same queue, so capacity is set once at startup. */
	fleet->outstanding_cap = (uint64_t)outstanding_file_cap(cfg);
	fleet->q = sftp_workqueue_new(work_queue_depth(cfg));
	if (fleet->q == NULL) {
		error_f("workqueue allocation failed");
		goto fail;
	}

	/* Spawn workers in parallel to overlap SSH handshakes, but cap
	 * the number of simultaneous unauthenticated connections to stay
	 * under the server's MaxStartups limit (default 10:30:100).
	 * In its own code block to limit namespace/declaration scope. */
	{
		int n = cfg->num_streams;
		int max_in_flight = cfg->max_auth_concurrent > 0
		    ? cfg->max_auth_concurrent : 8;
		int               auth_in_flight = 0;
		int               started = 0;
		pthread_mutex_t   auth_mu;
		pthread_cond_t    auth_cv;
		struct spawn_ctx  sctx[SFTP_PARALLEL_MAX_WORKERS];
		pthread_t         stids[SFTP_PARALLEL_MAX_WORKERS];
		int               failed = 0;

		pthread_mutex_init(&auth_mu, NULL);
		pthread_cond_init(&auth_cv, NULL);

		for (int i = 0; i < n; i++) {
			sctx[i].fleet              = fleet;
			sctx[i].auth_mu        = &auth_mu;
			sctx[i].auth_cv        = &auth_cv;
			sctx[i].auth_in_flight = &auth_in_flight;
			sctx[i].started        = &started;
			sctx[i].total          = n;
			sctx[i].max_in_flight  = max_in_flight;
			sctx[i].succeeded      = 0;
			if (pthread_create(&stids[i], NULL,
			    parallel_respawn_spawn_thread, &sctx[i]) != 0) {
				error_ft("spawn thread %d failed", i);
				/* Join threads already launched. */
				for (int j = 0; j < i; j++)
					pthread_join(stids[j], NULL);
				pthread_mutex_destroy(&auth_mu);
				pthread_cond_destroy(&auth_cv);
				goto fail;
			}
		}
		for (int i = 0; i < n; i++) {
			pthread_join(stids[i], NULL);
			if (!sctx[i].succeeded) {
				error_ft("worker %d setup failed", i);
				failed = 1;
			}
		}
		pthread_mutex_destroy(&auth_mu);
		pthread_cond_destroy(&auth_cv);
		if (failed)
			goto fail;
	}

	/* Reporter - best-effort. */
	if (pthread_create(&fleet->reporter_tid, NULL, parallel_reporter_thread, fleet) == 0)
		fleet->reporter_started = 1;

	fleet->started = 1;
	return fleet;

 fail:
	sftp_parallel_stop(fleet);
	return NULL;
}

/* Blocks until every outstanding unit has been retired, or until the fleet
 * aborts. The abort test is part of the predicate because an aborting fleet
 * stops retiring units, so waiting for pending to reach zero would hang. */
static void
parallel_drain_pending(struct sftp_parallel *fleet)
{
	pthread_mutex_lock(&fleet->pending_mu);
	while (fleet->pending > 0 && !fleet->abort_flag)
		pthread_cond_wait(&fleet->pending_cv, &fleet->pending_mu);
	pthread_mutex_unlock(&fleet->pending_mu);
}

/* Sets up the verify-phase meter before the units are submitted. The submit
 * blocks and is most of the phase, so a meter started after it would cover
 * only the tail while the finished transfer bar sat at 100% looking hung.
 *
 * Sized in work bytes: every transferred byte is hashed on both ends, so the
 * total is twice what moved and both legs advance it. Does nothing unless
 * the user asked for progress and something actually moved. */
static void
verify_phase_start_meter(struct sftp_parallel *fleet, int vn)
{
	uint64_t moved = 0;
	off_t vtotal;

	parallel_stats_snapshot(fleet, &moved, NULL, NULL);
	if (moved > fleet->progress_bytes_baseline)
		vtotal = (off_t)(moved - fleet->progress_bytes_baseline);
	else
		vtotal = 0;
	if (fleet->progress_meter_started)
		sftp_parallel_progress_stop(fleet);
	/* Suppress in frame mode: stdout is the binary status channel there,
	 * so this text would corrupt frames. */
	if (fleet->cfg.print_flag != SFTP_QUIET && !hpn_pm_active())
		mprintf("Verifying %d file(s)...\n", vn);
	if (!fleet->saved_showprogress || vtotal <= 0)
		return;

	/* Only the counters are zeroed here. The unit total is published by
	 * parallel_verify_phase_submit once it knows it: vn counts parked
	 * items, and a range-split file is one item but many verify units. */
	fleet->verify_done_units = 0;
	fleet->verify_done_bytes = 0;
	fleet->verify_meter_total = 2 * vtotal;
	fleet->aggregate_progress_counter = 0;
	/* WORK kind in the work-byte domain: the core marks it not a file and
	 * raises the verify phase flag. */
	hpn_meter_start(&fleet->meter, fleet, HPN_METER_WORK,
	    HPN_METER_DOM_WORK, "verify", 2 * vtotal,
	    &fleet->aggregate_progress_counter, 0);
	hpn_meter_bind_display(&fleet->meter, fleet, fleet->reporter_tid);
	/* verify_phase_active before meter_started: a reporter tick between the
	 * two would take the transfer branch against the verify meter's
	 * freshly-zeroed counter, and the ratchet would pin that bogus publish
	 * for the whole phase. */
	fleet->verify_phase_active = 1;
	fleet->progress_meter_started = 1;
}

/* Waits for a command's work to finish and closes it out.
 *
 * Entering wait is the universal "no more units are coming" point, for
 * directory walks and direct put/get alike, so it flushes the tail bundle
 * and publishes walker-phase DONE before blocking. Then it drains the
 * transfer units, runs the post-transfer verify phase over everything that
 * parked a tracker, drains those units too, and applies the directory
 * attributes that were deferred until nothing was still writing into those
 * directories.
 *
 * An abort skips the verify phase; stop cleans up whatever was parked. The
 * caller passes the control connection because the deferred attributes are
 * applied over it, not over a worker's. */
void
sftp_parallel_wait(struct sftp_parallel *fleet, struct sftp_conn *conn)
{
	if (fleet == NULL) return;

	/* Push the tail before waiting.
	 * Entering wait is the universal "done submitting" point for every
	 * command - directory walks and direct (non-walker) put/get alike -
	 * so the tail bundle can't be left stranded in the accumulator. */
	parallel_bundle_flush_pending(fleet);

	/* Entering wait is the "no more units coming" signal, so publish
	 * walker-phase DONE here. A directory walk already set it; direct
	 * put/get never does, and without it the endgame machinery (range
	 * split, straggler reaper) stays gated off for the whole transfer.
	 * Demotion back to SUBMIT is the submit path's business. */
	__atomic_store_n(&fleet->walker_phase, SFTP_WKP_DONE, __ATOMIC_RELAXED);
	parallel_drain_pending(fleet);

	/* Transfers drained: run the post-transfer verify phase. Every
	 * completed verified file (whole-file or range-split) parked its tracker
	 * at completion; submit them now as SFTP_OP_VERIFY units so the idle
	 * workers verify them in parallel on their own conns - off the transfer
	 * path - then wait for those units to drain before returning. */
	if (!fleet->abort_flag) {
		/* All verify units: range-split trackers (verify_pending) plus
		 * whole-file items (verify_whole_pending). Whole-file transfers
		 * park only in the latter, so gating the meter on verify_pending_n
		 * alone left the common case with no verify progress at all.
		 *
		 * Read without verify_pending_mu, which is safe only because a
		 * unit parks its tracker before it decrements pending: once
		 * pending reaches zero above, every park has finished and no
		 * worker can still be writing these. */
		int vn = fleet->verify_pending_n + fleet->verify_whole_pending_n;

		if (vn > 0)
			verify_phase_start_meter(fleet, vn);

		(void)parallel_verify_phase_submit(fleet);
		parallel_drain_pending(fleet);
		fleet->verify_phase_active = 0;
		/* Auto-repair now runs inline inside each verify unit (the
		 * worker splices the bad sub-chunks of its range and re-verifies
		 * on its own conn), so there is no separate repair phase here. */
	}

	/* Apply the deferred directory attributes now that every
	 * unit has drained (shared machinery with the serial walks). */
	if (fleet->dirattrs != NULL) {
		if (conn != NULL)
			sftp_hpn_dirattrs_apply(conn, fleet->dirattrs);
		else if (fleet->dirattrs->n > 0)
			error_f("no control connection: %d directory "
			    "attribute(s) not applied.",
			    fleet->dirattrs->n);
		sftp_hpn_dirattrs_free(fleet->dirattrs);
		free(fleet->dirattrs);
		fleet->dirattrs = NULL;
	}
}

/* Verify wave - this is the mid transfer verification. Hard pause + full drain run
 * mid-transfer to bound the parked-path memory: pause the in-flight transfers, drain
 * the entire parked set through the verify phase, wait for it, then reset the
 * prefix pool. */
static void
parallel_verify_wave(struct sftp_parallel *fleet)
{
	parallel_bundle_flush_pending(fleet);
	/* Pause: drain in-flight transfers (no new units arrive - the walker
	 * is blocked in this call). */
	parallel_drain_pending(fleet);
	if (fleet->abort_flag)
		return;
	debug("verify wave: draining parked set (%llu bytes)",
	    (unsigned long long)fleet->verify_parked_bytes);
	/* Drain the parked set into verify units (resets verify_parked_bytes),
	 * then wait for those units to finish. */
	(void)parallel_verify_phase_submit(fleet);
	parallel_drain_pending(fleet);
	/* Every parked item is now verified + freed, so nothing references the
	 * prefix pool indices: free the pool */
	parallel_verify_prefix_pool_reset(fleet);
}

/* Trigger check, called by the submitter after each unit (see the tail of
 * sftp_parallel_submit_upload / _download). Runs a verify wave when the parked
 * set is over its byte budget, or the prefix pool nears its INT16_MAX cap
 * (wave a little early so dirs keep factoring rather than degrading to full
 * paths). No-op until something is parked. */
void
parallel_verify_maybe_wave(struct sftp_parallel *fleet)
{
	int over;

	if (fleet == NULL)
		return;
	pthread_mutex_lock(&fleet->verify_pending_mu);
	over = (fleet->verify_park_budget > 0 &&
	    fleet->verify_parked_bytes >= fleet->verify_park_budget) ||
	    (fleet->verify_prefixes_n >= INT16_MAX - 256);
	pthread_mutex_unlock(&fleet->verify_pending_mu);
	if (over)
		parallel_verify_wave(fleet);
}

/* Aborts the transfer and makes every worker notice quickly.
 *
 * Setting the flag is not enough on its own: a worker blocked in a read or
 * write on its SSH socket will not look at it until the server drops the
 * connection, which can take minutes. So this closes each worker's pipe fds
 * and signals its ssh child, which turns those blocked syscalls into
 * immediate failures. The worker then unwinds, sees the flag at the top of
 * its loop, and exits within milliseconds, which is what lets stop's joins
 * return promptly.
 *
 * In-flight spawn attempts are signalled too, since a half-built worker has
 * no thread to notice anything yet. */
void
sftp_parallel_abort(struct sftp_parallel *fleet)
{
	if (fleet == NULL) return;
	fleet->abort_flag = 1;
	/* Stop the meter before anything else: with the fleet dying, any
	 * further redraw is a stale frame with a garbage rate. */
	sftp_parallel_progress_stop(fleet);
	if (fleet->q)
		sftp_workqueue_shutdown(fleet->q);

	/* Set each fd to -1 after closing so parallel_respawn_teardown_ssh,
	 * which runs later from sftp_parallel_stop, skips these slots rather
	 * than double-closing a number the kernel may have reused. */
	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		if (worker == NULL)
			continue;
		if (worker->fd_in >= 0) {
			(void)close(worker->fd_in);
			worker->fd_in = -1;
		}
		if (worker->fd_out >= 0) {
			(void)close(worker->fd_out);
			worker->fd_out = -1;
		}
		/* A close does not wake a thread already blocked in writev on
		 * a full pipe: Linux pins the struct file under the in-flight
		 * syscall, so the worker hangs there until the ssh child dies
		 * on its own, holding stop's join hostage. Killing the child
		 * breaks the pipe and the write fails at once. */
		if (worker->ssh_pid > 0)
			(void)kill(worker->ssh_pid, SIGTERM);
	}
	/* Also SIGTERM any current spawn attempts. The spawner's blocked
	 * sftp_init fails within ms of the child dying. Its post-register
	 * flag re-check covers the race where a spawn registers after this sweep. */
	for (int i = 0; i < fleet->n_spawning; i++) {
		if (fleet->spawning_pids[i] > 0)
			(void)kill(fleet->spawning_pids[i], SIGTERM);
	}
	pthread_mutex_unlock(&fleet->workers_mu);

	/* Wake anyone parked in parallel_drain_pending: units stop retiring
	 * once the fleet is aborting, so the count will never reach zero. */
	pthread_mutex_lock(&fleet->pending_mu);
	pthread_cond_broadcast(&fleet->pending_cv);
	pthread_mutex_unlock(&fleet->pending_mu);
}

/* Point the fleet at the caller's interrupt flag. The reporter polls it
 * once per tick (~200 ms) and calls sftp_parallel_abort when it goes
 * non-zero, so a Ctrl-C wakes sftp_parallel_wait promptly instead of
 * waiting for every in-flight unit to finish naturally. This indirection
 * exists because abort takes locks and cannot run in handler context. */
void
sftp_parallel_set_interrupt_flag(struct sftp_parallel *fleet,
    _Atomic sig_atomic_t *flag)
{
	if (fleet != NULL)
		fleet->ext_interrupt_flag = flag;
}

/* Record the path RTT and size the born-dead kill threshold from it.
 * The estimate also lets the watchdog compute a BDP-sized warmup budget,
 * so a freshly respawned worker in slow-start is not reaped
 * before it has had a chance to ramp. It is an application-level round
 * trip so this is in milliseconds even thought the unit is in micro. */
void
sftp_parallel_set_path_rtt(struct sftp_parallel *fleet, uint64_t rtt_us)
{
	if (fleet == NULL)
		return;
	fleet->path_rtt_us = rtt_us;

	/* RTT-dependent born-dead threshold: ~100 round-trips, i.e. rtt_ms/10
	 * seconds (rtt_us/10000), with the mantissa dropped, floored at
	 * BORN_DEAD_KILL_SEC (5s, RTT <= ~50ms) and capped at BORN_DEAD_SEC_MAX
	 * (40s, RTT >= ~400ms). A transient backend stall takes ~O(RTT) to
	 * clear, so the kill threshold must scale with RTT or it over-fires on
	 * high-RTT paths (see the BORN_DEAD_* comment). */
	if (rtt_us > 0) {
		int v = (int)(rtt_us / 10000ULL);
		if (v < BORN_DEAD_KILL_SEC)
			v = BORN_DEAD_KILL_SEC;
		if (v > BORN_DEAD_SEC_MAX)
			v = BORN_DEAD_SEC_MAX;
		fleet->born_dead_sec = v;
	}
}

/* Tear down the fleet and free it. The order is the point: shut the queue
 * so workers stop pulling, join the reporter so nothing reaps behind us,
 * drain the respawn threads, then kill the worker ssh children and join
 * their threads. Work that never ran is drained and finalized, and every
 * buffer the fleet owns is freed. fleet struct is invalid once this returns. */
void
sftp_parallel_stop(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return;

	fleet->stopped = 1;

	if (fleet->q)
		sftp_workqueue_shutdown(fleet->q);

	/* Join the reporter BEFORE touching the workers. Otherwise
	 * we might end up having a worker getting freed out of sync leading to
	 * a use after free. */
	if (fleet->reporter_started)
		pthread_join(fleet->reporter_tid, NULL);

	/* Drain detached respawn threads before touching fleet->workers[] or
	 * freeing fleet: they hold fleet across a ~2s sleep and would wake to freed
	 * memory. With the reporter joined no new ones start, and pending ones
	 * bail on fleet->stopped, so this loop is bounded. */
	pthread_mutex_lock(&fleet->workers_mu);

	/* SIGKILL in-flight spawn attempts so the wait below resolves in
	 * milliseconds instead of a connect timeout. KILL, not TERM: ssh
	 * catches TERM and shuts down in an orderly way, which can itself
	 * block on the very stall we are escaping. */
	for (int i = 0; i < fleet->n_spawning; i++) {
		if (fleet->spawning_pids[i] > 0)
			(void)kill(fleet->spawning_pids[i], SIGKILL);
	}
	while (fleet->pending_respawns > 0) {
		pthread_mutex_unlock(&fleet->workers_mu);
		struct timespec drain_ts = { 0, 50 * 1000 * 1000 };
		nanosleep(&drain_ts, NULL);
		pthread_mutex_lock(&fleet->workers_mu);
	}
	pthread_mutex_unlock(&fleet->workers_mu);

	if (fleet->workers) {
		/* Same reasoning for worker ssh children that survived the
		 * abort's SIGTERM: one was observed alive a minute later while
		 * its worker sat in pipe_write and this join waited behind it.
		 * KILL breaks the pipe, the write fails, the worker unwinds. */
		pthread_mutex_lock(&fleet->workers_mu);
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			if (worker != NULL && worker->ssh_pid > 0)
				(void)kill(worker->ssh_pid, SIGKILL);
		}
		pthread_mutex_unlock(&fleet->workers_mu);

		/* Join any worker threads the reporter had not already reaped. */
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			if (worker != NULL && worker->started)
				pthread_join(worker->tid, NULL);
		}
	}

	/* Drain work units an abort left undispatched. Each one owes its
	 * tracker a finalize and owns its path strings, and without this sweep
	 * both leak on every abort; leaked paths can be sensitive.
	 *
	 * This runs only at terminal stop, after every worker and the reporter
	 * have joined, so nothing pops or requeues alongside it and the fleet's
	 * pending count is never read again. */
	if (fleet->q) {
		void *item;
		while (sftp_workqueue_drain(fleet->q, &item) == 0) {
			struct sftp_work_unit *work_unit = item;
			(void)parallel_unit_tracker_finalize(work_unit->range_tracker, 1, NULL);
			parallel_unit_free(work_unit);
		}
	}

	if (fleet->workers) {
		/* Everything still in fleet->workers is ours now. */
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			if (worker == NULL) continue;
			if (worker->conn) {
				sftp_free(worker->conn);
				worker->conn = NULL;
			}
			parallel_respawn_teardown_ssh(worker);
			pthread_mutex_destroy(&worker->mu);
			free(worker);
		}
		free(fleet->workers);
		fleet->workers = NULL;
		fleet->num_workers = 0;
		fleet->workers_cap = 0;
	}

	if (fleet->q) {
		sftp_workqueue_free(fleet->q);
		fleet->q = NULL;
	}

	/* Restore the user's progress preference. */
	showprogress = fleet->saved_showprogress;

	/* Bundle accumulator: normally drained by parallel_bundle_flush_pending
	 * at wait. Free any leftover (e.g. aborted before wait) so the member
	 * units and the array don't leak. */
	for (int i = 0; i < fleet->bundle_pending_n; i++)
		parallel_unit_free(fleet->bundle_pending[i]);
	free(fleet->bundle_pending);
	fleet->bundle_pending = NULL;

	/* Verify-pending: range trackers + whole-files parked at completion
	 * but never submitted as verify units (e.g. aborted before verify
	 * phase). Free both lists so neither leaks. */
	for (int i = 0; i < fleet->verify_pending_n; i++)
		parallel_verify_tracker_free(fleet->verify_pending[i]);
	free(fleet->verify_pending);
	fleet->verify_pending = NULL;
	for (int i = 0; i < fleet->verify_whole_pending_n; i++)
		free(fleet->verify_whole_pending[i]);	/* single block */
	free(fleet->verify_whole_pending);
	fleet->verify_whole_pending = NULL;

	/* Path-factoring prefix pool: the registered directory prefixes. */
	for (int i = 0; i < fleet->verify_prefixes_n; i++)
		free(fleet->verify_prefixes[i]);
	free(fleet->verify_prefixes);
	fleet->verify_prefixes = NULL;

	/* Deferred directory attributes: wait applies and frees these, so a
	 * non-NULL list here means the transfer ended before it got there
	 * (abort, or a failed start). */
	if (fleet->dirattrs != NULL) {
		sftp_hpn_dirattrs_free(fleet->dirattrs);
		free(fleet->dirattrs);
		fleet->dirattrs = NULL;
	}

	/* Worker re-queue overflow: units parked here when a worker hit a full
	 * queue, never drained back (abort/shutdown before the reporter moved
	 * them). Threads have joined by now, so free without locking concerns. */
	parallel_retry_overflow_free(fleet);
	pthread_mutex_destroy(&fleet->verify_pending_mu);
	pthread_mutex_destroy(&fleet->retry_overflow_mu);
	pthread_mutex_destroy(&fleet->pending_mu);
	pthread_cond_destroy(&fleet->pending_cv);
	pthread_mutex_destroy(&fleet->workers_mu);
	hpn_strlist_free(&fleet->failed_paths);
	hpn_strlist_free(&fleet->verify_failed_paths);
	free(fleet);
}

/* Recursive worker for sftp_parallel_scan_upload_total: add src to the
 * running byte and file totals, descending into directories. Regular
 * files only, and the lstat means symlinks are skipped rather than
 * followed. Best effort: a path it cannot stat or a directory it cannot
 * open is left out of the total rather than reported, so on a tree with
 * unreadable directories the meter is sized short and finishes early. */
static void
scan_upload_recursive(const char *src, off_t *bytes_out,
    uint64_t *files_out)
{
	struct stat sb;
	DIR *dirp;
	struct dirent *dp;
	char *child = NULL;

	if (lstat(src, &sb) == -1)
		return;
	if (S_ISREG(sb.st_mode)) {
		*bytes_out += sb.st_size;
		(*files_out)++;
		return;
	}
	if (!S_ISDIR(sb.st_mode))
		return;
	if ((dirp = opendir(src)) == NULL)
		return;
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;
		free(child);
		xasprintf(&child, "%s/%s", src, dp->d_name);
		scan_upload_recursive(child, bytes_out, files_out);
	}
	free(child);
	closedir(dirp);
}

/* Total bytes of the regular files under a local path, and their count
 * via file_count_out when it is non-NULL. Callers use this to size the
 * progress meter before an upload starts, so it is deliberately best
 * effort: anything unreadable is omitted rather than treated as an
 * error. */
off_t
sftp_parallel_scan_upload_total(const char *src, uint64_t *file_count_out)
{
	off_t bytes = 0;
	uint64_t files = 0;

	scan_upload_recursive(src, &bytes, &files);
	if (file_count_out != NULL)
		*file_count_out = files;
	return bytes;
}

/* Record the scan-time total file count for the progress frames/meter. */
void
sftp_parallel_set_file_total(struct sftp_parallel *fleet, uint64_t total)
{
	if (fleet == NULL)
		return;
	__atomic_store_n(&fleet->files_total, total, __ATOMIC_RELAXED);
}

/* How many files the walker has submitted so far, for the END frame the
 * status relay publishes at the close of a run. Narrows to u_int because
 * the frame API is u_int-typed; the counter is per file, so the truncation
 * point is four billion files.
 *
 * A zero return means either no files or no fleet, which the value cannot
 * distinguish. That is fine for the one caller, which has already used the
 * fleet by the time it asks; a caller that cannot make that assumption has
 * to know whether it holds a fleet before reading this. */
u_int
sftp_parallel_files_submitted(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return (u_int)__atomic_load_n(&fleet->files_submitted,
	    __ATOMIC_RELAXED);
}

/* The scan-time file total, against which files_submitted is the progress.
 * Same u_int narrowing, and the same ambiguity: zero is both no files and
 * no fleet. */
u_int
sftp_parallel_files_total(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return (u_int)__atomic_load_n(&fleet->files_total,
	    __ATOMIC_RELAXED);
}

/* Was the run aborted (user interrupt, control-session loss, fatal
 * error)?  Read after sftp_parallel_wait so callers can refuse to
 * report success for a canceled, incomplete transfer. */
int
sftp_parallel_was_aborted(struct sftp_parallel *fleet)
{
	return fleet != NULL && fleet->abort_flag;
}

/* Starts the aggregate transfer meter. A total of 0 renders rate-only until
 * sftp_parallel_progress_set_total fills it in.
 *
 * Takes a byte baseline first, so the meter measures only this transfer and
 * not what earlier commands in the same session already moved, and clears
 * the verify total so a previous verify phase cannot hijack the stop
 * snapshot, which reads in the work-byte domain. No-op if a meter is already
 * running. */
void
sftp_parallel_progress_start(struct sftp_parallel *fleet, const char *label,
    off_t total_bytes)
{
	if (fleet == NULL || fleet->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	fleet->resume_stretch_on = 0;
	fleet->verify_meter_total = 0;	/* a stale verify total would hijack the stop snapshot */
	/* Nothing posted yet for this meter. */
	__atomic_store_n(&fleet->posted_total_add, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&fleet->posted_files_add, 0, __ATOMIC_RELAXED);
	/* Snapshot current accumulated bytes across all workers so the meter
	 * shows only bytes moved in this transfer, not prior transfers in the
	 * same session. */
	parallel_stats_snapshot(fleet, &fleet->progress_bytes_baseline, NULL, NULL);
	fleet->aggregate_progress_counter = 0;
	/* AGGREGATE kind: an unknown (0) total renders rate-only, and after
	 * this returns the reporter is the only thread that updates the
	 * meter. The core owns the label copy. */
	hpn_meter_start(&fleet->meter, fleet, HPN_METER_AGGREGATE,
	    HPN_METER_DOM_TRANSFER, label, total_bytes,
	    &fleet->aggregate_progress_counter, 0);
	hpn_meter_bind_display(&fleet->meter, fleet, fleet->reporter_tid);
	fleet->progress_meter_started = 1;
	/* Fresh meter: nothing deferred until _start_counted sets a verb. */
	fleet->progress_verb[0] = '\0';
}

/* Update a running transfer meter after it was started with an unknown (0)
 * total. The discover-tree download driver calls this once the enumeration has
 * drained and the full byte total and file count are known, so the aggregate
 * meter switches from rate-only to a real percentage and ETA, and (if the
 * client deferred its count via _start_counted) the label is rewritten to
 * "<verb> N files in parallel". No-op before the meter starts. */
void
sftp_parallel_progress_set_total(struct sftp_parallel *fleet, off_t total_bytes,
    size_t nfiles)
{
	if (fleet == NULL || !fleet->progress_meter_started)
		return;
	/* Recorded for the reporter rather than applied here: this runs on the
	 * walker's thread, and the reporter is the only thread that touches
	 * display state. The adds are cumulative so a second walk grows a live
	 * denominator instead of replacing it, which would leave the meter
	 * reading 100 percent. The reporter folds them in on its next tick and
	 * rewrites a deferred label from progress_verb. */
	if (total_bytes > 0)
		__atomic_fetch_add(&fleet->posted_total_add, total_bytes,
		    __ATOMIC_RELAXED);
	/* posted_files_add is u_int to match the frame API, so a size_t count
	 * narrows here; the truncation point is four billion files. */
	if (nfiles > 0)
		__atomic_fetch_add(&fleet->posted_files_add, (u_int)nfiles,
		    __ATOMIC_RELAXED);
}

/* Start a parallel download meter whose file count is not yet known (a
 * directory download - the real count arrives with the discover-tree walk).
 * Shows a count-less "<verb> files in parallel" until _set_total rewrites it to
 * "<verb> N files in parallel". verb is the tool's own word ("Fetching" for
 * sftp, "Downloading" for scp). */
void
sftp_parallel_progress_start_counted(struct sftp_parallel *fleet, const char *verb,
    off_t total_bytes)
{
	char label[128];

	/* A live meter keeps its own count, so arming the verb against it would
	 * let this command rewrite that meter's label and total. */
	if (fleet == NULL || fleet->progress_meter_started)
		return;
	if (verb == NULL)
		verb = "Fetching";
	snprintf(label, sizeof(label), "%s files in parallel", verb);
	sftp_parallel_progress_start(fleet, label, total_bytes);
	/* progress_start cleared progress_verb; set it AFTER so the count-fill
	 * in _set_total rewrites this label. */
	strlcpy(fleet->progress_verb, verb, sizeof(fleet->progress_verb));
}

/* Ends the command's progress meter, painting a final 100 percent first.
 *
 * The reporter advances the counter only on its tick, so the last units land
 * between ticks and a forced refresh would paint a stale 99. This snaps the
 * counter to the live meter's own total, then asks the reporter to paint it,
 * since the meter is bound to that thread and a repaint from here is
 * refused. If the reporter has not answered within two of its ticks it is
 * busy rather than gone, so the binding is dropped and the stop paints from
 * this thread. */
void
sftp_parallel_progress_stop(struct sftp_parallel *fleet)
{
	uint64_t bytes = 0;

	if (fleet == NULL || !fleet->progress_meter_started)
		return;
	/* Snap to whichever total the live meter is measuring. A verify meter
	 * counts hash work bytes, twice what moved, so painting the transfer
	 * byte snapshot onto it would finish the line at 50 percent. The
	 * bytes >= baseline test is what makes the cast below safe: without
	 * it the unsigned subtraction would wrap. */
	if (fleet->verify_meter_total > 0) {
		fleet->aggregate_progress_counter = fleet->verify_meter_total;
	} else {
		parallel_stats_snapshot(fleet, &bytes, NULL, NULL);
		if (bytes >= fleet->progress_bytes_baseline)
			fleet->aggregate_progress_counter =
			    (off_t)(bytes - fleet->progress_bytes_baseline);
	}
	/* Ask the reporter to paint the snapped total and wait up to two of
	 * its ticks. Every caller runs while the reporter is alive, so a
	 * silent one is busy rather than gone - blocked in a long fleet
	 * sample, say - and dropping the binding lets the stop paint from
	 * this thread instead of leaving the meter unpainted.
	 *
	 * The flag is the handshake: the release on the raise publishes the
	 * snapped total, the acquire on the poll observes the answer. */
	if (fleet->meter.display_bound) {
		int i;

		__atomic_store_n(&fleet->meter_final_request, 1,
		    __ATOMIC_RELEASE);
		for (i = 0; i < 40 && __atomic_load_n(&fleet->meter_final_request,
		    __ATOMIC_ACQUIRE); i++) {
			/* 10 ms: the reporter ticks every 200 ms, so the
			 * wait is sub-second by construction and bounded. */
			struct timespec ts = { 0, 10 * 1000000 };

			nanosleep(&ts, NULL);
		}
		if (__atomic_load_n(&fleet->meter_final_request,
		    __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&fleet->meter_final_request, 0,
			    __ATOMIC_RELAXED);
			fleet->meter.display_bound = 0;
		}
	}
	fleet->progress_meter_started = 0;
	hpn_meter_stop(&fleet->meter, fleet);
}

/* ----------------------------------------------------------------
 * Config accessors for the walker helpers in sftp-parallel-walk.c,
 * so they can read and adjust fleet config without seeing struct
 * sftp_parallel's internals. Each no-ops or returns a harmless
 * default when there is no fleet: zero for the flags, one stream.
 * ---------------------------------------------------------------- */

int
sftp_parallel_preserve_flag(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->cfg.preserve_flag;
}

int
sftp_parallel_num_streams(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 1;
	return fleet->cfg.num_streams;
}

void
sftp_parallel_set_verify_transfer(struct sftp_parallel *fleet, int on)
{
	if (fleet != NULL)
		fleet->cfg.verify_transfer = on ? 1 : 0;
}

/* Per-command preserve toggle: the parallel/bundle path reads preserve from
 * the orchestrator config, so a per-command put/get -p has to push it here
 * (the long-lived orchestrator was launched once with the program-level -p). */
void
sftp_parallel_set_preserve(struct sftp_parallel *fleet, int on)
{
	if (fleet != NULL)
		fleet->cfg.preserve_flag = on ? 1 : 0;
}

int
sftp_parallel_follow_link_flag(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->cfg.follow_link_flag;
}

/* Live abort state, as opposed to the fixed config above: is_aborting says
 * the run is ending, user_abort says the user's interrupt caused it rather
 * than a fleet failure, which is what picks a calm summary over error
 * reporting. Neither can be cached. */
int
sftp_parallel_is_aborting(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->abort_flag;
}

int
sftp_parallel_user_abort(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->abort_user;
}

/* Register the directory of a single transferred path so whole-file verify
 * items can store it relative to a shared prefix (held once) instead of the
 * full path per file. The recursive walker registers command roots itself;
 * this is the glob / direct-dispatch path (process_put/process_get), which
 * bypasses the walker. No-op unless verify is enabled. Call with both the
 * local and the remote path of each file; the dedup keeps the pool small for
 * the common flat-glob case (one or two distinct directories). */
void
sftp_parallel_register_verify_dir(struct sftp_parallel *fleet, const char *path)
{
	const char *slash;
	char *dir;

	if (fleet == NULL || path == NULL || !fleet->cfg.verify_transfer)
		return;
	if ((slash = strrchr(path, '/')) == NULL)
		return;			/* relative no-dir path: nothing to factor */
	dir = xmalloc((size_t)(slash - path) + 1);
	memcpy(dir, path, (size_t)(slash - path));
	dir[slash - path] = '\0';
	parallel_verify_prefix_register(fleet, dir);  /* handles ""/"."/dedup */
	free(dir);
}


/* Snapshot the fleet's counters into out, for the end-of-transfer report and
 * the exit-code decision. Live workers are summed under workers_mu and each
 * worker's own mutex, then the retired totals are added so workers the
 * reaper has already freed still count. out is zeroed first, so a NULL fleet
 * yields an all-zero snapshot. We can add stats easily if necessary. */
void
sftp_parallel_get_stats(struct sftp_parallel *fleet,
    struct sftp_parallel_stats *out)
{
	uint64_t bytes = 0, failed = 0, bytes_wired = 0;

	if (out == NULL)
		return;
	memset(out, 0, sizeof(*out));
	if (fleet == NULL)
		return;

	pthread_mutex_lock(&fleet->workers_mu);
	out->num_workers        = fleet->num_workers;
	out->protocol_violations = fleet->protocol_violations;
	out->total_respawns      = fleet->total_respawns;
	out->wedge_terminations  = fleet->wedge_terminations;
	out->peer_stall_terminations = fleet->peer_stall_terminations;
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		pthread_mutex_lock(&worker->mu);
		/* conn's lifetime is tied to the worker, so reading it
		 * under worker->mu is safe. Read once: debug evaluates its
		 * arguments whatever the log level. */
		uint64_t w_wired = sftp_conn_bytes_wired(worker->conn);

		bytes += worker->bytes_total;
		failed += worker->units_failed;
		bytes_wired += w_wired;
		debug("stats-sum: worker %d conn=%p wired=%llu bt=%llu",
		    worker->id, (void *)worker->conn,
		    (unsigned long long)w_wired,
		    (unsigned long long)worker->bytes_total);
		pthread_mutex_unlock(&worker->mu);
	}
	/* Add back what reaped (respawned/dead) workers contributed - their
	 * per-worker counters die with the struct. Without this the end-of-
	 * transfer report raced the reaper: stats taken after a reap (always,
	 * post-abort; sometimes, post-respawn) silently undercounted or
	 * vanished entirely (the bytes>0 gate failed). Read under workers_mu,
	 * which the reap site holds while accumulating. */
	bytes += fleet->retired_bytes;
	bytes_wired += fleet->retired_wired;
	failed += fleet->retired_units_failed;
	debug("stats-sum: retired_wired=%llu retired_bytes=%llu -> "
	    "aggregate wired=%llu bt=%llu",
	    (unsigned long long)fleet->retired_wired,
	    (unsigned long long)fleet->retired_bytes,
	    (unsigned long long)bytes_wired, (unsigned long long)bytes);
	pthread_mutex_unlock(&fleet->workers_mu);

	out->bytes_total_aggregate = bytes;
	out->bytes_wired_aggregate = bytes_wired;
	out->units_failed_aggregate = failed;
	out->walker_failures_aggregate =
	    __atomic_load_n(&fleet->walker_failures, __ATOMIC_RELAXED);
	pthread_mutex_lock(&fleet->pending_mu);
	out->units_pending = fleet->pending;
	pthread_mutex_unlock(&fleet->pending_mu);

	if (fleet->session_start_ms != 0)
		out->elapsed_ms = monotime_ms() - fleet->session_start_ms;
}

/* Drain the failed-path list the walkers and workers appended to:
 * returns the total failure count seen andntransfers ownership of the
 * path strings to the caller. The list is reset, so failures recorded
 * after this call start fresh. */
uint64_t
sftp_parallel_drain_failed_paths(struct sftp_parallel *fleet,
    char ***out_paths, size_t *out_used)
{
	if (fleet == NULL) {
		if (out_paths != NULL)
			*out_paths = NULL;
		if (out_used != NULL)
			*out_used = 0;
		return 0;
	}
	return hpn_strlist_drain(&fleet->failed_paths, out_paths, out_used);
}

/* Drain the verify transfer post-transfer mismatch list. Same
 * as sftp_parallel_drain_failed_paths above: returns the total mismatch count
 * and transfers ownership of the path strings to the caller.
 * A non-zero return means hpnsftp should exit SFTP_EX_VERIFY_FAILED. */
uint64_t
sftp_parallel_drain_verify_failures(struct sftp_parallel *fleet,
    char ***out_paths, size_t *out_used)
{
	if (fleet == NULL) {
		if (out_paths != NULL)
			*out_paths = NULL;
		if (out_used != NULL)
			*out_used = 0;
		return 0;
	}
	return hpn_strlist_drain(&fleet->verify_failed_paths, out_paths, out_used);
}
