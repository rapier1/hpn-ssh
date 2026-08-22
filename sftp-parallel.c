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

/*
 * sftp-client.c's I/O helpers (send_msg, get_msg_extended) return -1 and set
 * conn->hpn->dead on EOF or write errors rather than calling fatal(). If
 * fatal is called it will kill the entire fleet and we don't want that
 * to happen. Instead the problem is handled by the reporter (a coordinator process)
 * A dead connection propagates up through execute_unit back to the worker loop,
 * which re-queues the in-flight unit (if under MAX_RETRIES) and then exits.
 *
 * MAX_RETRIES = Retry budget per work unit.  Default 3 attempts (1st + 2 retries).
 *
 * Configured via ssh_config HPNMaxRetries copied to pcfg->max_retries.
 * Valid range is [1, 20]:
 *   - 1 = no retries (one attempt total).  Useful for diagnosing
 *     transient-vs-permanent failures: every failure is final.
 *   - 3 = default.  Covers ordinary network hiccups; doesn't punish
 *     permanent failures (permission denied, disk full) with much
 *     wasted retry time.
 *   - 20 = upper bound.  For demonstrably flaky networks where the
 *     transport layer hasn't yet self-recovered.  Above this the
 *     retry storm itself becomes the load problem.
 *
 * The reporter's watchdog detects dead workers via kill(0) probes and elapsed
 * time since last completion. When a worker is classified DEAD, it sends
 * SIGTERM to the SSH child (to unblock any pending I/O) and sets worker->doomed.
 * The reap loop joins the exited worker thread, frees its resources, and
 * spawns a replacement in a detached thread so the SSH handshake doesn't
 * block the reporter's 200ms progress ticks.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
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

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_watchdog_pause_until_ms */
#include "sftp-hpn-verify.h"		/* sftp_hpn_verify_repair[_resolve] */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "hpn-exit-codes.h"
#include "sftp-hpn-client.h"	/* deferred dir attrs */
#include "sftp-parallel-internal.h"

extern int showprogress;

/* Single definition; declared extern in sftp-parallel-internal.h. */
volatile sig_atomic_t parallel_user_abort_flag;


/* The depth of the work queue depth neeed to be bundle aware because a single bundle
 * might include thousands of files which, if we are just counting files, would destroy
 * performance. So if we are using bundles the max depth is dependant on the size of
 * the bundle
 */
static size_t
work_queue_depth(const struct sftp_parallel_config *cfg)
{
	size_t base = 0, per_bundle = 0, depth = 0;
	uint64_t target = 0;

	base = (size_t)cfg->num_streams * UPLOAD_BATCH_SIZE * 4 +
	    UPLOAD_BATCH_SIZE;
	if (!cfg->use_bundle)
		return base;

	target = (cfg->bundle_size > 0)
	    ? cfg->bundle_size : BUNDLE_TARGET_BYTES;
	per_bundle = (size_t)(target / BUNDLE_QUEUE_FILE_HINT);
	if (per_bundle < UPLOAD_BATCH_SIZE)
		per_bundle = UPLOAD_BATCH_SIZE;

	/* num_streams full bundles + one round of headroom so the walker stays
	 * ahead of all workers assembling at once. */
	depth = (size_t)cfg->num_streams * per_bundle * 2 +
	    UPLOAD_BATCH_SIZE;
	if (depth < base)
		depth = base;
	if (depth > WORK_QUEUE_DEPTH_MAX)
		depth = WORK_QUEUE_DEPTH_MAX;
	return depth;
}

/*
 * Ceiling on outstanding FILES, for a producer that enumerates far faster
 * than the fleet drains (the discover-tree walk).  Counted in files rather
 * than queued objects because the queue is heterogeneous: a bundle is one
 * object carrying thousands of files, while a file too large to bundle is one
 * object carrying one.  Only a file count is meaningful for both.
 *
 * Sized from the MAXIMUM a bundle can hold.  Real packing varies with the workload.
 * The byte target, the member cap, and the download path-list limit each
 * bind in different cases. A ceiling derived from any one of them starves the
 * others.  Against the hard maximum every worker is guaranteed its two
 * bundles whatever the packing, so the ceiling bounds memory without ever
 * being the thing that limits throughput.
 *
 * Without bundling a queued object is already a single file, so the queue's
 * own depth is the same quantity and is used as-is.
 */
static size_t
outstanding_file_cap(const struct sftp_parallel_config *cfg)
{
	if (!cfg->use_bundle)
		return work_queue_depth(cfg);

	return (size_t)cfg->num_streams * 2 * BUNDLE_BATCH_MAX_FILES;
}

/*
 * Walker-side failure recorder: bumps the aggregate counter and adds
 * "path: error" to the failed-paths list in one shot.  `err` may be
 * NULL when no errno-style message is available (e.g. depth limit,
 * "not a directory").  Single-call helper because every walker
 * skip-on-error site does both - bump + list.
 */
void
sftp_parallel_walker_record_failure(struct sftp_parallel *fleet, const char *path,
    const char *err)
{
	char buf[PATH_MAX + 256];

	/* need atomics because this happens while the fleet is live and
	 * working concurrently. This prevents possible issues */
	__atomic_fetch_add(&fleet->walker_failures, 1, __ATOMIC_RELAXED);
	if (path == NULL)
		path = "(unknown)";
	if (err != NULL && *err != '\0')
		snprintf(buf, sizeof(buf), "%s: %s", path, err);
	else
		snprintf(buf, sizeof(buf), "%s", path);
	hpn_strlist_append(&fleet->failed_paths, buf);
}

/*
 * Publish the walker's current phase (enum sftp_walker_phase).  Public so the
 * walker in sftp-parallel-walk.c can mark itself blocked/enumerating without
 * seeing struct sftp_parallel's internals.  Relaxed atomic; observability only.
 */
void
sftp_parallel_set_walker_phase(struct sftp_parallel *fleet, int phase)
{
	if (fleet != NULL)
		__atomic_store_n(&fleet->walker_phase, phase, __ATOMIC_RELAXED);
}

/*
 * Bounded thread-safe string list - see comment on struct hpn_strlist.
 */
void
hpn_strlist_init(struct hpn_strlist *list, size_t cap)
{
	pthread_mutex_init(&list->mu, NULL);
	list->cap   = cap;
	list->used  = 0;
	list->total = 0;
	list->items = (cap > 0) ? xcalloc(cap, sizeof(*list->items)) : NULL;
}

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

/*
 * Append `entry` to the list.  Always bumps `total`; only allocates a
 * new entry if `used < cap`.  Silently drops the string contents when
 * over cap so memory stays bounded; the count is preserved so the
 * user knows how many were dropped.
 */
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

/*
 * Drain the list.  Returns the total append count seen, and (when
 * `out` is non-NULL) transfers ownership of the held strings to the
 * caller via *out / *out_used.  The list itself is reset to empty
 * but remains usable for further appends.  Caller frees each string
 * and the array.
 */
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
	}
	/* Reset the list so subsequent appends start fresh. */
	if (list->items != NULL)
		memset(list->items, 0, list->cap * sizeof(*list->items));
	list->used  = 0;
	list->total = 0;
	pthread_mutex_unlock(&list->mu);
	return total;
}

/* ---------- Public API Functions ---------- */

/* instantiate the fleet of workers and fire them up. */
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
	 * valid until the enclosing scope exits.  Copy it into fleet->cfg_port_buf
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
	 * (parallel_verify_maybe_wave).  64 MiB, validated across a range of
	 * values as a reasonable batching-vs-RAM balance. Basically, if we are
	 * doing verification then do it occasionally during the transfer.*/
	fleet->verify_park_budget = 64 * 1024 * 1024;

	fleet->session_start_ms = monotime_ms();

	/* Fleet-abort zero-progress window, resolved from ssh_config
	 * HPNStallAbortTimeout (default 60 s).  The abort also requires no worker
	 * heartbeating and FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams
	 * unproductive respawns (see parallel_watchdog_sync_check); this knob
	 * only sizes the window.  0 disables the abort entirely. */
	fleet->noprogress_abort_s = cfg->stall_abort_timeout;
	if (fleet->noprogress_abort_s < 0)
		fleet->noprogress_abort_s = 0;

	/* Enable tail redistribution (cooperative yield of a confirmed-lagging
	 * endgame holder) from HPNTailRedistribute.  Default ON.
	 * off leaves the tail detector as telemetry only. */
	fleet->tail_redistribute = cfg->tail_redistribute;

	/* Auto-repair: on a post-transfer verify mismatch, re-transfer the
	 * bad ranges and re-verify, bounded by a per-range attempt cap.  ON by
	 * default; disabled by the -X VerifyRepair=no CLI token
	 * (cfg->no_verify_repair).  The attempt cap is fixed at 3. */
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
	 * XXX: This might need to be revisited. HPN_FAILED_PATHS_MAX × ~256 bytes typical
	 * = ~25 KiB at the default cap. */
	hpn_strlist_init(&fleet->failed_paths, HPN_FAILED_PATHS_MAX);
	hpn_strlist_init(&fleet->verify_failed_paths, HPN_FAILED_PATHS_MAX);

	/* 1. Workqueue. Sized for cfg->num_streams.  Respawned workers
	 * reuse the same queue, so capacity is set once at startup. */
	fleet->outstanding_cap = (uint64_t)outstanding_file_cap(cfg);
	fleet->q = sftp_workqueue_new(work_queue_depth(cfg));
	if (fleet->q == NULL) {
		error_f("workqueue allocation failed");
		goto fail;
	}

	/* 2. Suppress per-file progress in workers; the orchestrator drives
	 * aggregate progress when requested via sftp_parallel_progress_*. */
	fleet->saved_showprogress = showprogress;
	showprogress = 0;

	/* 3. Spawn workers in parallel to overlap SSH handshakes, but cap
	 * the number of simultaneous unauthenticated connections to stay
	 * under the server's MaxStartups limit (default 10:30:100).
	 8 in it's own clode block to limit namespace/declaration */
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

	/* 4. Reporter - best-effort. */
	if (pthread_create(&fleet->reporter_tid, NULL, parallel_reporter_thread, fleet) == 0)
		fleet->reporter_started = 1;

	fleet->started = 1;
	return fleet;

 fail:
	sftp_parallel_stop(fleet);
	return NULL;
}

void
sftp_parallel_wait(struct sftp_parallel *fleet, struct sftp_conn *conn)
{
	if (fleet == NULL) return;

	/* Push the the tail before waiting.
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
	pthread_mutex_lock(&fleet->pending_mu);
	while (fleet->pending > 0 && !fleet->abort_flag)
		pthread_cond_wait(&fleet->pending_cv, &fleet->pending_mu);
	pthread_mutex_unlock(&fleet->pending_mu);

	/* Transfers drained: run the post-transfer verify phase. Every
	 * completed verified file (whole-file or range-split) parked its tracker
	 * at completion; submit them now as SFTP_OP_VERIFY units so the idle
	 * workers verify them in parallel on their own conns - off the transfer
	 * path - then wait for those units to drain before returning. */
	if (!fleet->abort_flag) {
		/* All verify units: range-split trackers (verify_pending) plus
		 * whole-file items (verify_whole_pending).  Whole-file transfers
		 * park only in the latter, so gating the meter on verify_pending_n
		 * alone left the common case with no verify progress at all. */
		int vn = fleet->verify_pending_n + fleet->verify_whole_pending_n;

		if (vn > 0) {
			/*
			 * Set the verify meter up BEFORE submitting: the submit
			 * blocks and is most of the phase, so a meter started
			 * after it would cover only the tail while the finished
			 * transfer bar sits at 100% looking hung. Sized to the
			 * bytes just moved; the reporter advances it from
			 * verify_done_units, since pending is ambiguous
			 * mid-submit. This is a lot of work for a progressmeter
			 * but it will be a critical part of any GUI we develop.
			 */
			uint64_t moved = 0;
			off_t vtotal;

			parallel_stats_snapshot(fleet, &moved, NULL, NULL);
			vtotal = (moved > fleet->progress_bytes_baseline)
			    ? (off_t)(moved - fleet->progress_bytes_baseline) : 0;
			if (fleet->progress_meter_started)
				sftp_parallel_progress_stop(fleet);
			/* Suppress in frame mode: stdout is the binary status
			 * channel there, so this text would corrupt frames. */
			if (fleet->cfg.print_flag != SFTP_QUIET &&
			    !hpn_pm_active())
				mprintf("Verifying %d file(s)...\n", vn);
			if (fleet->saved_showprogress && vtotal > 0) {
				fleet->verify_total_units = (uint64_t)vn;
				fleet->verify_done_units = 0;
				fleet->verify_done_bytes = 0;
				/* WORK-bytes: each transferred byte is hashed
				 * on both ends (project_hash_work_meter_design),
				 * so the verify meter total is 2x the moved
				 * bytes and both legs advance it. */
				fleet->verify_meter_total = 2 * vtotal;
				fleet->aggregate_progress_counter = 0;
				/* WORK kind in the work-byte domain: the
				 * core marks it not a file and raises the
				 * verify phase flag. */
				hpn_meter_start(&fleet->meter, fleet,
				    HPN_METER_WORK, HPN_METER_DOM_WORK,
				    "verify", 2 * vtotal,
				    &fleet->aggregate_progress_counter, 0);
				hpn_meter_bind_display(&fleet->meter, fleet,
				    fleet->reporter_tid);
				/* verify_phase_active BEFORE meter_started: a
				 * reporter tick between the two would take the
				 * transfer branch against the verify meter's
				 * freshly-zeroed counter and the ratchet would
				 * pin the bogus publish for the whole phase. */
				fleet->verify_phase_active = 1;
				fleet->progress_meter_started = 1;
			}
		}
		(void)parallel_verify_phase_submit(fleet);
		pthread_mutex_lock(&fleet->pending_mu);
		while (fleet->pending > 0 && !fleet->abort_flag)
			pthread_cond_wait(&fleet->pending_cv, &fleet->pending_mu);
		pthread_mutex_unlock(&fleet->pending_mu);
		fleet->verify_phase_active = 0;
		/*
		 * Auto-repair now runs inline inside each verify unit (the
		 * worker splices the bad sub-chunks of its range and re-verifies
		 * on its own conn), so there is no separate repair phase here.
		 */
	}

	/* HPN: apply the deferred directory attributes now that every
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

/*
 * Verify wave - this is the mid transfer verification.  Hard pause + full drain run
 * mid-transfer to bound the parked-path memory: pause the in-flight transfers, drain
 * the entire parked set through the verify phase, wait for it, then reset the
 * prefix pool.
  */
static void
parallel_verify_wave(struct sftp_parallel *fleet)
{
	parallel_bundle_flush_pending(fleet);
	/* Pause: drain in-flight transfers (no new units arrive - the walker
	 * is blocked in this call). */
	pthread_mutex_lock(&fleet->pending_mu);
	while (fleet->pending > 0 && !fleet->abort_flag)
		pthread_cond_wait(&fleet->pending_cv, &fleet->pending_mu);
	pthread_mutex_unlock(&fleet->pending_mu);
	if (fleet->abort_flag)
		return;
	debug("verify wave: draining parked set (%llu bytes)",
	    (unsigned long long)fleet->verify_parked_bytes);
	/* Drain the parked set into verify units (resets verify_parked_bytes),
	 * then wait for those units to finish. */
	(void)parallel_verify_phase_submit(fleet);
	pthread_mutex_lock(&fleet->pending_mu);
	while (fleet->pending > 0 && !fleet->abort_flag)
		pthread_cond_wait(&fleet->pending_cv, &fleet->pending_mu);
	pthread_mutex_unlock(&fleet->pending_mu);
	/* Every parked item is now verified + freed, so nothing references the
	 * prefix pool indices: free the pool
	 */
	parallel_verify_prefix_pool_reset(fleet);
}

/*
 * Trigger check, called by the submitter after each unit (see the tail of
 * sftp_parallel_submit_upload / _download).  Runs a verify wave when the parked
 * set is over its byte budget, or the prefix pool nears its INT16_MAX cap
 * (wave a little early so dirs keep factoring rather than degrading to full
 * paths).  No-op until something is parked.
 */
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

void
sftp_parallel_abort(struct sftp_parallel *fleet)
{
	if (fleet == NULL) return;
	fleet->abort_flag = 1;
	/* Kill the progress meter FIRST: with the fleet dying, further
	 * redraws are stale frames with garbage rates. */
	sftp_parallel_progress_stop(fleet);
	if (fleet->q)
		sftp_workqueue_shutdown(fleet->q);

	/*
	 * Close every worker's SSH FDs.  Without this, a worker blocked in
	 * get_msg / send_msg on the SSH socket won't notice abort_flag
	 * until the server eventually drops the connection (seconds to
	 * minutes).  Closing the FD here makes the blocked read return
	 * EBADF / 0 immediately; the worker propagates the I/O failure,
	 * exits execute_unit, sees abort_flag at the top of its loop, and
	 * thread-exits within milliseconds.  pthread_join in
	 * sftp_parallel_free can then return promptly.
	 *
	 * Set the FD to -1 after closing so parallel_respawn_teardown_ssh (called
	 * later from sftp_parallel_free) is a no-op for these slots and
	 * doesn't double-close a (potentially reused) FD number.
	 */
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
		/* Closing the fds does NOT wake a worker thread already
		 * blocked in writev on a full pipe (Linux pins the struct
		 * file under the in-flight syscall): if the ssh child is
		 * alive but not draining - a stalled connection that
		 * survived the terminal's SIGINT - that worker hangs in
		 * pipe_write until the child dies naturally, holding
		 * stop()'s join (and the user's exit) hostage for the
		 * server's grace timeout.  Kill the child: the broken pipe
		 * fails the write immediately and the worker unwinds. */
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

	pthread_mutex_lock(&fleet->pending_mu);
	pthread_cond_broadcast(&fleet->pending_cv);
	pthread_mutex_unlock(&fleet->pending_mu);
}

void
sftp_parallel_set_interrupt_flag(struct sftp_parallel *fleet,
    _Atomic sig_atomic_t *flag)
{
	if (fleet != NULL)
		fleet->ext_interrupt_flag = flag;
}

void
sftp_parallel_set_path_rtt(struct sftp_parallel *fleet, uint64_t rtt_us)
{
	if (fleet == NULL)
		return;
	fleet->path_rtt_us = rtt_us;

	/* RTT-dependent born-dead threshold: ~100 round-trips, i.e. rtt_ms/10
	 * seconds (rtt_us/10000), with the mantissa dropped, floored at
	 * BORN_DEAD_KILL_SEC (5s, RTT <= ~59ms) and capped at BORN_DEAD_SEC_MAX
	 * (40s, RTT >= ~400ms).  A transient backend stall takes ~O(RTT) to
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

/*
 * Tear down the fleet and free it. The order is the point: shut the queue
 * so workers stop pulling, join the reporter so nothing reaps behind us,
 * drain the respawn threads, then kill the worker ssh children and join
 * their threads. Work that never ran is drained and finalized, and every
 * buffer the fleet owns is freed. fleet is invalid once this returns.
 */
void
sftp_parallel_stop(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return;

	fleet->stopped = 1;

	if (fleet->q)
		sftp_workqueue_shutdown(fleet->q);

	/*
	 * Join the reporter BEFORE touching the workers. Otherwise
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

		/* Reporter is gone - no concurrent reaping.  Join any worker
		 * threads it had not already reaped. */
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			if (worker != NULL && worker->started)
				pthread_join(worker->tid, NULL);
		}
	}

	/* Drain work units an abort left undispatched. All workers are
	 * joined, so nothing pops or requeues concurrently. Each unit owes its
	 * tracker one finalize  and owns its path strings. Without this sweep
	 * both leak on every abort, and leaked paths can be sensitive. */
	if (fleet->q) {
		void *item;
		while (sftp_workqueue_drain(fleet->q, &item) == 0) {
			struct sftp_work_unit *work_unit = item;
			/* A bundle container is one queue item but N members, and
			 * pending was bumped per member at add time, so decrement by
			 * n_members. Only matters if the drain is ever reused;
			 * pending is not read after a terminal stop. */
			uint64_t dec = (work_unit->members != NULL && work_unit->n_members > 0)
			    ? (uint64_t)work_unit->n_members : 1;
			pthread_mutex_lock(&fleet->pending_mu);
			fleet->pending = (fleet->pending > dec) ? (fleet->pending - dec) : 0;
			pthread_mutex_unlock(&fleet->pending_mu);
			(void)parallel_unit_tracker_finalize(work_unit->range_tracker, 1, NULL);
			parallel_unit_free(work_unit);
		}
	}

	if (fleet->workers) {
		/* Reporter is now joined - no more concurrent reaping. We
		 * own everything still in fleet->workers; tear it down. */
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
	 * at wait.  Free any leftover (e.g. aborted before wait) so the member
	 * units and the array don't leak. */
	for (int i = 0; i < fleet->bundle_pending_n; i++)
		parallel_unit_free(fleet->bundle_pending[i]);
	free(fleet->bundle_pending);
	fleet->bundle_pending = NULL;

	/* Verify-pending: range trackers + whole-file items parked at completion
	 * but never submitted as verify units (e.g. aborted before wait's verify
	 * phase).  Free both lists so neither leaks. */
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

	/* Worker re-queue overflow: units parked here when a worker hit a full
	 * queue, never drained back (abort/shutdown before the reporter moved
	 * them).  Threads have joined by now, so free without locking concerns. */
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

/*
 * Recursive worker for sftp_parallel_scan_upload_total: add src to the
 * running byte and file totals, descending into directories. Regular
 * files only, and the lstat means symlinks are skipped rather than
 * followed. Best effort: a path it cannot stat or a directory it cannot
 * open is left out of the total rather than reported.
 */
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

/*
 * Total bytes of the regular files under a local path, and their count
 * via file_count_out when it is non-NULL. Callers use this to size the
 * progress meter before an upload starts, so it is deliberately best
 * effort: anything unreadable is omitted rather than treated as an
 * error.
 */
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

/* Walker-authoritative per-file counts, for a final END-frame publish. */
u_int
sftp_parallel_files_submitted(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return (u_int)__atomic_load_n(&fleet->files_submitted,
	    __ATOMIC_RELAXED);
}

u_int
sftp_parallel_files_total(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return (u_int)__atomic_load_n(&fleet->files_total,
	    __ATOMIC_RELAXED);
}

/*
 * Was the run aborted (user interrupt, control-session loss, fatal
 * error)?  Read after sftp_parallel_wait so callers can refuse to
 * report success for a canceled, incomplete transfer.
 */
int
sftp_parallel_was_aborted(struct sftp_parallel *fleet)
{
	return fleet != NULL && fleet->abort_flag;
}

/* initialize the progressmeter */
void
sftp_parallel_progress_start(struct sftp_parallel *fleet, const char *label,
    off_t total_bytes)
{
	if (fleet == NULL || fleet->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	fleet->resume_stretch_on = 0;
	fleet->verify_meter_total = 0;	/* this is a TRANSFER meter; a stale
					 * verify total would hijack the stop
					 * snapshot (work-byte domain) */
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
	fleet->progress_verb[0] = '\0';	/* no deferred file count unless the
					 * caller re-arms it via _start_counted */
}

/*
 * Update a running transfer meter after it was started with an unknown (0)
 * total.  The discover-tree download driver calls this once the enumeration has
 * drained and the full byte total and file count are known, so the aggregate
 * meter switches from rate-only to a real percentage and ETA, and (if the
 * client deferred its count via _start_counted) the label is rewritten to
 * "<verb> N files in parallel".  No-op before the meter starts.
 */
void
sftp_parallel_progress_set_total(struct sftp_parallel *fleet, off_t total_bytes,
    size_t nfiles)
{
	if (fleet == NULL || !fleet->progress_meter_started)
		return;
	/*
	 * Post, do not apply: this runs on the walker's thread when an
	 * enumeration drains, and the reporter is the only thread that
	 * touches display state. Additive so a later walk grows a live
	 * denominator instead of replacing it, which
	 * could freeze the meter at a bogus 100 percent. The
	 * reporter folds these in on its next tick and rewrites a
	 * deferred-count label from progress_verb.
	 */
	if (total_bytes > 0)
		__atomic_fetch_add(&fleet->posted_total_add, total_bytes,
		    __ATOMIC_RELAXED);
	if (nfiles > 0)
		__atomic_fetch_add(&fleet->posted_files_add, (u_int)nfiles,
		    __ATOMIC_RELAXED);
}

/*
 * Start a parallel download meter whose file count is not yet known (a
 * directory download - the real count arrives with the discover-tree walk).
 * Shows a count-less "<verb> files in parallel" until _set_total rewrites it to
 * "<verb> N files in parallel".  verb is the tool's own word ("Fetching" for
 * sftp, "Downloading" for scp).
 */
void
sftp_parallel_progress_start_counted(struct sftp_parallel *fleet, const char *verb,
    off_t total_bytes)
{
	char label[128];

	if (fleet == NULL || fleet->progress_meter_started)
		return;		/* a live meter keeps its own count; arming
				 * the verb against it would let this
				 * command rewrite that meter's label and
				 * total (review finding #28) */
	if (verb == NULL)
		verb = "Fetching";
	snprintf(label, sizeof(label), "%s files in parallel", verb);
	sftp_parallel_progress_start(fleet, label, total_bytes);
	/* progress_start cleared progress_verb; set it AFTER so the count-fill
	 * in _set_total rewrites this label. */
	strlcpy(fleet->progress_verb, verb, sizeof(fleet->progress_verb));
}

/* stop the progress meter once we've reached the end of the workunit */
void
sftp_parallel_progress_stop(struct sftp_parallel *fleet)
{
	uint64_t bytes = 0;

	if (fleet == NULL || !fleet->progress_meter_started)
		return;
	/* The reporter advances the aggregate counter only on its tick, so
	 * the final units land between ticks and the meter's forced last
	 * refresh paints a stale 99%.  Snap to the LIVE meter's own total:
	 * the verify meter counts hash WORK-bytes (2x the moved bytes -
	 * project_hash_work_meter_design), so painting the transfer-byte
	 * snapshot onto it would land the completion line at 50%. */
	if (fleet->verify_meter_total > 0) {
		fleet->aggregate_progress_counter = fleet->verify_meter_total;
	} else {
		parallel_stats_snapshot(fleet, &bytes, NULL, NULL);
		if (bytes >= fleet->progress_bytes_baseline)
			fleet->aggregate_progress_counter =
			    (off_t)(bytes - fleet->progress_bytes_baseline);
	}
	/*
	 * The meter is bound to the reporter, so the final paint must come
	 * from it: a repaint from this thread is refused by the display
	 * gate, which is how completions were left showing the last alarm
	 * tick's 99 percent. Ask the reporter to paint the snapped total and
	 * wait up to two of its ticks. If it does not answer (already torn
	 * down on an abort path), unbind and let the stop paint from here;
	 * the reporter is not filling anything in that state.
	 * Atomic because the flag is the handshake with the reporter
	 * thread: the release on the raise publishes the snapped total,
	 * the acquire on the poll observes the reporter's answer. */
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
 * Read-only accessors for walker-helper fields.  Exposed so the
 * recursive walkers in sftp-parallel-walk.c can read config and
 * abort state without seeing struct sftp_parallel's internals.
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

/*
 * Register the directory of a single transferred path so whole-file verify
 * items can store it relative to a shared prefix (held once) instead of the
 * full path per file.  The recursive walker registers command roots itself;
 * this is the glob / direct-dispatch path (process_put/process_get), which
 * bypasses the walker.  No-op unless verify is enabled.  Call with both the
 * local and the remote path of each file; the dedup keeps the pool small for
 * the common flat-glob case (one or two distinct directories).
 */
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

int
sftp_parallel_follow_link_flag(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->cfg.follow_link_flag;
}

int
sftp_parallel_is_aborting(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->abort_flag;
}

/* 1 iff the abort was caused by the user's interrupt (Ctrl-C), as opposed
 * to a fleet failure.  Drives the interrupt-aware messaging. */
int
sftp_parallel_user_abort(const struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return 0;
	return fleet->abort_user;
}

/* ---------- Stats accessor (programmatic observability) ---------- */

/*
 * Snapshot the fleet's counters into out. Live workers are summed under
 * workers_mu and each worker's own mutex, then the retired totals are added
 * so workers the reaper has already freed still count. out is zeroed first,
 * so a NULL fleet yields an all-zero snapshot. we can expand the number of
 * data points if needed for development or reporting but these are useful.
 */
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
		bytes += worker->bytes_total;
		failed += worker->units_failed;
		/* conn's lifetime is tied to the worker, so reading it
		 * under worker->mu is safe. */
		bytes_wired += sftp_conn_bytes_wired(worker->conn);
		debug("stats-sum: worker %d conn=%p wired=%llu bt=%llu",
		    worker->id, (void *)worker->conn,
		    (unsigned long long)sftp_conn_bytes_wired(worker->conn),
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
	out->units_pending = (uint64_t)fleet->pending;
	pthread_mutex_unlock(&fleet->pending_mu);

	if (fleet->session_start_ms != 0)
		out->elapsed_ms = monotime_ms() - fleet->session_start_ms;
}

/*
 * Drain the failed-path list the walkers and workers appended to:
 * returns the total failure count seen and, when out_paths is non-NULL,
 * transfers ownership of the path strings to the caller. The list is
 * reset, so failures recorded after this call start fresh.
 */
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

/*
 * Drain the HPNVerifyTransfer post-transfer mismatch list.  Same
 * as sftp_parallel_drain_failed_paths above: returns the total mismatch count and
 * (when out_paths is non-NULL) transfers ownership of the path strings to
 * the caller.  A non-zero return means hpnsftp should exit
 * SFTP_EX_VERIFY_FAILED.
 */
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
