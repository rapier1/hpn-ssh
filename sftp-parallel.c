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
 * SIGTERM to the SSH child (to unblock any pending I/O) and sets w->doomed.
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
sftp_parallel_walker_record_failure(struct sftp_parallel *p, const char *path,
    const char *err)
{
	char buf[PATH_MAX + 256];

	/* need atomics because this happens while the fleet is live and
	 * working concurrently. This prevents possible issues */
	__atomic_fetch_add(&p->walker_failures, 1, __ATOMIC_RELAXED);
	if (path == NULL)
		path = "(unknown)";
	if (err != NULL && *err != '\0')
		snprintf(buf, sizeof(buf), "%s: %s", path, err);
	else
		snprintf(buf, sizeof(buf), "%s", path);
	hpn_strlist_append(&p->failed_paths, buf);
}

/*
 * Publish the walker's current phase (enum sftp_walker_phase).  Public so the
 * walker in sftp-parallel-walk.c can mark itself blocked/enumerating without
 * seeing struct sftp_parallel's internals.  Relaxed atomic; observability only.
 */
void
sftp_parallel_set_walker_phase(struct sftp_parallel *p, int phase)
{
	if (p != NULL)
		__atomic_store_n(&p->walker_phase, phase, __ATOMIC_RELAXED);
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

	struct sftp_parallel *p = xcalloc(1, sizeof(*p));

	/* Fresh fleet: clear the process-wide user-abort mirror left by a
	 * previous orchestrator's interrupt (the post-interrupt rebuild). */
	parallel_user_abort_flag = 0;

	p->cfg = *cfg;
	/* cfg.port may point to a stack buffer in the caller that is only
	 * valid until the enclosing scope exits.  Copy it into p->cfg_port_buf
	 * so the orchestrator owns the string for its entire lifetime. */
	if (cfg->port && cfg->port[0]) {
		strlcpy(p->cfg_port_buf, cfg->port, sizeof(p->cfg_port_buf));
		p->cfg.port = p->cfg_port_buf;
	}

	/* instantiate mutexs and the like */
	pthread_mutex_init(&p->pending_mu, NULL);
	pthread_cond_init(&p->pending_cv, NULL);
	pthread_mutex_init(&p->workers_mu, NULL);
	pthread_mutex_init(&p->verify_pending_mu, NULL);
	pthread_mutex_init(&p->retry_overflow_mu, NULL);

	/* Parked-verify memory gate: fleet-wide budget on parked-path bytes.
	 * When the parked set crosses this the submitter runs a verify wave
	 * (parallel_verify_maybe_wave).  64 MiB, validated across a range of
	 * values as a reasonable batching-vs-RAM balance. Basically, if we are
	 * doing verification then do it occasionally during the transfer.*/
	p->verify_park_budget = 64 * 1024 * 1024;

	p->session_start_ms = monotime_ms();

	/* Fleet-abort zero-progress window, resolved from ssh_config
	 * HPNStallAbortTimeout (default 60 s).  The abort also requires no worker
	 * heartbeating and FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams
	 * unproductive respawns (see parallel_watchdog_sync_check); this knob
	 * only sizes the window.  0 disables the abort entirely. */
	p->noprogress_abort_s = cfg->stall_abort_timeout;
	if (p->noprogress_abort_s < 0)
		p->noprogress_abort_s = 0;

	/* Enable tail redistribution (cooperative yield of a confirmed-lagging
	 * endgame holder) from HPNTailRedistribute.  Default ON.
	 * off leaves the tail detector as telemetry only. */
	p->tail_redistribute = cfg->tail_redistribute;

	/* Auto-repair: on a post-transfer verify mismatch, re-transfer the
	 * bad ranges and re-verify, bounded by a per-range attempt cap.  ON by
	 * default; disabled by the -X VerifyRepair=no CLI token
	 * (cfg->no_verify_repair).  The attempt cap is fixed at 3. */
	sftp_hpn_verify_repair_resolve(cfg->no_verify_repair,
	    &p->verify_repair_enabled, &p->verify_repair_attempts);
	p->last_worker_exit_code = -1;	/* no worker reaped yet */

	/* Born-dead 0-bytes kill threshold. This is when a worker starts but there
	 * is no data transmission for whatever reason. This can happen in lossy
	 * environments. RTT-derived once the path RTT is
	 * registered (sftp_parallel_set_path_rtt); BORN_DEAD_KILL_SEC until then. */
	p->born_dead_sec = BORN_DEAD_KILL_SEC;
	p->born_dead_stuck_offset = -1;	/* 0 is a valid range_offset */

	/* List of failures. Cap chosen so the worst-case allocation is
	 * bounded but the "show me what failed" list is still useful for moderately
	 * broken transfers. Really broken ones could potentially spam the interface.
	 * XXX: This might need to be revisited. HPN_FAILED_PATHS_MAX × ~256 bytes typical
	 * = ~25 KiB at the default cap. */
	hpn_strlist_init(&p->failed_paths, HPN_FAILED_PATHS_MAX);
	hpn_strlist_init(&p->verify_failed_paths, HPN_FAILED_PATHS_MAX);

	/* 1. Workqueue. Sized for cfg->num_streams.  Respawned workers
	 * reuse the same queue, so capacity is set once at startup. */
	p->outstanding_cap = (uint64_t)outstanding_file_cap(cfg);
	p->q = sftp_workqueue_new(work_queue_depth(cfg));
	if (p->q == NULL) {
		error_f("workqueue allocation failed");
		goto fail;
	}

	/* 2. Suppress per-file progress in workers; the orchestrator drives
	 * aggregate progress when requested via sftp_parallel_progress_*. */
	p->saved_showprogress = showprogress;
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
			sctx[i].p              = p;
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
	if (pthread_create(&p->reporter_tid, NULL, parallel_reporter_thread, p) == 0)
		p->reporter_started = 1;

	p->started = 1;
	return p;

 fail:
	sftp_parallel_stop(p);
	return NULL;
}

void
sftp_parallel_wait(struct sftp_parallel *p, struct sftp_conn *conn)
{
	if (p == NULL) return;

	/* Push the the tail before waiting.
	 * Entering wait is the universal "done submitting" point for every
	 * command - directory walks and direct (non-walker) put/get alike -
	 * so the tail bundle can't be left stranded in the accumulator. */
	parallel_bundle_flush_pending(p);

	/* Entering wait is the "no more units coming" signal, so publish
	 * walker-phase DONE here. A directory walk already set it; direct
	 * put/get never does, and without it the endgame machinery (range
	 * split, straggler reaper) stays gated off for the whole transfer.
	 * Demotion back to SUBMIT is the submit path's business. */
	__atomic_store_n(&p->walker_phase, SFTP_WKP_DONE, __ATOMIC_RELAXED);
	pthread_mutex_lock(&p->pending_mu);
	while (p->pending > 0 && !p->abort_flag)
		pthread_cond_wait(&p->pending_cv, &p->pending_mu);
	pthread_mutex_unlock(&p->pending_mu);

	/* Transfers drained: run the post-transfer verify phase. Every
	 * completed verified file (whole-file or range-split) parked its tracker
	 * at completion; submit them now as SFTP_OP_VERIFY units so the idle
	 * workers verify them in parallel on their own conns - off the transfer
	 * path - then wait for those units to drain before returning. */
	if (!p->abort_flag) {
		/* All verify units: range-split trackers (verify_pending) plus
		 * whole-file items (verify_whole_pending).  Whole-file transfers
		 * park only in the latter, so gating the meter on verify_pending_n
		 * alone left the common case with no verify progress at all. */
		int vn = p->verify_pending_n + p->verify_whole_pending_n;

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

			parallel_stats_snapshot(p, &moved, NULL, NULL);
			vtotal = (moved > p->progress_bytes_baseline)
			    ? (off_t)(moved - p->progress_bytes_baseline) : 0;
			if (p->progress_meter_started)
				sftp_parallel_progress_stop(p);
			/* Suppress in frame mode: stdout is the binary status
			 * channel there, so this text would corrupt frames. */
			if (p->cfg.print_flag != SFTP_QUIET &&
			    !hpn_pm_active())
				mprintf("Verifying %d file(s)...\n", vn);
			if (p->saved_showprogress && vtotal > 0) {
				p->verify_total_units = (uint64_t)vn;
				p->verify_done_units = 0;
				p->verify_done_bytes = 0;
				/* WORK-bytes: each transferred byte is hashed
				 * on both ends (project_hash_work_meter_design),
				 * so the verify meter total is 2x the moved
				 * bytes and both legs advance it. */
				p->verify_meter_total = 2 * vtotal;
				p->aggregate_progress_counter = 0;
				/* WORK kind in the work-byte domain: the
				 * core marks it not a file and raises the
				 * verify phase flag. */
				hpn_meter_start(&p->meter, p,
				    HPN_METER_WORK, HPN_METER_DOM_WORK,
				    "verify", 2 * vtotal,
				    &p->aggregate_progress_counter, 0);
				hpn_meter_bind_display(&p->meter, p,
				    p->reporter_tid);
				/* verify_phase_active BEFORE meter_started: a
				 * reporter tick between the two would take the
				 * transfer branch against the verify meter's
				 * freshly-zeroed counter and the ratchet would
				 * pin the bogus publish for the whole phase. */
				p->verify_phase_active = 1;
				p->progress_meter_started = 1;
			}
		}
		(void)parallel_verify_phase_submit(p);
		pthread_mutex_lock(&p->pending_mu);
		while (p->pending > 0 && !p->abort_flag)
			pthread_cond_wait(&p->pending_cv, &p->pending_mu);
		pthread_mutex_unlock(&p->pending_mu);
		p->verify_phase_active = 0;
		/*
		 * Auto-repair now runs inline inside each verify unit (the
		 * worker splices the bad sub-chunks of its range and re-verifies
		 * on its own conn), so there is no separate repair phase here.
		 */
	}

	/* HPN: apply the deferred directory attributes now that every
	 * unit has drained (shared machinery with the serial walks). */
	if (p->dirattrs != NULL) {
		if (conn != NULL)
			sftp_hpn_dirattrs_apply(conn, p->dirattrs);
		else if (p->dirattrs->n > 0)
			error_f("no control connection: %d directory "
			    "attribute(s) not applied.",
			    p->dirattrs->n);
		sftp_hpn_dirattrs_free(p->dirattrs);
		free(p->dirattrs);
		p->dirattrs = NULL;
	}
}

/*
 * Verify wave (parked-verify memory gate, HPN).  Hard pause + full drain run
 * mid-transfer to bound the parked-path memory: quiesce the in-flight transfers
 * (so the workers are free to verify and every completed file is parked), drain
 * the entire parked set through the verify phase, wait for it, then reset the
 * prefix pool.  Unlike sftp_parallel_wait this does NOT publish walker_phase=
 * DONE - the walk is not finished, so the endgame machinery stays gated off and
 * the in-flight units just complete normally.  Submitter (main) thread only -
 * the sftp_parallel_submit_* callers are never worker threads - so blocking here
 * is the intended pause; workers drain it.
 */
static void
parallel_verify_wave(struct sftp_parallel *p)
{
	parallel_bundle_flush_pending(p);
	/* Quiesce: drain in-flight transfers (no new units arrive - the walker
	 * is blocked in this call). */
	pthread_mutex_lock(&p->pending_mu);
	while (p->pending > 0 && !p->abort_flag)
		pthread_cond_wait(&p->pending_cv, &p->pending_mu);
	pthread_mutex_unlock(&p->pending_mu);
	if (p->abort_flag)
		return;
	debug("verify wave: draining parked set (%llu bytes) to bound memory",
	    (unsigned long long)p->verify_parked_bytes);
	/* Drain the parked set into verify units (resets verify_parked_bytes),
	 * then wait for those units to finish (the items are freed as they do). */
	(void)parallel_verify_phase_submit(p);
	pthread_mutex_lock(&p->pending_mu);
	while (p->pending > 0 && !p->abort_flag)
		pthread_cond_wait(&p->pending_cv, &p->pending_mu);
	pthread_mutex_unlock(&p->pending_mu);
	/* Every parked item is now verified + freed, so nothing references the
	 * prefix pool indices: free the pool (relieves the byte budget AND the
	 * INT16_MAX dir cap).  New parks after this re-register their dirs. */
	parallel_verify_prefix_pool_reset(p);
}

/*
 * Trigger check, called by the submitter after each unit (see the tail of
 * sftp_parallel_submit_upload / _download).  Runs a verify wave when the parked
 * set is over its byte budget, or the prefix pool nears its INT16_MAX cap
 * (wave a little early so dirs keep factoring rather than degrading to full
 * paths).  No-op until something is parked.
 */
void
parallel_verify_maybe_wave(struct sftp_parallel *p)
{
	int over;

	if (p == NULL)
		return;
	pthread_mutex_lock(&p->verify_pending_mu);
	over = (p->verify_park_budget > 0 &&
	    p->verify_parked_bytes >= p->verify_park_budget) ||
	    (p->verify_prefixes_n >= INT16_MAX - 256);
	pthread_mutex_unlock(&p->verify_pending_mu);
	if (over)
		parallel_verify_wave(p);
}

void
sftp_parallel_abort(struct sftp_parallel *p)
{
	if (p == NULL) return;
	p->abort_flag = 1;
	/* Kill the progress meter FIRST: with the fleet dying, further
	 * redraws are stale frames with garbage rates, and a redraw racing
	 * the abort messages clobbers their first characters. */
	sftp_parallel_progress_stop(p);
	if (p->q)
		sftp_workqueue_shutdown(p->q);

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
	 *
	 * Policy: abort means abort.  We do not gracefully drain in-flight
	 * RPCs - the user (or the orchestrator detecting an
	 * unrecoverable condition) has asked us to stop.
	 */
	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		if (w == NULL)
			continue;
		if (w->fd_in >= 0) {
			(void)close(w->fd_in);
			w->fd_in = -1;
		}
		if (w->fd_out >= 0) {
			(void)close(w->fd_out);
			w->fd_out = -1;
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
		if (w->ssh_pid > 0)
			(void)kill(w->ssh_pid, SIGTERM);
	}
	/* Also SIGTERM any IN-FLIGHT spawn attempts: their ssh children may
	 * sit in a connect for minutes, and "abort means abort" applies to
	 * recruits too.  The spawner's blocked sftp_init fails within ms of
	 * the child dying; its post-register flag re-check covers the race
	 * where a spawn registers after this sweep. */
	for (int i = 0; i < p->n_spawning; i++) {
		if (p->spawning_pids[i] > 0)
			(void)kill(p->spawning_pids[i], SIGTERM);
	}
	pthread_mutex_unlock(&p->workers_mu);

	pthread_mutex_lock(&p->pending_mu);
	pthread_cond_broadcast(&p->pending_cv);
	pthread_mutex_unlock(&p->pending_mu);
}

void
sftp_parallel_set_interrupt_flag(struct sftp_parallel *p,
    _Atomic sig_atomic_t *flag)
{
	if (p != NULL)
		p->ext_interrupt_flag = flag;
}

void
sftp_parallel_set_path_rtt(struct sftp_parallel *p, uint64_t rtt_us)
{
	if (p == NULL)
		return;
	p->path_rtt_us = rtt_us;

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
		p->born_dead_sec = v;
	}
}

void
sftp_parallel_stop(struct sftp_parallel *p)
{
	if (p == NULL || p->stopped) {
		if (p) p->stopped = 1;
		return;
	}
	p->stopped = 1;

	if (p->q)
		sftp_workqueue_shutdown(p->q);

	/*
	 * Join the reporter BEFORE touching the workers.  Each reporter tick
	 * reaps exited workers (pthread_join + sftp_free(w->conn) + free(w)) and
	 * removes them from p->workers[].  If it keeps running while we walk the
	 * workers below it can free a worker out from under us: the previous
	 * snapshot-then-join approach copied the worker pointers, then the
	 * reporter freed some of them concurrently, and we dereferenced
	 * (snap[i]->started) and double-joined (pthread_join(snap[i]->tid)) the
	 * freed structs - a use-after-free that crashes under worker death on a
	 * lossy path.  parallel_reporter_thread breaks its loop on p->stopped (set above),
	 * so this join returns within one tick; afterwards we own p->workers[]
	 * exclusively and no concurrent reaping can occur.
	 */
	if (p->reporter_started)
		pthread_join(p->reporter_tid, NULL);

	/* Drain detached respawn threads before touching the workers array or
	 * freeing p - they hold p across a ~2s nanosleep.  With the reporter
	 * joined, no NEW respawns can be scheduled, and the bail-on-stopped
	 * check in respawn_worker_thread (p->stopped is set above) makes each
	 * pending one exit shortly after its sleep without spawning.  A thread
	 * already past the check finishes its spawn attempt and decrements on
	 * completion; either way this loop is bounded.  Without the drain, a
	 * sleeping respawn thread would wake to a freed p (use-after-free) -
	 * previously a narrow quit-after-churn window, now a likely one since
	 * the post-interrupt fleet rebuild calls stop() seconds after an abort
	 * that has typically just scheduled respawns. */
	pthread_mutex_lock(&p->workers_mu);
	/* SIGKILL in-flight spawn attempts so the wait below resolves in
	 * milliseconds instead of a connect timeout (stop() may run without
	 * a preceding abort, e.g. session end after a clean transfer).
	 * KILL, not TERM: ssh catches SIGTERM for an orderly shutdown that
	 * can itself block on the very stall we are escaping. */
	for (int i = 0; i < p->n_spawning; i++) {
		if (p->spawning_pids[i] > 0)
			(void)kill(p->spawning_pids[i], SIGKILL);
	}
	while (p->pending_respawns > 0) {
		pthread_mutex_unlock(&p->workers_mu);
		struct timespec drain_ts = { 0, 50L * 1000 * 1000 };
		nanosleep(&drain_ts, NULL);
		pthread_mutex_lock(&p->workers_mu);
	}
	pthread_mutex_unlock(&p->workers_mu);

	if (p->workers) {
		/* SIGKILL any worker ssh children that survived the abort's
		 * SIGTERM.  ssh CATCHES SIGTERM and attempts an orderly
		 * shutdown - which itself blocks on a stalled connection
		 * (observed: a TERMed child surviving ~a minute while its
		 * worker thread sat in pipe_write and this join sat behind
		 * it).  KILL cannot be caught; the pipe breaks, the blocked
		 * write fails, the worker unwinds, the join below returns. */
		pthread_mutex_lock(&p->workers_mu);
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			if (w != NULL && w->ssh_pid > 0)
				(void)kill(w->ssh_pid, SIGKILL);
		}
		pthread_mutex_unlock(&p->workers_mu);

		/* Reporter is gone - no concurrent reaping.  Join any worker
		 * threads it had not already reaped. */
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			if (w != NULL && w->started)
				pthread_join(w->tid, NULL);
		}
	}

	/* Drain undispatched work units left in the queue by an abort.  All
	 * workers are joined, so nothing pops or requeues concurrently.  Each
	 * unit owes its tracker exactly one finalize (invariant I1) and owns
	 * its path strings - without this sweep both leaked on every abort,
	 * which the post-interrupt rebuild turned from a once-per-session
	 * leak into a recurring one (and leaked paths can be sensitive).
	 * In-flight units were already finalized by their dying workers via
	 * the push-fail give-up path; finalize's user-abort gate keeps these
	 * quiet after a Ctrl-C. */
	if (p->q) {
		void *item;
		while (sftp_workqueue_drain(p->q, &item) == 0) {
			struct sftp_work_unit *u = item;
			/* A bundle container is ONE queue item but N members, and
			 * pending was bumped once per member at bundle-add time
			 * (parallel_bundle_add), so decrement by n_members - a
			 * single decrement leaves pending overstated by N-1.
			 * Harmless at terminal stop (pending is not read after),
			 * but keeps the accounting correct if the drain is reused. */
			uint64_t dec = (u->members != NULL && u->n_members > 0)
			    ? (uint64_t)u->n_members : 1;
			pthread_mutex_lock(&p->pending_mu);
			p->pending = (p->pending > dec) ? (p->pending - dec) : 0;
			pthread_mutex_unlock(&p->pending_mu);
			(void)parallel_unit_tracker_finalize(u->range_tracker, 1, NULL);
			parallel_unit_free(u);
		}
	}

	if (p->workers) {
		/* Reporter is now joined - no more concurrent reaping. We
		 * own everything still in p->workers; tear it down. */
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			if (w == NULL) continue;
			if (w->conn) {
				sftp_free(w->conn);
				w->conn = NULL;
			}
			parallel_respawn_teardown_ssh(w);
			pthread_mutex_destroy(&w->mu);
			free(w);
		}
		free(p->workers);
		p->workers = NULL;
		p->num_workers = 0;
		p->workers_cap = 0;
	}

	if (p->q) {
		sftp_workqueue_free(p->q);
		p->q = NULL;
	}

	/* Restore the user's progress preference. */
	showprogress = p->saved_showprogress;

	/* Bundle accumulator: normally drained by parallel_bundle_flush_pending
	 * at wait.  Free any leftover (e.g. aborted before wait) so the member
	 * units and the array don't leak. */
	{
		int i;
		for (i = 0; i < p->bundle_pending_n; i++)
			parallel_unit_free(p->bundle_pending[i]);
		free(p->bundle_pending);
		p->bundle_pending = NULL;
	}
	/* Verify-pending: range trackers + whole-file items parked at completion
	 * but never submitted as verify units (e.g. aborted before wait's verify
	 * phase).  Free both lists so neither leaks. */
	{
		int i;
		for (i = 0; i < p->verify_pending_n; i++)
			parallel_verify_tracker_free(p->verify_pending[i]);
		free(p->verify_pending);
		p->verify_pending = NULL;
		for (i = 0; i < p->verify_whole_pending_n; i++)
			free(p->verify_whole_pending[i]);	/* single block */
		free(p->verify_whole_pending);
		p->verify_whole_pending = NULL;
	}
	/* Path-factoring prefix pool: the registered directory prefixes. */
	{
		int i;
		for (i = 0; i < p->verify_prefixes_n; i++)
			free(p->verify_prefixes[i]);
		free(p->verify_prefixes);
		p->verify_prefixes = NULL;
	}
	/* Worker re-queue overflow: units parked here when a worker hit a full
	 * queue, never drained back (abort/shutdown before the reporter moved
	 * them).  Threads have joined by now, so free without locking concerns. */
	parallel_retry_overflow_free(p);
	pthread_mutex_destroy(&p->verify_pending_mu);
	pthread_mutex_destroy(&p->retry_overflow_mu);
	pthread_mutex_destroy(&p->pending_mu);
	pthread_cond_destroy(&p->pending_cv);
	pthread_mutex_destroy(&p->workers_mu);
	hpn_strlist_free(&p->failed_paths);
	hpn_strlist_free(&p->verify_failed_paths);
	free(p);
}

static void
scan_upload_recursive(const char *src, off_t *bytes_out, long *files_out)
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

off_t
sftp_parallel_scan_upload_total(const char *src, long *file_count_out)
{
	off_t bytes = 0;
	long files = 0;

	scan_upload_recursive(src, &bytes, &files);
	if (file_count_out != NULL)
		*file_count_out = files;
	return bytes;
}

/* Record the scan-time total file count for the progress frames/meter. */
void
sftp_parallel_set_file_total(struct sftp_parallel *p, long total)
{
	if (p != NULL)
		__atomic_store_n(&p->files_total,
		    total > 0 ? (uint64_t)total : 0, __ATOMIC_RELAXED);
}

/* Walker-authoritative per-file counts, for a final END-frame publish. */
u_int
sftp_parallel_files_submitted(struct sftp_parallel *p)
{
	return p != NULL
	    ? (u_int)__atomic_load_n(&p->files_submitted, __ATOMIC_RELAXED) : 0;
}

u_int
sftp_parallel_files_total(struct sftp_parallel *p)
{
	return p != NULL
	    ? (u_int)__atomic_load_n(&p->files_total, __ATOMIC_RELAXED) : 0;
}

/*
 * Was the run aborted (user interrupt, control-session loss, fatal
 * error)?  Read after sftp_parallel_wait so callers can refuse to
 * report success for a canceled, incomplete transfer.
 */
int
sftp_parallel_was_aborted(struct sftp_parallel *p)
{
	return p != NULL && p->abort_flag;
}

void
sftp_parallel_progress_start(struct sftp_parallel *p, const char *label,
    off_t total_bytes)
{
	if (p == NULL || p->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	p->resume_stretch_on = 0;
	p->verify_meter_total = 0;	/* this is a TRANSFER meter; a stale
					 * verify total would hijack the stop
					 * snapshot (work-byte domain) */
	/* Nothing posted yet for this meter. */
	__atomic_store_n(&p->posted_total_add, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&p->posted_files_add, 0, __ATOMIC_RELAXED);
	/* Snapshot current accumulated bytes across all workers so the meter
	 * shows only bytes moved in this transfer, not prior transfers in the
	 * same session. */
	parallel_stats_snapshot(p, &p->progress_bytes_baseline, NULL, NULL);
	p->aggregate_progress_counter = 0;
	/* AGGREGATE kind: an unknown (0) total renders rate-only, and after
	 * this returns the reporter is the only thread that updates the
	 * meter. The core owns the label copy. */
	hpn_meter_start(&p->meter, p, HPN_METER_AGGREGATE,
	    HPN_METER_DOM_TRANSFER, label, total_bytes,
	    &p->aggregate_progress_counter, 0);
	hpn_meter_bind_display(&p->meter, p, p->reporter_tid);
	p->progress_meter_started = 1;
	p->progress_verb[0] = '\0';	/* no deferred file count unless the
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
sftp_parallel_progress_set_total(struct sftp_parallel *p, off_t total_bytes,
    size_t nfiles)
{
	if (p == NULL || !p->progress_meter_started)
		return;
	/*
	 * Post, do not apply: this runs on the walker's thread when an
	 * enumeration drains, and the reporter is the only thread that
	 * touches display state (review finding #19). Additive so a later
	 * walk grows a live denominator instead of replacing it, which
	 * could freeze the meter at a bogus 100 percent (finding #9). The
	 * reporter folds these in on its next tick and rewrites a
	 * deferred-count label from progress_verb.
	 */
	if (total_bytes > 0)
		__atomic_fetch_add(&p->posted_total_add, total_bytes,
		    __ATOMIC_RELAXED);
	if (nfiles > 0)
		__atomic_fetch_add(&p->posted_files_add, (u_int)nfiles,
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
sftp_parallel_progress_start_counted(struct sftp_parallel *p, const char *verb,
    off_t total_bytes)
{
	char label[128];

	if (p == NULL || p->progress_meter_started)
		return;		/* a live meter keeps its own count; arming
				 * the verb against it would let this
				 * command rewrite that meter's label and
				 * total (review finding #28) */
	if (verb == NULL)
		verb = "Fetching";
	snprintf(label, sizeof(label), "%s files in parallel", verb);
	sftp_parallel_progress_start(p, label, total_bytes);
	/* progress_start cleared progress_verb; set it AFTER so the count-fill
	 * in _set_total rewrites this label. */
	strlcpy(p->progress_verb, verb, sizeof(p->progress_verb));
}

void
sftp_parallel_progress_stop(struct sftp_parallel *p)
{
	uint64_t bytes = 0;

	if (p == NULL || !p->progress_meter_started)
		return;
	/* The reporter advances the aggregate counter only on its tick, so
	 * the final units land between ticks and the meter's forced last
	 * refresh paints a stale 99%.  Snap to the LIVE meter's own total:
	 * the verify meter counts hash WORK-bytes (2x the moved bytes -
	 * project_hash_work_meter_design), so painting the transfer-byte
	 * snapshot onto it would land the completion line at 50%. */
	if (p->verify_meter_total > 0) {
		p->aggregate_progress_counter = p->verify_meter_total;
	} else {
		parallel_stats_snapshot(p, &bytes, NULL, NULL);
		if (bytes >= p->progress_bytes_baseline)
			p->aggregate_progress_counter =
			    (off_t)(bytes - p->progress_bytes_baseline);
	}
	/*
	 * The meter is bound to the reporter, so the final paint must come
	 * from it: a repaint from this thread is refused by the display
	 * gate, which is how completions were left showing the last alarm
	 * tick's 99 percent. Ask the reporter to paint the snapped total and
	 * wait up to two of its ticks. If it does not answer (already torn
	 * down on an abort path), unbind and let the stop paint from here;
	 * the reporter is not filling anything in that state.
	 */
	if (p->meter.display_bound) {
		int i;

		__atomic_store_n(&p->meter_final_request, 1,
		    __ATOMIC_RELEASE);
		for (i = 0; i < 40 && __atomic_load_n(&p->meter_final_request,
		    __ATOMIC_ACQUIRE); i++) {
			/* 10 ms: the reporter ticks every 200 ms, so the
			 * wait is sub-second by construction and bounded. */
			struct timespec ts = { 0, 10 * 1000000L };

			nanosleep(&ts, NULL);
		}
		if (__atomic_load_n(&p->meter_final_request,
		    __ATOMIC_ACQUIRE)) {
			__atomic_store_n(&p->meter_final_request, 0,
			    __ATOMIC_RELAXED);
			p->meter.display_bound = 0;
		}
	}
	p->progress_meter_started = 0;
	hpn_meter_stop(&p->meter, p);
}

/* ---------- Recursive walkers (Approach B) ----------
 *
 * The walker runs on the producer (caller) thread and uses the control
 * connection (`conn`) for metadata operations: mkdir on the destination
 * tree, readdir/stat for downloads. Regular files are handed to the
 * orchestrator via submit_*; the workers transfer them in parallel while
 * the walker continues descending. The caller is expected to call
 * sftp_parallel_wait after the walker returns.
 *
 * Mirrors the structure of upload_dir_internal / download_dir_internal in
 * sftp-client.c. Symlinks honor the orchestrator's follow_link_flag;
 * non-regular files are skipped with a warning, matching legacy behavior.
 */



/* ----------------------------------------------------------------
 * Read-only accessors for walker-helper fields.  Exposed so the
 * recursive walkers in sftp-parallel-walk.c can read config and
 * abort state without seeing struct sftp_parallel's internals.
 * ---------------------------------------------------------------- */

int
sftp_parallel_preserve_flag(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->cfg.preserve_flag : 0;
}

int
sftp_parallel_num_streams(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->cfg.num_streams : 1;
}

void
sftp_parallel_set_verify_transfer(struct sftp_parallel *p, int on)
{
	if (p != NULL)
		p->cfg.verify_transfer = on ? 1 : 0;
}

/* Per-command preserve toggle: the parallel/bundle path reads preserve from
 * the orchestrator config, so a per-command put/get -p has to push it here
 * (the long-lived orchestrator was launched once with the program-level -p). */
void
sftp_parallel_set_preserve(struct sftp_parallel *p, int on)
{
	if (p != NULL)
		p->cfg.preserve_flag = on ? 1 : 0;
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
sftp_parallel_register_verify_dir(struct sftp_parallel *p, const char *path)
{
	const char *slash;
	char *dir;

	if (p == NULL || path == NULL || !p->cfg.verify_transfer)
		return;
	if ((slash = strrchr(path, '/')) == NULL)
		return;			/* relative no-dir path: nothing to factor */
	dir = xmalloc((size_t)(slash - path) + 1);
	memcpy(dir, path, (size_t)(slash - path));
	dir[slash - path] = '\0';
	parallel_verify_prefix_register(p, dir);  /* handles ""/"."/dedup */
	free(dir);
}

int
sftp_parallel_follow_link_flag(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->cfg.follow_link_flag : 0;
}

int
sftp_parallel_is_aborting(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->abort_flag : 0;
}

/* 1 iff the abort was caused by the user's interrupt (Ctrl-C), as opposed
 * to a fleet failure.  Drives the interrupt-aware messaging. */
int
sftp_parallel_user_abort(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->abort_user : 0;
}

/* ---------- Stats accessor (programmatic observability) ---------- */

void
sftp_parallel_get_stats(struct sftp_parallel *p,
    struct sftp_parallel_stats *out)
{
	if (out == NULL) return;
	memset(out, 0, sizeof(*out));
	if (p == NULL) return;

	uint64_t b = 0, c = 0, f = 0, w_bytes_wired = 0;
	pthread_mutex_lock(&p->workers_mu);
	out->num_workers        = p->num_workers;
	out->protocol_violations = p->protocol_violations;
	out->total_respawns      = p->total_respawns;
	out->wedge_terminations  = p->wedge_terminations;
	out->peer_stall_terminations = p->peer_stall_terminations;
	out->endgame_straggler_reaps = p->endgame_straggler_reaps;
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		b += w->bytes_total;
		c += w->units_completed;
		f += w->units_failed;
		/* Snapshot the conn's wired-bytes counter outside the worker
		 * mutex if conn can race - but conn lifetime is tied to the
		 * worker, so reading under the worker mutex is fine and we
		 * already hold it. */
		w_bytes_wired += sftp_conn_bytes_wired(w->conn);
		debug("stats-sum: worker %d conn=%p wired=%llu bt=%llu",
		    w->id, (void *)w->conn,
		    (unsigned long long)sftp_conn_bytes_wired(w->conn),
		    (unsigned long long)w->bytes_total);
		pthread_mutex_unlock(&w->mu);
	}
	/* Add back what reaped (respawned/dead) workers contributed - their
	 * per-worker counters die with the struct.  Without this the end-of-
	 * transfer report raced the reaper: stats taken after a reap (always,
	 * post-abort; sometimes, post-respawn) silently undercounted or
	 * vanished entirely (the bytes>0 gate failed).  Read under workers_mu,
	 * which the reap site holds while accumulating. */
	b             += p->retired_bytes;
	w_bytes_wired += p->retired_wired;
	c             += p->retired_units_completed;
	f             += p->retired_units_failed;
	debug("stats-sum: retired_wired=%llu retired_bytes=%llu -> "
	    "aggregate wired=%llu bt=%llu",
	    (unsigned long long)p->retired_wired,
	    (unsigned long long)p->retired_bytes,
	    (unsigned long long)w_bytes_wired, (unsigned long long)b);
	pthread_mutex_unlock(&p->workers_mu);

	out->bytes_total_aggregate = b;
	out->bytes_wired_aggregate = w_bytes_wired;
	out->units_completed_aggregate = c;
	out->units_failed_aggregate = f;
	out->walker_failures_aggregate =
	    __atomic_load_n(&p->walker_failures, __ATOMIC_RELAXED);
	pthread_mutex_lock(&p->pending_mu);
	out->units_pending = (uint64_t)p->pending;
	pthread_mutex_unlock(&p->pending_mu);

	if (p->session_start_ms != 0)
		out->elapsed_ms = monotime_ms() - p->session_start_ms;
	if (p->q) {
		out->queue_depth = sftp_workqueue_depth(p->q);
		out->queue_high_watermark = sftp_workqueue_high_watermark(p->q);
		/* queue capacity isn't directly queryable; derive from
		 * the formula used at construction. Slightly indirect but
		 * stable. */
		out->queue_capacity = work_queue_depth(&p->cfg);
	}
}

uint64_t
sftp_parallel_drain_failed_paths(struct sftp_parallel *p,
    char ***out_paths, size_t *out_used)
{
	if (p == NULL) {
		if (out_paths != NULL) *out_paths = NULL;
		if (out_used  != NULL) *out_used  = 0;
		return 0;
	}
	return hpn_strlist_drain(&p->failed_paths, out_paths, out_used);
}

/*
 * Drain the HPNVerifyTransfer post-transfer mismatch list.  Same contract
 * as sftp_parallel_drain_failed_paths: returns the total mismatch count and
 * (when out_paths is non-NULL) transfers ownership of the path strings to
 * the caller.  A non-zero return means hpnsftp should exit
 * SFTP_EX_VERIFY_FAILED.
 */
uint64_t
sftp_parallel_drain_verify_failures(struct sftp_parallel *p,
    char ***out_paths, size_t *out_used)
{
	if (p == NULL) {
		if (out_paths != NULL) *out_paths = NULL;
		if (out_used  != NULL) *out_used  = 0;
		return 0;
	}
	return hpn_strlist_drain(&p->verify_failed_paths, out_paths, out_used);
}


