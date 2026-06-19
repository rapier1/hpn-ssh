/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/*
 * Phase 2 worker fault isolation:
 *
 * sftp-client.c's I/O helpers (send_msg, get_msg_extended) return -1 and set
 * conn->hpn->dead on EOF or write errors rather than calling fatal(). A dead
 * connection propagates up through execute_unit() back to the worker loop,
 * which re-queues the in-flight unit (if under MAX_RETRIES) and then exits.
 *
 * The reporter's watchdog detects dead workers via kill(0) probes and elapsed
 * time since last completion. When a worker is classified DEAD, it sends
 * SIGTERM to the SSH child (to unblock any pending I/O) and sets w->doomed.
 * The reap loop joins the exited worker thread, frees its resources, and
 * spawns a replacement in a detached thread so the SSH handshake doesn't
 * block the reporter's 200ms progress ticks.
 *
 * Remaining Phase 2 work: convert protocol-level fatal()s (request ID
 * mismatch, unexpected packet type) to conn->hpn->dead.
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
#include "sftp-client-internal.h"	/* sftp_conn_watchdog_pause_until_ns */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "hpn-exit-codes.h"

extern int showprogress;

/* Work-queue depth is computed by work_queue_depth() below (defined after the
 * bundle constants it depends on), NOT a fixed macro: bundle mode needs a much
 * deeper queue than the old 64-file pipelining did. */

/* Retry budget per work unit.  Default 3 attempts (initial + 2 retries).
 *
 * Configured via ssh_config HPNMaxRetries (parsed by readconf.c into
 * options.parallel_unit_max_retries, then copied to pcfg->max_retries by
 * sftp-parallel-config.c).  Clamped to [1, 20] at the readconf layer:
 *   - 1 = no retries (one attempt total).  Useful for diagnosing
 *     transient-vs-permanent failures: every failure is final.
 *   - 3 = default.  Covers ordinary network hiccups; doesn't punish
 *     permanent failures (permission denied, disk full) with much
 *     wasted retry time.
 *   - 20 = upper bound.  For demonstrably flaky networks where the
 *     transport layer hasn't yet self-recovered.  Above this the
 *     retry storm itself becomes the load problem.
 */
#include "sftp-parallel-internal.h"

/* Single definition; declared extern in sftp-parallel-internal.h. */
volatile sig_atomic_t parallel_user_abort_flag;


static size_t
work_queue_depth(const struct sftp_parallel_config *cfg)
{
	size_t base = (size_t)cfg->num_streams * UPLOAD_BATCH_SIZE * 4 +
	    UPLOAD_BATCH_SIZE;

	if (!cfg->use_bundle)
		return base;

	uint64_t target = (cfg->bundle_size > 0)
	    ? cfg->bundle_size : BUNDLE_TARGET_BYTES;
	size_t per_bundle = (size_t)(target / BUNDLE_QUEUE_FILE_HINT);
	if (per_bundle < UPLOAD_BATCH_SIZE)
		per_bundle = UPLOAD_BATCH_SIZE;

	/* num_streams full bundles + one round of headroom so the walker stays
	 * ahead of all workers assembling at once. */
	size_t depth = (size_t)cfg->num_streams * per_bundle * 2 +
	    UPLOAD_BATCH_SIZE;
	if (depth < base)
		depth = base;
	if (depth > WORK_QUEUE_DEPTH_MAX)
		depth = WORK_QUEUE_DEPTH_MAX;
	return depth;
}

/* ---------- Worker SSH connection setup ---------- */

/* ---------- Work units ---------- */

/*
 * Walker-side failure recorder: bumps the aggregate counter and adds
 * "path: error" to the failed-paths list in one shot.  `err` may be
 * NULL when no errno-style message is available (e.g. depth limit,
 * "not a directory").  Single-call helper because every walker
 * skip-on-error site does both - bump + list.
 *
 * Public (declared in sftp-parallel.h) so the walkers in
 * sftp-parallel-walk.c can call it without seeing struct
 * sftp_parallel's internals.
 */
void
sftp_parallel_walker_record_failure(struct sftp_parallel *p, const char *path,
    const char *err)
{
	char buf[PATH_MAX + 256];

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
hpn_strlist_init(struct hpn_strlist *l, size_t cap)
{
	pthread_mutex_init(&l->mu, NULL);
	l->cap   = cap;
	l->used  = 0;
	l->total = 0;
	l->items = (cap > 0) ? xcalloc(cap, sizeof(*l->items)) : NULL;
}

void
hpn_strlist_free(struct hpn_strlist *l)
{
	if (l->items != NULL) {
		for (size_t i = 0; i < l->used; i++)
			free(l->items[i]);
		free(l->items);
		l->items = NULL;
	}
	pthread_mutex_destroy(&l->mu);
	l->used = 0;
	l->cap  = 0;
}

/*
 * Append `s` to the list.  Always bumps `total`; only allocates a
 * new entry if `used < cap`.  Silently drops the string contents when
 * over cap so memory stays bounded; the count is preserved so the
 * user knows how many were dropped.
 */
void
hpn_strlist_append(struct hpn_strlist *l, const char *s)
{
	if (l == NULL || s == NULL)
		return;
	pthread_mutex_lock(&l->mu);
	l->total++;
	if (l->used < l->cap)
		l->items[l->used++] = xstrdup(s);
	pthread_mutex_unlock(&l->mu);
}

/*
 * Drain the list.  Returns the total append count seen, and (when
 * `out` is non-NULL) transfers ownership of the held strings to the
 * caller via *out / *out_used.  The list itself is reset to empty
 * but remains usable for further appends.  Caller frees each string
 * and the array.
 */
uint64_t
hpn_strlist_drain(struct hpn_strlist *l, char ***out, size_t *out_used)
{
	uint64_t total;
	pthread_mutex_lock(&l->mu);
	total = l->total;
	if (out != NULL && out_used != NULL) {
		*out_used = l->used;
		if (l->used > 0) {
			*out = xcalloc(l->used, sizeof(**out));
			for (size_t i = 0; i < l->used; i++)
				(*out)[i] = l->items[i];   /* transfer ownership */
		} else {
			*out = NULL;
		}
	}
	/* Reset the list so subsequent appends start fresh. */
	if (l->items != NULL)
		memset(l->items, 0, l->cap * sizeof(*l->items));
	l->used  = 0;
	l->total = 0;
	pthread_mutex_unlock(&l->mu);
	return total;
}

/* ---------- Worker thread ---------- */

/*
 * Pending-counter trace: enabled when SFTP_PENDING_TRACE=1 in the
 * environment.  Writes one line per inc/dec to stderr so we can pair
 * them post-run and find any leaks.  Cheap when disabled.
 */
/* ── BEGIN Phase 4 gap 1: pipelined-batch helpers ─────────────────────────
 *
 * Three helpers manage the deferred phase-5 state across parallel_worker_thread
 * iterations:
 *
 *   worker_finalize_one_entry
 *     Records the result of a single batch entry: success → completion;
 *     failure → retry (re-queue) or maximum-retries-give-up.  Mirrors the
 *     existing inline result loop in parallel_worker_thread.
 *
 *   worker_drain_pipeline
 *     Calls sftp_upload_batch_finish on the carry-over prev batch (if
 *     any), processes per-entry results, frees the heap arrays.  Called
 *     before handling any non-batch work and at parallel_worker_thread exit.
 *
 *   worker_run_batch_pipelined
 *     Replaces the synchronous sftp_upload_batch() call.  Allocates heap
 *     entry/unit arrays so they survive across the next iteration, calls
 *     sftp_upload_batch_send (which drains prev as part of its phase 1),
 *     finalises prev (if there was one), then saves THIS batch as the
 *     new prev.  On send failure, finalises this batch inline (no carry).
 *
 * HPN_NO_BATCH_PIPELINE=1 in the environment disables the pipelining at
 * worker startup; the worker falls back to the legacy sftp_upload_batch
 * call.  Useful for A/B testing and for bisecting regressions without a
 * rebuild.
 * ──────────────────────────────────────────────────────────────────────── */

/* ── END Phase 4 gap 1 ────────────────────────────────────────────────── */

/* ── BEGIN Phase 5: bundle-mode batch dispatch ────────────────────────────
 *
 * worker_run_bundle is the bundle-mode analogue of
 * worker_run_batch_pipelined.  When w->bundle_enabled the worker calls
 * this instead - the batch of small files is packed into a single tar
 * stream and shipped through one OPEN/WRITE×N/CLOSE on a fresh bundle
 * handle.  This eliminates the per-file open/close round-trip that limits
 * Phase 4's pipelined batch path on high-RTT links.
 *
 * Per-entry success is signalled via the result field (set by
 * sftp_hpn_bundle_upload): on bundle failure every entry is marked -1, the
 * units retry through the normal worker_finalize_one_entry path, and the
 * batch is requeued unit-by-unit (no batch-wide retry needed since the
 * units are still individual work-queue entries).
 *
 * Synchronous in this first cut: no overlap with the next batch.  Could
 * be relaxed later by splitting send/finish like Phase 4 gap 1; not worth
 * the complexity until benchmarks show bundle close latency is a problem.
 * ────────────────────────────────────────────────────────────────────── */

/* ── END Phase 5 ──────────────────────────────────────────────────────── */

/* ---------- Reporter thread ---------- */

/*
 * Adaptive throughput-based stall detection (first pass).
 *
 * For each worker, computes kbps since the last tick.  Identifies the
 * fastest worker (max_kbps).  If the path looks healthy (max_kbps >=
 * cfg.tput_path_healthy_kbps), increments outlier_ticks for any worker
 * whose kbps is dramatically below max.  Returns the per-worker outlier
 * tick count via *worker_outlier_ticks[i] (caller-allocated array of
 * length p->num_workers; must be called under workers_mu).
 *
 * The caller (parallel_watchdog_check) combines this with the existing
 * time-based and ssh-child-existence checks to make final classifications.
 *
 * FUTURE: a server-side query (e.g. hpn-conn-stats@hpnssh.org SSH global
 * request) could provide an independent signal about each worker's
 * receive-side state - useful when the local-side tput estimate is
 * noisy or when we want to confirm the rwnd rescue has already fired.
 * For now we rely on local bytes_total deltas only.
 */

/*
 * Watchdog: classify each worker as HEALTHY/STALLED/DEAD based on (a) its
 * ssh child's existence and (b) elapsed time since last completion when
 * the queue had work to feed it, and (c) adaptive throughput-outlier
 * detection (if cfg.tput_path_healthy_kbps > 0). Returns nonzero if any
 * worker has transitioned to DEAD, signaling the reporter to abort the
 * orchestrator.
 */

/* ---------- Public API ---------- */

/*
 * Spawn one worker: SSH child via the master's socket, sftp_init, attach
 * to p->workers[] under workers_mu, then start the thread.  Returns the
 * worker on success, NULL on failure (with all resources cleaned up).
 * Used by sftp_parallel_start (during initial bring-up) and by the
 * reporter's respawn dispatch when a worker has died.
 */
/* ---------- Parallel spawn helper ---------- */

/* ---------- Public API ---------- */

struct sftp_parallel *
sftp_parallel_start(const struct sftp_parallel_config *cfg)
{
	if (cfg == NULL || cfg->host == NULL || cfg->num_streams < 1 ||
	    cfg->num_streams > SFTP_PARALLEL_MAX_WORKERS) {
		errno = EINVAL;
		return NULL;
	}

	/* Fresh fleet: clear the process-wide user-abort mirror left by a
	 * previous orchestrator's interrupt (the post-interrupt rebuild). */
	parallel_user_abort_flag = 0;

	struct sftp_parallel *p = xcalloc(1, sizeof(*p));
	p->cfg = *cfg;
	/* cfg.port may point to a stack buffer in the caller that is only
	 * valid until the enclosing scope exits.  Copy it into p->cfg_port_buf
	 * so the orchestrator owns the string for its entire lifetime. */
	if (cfg->port && cfg->port[0]) {
		strlcpy(p->cfg_port_buf, cfg->port, sizeof(p->cfg_port_buf));
		p->cfg.port = p->cfg_port_buf;
	}
	pthread_mutex_init(&p->pending_mu, NULL);
	pthread_cond_init(&p->pending_cv, NULL);
	pthread_mutex_init(&p->workers_mu, NULL);
	pthread_mutex_init(&p->bundle_mu, NULL);

	p->session_start_ns = monotime_ns();

	/* Fleet-abort zero-progress window (HPN_NOPROGRESS_ABORT_SEC, default
	 * FLEET_ABORT_NOPROGRESS_SEC).  The abort also requires no worker heart-
	 * beating and FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams unproductive
	 * respawns (see parallel_watchdog_sync_check); this knob only sizes the
	 * window.  0 disables
	 * the abort entirely. */
	{
		const char *e = getenv("HPN_NOPROGRESS_ABORT_SEC");
		p->noprogress_abort_s = (e && *e) ? atoi(e)
		    : FLEET_ABORT_NOPROGRESS_SEC;
		if (p->noprogress_abort_s < 0) p->noprogress_abort_s = 0;
	}

	/* ENV-VAR HPN_TAIL_REDISTRIBUTE=1: arm phase C tail redistribution
	 * (cooperative yield of a confirmed-lagging endgame holder).  Default
	 * off: the tail detector stays telemetry-only. */
	{
		const char *e = getenv("HPN_TAIL_REDISTRIBUTE");
		p->tail_redistribute = (e != NULL && *e == '1');
	}

	/* ENV-VAR HPN_RESPAWN_SCAN_IDLE=1: defer fleet-restoring respawns
	 * while READY healthy workers cover the queued demand.  Default off;
	 * see parallel_respawn_dispatch. */
	{
		const char *e = getenv("HPN_RESPAWN_SCAN_IDLE");
		p->respawn_scan_idle = (e != NULL && *e == '1');
	}
	p->last_worker_exit_code = -1;	/* no worker reaped yet */
	/* Born-dead 0-bytes kill threshold.  RTT-derived once the path RTT is
	 * registered (sftp_parallel_set_path_rtt); BORN_DEAD_KILL_SEC until then. */
	p->born_dead_sec = BORN_DEAD_KILL_SEC;
	p->born_dead_stuck_offset = -1;	/* 0 is a valid range_offset */

	/* Cap chosen so the worst-case allocation is bounded but the
	 * "show me what failed" list is still useful for moderately
	 * broken transfers.  HPN_FAILED_PATHS_MAX × ~256 bytes typical
	 * = ~25 KiB at the default cap. */
	hpn_strlist_init(&p->failed_paths, HPN_FAILED_PATHS_MAX);
	hpn_strlist_init(&p->verify_failed_paths, HPN_FAILED_PATHS_MAX);

	/* 1. Workqueue. Sized for cfg->num_streams.  Respawned workers
	 * reuse the same queue, so capacity is set once at startup. */
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
	 * under the server's MaxStartups limit (default 10:30:100). */
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

	/* HPN_ASYNC_VERIFY (env, default off): start the decoupled verify worker
	 * (its own connection) so transfer workers hand off finished files instead
	 * of blocking on the server read-back.  Only meaningful when verify is on;
	 * a failed start silently leaves async_verify=0 (inline verify). */
	{
		/* Async verify pool is ON by default, sized to the transfer fleet
		 * (one verify worker per stream preserves the inline path's
		 * parallel verify - see the single-worker j4 regression).  Override
		 * with HPN_ASYNC_VERIFY=N to force pool size N, or =0 to disable
		 * (fall back to inline verify on the transfer workers). */
		const char *av = getenv("HPN_ASYNC_VERIFY");
		int navp = (av != NULL) ? atoi(av) : p->cfg.num_streams;

		if (navp >= 1 && p->cfg.verify_transfer &&
		    parallel_verify_worker_start(p, navp) >= 1)
			__atomic_store_n(&p->async_verify, 1, __ATOMIC_RELAXED);
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

/* Defined later in this file. */

void
sftp_parallel_wait(struct sftp_parallel *p)
{
	if (p == NULL) return;
	/* Push the last partially-filled bundle (the tail) before waiting.
	 * Entering wait is the universal "done submitting" point for every
	 * command - directory walks and direct (non-walker) put/get alike -
	 * so the tail bundle can't be left stranded in the accumulator. */
	parallel_bundle_flush_pending(p);
	/* The caller drains only after a command has finished submitting, so
	 * entering wait IS the "no more units coming" signal.  Publish it as
	 * walker-phase DONE: for direct (non-walker) puts/gets nothing else
	 * ever sets DONE, leaving the endgame machinery (range split,
	 * straggler reaper) permanently gated off.  The walker's own DONE at
	 * the end of a directory walk makes this a no-op there.  The public
	 * submit entry points demote DONE back to SUBMIT, so the next
	 * interactive command re-gates correctly; the internal parallel_unit_submit() does
	 * NOT demote, because endgame-split pieces are submitted from a
	 * worker thread mid-drain and must not un-arm the endgame state. */
	__atomic_store_n(&p->walker_phase, SFTP_WKP_DONE, __ATOMIC_RELAXED);
	pthread_mutex_lock(&p->pending_mu);
	while (p->pending > 0 && !p->abort_flag)
		pthread_cond_wait(&p->pending_cv, &p->pending_mu);
	pthread_mutex_unlock(&p->pending_mu);

	/* Transfers done: every finished file's tracker was enqueued before its
	 * unit decremented pending, so the verify queue now holds them all.
	 * Drain + join the async verify worker so we don't return before the
	 * decoupled verifies finish and record any failures.  No-op unless
	 * HPN_ASYNC_VERIFY is active. */
	parallel_verify_worker_drain(p);
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
    volatile sig_atomic_t *flag)
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
			pthread_mutex_lock(&p->pending_mu);
			if (p->pending > 0)
				p->pending--;
			pthread_mutex_unlock(&p->pending_mu);
			(void)parallel_unit_tracker_finalize(u->range_tracker, 1, NULL);
			parallel_unit_free(u);
		}
	}

	if (p->stats_csv != NULL) {
		fclose(p->stats_csv);
		p->stats_csv = NULL;
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
	pthread_mutex_destroy(&p->bundle_mu);
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

void
sftp_parallel_progress_start(struct sftp_parallel *p, const char *label,
    off_t total_bytes)
{
	if (p == NULL || p->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	strlcpy(p->progress_label, label, sizeof(p->progress_label));
	/* Snapshot current accumulated bytes across all workers so the meter
	 * shows only bytes moved in this transfer, not prior transfers in the
	 * same session. */
	parallel_stats_snapshot(p, &p->progress_bytes_baseline, NULL, NULL);
	p->aggregate_progress_counter = 0;
	start_progress_meter(p->progress_label, total_bytes,
	    &p->aggregate_progress_counter);
	p->progress_meter_started = 1;
}

void
sftp_parallel_progress_stop(struct sftp_parallel *p)
{
	uint64_t bytes = 0;

	if (p == NULL || !p->progress_meter_started)
		return;
	/* The reporter advances the aggregate counter only on its tick, so
	 * a transfer's final bytes land between ticks and the meter's
	 * forced last refresh paints a stale 99%.  Snapshot once more here
	 * so stop_progress_meter's completion refresh shows true 100%. */
	parallel_stats_snapshot(p, &bytes, NULL, NULL);
	if (bytes >= p->progress_bytes_baseline)
		p->aggregate_progress_counter =
		    (off_t)(bytes - p->progress_bytes_baseline);
	p->progress_meter_started = 0;
	stop_progress_meter();
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

#define PARALLEL_MAX_DIR_DEPTH 64


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

	if (p->session_start_ns != 0)
		out->elapsed_ms =
		    (monotime_ns() - p->session_start_ns) / 1000000ULL;
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


