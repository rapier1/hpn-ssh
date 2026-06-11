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

/* Forward decl - hpn_strlist_append is defined below this point but
 * sftp_parallel_walker_record_failure (defined here) needs it.  Avoids reordering
 * the file. */
static void hpn_strlist_append(struct hpn_strlist *l, const char *s);

/*
 * Worker-side failed-path recorder.  Formats "path: cause" and appends
 * to the orchestrator's failed-paths list.  If `explicit_cause` is
 * NULL we pull from hpn_get_last_error() - the TLS-captured most-
 * recent ERROR-level log message on this thread, set automatically
 * inside do_log().  This is how a failed sftp_upload / sftp_download
 * gets its error text into the summary without any plumbing through
 * the RPC API.
 *
 * Falls back to "(no error captured)" when neither source has a
 * message - shouldn't happen in practice for a real give-up.
 *
 * Called only at give-up sites in worker_process_result and
 * worker_finalize_one_entry (NOT on retry).
 */
static void
worker_record_failed_path(struct sftp_parallel *p,
    struct sftp_work_unit *u, const char *explicit_cause)
{
	char        buf[PATH_MAX + 256];
	const char *path = (u && u->src_path) ? u->src_path : "(unknown)";
	const char *cause;

	if (explicit_cause != NULL && *explicit_cause != '\0') {
		cause = explicit_cause;
	} else {
		const char *captured = hpn_get_last_error();
		cause = (captured && *captured)
		    ? captured : "(no error captured)";
	}

	snprintf(buf, sizeof(buf), "%s: %s", path, cause);
	hpn_strlist_append(&p->failed_paths, buf);

	/* Reset so the next failure on this thread starts clean instead
	 * of stale.  Captured-error contract: it reflects the most recent
	 * error AT THE TIME we record the failure. */
	hpn_clear_last_error();
}

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
static void
hpn_strlist_init(struct hpn_strlist *l, size_t cap)
{
	pthread_mutex_init(&l->mu, NULL);
	l->cap   = cap;
	l->used  = 0;
	l->total = 0;
	l->items = (cap > 0) ? xcalloc(cap, sizeof(*l->items)) : NULL;
}

static void
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
static void
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
static uint64_t
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

static void
worker_record_start(struct sftp_worker *w)
{
	pthread_mutex_lock(&w->mu);
	w->units_started++;
	pthread_mutex_unlock(&w->mu);
}

static void
worker_record_completion(struct sftp_worker *w, off_t bytes, int success)
{
	pthread_mutex_lock(&w->mu);
	if (success) {
		w->bytes_total += (uint64_t)bytes;
		w->units_completed++;
	} else {
		w->units_failed++;
	}
	/* Reset live_bytes so the completed file's bytes aren't counted twice
	 * (once here in bytes_total and once via the live_counter hook). */
	__atomic_store_n(&w->live_bytes, 0, __ATOMIC_RELAXED);
	w->last_completion_ns = monotime_ns();
	pthread_mutex_unlock(&w->mu);
}

/*
 * Pending-counter trace: enabled when SFTP_PENDING_TRACE=1 in the
 * environment.  Writes one line per inc/dec to stderr so we can pair
 * them post-run and find any leaks.  Cheap when disabled.
 */
/*
 * HPNVerifyTransfer (parallel): verify one just-transferred whole file
 * end-to-end on the worker's connection and record a mismatch in the
 * orchestrator's thread-safe verify_failed_paths list.  Never fails the
 * unit - a mismatch is surfaced in the summary + exit code, not retried.
 */
static void
parallel_verify_one(struct sftp_worker *w, const char *local_path,
    const char *remote_path)
{
	struct sftp_parallel *p = w->parent;
	int r = sftp_verify_transfer(w->conn, local_path, remote_path);

	if (r == 0)
		return;	/* verified good */
	if (r < 0) {
		logit("worker %d VERIFY SKIPPED: \"%s\": server lacks "
		    "hpn-check-file@hpnssh.org or read error",
		    w->id, remote_path);
		return;
	}
	error_f("worker %d VERIFY FAILED: \"%s\" post-transfer hash "
	    "mismatch - transferred file does NOT match source",
	    w->id, remote_path);
	hpn_strlist_append(&p->verify_failed_paths, remote_path);
}

static int
execute_unit(struct sftp_worker *w, struct sftp_work_unit *u)
{
	struct sftp_parallel *p = w->parent;
	int rc = -1;

	switch (u->op) {
	case SFTP_OP_UPLOAD:
		/*
		 * Resume gate (Option A): u->verify makes sftp_upload hash even
		 * on a size match (closes the sparse-hole gap).  resume/verify
		 * are per-unit (the originating command's intent); the
		 * unsupported-remote fatal already fired up front in the main
		 * thread (see sftp_parallel_submit_upload), so the worker never
		 * fatals here.  Return 1/2 are "already complete" skip codes -
		 * map to success below so the unit isn't retried.
		 */
		rc = sftp_upload(w->conn, u->src_path, u->dst_path,
		    p->cfg.preserve_flag, u->resume, /*verify=*/u->verify,
		    p->cfg.fsync_flag, p->cfg.inplace_flag);
		if (rc == 0 && p->cfg.verify_transfer)
			parallel_verify_one(w, u->src_path, u->dst_path);
		if (rc == 1 || rc == 2)
			rc = 0;	/* identical / target-larger: complete */
		break;
	case SFTP_OP_UPLOAD_RANGE:
		/* Range-split resume gate + post-transfer verify happen at
		 * the orchestrator/finalize level, not per-range; see
		 * project_parallel_resume_verify_design (Phase 1 follow-up). */
		rc = sftp_upload_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length);
		break;
	case SFTP_OP_DOWNLOAD_RANGE:
		rc = sftp_download_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length);
		break;
	case SFTP_OP_DOWNLOAD:
		rc = sftp_download(w->conn, u->src_path, u->dst_path,
		    /*Attrib*/NULL, p->cfg.preserve_flag,
		    u->resume, p->cfg.fsync_flag,
		    p->cfg.inplace_flag, /*verify=*/u->verify);
		if (rc == 0 && p->cfg.verify_transfer)
			parallel_verify_one(w, u->dst_path, u->src_path);
		if (rc == 1 || rc == 2)
			rc = 0;	/* identical / target-larger: complete */
		break;
	}
	return rc;
}

/*
 * Permanent give-up of a work unit after MAX_RETRIES.  Snapshots the
 * cause from the TLS-captured most-recent ERROR log BEFORE the give-up
 * log clobbers it, then does all the bookkeeping in one place:
 *   - log give-up at error level
 *   - record per-worker completion as failure
 *   - decrement orchestrator pending counter
 *   - finalize range tracker (NULL-safe; only meaningful for range units)
 *   - append path + cause to failed-paths list
 *   - free the unit
 *
 * `log_prefix` distinguishes the caller in the give-up log ("unit" for
 * single-unit dispatch, "batch unit" for pipelined-batch).  `trace_tag`
 * is the pending-trace tag string.
 */
static void
worker_give_up_unit(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, const char *log_prefix,
    const char *trace_tag)
{
	char        cause[256];
	const char *captured = hpn_get_last_error();

	strlcpy(cause,
	    (captured && *captured) ? captured : "(no error captured)",
	    sizeof(cause));

	error_f("worker %d: %s failed after %d attempts: %s",
	    w->id, log_prefix, u->attempt,
	    u->src_path ? u->src_path : "(null)");
	worker_record_completion(w, 0, 0);
	parallel_unit_pending_dec_traced(p, u, w->id, trace_tag);
	(void)parallel_unit_tracker_finalize(u->range_tracker, 1, w);
	worker_record_failed_path(p, u, cause);
	parallel_unit_free(u);
}

/*
 * Push-fail give-up: the workqueue refused our retry submission
 * (shutdown in progress), so this unit can never run.  Same bookkeeping
 * as worker_give_up_unit but with an explicit cause string ("queue
 * shutdown") and no give-up log line - the push-fail itself is the
 * diagnostic.
 *
 * Caller must have already failed sftp_workqueue_push BEFORE calling
 * this; we just clean up.
 */
static void
worker_give_up_pushfail(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, const char *trace_tag)
{
	if (u->size > 0)
		__atomic_fetch_sub(&p->queued_bytes,
		    (uint64_t)u->size, __ATOMIC_RELAXED);
	worker_record_completion(w, 0, 0);
	parallel_unit_pending_dec_traced(p, u, w->id, trace_tag);
	(void)parallel_unit_tracker_finalize(u->range_tracker, 1, w);
	worker_record_failed_path(p, u, "queue shutdown");
	parallel_unit_free(u);
}

/* Handle the result of executing a single work unit (retry or completion). */
static void
worker_process_result(struct sftp_worker *w, struct sftp_work_unit *u, int rc)
{
	struct sftp_parallel *p = w->parent;

	/* HPN: free the per-inode writer slot claimed in parallel_worker_thread's
	 * dispatch gate.  Reached exactly once per executed unit on every
	 * path (success, retry-requeue, give-up), so retries release here and
	 * re-acquire when re-dispatched.  NULL tracker (non-range) = no-op. */
	parallel_unit_writer_release(u->range_tracker);

	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		parallel_unit_pending_dec_traced(p, u, w->id, "wpr/success");
		/* Range tracker: this range finished cleanly.  Last
		 * completer for the file frees the tracker. */
		(void)parallel_unit_tracker_finalize(u->range_tracker, 0, w);
		parallel_unit_free(u);
	} else {
		/*
		 * Failure.  A dead connection (wedge / peer-stall / transport
		 * drop) is a TRANSIENT, blameless failure: this worker is about
		 * to break the main loop and be respawned, so we re-queue the
		 * unit WITHOUT charging u->attempt - peer-stall churn must not
		 * burn the retry budget and abandon the byte-range (the br008
		 * j8 data-loss bug).  Only a failure on a still-LIVE connection
		 * (ambiguous server error) charges u->attempt and stays bounded
		 * by MAX_RETRIES.
		 *
		 * Re-queue position differs by class:
		 *   transient -> push_front: the worker exits, so a different
		 *     worker pops this unit next; jumping ahead of fresh work
		 *     lets the partially-complete file (and its range tracker)
		 *     finish promptly instead of waiting behind the whole queue.
		 *   ambiguous -> push (tail): the SAME live worker loops back
		 *     and would otherwise immediately re-pop and re-fail the
		 *     unit, burning MAX_RETRIES in a tight loop; the tail gives
		 *     the transient condition time to clear before the retry.
		 */
		int transient = sftp_conn_is_dead(w->conn);
		if (transient || ++u->attempt < parallel_unit_max_retries(p)) {
			if (u->size > 0)
				__atomic_fetch_add(&p->queued_bytes,
				    (uint64_t)u->size, __ATOMIC_RELAXED);
			if (parallel_unit_pending_trace_on())
				parallel_unit_pending_trace("REQUEUE", p, u, w->id,
				    transient ? "wpr/transient" : "wpr/retry");
			if ((transient
			    ? sftp_workqueue_push_front(p->q, u)
			    : sftp_workqueue_push(p->q, u)) != 0)
				worker_give_up_pushfail(p, w, u, "wpr/pushfail");
		} else {
			worker_give_up_unit(p, w, u, "unit", "wpr/maxretries");
		}
	}
}

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

static void
worker_finalize_one_entry(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, int rc)
{
	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		parallel_unit_pending_dec_traced(p, u, w->id, "batch/success");
		parallel_unit_free(u);
		return;
	}
	int transient = sftp_conn_is_dead(w->conn);
	if (transient || ++u->attempt < parallel_unit_max_retries(p)) {
		/*
		 * Transient (dead-conn) failures re-queue WITHOUT charging
		 * u->attempt and jump to the FRONT so the partial file finishes
		 * promptly; ambiguous (live-conn) failures charge the budget
		 * and go to the TAIL.  See the full rationale in
		 * worker_process_result.
		 */
		__atomic_store_n(&w->live_bytes, 0, __ATOMIC_RELAXED);
		if (u->size > 0)
			__atomic_fetch_add(&p->queued_bytes,
			    (uint64_t)u->size, __ATOMIC_RELAXED);
		if (parallel_unit_pending_trace_on())
			parallel_unit_pending_trace("REQUEUE", p, u, w->id,
			    transient ? "batch/transient" : "batch/retry");
		if ((transient
		    ? sftp_workqueue_push_front(p->q, u)
		    : sftp_workqueue_push(p->q, u)) != 0)
			worker_give_up_pushfail(p, w, u, "batch/pushfail");
		return;
	}
	worker_give_up_unit(p, w, u, "batch unit", "batch/maxretries");
}

static void
worker_drain_pipeline(struct sftp_worker *w)
{
	struct sftp_parallel *p = w->parent;
	if (w->batch_prev_pending == NULL)
		return;
	(void)sftp_upload_batch_finish(w->conn, w->batch_prev_pending);
	for (int i = 0; i < w->batch_prev_n; i++)
		worker_finalize_one_entry(p, w,
		    w->batch_prev_units[i],
		    w->batch_prev_entries[i].result);
	free(w->batch_prev_units);
	free(w->batch_prev_entries);
	w->batch_prev_pending = NULL;
	w->batch_prev_units   = NULL;
	w->batch_prev_entries = NULL;
	w->batch_prev_n       = 0;
}

static void
worker_run_batch_pipelined(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_upload_batch_entry *entries;
	struct sftp_work_unit **units;
	struct sftp_upload_batch_pending *new_pending;

	if (w->batch_pipe_disabled) {
		/* Legacy un-pipelined path - kept verbatim from the
		 * pre-Phase-4 implementation for A/B comparison. */
		struct sftp_upload_batch_entry stack_entries[UPLOAD_BATCH_SIZE];
		for (int i = 0; i < bn; i++) {
			stack_entries[i].local_path  = batch[i]->src_path;
			stack_entries[i].remote_path = batch[i]->dst_path;
			stack_entries[i].result      = 0;
			worker_record_start(w);
		}
		sftp_upload_batch(w->conn, stack_entries, bn,
		    p->cfg.preserve_flag, p->cfg.fsync_flag,
		    p->cfg.inplace_flag);
		for (int i = 0; i < bn; i++)
			worker_finalize_one_entry(p, w, batch[i],
			    stack_entries[i].result);
		return;
	}

	/* Pipelined path: heap-allocate the entry and unit arrays so they
	 * survive across the next parallel_worker_thread iteration. */
	entries = xcalloc(bn, sizeof(*entries));
	units   = xcalloc(bn, sizeof(*units));
	for (int i = 0; i < bn; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		units[i]               = batch[i];
		worker_record_start(w);
	}

	/* send() drains batch_prev_pending (if any) AFTER its phase 1
	 * OPENs are on the wire - that overlap is the win. */
	new_pending = sftp_upload_batch_send(w->conn, entries, bn,
	    p->cfg.preserve_flag, p->cfg.fsync_flag,
	    p->cfg.inplace_flag,
	    w->batch_prev_pending);
	/* batch_prev_pending has been freed inside send. */
	w->batch_prev_pending = NULL;

	/* Now finalise the prev batch's results (entries already populated
	 * by the drain that just ran inside send). */
	if (w->batch_prev_units != NULL) {
		for (int i = 0; i < w->batch_prev_n; i++)
			worker_finalize_one_entry(p, w,
			    w->batch_prev_units[i],
			    w->batch_prev_entries[i].result);
		free(w->batch_prev_units);
		free(w->batch_prev_entries);
		w->batch_prev_units   = NULL;
		w->batch_prev_entries = NULL;
		w->batch_prev_n       = 0;
	}

	if (new_pending == NULL) {
		/* THIS batch's send failed.  Every entry has result == -1;
		 * finalise inline and don't carry over. */
		for (int i = 0; i < bn; i++)
			worker_finalize_one_entry(p, w, units[i],
			    entries[i].result);
		free(units);
		free(entries);
	} else {
		/* Save this batch as the new prev for the next iteration. */
		w->batch_prev_pending = new_pending;
		w->batch_prev_units   = units;
		w->batch_prev_entries = entries;
		w->batch_prev_n       = bn;
	}
}
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

static void
worker_run_bundle(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_hpn_bundle_upload_entry *entries;
	uint64_t total_bytes = 0;
	int i, ok_count = 0;
	uint64_t t_start_ns, t_end_ns, elapsed_us;

	entries = xcalloc(bn, sizeof(*entries));
	for (i = 0; i < bn; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(w);
	}

	/* Phase-5 instrumentation: per-bundle wall time.  Always-on; one
	 * stderr line per bundle.  Format chosen so the harness can grep
	 * "BUNDLE worker=" and parse the key=value fields. */
	t_start_ns = monotime_ns();

	/* dest_dir = "" - each remote_path is treated as an absolute path
	 * by the server-side bundle handler.  This avoids needing to
	 * compute a common prefix across the batch; the server's bundle
	 * extractor calls mkdir_p on each containing directory anyway.
	 * Slight wire-size cost (full path repeated in every tar header)
	 * but trivial compared to the small-file payloads. */
	int bundle_rc = sftp_hpn_bundle_upload(w->conn, "", entries, bn,
	    p->cfg.preserve_flag, p->cfg.fsync_flag);

	t_end_ns = monotime_ns();
	elapsed_us = (t_end_ns - t_start_ns) / 1000ULL;
	for (i = 0; i < bn; i++)
		if (entries[i].result == 0)
			ok_count++;
	{
		double mibps = 0.0;
		if (elapsed_us > 0)
			mibps = ((double)total_bytes /
			    (1024.0 * 1024.0)) /
			    ((double)elapsed_us / 1e6);
		logit("BUNDLE worker=%d files=%d ok=%d bytes=%llu "
		    "elapsed_us=%llu MiBps=%.2f",
		    w->id, bn, ok_count,
		    (unsigned long long)total_bytes,
		    (unsigned long long)elapsed_us, mibps);
	}

	/*
	 * Downgrade to single-file ONLY when the server itself can't bundle
	 * (SERVER_CANT: refused open / no extension) - a permanent, connection-
	 * agnostic reason any worker would hit.  A TRANSPORT_FAILED (this
	 * worker's connection died mid-bundle) is NOT such a reason: the units
	 * bundle fine on a healthy worker, so leave them eligible and let
	 * worker_finalize_one_entry re-queue them (the dead-conn transient
	 * path).  Marking them ineligible here was the bundle-ineligible
	 * poisoning that dragged the whole fleet to single-file speed when a
	 * few connections wedged (2026-06-05 8-pass campaign).
	 */
	if (bundle_rc == SFTP_HPN_BUNDLE_SERVER_CANT) {
		for (i = 0; i < bn; i++)
			batch[i]->bundle_ineligible = 1;
	}

	for (i = 0; i < bn; i++)
		worker_finalize_one_entry(p, w, batch[i], entries[i].result);

	free(entries);
}

/*
 * Download-side counterpart of worker_run_bundle.  Builds the entries
 * array from a batch of SFTP_OP_DOWNLOAD units (src_path = remote,
 * dst_path = local), asks the server to pack the listed paths via
 * sftp_hpn_bundle_download, then finalises each work unit with its
 * per-entry result.
 *
 * Mirrors worker_run_bundle's failure handling: per-entry result is
 * propagated through worker_finalize_one_entry, which re-queues on
 * failure via the normal retry path.  If the whole transaction fails
 * (server refused extension, mid-stream wire error), every entry is
 * marked -1 and each gets retried individually.
 */
static void
worker_run_bundle_download(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_hpn_bundle_download_entry *entries;
	uint64_t total_bytes = 0;
	int i, ok_count = 0;
	uint64_t t_start_ns, t_end_ns, elapsed_us;

	entries = xcalloc(bn, sizeof(*entries));
	for (i = 0; i < bn; i++) {
		entries[i].remote_path = batch[i]->src_path;
		entries[i].local_path  = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(w);
	}

	t_start_ns = monotime_ns();
	int bundle_rc = sftp_hpn_bundle_download(w->conn, entries, bn,
	    p->cfg.preserve_flag);
	t_end_ns = monotime_ns();
	elapsed_us = (t_end_ns - t_start_ns) / 1000ULL;
	for (i = 0; i < bn; i++)
		if (entries[i].result == 0)
			ok_count++;
	{
		double mibps = 0.0;
		if (elapsed_us > 0)
			mibps = ((double)total_bytes / (1024.0 * 1024.0)) /
			    ((double)elapsed_us / 1e6);
		logit("BUNDLE-DL worker=%d files=%d ok=%d bytes=%llu "
		    "elapsed_us=%llu MiBps=%.2f",
		    w->id, bn, ok_count,
		    (unsigned long long)total_bytes,
		    (unsigned long long)elapsed_us, mibps);
	}

	/* Cause-scoped downgrade (see worker_run_bundle): only SERVER_CANT
	 * (server refused / no extension) forces the per-file path; a
	 * TRANSPORT_FAILED leaves the units bundle-eligible for a healthy
	 * worker. */
	if (bundle_rc == SFTP_HPN_BUNDLE_SERVER_CANT) {
		for (i = 0; i < bn; i++)
			batch[i]->bundle_ineligible = 1;
	}

	for (i = 0; i < bn; i++)
		worker_finalize_one_entry(p, w, batch[i], entries[i].result);

	free(entries);
}
/* ── END Phase 5 ──────────────────────────────────────────────────────── */

/*
 * Execute a single work unit through the non-batch path: drain any
 * deferred pipelined batch (its STATUSes would corrupt the next RPC),
 * mark the worker as actively working, run execute_unit, log the
 * dispatch-diag line, hand the result to worker_process_result.
 *
 * Used in three places by parallel_worker_thread:
 *   - the `bn == 1` branch (batch loop collected only one unit)
 *   - the leftover-after-batch dispatch
 *   - the outer else branch (DOWNLOAD without bundle, RANGE ops,
 *     mkdir, etc.)
 */
static void
worker_execute_single(struct sftp_worker *w, struct sftp_work_unit *u)
{
	worker_drain_pipeline(w);
	worker_record_start(w);
	int rc = execute_unit(w, u);
	debug_ft("dispatch-diag: worker %d executed op=%d rc=%d "
	    "offset=%lld length=%lld",
	    w->id, (int)u->op, rc,
	    (long long)u->range_offset,
	    (long long)u->range_length);
	worker_process_result(w, u, rc);
}

/*
 * Endgame range split: called by a worker holding a just-popped unit u when
 * that pop may have emptied the queue.  If the walker is done, the queue is
 * empty, and u is a large byte-range - i.e. u is the transfer's last
 * un-started unit - shrink u in place to its first piece and submit the
 * remaining pieces as sibling range units (same tracker) so idle workers
 * drain the tail in parallel instead of this worker grinding the whole
 * range solo.  One-shot per transfer (the gate is set only when a split
 * actually fires, so a final whole-file or bundle unit does not burn it).
 *
 * Tracker accounting: each piece owes exactly one finalize, so total and
 * remaining grow by the added piece count under the tracker mutex BEFORE
 * any piece is visible to other workers.  remaining >= 1 holds throughout
 * (u itself is still un-finalized), so last-completer cleanup cannot race
 * the split.  On a submit failure the unsent pieces are finalized-as-failed,
 * the same synthesis submit_upload_ranges uses; the file then surfaces as
 * INCOMPLETE/resumable.
 *
 * Accounting context: the caller has already subtracted u's full original
 * size from queued_bytes (dispatch path), so submitting pieces 1..n-1 via
 * parallel_unit_submit() re-adds exactly the bytes that are genuinely queued again, and
 * pending grows by one per piece - both consistent.
 *
 * ENV-VAR HPN_ENDGAME_SPLIT_N - developer-only: override the piece count
 * for tail-length sweeps; unset/0 = the file's writer cap (-w), which fits
 * exactly one wave of writers under the per-inode gate.
 */
static void
maybe_endgame_split(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u)
{
	struct sftp_range_tracker *t = u->range_tracker;
	off_t piece, end;
	int n, i;

	if (__atomic_load_n(&p->endgame_split_fired, __ATOMIC_RELAXED))
		return;
	if (u->op != SFTP_OP_UPLOAD_RANGE && u->op != SFTP_OP_DOWNLOAD_RANGE)
		return;
	if (t == NULL || u->range_length < ENDGAME_SPLIT_MIN_LEN)
		return;
	if (__atomic_load_n(&p->walker_phase, __ATOMIC_RELAXED) !=
	    SFTP_WKP_DONE)
		return;
	if (p->abort_flag || p->stopped || sftp_workqueue_depth(p->q) != 0)
		return;

	{
		const char *e = getenv("HPN_ENDGAME_SPLIT_N");
		n = (e && *e) ? atoi(e) : 0;
	}
	if (n <= 0)
		n = t->writer_cap;
	if ((off_t)n > u->range_length / ENDGAME_SPLIT_MIN_PIECE)
		n = (int)(u->range_length / ENDGAME_SPLIT_MIN_PIECE);
	if (n < 2)
		return;

	/* Aligned piece size; recompute the real piece count since the
	 * alignment round-up can swallow the last fractional piece. */
	piece = (u->range_length / n + ENDGAME_SPLIT_ALIGN - 1) /
	    ENDGAME_SPLIT_ALIGN * ENDGAME_SPLIT_ALIGN;
	end = u->range_offset + u->range_length;
	n = (int)((u->range_length + piece - 1) / piece);
	if (n < 2)
		return;

	__atomic_store_n(&p->endgame_split_fired, 1, __ATOMIC_RELAXED);

	pthread_mutex_lock(&t->mu);
	t->total     += n - 1;
	t->remaining += n - 1;
	pthread_mutex_unlock(&t->mu);

	debug_f("endgame split: \"%s\" range %lld+%lld -> %d pieces of %lld",
	    u->dst_path, (long long)u->range_offset,
	    (long long)u->range_length, n, (long long)piece);
	if (getenv("HPN_BUNDLE_TIMING") != NULL)
		logit("HPN ENDGAME-SPLIT worker=%d len=%lld pieces=%d "
		    "piece=%lld", w->id, (long long)u->range_length, n,
		    (long long)piece);

	/* Shrink the held unit to piece 0; submit pieces 1..n-1. */
	u->range_length = piece;
	u->size         = piece;
	for (i = 1; i < n; i++) {
		off_t poff = u->range_offset + (off_t)i * piece;
		off_t plen = end - poff < piece ? end - poff : piece;
		struct sftp_work_unit *nu = parallel_unit_make_range(u->src_path,
		    u->dst_path, poff, plen, t);
		nu->op = u->op;	/* download pieces inherit DOWNLOAD_RANGE */
		if (parallel_unit_submit(p, nu) != 0) {
			error_f("endgame split: submit piece %d of \"%s\" "
			    "failed", i, u->dst_path);
			for (; i < n; i++)
				(void)parallel_unit_tracker_finalize(t, 1, NULL);
			return;
		}
	}
}

/*
 * One-time worker setup: signal mask, env-var parsing for the bundle
 * and batch-pipeline kill switches, and per-worker bundle target.
 * Sampled once at startup; survives the worker's lifetime.  Factored
 * out of parallel_worker_thread to keep the main loop body readable.
 */
static void
worker_thread_init(struct sftp_worker *w)
{
	/* Mask SIGALRM so progressmeter timer ticks deliver only to the
	 * main thread / reporter (which holds it unmasked). */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	/* DISPATCH-DIAG: worker has reached the main loop entry, fully
	 * past spawn_one_worker / sftp_init.  If a worker is alive in
	 * p->workers[] but this line never appears for its id, the
	 * parallel_worker_thread itself never got scheduled / never started. */
	debug_ft("dispatch-diag: worker %d entered main loop", w->id);

	/* Phase 4 gap 1: read the HPN_NO_BATCH_PIPELINE env once per worker.
	 * Disables the pipelined batch path; falls back to legacy
	 * sftp_upload_batch.  Useful for A/B testing and bisecting. */
	{
		/* ENV-VAR HPN_NO_BATCH_PIPELINE - developer-only: kill switch
		 * for Phase-4 pipelined upload batch.  Forces the legacy
		 * synchronous path for A/B testing.  Not user-facing. */
		const char *e = getenv("HPN_NO_BATCH_PIPELINE");
		if (e != NULL && *e != '\0' && *e != '0')
			w->batch_pipe_disabled = 1;
	}

	/* Phase 5 bundle-mode: ON by default when the server advertises
	 * hpn-bundle@hpnssh.org.  Disabled when:
	 *   - HPNUseBundle no   in ssh_config (resolved by sftp.c via
	 *                       `hpnssh -G host`; stored in p->cfg.use_bundle)
	 *   - server doesn't advertise the hpn-bundle extension
	 * Either forces the Phase-4 pipelined batch fallback. */
	w->bundle_target_bytes = (w->parent->cfg.bundle_size > 0)
	    ? w->parent->cfg.bundle_size
	    : BUNDLE_TARGET_BYTES;

	/* Server-advertised HPNMaxBundleSize (from sshd_config).  Clamp
	 * our chosen target so we never generate a bundle the server
	 * would reject mid-stream.  Worker 0 only - other workers either
	 * produce duplicate warnings or quietly inherit the same value. */
	{
		uint64_t srv_max =
		    sftp_conn_server_max_bundle_size(w->conn);
		if (srv_max > 0 && w->bundle_target_bytes > srv_max) {
			if (w->id == 0)
				logit("server caps HPNBundleSize at %llu "
				    "bytes; clamping from %llu",
				    (unsigned long long)srv_max,
				    (unsigned long long)
				    w->bundle_target_bytes);
			w->bundle_target_bytes = srv_max;
		}
	}

	if (w->parent->cfg.use_bundle == 0) {
		debug_ft("worker %d: bundle disabled by "
		    "ssh_config HPNUseBundle no", w->id);
	} else if (sftp_conn_has_hpn_bundle(w->conn)) {
		w->bundle_enabled = 1;
		debug_ft("worker %d: hpn-bundle enabled (target_bytes=%llu)",
		    w->id, (unsigned long long)w->bundle_target_bytes);
	} else {
		debug_ft("worker %d: server lacks hpn-bundle extension, "
		    "using Phase-4 batch fallback", w->id);
	}
}

/*
 * Post-iteration termination check: returns 1 if the worker should
 * break out of the main loop (protocol-violation strike 1, or
 * connection died), 0 otherwise.  Strike 2 fatal()s the process and
 * never returns.
 *
 * Protocol-violation two-strikes policy:
 *   Strike 1 - log loudly, bump p->protocol_violations.  The conn is
 *     already dead (set by sftp_hpn_set_protocol_violation in
 *     sftp-client.c) so we fall through to the conn_is_dead branch
 *     immediately below and break out.  Reporter's respawn machinery
 *     replaces us with a fresh SSH child; transfer continues.
 *   Strike 2 (lifetime per hpnsftp process) - sustained pattern,
 *     not bad luck.  fatal().  The OS reaps remaining SSH children
 *     when the parent dies.  Current unit cleanup was already done by
 *     worker_process_result / batch result loop.
 *
 * Threshold is a fixed count (2), not a rate: a correctly-functioning
 * server produces zero violations regardless of worker count or
 * transfer length - SSH MAC catches all in-channel tampering below
 * this layer.  Anything reaching here is, by definition, abnormal.
 *
 * Possible causes: random bit-flip on a long transfer (historical NIC
 * silicon bug - common, benign-but-noisy, want to tolerate one) or
 * buggy/compromised server / persistent hardware fault (rare but
 * serious - must not paper over).
 */
static int
worker_should_terminate(struct sftp_worker *w)
{
	struct sftp_parallel *p = w->parent;

	if (sftp_conn_is_protocol_violation(w->conn)) {
		int total;

		pthread_mutex_lock(&p->workers_mu);
		p->protocol_violations++;
		total = p->protocol_violations;
		pthread_mutex_unlock(&p->workers_mu);

		if (total >= 2) {
			fatal("worker %d: protocol violation #%d in "
			    "this session - sustained pattern, "
			    "aborting hpnsftp (possible server "
			    "corruption, MITM, or persistent "
			    "hardware fault)", w->id, total);
		}
		error_f("worker %d: protocol violation #%d - killing "
		    "worker and respawning; one more this session "
		    "will exit hpnsftp", w->id, total);
		/* fall through to the conn_is_dead branch below: the
		 * conn is already marked dead by the protocol-violation
		 * handler in sftp-client.c. */
	}

	if (sftp_conn_is_dead(w->conn)) {
		if (!p->abort_flag && !p->stopped)
			debug_ft("worker %d: connection lost - "
			    "will attempt to respawn", w->id);
		return 1;
	}
	return 0;
}

void *
parallel_worker_thread(void *arg)
{
	struct sftp_worker *w = arg;
	struct sftp_parallel *p = w->parent;
	/* HPN writer-cap gate: counts consecutive range units requeued because
	 * their file is at its concurrent-writer cap.  Once a full pass over
	 * the queue finds only capped units, the worker sleeps briefly instead
	 * of busy-looping (see the gate below). */
	int capped_passes = 0;

	worker_thread_init(w);

	while (1) {
		if (p->abort_flag)
			break;
		void *item = NULL;
		uint64_t t_idle_start = monotime_ns();
		__atomic_store_n(&w->phase, WPH_POP_WAIT, __ATOMIC_RELAXED);
		__atomic_store_n(&w->pop_start_ns, t_idle_start,
		    __ATOMIC_RELEASE);
		/* Phase 4 gap 1 deadlock guard: if we have a deferred
		 * pipelined batch with pending CLOSE-STATUSes in the
		 * SSH socket buffer, we cannot block on the workqueue
		 * without first reading those replies - TCP back-pressure
		 * would otherwise stall the server.  Try a non-blocking
		 * pop first; if the queue is empty, drain the deferred
		 * batch (which reads the pending STATUSes and frees them)
		 * before falling back to a blocking pop. */
		if (w->batch_prev_pending != NULL) {
			if (sftp_workqueue_trypop(p->q, &item) != 0) {
				/* queue empty - drain before blocking */
				worker_drain_pipeline(w);
				item = NULL;
			}
		}
		if (item == NULL && sftp_workqueue_pop(p->q, &item) != 0) {
			__atomic_store_n(&w->pop_start_ns, 0,
			    __ATOMIC_RELEASE);
			break;	/* shutdown && empty */
		}
		uint64_t t_work_start = monotime_ns();
		__atomic_store_n(&w->pop_start_ns, 0, __ATOMIC_RELEASE);
		/* Mark when this worker took possession of a unit so the
		 * watchdog can measure "how long has this worker been
		 * holding the current unit" even if the worker has never
		 * completed a previous unit.  Cleared at the end of this
		 * iteration after the unit (or batch) has been processed. */
		__atomic_store_n(&w->unit_start_ns, t_work_start,
		    __ATOMIC_RELEASE);
		struct sftp_work_unit *u0 = item;
		if (u0 == NULL) {
			__atomic_store_n(&w->unit_start_ns, 0,
			    __ATOMIC_RELEASE);
			continue;
		}
		/*
		 * HPN per-inode concurrent-writer cap.  Range units of one file
		 * share a tracker; only writer_cap of them may run at once.  If
		 * this file is already at its cap, return the unit to the queue
		 * and look for other work (e.g. another file's ranges).  queued_
		 * bytes is not adjusted here: it is decremented below only on the
		 * path that actually dispatches the unit, so a requeue leaves the
		 * accounting untouched.  Bounded spin: after one full pass over
		 * the queue turns up nothing but capped units (a single-file
		 * transfer), sleep ~2 ms so the surplus workers idle cheaply
		 * until an active writer finishes and frees a slot.  Whole-file
		 * and bundle units have no tracker and always pass. */
		if (!parallel_unit_writer_acquire(u0->range_tracker)) {
			/* Push-fail = the queue shut down under us (abort).
			 * The unit can never run: do the full give-up
			 * bookkeeping (pending, queued_bytes, tracker
			 * finalize, free) - silently dropping it stranded
			 * the tracker and leaked the unit. */
			if (sftp_workqueue_push(p->q, u0) != 0)
				worker_give_up_pushfail(p, w, u0,
				    "capgate/pushfail");
			__atomic_store_n(&w->unit_start_ns, 0, __ATOMIC_RELEASE);
			if (++capped_passes >=
			    (int)sftp_workqueue_depth(p->q) + 1) {
				const struct timespec ts = { 0, 2L*1000*1000 };
				nanosleep(&ts, NULL);
				capped_passes = 0;
			}
			continue;
		}
		capped_passes = 0;
		__atomic_store_n(&w->phase, WPH_ASSEMBLE, __ATOMIC_RELAXED);

		/* DISPATCH-DIAG: worker pulled a unit off the queue.  If
		 * "entered main loop" appears for a worker but no "popped"
		 * line ever follows, the worker is blocked in pop_blocking
		 * with no signal reaching it. */
		debug_ft("dispatch-diag: worker %d popped op=%d "
		    "offset=%lld length=%lld src=\"%s\" dst=\"%s\" "
		    "idle_us=%llu",
		    w->id, (int)u0->op,
		    (long long)u0->range_offset,
		    (long long)u0->range_length,
		    u0->src_path ? u0->src_path : "(null)",
		    u0->dst_path ? u0->dst_path : "(null)",
		    (unsigned long long)
		        ((t_work_start - t_idle_start) / 1000ULL));
		if (u0->size > 0)
			__atomic_fetch_sub(&p->queued_bytes,
			    (uint64_t)u0->size, __ATOMIC_RELAXED);

		/* Endgame range split: u0 may be the transfer's last
		 * un-started unit (walker done + queue emptied by this pop).
		 * All conditions are checked inside; no-op for non-range
		 * units and after the one-shot gate fires.  Runs after the
		 * full-size queued_bytes subtraction above so the pieces'
		 * parallel_unit_submit() re-adds exactly the re-queued bytes. */
		maybe_endgame_split(p, w, u0);

		/*
		 * Batch-open optimisation for uploads: accumulate up to
		 * UPLOAD_BATCH_SIZE upload units using non-blocking trypop,
		 * then call sftp_upload_batch to pipeline all N SSH_FXP_OPEN
		 * requests before waiting for any handle (1 RTT for N opens
		 * instead of 1 RTT each).  Same pipelining for closes.
		 * Falls back to single-unit execution if the first unit is
		 * not an upload or if the batch stays at size 1.
		 */
		/* Phase 5 (download side): only batch DOWNLOAD units when
		 * the server advertises hpn-bundle-fetch and the worker has
		 * bundle mode on; otherwise downloads continue down the
		 * single-unit branch (Phase 4 pipelining for downloads is
		 * still future work). */
		int batch_eligible_download =
		    (u0->op == SFTP_OP_DOWNLOAD &&
		     w->bundle_enabled &&
		     sftp_conn_has_hpn_bundle_fetch(w->conn));
		enum sftp_op batch_op = u0->op;

		/* Phase 5: a previous bundle attempt failed at the wire for
		 * this unit (server refused, cap exceeded, transport error).
		 * Skip the batch path entirely so this retry goes through
		 * sftp_download / sftp_upload directly.  Without this gate,
		 * the unit would loop bundle-fail → retry → bundle-fail until
		 * MAX_RETRIES, then be permanently lost. */
		if (u0->bundle_ineligible) {
			batch_eligible_download = 0;
			/* For uploads the check happens inside the block; the
			 * `bn == 1` branch below handles per-file dispatch.
			 * For downloads, dropping the eligibility gate sends
			 * the unit straight to the outer single-unit path. */
		}

		if ((u0->op == SFTP_OP_UPLOAD && !u0->bundle_ineligible) ||
		    batch_eligible_download) {
			/* Bundle mode is byte-capped (bundle_target_bytes), so allow
			 * many more than UPLOAD_BATCH_SIZE files per batch; heap-
			 * allocate since the bundle ceiling is large. */
			int batch_cap = w->bundle_enabled
			    ? BUNDLE_BATCH_MAX_FILES : UPLOAD_BATCH_SIZE;
			struct sftp_work_unit **batch =
			    xcalloc((size_t)batch_cap, sizeof(*batch));
			struct sftp_work_unit *leftover = NULL;
			int bn = 0;
			/* Soft byte cap: keep adding while batch_bytes is at or
			 * below the cap.  The first unit is always added even if
			 * its size alone exceeds the cap (so a single huge file
			 * is never orphaned).  See UPLOAD_BATCH_BYTE_CAP.
			 *
			 * Phase 5: in bundle mode use the smaller
			 * w->bundle_target_bytes cap so each tar stream stays
			 * small enough to compose well with parallel streams. */
			uint64_t batch_bytes = (u0->size > 0) ?
			    (uint64_t)u0->size : 0;
			const uint64_t batch_byte_cap = w->bundle_enabled
			    ? w->bundle_target_bytes
			    : UPLOAD_BATCH_BYTE_CAP;

			batch[bn++] = u0;
			/* Gate: in bundle mode, stop iterating BEFORE
			 * popping a unit that we have no room for.  The
			 * original soft gate (`batch_bytes <= cap`) tripped
			 * one iteration too late: when batch_bytes already
			 * equals cap, the gate was true → pop next → only
			 * then discover it can't fit → leftover.  That
			 * popped-just-to-discard pattern was a fencepost
			 * costing exactly one bundle-eligible unit per
			 * batch, forcing that unit through the slow per-
			 * file leftover dispatch.
			 *
			 * In bundle mode, gate strictly so we don't pop
			 * unless there's free byte budget.  Non-bundle path
			 * keeps the soft `<=` cap so a single
			 * larger-than-target unit isn't orphaned by a
			 * stricter gate. */
			while (bn < batch_cap && !p->abort_flag &&
			    (w->bundle_enabled
			        ? batch_bytes <  batch_byte_cap
			        : batch_bytes <= batch_byte_cap)) {
				void *nxt = NULL;
				if (sftp_workqueue_trypop(p->q, &nxt) != 0)
					break; /* queue empty or shutdown */
				struct sftp_work_unit *nu = nxt;
				if (nu->size > 0)
					__atomic_fetch_sub(&p->queued_bytes,
					    (uint64_t)nu->size,
					    __ATOMIC_RELAXED);
				/* Even with the strict gate, a unit of
				 * non-uniform size may overshoot the cap on
				 * its own (e.g. batch_bytes=1 MiB, cap=4 MiB,
				 * popped unit=4 MiB → projected total 5 MiB).
				 * Still need a fits check; that unit goes to
				 * leftover dispatch.  Bundle-ineligibility at
				 * parallel_unit_submit() bounds unit size to cap/4 so this
				 * branch is rare in practice. */
				int fits = 1;
				if (w->bundle_enabled && nu->size > 0 &&
				    batch_bytes + (uint64_t)nu->size >
				    batch_byte_cap) {
					fits = 0;
				}
				if (nu->op == batch_op &&
				    !nu->bundle_ineligible && fits) {
					batch[bn++] = nu;
					if (nu->size > 0)
						batch_bytes +=
						    (uint64_t)nu->size;
				} else {
					/* Off-op, bundle-ineligible, OR
					 * would-overshoot: stop collecting
					 * and dispatch nu via the post-batch
					 * leftover path. */
					leftover = nu;
					break;
				}
			}

			/*logit("sftp-parallel: worker %d batch_size=%d "
			    "(queue_depth=%zu)", w->id, bn,
			    sftp_workqueue_depth(p->q)); */

			__atomic_store_n(&w->phase, WPH_RUN, __ATOMIC_RELAXED);
			if (bn == 1) {
				/* Single file - skip batch overhead. */
				worker_execute_single(w, batch[0]);
			} else if ((int)batch_op == (int)SFTP_OP_DOWNLOAD) {
				/*
				 * Phase 5 (download side): the eligibility
				 * gate above guarantees w->bundle_enabled and
				 * the server has hpn-bundle-fetch, so the only
				 * dispatch for a multi-unit DOWNLOAD batch is
				 * bundle-fetch.  Synchronous; no pipelined
				 * carry-over state on the download bundle path.
				 */
				worker_run_bundle_download(w, batch, bn);
			} else if (w->bundle_enabled) {
				/*
				 * Phase 5 (upload side): bundle this batch as
				 * a tar stream and ship through one
				 * OPEN/WRITE×N/CLOSE.  Synchronous; the
				 * pipelined-batch carry-over state
				 * (batch_prev_pending et al) is unused on the
				 * bundle path and stays NULL.
				 */
				worker_run_bundle(w, batch, bn);
			} else {
				/*
				 * True batch.  Phase 4 gap 1:
				 * worker_run_batch_pipelined handles the entries
				 * array, send/finish, and per-entry finalisation.
				 * In pipelined mode (default) the THIS batch's
				 * phase 5 is deferred; the PREVIOUS batch's
				 * results are finalised inside the helper.  In
				 * the kill-switch path (HPN_NO_BATCH_PIPELINE=1)
				 * it falls back to a synchronous sftp_upload_batch
				 * call with the same finalisation logic inline.
				 */
				worker_run_batch_pipelined(w, batch, bn);
			}

			/* Process the leftover non-batch unit (if any).  It was
			 * popped inside the batch loop, bypassing the dispatch
			 * gate at the top of the loop, so a range leftover must
			 * claim its per-inode writer slot here too - or requeue
			 * if the file is at cap - to keep acquire/release
			 * balanced (worker_process_result always releases).
			 * queued_bytes was decremented when it was popped, so a
			 * requeue re-adds it.  NULL-tracker leftovers (whole-file
			 * uploads) acquire trivially and release as a no-op. */
			if (leftover != NULL) {
				if (parallel_unit_writer_acquire(
				    leftover->range_tracker)) {
					/* Endgame range split: a range
					 * leftover can also be the last
					 * un-started unit (see the main
					 * dispatch site). */
					maybe_endgame_split(p, w, leftover);
					worker_execute_single(w, leftover);
				} else {
					if (leftover->size > 0)
						__atomic_fetch_add(
						    &p->queued_bytes,
						    (uint64_t)leftover->size,
						    __ATOMIC_RELAXED);
					/* Queue shut down under us: full
					 * give-up bookkeeping, not a silent
					 * drop (see the cap-gate site). */
					if (sftp_workqueue_push(p->q,
					    leftover) != 0)
						worker_give_up_pushfail(p, w,
						    leftover,
						    "leftover/pushfail");
				}
			}
			free(batch);	/* heap batch; bundle mode can exceed UPLOAD_BATCH_SIZE */
		} else {
			/* Download (no bundle) or any range op - all bypass
			 * the upload-batch path. */
			worker_execute_single(w, u0);
		}

		/* Account for this iteration's idle and work time. */
		{
			uint64_t t_work_end = monotime_ns();
			pthread_mutex_lock(&w->mu);
			w->idle_ns += t_work_start - t_idle_start;
			w->work_ns += t_work_end - t_work_start;
			pthread_mutex_unlock(&w->mu);
		}

		/* Unit (or batch) finished - clear the wedge-detection
		 * timestamp so the watchdog only ever counts time spent
		 * actually holding work. */
		__atomic_store_n(&w->unit_start_ns, 0, __ATOMIC_RELEASE);

		if (worker_should_terminate(w))
			break;
	}
	/* Phase 4 gap 1: drain any deferred pipelined batch state before
	 * exiting.  If the connection died, this is a best-effort drain
	 * (sftp_upload_batch_finish handles a dead conn by marking entries
	 * failed and freeing). */
	worker_drain_pipeline(w);

	/* Mark exited so the reporter thread can reap us (join + free). */
	pthread_mutex_lock(&w->mu);
	w->exited = 1;
	pthread_mutex_unlock(&w->mu);
	return NULL;
}

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
	p->last_worker_exit_code = -1;	/* no worker reaped yet */
	/* Born-dead 0-bytes kill threshold.  RTT-derived once the path RTT is
	 * registered (sftp_parallel_set_path_rtt); BORN_DEAD_KILL_SEC until then. */
	p->born_dead_sec = BORN_DEAD_KILL_SEC;

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
	if (p == NULL || !p->progress_meter_started)
		return;
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


