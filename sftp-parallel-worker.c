/*
 * sftp-parallel-worker.c - the worker thread for the parallel SFTP
 * orchestrator: unit execution (single, batch-pipelined, bundle,
 * range), result processing and give-up paths, per-worker accounting,
 * the endgame range split, and the thread loop itself.  Split from
 * sftp-parallel.c; moves are verbatim.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-verify.h"		/* sftp_hpn_verify_transfer */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"
#include "hpn-exit-codes.h"

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
 * HPNVerifyTransfer (parallel): verify one just-transferred whole file
 * end-to-end on the worker's connection and record a mismatch in the
 * orchestrator's thread-safe verify_failed_paths list.  Never fails the
 * unit - a mismatch is surfaced in the summary + exit code, not retried.
 */
void
parallel_verify_one(struct sftp_worker *w, const char *local_path,
    const char *remote_path, int local_is_target)
{
	struct sftp_parallel *p = w->parent;
	int r = sftp_hpn_verify_transfer(w->conn, local_path, remote_path,
	    local_is_target);

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

/*
 * HPNVerifyTransfer (range-split upload): per-range verify off the tracker's
 * teed source hashes - no whole-file source re-read.  Builds the range arrays
 * from the slots and compares against the server's per-range dest hashes.  A
 * -1 (server lacks sftp-hash-range, or a local read failed) falls back to the
 * whole-file verify so integrity is still checked.
 */
void
parallel_verify_one_ranges(struct sftp_worker *w, struct sftp_range_tracker *t)
{
	struct sftp_parallel	*p = w->parent;
	struct sftp_hash_range	*ranges;
	uint64_t		*local_hashes;
	int			*valid;
	u_int			 i, n;
	int			 r;

	if (t->vslots == NULL || t->vslots_n <= 0) {
		parallel_verify_one(w, t->src_path, t->path,
		    /*local_is_target=*/0);
		return;
	}
	/*
	 * Bound by vslots_n (the allocation), NOT t->total: the endgame split
	 * grows total with sub-range pieces but never resizes vslots.  Those
	 * pieces tile a slot whose original range was left valid=0 (the held
	 * unit shrank, so its hash was not stored), so re-reading that slot's
	 * full [off, len) at finalize already covers every piece - the extra
	 * grown slots neither exist nor are needed.
	 */
	n = (u_int)t->vslots_n;
	ranges       = xcalloc(n, sizeof(*ranges));
	local_hashes = xcalloc(n, sizeof(*local_hashes));
	valid        = xcalloc(n, sizeof(*valid));
	for (i = 0; i < n; i++) {
		ranges[i].off   = t->vslots[i].off;
		ranges[i].len   = t->vslots[i].len;
		local_hashes[i] = t->vslots[i].hash;
		valid[i]        = t->vslots[i].valid;
	}
	r = sftp_hpn_verify_transfer_ranges(w->conn, t->src_path, t->path,
	    ranges, local_hashes, valid, n);
	free(ranges);
	free(local_hashes);
	free(valid);

	if (r == 0)
		return;	/* verified good */
	if (r < 0) {
		/* Per-range path unavailable - re-check whole-file (re-reads
		 * the source but still proves integrity). */
		parallel_verify_one(w, t->src_path, t->path,
		    /*local_is_target=*/0);
		return;
	}
	error_f("worker %d VERIFY FAILED: \"%s\" post-transfer hash "
	    "mismatch - transferred file does NOT match source",
	    w->id, t->path);
	hpn_strlist_append(&p->verify_failed_paths, t->path);
}

/* Close and clear the worker's warm remote handle (held open across same-
 * file range writes to skip the boundary close/reopen).  Skips the wire
 * close on a dead connection; always frees the cached handle + path. */
static void
parallel_worker_close_warm(struct sftp_worker *w)
{
	if (w->warm_handle == NULL)
		return;
	if (!sftp_conn_is_dead(w->conn))
		(void)sftp_close(w->conn, w->warm_handle, w->warm_handle_len);
	free(w->warm_handle);
	free(w->warm_dst_path);
	w->warm_handle = NULL;
	w->warm_handle_len = 0;
	w->warm_dst_path = NULL;
}

static int
execute_unit(struct sftp_worker *w, struct sftp_work_unit *u)
{
	struct sftp_parallel *p = w->parent;
	int rc = -1;

	/* The warm handle is only valid as a same-file UPLOAD_RANGE
	 * continuation; any other op, or a different file, closes it first. */
	if (w->warm_handle != NULL &&
	    (u->op != SFTP_OP_UPLOAD_RANGE || w->warm_dst_path == NULL ||
	     u->dst_path == NULL ||
	     strcmp(w->warm_dst_path, u->dst_path) != 0))
		parallel_worker_close_warm(w);

	/* Lazy file creation: first range dispatched for a tracked file
	 * creates it (exactly-once via the tracker mutex; no-op for
	 * untracked ops and existing files).  A permanent create failure
	 * sets u->no_retry and fails the unit immediately. */
	if (u->range_tracker != NULL &&
	    parallel_unit_ensure_file(w->conn, u) != 0)
		return -1;

	/* Post-transfer verify: the parked tracker is verified on this worker's
	 * own conn and freed by the handler (which NULLs verify_tracker so
	 * parallel_unit_free won't double-free).  Verify never fails the unit -
	 * a mismatch goes to verify_failed_paths, not a retry - so it always
	 * returns 0 and worker_process_result just dec-pendings and frees it. */
	if (u->op == SFTP_OP_VERIFY) {
		parallel_verify_and_free(w, u->verify_tracker);
		u->verify_tracker = NULL;
		return 0;
	}

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
			parallel_verify_park_whole_file(p, u->src_path,
			    u->dst_path, /*local_is_target=*/0);  /* local = source */
		if (rc == 1 || rc == 2)
			rc = 0;	/* identical / target-larger: complete */
		break;
	case SFTP_OP_UPLOAD_RANGE: {
		/* Range-split resume gate + post-transfer verify happen at
		 * the orchestrator/finalize level, not per-range; see
		 * project_parallel_resume_verify_design (Phase 1 follow-up).
		 * The warm handle (built from the worker's cache) is reused
		 * across consecutive same-file ranges and synced back. */
		struct sftp_range_warm warm = {
			w->warm_handle, w->warm_handle_len, w->warm_dst_path
		};
		/* HPN_NO_RANGE_WARM kill switch: NULL disables the warm cache
		 * (open+close every range, the pre-warm-handle behaviour). */
		struct sftp_range_warm *warmp =
		    w->range_warm_disabled ? NULL : &warm;
		rc = sftp_upload_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length, &u->acked_bytes, warmp,
		    (u->range_tracker != NULL && u->range_tracker->verify)
		    ? &u->range_hash : NULL);
		w->warm_handle = warm.handle;
		w->warm_handle_len = warm.handle_len;
		w->warm_dst_path = warm.path;
		debug("unit-exec: worker %d UPLOAD_RANGE [%lld+%lld) rc=%d "
		    "acked=%lld attempt=%d", w->id,
		    (long long)u->range_offset, (long long)u->range_length,
		    rc, (long long)u->acked_bytes, u->attempt);
		/* HPNVerifyTransfer: a range that transferred in one clean pass
		 * (first attempt, fully acked) has a teed source hash good for
		 * the whole original range - record it so finalize skips the
		 * source re-read.  Pass the span actually covered: store_range_hash
		 * keeps the hash only if it still equals the slot's original
		 * [off, len), so a highwater-resumed remainder (which reaches here
		 * with attempt reset to 0) leaves the slot unset and is re-read per
		 * range at finalize. */
		if (rc == 0 && u->attempt == 0 && u->range_tracker != NULL &&
		    u->acked_bytes == u->range_length)
			parallel_unit_store_range_hash(u->range_tracker,
			    u->range_index, (uint64_t)u->range_offset,
			    (uint64_t)u->range_length, u->range_hash);
		break;
	}
	case SFTP_OP_DOWNLOAD_RANGE:
		rc = sftp_download_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length, &u->acked_bytes);
		debug("unit-exec: worker %d DOWNLOAD_RANGE [%lld+%lld) rc=%d "
		    "acked=%lld attempt=%d", w->id,
		    (long long)u->range_offset, (long long)u->range_length,
		    rc, (long long)u->acked_bytes, u->attempt);
		break;
	case SFTP_OP_DOWNLOAD:
		rc = sftp_download(w->conn, u->src_path, u->dst_path,
		    /*Attrib*/NULL, p->cfg.preserve_flag,
		    u->resume, p->cfg.fsync_flag,
		    p->cfg.inplace_flag, /*verify=*/u->verify);
		if (rc == 0 && p->cfg.verify_transfer)
			parallel_verify_park_whole_file(p, u->dst_path,
			    u->src_path, /*local_is_target=*/1);  /* local = downloaded */
		if (rc == 1 || rc == 2)
			rc = 0;	/* identical / target-larger: complete */
		break;
	case SFTP_OP_VERIFY:
		/* Handled before the switch via an early return; reaching the
		 * switch with a verify op is a bug. */
		fatal_f("verify unit reached execute_unit switch (op=%d)",
		    (int)u->op);
		break;
	case SFTP_OP_BUNDLE_UPLOAD:
	case SFTP_OP_BUNDLE_DOWNLOAD:
		/* Bundle containers are dispatched directly in the worker loop
		 * (worker_dispatch_bundle_container) and never reach here. */
		fatal_f("bundle container reached execute_unit (op=%d)",
		    (int)u->op);
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

	/* Cooperative yield (phase C): consume+clear the request whatever
	 * the outcome - a unit that completed despite the flag (race with
	 * its own finish) must not poison the next dispatch.  A yielded
	 * non-success on a LIVE connection is voluntary: requeue the
	 * remainder without charging the retry budget. */
	int yielded = __atomic_exchange_n(&w->yield_req, 0, __ATOMIC_RELAXED);

	/* HPN: free the per-inode writer slot claimed in parallel_worker_thread's
	 * dispatch gate.  Reached exactly once per executed unit on every
	 * path (success, retry-requeue, give-up), so retries release here and
	 * re-acquire when re-dispatched.  NULL tracker (non-range) = no-op.
	 * The kick wakes workers parked in the cap-gate's wait_activity so a
	 * freed slot is picked up immediately instead of on the timeout. */
	if (u->range_tracker != NULL) {
		parallel_unit_writer_release(u->range_tracker);
		sftp_workqueue_kick(p->q);
	}

	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		/*
		 * Range tracker: this range finished cleanly.  Finalize BEFORE
		 * decrementing pending.  For the last range of a verified file,
		 * finalize runs the whole-file post-transfer verify on this
		 * worker's own live conn; dropping pending to 0 first would wake
		 * sftp_parallel_wait and let the main thread tear the conn down
		 * mid-verify (a broken pipe on the hpn-check-file send).  The
		 * unit is not truly complete until verified, so it stays pending
		 * across the verify.  Last completer for the file frees the
		 * tracker.  (Verify-off: finalize is the same fast bookkeeping,
		 * so the reorder is a no-op in timing.)
		 */
		(void)parallel_unit_tracker_finalize(u->range_tracker, 0, w);
		parallel_unit_pending_dec_traced(p, u, w->id, "wpr/success");
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

		/* A yield on a connection that DIED during the wind-down is
		 * not a yield - it is an ordinary death; the transient path
		 * already handles it (and the respawned worker can't defer). */
		if (transient)
			yielded = 0;

		/*
		 * Highwater resume (HPN): the failed attempt confirmed
		 * acked_bytes contiguous bytes on the target, so the unit
		 * requeues as just its unlanded remainder - worker death
		 * costs the in-flight window, not the whole range.  Progress
		 * also RESETS the retry budget: attempts only count when
		 * they were fruitless, so a flaky-but-advancing range cannot
		 * exhaust retries and give up at 90% transferred.  The
		 * tracker is untouched: same unit, same single finalize.
		 */
		if ((u->op == SFTP_OP_UPLOAD_RANGE ||
		    u->op == SFTP_OP_DOWNLOAD_RANGE) &&
		    u->acked_bytes > 0 &&
		    u->acked_bytes < u->range_length) {
			debug("worker %d: range \"%s\" [%lld+%lld) resumes "
			    "past %lld acked bytes%s", w->id,
			    u->dst_path ? u->dst_path : u->src_path,
			    (long long)u->range_offset,
			    (long long)u->range_length,
			    (long long)u->acked_bytes,
			    yielded ? " (cooperative yield)" : "");
			u->range_offset += u->acked_bytes;
			u->range_length -= u->acked_bytes;
			u->size = u->range_length;
			u->attempt = 0;
			u->acked_bytes = 0;
		}

		/* Yield handoff: mark the remainder so dispatch gives a
		 * DIFFERENT worker first crack at it (one courtesy defer). */
		u->yield_from = yielded ? w->id + 1 : 0;

		if (!u->no_retry &&
		    (transient || yielded ||
		    ++u->attempt < parallel_unit_max_retries(p))) {
			if (u->size > 0)
				__atomic_fetch_add(&p->queued_bytes,
				    (uint64_t)u->size, __ATOMIC_RELAXED);
			if (parallel_unit_pending_trace_on())
				parallel_unit_pending_trace("REQUEUE", p, u, w->id,
				    yielded ? "wpr/yield" :
				    transient ? "wpr/transient" : "wpr/retry");
			/* Yields jump the queue like transients: the parked
			 * READY fleet should pick the remainder up NOW. */
			if (((transient || yielded)
			    ? sftp_workqueue_push_front(p->q, u)
			    : sftp_workqueue_push(p->q, u)) != 0)
				worker_give_up_pushfail(p, w, u, "wpr/pushfail");
			else if (yielded)
				sftp_workqueue_kick(p->q);
		} else {
			worker_give_up_unit(p, w, u, "unit", "wpr/maxretries");
		}
	}
}

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
	if (!u->no_retry &&
	    (transient || ++u->attempt < parallel_unit_max_retries(p))) {
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
	/* HPNVerifyTransfer: record per-file bundle verify mismatches into the
	 * orchestrator's thread-safe list (folded into exit 57), the bundle
	 * counterpart of parallel_verify_one. */
	for (i = 0; i < bn; i++) {
		if (entries[i].verify_failed) {
			error_f("worker %d BUNDLE VERIFY FAILED: \"%s\" "
			    "post-transfer hash mismatch", w->id,
			    entries[i].remote_path);
			hpn_strlist_append(&p->verify_failed_paths,
			    entries[i].remote_path);
		}
	}
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
	/* HPNVerifyTransfer: record per-file download bundle verify mismatches
	 * (mirror of the upload-bundle path). */
	for (i = 0; i < bn; i++) {
		if (entries[i].verify_failed) {
			error_f("worker %d BUNDLE VERIFY FAILED: \"%s\" "
			    "post-transfer hash mismatch", w->id,
			    entries[i].local_path);
			hpn_strlist_append(&p->verify_failed_paths,
			    entries[i].local_path);
		}
	}
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

/*
 * Dispatch a pre-formed bundle container (SFTP_OP_BUNDLE_*).  The producer
 * grouped the members, so there is no accumulation race here: detach the
 * member array, run it through the existing array-based bundle path (which
 * finalises and frees each member via worker_finalize_one_entry), then free
 * the now-memberless shell.  queued_bytes for the whole bundle was already
 * subtracted at pickup (the container's ->size = sum of member bytes).
 */
static void
worker_dispatch_bundle_container(struct sftp_worker *w,
    struct sftp_work_unit *u0)
{
	struct sftp_work_unit **members = u0->members;
	int n = u0->n_members;

	u0->members = NULL;	/* detach: shell free must not touch members */
	u0->n_members = 0;
	if (u0->op == SFTP_OP_BUNDLE_DOWNLOAD)
		worker_run_bundle_download(w, members, n);
	else
		worker_run_bundle(w, members, n);
	free(members);
	parallel_unit_free(u0);
}

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
	/*
	 * A bundle container can reach the single-file path as an accumulate-
	 * loop "leftover": once a transient bundle failure re-queues its members
	 * as individual units, the queue mixes containers with individuals, and
	 * a worker accumulating individuals can trypop a container (off-op ->
	 * leftover).  Dispatch it as a bundle, not through execute_unit (which
	 * fatals on a container op).  Its queued_bytes was already subtracted at
	 * pickup, so worker_dispatch_bundle_container does no further accounting.
	 */
	if (u->op == SFTP_OP_BUNDLE_UPLOAD || u->op == SFTP_OP_BUNDLE_DOWNLOAD) {
		worker_dispatch_bundle_container(w, u);
		return;
	}
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
	int stagger_ms;

	/*
	 * Default OFF pending re-evaluation (2026-06-11).  The split's
	 * measured record: throughput benefit inside noise on large files
	 * (06-10 campaign), actively harmful on files with fewer ranges
	 * than workers (5x10GB campaigns: synchronized piece launches
	 * inflated path RTT 101->312ms; 17s transfers became 40-88s), and
	 * its rescue scenario - a wedged worker holding the tail - is
	 * already covered by the watchdog's straggler reap + requeue.
	 * ENV-VAR HPN_ENDGAME_SPLIT - developer-only: set to 1 to enable
	 * for clean-window evaluation.
	 */
	{
		const char *en = getenv("HPN_ENDGAME_SPLIT");

		if (en == NULL || *en != '1')
			return;
	}

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

	/*
	 * No-tail gate: when the file has no more ranges than the per-inode
	 * writer cap (total <= writer_cap), every range starts at once, the
	 * queue drains instantly, and there is NO tail to drain.  Firing the
	 * split here only re-injects a synchronized multi-connection writer
	 * burst (measured inflating path RTT ~2.5x, 101->312ms) for no gain -
	 * a net loss on such files.  (No separate maturity check needed: the
	 * qdepth==0 gate above means every range is already dispatched, so on
	 * a real tail some have completed by the time we reach here.)
	 */
	pthread_mutex_lock(&t->mu);
	if (t->total <= t->writer_cap) {
		pthread_mutex_unlock(&t->mu);
		return;
	}
	pthread_mutex_unlock(&t->mu);

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

	{
		const char *sv = getenv("HPN_ENDGAME_SPLIT_STAGGER_MS");

		stagger_ms = (sv != NULL && *sv != '\0') ?
		    atoi(sv) : ENDGAME_SPLIT_STAGGER_MS;
	}

	/* Shrink the held unit to piece 0; submit pieces 1..n-1.  De-sync the
	 * launches: a fixed gap after each submit keeps the N connections from
	 * ramping in lockstep into the shared path - the synchronized burst was
	 * measured inflating RTT ~2.5x and tripping cwnd-collapse wedges.  The
	 * gap after the LAST submit also spaces piece 0, which this worker runs
	 * on return.  HPN_ENDGAME_SPLIT_STAGGER_MS=0 restores the old
	 * simultaneous launch.  The submit loop holds no lock (tracker mu was
	 * released above; parallel_unit_submit takes the workqueue lock only
	 * internally), so the sleep does not stall the fleet. */
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
		if (stagger_ms > 0) {
			struct timespec ts;

			ms_to_timespec(&ts, stagger_ms);
			nanosleep(&ts, NULL);
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

	/* -1 = "holds no range" (0 is a valid range_offset); the watchdog's
	 * stuck-range detector compares against this. */
	__atomic_store_n(&w->unit_offset, (int64_t)-1, __ATOMIC_RELAXED);

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
	{
		/* ENV-VAR HPN_NO_RANGE_WARM - developer-only: kill switch for
		 * the warm range handle (reuse across same-file ranges).  When
		 * set, execute_unit passes a NULL warm cache so sftp_upload_range
		 * opens+closes every range as before.  For A/B testing. */
		const char *e = getenv("HPN_NO_RANGE_WARM");
		if (e != NULL && *e != '\0' && *e != '0')
			w->range_warm_disabled = 1;
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
		/* Midstream-substitution bench: a worker subbed out as an extreme
		 * straggler stays parked until its cooldown expires, then re-enters
		 * the pool (if still slow it is re-subbed).  Keeps it from
		 * re-grabbing its own yielded remainder without permanently
		 * shrinking the writer pool. */
		{
			time_t bench = __atomic_load_n(&w->midstream_benched_s,
			    __ATOMIC_RELAXED);
			if (bench != 0) {
				if (monotime() < bench) {
					__atomic_store_n(&w->avail,
					    WORKER_AVAIL_CAPPED, __ATOMIC_RELAXED);
					sftp_workqueue_wait_activity(p->q, 250);
					continue;
				}
				__atomic_store_n(&w->midstream_benched_s, 0,
				    __ATOMIC_RELAXED);	/* cooldown over: re-enter */
				/* Re-arm the EMA warmup so the detector gives this
				 * worker a fresh window to prove its throughput
				 * before it is eligible to be re-benched: its EMA
				 * froze while parked, and judging it on that stale
				 * value would re-bench it instantly.  Mirrors the
				 * watchdog's new-unit cold-start. */
				w->tput_ema_warmup_ticks = 0;
			}
		}
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
		/* Availability intent: about to block in pop = purposefully
		 * idle, healthy, ready for work (see enum worker_avail). */
		__atomic_store_n(&w->avail, WORKER_AVAIL_READY,
		    __ATOMIC_RELAXED);
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
		 * Cooperative-yield handoff (phase C): the worker that just
		 * yielded this remainder must not immediately re-pop its own
		 * handoff - that would defeat the redistribution.  One
		 * courtesy defer: push it back, clear the marker (so a lone
		 * worker can never deadlock on its own yield), park briefly
		 * to give a READY worker the race.  Any other worker runs it
		 * immediately (and clears the marker by dispatching).
		 */
		if (u0->yield_from == w->id + 1) {
			u0->yield_from = 0;
			if (sftp_workqueue_push_front(p->q, u0) != 0) {
				worker_give_up_pushfail(p, w, u0,
				    "yield/pushfail");
				__atomic_store_n(&w->unit_start_ns, 0,
				    __ATOMIC_RELEASE);
				continue;
			}
			__atomic_store_n(&w->unit_start_ns, 0,
			    __ATOMIC_RELEASE);
			sftp_workqueue_kick(p->q);
			sftp_workqueue_wait_activity(p->q, 250);
			continue;
		}
		if (u0->yield_from != 0) {
			/* A DIFFERENT worker reached this yielded remainder before
			 * the holder could re-pop it: the cooperative handoff
			 * actually moved the work off the straggler onto a peer.
			 * Covers both yield sources (tail-redistribute and
			 * MIDSTREAM); debug level - midstream visibility during its
			 * verification comes from the separate MIDSTREAM-SUB bench
			 * line.  The holder-defer case above clears the marker
			 * first, so this counts direct handoffs only. */
			debug("HPN YIELD-HANDOFF \"%s\" [%lld+%lld) "
			    "yielded_by=%d taken_by=%d",
			    u0->dst_path ? u0->dst_path : u0->src_path,
			    (long long)u0->range_offset,
			    (long long)u0->range_length,
			    u0->yield_from - 1, w->id);
		}
		u0->yield_from = 0;
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
			/* Availability intent: cap-gate parking = available for
			 * OTHER files, blocked on this one's writer cap. */
			__atomic_store_n(&w->avail, WORKER_AVAIL_CAPPED,
			    __ATOMIC_RELAXED);
			/* A full pass over the queue found only capped units:
			 * park on the queue's activity channel instead of
			 * spinning pop/requeue (measured: ~6M futile cycles
			 * per large single-file transfer).  Exact wakeup on
			 * slot release or any push; the 100ms timeout is a
			 * backstop, never the path. */
			if (++capped_passes >=
			    (int)sftp_workqueue_depth(p->q) + 1) {
				sftp_workqueue_wait_activity(p->q, 250);
				capped_passes = 0;
			}
			continue;
		}
		capped_passes = 0;
		__atomic_store_n(&w->phase, WPH_ASSEMBLE, __ATOMIC_RELAXED);
		/* Availability intent + unit size for the tail detector's
		 * projected-tail (size published beside unit_start_ns). */
		__atomic_store_n(&w->avail, WORKER_AVAIL_BUSY,
		    __ATOMIC_RELAXED);
		__atomic_store_n(&w->unit_size, (uint64_t)u0->size,
		    __ATOMIC_RELAXED);
		__atomic_store_n(&w->unit_offset,
		    (u0->op == SFTP_OP_UPLOAD_RANGE ||
		     u0->op == SFTP_OP_DOWNLOAD_RANGE)
		    ? (int64_t)u0->range_offset : (int64_t)-1,
		    __ATOMIC_RELAXED);

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

		if (u0->op == SFTP_OP_BUNDLE_UPLOAD ||
		    u0->op == SFTP_OP_BUNDLE_DOWNLOAD) {
			/* Producer-assembled bundle: dispatch the whole
			 * container directly - no worker-side accumulation,
			 * no startup grab race. */
			__atomic_store_n(&w->phase, WPH_RUN, __ATOMIC_RELAXED);
			worker_dispatch_bundle_container(w, u0);
		} else if ((u0->op == SFTP_OP_UPLOAD &&
		    !u0->bundle_ineligible) || batch_eligible_download) {
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
		__atomic_store_n(&w->unit_size, 0, __ATOMIC_RELAXED);
		__atomic_store_n(&w->unit_offset, (int64_t)-1, __ATOMIC_RELAXED);

		if (worker_should_terminate(w))
			break;
	}
	/* Phase 4 gap 1: drain any deferred pipelined batch state before
	 * exiting.  If the connection died, this is a best-effort drain
	 * (sftp_upload_batch_finish handles a dead conn by marking entries
	 * failed and freeing). */
	worker_drain_pipeline(w);

	/* Close any warm range handle still held (last same-file range's
	 * handle, or one carried through an idle wait).  Best-effort on a
	 * dead connection. */
	parallel_worker_close_warm(w);

	/* Mark exited so the reporter thread can reap us (join + free). */
	pthread_mutex_lock(&w->mu);
	w->exited = 1;
	pthread_mutex_unlock(&w->mu);
	return NULL;
}
