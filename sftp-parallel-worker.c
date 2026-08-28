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
 * sftp-parallel-worker.c - the worker thread for the parallel SFTP
 * orchestrator.
 *
 * One of these threads runs per parallel stream. It takes work units off the
 * shared queue and runs them on its own SSH connection: whole files, single
 * byte ranges of a large file, resume spans, pipelined upload batches, and
 * bundles of small files. It decides what to do with each result, either
 * retrying the unit or giving up on it and recording the path as undelivered.
 *
 * It also runs the post-transfer verify units, hashing a whole file or one
 * range chunk and repairing what does not match, and it keeps the per-worker
 * counters and timestamps that the watchdog and the reporter read from
 * another thread.
 *
 * Also here: the one-time worker setup, the rule for when a worker should
 * stop, and the cache of a still-open remote file handle that lets
 * consecutive ranges of the same file skip a reopen.
 *
 * Three access disciplines run through the file, chosen by who can see the
 * data rather than by what thread the code runs on. A work unit belongs to
 * one worker from pop to free, so its fields are plain. Fields the reporter
 * or the watchdog read while this thread writes them are relaxed atomics,
 * where a stale read only paints a stale meter. The per-worker counters take
 * worker->mu instead, because a reader needs them to agree with each other.
 * A stronger order appears only where one value publishes others, as with
 * the acquire-release on verify_job->ranges_left.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-verify.h"		/* sftp_hpn_verify_repair, _chunk */
#include "sftp-hpn-transferlog.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"

/*
 * Records one path the fleet could not deliver, as "path: cause", in the
 * fleet's failed-paths list. The end of run summary prints that list, so this
 * is what turns a give-up into something the user sees rather than something
 * buried in the log.
 *
 * The cause comes from the caller. Both give-up paths capture it before they
 * do anything else, because the text they want is the most recent error log
 * line on this thread and their own give-up logging would overwrite it. That
 * captured text is cleared at the end here, so the next failure on this
 * thread starts from nothing rather than inheriting this one.
 *
 * Called only from worker_give_up_unit and worker_give_up_pushfail, never on
 * a retry.
 */
static void
worker_record_failed_path(struct sftp_parallel *fleet,
    struct sftp_work_unit *unit, const char *explicit_cause)
{
	char        buf[PATH_MAX + 256];
	const char *path = unit->src_path;

	/* these should never be necessary */
	if (explicit_cause == NULL)
		explicit_cause = "(unknown cause)";
	if (path == NULL)
		path = "(unknown path)";

	snprintf(buf, sizeof(buf), "%s: %s", path, explicit_cause);
	hpn_strlist_append(&fleet->failed_paths, buf);

	hpn_clear_last_error();
}

/* Count one unit sent to this worker. Need to lock to prevent
 * potential overwrites/inconsistency. */
static void
worker_record_start(struct sftp_worker *worker)
{
	pthread_mutex_lock(&worker->mu);
	worker->units_started++;
	pthread_mutex_unlock(&worker->mu);
}

/* Retire one dispatched unit. Success adds its bytes and counts a completion,
 * failure only counts; bytes is ignored on the failure path. Clears the
 * live counters so the unit is not counted twice, and stamps
 * last_completion_ms (for logs). */
static void
worker_record_completion(struct sftp_worker *worker, off_t bytes, int success)
{
	pthread_mutex_lock(&worker->mu);
	if (success) {
		worker->bytes_total += (uint64_t)bytes;
		worker->units_completed++;
	} else {
		worker->units_failed++;
	}
	/* Reset live_bytes so the completed file's bytes aren't counted twice
	 * (once here in bytes_total and once via the live_counter hook). */
	__atomic_store_n(&worker->live_bytes, 0, __ATOMIC_RELAXED);
	/* Retire any hash-work op the unit ran (chunked resume check):
	 * stale op progress would otherwise pollute the reporter's sums
	 * and the ratchet would lock it in. (Verify units end theirs at
	 * the fold sites; re-ending is harmless.) */
	sftp_conn_hash_op_end(worker->conn);
	worker->last_completion_ms = monotime_ms();
	pthread_mutex_unlock(&worker->mu);
}

/*
 * Verify transfer (parallel): verify one just-transferred whole file
 * end-to-end on the worker's connection and record a mismatch in the
 * orchestrator's verify_failed_paths list. Never fails the unit.
 * A mismatch is surfaced in the summary + exit code, not retried.
 */
static void
parallel_verify_one(struct sftp_worker *worker, const char *local_path,
    const char *remote_path, int local_is_target)
{
	struct sftp_parallel *fleet = worker->parent;
	/* Whole-file mode: len 0 makes the engine verify span [0, size). No
	 * teed hash is passed, because the decoupled verify may run on a
	 * different worker than the one that uploaded the file, and the
	 * size-keyed accumulator could hold another same-size file's hash. */
	int repaired = 0;
	int verify_rc = sftp_hpn_verify_repair(worker->conn, local_path, remote_path,
	    local_is_target, /*off=*/0, /*len=*/0,
	    /*have_local_hash=*/0, /*local_hash=*/0,
	    fleet->verify_repair_enabled, fleet->verify_repair_attempts, &repaired);

	/* TransferLog: under -V the transfer line was deferred to this,
	 * the file's final status. Unverifiable (verify_rc < 0) transferred fine
	 * but cannot claim "verified" - log it as plain success. Size
	 * from the local side, which exists in both directions. The
	 * destination path names the file. */
	if (transferlog_active()) {
		struct stat local_st;
		long long size = (stat(local_path, &local_st) == 0) ?
		    (long long)local_st.st_size : -1;
		enum transferlog_status status;

		if (verify_rc > 0)
			status = TRANSFERLOG_FAILED;
		else if (verify_rc < 0)
			status = TRANSFERLOG_SUCCESS;
		else
			status = repaired ? TRANSFERLOG_REPAIRED :
			    TRANSFERLOG_VERIFIED;
		transferlog_file(status, size,
		    local_is_target ? local_path : remote_path);
	}
	if (verify_rc == 0)
		return;	/* verified good (possibly after repair) */
	if (verify_rc < 0) {
		logit("VERIFY SKIPPED: \"%s\": server lacks "
		    "hpn-check-file@hpnssh.org or read error",
		    remote_path);
		return;
	}
	/*
	 * Unrepairable (converged, hit the cap, or repair disabled): the core
	 * already logged the specific cause; record the failure for the run
	 * summary + exit code.
	 */
	error_f("worker %d VERIFY FAILED: %s file \"%s\" does NOT match source",
	    worker->id, local_is_target ? "local" : "remote",
	    local_is_target ? local_path : remote_path);
	parallel_verify_fail_record(fleet, local_is_target, local_path, remote_path);
}

/* Close and clear the worker's warm remote handle (held open across same-
 * file range writes to skip the boundary close/reopen). Skips the wire
 * close on a dead connection; always frees the cached handle + path. */
static void
parallel_worker_close_warm(struct sftp_worker *worker)
{
	if (worker->warm_handle == NULL)
		return;
	if (!sftp_conn_is_dead(worker->conn))
		(void)sftp_close(worker->conn, worker->warm_handle, worker->warm_handle_len);
	free(worker->warm_handle);
	free(worker->warm_dst_path);
	worker->warm_handle = NULL;
	worker->warm_handle_len = 0;
	worker->warm_dst_path = NULL;
}

/*
 * Runs one work unit on this worker's connection and reports how it went.
 * A return of 0 means the unit finished. Anything else is a failure
 * and worker_process_result decides whether to retry the unit or give up.
 *
 * Three things happen before the unit itself runs. 1) the flag that
 * records a permission denied is cleared, so the retry only what this unit
 * ran into. 2) the worker may be holding an open file on the server from
 * the prior  unit so we don't have to reopening it between consecutive ranges.
 * Otherwise the handle is closed. 3) if this unit is one range of a file
 * split across workers, the file is created now unless already done.
 *
 * A verify unit is handled above the switch and returns as soon as it is done.
 * Verifying never fails a unit. A file that does not match its source is added
 * to the fleet's verify_failed_paths list, which the end of run summary
 * prints, instead of be restransmitted,
 *
 * Bundle containers, which carry many small files in a single unit, never
 * reach this function. That's in the worker loop.
 *
 * TODO: the verify handling above the switch is about half of this function.
 * Moving it into one function for a range chunk and one for a whole file would
 * leave this a plain dispatcher, and each of those paths could then explain
 * itself in its own leading comment.
 */
static int
execute_unit(struct sftp_worker *worker, struct sftp_work_unit *unit)
{
	struct sftp_parallel *fleet = worker->parent;
	int rc = -1;

	/* Scope the permanent-denial signal (set by the SFTP status
	 * reader on PERMISSION_DENIED) to this unit, so the retry decider
	 * sees only THIS unit's refusals. */
	sftp_conn_clear_perm_denied(worker->conn);

	/* The warm handle is only valid as a same-file UPLOAD_RANGE
	 * continuation; any other op, or a different file, closes it first. */
	if (worker->warm_handle != NULL &&
	    (unit->op != SFTP_OP_UPLOAD_RANGE || worker->warm_dst_path == NULL ||
	     unit->dst_path == NULL ||
	     strcmp(worker->warm_dst_path, unit->dst_path) != 0))
		parallel_worker_close_warm(worker);

	/* Lazy file creation: first range dispatched for a tracked file
	 * creates it (exactly-once via the tracker mutex; no-op for
	 * untracked ops and existing files). A permanent create failure
	 * sets unit->no_retry and fails the unit immediately. */
	if (unit->range_tracker != NULL &&
	    parallel_unit_ensure_file(worker->conn, unit) != 0)
		return -1;

	/* Post-transfer verify: the parked file is verified on this worker's own
	 * conn and its carrier (verify_job for a range chunk, verify_whole for a
	 * whole file) freed by the handler, which NULLs it so parallel_unit_free
	 * won't double-free. Verify never fails the unit - a mismatch goes to
	 * verify_failed_paths, not a retry - so it always returns 0 and
	 * worker_process_result just dec-pendings and frees it. */
	if (unit->op == SFTP_OP_VERIFY) {
		/*
		 * Range-granular: one transfer-range chunk of a large file. Many
		 * such units share the file's verify_job; the last to finish
		 * (ranges_left -> 0) records the file as failed if any chunk
		 * mismatched, and frees the job.
		 */
		if (unit->verify_job != NULL) {
			struct verify_job *job = unit->verify_job;
			int idx = unit->range_index;
			/* Upload re-uses a teed source hash where one was stored;
			 * download (and untee'd ranges) read the local range back. */
			int have_teed = (!job->local_is_target && job->valid[idx]);
			int verify_rc;

			/*
			 * Verify this chunk on the worker's own conn, splicing the
			 * bad 64 MiB sub-chunks in place on a mismatch. Each worker
			 * repairs only its own index, with no cross-worker
			 * coordination. Returns 0 for good or repaired, 1 for
			 * unrepairable, and -1 for unverifiable, which warns rather
			 * than counting as a content failure.
			 */
			int repaired = 0;

			verify_rc = sftp_hpn_verify_repair(worker->conn, job->local_path,
			    job->remote_path, job->local_is_target,
			    job->offs[idx], job->lens[idx],
			    have_teed, have_teed ? job->hashes[idx] : 0,
			    fleet->verify_repair_enabled, fleet->verify_repair_attempts,
			    &repaired);
			if (verify_rc == 1)	/* unrepairable mismatch */
				__atomic_store_n(&job->failed, 1, __ATOMIC_RELAXED);
			else if (verify_rc < 0)	/* couldn't verify this chunk */
				__atomic_store_n(&job->any_unverified, 1,
				    __ATOMIC_RELAXED);
			if (repaired)
				__atomic_store_n(&job->any_repaired, 1,
				    __ATOMIC_RELAXED);
			unit->verify_job = NULL;

			/* Meter: this chunk's hash work is done, both legs. End
			 * the op before folding, because the other order lets a
			 * reporter tick count the chunk twice and publish a rate
			 * spike, while the dip this order leaves is absorbed by
			 * the reporter's monotonic publish. */
			sftp_conn_hash_op_end(worker->conn);
			__atomic_fetch_add(&fleet->verify_done_bytes,
			    2 * (uint64_t)job->lens[idx], __ATOMIC_RELAXED);

			/*
			 * Last chunk to finish (the ACQ_REL barrier makes every
			 * worker's job->failed store visible here): record the file
			 * as failed if any chunk was unrepairable, then free the
			 * job. No separate repair phase - the repair already ran
			 * inline above.
			 */
			if (__atomic_sub_fetch(&job->ranges_left, 1,
			    __ATOMIC_ACQ_REL) == 0) {
				int j_failed = __atomic_load_n(&job->failed,
				    __ATOMIC_RELAXED);

				if (j_failed) {
					error_f("worker %d VERIFY FAILED: %s file "
					    "\"%s\" does NOT match source", worker->id,
					    job->local_is_target ? "local" : "remote",
					    job->local_is_target ? job->local_path
					    : job->remote_path);
					parallel_verify_fail_record(fleet,
					    job->local_is_target, job->local_path,
					    job->remote_path);
				}
				/* TransferLog: FINAL status for a range-split
				 * file under -V. Any unverifiable chunk
				 * demotes "verified" to plain success. */
				if (transferlog_active()) {
					struct stat local_st;
					long long size =
					    (stat(job->local_path, &local_st) == 0) ?
					    (long long)local_st.st_size : -1;
					enum transferlog_status status;

					if (j_failed)
						status = TRANSFERLOG_FAILED;
					else if (__atomic_load_n(
					    &job->any_repaired, __ATOMIC_RELAXED))
						status = TRANSFERLOG_REPAIRED;
					else if (__atomic_load_n(
					    &job->any_unverified, __ATOMIC_RELAXED))
						status = TRANSFERLOG_SUCCESS;
					else
						status = TRANSFERLOG_VERIFIED;
					transferlog_file(status, size,
					    job->local_is_target ?
					    job->local_path : job->remote_path);
				}
				parallel_verify_job_free(job);
			}
			__atomic_fetch_add(&fleet->verify_done_units, 1,
			    __ATOMIC_RELAXED);
			return 0;
		}

		/* Whole-file / small file: one unit per file, carried by a
		 * lightweight verify_whole_item. Verify+repair inline on this
		 * worker's own conn, then free the item. */
		if (unit->verify_whole != NULL) {
			struct verify_whole_item *item = unit->verify_whole;
			/* Rebuild each full path from its prefix + relative.
			 * Both rels share one buffer: local_rel is buf, remote_rel
			 * begins just past local_rel's NUL. */
			const char *lrel = item->buf;
			const char *rrel = item->buf + strlen(item->buf) + 1;
			char *local = parallel_verify_prefix_join(fleet,
			    item->local_prefix, lrel);
			char *remote = parallel_verify_prefix_join(fleet,
			    item->remote_prefix, rrel);

			parallel_verify_one(worker, local, remote,
			    item->local_is_target);
			free(local);
			free(remote);
			free(item);	/* single block: header + both rels */
			unit->verify_whole = NULL;
		} else {
			/* Exactly one carrier is always set (struct
			 * sftp_work_unit), so neither means the unit was
			 * built wrong upstream. */
			error_f("worker %d: verify unit carries neither a "
			    "verify_job nor a verify_whole item", worker->id);
		}
		/* Drive the verify-phase meter: count completed verifies (the
		 * submit interleaves with draining, so pending is ambiguous). */
		__atomic_fetch_add(&fleet->verify_done_units, 1, __ATOMIC_RELAXED);
		/* Byte-granular meter: this file's hash work is done. Capture
		 * the op's work-bytes, END the op, then fold - capture-end-fold
		 * is the required order (ending first loses the figure; folding
		 * first lets a reporter tick count the file twice). The dip
		 * between end and fold is absorbed by the monotonic publish. */
		{
			uint64_t work =
			    sftp_conn_hash_work_done_get(worker->conn);
			sftp_conn_hash_op_end(worker->conn);
			__atomic_fetch_add(&fleet->verify_done_bytes, work,
			    __ATOMIC_RELAXED);
		}
		return 0;
	}

	switch (unit->op) {
	case SFTP_OP_UPLOAD:
		/*
		 * Resume gate (Option A): unit->verify makes sftp_upload hash even
		 * on a size match (closes the sparse-hole gap). resume/verify
		 * are per-unit (the originating command's intent); the
		 * unsupported-remote fatal already fired up front in the main
		 * thread (see sftp_parallel_submit_upload), so the worker never
		 * fatals here. Return 1/2 are "already complete" skip codes -
		 * map to success below so the unit isn't retried.
		 */
		rc = sftp_upload(worker->conn, unit->src_path, unit->dst_path,
		    fleet->cfg.preserve_flag, unit->resume, /*verify=*/unit->verify,
		    fleet->cfg.fsync_flag, fleet->cfg.inplace_flag);
		if (rc == 0 && fleet->cfg.verify_transfer)
			parallel_verify_park_whole_file(fleet, unit->src_path,
			    unit->dst_path, /*local_is_target=*/0);  /* local = source */
		if (rc == 1 || rc == 2) {
			unit->skipped = 1;	/* TransferLog: final at completion */
			rc = 0;	/* identical / target-larger: complete */
		}
		break;
	case SFTP_OP_UPLOAD_RANGE: {
		/* Resume and post-transfer verify are decided per file at the
		 * orchestrator and finalize level, not per range. The warm
		 * handle comes from the worker's cache and is synced back. */
		struct sftp_range_warm warm = {
			worker->warm_handle, worker->warm_handle_len, worker->warm_dst_path
		};
		struct sftp_range_warm *warmp = &warm;
		rc = sftp_upload_range(worker->conn, unit->src_path, unit->dst_path,
		    unit->range_offset, unit->range_length, &unit->acked_bytes, warmp,
		    (unit->range_tracker != NULL && unit->range_tracker->verify)
		    ? &unit->range_hash : NULL);
		worker->warm_handle = warm.handle;
		worker->warm_handle_len = warm.handle_len;
		worker->warm_dst_path = warm.path;
		debug3("unit-exec: worker %d UPLOAD_RANGE [%lld+%lld) rc=%d "
		    "acked=%lld attempt=%d", worker->id,
		    (long long)unit->range_offset, (long long)unit->range_length,
		    rc, (long long)unit->acked_bytes, unit->attempt);
		/* Verify transfer: a range that transferred in one clean pass
		 * (first attempt, fully acked) has a teed source hash good for
		 * the whole original range - record it so finalize skips the
		 * source re-read. Pass the span actually covered: store_range_hash
		 * keeps the hash only if it still equals the slot's original
		 * [off, len), so a highwater-resumed remainder (which reaches here
		 * with attempt reset to 0) leaves the slot unset and is re-read per
		 * range at finalize. */
		if (rc == 0 && unit->attempt == 0 && unit->range_tracker != NULL &&
		    unit->acked_bytes == unit->range_length)
			parallel_unit_store_range_hash(unit->range_tracker,
			    unit->range_index, (uint64_t)unit->range_offset,
			    (uint64_t)unit->range_length, unit->range_hash);
		break;
	}
	case SFTP_OP_DOWNLOAD_RANGE:
		rc = sftp_download_range(worker->conn, unit->src_path, unit->dst_path,
		    unit->range_offset, unit->range_length, &unit->acked_bytes);
		debug3("unit-exec: worker %d DOWNLOAD_RANGE [%lld+%lld) rc=%d "
		    "acked=%lld attempt=%d", worker->id,
		    (long long)unit->range_offset, (long long)unit->range_length,
		    rc, (long long)unit->acked_bytes, unit->attempt);
		break;
	case SFTP_OP_RESUME_SPAN: {
		/*
		 * Verified-resume overlap span: reconcile [offset, length) of
		 * the existing partial against the source through the shared
		 * verify and repair engine, which hash-compares in chunks and
		 * splices only the runs that differ. Repair is forced on
		 * whatever the user's setting, because for a resume the repair
		 * is the transfer. The engine opens a hash op on the conn, so
		 * the resume-check meter and the watchdog's hash gate see this
		 * work as they do the serial path. Anything but 0 takes the
		 * normal retry path; the engine is idempotent, so a whole-span
		 * retry after a worker death re-hashes and re-splices safely.
		 */
		int local_is_target = (unit->range_tracker != NULL &&
		    unit->range_tracker->target == SFTP_RANGE_TARGET_LOCAL);

		rc = sftp_hpn_verify_repair(worker->conn,
		    local_is_target ? unit->dst_path : unit->src_path,
		    local_is_target ? unit->src_path : unit->dst_path,
		    local_is_target, unit->range_offset, unit->range_length,
		    /*have_local_hash=*/0, /*local_hash=*/0,
		    /*repair_enabled=*/1, parallel_unit_max_retries(fleet),
		    /*repaired_out=*/NULL);
		debug3("unit-exec: worker %d RESUME_SPAN [%lld+%lld) rc=%d "
		    "attempt=%d", worker->id, (long long)unit->range_offset,
		    (long long)unit->range_length, rc, unit->attempt);
		rc = (rc == 0) ? 0 : -1;
		break;
	}
	case SFTP_OP_DOWNLOAD:
		rc = sftp_download(worker->conn, unit->src_path, unit->dst_path,
		    /*Attrib*/NULL, fleet->cfg.preserve_flag,
		    unit->resume, fleet->cfg.fsync_flag,
		    fleet->cfg.inplace_flag, /*verify=*/unit->verify);
		if (rc == 0 && fleet->cfg.verify_transfer)
			parallel_verify_park_whole_file(fleet, unit->dst_path,
			    unit->src_path, /*local_is_target=*/1);  /* local = downloaded */
		if (rc == 1 || rc == 2) {
			unit->skipped = 1;	/* TransferLog: final at completion */
			rc = 0;	/* identical / target-larger: complete */
		}
		break;
	case SFTP_OP_VERIFY:
		/* Handled before the switch via an early return; reaching the
		 * switch with a verify op is a bug. */
		fatal_f("verify unit reached execute_unit switch (op=%d)",
		    (int)unit->op);
		break;
	case SFTP_OP_BUNDLE_UPLOAD:
	case SFTP_OP_BUNDLE_DOWNLOAD:
		/* Bundle containers are dispatched directly in the worker loop
		 * (worker_dispatch_bundle_container) and never reach here. */
		fatal_f("bundle container reached execute_unit (op=%d)",
		    (int)unit->op);
		break;
	}
	return rc;
}

/*
 * The bookkeeping every permanent give-up owes the rest of the fleet: the
 * worker's counters, the transfer log, the file's range tracker, the
 * failed-paths list the end of run summary prints, and last of all the
 * pending count. The unit is freed at the end, so the caller must treat it
 * as dead.
 */
static void
worker_retire_failed_unit(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit *unit, const char *cause)
{
	worker_record_completion(worker, 0, 0);
	/* TransferLog: a whole-file give-up is the file's final status, while
	 * range and span give-ups are logged once at tracker finalize. */
	if (unit->op == SFTP_OP_UPLOAD || unit->op == SFTP_OP_DOWNLOAD)
		transferlog_file(TRANSFERLOG_FAILED, (long long)unit->size,
		    unit->dst_path);
	(void)parallel_unit_tracker_finalize(unit->range_tracker, 1, worker);
	worker_record_failed_path(fleet, unit, cause);
	/* Dropping pending is what wakes sftp_parallel_wait, so it goes last,
	 * after everything this worker still had to do with shared state. The
	 * success path in worker_process_result orders it the same way. */
	parallel_unit_pending_dec(fleet);
	parallel_unit_free(unit);
}

/*
 * Gives up on a work unit for good, either because it ran out of retries or
 * because the failure was one that retrying cannot clear. Takes a copy of
 * the thread's most recent error log line first, since the give-up log below
 * would otherwise overwrite the text that explains the failure.
 *
 * log_prefix names the caller in the give-up log, "unit" for single dispatch
 * and "batch unit" for a member of a pipelined batch.
 */
static void
worker_give_up_unit(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit *unit, const char *log_prefix)
{
	char        cause[256];
	const char *captured = hpn_get_last_error();
	const char *path = unit->src_path;

	if (captured == NULL || *captured == '\0')
		captured = "(no error captured)";
	strlcpy(cause, captured, sizeof(cause));
	if (path == NULL)
		path = "(unknown path)";

	error_f("worker %d: %s failed after %d attempts: %s",
	    worker->id, log_prefix, unit->attempt, path);
	worker_retire_failed_unit(fleet, worker, unit, cause);
}

/*
 * Gives up on a unit the workqueue refused to take back, which happens when
 * the queue is shutting down. The unit can never run, so it gets the same
 * bookkeeping with "queue shutdown" as the cause.
 *
 * Nothing logs this on its own: the queue does not log a refused push and
 * this path deliberately stays quiet, since a shutting-down fleet would
 * otherwise emit one line per undelivered unit. What the user sees is the
 * failed-paths entry in the end of run summary.
 *
 * The caller has already tried the push and failed; this only cleans up.
 */
static void
worker_give_up_pushfail(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit *unit)
{
	worker_retire_failed_unit(fleet, worker, unit, "queue shutdown");
}

/*
 * Decides whether a failed unit goes back on the queue or is given up on,
 * and carries out whichever it is. This is the retry policy for every path:
 * a dead connection or a cooperative yield requeues without spending an
 * attempt and jumps the queue, anything else spends one and goes to the
 * tail. A permission denied on a live connection is permanent, since no
 * number of retries can clear it.
 *
 * The increment sits inside the condition on purpose: a transient or a yield
 * short-circuits before it, which is how those two requeue for free. The
 * push is non-blocking because a worker must never block on a full queue it
 * also drains, which self-deadlocks at -j1.
 */
static void
worker_retry_or_give_up(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit *unit, int transient, int yielded,
    const char *log_prefix)
{
	if (!transient && sftp_conn_saw_perm_denied(worker->conn))
		unit->no_retry = 1;
	if (!unit->no_retry &&
	    (transient || yielded ||
	    ++unit->attempt < parallel_unit_max_retries(fleet))) {
		if (parallel_worker_requeue(fleet, unit, transient || yielded) != 0)
			worker_give_up_pushfail(fleet, worker, unit);
		else if (yielded)
			sftp_workqueue_kick(fleet->q);
		return;
	}
	worker_give_up_unit(fleet, worker, unit, log_prefix);
}

/*
 * Decides what happens to a unit after the worker has run it, and owns the
 * retry policy.
 *
 * A success records the bytes, writes the transfer log line for a whole
 * file, finalizes the file's range tracker, and frees the unit.
 *
 * A failure is classified first. A dead connection is transient and
 * blameless: this worker is about to exit and be replaced, so the unit
 * returns to the queue without charging its retry budget. A failure on a
 * live connection is ambiguous and does charge it, bounded by the retry
 * limit. A permission denied on a live connection is permanent and gives up
 * at once, since no number of retries can clear it.
 *
 * A partially landed range requeues as just its unlanded remainder, and
 * because it made progress its retry budget is reset. That way a flaky but
 * advancing range cannot run out of retries at 90 percent transferred.
 *
 * Transients and cooperative yields go to the front of the queue so another
 * worker takes them promptly; an ambiguous retry goes to the tail so the
 * same worker does not immediately re-pop and re-fail it.
 */
static void
worker_process_result(struct sftp_worker *worker, struct sftp_work_unit *unit, int rc)
{
	struct sftp_parallel *fleet = worker->parent;

	/* Cooperative yield: consume and clear the request whatever the
	 * outcome, so a unit that completed despite the flag does not poison
	 * the next dispatch. A yielded failure on a live connection is
	 * voluntary and requeues without charging the retry budget. */
	int yielded = __atomic_exchange_n(&worker->yield_req, 0, __ATOMIC_RELAXED);

	/* Free the per-inode writer slot claimed in parallel_worker_thread's
	 * dispatch gate. Reached exactly once per executed unit on every
	 * path, so retries release here and re-acquire when re-dispatched.
	 * NULL tracker = no-op. The kick wakes workers parked in the
	 * cap-gate's wait_activity so a freed slot is picked up immediately
	 * instead of on the timeout. */
	if (unit->range_tracker != NULL) {
		parallel_unit_writer_release(unit->range_tracker);
		sftp_workqueue_kick(fleet->q);
	}

	if (rc == 0) {
		worker_record_completion(worker, unit->size, 1);
		/* TransferLog: a whole-file unit's status is final here -
		 * skipped always (never parked), success when no verify
		 * phase follows (with -V the line defers to the verify
		 * resolution). Range/span files log at tracker finalize. */
		if ((unit->op == SFTP_OP_UPLOAD || unit->op == SFTP_OP_DOWNLOAD) &&
		    (unit->skipped || !fleet->cfg.verify_transfer))
			transferlog_file(unit->skipped ? TRANSFERLOG_SKIPPED :
			    TRANSFERLOG_SUCCESS, (long long)unit->size,
			    unit->dst_path);
		/*
		 * Range tracker: this range finished cleanly. Finalize before
		 * decrementing pending, because finalize writes the transfer log
		 * line and, for the last range of the file, either parks the
		 * tracker for the verify phase or frees it. Dropping pending to
		 * zero is what wakes sftp_parallel_wait, so it goes after the
		 * worker is done with that shared state. The give-up path in
		 * worker_retire_failed_unit orders it the same way.
		 */
		(void)parallel_unit_tracker_finalize(unit->range_tracker, 0, worker);
		parallel_unit_pending_dec(fleet);
		parallel_unit_free(unit);
	} else {
		/*
		 * Failure. Transient means the connection is dead and this worker
		 * is about to be replaced; ambiguous means it failed on a live
		 * connection. Not charging the retry budget for a transient
		 * matters: peer-stall churn burning through the budget is what
		 * abandoned byte ranges in the br008 j8 data-loss bug.
		 */
		int transient = sftp_conn_is_dead(worker->conn);

		/* A yield on a connection that died during the wind-down is not a
		 * yield but an ordinary death, which the transient path already
		 * handles; a respawned worker cannot defer anything. */
		if (transient)
			yielded = 0;

		/*
		 * Highwater resume: the failed attempt confirmed
		 * acked_bytes contiguous bytes on the target, so the unit
		 * requeues as just its unlanded remainder. Worker death
		 * costs the in-flight window, not the whole range. Progress
		 * also resets the retry budget. Attempts only count when
		 * they were fruitless, so a flaky-but-advancing range cannot
		 * exhaust retries and give up at 90% transferred. The
		 * tracker is untouched: same unit, same single finalize.
		 */
		if ((unit->op == SFTP_OP_UPLOAD_RANGE ||
		    unit->op == SFTP_OP_DOWNLOAD_RANGE) &&
		    unit->acked_bytes > 0 &&
		    unit->acked_bytes < unit->range_length) {
			debug("worker %d: range \"%s\" [%lld+%lld) resumes "
			    "past %lld acked bytes%s", worker->id,
			    unit->dst_path ? unit->dst_path : unit->src_path,
			    (long long)unit->range_offset,
			    (long long)unit->range_length,
			    (long long)unit->acked_bytes,
			    yielded ? " (cooperative yield)" : "");
			/* Those acked bytes really landed on the target, so
			 * credit them now. The retry carries only the
			 * remainder, and live_bytes is add-only and about to
			 * be reset, so this is the one chance to count them. */
			pthread_mutex_lock(&worker->mu);
			worker->bytes_total += (uint64_t)unit->acked_bytes;
			pthread_mutex_unlock(&worker->mu);
			unit->range_offset += unit->acked_bytes;
			unit->range_length -= unit->acked_bytes;
			unit->size = unit->range_length;
			unit->attempt = 0;
			unit->acked_bytes = 0;
		}
		/* This attempt is done with. Clear the live counter the way
		 * worker_finalize_one_entry does, so the next attempt starts
		 * from zero instead of inheriting this one's bytes. */
		__atomic_store_n(&worker->live_bytes, 0, __ATOMIC_RELAXED);

		/* Yield handoff: mark the remainder so dispatch gives another
		 * worker first crack at it, one courtesy defer. */
		if (yielded)
			unit->yield_from = worker->id + 1;
		else
			unit->yield_from = 0;

		worker_retry_or_give_up(fleet, worker, unit, transient, yielded,
		    "unit");
	}
}

/*
 * Retires one member of a completed batch or bundle. A success counts the
 * bytes, writes the transfer log line, and, when verifying, parks the file
 * for the post-transfer verify phase. Any non-zero result (rc) is a failure and
 * goes through the same retry decision as a single unit.
 *
 * This is where the pipelined upload batch and the bundle path converge, so
 * parking here is what gives both of them verify coverage. Single files and
 * range-split files park in execute_unit and at tracker finalize instead.
 */
static void
worker_finalize_one_entry(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit *unit, int rc)
{
	/* anything other than rc == 0 indicates a failure */
	if (rc == 0) {
		worker_record_completion(worker, unit->size, 1);
		/* TransferLog: batched/bundled member success is final here
		 * unless the verify phase will resolve it. */
		if (!fleet->cfg.verify_transfer)
			transferlog_file(TRANSFERLOG_SUCCESS,
			    (long long)unit->size, unit->dst_path);
		else if (unit->op == SFTP_OP_UPLOAD)
			parallel_verify_park_whole_file(fleet, unit->src_path,
			    unit->dst_path, /*local_is_target=*/0);
		else if (unit->op == SFTP_OP_DOWNLOAD)
			parallel_verify_park_whole_file(fleet, unit->dst_path,
			    unit->src_path, /*local_is_target=*/1);
		parallel_unit_pending_dec(fleet);
		parallel_unit_free(unit);
		return;
	}
	int transient = sftp_conn_is_dead(worker->conn);

	/* This attempt is over: clear the live counter so the next one starts
	 * from zero. A batch member is a whole file, so there is no partially
	 * landed remainder to credit the way a range unit has. */
	__atomic_store_n(&worker->live_bytes, 0, __ATOMIC_RELAXED);
	worker_retry_or_give_up(fleet, worker, unit, transient, /*yielded=*/0,
	    "batch unit");
}

/*
 * Retires the members of the carried-over batch and clears it. The caller
 * has already collected that batch's replies, either through
 * sftp_upload_batch_finish or through the drain that runs inside
 * sftp_upload_batch_send, so every entry result is final by the time we get
 * here. No-op when nothing is carried over.
 */
static void
worker_finalize_prev_batch(struct sftp_worker *worker)
{
	struct sftp_parallel *fleet = worker->parent;

	if (worker->batch_prev_units == NULL)
		return;
	for (int i = 0; i < worker->batch_prev_n; i++)
		worker_finalize_one_entry(fleet, worker,
		    worker->batch_prev_units[i],
		    worker->batch_prev_entries[i].result);
	free(worker->batch_prev_units);
	free(worker->batch_prev_entries);
	worker->batch_prev_units   = NULL;
	worker->batch_prev_entries = NULL;
	worker->batch_prev_n       = 0;
}

/*
 * Finishes the batch whose CLOSE collection was deferred while the next
 * batch's opens went out, retires each member through
 * worker_finalize_one_entry, and clears the carry-over state.
 *
 * Called before this worker does anything that is not another batch, and
 * again on the way out. Doing it before a blocking pop matters: the deferred
 * replies are already in the socket, and blocking on an empty queue without
 * reading them stalls the server behind TCP back-pressure.
 *
 * The permission-denied signal is cleared first so a denial from an earlier
 * unit cannot make every member of this batch permanent. The pending struct
 * is freed by sftp_upload_batch_finish; the two arrays are ours to free.
 */
static void
worker_drain_pipeline(struct sftp_worker *worker)
{
	if (worker->batch_prev_pending == NULL)
		return;
	sftp_conn_clear_perm_denied(worker->conn); /* scope to this batch drain */
	(void)sftp_upload_batch_finish(worker->conn, worker->batch_prev_pending);
	worker->batch_prev_pending = NULL; /* freed elsewhere */
	worker_finalize_prev_batch(worker);
}

/*
 * Sends one upload batch with its opens pipelined, and keeps the previous
 * batch's replies moving at the same time.
 *
 * The entry and unit arrays are heap allocated because they outlive this
 * call: they belong to the batch that is still in flight when the worker
 * returns to its loop. sftp_upload_batch_send drains the previous batch
 * inside its first phase, so those replies are collected while this batch's
 * opens are already on the wire, which is the point of the split. Its
 * members are retired here once that drain has run.
 *
 * A failed send marks every entry in both batches failed and returns NULL,
 * so this batch is retired immediately and nothing is carried over.
 */
static void
worker_run_batch_pipelined(struct sftp_worker *worker,
    struct sftp_work_unit **batch, int batch_n)
{
	struct sftp_parallel *fleet = worker->parent;
	struct sftp_upload_batch_entry *entries;
	struct sftp_work_unit **units;
	struct sftp_upload_batch_pending *new_pending;

	/* scope the permanent-denial signal to this batch's drain. */
	sftp_conn_clear_perm_denied(worker->conn);

	/* Pipelined path: heap-allocate the entry and unit arrays so they
	 * survive across the next parallel_worker_thread iteration. */
	entries = xcalloc(batch_n, sizeof(*entries));
	units   = xcalloc(batch_n, sizeof(*units));
	for (int i = 0; i < batch_n; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		units[i]               = batch[i];
		worker_record_start(worker);
	}

	/* send() drains batch_prev_pending, if any, after its own
	 * opens are on the wire; that overlap is the win. */
	new_pending = sftp_upload_batch_send(worker->conn, entries, batch_n,
	    fleet->cfg.preserve_flag, fleet->cfg.fsync_flag,
	    fleet->cfg.inplace_flag,
	    worker->batch_prev_pending);
	/* batch_prev_pending has been freed inside send. */
	worker->batch_prev_pending = NULL;

	/* The prev batch's entries were populated by the drain that just ran
	 * inside send, so its members can be retired now. */
	worker_finalize_prev_batch(worker);

	if (new_pending == NULL) {
		/* This batch's send failed. Every entry has result == -1;
		 * finalise inline and don't carry over. */
		for (int i = 0; i < batch_n; i++)
			worker_finalize_one_entry(fleet, worker, units[i],
			    entries[i].result);
		free(units);
		free(entries);
	} else {
		/* Save this batch as the new prev for the next iteration. */
		worker->batch_prev_pending = new_pending;
		worker->batch_prev_units   = units;
		worker->batch_prev_entries = entries;
		worker->batch_prev_n       = batch_n;
	}
}

/*
 * Shared tail for the two bundle paths: accounts the member bytes, logs one
 * line per bundle, decides what a bundle-level failure means for the members,
 * and retires each of them with its own result.
 *
 * Two failures are handled here. A server that cannot bundle at all marks the
 * members ineligible so they fall back to the per-file path. A server whose
 * request policy denies this class of transfer stops the whole run, since
 * every remaining file would be denied one at a time anyway. A transport
 * failure is deliberately neither: those units bundle fine on a healthy
 * worker, so they stay eligible and requeue as ordinary transients.
 *
 * The two callers differ only in their entry struct, so they copy the
 * per-entry results into results[] first. label is the log tag.
 */
static void
worker_finish_bundle(struct sftp_parallel *fleet, struct sftp_worker *worker,
    struct sftp_work_unit **batch, int batch_n, int bundle_rc,
    const int *results, uint64_t total_bytes,
    uint64_t t_start_ms, uint64_t t_end_ms,
    const char *label)
{
	uint64_t elapsed_ms = t_end_ms - t_start_ms;
	off_t wired_data = 0;
	double mibps = 0.0;
	int i, ok_count = 0;

	for (i = 0; i < batch_n; i++)
		if (results[i] == 0) {
			ok_count++;
			wired_data += batch[i]->size;
		}
	/* Count member data, not the tar-framed wire stream, for the run
	 * summary, so it reflects what the user moved. Only the ok
	 * members; failed ones re-transfer and are counted on that path. */
	sftp_conn_bytes_wired_add(worker->conn, (uint64_t)wired_data);
	if (elapsed_ms > 0)
		mibps = ((double)total_bytes / (1024.0 * 1024.0)) /
		    ((double)elapsed_ms / 1e3);
	/* One stderr line per bundle; format for easy grepping */
	debug("%s worker=%d files=%d ok=%d bytes=%llu elapsed_ms=%llu "
	    "MiBps=%.2f", label, worker->id, batch_n, ok_count,
	    (unsigned long long)total_bytes,
	    (unsigned long long)elapsed_ms, mibps);

	/*
	 * Downgrade to single-file only when the server itself cannot bundle
	 * due to a permanent, connection agnostic reason any worker would hit.
	 * A TRANSPORT_FAILED is not such a reason. The units bundle fine on
	 * a healthy worker, so leave them eligible and let
	 * worker_finalize_one_entry re-queue them (the dead-conn transient
	 * path). Marking them ineligible here is a bundle-ineligible
	 * poisoning that can cause significant performance issues.
	 */
	if (bundle_rc == SFTP_HPN_BUNDLE_POLICY_DENIED) {
		/*
		 * The server's -P/-p request policy forbids this whole class of
		 * transfer - every file would be denied. Fail this batch with
		 * no per-file fallback and stop the entire transfer: abort_flag
		 * halts each worker at the top of its loop and the workqueue
		 * shutdown wakes any blocked in pop, so we don't grind through
		 * and re-deny every remaining file. Only a confirmed policy
		 * tag reaches here, so a real per-file ACL still takes the
		 * SERVER_CANT fallback below.
		 */
		for (i = 0; i < batch_n; i++)
			batch[i]->no_retry = 1;
		/* Exchange, not test-then-set: two workers denied in the same
		 * instant would otherwise both print the line. */
		if (__atomic_exchange_n(&fleet->policy_denied, 1,
		    __ATOMIC_RELAXED) == 0)
			logit("transfer stopped: server request policy denies "
			    "this class of transfer");
		fleet->abort_flag = 1;
		if (fleet->q != NULL)
			sftp_workqueue_shutdown(fleet->q);
	} else if (bundle_rc == SFTP_HPN_BUNDLE_SERVER_CANT) {
		for (i = 0; i < batch_n; i++)
			batch[i]->bundle_ineligible = 1;
	}

	/*
	 * A bundle member has not yet had its own per-file open/write attempted,
	 * so the per-conn saw_perm_denied flag (whether stale from a prior unit
	 * on this worker or set by the bundle's own container OPEN) must not
	 * decide the members' no_retry. Clear it so a SERVER_CANT bundle's
	 * members fall back to the per-file path, where each member's own denial
	 * sets no_retry. POLICY_DENIED already set no_retry explicitly
	 * above; TRANSPORT_FAILED is guarded by !transient in the finalizer.
	 */
	sftp_conn_clear_perm_denied(worker->conn);

	for (i = 0; i < batch_n; i++)
		worker_finalize_one_entry(fleet, worker, batch[i], results[i]);
}

/*
 * Bundle-mode analogue of worker_run_batch_pipelined. The batch of small
 * files is packed into a single tar stream and shipped through one
 * OPEN/WRITE/CLOSE on a fresh bundle handle, which removes the per-file open
 * and close round trip that limits the pipelined path on high-RTT links.
 *
 * sftp_hpn_bundle_upload reports success per entry. When the bundle itself
 * fails every entry is marked failed and the members retry individually,
 * with no batch-wide retry needed: they are still separate work-queue units.
 *
 * TODO: this path is synchronous, so nothing overlaps the next batch. It
 * could be split into send and finish like the pipelined path, which is only
 * worth the complexity if a benchmark shows bundle close latency mattering.
 */
static void
worker_run_bundle(struct sftp_worker *worker,
    struct sftp_work_unit **batch, int batch_n)
{
	struct sftp_parallel *fleet = worker->parent;
	struct sftp_hpn_bundle_upload_entry *entries;
	struct sftp_bundle_opts opts;
	int *results;
	uint64_t total_bytes = 0, t_start_ms, t_end_ms;
	int i, bundle_rc;

	entries = xcalloc(batch_n, sizeof(*entries));
	results = xcalloc(batch_n, sizeof(*results));
	for (i = 0; i < batch_n; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(worker);
	}

	t_start_ms = monotime_ms();
	/* dest_dir = "" Each remote_path is treated as an absolute path by
	 * the server-side bundle handler. This avoids computing a common
	 * prefix across the batch. The server's bundle extractor calls mkdir_p
	 * on each containing directory anyway. Slight wire-size cost (full
	 * path repeated in every tar header) but trivial vs the small-file
	 * payloads. */
	opts.preserve = fleet->cfg.preserve_flag;
	opts.fsync = fleet->cfg.fsync_flag;
	opts.writer_pool = fleet->cfg.writer_pool;
	bundle_rc = sftp_hpn_bundle_upload(worker->conn, "", entries, batch_n,
	    &opts, fleet->cfg.bundle_size);
	t_end_ms = monotime_ms();

	for (i = 0; i < batch_n; i++)
		results[i] = entries[i].result;
	
	worker_finish_bundle(fleet, worker, batch, batch_n, bundle_rc, results,
            total_bytes, t_start_ms, t_end_ms, "BUNDLE");

	free(entries);
	free(results);
}

/*
 * Download counterpart of worker_run_bundle. Builds the entry array from a
 * batch of download units, with each unit's source path as the remote and
 * its destination as the local, and asks the server to pack those paths into
 * one tar stream. worker_finish_bundle does the accounting, the log line,
 * the failure handling, and the per-member retirement.
 */
static void
worker_run_bundle_download(struct sftp_worker *worker,
    struct sftp_work_unit **batch, int batch_n)
{
	struct sftp_parallel *fleet = worker->parent;
	struct sftp_hpn_bundle_download_entry *entries;
	struct sftp_bundle_opts opts;
	int *results;
	uint64_t total_bytes = 0, t_start_ms, t_end_ms;
	int i, bundle_rc;

	entries = xcalloc(batch_n, sizeof(*entries));
	results = xcalloc(batch_n, sizeof(*results));
	for (i = 0; i < batch_n; i++) {
		entries[i].remote_path = batch[i]->src_path;
		entries[i].local_path  = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(worker);
	}

	t_start_ms = monotime_ms();
	opts.preserve = fleet->cfg.preserve_flag;
	opts.fsync = fleet->cfg.fsync_flag;
	opts.writer_pool = fleet->cfg.writer_pool;
	bundle_rc = sftp_hpn_bundle_download(worker->conn, entries, batch_n,
	    &opts, /*progress=*/NULL);
	t_end_ms = monotime_ms();

	for (i = 0; i < batch_n; i++)
		results[i] = entries[i].result;
	worker_finish_bundle(fleet, worker, batch, batch_n, bundle_rc, results, total_bytes,
	    t_start_ms, t_end_ms, "BUNDLE-DL");

	free(entries);
	free(results);
}

/*
 * Dispatches a bundle container that the producer already grouped, so there
 * is no accumulation race here. The member array is detached first, run
 * through the same array-based path a worker-accumulated batch uses, and the
 * empty shell freed.
 *
 * The shell carries no pending count of its own; each member was counted
 * when it joined the accumulator and is discounted by its own retirement.
 */
static void
worker_dispatch_bundle_container(struct sftp_worker *worker,
    struct sftp_work_unit *unit)
{
	struct sftp_work_unit **members = unit->members;
	int n = unit->n_members;

	unit->members = NULL;	/* detach: shell free must not touch members */
	unit->n_members = 0;
	if (unit->op == SFTP_OP_BUNDLE_DOWNLOAD)
		worker_run_bundle_download(worker, members, n);
	else
		worker_run_bundle(worker, members, n);
	free(members);
	parallel_unit_free(unit);
}

/*
 * Runs one work unit outside the batch paths: drains any deferred pipelined
 * batch first, since its unread replies would corrupt the next request, then
 * runs the unit and hands the result to worker_process_result.
 *
 * Called from three places in parallel_worker_thread: when the batch loop
 * collected only one unit, for a unit popped during collection that did not
 * belong in the batch, and for everything that never enters a batch at all,
 * which is downloads without bundling, range units, and resume spans.
 */
static void
worker_execute_single(struct sftp_worker *worker, struct sftp_work_unit *unit)
{
	/*
	 * A bundle container can reach the single-file path as an accumulate-
	 * loop "leftover": once a transient bundle failure re-queues its members
	 * as individual units, the queue mixes containers with individuals, and
	 * a worker accumulating individuals can trypop a container (off-op ->
	 * leftover). Dispatch it as a bundle, not through execute_unit (which
	 * fatals on a container op).
	 */
	if (unit->op == SFTP_OP_BUNDLE_UPLOAD || unit->op == SFTP_OP_BUNDLE_DOWNLOAD) {
		worker_dispatch_bundle_container(worker, unit);
		return;
	}
	worker_drain_pipeline(worker);
	worker_record_start(worker);
	int rc = execute_unit(worker, unit);
	worker_process_result(worker, unit, rc);
}

/*
 * One-time worker setup, run before the loop starts: block SIGALRM so the
 * progress meter's timer ticks reach only the main thread and the reporter,
 * mark the worker as holding no range, and settle whether this worker will
 * bundle.
 *
 * Bundling needs both sides to agree: HPNUseBundle must not be off in
 * ssh_config, and the server must advertise the extension. Failing either,
 * the worker falls back to the pipelined batch path.
 */
static void
worker_thread_init(struct sftp_worker *worker)
{
	/* Mask SIGALRM so progressmeter timer ticks deliver only to the
	 * main thread / reporter (which holds it unmasked). */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	/* -1 = "holds no range" (0 is a valid range_offset); the watchdog's
	 * stuck-range detector compares against this. */
	__atomic_store_n(&worker->unit_offset, (int64_t)-1, __ATOMIC_RELAXED);

	/* set our bundle size */ 
	if (worker->parent->cfg.bundle_size > 0)
		worker->bundle_target_bytes = worker->parent->cfg.bundle_size;
	else
		worker->bundle_target_bytes = BUNDLE_TARGET_BYTES_DEFAULT;

	/* can we use the bundle method? Might be disabled or not available */
	if (worker->parent->cfg.use_bundle == 0) {
		debug_ft("worker %d: bundle disabled by "
		    "ssh_config HPNUseBundle no", worker->id);
	} else if (sftp_conn_has_hpn_bundle(worker->conn)) {
		worker->bundle_enabled = 1;
		debug_ft("worker %d: hpn-bundle enabled (target_bytes=%llu)",
		    worker->id, (unsigned long long)worker->bundle_target_bytes);
	} else {
		debug_ft("worker %d: server lacks hpn-bundle extension, "
		    "using the pipelined batch fallback", worker->id);
	}
}

/*
 * Post-iteration check: returns 1 when the worker should break out of the
 * loop, either because its connection died or because it hit a protocol
 * violation. A second violation in one session does not return at all - it
 * fatals the process.
 *
 * The threshold is a fixed count rather than a rate because a correctly
 * functioning server produces zero violations regardless of worker count or
 * transfer length: the SSH MAC catches in-channel tampering below this
 * layer, so anything arriving here is already abnormal. One is tolerated
 * because a single bit-flip on a long transfer is a known and
 * benign-but-noisy hardware failure. Two is a pattern, which means a buggy
 * or compromised server or a persistent fault, and papering over that would
 * be worse than stopping.
 *
 * Strike 1 leaves the unit cleanup already done by worker_process_result or
 * the batch result loop, and the reporter's respawn machinery replaces the
 * worker. Strike 2 exits the process; the OS reaps the remaining SSH
 * children.
 */
static int
worker_should_terminate(struct sftp_worker *worker)
{
	struct sftp_parallel *fleet = worker->parent;

	if (sftp_conn_is_protocol_violation(worker->conn)) {
		int total;

		pthread_mutex_lock(&fleet->workers_mu);
		fleet->protocol_violations++;
		total = fleet->protocol_violations;
		pthread_mutex_unlock(&fleet->workers_mu);

		if (total >= 2) {
			fatal("worker %d: protocol violation #%d in "
			    "this session - sustained pattern, "
			    "aborting hpnsftp (possible server "
			    "corruption, MITM, or persistent "
			    "hardware fault)", worker->id, total);
		}
		error_f("worker %d: protocol violation #%d - killing "
		    "worker and respawning; one more this session "
		    "will exit hpnsftp", worker->id, total);
		return 1;	/* the conn is dead either way */
	}

	if (sftp_conn_is_dead(worker->conn)) {
		if (!fleet->abort_flag && !fleet->stopped)
			debug_ft("worker %d: connection lost - "
			    "will attempt to respawn", worker->id);
		return 1;
	}
	return 0;
}

/*
 * Collects units that can travel with `first` into batch[], stopping at the
 * batch size, the byte cap, the fetch-request cap, or the first unit that
 * does not belong. Returns how many units are in the batch, always at least
 * one. A unit that was popped and rejected is handed back through
 * leftover_out for the caller to run on its own.
 */
static int
worker_collect_batch(struct sftp_worker *worker, struct sftp_work_unit *first,
    struct sftp_work_unit **batch, int batch_cap,
    struct sftp_work_unit **leftover_out)
{
	struct sftp_parallel *fleet = worker->parent;
	enum sftp_op batch_op = first->op;
	int batch_n = 0;
	/* Byte cap: bundle mode uses the smaller per-bundle target so each tar
	 * stream still composes well with the other parallel streams. The first
	 * unit is always taken, even when it alone exceeds the cap, so a single
	 * large file is never orphaned. */
	uint64_t batch_bytes = 0;
	uint64_t batch_byte_cap;
	/* A download bundle lists every member's remote path in one
	 * hpn-bundle-fetch request, so collection also stops before that list
	 * overflows SFTP_MAX_MSG_LENGTH. An upload streams its paths inside the
	 * tar and is immune. Cost per member is a 4-byte length plus the path;
	 * the cap leaves room for one PATH_MAX overshoot, since the gate is
	 * checked after the last add, plus the request header. */
	uint64_t batch_path_bytes = 0;

	if (first->size > 0)
		batch_bytes = (uint64_t)first->size;
	if (worker->bundle_enabled)
		batch_byte_cap = worker->bundle_target_bytes;
	else
		batch_byte_cap = UPLOAD_BATCH_BYTE_CAP;

	*leftover_out = NULL;
	batch[batch_n++] = first;
	if (batch_op == SFTP_OP_DOWNLOAD) {
		batch_path_bytes = 4;
		if (first->src_path != NULL)
			batch_path_bytes += strlen(first->src_path);
	}
	/* In bundle mode the byte gate is strict, so a unit is only popped when
	 * there is budget left for it. The soft gate popped one unit too many:
	 * with batch_bytes already at the cap it still popped, then discarded
	 * the unit to the leftover path, costing exactly one bundle-eligible
	 * unit per batch. The non-bundle path keeps the soft gate so a single
	 * larger-than-target unit is not orphaned. */
	while (batch_n < batch_cap && !fleet->abort_flag &&
	    (worker->bundle_enabled
	        ? batch_bytes <  batch_byte_cap
	        : batch_bytes <= batch_byte_cap) &&
	    (batch_op != SFTP_OP_DOWNLOAD ||
	        batch_path_bytes < BUNDLE_DL_FETCH_REQ_MAX)) {
		void *next_item = NULL;
		if (sftp_workqueue_trypop(fleet->q, &next_item) != 0)
			break;	/* queue empty or shutdown */
		struct sftp_work_unit *next_unit = next_item;
		/* Even with the strict gate a unit can overshoot on its own,
		 * so it still needs a fits check. Bundle-ineligibility at
		 * parallel_unit_submit bounds unit size to a quarter of the
		 * cap, which makes this rare. */
		int fits = 1;
		if (worker->bundle_enabled && next_unit->size > 0 &&
		    batch_bytes + (uint64_t)next_unit->size > batch_byte_cap)
			fits = 0;
		if (next_unit->op != batch_op ||
		    next_unit->bundle_ineligible || !fits) {
			/* Wrong op, not bundleable, or no room: stop here and
			 * let the caller run it by itself. */
			*leftover_out = next_unit;
			break;
		}
		batch[batch_n++] = next_unit;
		if (next_unit->size > 0)
			batch_bytes += (uint64_t)next_unit->size;
		if (batch_op == SFTP_OP_DOWNLOAD) {
			batch_path_bytes += 4;
			if (next_unit->src_path != NULL)
				batch_path_bytes += strlen(next_unit->src_path);
		}
	}
	return batch_n;
}

/*
 * Collects a batch around `first` and dispatches it: a batch of one takes the
 * single-unit path, a download batch is bundle-fetched, and an upload batch is
 * either bundled into a tar stream or sent through the pipelined batch path,
 * depending on whether this worker bundles. A leftover from collection runs
 * afterwards.
 */
static void
worker_run_batch(struct sftp_worker *worker, struct sftp_work_unit *first)
{
	struct sftp_parallel *fleet = worker->parent;
	struct sftp_work_unit **batch;
	struct sftp_work_unit *leftover = NULL;
	int batch_cap, batch_n;

	/* Bundle mode is byte-capped rather than count-capped, so it allows far
	 * more files per batch than the pipelined path; hence the heap array. */
	if (worker->bundle_enabled)
		batch_cap = BUNDLE_BATCH_MAX_FILES;
	else
		batch_cap = UPLOAD_BATCH_SIZE;
	batch = xcalloc((size_t)batch_cap, sizeof(*batch));
	batch_n = worker_collect_batch(worker, first, batch, batch_cap,
	    &leftover);

	__atomic_store_n(&worker->phase, WPH_RUN, __ATOMIC_RELAXED);
	if (batch_n == 1) {
		worker_execute_single(worker, batch[0]);
	} else if (first->op == SFTP_OP_DOWNLOAD) {
		/* The eligibility gate in the worker loop guarantees bundle
		 * mode and server support, so bundle-fetch is the only
		 * dispatch for a multi-unit download batch. Synchronous, with
		 * no carry-over state. */
		worker_run_bundle_download(worker, batch, batch_n);
	} else if (worker->bundle_enabled) {
		/* One tar stream through a single open, writes and close.
		 * Synchronous; the pipelined carry-over state stays NULL. */
		worker_run_bundle(worker, batch, batch_n);
	} else {
		/* Pipelined batch: this batch's close collection is deferred
		 * and the previous batch's results are finalised inside. */
		worker_run_batch_pipelined(worker, batch, batch_n);
	}

	/* The leftover was popped inside the collection loop, bypassing the
	 * dispatch gate in the worker loop. Unlike a batch member, which is
	 * always a whole-file unit with no tracker, a leftover can be a range
	 * unit, so it claims its writer slot here to stay balanced with the
	 * release in worker_process_result. A NULL tracker acquires trivially
	 * and releases as a no-op. */
	if (leftover != NULL) {
		if (parallel_unit_writer_acquire(leftover->range_tracker)) {
			worker_execute_single(worker, leftover);
		} else if (parallel_worker_requeue(fleet, leftover,
		    /*front=*/0) != 0) {
			/* The queue shut down under us: full give-up
			 * bookkeeping, not a silent drop. */
			worker_give_up_pushfail(fleet, worker, leftover);
		}
	}
	free(batch);
}

/*
 * The worker thread. Each parallel stream runs one of these on its own SSH
 * connection, and they all pull from the same shared queue, so work spreads
 * itself across whichever workers are free.
 *
 * One pass of the loop takes one unit off the queue and runs it. Before
 * running anything the worker checks three things. If it is holding a
 * deferred batch whose replies are still unread, it drains that first,
 * because blocking on an empty queue while the server waits to be read would
 * stall the connection. If the unit came back from this same worker's own
 * cooperative yield, it is pushed back once so a different worker gets a
 * chance at it. If the unit is one range of a file that already has as many
 * writers as it allows, it goes back on the queue and the worker looks for
 * other work, sleeping briefly once a full pass turns up nothing but capped
 * units.
 *
 * How the unit runs depends on what it is. A bundle container is dispatched
 * whole. An upload, or a download when bundling is available, is collected
 * into a batch along with as many following units of the same kind as fit,
 * and that batch goes out as one bundle or one pipelined group. Anything
 * else runs on its own. A unit popped during collection that does not belong
 * in the batch is run by itself afterwards.
 *
 * The loop also publishes what the worker is doing, since the watchdog and
 * the reporter run on another thread and can only see these fields: which
 * phase it is in, whether it is busy, idle, or blocked on a writer cap, when
 * it picked up its current unit, and that unit's size and offset.
 *
 * A worker blocking for work keeps any warm file handle open. It is closed
 * when the worker takes a unit for a different file, or on the way out, so an
 * idle worker can hold a file open on the server for the length of its wait.
 *
 * The loop ends when the queue is shut down and empty, when the fleet
 * aborts, or when worker_should_terminate says this worker should stop. On
 * the way out it drains any deferred batch, closes a warm file handle it may
 * still be holding, and marks itself exited so the reporter can join it.
 */
void *
parallel_worker_thread(void *arg)
{
	struct sftp_worker *worker = arg;
	struct sftp_parallel *fleet = worker->parent;
	/* HPN writer-cap gate: counts consecutive range units requeued because
	 * their file is at its concurrent-writer cap. Once a full pass over
	 * the queue finds only capped units, the worker sleeps briefly instead
	 * of busy-looping (see the gate below). */
	int capped_passes = 0;

	worker_thread_init(worker);

	while (1) {
		if (fleet->abort_flag)
			break;
		void *item = NULL;
		__atomic_store_n(&worker->phase, WPH_POP_WAIT, __ATOMIC_RELAXED);
		/* Deferred-batch deadlock guard: if we have a deferred
		 * pipelined batch with pending CLOSE-STATUSes in the
		 * SSH socket buffer, we cannot block on the workqueue
		 * without first reading those replies - TCP back-pressure
		 * would otherwise stall the server. Try a non-blocking
		 * pop first; if the queue is empty, drain the deferred
		 * batch (which reads the pending STATUSes and frees them)
		 * before falling back to a blocking pop. */
		if (worker->batch_prev_pending != NULL) {
			if (sftp_workqueue_trypop(fleet->q, &item) != 0) {
				/* queue empty - drain before blocking */
				__atomic_store_n(&worker->phase,
				    WPH_FINALIZE, __ATOMIC_RELAXED);
				worker_drain_pipeline(worker);
				__atomic_store_n(&worker->phase,
				    WPH_POP_WAIT, __ATOMIC_RELAXED);
				item = NULL;
			}
		}
		/* Availability intent: about to block in pop = purposefully
		 * idle, healthy, ready for work (see enum worker_avail). */
		__atomic_store_n(&worker->avail, WORKER_AVAIL_READY,
		    __ATOMIC_RELAXED);
		if (item == NULL && sftp_workqueue_pop(fleet->q, &item) != 0)
			break;	/* shutdown && empty */
		uint64_t t_work_start = monotime_ms();
		/* Mark when this worker took possession of a unit so the
		 * watchdog can measure "how long has this worker been
		 * holding the current unit" even if the worker has never
		 * completed a previous unit. Cleared at the end of this
		 * iteration after the unit (or batch) has been processed. */
		__atomic_store_n(&worker->unit_start_ms, t_work_start,
		    __ATOMIC_RELEASE);
		struct sftp_work_unit *unit = item;
		if (unit == NULL) {
			__atomic_store_n(&worker->unit_start_ms, 0,
			    __ATOMIC_RELEASE);
			continue;
		}
		/*
		 * Cooperative-yield handoff (phase C): the worker that just
		 * yielded this remainder must not immediately re-pop its own
		 * handoff - that would defeat the redistribution. One
		 * courtesy defer: push it back, clear the marker (so a lone
		 * worker can never deadlock on its own yield), park briefly
		 * to give a READY worker the race. Any other worker runs it
		 * immediately (and clears the marker by dispatching).
		 */
		if (unit->yield_from == worker->id + 1) {
			unit->yield_from = 0;
			if (parallel_worker_requeue(fleet, unit, /*front=*/1) != 0) {
				worker_give_up_pushfail(fleet, worker, unit);
				__atomic_store_n(&worker->unit_start_ms, 0,
				    __ATOMIC_RELEASE);
				continue;
			}
			__atomic_store_n(&worker->unit_start_ms, 0,
			    __ATOMIC_RELEASE);
			sftp_workqueue_kick(fleet->q);
			sftp_workqueue_wait_activity(fleet->q, 250);
			continue;
		}
		if (unit->yield_from != 0) {
			/* A DIFFERENT worker reached this yielded remainder before
			 * the holder could re-pop it: the cooperative handoff
			 * actually moved the work off the straggler onto a peer
			 * (tail-redistribute). The holder-defer case above clears
			 * the marker first, so this counts direct handoffs only. */
			debug("HPN YIELD-HANDOFF \"%s\" [%lld+%lld) "
			    "yielded_by=%d taken_by=%d",
			    unit->dst_path ? unit->dst_path : unit->src_path,
			    (long long)unit->range_offset,
			    (long long)unit->range_length,
			    unit->yield_from - 1, worker->id);
		}
		unit->yield_from = 0;
		/*
		 * Per-inode concurrent-writer cap. Range units of one file share
		 * a tracker and only writer_cap of them may write at once, so a
		 * unit whose file is at its cap goes back on the queue and the
		 * worker looks for another file's work. Whole file and bundle
		 * units have no tracker and always pass.
		 *
		 * Once a full pass over the queue turns up nothing but capped
		 * units, which is what a single-file transfer looks like, the
		 * worker parks on the queue's activity channel rather than
		 * spinning pop and requeue (measured at ~6M futile cycles on one
		 * large file). It wakes on a slot release or any push; the 250 ms
		 * timeout is a backstop, not the path.
		 */
		if (!parallel_unit_writer_acquire(unit->range_tracker)) {
			/* Push-fail = the queue shut down under us (abort).
			 * The unit can never run: do the full give-up
			 * bookkeeping (pending, tracker finalize,
			 * free) - silently dropping it stranded
			 * the tracker and leaked the unit. */
			if (parallel_worker_requeue(fleet, unit, /*front=*/0) != 0)
				worker_give_up_pushfail(fleet, worker, unit);
			__atomic_store_n(&worker->unit_start_ms, 0, __ATOMIC_RELEASE);
			/* Availability intent: parked on this file's cap, but
			 * available for any other file. */
			__atomic_store_n(&worker->avail, WORKER_AVAIL_CAPPED,
			    __ATOMIC_RELAXED);
			if (++capped_passes >=
			    (int)sftp_workqueue_depth(fleet->q) + 1) {
				sftp_workqueue_wait_activity(fleet->q, 250);
				capped_passes = 0;
			}
			continue;
		}
		capped_passes = 0;
		__atomic_store_n(&worker->phase, WPH_ASSEMBLE, __ATOMIC_RELAXED);
		/* Availability intent + unit size for the tail detector's
		 * projected-tail (size published beside unit_start_ms). */
		__atomic_store_n(&worker->avail, WORKER_AVAIL_BUSY,
		    __ATOMIC_RELAXED);
		__atomic_store_n(&worker->unit_size, (uint64_t)unit->size,
		    __ATOMIC_RELAXED);
		__atomic_store_n(&worker->unit_offset,
		    (unit->op == SFTP_OP_UPLOAD_RANGE ||
		     unit->op == SFTP_OP_DOWNLOAD_RANGE ||
		     unit->op == SFTP_OP_RESUME_SPAN)
		    ? (int64_t)unit->range_offset : (int64_t)-1,
		    __ATOMIC_RELAXED);

		/*
		 * Uploads collect into a batch so that N opens go out in one
		 * round trip instead of N, with the closes pipelined the same
		 * way. Downloads only collect when they can be bundled, which
		 * needs bundle mode on this worker and hpn-bundle-fetch on the
		 * server; download pipelining is still future work. Either way a
		 * batch of one falls back to single-unit execution.
		 *
		 * A unit whose earlier bundle attempt failed at the wire is not
		 * eligible: its retry goes through sftp_upload or sftp_download
		 * directly, or it would fail as a bundle, retry as a bundle, and
		 * repeat until it ran out of retries and was lost.
		 */
		int batch_eligible_download =
		    (unit->op == SFTP_OP_DOWNLOAD &&
		     !unit->bundle_ineligible &&
		     worker->bundle_enabled &&
		     sftp_conn_has_hpn_bundle_fetch(worker->conn));

		if (unit->op == SFTP_OP_BUNDLE_UPLOAD ||
		    unit->op == SFTP_OP_BUNDLE_DOWNLOAD) {
			/* Producer-assembled bundle: dispatch the whole
			 * container directly - no worker-side accumulation,
			 * no startup grab race. */
			__atomic_store_n(&worker->phase, WPH_RUN, __ATOMIC_RELAXED);
			worker_dispatch_bundle_container(worker, unit);
		} else if ((unit->op == SFTP_OP_UPLOAD &&
		    !unit->bundle_ineligible) || batch_eligible_download) {
			worker_run_batch(worker, unit);
		} else {
			/* Download (no bundle) or any range op - all bypass
			 * the upload-batch path. */
			worker_execute_single(worker, unit);
		}

		/* Unit (or batch) finished - clear the wedge-detection
		 * timestamp so the watchdog only ever counts time spent
		 * actually holding work. */
		__atomic_store_n(&worker->unit_start_ms, 0, __ATOMIC_RELEASE);
		__atomic_store_n(&worker->unit_size, 0, __ATOMIC_RELAXED);
		__atomic_store_n(&worker->unit_offset, (int64_t)-1, __ATOMIC_RELAXED);

		if (worker_should_terminate(worker))
			break;
	}
	/* Drain any deferred pipelined batch state before
	 * exiting. If the connection died, this is a best-effort drain
	 * (sftp_upload_batch_finish handles a dead conn by marking entries
	 * failed and freeing). */
	__atomic_store_n(&worker->phase, WPH_FINALIZE, __ATOMIC_RELAXED);
	worker_drain_pipeline(worker);

	/* Close any warm range handle still held (last same-file range's
	 * handle, or one carried through an idle wait). Best-effort on a
	 * dead connection. */
	parallel_worker_close_warm(worker);

	/* Trace phase for the reap window: finished, not yet joined. */
	__atomic_store_n(&worker->phase, WPH_EXIT, __ATOMIC_RELAXED);

	/* Mark exited so the reporter thread can reap us (join + free). */
	pthread_mutex_lock(&worker->mu);
	worker->exited = 1;
	pthread_mutex_unlock(&worker->mu);
	return NULL;
}
