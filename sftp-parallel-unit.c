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
 * sftp-parallel-unit.c - work units and submission for the parallel
 * SFTP orchestrator: unit/range-tracker construction and teardown,
 * per-file writer-cap slots, pending accounting, range splitting
 * policy, and the submit paths (whole-file, resume, byte-range).
 * Split from sftp-parallel.c; moves are verbatim.
 *
 * PFS NOTE: stripe_info_viable() and get_cached_fs_info() are the
 * filesystem-aware seam in the submit path (today: Lustre via
 * sftp-lustre.c and the fs-info extension). Future parallel-fs
 * support (GPFS, BeeGFS, GFS) should generalize THESE call sites
 * into a provider interface rather than adding new probes elsewhere.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
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

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-hpn-transferlog.h"
#include "sftp-parallel-internal.h"

static struct sftp_work_unit *
make_unit(enum sftp_op op, const char *src, const char *dst,
    off_t size, mode_t mode)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op = op;
	u->src_path = src ? xstrdup(src) : NULL;
	u->dst_path = dst ? xstrdup(dst) : NULL;
	u->size = size;
	u->mode = mode;
	return u;
}

/*
 * Shared range-unit builder: upload and download range units are identical
 * except for the op enum. src/dst map to src_path/dst_path (upload:
 * local -> remote; download: remote -> local).
 */
static struct sftp_work_unit *
make_range_unit(enum sftp_op op, const char *src, const char *dst,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op            = op;
	u->src_path      = xstrdup(src);
	u->dst_path      = xstrdup(dst);
	u->size          = range_length;
	u->range_offset  = range_offset;
	u->range_length  = range_length;
	u->range_tracker = tracker;
	return u;
}

struct sftp_work_unit *
parallel_unit_make_range(const char *src, const char *dst,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	return make_range_unit(SFTP_OP_UPLOAD_RANGE, src, dst,
	    range_offset, range_length, tracker);
}

void
parallel_unit_free(struct sftp_work_unit *u)
{
	if (u == NULL) return;
	/* Bundle container: free any still-attached member units. The worker
	 * detaches members (sets ->members = NULL) before dispatch, so this
	 * only fires on the abort/drain path where the bundle was never run. */
	if (u->members != NULL) {
		int i;
		for (i = 0; i < u->n_members; i++)
			parallel_unit_free(u->members[i]);
		free(u->members);
	}
	free(u->src_path);
	free(u->dst_path);
	/* range_tracker is shared across sibling range units; never freed
	 * by parallel_unit_free. See parallel_unit_tracker_finalize for ownership rules. */
	/* A whole-file verify unit owns its parked item. The verify handler
	 * NULLs this after freeing it, so a still-set pointer means the unit was
	 * dropped before any worker ran it (abort / queue shutdown): free it. */
	if (u->verify_whole != NULL) {
		free(u->verify_whole);	/* single block: header + both rels */
		u->verify_whole = NULL;
	}
	/* Range-granular verify: this dropped chunk still holds a reference to the
	 * shared per-file job; release it (free the job on the last reference,
	 * exactly like a completed chunk - just without recording a failure). */
	if (u->verify_job != NULL) {
		if (u->op == SFTP_OP_VERIFY &&
		    __atomic_sub_fetch(&u->verify_job->ranges_left, 1,
		    __ATOMIC_ACQ_REL) == 0)
			parallel_verify_job_free(u->verify_job);
		u->verify_job = NULL;
	}
	free(u);
}

/*
 * Range-completion tracker constructor. Allocated once per range-split
 * transfer (download by submit_download_ranges, upload by
 * submit_upload_ranges) and attached to each of the N range work units
 * it creates. Lives until the last range completes; that completer
 * frees the tracker.
 */
static struct sftp_range_tracker *
range_tracker_new(int total, enum sftp_range_target target, const char *path,
    const char *src_path, int verify, int writer_cap)
{
	struct sftp_range_tracker *t = xcalloc(1, sizeof(*t));
	pthread_mutex_init(&t->mu, NULL);
	t->total      = total;
	t->remaining  = total;
	t->any_failed = 0;
	t->target     = target;
	t->path       = xstrdup(path);
	t->src_path   = (src_path != NULL) ? xstrdup(src_path) : NULL;
	t->verify     = verify;
	/* Per-range verify slots, allocated for BOTH directions when verifying so
	 * the range-granular parallel verify can fan a big file's transfer ranges
	 * across the pool. Upload (REMOTE) tees a source hash into each slot
	 * (valid=1); download (LOCAL) leaves valid=0 and reads the dest range back
	 * at verify time. Either way submit_*_ranges fills off/len. */
	t->vslots = (verify && total > 0)
	    ? xcalloc((size_t)total, sizeof(*t->vslots)) : NULL;
	t->vslots_n = (t->vslots != NULL) ? total : 0;
	t->active_writers = 0;
	/* writer_cap comes from cfg.writers_per_inode_cap (-w); guard against an
	 * unset (0) or out-of-range config by falling back to the default. */
	if (writer_cap < HPN_RANGE_WRITERS_CAP_FLOOR ||
	    writer_cap > HPN_RANGE_WRITERS_CAP_MAX)
		writer_cap = HPN_RANGE_WRITERS_CAP_DEFAULT;
	t->writer_cap     = writer_cap;
	return t;
}

/*
 * Verify transfer: record a range's teed source hash into its tracker slot.
 * The teed hash covers exactly the byte span the unit transferred in this
 * pass. It is authoritative for the slot ONLY when that span still equals the
 * slot's original [off, len) - i.e. the range was never split. The caller's
 * own attempt==0 guard is NOT sufficient: the highwater-resume requeue
 * (worker_process_result) resets attempt to 0 and shrinks the unit to its
 * remainder, so a resumed range reaches here looking "first-attempt clean"
 * while its teed hash covers only the tail. The endgame split likewise shrinks
 * the held unit and spawns pieces. So the authoritative guard lives here:
 * store only when (off, len) match the slot; any split leaves valid=0 and the
 * range is re-read in full from the source at finalize. NULL-safe; a no-op
 * unless this is a verified upload.
 */
void
parallel_unit_store_range_hash(struct sftp_range_tracker *t, int index,
    uint64_t off, uint64_t len, uint64_t hash)
{
	if (t == NULL || t->vslots == NULL)
		return;
	pthread_mutex_lock(&t->mu);
	if (index >= 0 && index < t->vslots_n &&
	    off == t->vslots[index].off && len == t->vslots[index].len) {
		t->vslots[index].hash  = hash;
		t->vslots[index].valid = 1;
	}
	pthread_mutex_unlock(&t->mu);
}

/*
 * Concurrent-writer cap (HPN). Try to claim a writer slot on this file's
 * tracker: succeeds (returns 1, active_writers bumped) only while below the
 * cap. NULL tracker (non-range unit) always succeeds with no accounting.
 * Paired 1:1 with parallel_unit_writer_release per executed unit.
 */
int
parallel_unit_writer_acquire(struct sftp_range_tracker *t)
{
	int ok = 1;

	if (t == NULL)
		return 1;
	pthread_mutex_lock(&t->mu);
	if (t->active_writers < t->writer_cap) {
		t->active_writers++;
		t->cap_grants++;
	} else {
		ok = 0;
		t->cap_denials++;
	}
	pthread_mutex_unlock(&t->mu);
	return ok;
}

/* Release a writer slot claimed by parallel_unit_writer_acquire. NULL-safe;
 * clamped so a stray release can never drive the count negative. */
void
parallel_unit_writer_release(struct sftp_range_tracker *t)
{
	if (t == NULL)
		return;
	pthread_mutex_lock(&t->mu);
	if (t->active_writers > 0)
		t->active_writers--;
	pthread_mutex_unlock(&t->mu);
}

/*
 * Lazy first-writer file creation. Called by the worker before it
 * dispatches the first range of a unit; the tracker mutex makes it
 * exactly-once per file. create-if-absent ONLY: layout-created files
 * (Lustre auto-stripe creates with layout before data) and existing
 * partials (reput onto a previous attempt) pass through untouched -
 * never truncated, never re-laid-out. No size is pinned: the file
 * grows with the pwrite highwater, so interrupted transfers show
 * honest sizes and verified resume hashes only what exists.
 * Permanent failures (permission class) set u->no_retry so the unit
 * gives up instead of burning retries on an error that cannot clear.
 */
int
parallel_unit_ensure_file(struct sftp_conn *conn, struct sftp_work_unit *u)
{
	struct sftp_range_tracker *t = u->range_tracker;
	int r = 0, permanent = 0;

	if (t == NULL)
		return 0;
	pthread_mutex_lock(&t->mu);
	if (t->file_ensured) {
		pthread_mutex_unlock(&t->mu);
		return 0;
	}
	if (t->target == SFTP_RANGE_TARGET_REMOTE) {
		r = sftp_create_file(conn, t->path,
		    u->mode != 0 ? u->mode : 0644, &permanent);
	} else {
		int fd = open(t->path, O_WRONLY | O_CREAT,
		    u->mode != 0 ? u->mode : 0644);
		if (fd >= 0)
			close(fd);
		else {
			r = -1;
			if (errno == EACCES || errno == EROFS ||
			    errno == EDQUOT || errno == ENOSPC)
				permanent = 1;
			error("create local \"%s\": %s", t->path,
			    strerror(errno));
		}
	}
	if (r == 0)
		t->file_ensured = 1;
	else if (permanent)
		u->no_retry = 1;
	pthread_mutex_unlock(&t->mu);
	return r;
}

/*
 * Batch completion: retire `n` ranges in one call, all with the same
 * outcome (`failed` = 1 on permanent give-up, 0 on success). The
 * submit-error paths use this to synthesise failures for every range
 * they never submitted: ONE decrement under ONE lock acquisition, so
 * the call that drops remaining to 0 (and frees the tracker) is
 * unambiguous - the caller treats the pointer as dead after the call,
 * unconditionally. This replaced a finalize-in-a-loop pattern whose
 * safety relied on the loop count being arithmetically exact
 * (scan-build flagged it as a potential UAF; see
 * SECURITY_REVIEW_19.0_FINDINGS.md LOW-1).
 *
 * `worker` is the worker reporting completion; used only for sftp_rm on
 * REMOTE-target trackers when the corrupt-file cleanup fires. May
 * be NULL otherwise (I4).
 *
 * Returns 1 if THIS call was the last-completer AND any range
 * failed (informational - the cleanup happened inside this call
 * regardless). Returns 0 otherwise.
 *
 * Tracker is freed when remaining hits 0; after any call the caller
 * must assume the pointer is dead (I3).
 *
 * No-op on NULL t or n <= 0 (I5).
 */
int
parallel_unit_tracker_finalize_n(struct sftp_range_tracker *t, int n,
    int failed, struct sftp_worker *worker)
{
	int was_last, incomplete;

	if (t == NULL || n <= 0)
		return 0;

	pthread_mutex_lock(&t->mu);
	if (failed)
		t->any_failed = 1;
	t->remaining -= n;
	was_last   = (t->remaining == 0);
	incomplete = was_last && t->any_failed;
	if (was_last && getenv("HPN_PARALLEL_TRACE") != NULL)
		logit("HPN CAP-COUNTERS \"%s\": grants=%llu denials=%llu "
		    "(cap=%d total_ranges=%d)", t->path,
		    (unsigned long long)t->cap_grants,
		    (unsigned long long)t->cap_denials,
		    t->writer_cap, t->total);
	pthread_mutex_unlock(&t->mu);

	if (!was_last)
		return 0;

	if (incomplete) {
		/*
		 * At least one byte-range failed permanently after retries,
		 * so the pre-allocated file is now full-size with HOLES (the
		 * failed ranges are still zeros from fallocate). Do NOT
		 * delete it. Leaving it in place keeps it RESUMABLE: the
		 * user re-runs verified resume (reputv for uploads, regetv
		 * for downloads), which uses sftp-hash-range@hpnssh.org to
		 * hash each range and refill only the mismatched ones -
		 * salvaging every range that already transferred instead of
		 * forcing a full re-send. Unlinking would throw all that
		 * good data away. Report loudly so the user and any
		 * automation know the file is incomplete; the non-zero
		 * process exit comes from the failed-path accounting at the
		 * give-up site (worker_record_failed_path).
		 */
		if (parallel_user_abort_flag) {
			/* The "failure" is the user's own interrupt - the
			 * per-file detail goes to debug and the flush prints
			 * one calm interrupt summary instead. */
			debug("range-split: %s file \"%s\" incomplete after "
			    "interrupt; left in place, resumable "
			    "(reputv / regetv)",
			    t->target == SFTP_RANGE_TARGET_LOCAL ?
			    "local" : "remote", t->path);
		} else {
			error("range-split: %s file \"%s\" is INCOMPLETE. "
			    "The file is left in place and is resumable with "
			    "reputv or regetv.",
			    t->target == SFTP_RANGE_TARGET_LOCAL ?
			    "local" : "remote", t->path);
			debug("range-split: \"%s\": at least one byte-range "
			    "failed permanently after retries", t->path);
		}
		/* TransferLog: the file's final status (interrupt included -
		 * an aborted file is still not delivered). */
		transferlog_file(TRANSFERLOG_FAILED,
		    (long long)t->file_bytes, t->path);
	} else if (t->verify && worker != NULL) {
		/*
		 * Verify transfer: the file's last range just finished
		 * cleanly. Park the completed tracker for the post-transfer
		 * verify phase rather than verifying here - keeping verify off
		 * the transfer path so an in-flight transfer never blocks on a
		 * server read-back. sftp_parallel_wait submits it as an
		 * SFTP_OP_VERIFY unit once the transfer queue drains; the verify
		 * handler frees the tracker.
		 */
		parallel_verify_park(worker->parent, t);
		return incomplete;
	} else {
		/* TransferLog: clean range/span completion with no verify
		 * phase to defer to - final here. */
		transferlog_file(TRANSFERLOG_SUCCESS,
		    (long long)t->file_bytes, t->path);
	}
	pthread_mutex_destroy(&t->mu);
	free(t->vslots);
	free(t->path);
	free(t->src_path);
	free(t);
	return incomplete;
}

/*
 * One range's final completion: `failed` = 1 on permanent give-up
 * (after MAX_RETRIES) or 0 on success. Must be called exactly once
 * per range unit, on its final outcome only - see invariants (I1)
 * and (I2) at struct sftp_range_tracker. Thin n=1 wrapper over the
 * batch form above; all the ownership rules there apply.
 */
int
parallel_unit_tracker_finalize(struct sftp_range_tracker *t, int failed,
    struct sftp_worker *worker)
{
	return parallel_unit_tracker_finalize_n(t, 1, failed, worker);
}

/*
 * Free a completed range tracker. Range-split files reuse their transfer
 * tracker for the verify phase (parked at finalize); this releases it after the
 * verify units have built their verify_job from it, and on the abort/drop path.
 * Verify itself now runs inline per range in the worker, so this no longer
 * verifies anything - it is purely the tracker's free.
 */
void
parallel_verify_tracker_free(struct sftp_range_tracker *t)
{
	pthread_mutex_destroy(&t->mu);
	free(t->vslots);
	free(t->path);
	free(t->src_path);
	free(t);
}

/*
 * Park a completed range-split tracker for the post-transfer verify phase.
 * Called from finalize in place of an inline verify; the tracker (with its
 * teed per-range source hashes) is held until sftp_parallel_wait submits it.
 */
void
parallel_verify_park(struct sftp_parallel *fleet, struct sftp_range_tracker *t)
{
	pthread_mutex_lock(&fleet->verify_pending_mu);
	if (fleet->verify_pending_n == fleet->verify_pending_cap) {
		int ncap = fleet->verify_pending_cap ? fleet->verify_pending_cap * 2 : 16;
		fleet->verify_pending = xreallocarray(fleet->verify_pending,
		    (size_t)ncap, sizeof(*fleet->verify_pending));
		fleet->verify_pending_cap = ncap;
	}
	fleet->verify_pending[fleet->verify_pending_n++] = t;
	/* Memory gate charged at SUBMIT, not at park (see park_whole_file). */
	pthread_mutex_unlock(&fleet->verify_pending_mu);
}

/*
 * Record a file whose post-transfer verify (and its inline auto-repair) could
 * not be made to match, naming the DEST, so the run summary reports it and
 * hpnsftp exits SFTP_EX_VERIFY_FAILED.
 */
void
parallel_verify_fail_record(struct sftp_parallel *fleet, int local_is_target,
    const char *local_path, const char *remote_path)
{
	char *desc;

	/* Name the DEST (the written, corrupt file), labeled local/remote. */
	xasprintf(&desc, "%s file \"%s\"",
	    local_is_target ? "local" : "remote",
	    local_is_target ? local_path : remote_path);
	hpn_strlist_append(&fleet->verify_failed_paths, desc);
	free(desc);
}

/* Strip trailing '/' from a path in place (but keep a lone "/"). */
static void
path_trim_trailing_slash(char *s)
{
	size_t n = strlen(s);
	while (n > 1 && s[n - 1] == '/')
		s[--n] = '\0';
}

/* If `prefix` prefixes `path` at a '/' boundary, point *rel past "prefix/" and
 * return 1; else 0. */
static int
path_strip_prefix(const char *path, const char *prefix, const char **rel)
{
	size_t pl = strlen(prefix);

	if (pl == 0 || strncmp(path, prefix, pl) != 0 || path[pl] != '/')
		return 0;
	*rel = path + pl + 1;
	return 1;
}

/* Record one directory prefix in the path-factoring pool, deduped. "." and a
 * relative path with no directory part are skipped. Whole-file verify items
 * store their paths relative to a registered prefix, so a long common
 * directory is held once here instead of twice in every parked item. */
void
parallel_verify_prefix_register(struct sftp_parallel *fleet, const char *dir)
{
	char *d;
	int i;

	if (fleet == NULL || dir == NULL || dir[0] == '\0')
		return;
	d = xstrdup(dir);
	path_trim_trailing_slash(d);
	/* "." (the dirname of a relative no-dir path) can never prefix-match a
	 * path at a '/' boundary; don't pollute the pool with it. */
	if (strcmp(d, ".") == 0) {
		free(d);
		return;
	}
	pthread_mutex_lock(&fleet->verify_pending_mu);
	for (i = 0; i < fleet->verify_prefixes_n; i++) {	/* dedup */
		if (strcmp(fleet->verify_prefixes[i], d) == 0) {
			pthread_mutex_unlock(&fleet->verify_pending_mu);
			free(d);
			return;
		}
	}
	/* The pool index is stored as int16_t in verify_whole_item. Cap the pool
	 * at INT16_MAX entries: past the cap, leave this dir unregistered so its
	 * files store the full path (prefix = -1) instead of an out-of-range index.
	 * Graceful degradation - never a bad index. Reaching here needs one
	 * command set spanning 32k+ distinct directories. */
	if (fleet->verify_prefixes_n >= INT16_MAX) {
		pthread_mutex_unlock(&fleet->verify_pending_mu);
		free(d);
		return;
	}
	if (fleet->verify_prefixes_n == fleet->verify_prefixes_cap) {
		int ncap = fleet->verify_prefixes_cap ? fleet->verify_prefixes_cap * 2 : 8;
		fleet->verify_prefixes = xreallocarray(fleet->verify_prefixes,
		    (size_t)ncap, sizeof(*fleet->verify_prefixes));
		fleet->verify_prefixes_cap = ncap;
	}
	fleet->verify_prefixes[fleet->verify_prefixes_n++] = d;
	/* Memory gate: account the dir string + its array slot (+16 rounding). */
	fleet->verify_parked_bytes += strlen(d) + 1 + 8 + 16;
	pthread_mutex_unlock(&fleet->verify_pending_mu);
}

/* Find the longest registered prefix of `path`, point *rel at the suffix past
 * it, and return that prefix's index. Returns -1 with *rel = path when nothing
 * matches. Each path side is matched on its own, so an upload with a full
 * local path and a relative remote one factors both. */
int
parallel_verify_prefix_match(struct sftp_parallel *fleet, const char *path,
    const char **rel)
{
	int i, best = -1;
	size_t best_len = 0;

	*rel = path;			/* default: no prefix, store the path as-is */
	if (fleet == NULL)
		return -1;
	pthread_mutex_lock(&fleet->verify_pending_mu);
	for (i = 0; i < fleet->verify_prefixes_n; i++) {
		const char *r;
		size_t pl = strlen(fleet->verify_prefixes[i]);

		if (pl > best_len &&
		    path_strip_prefix(path, fleet->verify_prefixes[i], &r)) {
			best = i;
			best_len = pl;
			*rel = r;
		}
	}
	pthread_mutex_unlock(&fleet->verify_pending_mu);
	return best;
}

/* Rebuild a full path from a prefix index and the relative suffix stored with
 * it. A negative index means the item held the whole path, so rel is copied
 * as-is. Always returns allocated memory; the caller frees it. */
char *
parallel_verify_prefix_join(struct sftp_parallel *fleet, int idx, const char *rel)
{
	char *out, *prefix = NULL;

	if (idx < 0)
		return xstrdup(rel);		/* no prefix: rel is the path as-is */
	pthread_mutex_lock(&fleet->verify_pending_mu);
	if (idx < fleet->verify_prefixes_n)
		prefix = xstrdup(fleet->verify_prefixes[idx]);
	pthread_mutex_unlock(&fleet->verify_pending_mu);
	if (prefix == NULL)
		return xstrdup(rel);		/* defensive: pool changed */
	xasprintf(&out, "%s/%s", prefix, rel);
	free(prefix);
	return out;
}

/*
 * Empty the prefix pool (free the dir strings, keep the array allocation for
 * reuse). Called by a verify wave AFTER every parked item has been verified
 * and freed, so nothing references the pool indices anymore - new parks after
 * the wave re-register their dirs. Relieves both the byte budget and the
 * INT16_MAX pool cap. Submitter thread only.
 */
void
parallel_verify_prefix_pool_reset(struct sftp_parallel *fleet)
{
	int i;

	if (fleet == NULL)
		return;
	pthread_mutex_lock(&fleet->verify_pending_mu);
	for (i = 0; i < fleet->verify_prefixes_n; i++)
		free(fleet->verify_prefixes[i]);
	fleet->verify_prefixes_n = 0;
	pthread_mutex_unlock(&fleet->verify_pending_mu);
}

/*
 * Allocate a parked whole-file verify item in ONE block: the fixed header
 * followed by "local_rel\0remote_rel\0". This is the single point that owns
 * the item's size arithmetic - both copies use the SAME measured lengths used
 * to size the allocation (terminating NUL included), so bytes copied can never
 * exceed bytes allocated. The PATH_MAX guard is belt-and-suspenders: these are
 * transfer paths that already opened files (so each is <= PATH_MAX), but it
 * stops a corrupt length from wrapping the size_t add into a short allocation.
 */
static struct verify_whole_item *
verify_whole_item_new(int local_prefix, const char *local_rel,
    int remote_prefix, const char *remote_rel, int local_is_target)
{
	struct verify_whole_item *it;
	size_t llen = strlen(local_rel);
	size_t rlen = strlen(remote_rel);

	if (llen > PATH_MAX || rlen > PATH_MAX)
		fatal_f("verify path too long (local=%zu remote=%zu)",
		    llen, rlen);
	it = xmalloc(sizeof(*it) + llen + 1 + rlen + 1);
	it->local_prefix = (int16_t)local_prefix;
	it->remote_prefix = (int16_t)remote_prefix;
	it->local_is_target = (int8_t)local_is_target;
	memcpy(it->buf, local_rel, llen + 1);		/* includes NUL */
	memcpy(it->buf + llen + 1, remote_rel, rlen + 1);
	return it;
}

/*
 * Park a completed whole-file (non-range-split) transfer for the verify phase.
 * Stores a lightweight verify_whole_item with paths held RELATIVE to a
 * registered directory prefix (the long common prefix lives once in the pool,
 * not in two full paths per file). No match (non-recursive / disparate) falls
 * back to full paths. The verify handler rebuilds local/remote.
 */
void
parallel_verify_park_whole_file(struct sftp_parallel *fleet, const char *local_path,
    const char *remote_path, int local_is_target)
{
	struct verify_whole_item *it;
	const char *lrel = NULL, *rrel = NULL;
	int lp, rp;

	/* Factor each side independently: the always-full side (remote on both
	 * upload and download) matches a registered dir prefix; a relative side
	 * matches nothing and is stored as-is (already short). */
	lp = parallel_verify_prefix_match(fleet, local_path, &lrel);
	rp = parallel_verify_prefix_match(fleet, remote_path, &rrel);
	it = verify_whole_item_new(lp, lrel, rp, rrel, local_is_target);

	pthread_mutex_lock(&fleet->verify_pending_mu);
	if (fleet->verify_whole_pending_n == fleet->verify_whole_pending_cap) {
		int ncap = fleet->verify_whole_pending_cap
		    ? fleet->verify_whole_pending_cap * 2 : 16;
		fleet->verify_whole_pending = xreallocarray(fleet->verify_whole_pending,
		    (size_t)ncap, sizeof(*fleet->verify_whole_pending));
		fleet->verify_whole_pending_cap = ncap;
	}
	fleet->verify_whole_pending[fleet->verify_whole_pending_n++] = it;
	/* Memory gate is charged at SUBMIT (parallel_verify_item_bytes_estimate),
	 * not here - parking is the lagging event the submitter can't see. */
	pthread_mutex_unlock(&fleet->verify_pending_mu);
}

/* Free a range-granular verify job (paths + the per-range arrays). */
void
parallel_verify_job_free(struct verify_job *j)
{
	if (j == NULL)
		return;
	free(j->local_path);
	free(j->remote_path);
	free(j->offs);
	free(j->lens);
	free(j->hashes);
	free(j->valid);
	free(j);
}

/*
 * Build a per-file verify job from a completed range tracker: copy the transfer
 * ranges (vslots) - the teed source hashes among them - into the job and resolve
 * the direction. Upload (REMOTE target): local=source/remote=dest, teed source
 * hashes apply. Download (LOCAL target): local=dest/remote=source, no teed.
 */
static struct verify_job *
build_verify_job(struct sftp_range_tracker *t)
{
	struct verify_job *j = xcalloc(1, sizeof(*j));
	int n = t->vslots_n, k;

	j->local_is_target = (t->target == SFTP_RANGE_TARGET_LOCAL);
	if (j->local_is_target) {
		j->local_path = xstrdup(t->path);	/* dest */
		j->remote_path = xstrdup(t->src_path);	/* source */
	} else {
		j->local_path = xstrdup(t->src_path);	/* source */
		j->remote_path = xstrdup(t->path);	/* dest */
	}
	j->n_ranges = n;
	j->ranges_left = n;
	j->offs = xcalloc((size_t)n, sizeof(*j->offs));
	j->lens = xcalloc((size_t)n, sizeof(*j->lens));
	j->hashes = xcalloc((size_t)n, sizeof(*j->hashes));
	j->valid = xcalloc((size_t)n, sizeof(*j->valid));
	for (k = 0; k < n; k++) {
		j->offs[k] = (off_t)t->vslots[k].off;
		j->lens[k] = (off_t)t->vslots[k].len;
		j->hashes[k] = t->vslots[k].hash;
		j->valid[k] = t->vslots[k].valid;
	}
	return j;
}

/* Grow the pending-units array as needed and append one unit. */
static void
verify_units_append(struct sftp_work_unit ***units, int *nunits, int *ucap,
    struct sftp_work_unit *u)
{
	if (*nunits == *ucap) {
		*ucap = *ucap ? *ucap * 2 : 64;
		*units = xreallocarray(*units, (size_t)*ucap, sizeof(**units));
	}
	(*units)[(*nunits)++] = u;
}

/*
 * Submit the parked files as SFTP_OP_VERIFY work units, drained by the idle
 * workers over their own connections. Range-split files with teed source
 * hashes (verified upload, server advertises sftp-hash-range) fan ONE unit per
 * transfer range across the pool (range-granular within-file parallel verify);
 * each shares the file's verify job and the last range to finish frees it.
 * Range-split files WITHOUT teed hashes (verified download, or a pre-19 server)
 * and parked whole-file items each get one whole-file verify unit carrying a
 * lightweight verify_whole_item. Returns the total UNIT count (= chunks +
 * whole-file units, not files) for the phase meter.
 */
int
parallel_verify_phase_submit(struct sftp_parallel *fleet)
{
	struct sftp_range_tracker **arr;
	struct verify_whole_item **warr;
	struct sftp_work_unit **units = NULL;
	int i, n, wn, can_chunk, nunits = 0, ucap = 0;

	pthread_mutex_lock(&fleet->verify_pending_mu);
	arr = fleet->verify_pending;
	n = fleet->verify_pending_n;
	fleet->verify_pending = NULL;
	fleet->verify_pending_n = 0;
	fleet->verify_pending_cap = 0;
	warr = fleet->verify_whole_pending;
	wn = fleet->verify_whole_pending_n;
	fleet->verify_whole_pending = NULL;
	fleet->verify_whole_pending_n = 0;
	fleet->verify_whole_pending_cap = 0;
	/* Memory gate: this drains every parked item into verify units (their
	 * frees follow as the units complete), so the parked total returns to 0.
	 * The prefix pool's bytes are released separately by the wave's
	 * pool_reset once the verify units finish reading it. */
	fleet->verify_parked_bytes = 0;
	pthread_mutex_unlock(&fleet->verify_pending_mu);

	/* Range-granular verify needs the server's sftp-hash-range; all workers
	 * talk to the same server, so one worker's conn answers for the fleet. */
	can_chunk = (fleet->num_workers > 0 && fleet->workers[0] != NULL &&
	    fleet->workers[0]->conn != NULL &&
	    sftp_conn_has_hash_range(fleet->workers[0]->conn));

	for (i = 0; i < n; i++) {
		struct sftp_range_tracker *t = arr[i];

		if (can_chunk && t->vslots != NULL && t->vslots_n > 0) {
			struct verify_job *j = build_verify_job(t);
			int k;

			parallel_verify_tracker_free(t);	/* paths copied */
			for (k = 0; k < j->n_ranges; k++) {
				struct sftp_work_unit *u = xcalloc(1, sizeof(*u));

				u->op = SFTP_OP_VERIFY;
				u->verify_job = j;
				u->range_index = k;
				u->range_offset = j->offs[k];
				u->range_length = j->lens[k];
				verify_units_append(&units, &nunits, &ucap, u);
			}
		} else {
			/* No teed hashes: whole-file verify. t->path is the
			 * written file (LOCAL target = download, REMOTE = upload);
			 * resolve to local/remote. These are range-split files
			 * (few), and no prefix pool applies here, so hold the full
			 * paths (prefix = -1). */
			struct verify_whole_item *it;
			struct sftp_work_unit *u = xcalloc(1, sizeof(*u));

			if (t->target == SFTP_RANGE_TARGET_LOCAL)
				it = verify_whole_item_new(-1, t->path,
				    -1, t->src_path, /*local_is_target=*/1);
			else
				it = verify_whole_item_new(-1, t->src_path,
				    -1, t->path, /*local_is_target=*/0);
			parallel_verify_tracker_free(t);
			u->op = SFTP_OP_VERIFY;
			u->verify_whole = it;
			verify_units_append(&units, &nunits, &ucap, u);
		}
	}
	free(arr);

	for (i = 0; i < wn; i++) {
		struct sftp_work_unit *u = xcalloc(1, sizeof(*u));

		u->op = SFTP_OP_VERIFY;
		u->verify_whole = warr[i];	/* take ownership of the item */
		verify_units_append(&units, &nunits, &ucap, u);
	}
	free(warr);

	/* Set the unit total BEFORE pushing so the reporter's 100%-snap gate
	 * (done_units >= total) can't fire early while we are still submitting. */
	fleet->verify_total_units = (uint64_t)nunits;

	for (i = 0; i < nunits; i++)
		(void)parallel_unit_submit(fleet, units[i]);
	free(units);
	return nunits;
}

/*
 * Resolve the effective per-unit retry budget. See the comment at the
 * HPN_MAX_RETRIES_* defines near the top of this file for the full
 * policy. Definition lives here because struct sftp_parallel is
 * opaque earlier in the file; the forward decl appears alongside the
 * defines.
 */
int
parallel_unit_max_retries(struct sftp_parallel *fleet)
{
	if (fleet != NULL &&
	    fleet->cfg.max_retries >= HPN_MAX_RETRIES_MIN &&
	    fleet->cfg.max_retries <= HPN_MAX_RETRIES_MAX)
		return fleet->cfg.max_retries;
	return HPN_MAX_RETRIES_DEFAULT;
}

/*
 * Drop one from the pending count and wake whatever is waiting on the change.
 * Caller holds pending_mu.
 *
 * Two waiters watch this counter and they need different edges.
 * sftp_parallel_wait sleeps until the fleet is idle, so it needs the zero
 * transition. A producer throttled by sftp_parallel_await_capacity sleeps
 * until there is room under the ceiling, so it needs the edge where pending
 * falls below outstanding_cap - reached long before zero. Signalling only at
 * zero leaves that producer to fall out on its timeout instead, which makes
 * the timeout the mechanism rather than the backstop and limits how fast work
 * can reach the fleet to one ceiling per timeout period.
 *
 * Only the crossing is signalled, not every decrement below the ceiling: the
 * latter would broadcast once per completed file for no gain. Decrements are
 * serialised by the mutex so every value is visited and the crossing cannot
 * be skipped, and a waiter tests the same predicate under the same mutex, so
 * there is no lost wakeup.
 */
static void
pending_dec_locked(struct sftp_parallel *fleet)
{
	if (fleet->pending > 0)
		fleet->pending--;
	if (fleet->pending == 0 ||
	    (fleet->outstanding_cap != 0 &&
	     fleet->pending + 1 == fleet->outstanding_cap))
		pthread_cond_broadcast(&fleet->pending_cv);
}

void
parallel_unit_pending_dec(struct sftp_parallel *fleet)
{
	pthread_mutex_lock(&fleet->pending_mu);
	pending_dec_locked(fleet);
	pthread_mutex_unlock(&fleet->pending_mu);
}


/*
 * Return this parallel's bundle byte target (HPNBundleSize or the
 * compile-time default). Eligibility against it is decided by the
 * shared hpn_bundle_file_eligible() in sftp-hpn-bundle.h, one source
 * of truth with the serial walk accumulator.
 */
static uint64_t
bundle_target_for(const struct sftp_parallel *fleet)
{
	return (fleet != NULL && fleet->cfg.bundle_size > 0)
	    ? fleet->cfg.bundle_size
	    : BUNDLE_TARGET_BYTES_DEFAULT;
}

static int submit_upload_maybe_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode);
static int submit_download_maybe_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode);

/*
 * Roll back one bundle member's submit accounting and free it. Used when a
 * flush can't push (queue shut down) - mirrors parallel_unit_submit's own
 * push-fail backout so pending stays balanced.
 */
static void
parallel_bundle_member_pushfail(struct sftp_parallel *fleet,
    struct sftp_work_unit *u)
{
	pthread_mutex_lock(&fleet->pending_mu);
	pending_dec_locked(fleet);
	pthread_mutex_unlock(&fleet->pending_mu);
	parallel_unit_free(u);
}

/*
 * Flush the producer-side bundle accumulator (submit thread only).
 *   n == 0  -> nothing to do.
 *   n == 1  -> push the lone member as an ordinary unit (a bundle of one is
 *              pointless; it still transfers, just un-bundled).
 *   n >= 2  -> wrap the members in a SFTP_OP_BUNDLE_* container and push that.
 * Members keep the pending accounting they took at add time; the
 * container is a transport shell (its ->size = the sum of member bytes).
 */
static void
parallel_bundle_flush(struct sftp_parallel *fleet)
{
	int n = fleet->bundle_pending_n, i;

	if (n == 0)
		return;
	fleet->bundle_pending_n = 0;
	fleet->bundle_pending_framed = 0;
	fleet->bundle_pending_path_bytes = 0;

	if (n == 1) {
		struct sftp_work_unit *u = fleet->bundle_pending[0];
		if (sftp_workqueue_push(fleet->q, u) != 0)
			parallel_bundle_member_pushfail(fleet, u);
		return;
	}

	struct sftp_work_unit *c = xcalloc(1, sizeof(*c));
	c->op = (fleet->bundle_pending_op == SFTP_OP_DOWNLOAD)
	    ? SFTP_OP_BUNDLE_DOWNLOAD : SFTP_OP_BUNDLE_UPLOAD;
	c->members = xreallocarray(NULL, (size_t)n, sizeof(*c->members));
	c->n_members = n;
	for (i = 0; i < n; i++) {
		c->members[i] = fleet->bundle_pending[i];
		if (fleet->bundle_pending[i]->size > 0)
			c->size += fleet->bundle_pending[i]->size;
	}
	if (sftp_workqueue_push(fleet->q, c) != 0) {
		for (i = 0; i < n; i++)
			parallel_bundle_member_pushfail(fleet, c->members[i]);
		free(c->members);
		free(c);
	}
}

/*
 * Add a bundle-eligible small file to the accumulator. It takes the same
 * pending accounting as an individual unit (members are real
 * work units; the bundle just transports them), then accumulates and
 * flushes a full bundle at the framed-byte or file-count cap. Submit
 * thread only; there is no lock here by design.
 * Producer-side grouping exists because worker-side accumulation raced
 * at startup: the thundering herd stranded a transfer's first files as
 * un-bundled single round trips.
 */
static int
parallel_bundle_add(struct sftp_parallel *fleet, struct sftp_work_unit *u)
{
	uint64_t target = (fleet->cfg.bundle_size > 0)
	    ? fleet->cfg.bundle_size : BUNDLE_TARGET_BYTES_DEFAULT;

	pthread_mutex_lock(&fleet->pending_mu);
	fleet->pending++;
	pthread_mutex_unlock(&fleet->pending_mu);

	/* A bundle carries one direction; flush a pending one of the other op. */
	if (fleet->bundle_pending_n > 0 && fleet->bundle_pending_op != u->op)
		parallel_bundle_flush(fleet);
	if (fleet->bundle_pending_n == fleet->bundle_pending_cap) {
		int ncap = fleet->bundle_pending_cap ? fleet->bundle_pending_cap * 2 : 64;
		fleet->bundle_pending = xreallocarray(fleet->bundle_pending,
		    (size_t)ncap, sizeof(*fleet->bundle_pending));
		fleet->bundle_pending_cap = ncap;
	}
	fleet->bundle_pending[fleet->bundle_pending_n++] = u;
	fleet->bundle_pending_op = u->op;
	fleet->bundle_pending_framed += BUNDLE_REC_FRAME_BYTES(
	    u->dst_path ? strlen(u->dst_path) : 0, u->size);
	/* Download bundles list every member's remote path (src_path) in one
	 * hpn-bundle-fetch request; track that request size and flush before it
	 * overflows SFTP_MAX_MSG_LENGTH (see BUNDLE_DL_FETCH_REQ_MAX). */
	if (u->op == SFTP_OP_DOWNLOAD)
		fleet->bundle_pending_path_bytes += 4 +
		    (u->src_path ? strlen(u->src_path) : 0);
	if ((fleet->bundle_pending_op == SFTP_OP_DOWNLOAD ?
	    hpn_bundle_dl_should_flush(fleet->bundle_pending_framed,
	    fleet->bundle_pending_n, target, fleet->bundle_pending_path_bytes,
	    BUNDLE_DL_FETCH_REQ_MAX) :
	    hpn_bundle_should_flush(fleet->bundle_pending_framed,
	    fleet->bundle_pending_n, target)))
		parallel_bundle_flush(fleet);
	sftp_workqueue_kick(fleet->q);
	return 0;
}

/* Flush a partially-filled producer-side bundle (the tail). Called from
 * sftp_parallel_wait once a command has finished submitting. */
void
parallel_bundle_flush_pending(struct sftp_parallel *fleet)
{
	if (fleet == NULL)
		return;
	parallel_bundle_flush(fleet);
	sftp_workqueue_kick(fleet->q);
}

/*
 * Internal submit. Deliberately does NOT demote walker-phase DONE the way
 * the public submit entry points do: endgame-split pieces arrive here from
 * worker threads mid-drain, and demoting would un-arm the endgame state
 * they were created by.
 */
int
parallel_unit_submit(struct sftp_parallel *fleet, struct sftp_work_unit *u)
{
	if (fleet == NULL || fleet->stopped || fleet->abort_flag) {
		parallel_unit_free(u);
		return -1;
	}
	/* u is contractually non-NULL (callers build units via make_unit() /
	 * xcalloc, which fatal on OOM). Guard once here so the derefs below
	 * need no per-site NULL check. */
	if (u == NULL)
		return -1;
	/* Bundle-eligibility gate: when bundle mode is enabled and the
	 * unit's file size exceeds the per-target threshold, mark it
	 * ineligible so the worker routes it through the single-file
	 * path (which may further range-split it). Range and resume
	 * units are never bundle-eligible regardless of size - handled
	 * by their op-type elsewhere. */
	if (fleet->cfg.use_bundle && u->size > 0 &&
	    !hpn_bundle_file_eligible((uint64_t)u->size,
	    bundle_target_for(fleet))) {
		u->bundle_ineligible = 1;
	}
	/* Producer-side bundle assembly: group eligible small files into whole
	 * bundles here (single submit thread) so workers pull a complete bundle
	 * rather than racing to accumulate one. Everything else - large/range/
	 * resume units, and worker re-submits (always bundle_ineligible) - takes
	 * the individual path below. */
	if (fleet->cfg.use_bundle && !u->bundle_ineligible &&
	    (u->op == SFTP_OP_UPLOAD || u->op == SFTP_OP_DOWNLOAD))
		return parallel_bundle_add(fleet, u);
	pthread_mutex_lock(&fleet->pending_mu);
	fleet->pending++;
	pthread_mutex_unlock(&fleet->pending_mu);
	if (sftp_workqueue_push(fleet->q, u) != 0) {
		pthread_mutex_lock(&fleet->pending_mu);
		pending_dec_locked(fleet);
		pthread_mutex_unlock(&fleet->pending_mu);
		parallel_unit_free(u);
		return -1;
	}
	/* Genuinely NEW work: wake any workers parked in the cap-gate's
	 * activity wait. Deliberately NOT done inside the queue's push -
	 * the cap-gate's own requeue pushes there, and kicking from push
	 * created a wake->pass->requeue->kick feedback storm (measured:
	 * denials 6M -> 109M, four cores burned). */
	sftp_workqueue_kick(fleet->q);
	return 0;
}

/*
 * Worker-context re-queue (non-blocking). A worker that blocks on a full fleet->q
 * it also drains can self-deadlock (fatal at -j1). Try the queue; on full,
 * park the unit on the retry-overflow list (existing allocation, FIFO,
 * reporter-drained). pending is unchanged - the unit stays pending
 * wherever it sits, so callers must not re-account here. Returns 0 if
 * the unit was placed (queue or overflow), -1 only if the queue is shut
 * down - the caller does the give-up bookkeeping.
 */
int
parallel_worker_requeue(struct sftp_parallel *fleet, struct sftp_work_unit *u,
    int front)
{
	int rc = front ? sftp_workqueue_trypush_front(fleet->q, u)
	               : sftp_workqueue_trypush(fleet->q, u);
	if (rc == 0)
		return 0;	/* placed on the queue */
	if (rc < 0)
		return -1;	/* queue shut down -> caller gives up */

	/* rc > 0: queue full. Park on the overflow list; never block. */
	pthread_mutex_lock(&fleet->retry_overflow_mu);
	u->overflow_next = NULL;
	u->overflow_front = front;
	if (fleet->retry_overflow_tail != NULL)
		fleet->retry_overflow_tail->overflow_next = u;
	else
		fleet->retry_overflow_head = u;
	fleet->retry_overflow_tail = u;
	size_t depth = ++fleet->retry_overflow_n;
	pthread_mutex_unlock(&fleet->retry_overflow_mu);
	debug2_ft("re-queue overflow: fleet->q full, parked unit (depth=%zu)",
	    depth);
	return 0;
}

/*
 * Reporter-context: move overflow-parked units back into fleet->q while it has
 * room. Each re-enters via its original front/tail intent (a worker blocked
 * in pop wakes on trypush's not_empty signal). Stops at the first unit that
 * won't fit (queue full again) or on shutdown, re-parking it at the head so
 * FIFO order and the pending invariant hold.
 */
void
parallel_retry_overflow_drain(struct sftp_parallel *fleet)
{
	for (;;) {
		pthread_mutex_lock(&fleet->retry_overflow_mu);
		struct sftp_work_unit *u = fleet->retry_overflow_head;
		if (u == NULL) {
			pthread_mutex_unlock(&fleet->retry_overflow_mu);
			return;
		}
		fleet->retry_overflow_head = u->overflow_next;
		if (fleet->retry_overflow_head == NULL)
			fleet->retry_overflow_tail = NULL;
		fleet->retry_overflow_n--;
		pthread_mutex_unlock(&fleet->retry_overflow_mu);

		int front = u->overflow_front;
		u->overflow_next = NULL;
		u->overflow_front = 0;
		int rc = front ? sftp_workqueue_trypush_front(fleet->q, u)
		               : sftp_workqueue_trypush(fleet->q, u);
		if (rc == 0)
			continue;	/* placed; try the next parked unit */

		/* Full again or shut down: re-park at the head and stop. */
		pthread_mutex_lock(&fleet->retry_overflow_mu);
		u->overflow_front = front;
		u->overflow_next = fleet->retry_overflow_head;
		fleet->retry_overflow_head = u;
		if (fleet->retry_overflow_tail == NULL)
			fleet->retry_overflow_tail = u;
		fleet->retry_overflow_n++;
		pthread_mutex_unlock(&fleet->retry_overflow_mu);
		return;
	}
}

/*
 * Stop/abort cleanup: free any units still parked on the overflow list. Run
 * after the workers and reporter have joined (no concurrent access). These
 * units never reached a worker, so freeing mirrors a drained queue item.
 */
void
parallel_retry_overflow_free(struct sftp_parallel *fleet)
{
	struct sftp_work_unit *u, *next;

	pthread_mutex_lock(&fleet->retry_overflow_mu);
	u = fleet->retry_overflow_head;
	fleet->retry_overflow_head = NULL;
	fleet->retry_overflow_tail = NULL;
	fleet->retry_overflow_n = 0;
	pthread_mutex_unlock(&fleet->retry_overflow_mu);

	while (u != NULL) {
		next = u->overflow_next;
		u->overflow_next = NULL;
		/* Each parked unit still owes its shared range_tracker exactly
		 * one finalize (invariant I1); parallel_unit_free never touches
		 * the tracker. Without this the tracker's remaining never
		 * reaches 0, so the tracker (plus its path/src_path/vslots)
		 * leaks and the incomplete-file finalize is skipped. Mirror the
		 * abort queue-drain in sftp_parallel_stop. A NULL tracker
		 * (whole-file / bundle units) is a no-op. */
		(void)parallel_unit_tracker_finalize(u->range_tracker, 1, NULL);
		parallel_unit_free(u);
		u = next;
	}
}

/*
 * Whole-file submit for a resumed and/or verified transfer. resume/verify
 * disable speculative range-splitting: range-split resume is the deferred
 * sparse-hole case, so the file goes as one unit where sftp_upload/
 * sftp_download's hash gate applies. The unsupported-remote check fires
 * HERE, in the main (submit) thread - a fatal() inside a worker would fight
 * fault isolation, and hpn-check-file support is identical across workers,
 * so one up-front check on the control connection suffices. 'remote' is the
 * path named in the failure message; 'src'/'dst' follow make_unit's
 * per-op convention (upload: local→remote; download: remote→local).
 */
static int
submit_resume_whole_file(struct sftp_parallel *fleet, struct sftp_conn *conn,
    enum sftp_op op, const char *src, const char *dst, const char *remote,
    off_t size, mode_t mode, int resume, int verify)
{
	struct sftp_work_unit *u;

	if (verify && conn != NULL && !sftp_conn_has_hpn_check_file(conn))
		fatal("\"%s\": %s", remote, RESUME_INCOMPAT_MSG);
	u = make_unit(op, src, dst, size, mode);
	u->resume = resume;
	u->verify = verify;
	return parallel_unit_submit(fleet, u);
}

/*
 * Parallel verified-resume split (project_verify_refill_parallel): an
 * existing partial destination divides the file at its EOF. Everything
 * past dest EOF is KNOWN missing - the pwrite highwater guarantees no
 * data exists there, the same fact the serial gate's dest-EOF clamp
 * relies on - so the tail [dest_size, src_size) submits as ordinary
 * range units, no hashing. The overlap [0, dest_size) submits as
 * RESUME_SPAN units that each hash-compare their span and splice only
 * mismatched runs (the shared verify+repair engine). Every unit is
 * built here in the submit thread under ONE range tracker, so
 * completion, verify parking, retries, and failure semantics are
 * exactly those of an ordinary range-split file - and the spans hash
 * concurrently on their workers' connections, dividing the hash phase
 * as well as the refill (the serial path's two bottlenecks).
 *
 * Piece size rides the -M knob (parallel_unit_split_min_size), matching
 * ordinary range sizing; no stripe alignment on the tail (a resumed
 * partial's layout is already fixed by its first attempt).
 *
 * Returns 0 when the split was submitted, -1 when the caller should
 * fall back to the whole-file resume unit (too small to split, or a
 * mid-loop submit refusal - which only happens under queue shutdown,
 * where the fallback's own submit refuses identically).
 */
static int
submit_resume_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    enum sftp_op op, const char *src, const char *dst, const char *remote,
    off_t src_size, off_t dest_size, mode_t mode)
{
	struct sftp_range_tracker *tracker;
	off_t span = (off_t)parallel_unit_split_min_size(fleet);
	off_t tail_len = src_size - dest_size;
	enum sftp_op tail_op = (op == SFTP_OP_UPLOAD) ?
	    SFTP_OP_UPLOAD_RANGE : SFTP_OP_DOWNLOAD_RANGE;
	int n_spans, n_tail, n, i;

	(void)conn;
	n_spans = (int)((dest_size + span - 1) / span);
	n_tail = (int)((tail_len + span - 1) / span);
	n = n_spans + n_tail;
	if (n < 2)
		return -1;

	debug("resume-split %s \"%s\": overlap %lld bytes -> %d span(s), "
	    "known-missing tail %lld bytes -> %d range(s)",
	    op == SFTP_OP_UPLOAD ? "upload" : "download", remote,
	    (long long)dest_size, n_spans, (long long)tail_len, n_tail);

	tracker = range_tracker_new(n,
	    op == SFTP_OP_UPLOAD ? SFTP_RANGE_TARGET_REMOTE :
	    SFTP_RANGE_TARGET_LOCAL, /*path=*/dst, /*src=*/src,
	    /*verify=*/fleet->cfg.verify_transfer, fleet->cfg.writers_per_inode_cap);
	tracker->file_bytes = src_size;

	for (i = 0; i < n; i++) {
		struct sftp_work_unit *ru;
		off_t offset, length;

		if (i < n_spans) {
			offset = (off_t)i * span;
			length = (i == n_spans - 1) ?
			    (dest_size - offset) : span;
		} else {
			offset = dest_size + (off_t)(i - n_spans) * span;
			length = (i == n - 1) ? (src_size - offset) : span;
		}
		ru = make_range_unit(i < n_spans ?
		    SFTP_OP_RESUME_SPAN : tail_op,
		    src, dst, offset, length, tracker);
		ru->range_index = i;
		ru->mode = mode;
		if (tracker->vslots != NULL) {
			tracker->vslots[i].off = (u_int64_t)offset;
			tracker->vslots[i].len = (u_int64_t)length;
		}
		if (parallel_unit_submit(fleet, ru) != 0) {
			if (fleet->abort_flag)
				debug("submit resume piece %d of \"%s\" "
				    "refused (abort in progress)", i, remote);
			else
				error("submit resume piece %d of \"%s\" "
				    "failed", i, remote);
			/* Synthesise failures for the unsubmitted pieces so
			 * the tracker reaches remaining=0 (see the sibling
			 * comment in submit_upload_ranges). Tracker is dead
			 * to this function after the call. */
			(void)parallel_unit_tracker_finalize_n(tracker,
			    n - i, 1, NULL);
			return -1;
		}
	}
	return 0;
}

/*
 * Estimate the parked-verify footprint of a file BEFORE it transfers, so the
 * memory gate can be charged at SUBMIT time (a leading signal the submitter
 * sees) rather than at park time (a lagging signal it misses - on download the
 * walker submits everything before anything parks). Same formula as the actual
 * park in parallel_verify_park_whole_file, using the same prefix factoring, so
 * the estimate equals the real item size.
 */
static uint64_t
parallel_verify_item_bytes_estimate(struct sftp_parallel *fleet,
    const char *local_path, const char *remote_path)
{
	const char *lrel = local_path, *rrel = remote_path;

	(void)parallel_verify_prefix_match(fleet, local_path, &lrel);
	(void)parallel_verify_prefix_match(fleet, remote_path, &rrel);
	return (uint64_t)sizeof(struct verify_whole_item)
	    + strlen(lrel) + 1 + strlen(rrel) + 1 + 8 + 16;
}

/*
 * Submit one file for upload. conn is optional: when present it is used to
 * query stripe geometry and pre-create the remote file so the file can be
 * split across workers by byte range; NULL submits it as a single
 * whole-file unit.
 *
 * resume and verify carry the originating command's intent. When either is
 * set the file is submitted whole-file, because range-split resume is not
 * implemented, and when verify is set the remote must advertise
 * hpn-check-file@hpnssh.org - that is checked once up front on conn in the
 * calling thread and is fatal if missing.
 */
int
sftp_parallel_submit_upload(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode,
    int resume, int verify)
{
	/* A new command is submitting, so demote walker-phase DONE back to
	 * SUBMIT: sftp_parallel_wait leaves it DONE, and the endgame
	 * machinery must re-gate for this command's units. Main thread
	 * only. */
	if (fleet != NULL && __atomic_load_n(&fleet->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE)
		__atomic_store_n(&fleet->walker_phase, SFTP_WKP_SUBMIT,
		    __ATOMIC_RELAXED);
	int rc;

	if (resume || verify) {
		rc = -1;
		/*
		 * Resume onto an existing shorter partial: split into
		 * known-missing tail ranges + overlap reconcile spans (see
		 * submit_resume_split). Gated on BOTH resume extensions so
		 * the whole-file fallback keeps sole ownership of the
		 * -Z-against-unsupported-server fatal. Absent/equal/larger
		 * destinations keep the whole-file gate (fresh, identical-
		 * skip, and target-larger semantics live there).
		 */
		if (resume && conn != NULL &&
		    sftp_conn_has_hash_range(conn) &&
		    sftp_conn_has_hpn_check_file(conn)) {
			Attrib ra;

			if (sftp_stat(conn, remote_path, 1, &ra) == 0 &&
			    (ra.flags & SSH2_FILEXFER_ATTR_SIZE) != 0 &&
			    ra.size > 0 && (off_t)ra.size < size)
				rc = submit_resume_split(fleet, conn,
				    SFTP_OP_UPLOAD, local_path, remote_path,
				    remote_path, size, (off_t)ra.size, mode);
		}
		if (rc != 0)
			rc = submit_resume_whole_file(fleet, conn, SFTP_OP_UPLOAD,
			    local_path, remote_path, remote_path, size, mode,
			    resume, verify);
	}
	/* When a control connection is supplied, route through the
	 * speculative-split decision so a single large file produces
	 * multiple range work units (feeds the byte-based scale-up
	 * trigger). Otherwise, fall back to a whole-file unit. */
	else if (conn != NULL)
		rc = submit_upload_maybe_split(fleet, conn, local_path, remote_path,
		    size, mode);
	else
		rc = parallel_unit_submit(fleet,
		    make_unit(SFTP_OP_UPLOAD, local_path, remote_path, size, mode));
	/* Memory gate: charge this file's parked-verify footprint NOW, at submit
	 * (a leading signal), then drain if the outstanding total is over budget.
	 * Submit blocks during the drain - that block IS the backpressure that
	 * paces submission with verification. Main thread only. */
	if (fleet != NULL && fleet->cfg.verify_transfer) {
		uint64_t est = parallel_verify_item_bytes_estimate(fleet,
		    local_path, remote_path);
		pthread_mutex_lock(&fleet->verify_pending_mu);
		fleet->verify_parked_bytes += est;
		pthread_mutex_unlock(&fleet->verify_pending_mu);
		parallel_verify_maybe_wave(fleet);
	}
	/* The single authoritative file count: every caller - walker,
	 * glob, direct single-file - funnels through this chokepoint, one
	 * count per successfully submitted file, upstream of bundling /
	 * range-splitting / verify re-submits (relayed via the frames). */
	if (rc == 0 && fleet != NULL)
		__atomic_add_fetch(&fleet->files_submitted, 1, __ATOMIC_RELAXED);
	return rc;
}

/* Download counterpart of sftp_parallel_submit_upload; same resume and
 * verify rules apply. */
int
sftp_parallel_submit_download(struct sftp_parallel *fleet,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode,
    int resume, int verify)
{
	/* Demote DONE back to SUBMIT (see sftp_parallel_submit_upload). */
	if (fleet != NULL && __atomic_load_n(&fleet->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE)
		__atomic_store_n(&fleet->walker_phase, SFTP_WKP_SUBMIT,
		    __ATOMIC_RELAXED);
	int rc;

	if (resume || verify) {
		rc = -1;
		/* Mirror of the upload resume-split (see that comment); the
		 * partial is local here, so one local stat decides. */
		if (resume && conn != NULL &&
		    sftp_conn_has_hash_range(conn) &&
		    sftp_conn_has_hpn_check_file(conn)) {
			struct stat st;

			if (stat(local_path, &st) == 0 &&
			    S_ISREG(st.st_mode) && st.st_size > 0 &&
			    st.st_size < size)
				rc = submit_resume_split(fleet, conn,
				    SFTP_OP_DOWNLOAD, remote_path, local_path,
				    remote_path, size, st.st_size, mode);
		}
		if (rc != 0)
			rc = submit_resume_whole_file(fleet, conn,
			    SFTP_OP_DOWNLOAD, remote_path, local_path,
			    remote_path, size, mode, resume, verify);
	}
	else if (conn != NULL)
		rc = submit_download_maybe_split(fleet, conn, remote_path, local_path,
		    size, mode);
	else
		rc = parallel_unit_submit(fleet,
		    make_unit(SFTP_OP_DOWNLOAD, remote_path, local_path, size, mode));
	/* Memory gate (see submit_upload): charge the footprint at submit, drain
	 * if over budget. This is what makes the trigger fire on DOWNLOAD too -
	 * the walker submits all units before any file parks, so charging at
	 * submit is the only point that sees the memory coming. */
	if (fleet != NULL && fleet->cfg.verify_transfer) {
		uint64_t est = parallel_verify_item_bytes_estimate(fleet,
		    local_path, remote_path);
		pthread_mutex_lock(&fleet->verify_pending_mu);
		fleet->verify_parked_bytes += est;
		pthread_mutex_unlock(&fleet->verify_pending_mu);
		parallel_verify_maybe_wave(fleet);
	}
	/* Single authoritative file count - see the upload sibling. */
	if (rc == 0 && fleet != NULL)
		__atomic_add_fetch(&fleet->files_submitted, 1, __ATOMIC_RELAXED);
	return rc;
}

/*
 * Validate / normalise stripe_size for use as a chunk-boundary alignment
 * unit. Returns 1 if we have a usable stripe_size and the caller may
 * align byte-ranges to it; 0 means fall back to plain even division.
 *
 * Mutates *info in place for the GPFS heuristic only: GPFS exposes no
 * per-OST stripe via SFTP fs-info, so we substitute its statvfs
 * block_size as the alignment unit. Other filesystems are taken at
 * face value - only stripe_size matters downstream, and overly-large
 * values simply collapse range-splitting back toward whole-file
 * uploads (the alignment-up-to-stripe rounding pushes per_range past
 * file_size), which is harmless.
 */
static int
stripe_info_viable(struct sftp_fs_info *info, const char *path)
{
	if (strcmp(info->fs_type, "gpfs") == 0 && info->stripe_size == 0) {
		/* Valid GPFS block sizes are 256 KiB–16 MiB per IBM
		 * Spectrum Scale docs; anything else is a bogus statvfs
		 * return or a fs_type false positive. Bail rather than
		 * guessing. */
		if (info->block_size < 256 * 1024 ||
		    info->block_size > 16 * 1024 * 1024) {
			logit("hpn-fs-info: GPFS detected but block_size=%llu"
			    " is outside the valid range (256 KiB–16 MiB);"
			    " skipping stripe alignment for \"%s\"",
			    (unsigned long long)info->block_size, path);
			return 0;
		}
		info->stripe_size = info->block_size;
		debug3("hpn-fs-info: gpfs, using block_size=%llu as alignment unit",
		    (unsigned long long)info->stripe_size);
	}
	return info->stripe_size > 0;
}

/*
 * One-shot lazy fs-info accessor. Both submit_upload_maybe_split and
 * submit_download_maybe_split need the destination filesystem's stripe geometry
 * for chunk alignment; we query it once and cache it on the orchestrator.
 * Returns 1 if we got usable stripe info, 0 if alignment should fall back
 * to plain file_size/num_ranges. Output goes in *info_out (caller may
 * inspect info->stripe_size etc).
 * Caching matters at high RTT: querying fs-info synchronously per large
 * file stalls the walker between submissions.
 */
static int
get_cached_fs_info(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *remote_path, struct sftp_fs_info *info_out)
{
	if (fleet->fs_info_cached) {
		*info_out = fleet->fs_info_cache;
	} else {
		memset(info_out, 0, sizeof(*info_out));
		sftp_fs_info(conn, remote_path, info_out);
		fleet->fs_info_cache = *info_out;
		fleet->fs_info_cached = 1;
	}
	return stripe_info_viable(info_out, remote_path);
}

/*
 * Populate the one-shot fs-info cache up front. A submit issued while a
 * streamed reply is draining must send nothing on that connection, and the
 * lazy query above is the one thing in the download submit path that would;
 * doing it here means the drain finds the answer already cached. Warming with
 * the walk root matches what the first file would have asked for, since the
 * cache is per-orchestrator rather than per-path. No-op once cached.
 */
void
sftp_parallel_prewarm_fs_info(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *remote_path)
{
	struct sftp_fs_info info;

	if (fleet == NULL || conn == NULL || remote_path == NULL)
		return;
	(void)get_cached_fs_info(fleet, conn, remote_path, &info);
}

/* How long a capacity wait sleeps before re-testing on its own. Only one of
 * the three fleet->pending decrement sites broadcasts pending_cv (the push-fail
 * backout paths do not), so this bounds a missed wake to one re-test rather
 * than a wedged walk. A completion normally wakes the wait immediately and
 * this never fires, so second resolution is all it needs. */
#define AWAIT_CAPACITY_POLL_SEC  1

/*
 * Block until outstanding (submitted but not completed) files fall below
 * fleet->outstanding_cap.
 *
 * A producer that enumerates much faster than the fleet transfers will
 * otherwise submit the whole tree before much of it has moved, and every
 * outstanding file's unit and its two path strings sit in memory at once.
 * The workqueue cannot prevent that: its depth counts queued objects, and
 * under bundling one object is a bundle carrying thousands of files.
 *
 * Called from the walk, so blocking here stops the caller reading the
 * discover-tree reply and TCP back-pressure reaches the server, which stops
 * producing records. Workers drain on their own connections and broadcast
 * as they complete, so they cannot be blocked by this wait. Returns
 * immediately once an abort is set, so a failed or interrupted fleet does
 * not leave the walk parked here.
 */
void
sftp_parallel_await_capacity(struct sftp_parallel *fleet)
{
	struct timespec deadline;

	if (fleet == NULL || fleet->outstanding_cap == 0)
		return;

	pthread_mutex_lock(&fleet->pending_mu);
	while (fleet->pending >= fleet->outstanding_cap &&
	    !sftp_parallel_is_aborting(fleet)) {
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec += AWAIT_CAPACITY_POLL_SEC;
		(void)pthread_cond_timedwait(&fleet->pending_cv, &fleet->pending_mu,
		    &deadline);
	}
	pthread_mutex_unlock(&fleet->pending_mu);
}

/*
 * Resolve the range-split minimum file size, in bytes. Precedence:
 *   1. cfg.range_split_min_mb (set by -M CLI flag, sftp.c)
 *   2. RANGE_SPLIT_MIN_SIZE_DEFAULT (2 GiB)
 *
 * Values are clamped to [FLOOR, CEILING] = [64 MiB, 10 GiB]. Logs the
 * chosen value once per orchestrator at default verbosity.
 *
 * The 2 GiB default came out of a measured sweep across Lustre and ext4.
 * The scheme it replaced derived a per-file range count, which forced
 * absurdly large ranges on big files and rested on an oversubscription
 * premise that measurement contradicts: more and smaller ranges fade
 * throughput rather than balancing the tail. Tail balancing belongs at
 * the endgame, not in the range size.
 */
uint64_t
parallel_unit_split_min_size(struct sftp_parallel *fleet)
{
	uint64_t bytes;
	const char *source;

	if (fleet->cfg.range_split_min_mb > 0) {
		bytes = (uint64_t)fleet->cfg.range_split_min_mb * 1024ULL * 1024ULL;
		source = "-M";
	} else {
		bytes = RANGE_SPLIT_MIN_SIZE_DEFAULT;
		source = "default";
	}

	if (bytes < RANGE_SPLIT_MIN_SIZE_FLOOR)
		bytes = RANGE_SPLIT_MIN_SIZE_FLOOR;
	if (bytes > RANGE_SPLIT_MIN_SIZE_CEILING)
		bytes = RANGE_SPLIT_MIN_SIZE_CEILING;

	static struct sftp_parallel *logged_for;
	if (logged_for != fleet) {
		/* Config echo - debug only; the user set (or defaulted) this. */
		debug("range-split threshold = %llu MiB (source: %s)",
		    (unsigned long long)(bytes / (1024ULL*1024ULL)),
		    source);
		logged_for = fleet;
	}
	return bytes;
}


static struct sftp_work_unit *
make_download_range_unit(const char *remote_path, const char *local_path,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	return make_range_unit(SFTP_OP_DOWNLOAD_RANGE, remote_path, local_path,
	    range_offset, range_length, tracker);
}

/*
 * Pre-create remote file at the correct size, then split the local file
 * into num_ranges byte ranges and submit one SFTP_OP_UPLOAD_RANGE work unit
 * per range. The pre-creation step (open+setstat+close) is synchronous on
 * conn so all ranges see a fully allocated remote file before any worker
 * starts writing.
 *
 * range_size    - size of each range in bytes (last range may be shorter)
 * num_ranges    - number of ranges; must be >= 2
 *
 * Returns 0 if all ranges were submitted, -1 on pre-creation failure (caller
 * should fall back to a single whole-file upload unit).
 */
static int
submit_upload_ranges(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode,
    off_t range_size, int num_ranges)
{
	int i, effective_ranges = 0;
	struct sftp_range_tracker *tracker = NULL;

	/* Lazy creation: the file is created by the first worker that
	 * dispatches a range for it (parallel_unit_ensure_file), so an
	 * interrupted transfer leaves no empty placeholders. Fail fast
	 * here on an unusable destination: stat the target DIRECTORY so a
	 * bad path/permissions surfaces at submit, not as per-unit retry
	 * churn at first write. */
	{
		char *dcopy = xstrdup(remote_path);
		Attrib da;
		int dret = sftp_stat(conn, dirname(dcopy), 1, &da);
		free(dcopy);
		if (dret != 0) {
			error("destination directory for \"%s\" is not "
			    "accessible", remote_path);
			return -1;
		}
	}

	debug("range-split upload \"%s\": %d ranges of %lld bytes "
	    "(%.1f MiB each)", remote_path, num_ranges,
	    (long long)range_size, (double)range_size / (1024.0*1024.0));

	/* Count effective (positive-length) ranges first so the tracker
	 * knows the exact number of completions to wait for. Mirrors the
	 * download path; see submit_download_ranges for rationale. */
	for (i = 0; i < num_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == num_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (length <= 0)
			break;
		effective_ranges++;
	}
	if (effective_ranges == 0)
		return -1;

	/* Upload: remote file is the target, local file is the source. Tag the
	 * tracker for post-transfer verify when verify transfer is on, so the
	 * last range to finalize runs the whole-file integrity check (range
	 * units do not pass through execute_unit's whole-file verify). */
	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_REMOTE, remote_path, /*src=*/local_path,
	    /*verify=*/fleet->cfg.verify_transfer, fleet->cfg.writers_per_inode_cap);
	tracker->file_bytes = file_size;

	/* Submit one SFTP_OP_UPLOAD_RANGE work unit per range. */
	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		struct sftp_work_unit *ru = parallel_unit_make_range(local_path,
		    remote_path, offset, length, tracker);
		if (ru != NULL) {
			ru->range_index = i;
			if (tracker->vslots != NULL) {
				tracker->vslots[i].off = (u_int64_t)offset;
				tracker->vslots[i].len = (u_int64_t)length;
			}
		}
		if (parallel_unit_submit(fleet, ru) != 0) {
			/* Under an abort the refusal is expected fallout
			 * (queue is shut), not a fault - keep it quiet. */
			if (fleet->abort_flag)
				debug("submit range %d of \"%s\" refused "
				    "(abort in progress)", i, local_path);
			else
				error("submit range %d of \"%s\" failed",
				    i, local_path);
			/* Synthesise failures for the ranges we never
			 * submitted so the tracker reaches remaining=0 and
			 * the incomplete-file reporting runs (the file is
			 * left in place, resumable). NULL worker is fine.
			 * One batch call; the tracker may be freed inside
			 * and is dead to this function afterwards. */
			(void)parallel_unit_tracker_finalize_n(tracker,
			    effective_ranges - i, 1, NULL);
			return -1;
		}
	}
	return 0;
}

/*
 * Pre-create the local file at file_size, then split the remote file into
 * num_ranges byte ranges and submit one SFTP_OP_DOWNLOAD_RANGE work unit
 * per range.
 *
 * Returns 0 if all ranges were submitted, -1 on pre-creation failure (caller
 * should fall back to a single whole-file download unit).
 */
static int
submit_download_ranges(struct sftp_parallel *fleet,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode,
    off_t range_size, int num_ranges)
{
	int i, effective_ranges = 0;
	struct sftp_range_tracker *tracker = NULL;

	/* Lazy creation (see submit_upload_ranges): fail fast on an
	 * unwritable local destination directory. */
	{
		char *dcopy = xstrdup(local_path);
		if (access(dirname(dcopy), W_OK) != 0) {
			error("local destination directory for \"%s\": %s",
			    local_path, strerror(errno));
			free(dcopy);
			return -1;
		}
		free(dcopy);
	}

	debug("range-split download \"%s\": %d ranges of %lld bytes "
	    "(%.1f MiB each)", remote_path, num_ranges,
	    (long long)range_size, (double)range_size / (1024.0*1024.0));

	/* Count ranges with positive length first so the tracker knows the
	 * exact number of completions to wait for. A trailing range may be
	 * vacuous if the caller's range_size × num_ranges rounded past
	 * file_size. */
	for (i = 0; i < num_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == num_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (length <= 0)
			break;
		effective_ranges++;
	}
	if (effective_ranges == 0)
		return -1;

	/* Download: local file is the target, remote file is the source. */
	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_LOCAL, local_path, /*src=*/remote_path,
	    /*verify=*/fleet->cfg.verify_transfer, fleet->cfg.writers_per_inode_cap);
	tracker->file_bytes = file_size;

	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		struct sftp_work_unit *ru = make_download_range_unit(remote_path,
		    local_path, offset, length, tracker);
		/* Record the range geometry for the range-granular verify. Download
		 * tees no source hash, so valid stays 0 and the verify reads the
		 * dest range back; only off/len are needed here. */
		if (ru != NULL && tracker->vslots != NULL) {
			tracker->vslots[i].off = (u_int64_t)offset;
			tracker->vslots[i].len = (u_int64_t)length;
		}
		if (parallel_unit_submit(fleet, ru) != 0) {
			/* Under an abort the refusal is expected fallout
			 * (queue is shut), not a fault - keep it quiet. */
			if (fleet->abort_flag)
				debug("submit download range %d of \"%s\" "
				    "refused (abort in progress)",
				    i, remote_path);
			else
				error("submit download range %d of \"%s\" "
				    "failed", i, remote_path);
			/* Synthesise failures for the ranges we never
			 * submitted so the tracker reaches remaining=0 and
			 * the incomplete-file reporting runs (the file is
			 * left in place, resumable). Without this the
			 * tracker leaks. No worker context here, so pass
			 * NULL. One batch call; the tracker may be freed
			 * inside and is dead to this function afterwards. */
			(void)parallel_unit_tracker_finalize_n(tracker,
			    effective_ranges - i, 1, NULL);
			return -1;
		}
	}
	return 0;
}

/*
 * Shared range-split decision used by both directions. Returns 1 and fills
 * *range_size / *num_ranges when the file should be split into ranges, or 0
 * to fall back to a whole-file transfer. Range splitting needs a known file
 * size (callers pass it from the local stat / the SFTP directory listing /
 * the glob attrib cache); a zero/too-small size, a sub-floor file, or the
 * HPN_NO_RANGE_SPLIT escape hatch all return 0.
 *
 * Range COUNT = file_size / floor (parallel_unit_split_min_size, default
 * 2 GiB, -M override): the floor is the single knob and governs range SIZE;
 * there is no count cap. Range SIZE is stripe-aligned when hpn-fs-info
 * reports Lustre/GPFS geometry (adjacent ranges target different OSTs),
 * otherwise plain file_size/num_ranges.
 */
static int
compute_range_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *remote_path, off_t file_size,
    off_t *range_size, int *num_ranges)
{
	struct sftp_fs_info info;
	int max_ranges, n, have_stripe;
	off_t per_range;

	if (file_size <= 0)
		return 0;
	/* Static-floor fast path: below any plausible threshold, short-circuit
	 * without paying for the fs-info RTT. */
	if ((uint64_t)file_size < RANGE_SPLIT_MIN_SIZE_FLOOR)
		return 0;
	if ((uint64_t)file_size < parallel_unit_split_min_size(fleet))
		return 0;

	max_ranges = (int)(file_size / parallel_unit_split_min_size(fleet));
	if (max_ranges < 2)
		return 0;

	/* fs-info costs one control-connection RTT; cached per orchestrator
	 * (the destination filesystem does not change within a transfer). */
	have_stripe = get_cached_fs_info(fleet, conn, remote_path, &info);
	n = max_ranges;
	per_range = (file_size + n - 1) / n;
	if (have_stripe && info.stripe_size > 0) {
		off_t stripe = (off_t)info.stripe_size;
		*range_size = ((per_range + stripe - 1) / stripe) * stripe;
		/*
		 * The stripe round-up inflates range_size above per_range, so the
		 * original n ranges of range_size would overshoot EOF - ranges
		 * that start past EOF and a negative-length final range (the
		 * submit_*_ranges path takes the last length as file_size -
		 * offset). Recompute the range COUNT from the inflated size so
		 * the ranges tile the file exactly (each stripe-aligned; the last
		 * is the remainder). n only shrinks here since range_size >=
		 * per_range; if it drops below 2 the stripe-aligned split is not
		 * worth doing, so fall back to the whole-file path.
		 */
		n = (int)((file_size + *range_size - 1) / *range_size);
		if (n < 2)
			return 0;
	} else {
		/* No stripe geometry from hpn-fs-info. The server now resolves
		 * the Lustre default (sftp-lustre.c lustre_get_stripe walks up to
		 * a concrete default), so a zero stripe here means a non-striped
		 * filesystem (ext4/xfs/NFS/etc.) - use plain even division. */
		*range_size = per_range;
	}
	*num_ranges = n;
	return 1;
}

static int
submit_download_maybe_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode)
{
	off_t range_size;
	int num_ranges;

	if (compute_range_split(fleet, conn, remote_path, file_size,
	    &range_size, &num_ranges) &&
	    submit_download_ranges(fleet, remote_path, local_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* No split, or pre-creation failed - whole-file. */
	return parallel_unit_submit(fleet, make_unit(SFTP_OP_DOWNLOAD,
	    remote_path, local_path, file_size, mode));
}

/*
 * Decide whether and how to range-split a large file, then either submit
 * range units (via submit_upload_ranges) or fall back to a whole-file unit.
 * The split decision is shared with the download side in compute_range_split().
 */
static int
submit_upload_maybe_split(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode)
{
	off_t range_size;
	int num_ranges;

	if (compute_range_split(fleet, conn, remote_path, file_size,
	    &range_size, &num_ranges) &&
	    submit_upload_ranges(fleet, conn, local_path, remote_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* No split, or pre-creation failed - whole-file. */
	return parallel_unit_submit(fleet, make_unit(SFTP_OP_UPLOAD,
	    local_path, remote_path, file_size, mode));
}
