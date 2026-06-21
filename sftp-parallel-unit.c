/*
 * sftp-parallel-unit.c - work units and submission for the parallel
 * SFTP orchestrator: unit/range-tracker construction and teardown,
 * per-file writer-cap slots, pending accounting, range splitting
 * policy, and the submit paths (whole-file, resume, byte-range).
 * Split from sftp-parallel.c; moves are verbatim.
 *
 * PFS NOTE: stripe_info_viable() and get_cached_fs_info() are the
 * filesystem-aware seam in the submit path (today: Lustre via
 * sftp-lustre.c and the fs-info extension).  Future parallel-fs
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

struct sftp_work_unit *
parallel_unit_make_range(const char *src, const char *dst,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op            = SFTP_OP_UPLOAD_RANGE;
	u->src_path      = xstrdup(src);
	u->dst_path      = xstrdup(dst);
	u->size          = range_length;
	u->range_offset  = range_offset;
	u->range_length  = range_length;
	u->range_tracker = tracker;
	return u;
}

void
parallel_unit_free(struct sftp_work_unit *u)
{
	if (u == NULL) return;
	/* Bundle container: free any still-attached member units.  The worker
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
	 * by parallel_unit_free.  See parallel_unit_tracker_finalize for ownership rules. */
	/* A verify unit owns its parked tracker.  The verify handler NULLs this
	 * after freeing it, so a still-set pointer means the unit was dropped
	 * before any worker ran it (abort / queue shutdown): free it here. */
	if (u->verify_tracker != NULL)
		parallel_verify_and_free(NULL, u->verify_tracker);
	/* Range-granular verify: this dropped chunk still holds a reference to the
	 * shared per-file job; release it (free the job on the last reference,
	 * exactly like a completed chunk - just without recording a failure). */
	if (u->verify_job != NULL) {
		if (__atomic_sub_fetch(&u->verify_job->ranges_left, 1,
		    __ATOMIC_ACQ_REL) == 0)
			parallel_verify_job_free(u->verify_job);
		u->verify_job = NULL;
	}
	free(u);
}

/*
 * Range-completion tracker constructor.  Allocated once per range-split
 * transfer (download by submit_download_ranges, upload by
 * submit_upload_ranges) and attached to each of the N range work units
 * it creates.  Lives until the last range completes; that completer
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
	 * across the pool.  Upload (REMOTE) tees a source hash into each slot
	 * (valid=1); download (LOCAL) leaves valid=0 and reads the dest range back
	 * at verify time.  Either way submit_*_ranges fills off/len. */
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
 * HPNVerifyTransfer: record a range's teed source hash into its tracker slot.
 * The teed hash covers exactly the byte span the unit transferred in this
 * pass.  It is authoritative for the slot ONLY when that span still equals the
 * slot's original [off, len) - i.e. the range was never split.  The caller's
 * own attempt==0 guard is NOT sufficient: the highwater-resume requeue
 * (worker_process_result) resets attempt to 0 and shrinks the unit to its
 * remainder, so a resumed range reaches here looking "first-attempt clean"
 * while its teed hash covers only the tail.  The endgame split likewise shrinks
 * the held unit and spawns pieces.  So the authoritative guard lives here:
 * store only when (off, len) match the slot; any split leaves valid=0 and the
 * range is re-read in full from the source at finalize.  NULL-safe; a no-op
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
 * Concurrent-writer cap (HPN).  Try to claim a writer slot on this file's
 * tracker: succeeds (returns 1, active_writers bumped) only while below the
 * cap.  NULL tracker (non-range unit) always succeeds with no accounting.
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

/* Release a writer slot claimed by parallel_unit_writer_acquire.  NULL-safe;
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
 * Lazy first-writer file creation.  Called by the worker before it
 * dispatches the first range of a unit; the tracker mutex makes it
 * exactly-once per file.  create-if-absent ONLY: layout-created files
 * (Lustre auto-stripe creates with layout before data) and existing
 * partials (reput onto a previous attempt) pass through untouched -
 * never truncated, never re-laid-out.  No size is pinned: the file
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
 * One range's final completion: `failed` = 1 on permanent give-up
 * (after MAX_RETRIES) or 0 on success.  Must be called exactly once
 * per range unit, on its final outcome only - see invariants (I1)
 * and (I2) at struct sftp_range_tracker.
 *
 * `w` is the worker reporting completion; used only for sftp_rm on
 * REMOTE-target trackers when the corrupt-file cleanup fires.  May
 * be NULL otherwise (I4).
 *
 * Returns 1 if THIS call was the last-completer AND any range
 * failed (informational - the cleanup happened inside this call
 * regardless).  Returns 0 otherwise.
 *
 * Tracker is freed when remaining hits 0; callers that saw a 0
 * return value have a dead pointer and must not deref it (I3).
 *
 * No-op on NULL t (I5).
 */
int
parallel_unit_tracker_finalize(struct sftp_range_tracker *t, int failed,
    struct sftp_worker *w)
{
	int was_last, incomplete;

	if (t == NULL)
		return 0;

	pthread_mutex_lock(&t->mu);
	if (failed)
		t->any_failed = 1;
	t->remaining--;
	was_last   = (t->remaining == 0);
	incomplete = was_last && t->any_failed;
	if (was_last && getenv("HPN_BUNDLE_TIMING") != NULL)
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
		 * failed ranges are still zeros from fallocate).  Do NOT
		 * delete it.  Leaving it in place keeps it RESUMABLE: the
		 * user re-runs verified resume (reputv for uploads, regetv
		 * for downloads), which uses sftp-hash-range@hpnssh.org to
		 * hash each range and refill only the mismatched ones -
		 * salvaging every range that already transferred instead of
		 * forcing a full re-send.  Unlinking would throw all that
		 * good data away.  Report loudly so the user and any
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
	} else if (t->verify && w != NULL) {
		/*
		 * HPNVerifyTransfer: the file's last range just finished
		 * cleanly.  Park the completed tracker for the post-transfer
		 * verify phase rather than verifying here - keeping verify off
		 * the transfer path so an in-flight transfer never blocks on a
		 * server read-back.  sftp_parallel_wait submits it as an
		 * SFTP_OP_VERIFY unit once the transfer queue drains; the verify
		 * handler frees the tracker.
		 */
		parallel_verify_park(w->parent, t);
		return incomplete;
	}
	pthread_mutex_destroy(&t->mu);
	free(t->vslots);
	free(t->path);
	free(t->src_path);
	free(t);
	return incomplete;
}

/*
 * Run the post-transfer verify for a completed range tracker on worker w's
 * connection, then free the tracker.  Called from the SFTP_OP_VERIFY worker
 * path; with w == NULL it frees the tracker without verifying (drop path).
 * Download (target LOCAL) uses the whole-file readback verify; upload (REMOTE)
 * uses the per-range verify off the teed source hashes when slots are present,
 * else the whole-file fallback (pre-19 server path, and all whole-file units).
 */
void
parallel_verify_and_free(struct sftp_worker *w, struct sftp_range_tracker *t)
{
	if (t->verify && w != NULL) {
		if (t->target == SFTP_RANGE_TARGET_LOCAL)
			parallel_verify_one(w, t->path, t->src_path,
			    /*local_is_target=*/1);
		else if (t->vslots != NULL)
			parallel_verify_one_ranges(w, t);
		else
			parallel_verify_one(w, t->src_path, t->path,
			    /*local_is_target=*/0);
	}
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
parallel_verify_park(struct sftp_parallel *p, struct sftp_range_tracker *t)
{
	pthread_mutex_lock(&p->verify_pending_mu);
	if (p->verify_pending_n == p->verify_pending_cap) {
		int ncap = p->verify_pending_cap ? p->verify_pending_cap * 2 : 16;
		p->verify_pending = xreallocarray(p->verify_pending,
		    (size_t)ncap, sizeof(*p->verify_pending));
		p->verify_pending_cap = ncap;
	}
	p->verify_pending[p->verify_pending_n++] = t;
	pthread_mutex_unlock(&p->verify_pending_mu);
}

/*
 * Park a completed whole-file (non-range-split) transfer for the verify phase.
 * Builds a lightweight tracker carrying just the paths + direction; with no
 * vslots, parallel_verify_and_free runs the whole-file readback verify.  The
 * path/src_path convention matches parallel_verify_and_free's dispatch:
 * download (local is target) hashes t->path locally vs t->src_path remote;
 * upload reads t->src_path locally vs the server's hash of t->path.
 */
void
parallel_verify_park_whole_file(struct sftp_parallel *p, const char *local_path,
    const char *remote_path, int local_is_target)
{
	struct sftp_range_tracker *t = xcalloc(1, sizeof(*t));

	pthread_mutex_init(&t->mu, NULL);
	t->verify = 1;
	if (local_is_target) {
		t->target = SFTP_RANGE_TARGET_LOCAL;
		t->path = xstrdup(local_path);
		t->src_path = xstrdup(remote_path);
	} else {
		t->target = SFTP_RANGE_TARGET_REMOTE;
		t->path = xstrdup(remote_path);
		t->src_path = xstrdup(local_path);
	}
	parallel_verify_park(p, t);
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
 * the direction.  Upload (REMOTE target): local=source/remote=dest, teed source
 * hashes apply.  Download (LOCAL target): local=dest/remote=source, no teed.
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

/*
 * Submit the parked files as SFTP_OP_VERIFY work units, drained by the idle
 * workers over their own connections.  Range-split files (vslots present, server
 * advertises sftp-hash-range) fan ONE unit per transfer range across the pool
 * (range-granular within-file parallel verify); each shares the file's verify
 * job and the last range to finish frees it.  Whole-file / small / pre-19-server
 * files stay one unit per file carrying the tracker (parallel_verify_and_free).
 * Returns the total UNIT count (= chunks, not files) for the phase meter.
 */
int
parallel_verify_phase_submit(struct sftp_parallel *p)
{
	struct sftp_range_tracker **arr;
	struct sftp_work_unit **units = NULL;
	int i, n, can_chunk, nunits = 0, ucap = 0;

	pthread_mutex_lock(&p->verify_pending_mu);
	arr = p->verify_pending;
	n = p->verify_pending_n;
	p->verify_pending = NULL;
	p->verify_pending_n = 0;
	p->verify_pending_cap = 0;
	pthread_mutex_unlock(&p->verify_pending_mu);

	/* Range-granular verify needs the server's sftp-hash-range; all workers
	 * talk to the same server, so one worker's conn answers for the fleet. */
	can_chunk = (p->num_workers > 0 && p->workers[0] != NULL &&
	    p->workers[0]->conn != NULL &&
	    sftp_conn_has_hash_range(p->workers[0]->conn));

	for (i = 0; i < n; i++) {
		struct sftp_range_tracker *t = arr[i];

		if (can_chunk && t->vslots != NULL && t->vslots_n > 0) {
			struct verify_job *j = build_verify_job(t);
			int k;

			parallel_verify_and_free(NULL, t);	/* free; no verify */
			for (k = 0; k < j->n_ranges; k++) {
				struct sftp_work_unit *u = xcalloc(1, sizeof(*u));

				u->op = SFTP_OP_VERIFY;
				u->verify_job = j;
				u->range_index = k;
				u->range_offset = j->offs[k];
				u->range_length = j->lens[k];
				if (nunits == ucap) {
					ucap = ucap ? ucap * 2 : 64;
					units = xreallocarray(units,
					    (size_t)ucap, sizeof(*units));
				}
				units[nunits++] = u;
			}
		} else {
			struct sftp_work_unit *u = xcalloc(1, sizeof(*u));

			u->op = SFTP_OP_VERIFY;
			u->verify_tracker = t;
			if (nunits == ucap) {
				ucap = ucap ? ucap * 2 : 64;
				units = xreallocarray(units, (size_t)ucap,
				    sizeof(*units));
			}
			units[nunits++] = u;
		}
	}
	free(arr);

	/* Set the unit total BEFORE pushing so the reporter's 100%-snap gate
	 * (done_units >= total) can't fire early while we are still submitting. */
	p->verify_total_units = (uint64_t)nunits;

	for (i = 0; i < nunits; i++)
		(void)parallel_unit_submit(p, units[i]);
	free(units);
	return nunits;
}

/*
 * Resolve the effective per-unit retry budget.  See the comment at the
 * HPN_MAX_RETRIES_* defines near the top of this file for the full
 * policy.  Definition lives here because struct sftp_parallel is
 * opaque earlier in the file; the forward decl appears alongside the
 * defines.
 */
int
parallel_unit_max_retries(struct sftp_parallel *p)
{
	if (p != NULL &&
	    p->cfg.max_retries >= HPN_MAX_RETRIES_MIN &&
	    p->cfg.max_retries <= HPN_MAX_RETRIES_MAX)
		return p->cfg.max_retries;
	return HPN_MAX_RETRIES_DEFAULT;
}

static int pending_trace_enabled = -1;

int
parallel_unit_pending_trace_on(void)
{
	if (pending_trace_enabled < 0) {
		/* ENV-VAR SFTP_PENDING_TRACE - developer-only: enable verbose
		 * pending-counter trace logging for debugging work-unit
		 * lifecycle issues.  Not user-facing. */
		const char *e = getenv("SFTP_PENDING_TRACE");
		pending_trace_enabled = (e && e[0] == '1') ? 1 : 0;
	}
	return pending_trace_enabled;
}

void
parallel_unit_pending_trace(const char *action, struct sftp_parallel *p,
    const struct sftp_work_unit *u, int worker_id, const char *site)
{
	if (!parallel_unit_pending_trace_on())
		return;
	const char *src = (u && u->src_path) ? u->src_path : "(null)";
	const char *dst = (u && u->dst_path) ? u->dst_path : "(null)";
	int op = u ? (int)u->op : -1;
	logit_f("PTRACE %s pending=%llu op=%d u=%p w=%d site=%s src=%s dst=%s",
	    action, (unsigned long long)p->pending, op, (const void *)u,
	    worker_id, site, src, dst);
}

void
parallel_unit_pending_dec(struct sftp_parallel *p)
{
	pthread_mutex_lock(&p->pending_mu);
	if (p->pending > 0)
		p->pending--;
	if (p->pending == 0)
		pthread_cond_broadcast(&p->pending_cv);
	pthread_mutex_unlock(&p->pending_mu);
}

/* Traced variant: pass the unit and a call-site label so the trace can
 * pair each dec with the corresponding inc.  Production callers should
 * use the macro PENDING_DEC defined below, which expands to the traced
 * variant when parallel_unit_pending_trace_on(). */
void
parallel_unit_pending_dec_traced(struct sftp_parallel *p, const struct sftp_work_unit *u,
    int worker_id, const char *site)
{
	if (parallel_unit_pending_trace_on())
		parallel_unit_pending_trace("DEC", p, u, worker_id, site);
	parallel_unit_pending_dec(p);
}

/*
 * Return the maximum file size (in bytes) eligible for the bundle path
 * given this parallel's bundle target.  Files at or above this size
 * waste the bundle protocol's OPEN/CLOSE amortisation (a "bundle" of
 * one large file is just an SFTP put/get with extra round-trips) and
 * starve other workers while this one packs.  See BUNDLE_MIN_FILES_PER_BUNDLE
 * for the derivation.
 *
 * Computed once per submit; no caching needed (a divide + branch).
 */
static uint64_t
bundle_file_size_max_for(const struct sftp_parallel *p)
{
	uint64_t target = (p != NULL && p->cfg.bundle_size > 0)
	    ? p->cfg.bundle_size
	    : BUNDLE_TARGET_BYTES_DEFAULT;
	return BUNDLE_FILE_MAX_BYTES(target);
}

static int submit_upload_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode);
static int submit_download_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode);

/*
 * Roll back one bundle member's submit accounting and free it.  Used when a
 * flush can't push (queue shut down) - mirrors parallel_unit_submit's own
 * push-fail backout so pending / queued_bytes stay balanced.
 */
static void
parallel_bundle_member_pushfail(struct sftp_parallel *p,
    struct sftp_work_unit *u)
{
	pthread_mutex_lock(&p->pending_mu);
	if (p->pending > 0) p->pending--;
	pthread_mutex_unlock(&p->pending_mu);
	if (parallel_unit_pending_trace_on())
		parallel_unit_pending_trace("DEC_PUSHFAIL", p, u, -1,
		    "bundle/pushfail");
	if (u->size > 0)
		__atomic_fetch_sub(&p->queued_bytes, (uint64_t)u->size,
		    __ATOMIC_RELAXED);
	parallel_unit_free(u);
}

/*
 * Flush the producer-side bundle accumulator (caller holds bundle_mu).
 *   n == 0  -> nothing to do.
 *   n == 1  -> push the lone member as an ordinary unit (a bundle of one is
 *              pointless; it still transfers, just un-bundled).
 *   n >= 2  -> wrap the members in a SFTP_OP_BUNDLE_* container and push that.
 * Members keep the pending / queued_bytes accounting they took at add time;
 * the container is a transport shell (its ->size = sum of member bytes drives
 * the single pickup subtraction at worker dispatch).
 */
static void
parallel_bundle_flush_locked(struct sftp_parallel *p)
{
	int n = p->bundle_pending_n, i;

	if (n == 0)
		return;
	p->bundle_pending_n = 0;
	p->bundle_pending_framed = 0;

	if (n == 1) {
		struct sftp_work_unit *u = p->bundle_pending[0];
		if (sftp_workqueue_push(p->q, u) != 0)
			parallel_bundle_member_pushfail(p, u);
		return;
	}

	struct sftp_work_unit *c = xcalloc(1, sizeof(*c));
	c->op = (p->bundle_pending_op == SFTP_OP_DOWNLOAD)
	    ? SFTP_OP_BUNDLE_DOWNLOAD : SFTP_OP_BUNDLE_UPLOAD;
	c->members = xreallocarray(NULL, (size_t)n, sizeof(*c->members));
	c->n_members = n;
	for (i = 0; i < n; i++) {
		c->members[i] = p->bundle_pending[i];
		if (p->bundle_pending[i]->size > 0)
			c->size += p->bundle_pending[i]->size;
	}
	if (sftp_workqueue_push(p->q, c) != 0) {
		for (i = 0; i < n; i++)
			parallel_bundle_member_pushfail(p, c->members[i]);
		free(c->members);
		free(c);
	}
}

/*
 * Add a bundle-eligible small file to the accumulator.  It takes the same
 * pending / queued_bytes accounting as an individual unit (members are real
 * work units; the bundle just transports them), then accumulates under
 * bundle_mu and flushes a full bundle at the framed-byte or file-count cap.
 */
static int
parallel_bundle_add(struct sftp_parallel *p, struct sftp_work_unit *u)
{
	uint64_t add_bytes = (u->size > 0) ? (uint64_t)u->size : 0;
	uint64_t target = (p->cfg.bundle_size > 0)
	    ? p->cfg.bundle_size : BUNDLE_TARGET_BYTES_DEFAULT;

	pthread_mutex_lock(&p->pending_mu);
	p->pending++;
	pthread_mutex_unlock(&p->pending_mu);
	if (parallel_unit_pending_trace_on())
		parallel_unit_pending_trace("INC", p, u, -1, "bundle-add");
	if (add_bytes)
		__atomic_fetch_add(&p->queued_bytes, add_bytes,
		    __ATOMIC_RELAXED);

	pthread_mutex_lock(&p->bundle_mu);
	/* A bundle carries one direction; flush a pending one of the other op. */
	if (p->bundle_pending_n > 0 && p->bundle_pending_op != u->op)
		parallel_bundle_flush_locked(p);
	if (p->bundle_pending_n == p->bundle_pending_cap) {
		int ncap = p->bundle_pending_cap ? p->bundle_pending_cap * 2 : 64;
		p->bundle_pending = xreallocarray(p->bundle_pending,
		    (size_t)ncap, sizeof(*p->bundle_pending));
		p->bundle_pending_cap = ncap;
	}
	p->bundle_pending[p->bundle_pending_n++] = u;
	p->bundle_pending_op = u->op;
	p->bundle_pending_framed += BUNDLE_TAR_FRAME_BYTES(u->size);
	if (p->bundle_pending_framed >= target ||
	    p->bundle_pending_n >= BUNDLE_BATCH_MAX_FILES)
		parallel_bundle_flush_locked(p);
	pthread_mutex_unlock(&p->bundle_mu);
	sftp_workqueue_kick(p->q);
	return 0;
}

void
parallel_bundle_flush_pending(struct sftp_parallel *p)
{
	if (p == NULL)
		return;
	pthread_mutex_lock(&p->bundle_mu);
	parallel_bundle_flush_locked(p);
	pthread_mutex_unlock(&p->bundle_mu);
	sftp_workqueue_kick(p->q);
}

int
parallel_unit_submit(struct sftp_parallel *p, struct sftp_work_unit *u)
{
	if (p == NULL || p->stopped || p->abort_flag) {
		parallel_unit_free(u);
		return -1;
	}
	/* Bundle-eligibility gate: when bundle mode is enabled and the
	 * unit's file size exceeds the per-target threshold, mark it
	 * ineligible so the worker routes it through the single-file
	 * path (which may further range-split it).  Range and resume
	 * units are never bundle-eligible regardless of size - handled
	 * by their op-type elsewhere. */
	if (u != NULL && p->cfg.use_bundle && u->size > 0 &&
	    (uint64_t)u->size > bundle_file_size_max_for(p)) {
		u->bundle_ineligible = 1;
	}
	/* Producer-side bundle assembly: group eligible small files into whole
	 * bundles here (single submit thread) so workers pull a complete bundle
	 * rather than racing to accumulate one.  Everything else - large/range/
	 * resume units, and worker re-submits (always bundle_ineligible) - takes
	 * the individual path below. */
	if (u != NULL && p->cfg.use_bundle && !u->bundle_ineligible &&
	    (u->op == SFTP_OP_UPLOAD || u->op == SFTP_OP_DOWNLOAD))
		return parallel_bundle_add(p, u);
	uint64_t add_bytes = (u->size > 0) ? (uint64_t)u->size : 0;
	pthread_mutex_lock(&p->pending_mu);
	p->pending++;
	pthread_mutex_unlock(&p->pending_mu);
	if (parallel_unit_pending_trace_on())
		parallel_unit_pending_trace("INC", p, u, -1, "submit");
	if (add_bytes)
		__atomic_fetch_add(&p->queued_bytes, add_bytes,
		    __ATOMIC_RELAXED);
	if (sftp_workqueue_push(p->q, u) != 0) {
		pthread_mutex_lock(&p->pending_mu);
		if (p->pending > 0) p->pending--;
		pthread_mutex_unlock(&p->pending_mu);
		if (parallel_unit_pending_trace_on())
			parallel_unit_pending_trace("DEC_PUSHFAIL", p, u, -1,
			    "submit/pushfail");
		if (add_bytes)
			__atomic_fetch_sub(&p->queued_bytes, add_bytes,
			    __ATOMIC_RELAXED);
		parallel_unit_free(u);
		return -1;
	}
	/* Genuinely NEW work: wake any workers parked in the cap-gate's
	 * activity wait.  Deliberately NOT done inside the queue's push -
	 * the cap-gate's own requeue pushes there, and kicking from push
	 * created a wake->pass->requeue->kick feedback storm (measured:
	 * denials 6M -> 109M, four cores burned). */
	sftp_workqueue_kick(p->q);
	return 0;
}

/*
 * Worker-context re-queue (non-blocking).  A worker that blocks on a full p->q
 * it also drains can self-deadlock (fatal at -j1).  Try the queue; on full,
 * park the unit on the retry-overflow list (existing allocation, FIFO,
 * reporter-drained).  pending/queued_bytes are unchanged - the unit stays
 * pending wherever it sits, so callers must NOT re-account here.
 */
int
parallel_worker_requeue(struct sftp_parallel *p, struct sftp_work_unit *u,
    int front)
{
	int rc = front ? sftp_workqueue_trypush_front(p->q, u)
	               : sftp_workqueue_trypush(p->q, u);
	if (rc == 0)
		return 0;	/* placed on the queue */
	if (rc < 0)
		return -1;	/* queue shut down -> caller gives up */

	/* rc > 0: queue full.  Park on the overflow list; never block. */
	pthread_mutex_lock(&p->retry_overflow_mu);
	u->overflow_next = NULL;
	u->overflow_front = front;
	if (p->retry_overflow_tail != NULL)
		p->retry_overflow_tail->overflow_next = u;
	else
		p->retry_overflow_head = u;
	p->retry_overflow_tail = u;
	size_t depth = ++p->retry_overflow_n;
	pthread_mutex_unlock(&p->retry_overflow_mu);
	debug2_ft("re-queue overflow: p->q full, parked unit (depth=%zu)", depth);
	return 0;
}

/*
 * Reporter-context: move overflow-parked units back into p->q while it has
 * room.  Each re-enters via its original front/tail intent (a worker blocked
 * in pop wakes on trypush's not_empty signal).  Stops at the first unit that
 * won't fit (queue full again) or on shutdown, re-parking it at the head so
 * FIFO order and the pending invariant hold.
 */
void
parallel_retry_overflow_drain(struct sftp_parallel *p)
{
	for (;;) {
		pthread_mutex_lock(&p->retry_overflow_mu);
		struct sftp_work_unit *u = p->retry_overflow_head;
		if (u == NULL) {
			pthread_mutex_unlock(&p->retry_overflow_mu);
			return;
		}
		p->retry_overflow_head = u->overflow_next;
		if (p->retry_overflow_head == NULL)
			p->retry_overflow_tail = NULL;
		p->retry_overflow_n--;
		pthread_mutex_unlock(&p->retry_overflow_mu);

		int front = u->overflow_front;
		u->overflow_next = NULL;
		u->overflow_front = 0;
		int rc = front ? sftp_workqueue_trypush_front(p->q, u)
		               : sftp_workqueue_trypush(p->q, u);
		if (rc == 0)
			continue;	/* placed; try the next parked unit */

		/* Full again or shut down: re-park at the head and stop. */
		pthread_mutex_lock(&p->retry_overflow_mu);
		u->overflow_front = front;
		u->overflow_next = p->retry_overflow_head;
		p->retry_overflow_head = u;
		if (p->retry_overflow_tail == NULL)
			p->retry_overflow_tail = u;
		p->retry_overflow_n++;
		pthread_mutex_unlock(&p->retry_overflow_mu);
		return;
	}
}

/*
 * Stop/abort cleanup: free any units still parked on the overflow list.  Run
 * after the workers and reporter have joined (no concurrent access).  These
 * units never reached a worker, so freeing mirrors a drained queue item.
 */
void
parallel_retry_overflow_free(struct sftp_parallel *p)
{
	struct sftp_work_unit *u, *next;

	pthread_mutex_lock(&p->retry_overflow_mu);
	u = p->retry_overflow_head;
	p->retry_overflow_head = NULL;
	p->retry_overflow_tail = NULL;
	p->retry_overflow_n = 0;
	pthread_mutex_unlock(&p->retry_overflow_mu);

	while (u != NULL) {
		next = u->overflow_next;
		u->overflow_next = NULL;
		parallel_unit_free(u);
		u = next;
	}
}

/*
 * Whole-file submit for a resumed and/or verified transfer.  resume/verify
 * disable speculative range-splitting: range-split resume is the deferred
 * sparse-hole case, so the file goes as one unit where sftp_upload/
 * sftp_download's hash gate applies.  The unsupported-remote check fires
 * HERE, in the main (submit) thread - a fatal() inside a worker would fight
 * fault isolation, and hpn-check-file support is identical across workers,
 * so one up-front check on the control connection suffices.  'remote' is the
 * path named in the failure message; 'src'/'dst' follow make_unit's
 * per-op convention (upload: local→remote; download: remote→local).
 */
static int
submit_resume_whole_file(struct sftp_parallel *p, struct sftp_conn *conn,
    enum sftp_op op, const char *src, const char *dst, const char *remote,
    off_t size, mode_t mode, int resume, int verify)
{
	struct sftp_work_unit *u;

	if (verify && conn != NULL && !sftp_conn_has_hpn_check_file(conn))
		fatal("\"%s\": %s", remote, RESUME_INCOMPAT_MSG);
	u = make_unit(op, src, dst, size, mode);
	u->resume = resume;
	u->verify = verify;
	return parallel_unit_submit(p, u);
}

int
sftp_parallel_submit_upload(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode,
    int resume, int verify)
{
	/* New command submitting: re-gate the endgame machinery (see the
	 * DONE-at-wait note in sftp_parallel_wait).  Main thread only. */
	if (p != NULL && __atomic_load_n(&p->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE)
		__atomic_store_n(&p->walker_phase, SFTP_WKP_SUBMIT,
		    __ATOMIC_RELAXED);
	if (resume || verify)
		return submit_resume_whole_file(p, conn, SFTP_OP_UPLOAD,
		    local_path, remote_path, remote_path, size, mode,
		    resume, verify);
	/* When a control connection is supplied, route through the
	 * speculative-split decision so a single large file produces
	 * multiple range work units (feeds the byte-based scale-up
	 * trigger).  Otherwise, fall back to a whole-file unit. */
	if (conn != NULL)
		return submit_upload_maybe_split(p, conn, local_path, remote_path,
		    size, mode);
	return parallel_unit_submit(p,
	    make_unit(SFTP_OP_UPLOAD, local_path, remote_path, size, mode));
}

int
sftp_parallel_submit_download(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode,
    int resume, int verify)
{
	/* New command submitting: re-gate the endgame machinery (see the
	 * DONE-at-wait note in sftp_parallel_wait).  Main thread only. */
	if (p != NULL && __atomic_load_n(&p->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE)
		__atomic_store_n(&p->walker_phase, SFTP_WKP_SUBMIT,
		    __ATOMIC_RELAXED);
	if (resume || verify)
		return submit_resume_whole_file(p, conn, SFTP_OP_DOWNLOAD,
		    remote_path, local_path, remote_path, size, mode,
		    resume, verify);
	if (conn != NULL)
		return submit_download_maybe_split(p, conn, remote_path, local_path,
		    size, mode);
	return parallel_unit_submit(p,
	    make_unit(SFTP_OP_DOWNLOAD, remote_path, local_path, size, mode));
}

/*
 * Validate / normalise stripe_size for use as a chunk-boundary alignment
 * unit.  Returns 1 if we have a usable stripe_size and the caller may
 * align byte-ranges to it; 0 means fall back to plain even division.
 *
 * Mutates *info in place for the GPFS heuristic only: GPFS exposes no
 * per-OST stripe via SFTP fs-info, so we substitute its statvfs
 * block_size as the alignment unit.  Other filesystems are taken at
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
		 * return or a fs_type false positive.  Bail rather than
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
 * One-shot lazy fs-info accessor.  Both submit_upload_maybe_split and
 * submit_download_maybe_split need the destination filesystem's stripe geometry
 * for chunk alignment; we query it once and cache it on the orchestrator.
 * Returns 1 if we got usable stripe info, 0 if alignment should fall back
 * to plain file_size/num_ranges.  Output goes in *info_out (caller may
 * inspect info->stripe_size etc).
 */
static int
get_cached_fs_info(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, struct sftp_fs_info *info_out)
{
	if (p->fs_info_cached) {
		*info_out = p->fs_info_cache;
	} else {
		memset(info_out, 0, sizeof(*info_out));
		sftp_fs_info(conn, remote_path, info_out);
		p->fs_info_cache = *info_out;
		p->fs_info_cached = 1;
	}
	return stripe_info_viable(info_out, remote_path);
}

/*
 * Resolve the range-split minimum file size, in bytes.  Precedence:
 *   1. cfg.range_split_min_mb (set by -M CLI flag, sftp.c)
 *   2. RANGE_SPLIT_MIN_SIZE_DEFAULT (2 GiB)
 *
 * Values are clamped to [FLOOR, CEILING] = [64 MiB, 10 GiB].  Logs the
 * chosen value once per orchestrator at default verbosity.
 */
uint64_t
parallel_unit_split_min_size(struct sftp_parallel *p)
{
	uint64_t bytes;
	const char *source;

	if (p->cfg.range_split_min_mb > 0) {
		bytes = (uint64_t)p->cfg.range_split_min_mb * 1024ULL * 1024ULL;
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
	if (logged_for != p) {
		/* Config echo - debug only; the user set (or defaulted) this. */
		debug("range-split threshold = %llu MiB (source: %s)",
		    (unsigned long long)(bytes / (1024ULL*1024ULL)),
		    source);
		logged_for = p;
	}
	return bytes;
}


static struct sftp_work_unit *
make_download_range_unit(const char *remote_path, const char *local_path,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op            = SFTP_OP_DOWNLOAD_RANGE;
	u->src_path      = xstrdup(remote_path);
	u->dst_path      = xstrdup(local_path);
	u->size          = range_length;
	u->range_offset  = range_offset;
	u->range_length  = range_length;
	u->range_tracker = tracker;
	return u;
}

/*
 * Pre-create remote file at the correct size, then split the local file
 * into num_ranges byte ranges and submit one SFTP_OP_UPLOAD_RANGE work unit
 * per range.  The pre-creation step (open+setstat+close) is synchronous on
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
submit_upload_ranges(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode,
    off_t range_size, int num_ranges)
{
	int i, effective_ranges = 0;
	struct sftp_range_tracker *tracker = NULL;

	/* Lazy creation: the file is created by the first worker that
	 * dispatches a range for it (parallel_unit_ensure_file), so an
	 * interrupted transfer leaves no empty placeholders.  Fail fast
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
	 * knows the exact number of completions to wait for.  Mirrors the
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

	/* Upload: remote file is the target, local file is the source.  Tag the
	 * tracker for post-transfer verify when HPNVerifyTransfer is on, so the
	 * last range to finalize runs the whole-file integrity check (range
	 * units do not pass through execute_unit's whole-file verify). */
	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_REMOTE, remote_path, /*src=*/local_path,
	    /*verify=*/p->cfg.verify_transfer, p->cfg.writers_per_inode_cap);

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
		if (parallel_unit_submit(p, ru) != 0) {
			/* Under an abort the refusal is expected fallout
			 * (queue is shut), not a fault - keep it quiet. */
			if (p->abort_flag)
				debug("submit range %d of \"%s\" refused "
				    "(abort in progress)", i, local_path);
			else
				error("submit range %d of \"%s\" failed",
				    i, local_path);
			/* Synthesise failures for ranges we never submitted
			 * so the tracker reaches remaining=0 and removes the
			 * (now-corrupt) remote file.  NULL worker is fine -
			 * the REMOTE branch logs loudly if it can't remove.
			 *
			 * Safety: see the matching download-side comment in
			 * submit_download_range_split - total finalize count
			 * across workers + this loop is bounded by
			 * effective_ranges, so if our final call frees the
			 * tracker, the loop bound prevents re-dereference. */
			int unsent;
			for (unsent = i; unsent < effective_ranges; unsent++)
				(void)parallel_unit_tracker_finalize(tracker, 1, NULL);
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
submit_download_ranges(struct sftp_parallel *p,
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
	 * exact number of completions to wait for.  A trailing range may be
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
	    /*verify=*/p->cfg.verify_transfer, p->cfg.writers_per_inode_cap);

	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		struct sftp_work_unit *ru = make_download_range_unit(remote_path,
		    local_path, offset, length, tracker);
		/* Record the range geometry for the range-granular verify.  Download
		 * tees no source hash, so valid stays 0 and the verify reads the
		 * dest range back; only off/len are needed here. */
		if (ru != NULL && tracker->vslots != NULL) {
			tracker->vslots[i].off = (u_int64_t)offset;
			tracker->vslots[i].len = (u_int64_t)length;
		}
		if (parallel_unit_submit(p, ru) != 0) {
			/* Under an abort the refusal is expected fallout
			 * (queue is shut), not a fault - keep it quiet. */
			if (p->abort_flag)
				debug("submit download range %d of \"%s\" "
				    "refused (abort in progress)",
				    i, remote_path);
			else
				error("submit download range %d of \"%s\" "
				    "failed", i, remote_path);
			/* Synthesise failures for ranges we never submitted
			 * so the tracker reaches remaining=0 and unlinks the
			 * corrupt local file.  Without this the tracker
			 * leaks and the file is silently left behind.  No
			 * worker context here, so pass NULL - local target
			 * uses unlink() and doesn't need it.
			 *
			 * Safety: workers finalize at most `i` times (they
			 * only received ranges 0..i-1); this loop adds
			 * exactly (effective_ranges - i) more.  Total ≤
			 * effective_ranges, so if our final iteration is the
			 * one that drops remaining to 0 and frees the
			 * tracker, the loop condition `unsent <
			 * effective_ranges` fails immediately after - we
			 * never re-dereference `tracker`.  Scan-build flags
			 * this as a potential UAF because it can't see the
			 * X ≤ i worker-finalize invariant. */
			int unsent;
			for (unsent = i; unsent < effective_ranges; unsent++)
				(void)parallel_unit_tracker_finalize(tracker, 1, NULL);
			return -1;
		}
	}
	return 0;
}

static int
submit_download_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode)
{
	struct sftp_fs_info info;
	off_t range_size;
	int num_ranges, max_ranges;

	/* Range splitting requires a known file size.  Callers always pass it:
	 *   - recursive walk      - from the SFTP directory listing
	 *   - upload              - from the local stat
	 *   - process_get (sftp.c) - from the glob attrib cache (free, since
	 *                            glob already stat'd via fudge_stat), with
	 *                            an explicit stat as defensive fallback.
	 * If size is still zero here (very small file or unknown), fall back
	 * to whole-file. */
	if (file_size <= 0)
		goto whole_file;

	/* Static-floor fast path: files clearly below any plausible
	 * threshold can short-circuit without paying for the fs-info RTT. */
	if ((uint64_t)file_size < RANGE_SPLIT_MIN_SIZE_FLOOR)
		goto whole_file;

	{
		uint64_t min_split =
		    parallel_unit_split_min_size(p);
		if ((uint64_t)file_size < min_split)
			goto whole_file;
	}

	/* Diagnostic / testing escape hatch: HPN_NO_RANGE_SPLIT=1 in the
	 * environment forces the whole-file path so we can compare pure
	 * multi-file parallelism (one worker per file) against the
	 * range-split path on the same workload. */
	{
		/* ENV-VAR HPN_NO_RANGE_SPLIT - developer-only: kill switch for
		 * range-splitting (force whole-file upload).  A/B test and
		 * diagnostic only; not user-facing. */
		const char *no_split = getenv("HPN_NO_RANGE_SPLIT");
		if (no_split && *no_split && *no_split != '0')
			goto whole_file;
	}

	/* Range COUNT = file_size / floor.  The floor (parallel_unit_split_min_size,
	 * default 2 GiB, -M override) is the single knob and governs range SIZE.
	 * No count cap: the old min(by_size, num_streams*RANGE_CHUNK_MULTIPLIER)
	 * ceiling forced absurd ranges on big files (a 1.5 TB file became 32 x
	 * 46 GB), so it's removed - let the floor decide. */
	max_ranges = (int)(file_size / parallel_unit_split_min_size(p));
	if (max_ranges < 2)
		goto whole_file;

	/* Same rationale as submit_upload_maybe_split: stripe-aligned when geometry
	 * is available, plain file_size/num_ranges otherwise. */
	int have_stripe = get_cached_fs_info(p, conn, remote_path, &info);
	num_ranges = max_ranges;
	if (num_ranges < 2)
		goto whole_file;

	{
		off_t per_range = (file_size + num_ranges - 1) / num_ranges;
		if (have_stripe && info.stripe_size > 0) {
			off_t stripe = (off_t)info.stripe_size;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		} else {
			/* TEMP (pending fs-info stripe fix): fs-info returned no
			 * stripe, but the Lustre stripe here is 1 MiB - align
			 * ranges to it so range offsets stay page-aligned and the
			 * server's O_DIRECT helper engages instead of silently
			 * falling back to buffered.  Revert to plain per_range
			 * once fs-info reports stripe geometry (have_stripe). */
			off_t stripe = 1048576;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		}
	}

	if (submit_download_ranges(p, remote_path, local_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* Pre-creation failed - fall back to whole-file. */

 whole_file:
	return parallel_unit_submit(p, make_unit(SFTP_OP_DOWNLOAD, remote_path, local_path,
	    file_size, mode));
}

/*
 * Decide whether and how to range-split a large file, then either submit
 * range units (via submit_upload_ranges) or fall back to a whole-file unit.
 *
 * Two range-split modes:
 *   - Stripe-aligned: when hpn-fs-info reports valid Lustre/GPFS stripe
 *     geometry, each range is rounded up to a stripe boundary so adjacent
 *     ranges target different OSTs.
 *   - Plain: when no stripe info is available (ext4/xfs/NFS/etc.), ranges
 *     are simply file_size / num_ranges.  The server pwrite()s into a
 *     pre-allocated file; whether the underlying FS actually parallelises
 *     those writes is filesystem-dependent, but exercised in practice on
 *     ext4 (juliet) without measurable regression vs. whole-file.
 */
static int
submit_upload_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode)
{
	struct sftp_fs_info info;
	off_t range_size;
	int num_ranges, max_ranges;

	/* Static-floor fast path: avoid the fs-info RTT for clearly
	 * too-small files. */
	if ((uint64_t)file_size < RANGE_SPLIT_MIN_SIZE_FLOOR)
		goto whole_file;

	{
		uint64_t min_split =
		    parallel_unit_split_min_size(p);
		if ((uint64_t)file_size < min_split)
			goto whole_file;
	}

	/* HPN_NO_RANGE_SPLIT=1 escape hatch, mirroring submit_upload_maybe_split. */
	{
		/* ENV-VAR HPN_NO_RANGE_SPLIT - developer-only: kill switch for
		 * range-splitting (same as upload-side use, download path). */
		const char *no_split = getenv("HPN_NO_RANGE_SPLIT");
		if (no_split && *no_split && *no_split != '0')
			goto whole_file;
	}

	/* Range count = file_size / floor; no count cap (see submit_upload_maybe_
	 * split for the rationale - the old num_streams*RANGE_CHUNK_MULTIPLIER
	 * ceiling forced absurd ranges on big files).  Floor is the single knob. */
	max_ranges = (int)(file_size / parallel_unit_split_min_size(p));
	if (max_ranges < 2)
		goto whole_file;

	/* fs-info costs one RTT on the control connection.  Cache the
	 * answer per orchestrator (cached on p): the destination filesystem
	 * does not change within a transfer, and querying every file at high
	 * RTT starves the workers. */
	/* When stripe geometry is available (Lustre/GPFS), align each range
	 * to a stripe boundary so adjacent ranges target different OSTs.
	 * Otherwise (ext4/xfs/NFS/etc., where sftp_fs_info returned no stripe
	 * data), fall back to plain file_size/num_ranges chunks.  The server
	 * pwrite()s into a pre-allocated file; whether the underlying FS
	 * actually parallelises those writes is filesystem-dependent. */
	int have_stripe = get_cached_fs_info(p, conn, remote_path, &info);
	num_ranges = max_ranges;
	if (num_ranges < 2)
		goto whole_file;

	{
		off_t per_range = (file_size + num_ranges - 1) / num_ranges;
		if (have_stripe && info.stripe_size > 0) {
			off_t stripe = (off_t)info.stripe_size;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		} else {
			/* TEMP (pending fs-info stripe fix): fs-info returned no
			 * stripe, but the Lustre stripe here is 1 MiB - align
			 * ranges to it so range offsets stay page-aligned and the
			 * server's O_DIRECT helper engages instead of silently
			 * falling back to buffered.  Revert to plain per_range
			 * once fs-info reports stripe geometry (have_stripe). */
			off_t stripe = 1048576;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		}
	}

	if (submit_upload_ranges(p, conn, local_path, remote_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* Pre-creation failed - fall back to whole-file. */

 whole_file:
	return parallel_unit_submit(p, make_unit(SFTP_OP_UPLOAD, local_path, remote_path,
	    file_size, mode));
}
