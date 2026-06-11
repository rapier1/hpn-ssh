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
	free(u->src_path);
	free(u->dst_path);
	/* range_tracker is shared across sibling range units; never freed
	 * by parallel_unit_free.  See parallel_unit_tracker_finalize for ownership rules. */
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
    int writer_cap)
{
	struct sftp_range_tracker *t = xcalloc(1, sizeof(*t));
	pthread_mutex_init(&t->mu, NULL);
	t->total      = total;
	t->remaining  = total;
	t->any_failed = 0;
	t->target     = target;
	t->path       = xstrdup(path);
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
	if (t->active_writers < t->writer_cap)
		t->active_writers++;
	else
		ok = 0;
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
	}
	pthread_mutex_destroy(&t->mu);
	free(t->path);
	free(t);
	return incomplete;
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
	return 0;
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

	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_REMOTE, remote_path, p->cfg.writers_per_inode_cap);

	/* Submit one SFTP_OP_UPLOAD_RANGE work unit per range. */
	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (parallel_unit_submit(p, parallel_unit_make_range(local_path, remote_path,
		    offset, length, tracker)) != 0) {
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

	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_LOCAL, local_path, p->cfg.writers_per_inode_cap);

	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (parallel_unit_submit(p, make_download_range_unit(remote_path, local_path,
		    offset, length, tracker)) != 0) {
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
