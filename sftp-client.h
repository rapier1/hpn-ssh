/* $OpenBSD: sftp-client.h,v 1.41 2026/03/03 09:57:25 dtucker Exp $ */

/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Client side of SSH2 filexfer protocol */

#ifndef _SFTP_CLIENT_H
#define _SFTP_CLIENT_H

typedef struct SFTP_DIRENT SFTP_DIRENT;

struct SFTP_DIRENT {
	char *filename;
	char *longname;
	Attrib a;
};

/*
 * Used for statvfs responses on the wire from the server, because the
 * server's native format may be larger than the client's.
 */
struct sftp_statvfs {
	uint64_t f_bsize;
	uint64_t f_frsize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	uint64_t f_favail;
	uint64_t f_fsid;
	uint64_t f_flag;
	uint64_t f_namemax;
};

/*
 * Filesystem information returned by the hpn-fs-info@hpnssh.org extension.
 * Used by the parallel orchestrator to align byte-range splits to Lustre/GPFS
 * stripe boundaries.  All fields zero/empty if the server does not support
 * the extension.
 */
struct sftp_fs_info {
	char     fs_type[32];   /* "lustre", "gpfs", "ext4", "xfs", etc. */
	uint64_t stripe_size;   /* bytes per stripe; 0 if not applicable */
	uint32_t stripe_count;  /* number of OSTs/stripes; 0 if not applicable */
	uint64_t block_size;    /* optimal I/O block size (always present) */
};

/* Used for limits response on the wire from the server */
struct sftp_limits {
	uint64_t packet_length;
	uint64_t read_length;
	uint64_t write_length;
	uint64_t open_handles;
};

/* print flag values */
#define SFTP_QUIET		0	/* be quiet during transfers */
#define SFTP_PRINT		1	/* list files and show progress bar */
#define SFTP_PROGRESS_ONLY	2	/* progress bar only */

/*
 * Exit code returned by hpnsftp/hpnscp when one or more files fail
 * post-transfer XXH3 verification (HPNVerifyTransfer) or the verified
 * resume gate.  The transfer is NOT aborted on a mismatch - the file is
 * re-transferred (resume) or flagged (verify) and a summary is printed -
 * but the process exits non-zero so automation can detect it.  57 = a
 * Pittsburgh/PSC nod (Heinz 57); chosen to avoid the existing 0/1/255
 * exit codes and the BSD sysexits block (64-78).
 */
#define SFTP_EX_VERIFY_FAILED	57

/*
 * Single canonical message for "the remote can't do verified resume".
 * Referenced by sftp_upload, sftp_download, and the parallel submit path
 * so every verified-resume fatal reads identically regardless of mode or
 * direction.  Verified resume requires the server's hpn-check-file@hpnssh.org
 * extension; when it is absent we fail loudly rather than silently degrade
 * to an unverified resume or a full re-transfer behind the user's back.
 */
#define RESUME_INCOMPAT_MSG \
	"The remote is not compatible with verified resume. " \
	"Please upgrade the remote to at least HPN-SSH 19.0.0"

/*
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
struct sftp_conn *sftp_init(int, int, u_int, u_int, uint64_t);
void sftp_free(struct sftp_conn *);
void sftp_set_live_counter(struct sftp_conn *, volatile uint64_t *);
void sftp_set_yield_flag(struct sftp_conn *, volatile int *);
/* HPN adaptive upload pacing master switch (-X Pacing=; default on).
 * Implemented in sftp-hpn-client.c; declared here so sftp.c/scp.c option
 * parsing reaches it without the full HPN header. */
void sftp_hpn_pace_set_enabled(int);

/* Returns non-zero if the connection suffered an unrecoverable I/O error.
 * Workers should check this after a failed transfer and exit their loop. */
int sftp_conn_is_dead(struct sftp_conn *);

/* HPN: non-zero if a PERMISSION_DENIED reply was seen since the last
 * clear; clear resets it.  Used to make a refused op non-retryable. */
int sftp_conn_saw_perm_denied(struct sftp_conn *);
void sftp_conn_clear_perm_denied(struct sftp_conn *);
/* HPN: latch the sticky permission-denied flag (the internal set-sites). */
void sftp_conn_set_perm_denied(struct sftp_conn *);

/* HPN: a refused op was a -P/-p request-policy denial (server-tagged), not a
 * filesystem error.  check_policy_tag reads the SSH_FXP_STATUS error-message
 * just after the status code and latches the flag if it carries the tag. */
int sftp_conn_saw_policy_denied(struct sftp_conn *);
void sftp_conn_clear_policy_denied(struct sftp_conn *);
void sftp_conn_check_policy_tag(struct sftp_conn *, struct sshbuf *);

/*
 * Mark a connection as dead with prominent diagnostic logging, without
 * terminating the process. Used to replace fatal() in code paths that
 * may run inside a parallel-streams worker, where fatal() would crash
 * the entire orchestrator.
 *
 * After this call, sftp_conn_is_dead() returns true and subsequent RPC
 * calls on this connection short-circuit to error returns. Callers must
 * still propagate the failure via their own return value (or rely on
 * the worker thread's per-unit conn->dead post-check to abandon the
 * unit and exit so the watchdog can respawn).
 */
void sftp_conn_die(struct sftp_conn *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Returns non-zero if a protocol-level violation was detected (ID mismatch,
 * unexpected packet type). Distinct from sftp_conn_is_dead: indicates possible
 * MITM attack or serious server corruption. The parallel orchestrator aborts
 * the entire transfer on violation rather than retrying the affected worker. */
int sftp_conn_is_protocol_violation(struct sftp_conn *);

u_int sftp_proto_version(struct sftp_conn *);

/*
 * HPN: server-advertised per-user parallel-worker cap.
 * -1 = not advertised (stock/non-HPN server); 0 = advertised, no cap;
 * N>0 = advertised cap.  Used by the orchestrator to clamp -j.
 */
int sftp_hpn_max_workers_cap(struct sftp_conn *);

/* Query server limits */
int sftp_get_limits(struct sftp_conn *, struct sftp_limits *);

/* Close file referred to by 'handle' */
int sftp_close(struct sftp_conn *, const u_char *, u_int);

/* Read contents of 'path' to NULL-terminated array 'dir' */
int sftp_readdir(struct sftp_conn *, const char *, SFTP_DIRENT ***);

/* Frees a NULL-terminated array of SFTP_DIRENTs (eg. from sftp_readdir) */
void sftp_free_dirents(SFTP_DIRENT **);

/* Delete file 'path' */
int sftp_rm(struct sftp_conn *, const char *);

/* Create directory 'path' */
int sftp_mkdir(struct sftp_conn *, const char *, Attrib *, int);

/* Remove directory 'path' */
int sftp_rmdir(struct sftp_conn *, const char *);

/* Get file attributes of 'path' (follows symlinks) */
int sftp_stat(struct sftp_conn *, const char *, int, Attrib *);

/* Get file attributes of 'path' (does not follow symlinks) */
int sftp_lstat(struct sftp_conn *, const char *, int, Attrib *);

/* Set file attributes of 'path' */
int sftp_setstat(struct sftp_conn *, const char *, Attrib *);

/* Set file attributes of open file 'handle' */
int sftp_fsetstat(struct sftp_conn *, const u_char *, u_int, Attrib *);

/* Set file attributes of 'path', not following symlinks */
int sftp_lsetstat(struct sftp_conn *conn, const char *path, Attrib *a);

/* Canonicalise 'path' - caller must free result */
char *sftp_realpath(struct sftp_conn *, const char *);

/* Canonicalisation with tilde expansion (requires server extension) */
char *sftp_expand_path(struct sftp_conn *, const char *);

/* Returns non-zero if server can tilde-expand paths */
int sftp_can_expand_path(struct sftp_conn *);

/* Get statistics for filesystem hosting file at "path" */
int sftp_statvfs(struct sftp_conn *, const char *, struct sftp_statvfs *, int);

/* Rename 'oldpath' to 'newpath' */
int sftp_rename(struct sftp_conn *, const char *, const char *, int);

/* Copy 'oldpath' to 'newpath' */
int sftp_copy(struct sftp_conn *, const char *, const char *);

/* Link 'oldpath' to 'newpath' */
int sftp_hardlink(struct sftp_conn *, const char *, const char *);

/* Rename 'oldpath' to 'newpath' */
int sftp_symlink(struct sftp_conn *, const char *, const char *);

/* Call fsync() on open file 'handle' */
int sftp_fsync(struct sftp_conn *conn, u_char *, u_int);

/*
 * Download 'remote_path' to 'local_path'. Preserve permissions and times
 * if 'pflag' is set.
 *
 * Trailing ints are (preserve, resume, fsync, inplace, verify): 'verify' is
 * LAST here, unlike sftp_upload / sftp_upload_dir / sftp_download_dir where
 * it follows 'resume'.  All args are plain ints, so a mis-ordered call
 * compiles silently - do not copy another transfer function's argument
 * order onto sftp_download().
 */
int sftp_download(struct sftp_conn *, const char *, const char *, Attrib *,
    int, int, int, int, int);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set.  The 'verify' arg (after resume) mirrors
 * sftp_upload_dir: when set, each file is resumed with hash verification
 * (fatal if the server lacks hpn-check-file@hpnssh.org).
 */
int sftp_download_dir(struct sftp_conn *, const char *, const char *, Attrib *,
    int, int, int, int, int, int, int);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set. If 'verify' is set, the server MUST support the
 * hpn-check-file@hpnssh.org extension: the overlapping prefix is
 * hash-compared before deciding whether to resume or restart. If the
 * extension is unavailable this is fatal (RESUME_INCOMPAT_MSG) - there is
 * no silent fallback to size-only resume. Plain (verify=0) resume is
 * size-only and works against any server.
 */
int sftp_upload(struct sftp_conn *, const char *, const char *,
    int, int, int, int, int);

/*
 * HPNVerifyTransfer post-transfer integrity check: XXH3 the full local and
 * remote file and compare.  Returns 0 = match, 1 = mismatch (corruption),
 * -1 = could not verify (server lacks hpn-check-file or I/O error).
 */

/*
 * Per-file descriptor for a pipelined upload batch.  Caller fills local_path
 * and remote_path; result is written by the function (0 = success, -1 = fail).
 */
struct sftp_upload_batch_entry {
	const char *local_path;
	const char *remote_path;
	int         result;
};

/* ── BEGIN Phase 4 gap 1: pipelined batch send/finish ──────────────────────
 *
 * Upload N files with pipelined SSH_FXP_OPEN/CLOSE (all N opens in one burst,
 * transfer sequentially, all N closes in one burst) so per-file open/close RTT
 * is amortised from 2*N down to 2 - critical for many-small-file workloads at
 * high latency.  resume is not supported; all other flags apply to every entry.
 *
 * The send/finish split lets the caller pipeline back-to-back batches: send the
 * next batch's OPENs (phase 1) while the
 * previous batch's CLOSE STATUSes are still being collected (phase 5).
 *
 *   pending = sftp_upload_batch_send(conn, entries, n, ..., prev_pending);
 *     // does phases 1, 2, 3a-d, 4 for the new batch.
 *     // if prev_pending != NULL: drains it (phase 5 of previous batch)
 *     // AFTER the new batch's phase 1, so the server-side processing of
 *     // prev's CLOSEs overlaps with this batch's OPENs on the wire.
 *     // prev_pending is freed during the drain.
 *
 *   sftp_upload_batch_finish(conn, pending);
 *     // drains the new batch's phase 5.  Free's pending.
 *
 * On error during send (connection dies, protocol violation), all entries
 * in BOTH the current batch and prev (if drain failed) are marked failed
 * and the function returns NULL.  Caller must NOT call finish on a
 * NULL pending. */
struct sftp_upload_batch_pending;

struct sftp_upload_batch_pending *sftp_upload_batch_send(
    struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, int n,
    int preserve_flag, int fsync_flag, int inplace_flag,
    struct sftp_upload_batch_pending *prev);

int sftp_upload_batch_finish(struct sftp_conn *conn,
    struct sftp_upload_batch_pending *pending);

/* ── END Phase 4 gap 1 ───────────────────────────────────────────────────── */

/* ── BEGIN Phase 5: hpn-bundle small-file streaming ──────────────────────
 *
 * Bundle upload via the `hpn-bundle-open@hpnssh.org` SFTP extension.
 * Many small files are packed into a single tar-format byte stream and
 * delivered through one OPEN / WRITE×N / CLOSE sequence - amortising the
 * per-file OPEN/CLOSE round-trip cost that limits small-file throughput
 * even after Phase 4 pipelining.
 *
 * Composes with parallel streams: each worker handles its own bundles
 * over its own SSH connection; many concurrent bundles in flight.
 *
 * Server support detected via the `hpn-bundle@hpnssh.org` extension
 * advertised in SSH_FXP_VERSION (see SFTP_EXT_HPN_BUNDLE in sftp-client.c).
 * When unsupported, caller must fall back to per-file uploads.
 *
 * See project_phase5_bundling_design.md in the memory store for the full
 * protocol and architectural notes.
 */

struct sftp_hpn_bundle_upload_entry {
	const char *local_path;
	const char *remote_path;   /* relative path inside the bundle dest */
	int         result;        /* 0 = ok; -1 = failed (set by function) */
};

/*
 * Upload N small files as a single tar stream to remote_dest_dir.  The
 * server's hpn-bundle handler extracts each file into remote_dest_dir/
 * preserving the relative path supplied in entries[i].remote_path.
 *
 * preserve_flag: when non-zero, file mode + mtime are carried in the tar
 *   header and applied on extract.  Otherwise extracted files use 0644
 *   mode and current mtime.
 * fsync_flag: when non-zero, request the server fsync each extracted
 *   file before the bundle is closed.
 *
 * Returns one of enum sftp_hpn_bundle_result.  On any non-OK return all
 * entries[].result are set to -1 (the protocol does not return per-record
 * status - whole-bundle re-queue).  The caller MUST distinguish the cause:
 * SERVER_CANT is a permanent, connection-agnostic reason (the server refused
 * the bundle or lacks the extension) and the units should be marked
 * bundle_ineligible (single-file fallback); TRANSPORT_FAILED means only THIS
 * worker's connection died mid-bundle - the units bundle fine on a healthy
 * worker, so they stay bundle-eligible and are simply re-queued.  Failure
 * values are negative so legacy `!= 0` / `< 0` checks still see failure.
 */
enum sftp_hpn_bundle_result {
	SFTP_HPN_BUNDLE_OK               =  0,
	SFTP_HPN_BUNDLE_SERVER_CANT      = -1, /* permanent: refused / no ext */
	SFTP_HPN_BUNDLE_TRANSPORT_FAILED = -2, /* transient: this conn died */
	SFTP_HPN_BUNDLE_POLICY_DENIED    = -3, /* permanent: -P/-p policy forbids
						* this whole class - abort the
						* transfer, do not fall back */
};

int sftp_hpn_bundle_upload(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_hpn_bundle_upload_entry *entries, int n,
    int preserve_flag, int fsync_flag, int writer_pool, uint64_t bundle_size);

/* True iff the server advertised the hpn-bundle@hpnssh.org extension. */
int sftp_conn_has_hpn_bundle(struct sftp_conn *conn);

/*
 * Install the resolved bundling knobs (HPNUseBundle, HPNBundleSize,
 * HPNWriterPool) on the connection for the serial-path recursive walks.
 * Without this call the connection uses the options' documented defaults
 * (bundling on, writer pool on, default bundle size).
 */
void sftp_conn_set_bundle_config(struct sftp_conn *conn, int use_bundle,
    uint64_t bundle_size, int writer_pool);

/* True iff the server advertised hpn-bundle-fetch@hpnssh.org (download). */
int sftp_conn_has_hpn_bundle_fetch(struct sftp_conn *conn);

/*
 * True iff the server advertised hpn-check-file@hpnssh.org, i.e. it can
 * answer the XXH3 hash queries that verified resume depends on.  Lets the
 * parallel submit path (which sees struct sftp_conn only as opaque) make
 * the up-front "can this remote verify?" decision in the main thread.
 */
int sftp_conn_has_hpn_check_file(struct sftp_conn *conn);

/*
 * Run the classic (single-conn) post-transfer verify phase: verify every file
 * parked by sftp_conn_verify_park during the command's transfers, recording
 * mismatches on the conn.  Call once at the end of each put/get command (the
 * single-conn analogue of the -j orchestrator's verify phase); no-op when
 * nothing was parked.
 */
void sftp_conn_verify_run_phase(struct sftp_conn *conn);

/* Number of files parked for the classic verify phase (0 in parallel mode or
 * with verify off).  Used to gate the "Verifying N file(s)..." start line. */
size_t sftp_conn_verify_pending_count(struct sftp_conn *conn);

/*
 * Drain the classic (single-conn) post-transfer verify failures recorded by
 * the verify phase.  Ownership of *out_paths and its strings transfers to the
 * caller; the conn's list resets to empty.  Mirrors
 * sftp_parallel_drain_verify_failures so the end-of-run summary + exit code
 * cover classic and parallel transfers uniformly.  Returns the count.
 */
size_t sftp_conn_drain_verify_failures(struct sftp_conn *conn,
    char ***out_paths, size_t *out_used);

/*
 * True iff the server advertised sftp-hash-range@hpnssh.org, i.e. it can
 * answer batched per-range XXH3 queries used by chunked resume to re-transfer
 * only mismatched chunks instead of the whole file.
 */
int sftp_conn_has_hash_range(struct sftp_conn *conn);

/*
 * True iff the server advertised hpn-file-layout@hpnssh.org, i.e. it can
 * apply a filesystem layout (today: Lustre stripe count) to a destination
 * directory before files land in it.  Used by HPNLustreStripeCount.
 */
int sftp_conn_has_file_layout(struct sftp_conn *conn);

/*
 * Download-side counterpart of sftp_hpn_bundle_upload.  Asks the server to
 * pack the listed `entries[].remote_path` files into a single tar stream,
 * then untars locally into each `entries[].local_path`.  Per-entry result
 * codes are written into entries[i].result (0 = ok, -1 = skipped/failed).
 *
 * Returns 0 if the bundle transaction succeeded (even if some per-entry
 * results are -1), -1 if the server refused the extension or the
 * transaction failed at the wire level (in which case every entry is
 * marked -1 and the caller should fall back to per-file downloads).
 *
 * Implementation lives in sftp-hpn-client.c.
 */
struct sftp_hpn_bundle_download_entry {
	const char *remote_path;
	const char *local_path;
	int         result;
};

int sftp_hpn_bundle_download(struct sftp_conn *conn,
    struct sftp_hpn_bundle_download_entry *entries, int n,
    int preserve_flag, int writer_pool);

/* ── END Phase 5 ─────────────────────────────────────────────────────────*/

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set. 'verify' is propagated to each file upload.
 */
int sftp_upload_dir(struct sftp_conn *, const char *, const char *,
    int, int, int, int, int, int, int);

/*
 * Download a 'from_path' from the 'from' connection and upload it to
 * to 'to' connection at 'to_path'.
 */
int sftp_crossload(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *a, int preserve_flag);

/*
 * Recursively download a directory from 'from_path' from the 'from'
 * connection and upload it to 'to' connection at 'to_path'.
 */
int sftp_crossload_dir(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *dirattrib, int preserve_flag, int print_flag,
    int follow_link_flag);

/*
 * User/group ID to name translation.
 */
int sftp_can_get_users_groups_by_id(struct sftp_conn *conn);
int sftp_get_users_groups_by_id(struct sftp_conn *conn,
    const u_int *uids, u_int nuids,
    const u_int *gids, u_int ngids,
    char ***usernamesp, char ***groupnamesp);

/*
 * Query the server for filesystem type and stripe geometry of the given path.
 * Fills *info on success; on error or if the extension is unsupported, *info
 * is zeroed (all-zeros is a safe "unknown" sentinel for callers).
 * Returns 0 on success, -1 if the extension is unsupported or the query failed.
 */
int sftp_fs_info(struct sftp_conn *, const char *path, struct sftp_fs_info *info);

/*
 * Pre-create a remote file at exactly `size` bytes (O_CREAT|O_TRUNC + setstat
 * size) so that parallel range-upload workers can subsequently open it with
 * O_WRONLY and write their byte ranges concurrently without racing on creation.
 * Returns 0 on success, -1 on error.
 */
int sftp_create_file(struct sftp_conn *, const char *remote_path, mode_t,
    int *permanent_out);

/*
 * Upload a byte range of a local file to the corresponding byte range of a
 * remote file.  The remote file must already exist at the correct size (i.e.
 * pre-created by the orchestrator).  Opens the remote file with O_WRONLY only
 * (no O_CREAT, no O_TRUNC) so concurrent range workers don't clobber each other.
 *
 * local_path    - source file on the local filesystem
 * remote_path   - destination file on the remote server
 * range_offset  - byte offset in both files where this range starts
 * range_length  - number of bytes to transfer
 * acked_out     - highwater (contiguous acked bytes) for resume-on-requeue
 * warm          - optional warm-handle cache (NULL = open+close every call,
 *                 the original behaviour).  When non-NULL and warm->handle is
 *                 already set, the open remote handle is REUSED (the caller
 *                 guarantees it is for THIS remote_path); on a clean success
 *                 the handle is left OPEN and stored back in *warm so the next
 *                 same-file range skips the close/reopen + cold-window dip at
 *                 the boundary.  On any error/yield the handle is closed and
 *                 *warm cleared.  The caller owns *warm and must close it
 *                 (sftp_close + free) when it moves to a different file or
 *                 goes idle.
 *
 * Returns 0 on success, -1 on error.
 */
struct sftp_range_warm {
	u_char *handle;       /* open remote handle, or NULL */
	size_t  handle_len;
	char   *path;         /* strdup of the remote path it is open on */
};
int sftp_upload_range(struct sftp_conn *, const char *local_path,
    const char *remote_path, off_t range_offset, off_t range_length,
    off_t *acked_out, struct sftp_range_warm *warm, uint64_t *range_hash_out);

/*
 * Download a byte range of a remote file into the corresponding byte range
 * of a local file.  The local file must already exist at the correct size
 * (pre-created by the orchestrator).  Opens the local file with O_WRONLY
 * only (no O_CREAT, no O_TRUNC) so concurrent range workers don't clobber
 * each other.
 *
 * remote_path   - source file on the remote server
 * local_path    - destination file on the local filesystem
 * range_offset  - byte offset in both files where this range starts
 * range_length  - number of bytes to transfer
 *
 * Returns 0 on success, -1 on error.
 */
int sftp_download_range(struct sftp_conn *, const char *remote_path,
    const char *local_path, off_t range_offset, off_t range_length,
    off_t *acked_out);

/* Concatenate paths, taking care of slashes. Caller must free result. */
char *sftp_path_append(const char *, const char *);

/* Make absolute path if relative path and CWD is given. Does not modify
 * original if the path is already absolute. */
char *sftp_make_absolute(char *, const char *);

/* Check if remote path is directory */
int sftp_remote_is_dir(struct sftp_conn *conn, const char *path);

/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
int sftp_globpath_is_dir(const char *pathname);

#endif
