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
 * Initialise a SSH filexfer connection. Returns NULL on error or
 * a pointer to a initialized sftp_conn struct on success.
 */
struct sftp_conn *sftp_init(int, int, u_int, u_int, uint64_t);
void sftp_free(struct sftp_conn *);
void sftp_set_live_counter(struct sftp_conn *, volatile uint64_t *);

/* Returns non-zero if the connection suffered an unrecoverable I/O error.
 * Workers should check this after a failed transfer and exit their loop. */
int sftp_conn_is_dead(struct sftp_conn *);

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
 * if 'pflag' is set
 */
int sftp_download(struct sftp_conn *, const char *, const char *, Attrib *,
    int, int, int, int);

/*
 * Recursively download 'remote_directory' to 'local_directory'. Preserve
 * times if 'pflag' is set
 */
int sftp_download_dir(struct sftp_conn *, const char *, const char *, Attrib *,
    int, int, int, int, int, int);

/*
 * Upload 'local_path' to 'remote_path'. Preserve permissions and times
 * if 'pflag' is set
 */
int sftp_upload(struct sftp_conn *, const char *, const char *,
    int, int, int, int);

/*
 * Per-file descriptor for sftp_upload_batch.  Caller fills local_path and
 * remote_path; result is written by the function (0 = success, -1 = failure).
 */
struct sftp_upload_batch_entry {
	const char *local_path;
	const char *remote_path;
	int         result;
};

/*
 * Upload N files with pipelined SSH_FXP_OPEN and SSH_FXP_CLOSE: all N
 * opens are sent in a single burst (1 RTT for all handles), files are
 * transferred sequentially, then all N closes are sent in a single burst
 * (1 RTT for all status replies). Amortises per-file open/close RTT from
 * 2*N RTTs down to 2 RTTs for the batch, which matters greatly for
 * many-small-file workloads at high latency.
 *
 * resume is not supported; all other flags apply to every entry.
 * Returns 0 if every file succeeded, -1 if any failed (check entry->result
 * for per-file status).
 */
int sftp_upload_batch(struct sftp_conn *, struct sftp_upload_batch_entry *,
    int n, int preserve_flag, int fsync_flag, int inplace_flag);

/*
 * Recursively upload 'local_directory' to 'remote_directory'. Preserve
 * times if 'pflag' is set
 */
int sftp_upload_dir(struct sftp_conn *, const char *, const char *,
    int, int, int, int, int, int);

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
int sftp_precreate(struct sftp_conn *, const char *remote_path, off_t size);

/*
 * Upload a byte range of a local file to the corresponding byte range of a
 * remote file.  The remote file must already exist at the correct size (i.e.
 * pre-created by the orchestrator).  Opens the remote file with O_WRONLY only
 * (no O_CREAT, no O_TRUNC) so concurrent range workers don't clobber each other.
 *
 * local_path    — source file on the local filesystem
 * remote_path   — destination file on the remote server
 * range_offset  — byte offset in both files where this range starts
 * range_length  — number of bytes to transfer
 *
 * Returns 0 on success, -1 on error.
 */
int sftp_upload_range(struct sftp_conn *, const char *local_path,
    const char *remote_path, off_t range_offset, off_t range_length);

/*
 * Download a byte range of a remote file into the corresponding byte range
 * of a local file.  The local file must already exist at the correct size
 * (pre-created by the orchestrator).  Opens the local file with O_WRONLY
 * only (no O_CREAT, no O_TRUNC) so concurrent range workers don't clobber
 * each other.
 *
 * remote_path   — source file on the remote server
 * local_path    — destination file on the local filesystem
 * range_offset  — byte offset in both files where this range starts
 * range_length  — number of bytes to transfer
 *
 * Returns 0 on success, -1 on error.
 */
int sftp_download_range(struct sftp_conn *, const char *remote_path,
    const char *local_path, off_t range_offset, off_t range_length);

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
