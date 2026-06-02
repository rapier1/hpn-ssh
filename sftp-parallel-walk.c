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
 * sftp-parallel-walk.c - recursive directory walkers (Approach B) for the
 * parallel-streams orchestrator.  Split out of sftp-parallel.c during the
 * 18.10 cleanup pass.
 *
 * The walker runs on the producer (caller) thread and uses the control
 * connection (`conn`) for metadata operations: mkdir on the destination
 * tree, readdir/stat for downloads.  Regular files are handed to the
 * orchestrator via sftp_parallel_submit_upload / submit_download; the
 * workers transfer them in parallel while the walker continues
 * descending.  The caller is expected to call sftp_parallel_wait after
 * the walker returns.
 *
 * Mirrors the structure of upload_dir_internal / download_dir_internal in
 * sftp-client.c.  Symlinks honour follow_link_flag from the
 * orchestrator's config; non-regular files are skipped with a warning
 * (matching legacy SFTP behaviour).
 *
 * Boundary: struct sftp_parallel is opaque here.  Access goes through:
 *   sftp_parallel_preserve_flag()
 *   sftp_parallel_follow_link_flag()
 *   sftp_parallel_is_aborting()
 *   sftp_parallel_submit_upload()
 *   sftp_parallel_submit_download()
 *   sftp_parallel_walker_record_failure()
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "utf8.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"  /* sftp_conn_{lustre_stripe_count,layout_set_declined} */
#include "sftp-hpn-client.h"        /* sftp_hpn_set_file_layout */
#include "sftp-hpn-server.h"        /* HPN_FILE_LAYOUT_* */
#include "sftp-parallel.h"

/*
 * Maximum directory recursion depth.  Deeper trees are refused with a
 * walker failure rather than risking stack exhaustion.
 */
#define PARALLEL_MAX_DIR_DEPTH 64

/*
 * HPNLustreStripeCount (EXPERIMENTAL): one-shot helper run at the top of
 * the upload walker.  Queries the destination directory's filesystem via
 * hpn-fs-info; if it's Lustre and the current stripe count is below the
 * desired value, asks the server to apply the new stripe count via
 * hpn-file-layout.  Subsequent files created in the directory (including
 * those extracted from bundles) inherit the layout.
 *
 * Silent on every non-Lustre destination - operators of non-Lustre sites
 * see nothing change.  On Lustre destinations the actual stripe-set
 * action emits one INFO line per directory modified.  Server-side
 * failure (EPERM, controlled OST pools) emits one WARN line and latches
 * conn->hpn->layout_set_declined so subsequent calls short-circuit.
 *
 * Called only when parallel mode is engaged (-j N with N >= 2); skipped
 * on single-stream transfers.
 */
void
maybe_apply_lustre_layout(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *dst)
{
	struct sftp_fs_info info;
	int desired;
	int configured;
	int n_workers;
	uint32_t applied = 0;
	int rc;

	if (p == NULL || conn == NULL || dst == NULL)
		return;
	if (sftp_conn_layout_set_declined(conn))
		return;  /* prior failure on this conn - short-circuit */

	configured = sftp_conn_lustre_stripe_count(conn);
	if (configured == 0)
		return;  /* HPNLustreStripeCount=0 → feature disabled */

	n_workers = sftp_parallel_num_streams(p);
	if (n_workers < 2)
		return;  /* not in parallel mode */

	if (!sftp_conn_has_file_layout(conn))
		return;  /* server is too old or built without it */

	/* desired = explicit count if HPNLustreStripeCount was set; else -j N */
	desired = (configured > 0) ? configured : n_workers;

	if (sftp_fs_info(conn, dst, &info) != 0)
		return;  /* server lacks hpn-fs-info, or query failed */
	if (strcmp(info.fs_type, "lustre") != 0)
		return;  /* not a Lustre destination */
	if (info.stripe_count >= (uint32_t)desired) {
		debug_f("Lustre auto-stripe: \"%s\" already at stripe_count=%u "
		    "(desired %d); no change", dst, info.stripe_count, desired);
		return;
	}

	rc = sftp_hpn_set_file_layout(conn, dst, (u_int32_t)desired, &applied);
	switch (rc) {
	case HPN_FILE_LAYOUT_OK:
		logit("Lustre auto-stripe (experimental): \"%s\" "
		    "stripe_count %u -> %u", dst, info.stripe_count, applied);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug_f("Lustre auto-stripe: \"%s\" reports not on a "
		    "layout-capable filesystem despite fs-info=lustre; "
		    "skipping further calls on this connection", dst);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("Lustre auto-stripe (experimental): \"%s\": permission "
		    "denied; layout will not be set for the rest of this "
		    "transfer.  Disable with HPNLustreStripeCount=0.", dst);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	default:
		logit("Lustre auto-stripe (experimental): \"%s\": layout set "
		    "failed (status %d); layout will not be set for the rest "
		    "of this transfer.", dst, rc);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	}
}

static int
parallel_upload_walk(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int depth, int resume, int verify)
{
	int created = 0, ret = 0;
	DIR *dirp;
	struct dirent *dp;
	char *new_src = NULL, *new_dst = NULL;
	struct stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;
	int preserve_flag    = sftp_parallel_preserve_flag(p);
	int follow_link_flag = sftp_parallel_follow_link_flag(p);

	if (depth >= PARALLEL_MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		sftp_parallel_walker_record_failure(p, src,
		    "max directory depth exceeded");
		return -1;
	}
	if (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		sftp_parallel_walker_record_failure(p, src, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		sftp_parallel_walker_record_failure(p, src, "not a directory");
		return -1;
	}

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	if (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	if (sftp_mkdir(conn, dst, &a, 0) == 0) {
		created = 1;
	} else {
		if (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			return -1;
		if (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			return -1;
		}
	}
	a.perm = saved_perm;

	/*
	 * Now that the destination directory exists, try to bump its Lustre
	 * stripe count if HPNLustreStripeCount asks for one wider than the
	 * current default.  Silent + no-op on non-Lustre destinations, on
	 * non-parallel transfers, and after the first failure on the conn
	 * (the helper latches conn->hpn->layout_set_declined).  Files
	 * subsequently created in this directory (worker writes, bundle
	 * extraction, walker children) inherit the new layout.  Runs on
	 * both freshly-created and pre-existing destination dirs by design
	 * - see HPNLustreStripeCount in hpnssh_config(5) for opt-out.
	 */
	maybe_apply_lustre_layout(p, conn, dst);

	if ((dirp = opendir(src)) == NULL) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		sftp_parallel_walker_record_failure(p, src, strerror(errno));
		return -1;
	}
	while (((dp = readdir(dirp)) != NULL) &&
	    !sftp_parallel_is_aborting(p)) {
		const char *filename = dp->d_name;
		if (dp->d_ino == 0) {
			/* Filesystem race / oddity (entry marked in-use but
			 * has no inode).  Skip; not user data. */
			debug_f("skipping \"%s/%s\" with d_ino == 0",
			    src, filename);
			continue;
		}
		if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			continue;
		free(new_dst); free(new_src);
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		if (lstat(new_src, &sb) == -1) {
			error("local lstat \"%s\": %s", new_src,
			    strerror(errno));
			sftp_parallel_walker_record_failure(p, new_src,
			    strerror(errno));
			ret = -1;
			continue;
		}
		if (S_ISLNK(sb.st_mode)) {
			if (!follow_link_flag) {
				/* Skipping symlink is the user's explicit
				 * choice (no -L); not a loss. */
				logit("%s: not a regular file", filename);
				continue;
			}
			if (stat(new_src, &sb) == -1) {
				error("local stat \"%s\": %s", new_src,
				    strerror(errno));
				sftp_parallel_walker_record_failure(p, new_src,
				    strerror(errno));
				ret = -1;
				continue;
			}
		}
		if (S_ISDIR(sb.st_mode)) {
			if (parallel_upload_walk(p, conn, new_src, new_dst,
			    depth + 1, resume, verify) == -1)
				ret = -1;
		} else if (S_ISREG(sb.st_mode)) {
			if (sftp_parallel_submit_upload(p, conn, new_src,
			    new_dst, sb.st_size, sb.st_mode, resume,
			    verify) != 0) {
				error("submit \"%s\" -> \"%s\" failed",
				    new_src, new_dst);
				sftp_parallel_walker_record_failure(p, new_src,
				    "submit failed");
				ret = -1;
			}
		} else {
			/* Non-regular file (socket / fifo / device): SFTP
			 * cannot transfer these.  By-design skip; not a
			 * loss of user data. */
			logit("%s: not a regular file", filename);
		}
	}
	free(new_dst);
	free(new_src);

	if (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(void)closedir(dirp);
	return ret;
}

int
sftp_parallel_upload_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify)
{
	if (p == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);
	return parallel_upload_walk(p, conn, src, dst, 0, resume, verify);
}

static int
parallel_download_walk(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int depth, Attrib *dirattrib,
    int resume, int verify)
{
	int i, ret = 0;
	SFTP_DIRENT **dir_entries;
	char *new_src = NULL, *new_dst = NULL;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;
	int preserve_flag    = sftp_parallel_preserve_flag(p);
	int follow_link_flag = sftp_parallel_follow_link_flag(p);

	if (depth >= PARALLEL_MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		sftp_parallel_walker_record_failure(p, src,
		    "max directory depth exceeded");
		return -1;
	}
	if (dirattrib == NULL) {
		if (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			sftp_parallel_walker_record_failure(p, src,
			    "remote stat failed");
			return -1;
		}
		dirattrib = &ldirattrib;
	}
	if (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		sftp_parallel_walker_record_failure(p, src, "not a directory");
		return -1;
	}
	if (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	}
	if (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		sftp_parallel_walker_record_failure(p, dst, strerror(errno));
		return -1;
	}
	if (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		sftp_parallel_walker_record_failure(p, src,
		    "remote readdir failed");
		return -1;
	}

	for (i = 0; dir_entries[i] != NULL &&
	    !sftp_parallel_is_aborting(p); i++) {
		const char *filename = dir_entries[i]->filename;
		free(new_dst); free(new_src);
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);
		a = &dir_entries[i]->a;

		if (S_ISLNK(a->perm)) {
			if (!follow_link_flag) {
				/* Skipping symlink is the user's explicit
				 * choice (no -L); not a loss. */
				logit("download \"%s\": not a regular file",
				    new_src);
				continue;
			}
			if (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				error("remote stat \"%s\" failed", new_src);
				sftp_parallel_walker_record_failure(p, new_src,
				    "remote stat failed");
				ret = -1;
				continue;
			}
			a = &lsym;
		}

		if (S_ISDIR(a->perm)) {
			if (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			if (parallel_download_walk(p, conn, new_src, new_dst,
			    depth + 1, a, resume, verify) == -1)
				ret = -1;
		} else if (S_ISREG(a->perm)) {
			off_t fsize = (a->flags & SSH2_FILEXFER_ATTR_SIZE) ?
			    (off_t)a->size : 0;
			mode_t fmode = (a->flags &
			    SSH2_FILEXFER_ATTR_PERMISSIONS) ?
			    (a->perm & 07777) : 0644;
			if (sftp_parallel_submit_download(p, conn,
			    new_src, new_dst, fsize, fmode, resume,
			    verify) != 0) {
				error("submit download \"%s\" -> \"%s\" failed",
				    new_src, new_dst);
				sftp_parallel_walker_record_failure(p, new_src,
				    "submit failed");
				ret = -1;
			}
		} else {
			/* Non-regular remote entry: SFTP cannot transfer
			 * these.  By-design skip; not a loss of user data. */
			logit("download \"%s\": not a regular file", new_src);
		}
	}
	free(new_dst);
	free(new_src);

	if (preserve_flag &&
	    (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
		struct timeval tv[2];
		tv[0].tv_sec = dirattrib->atime;
		tv[1].tv_sec = dirattrib->mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (utimes(dst, tv) == -1)
			error("local set times on \"%s\": %s",
			    dst, strerror(errno));
	}
	if (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s",
		    dst, strerror(errno));

	sftp_free_dirents(dir_entries);
	return ret;
}

int
sftp_parallel_download_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify)
{
	if (p == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);
	return parallel_download_walk(p, conn, src, dst, 0, NULL, resume, verify);
}
