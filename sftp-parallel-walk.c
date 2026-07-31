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
#include "sftp-lustre-client.h"     /* maybe_apply_lustre_layout{,_local} */
#include "sftp-parallel.h"
#include "xmalloc.h"		/* xcalloc for the deferred dir-attr list */
#include "sftp-hpn-client.h"	/* shared dir helpers */
#include "sftp-parallel-internal.h"	/* parallel_verify_prefix_register */

/*
 * Maximum directory recursion depth.  Deeper trees are refused with a
 * walker failure rather than risking stack exhaustion.
 */
#define PARALLEL_MAX_DIR_DEPTH 64

/* Lazy accessor for the deferred directory-attribute list (applied at
 * the end of sftp_parallel_wait; see sftp-parallel-internal.h). */
static struct sftp_hpn_dirattr_list *
parallel_dirattrs(struct sftp_parallel *p, struct sftp_conn *conn)
{
	if (p->dirattrs == NULL)
		p->dirattrs = xcalloc(1, sizeof(*p->dirattrs));
	p->dirattrs_conn = conn;
	return p->dirattrs;
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
	Attrib a;
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
	sftp_parallel_set_walker_phase(p, SFTP_WKP_MKDIR);
	/* HPN: shared helper (same one the serial walk uses); final
	 * attrs are deferred until every unit has drained. */
	if (sftp_hpn_ensure_remote_dir(conn, dst, &a, &created) != 0) {
		sftp_parallel_walker_record_failure(p, src,
		    "cannot create or access destination directory");
		return -1;
	}

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
	sftp_parallel_set_walker_phase(p, SFTP_WKP_ENUM);
	while (((dp = readdir(dirp)) != NULL) &&
	    !sftp_parallel_is_aborting(p)) {
		const char *filename = dp->d_name;
		sftp_parallel_set_walker_phase(p, SFTP_WKP_ENUM);
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
			sftp_parallel_set_walker_phase(p, SFTP_WKP_SUBMIT);
			if (sftp_parallel_submit_upload(p, conn, new_src,
			    new_dst, sb.st_size, sb.st_mode, resume,
			    verify) != 0) {
				/* An aborting fleet refuses submissions by
				 * design; record the honest cause and stay
				 * quiet - flush prints the interrupt summary. */
				if (sftp_parallel_is_aborting(p)) {
					debug("submit \"%s\" refused "
					    "(abort in progress)", new_src);
					sftp_parallel_walker_record_failure(p,
					    new_src, "interrupted");
				} else {
					error("submit \"%s\" -> \"%s\" failed",
					    new_src, new_dst);
					sftp_parallel_walker_record_failure(p,
					    new_src, "submit failed");
				}
				ret = -1;
			}
			/* file counting happens at the submit chokepoint
			 * (sftp_parallel_submit_upload), which also covers
			 * the direct and glob callers */
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
		sftp_hpn_dirattrs_defer_remote(parallel_dirattrs(p, conn),
		    dst, &a);

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
	/* Register this command's roots as prefixes so whole-file verify items
	 * store paths relative to them (upload: local root = src, remote = dst).
	 * Gated on the orchestrator's verify_transfer (same flag the park checks);
	 * the per-command `verify` arg is not reliably set for putv. */
	if (p->cfg.verify_transfer) {
		parallel_verify_prefix_register(p, src);
		parallel_verify_prefix_register(p, dst);
	}
	{
		int rc = parallel_upload_walk(p, conn, src, dst, 0, resume,
		    verify);
		sftp_parallel_set_walker_phase(p, SFTP_WKP_DONE);
		return rc;
	}
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
	/* HPN: shared helper; final mode/times deferred until drain. */
	if (sftp_hpn_ensure_local_dir(dst, dirattrib, &mode, &tmpmode) != 0) {
		sftp_parallel_walker_record_failure(p, dst,
		    "cannot create local directory");
		return -1;
	}
	/* Download parity: give the local destination directory the same
	 * Lustre default layout uploads get on the remote side, so files
	 * created under it inherit a parallel-friendly stripe. */
	maybe_apply_lustre_layout_local(p, conn, dst);
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
				/* Mirror of the upload walker: an aborting
				 * fleet refuses submissions by design. */
				if (sftp_parallel_is_aborting(p)) {
					debug("submit download \"%s\" refused "
					    "(abort in progress)", new_src);
					sftp_parallel_walker_record_failure(p,
					    new_src, "interrupted");
				} else {
					error("submit download \"%s\" -> "
					    "\"%s\" failed", new_src, new_dst);
					sftp_parallel_walker_record_failure(p,
					    new_src, "submit failed");
				}
				ret = -1;
			}
			/* file counting happens at the submit chokepoint
			 * (sftp_parallel_submit_download) - see the upload
			 * walker */
		} else {
			/* Non-regular remote entry: SFTP cannot transfer
			 * these.  By-design skip; not a loss of user data. */
			logit("download \"%s\": not a regular file", new_src);
		}
	}
	free(new_dst);
	free(new_src);

	{
		Attrib da = *dirattrib;

		if (!preserve_flag)
			da.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
		if (preserve_flag || mode != tmpmode)
			sftp_hpn_dirattrs_defer_local(
			    parallel_dirattrs(p, conn), dst, mode,
			    tmpmode, &da);
	}

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
	/* Register this command's roots as prefixes (download: local root = dst,
	 * remote = src).  Gated on verify_transfer (same flag the park checks). */
	if (p->cfg.verify_transfer) {
		parallel_verify_prefix_register(p, dst);
		parallel_verify_prefix_register(p, src);
	}
	{
		int rc = parallel_download_walk(p, conn, src, dst, 0, NULL,
		    resume, verify);
		sftp_parallel_set_walker_phase(p, SFTP_WKP_DONE);
		return rc;
	}
}
