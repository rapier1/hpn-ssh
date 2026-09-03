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
 * sftp-parallel-walk.c - recursive directory walkers for the
 * parallel-streams orchestrator.
 *
 * The walker runs on the producer (caller) thread and uses the control
 * connection (`conn`) for metadata operations: mkdir on the destination
 * tree, and enumeration of the source. Downloads enumerate through one
 * streamed discover-tree request where the server offers it and fall
 * back to recursive readdir otherwise; both replay through the same
 * sink. Regular files are handed to the orchestrator via
 * sftp_parallel_submit_upload / submit_download; the workers transfer
 * them in parallel while the walker continues descending. The caller is
 * expected to call sftp_parallel_wait after the walker returns.
 *
 * Symlinks honour follow_link_flag from the orchestrator's config;
 * non-regular files are skipped with a warning (matching legacy SFTP
 * behaviour).
 *
 * Boundary: this file includes sftp-parallel-internal.h, so struct
 * sftp_parallel is visible. It is reached directly in only two places,
 * the deferred dir-attr list in parallel_dirattrs and the config block.
 * Everything else goes through the orchestrator's sftp_parallel_*
 * functions.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>

#include "log.h"
#include "misc.h"
#include "utf8.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-lustre-client.h"     /* maybe_apply_lustre_layout{,_local} */
#include "sftp-parallel.h"
#include "xmalloc.h"		/* xcalloc for the deferred dir-attr list */
#include "sftp-hpn-client.h"	/* shared dir helpers */
#include "sftp-hpn-tree.h"	/* hpn-discover-tree fetch + records */
#include "sftp-parallel-internal.h"	/* parallel_verify_prefix_register */
#include "progressmeter.h"	/* pm_mprintf */

/*
 * Parallel upload sink for the shared upload driver
 * (sftp_upload_walk_consume). It submits each file to the worker fleet,
 * applies the Lustre layout and worker phases, defers remote dir attrs onto
 * the parallel list, and records per-entry failures on the walker. The
 * callback-table pattern is documented on struct sftp_upload_sink.
 */
struct parallel_ul_sink {
	struct sftp_upload_sink	 base;
	struct sftp_parallel	*fleet;
	struct sftp_conn	*conn;
	int	resume, verify;
};

/*
 * Parallel download sink for the shared discover-tree consumer
 * (sftp_tree_download_consume): create local dirs with Lustre-layout parity,
 * submit regular files to the worker fleet, defer directory attrs, and
 * record per-entry failures on the walker. Mirrors what parallel_download_
 * walk does per entry; the shared consumer supplies the iteration. The
 * stream is drained before the first submit (see sftp_hpn_discover_tree);
 * overlapping discovery with worker transfers is a future optimization
 * (design section 9).
 */
struct parallel_dl_sink {
	struct sftp_tree_dl_sink	 base;
	struct sftp_parallel		*fleet;
	struct sftp_conn		*conn;
	int	preserve_flag, resume, verify;
};

/* Lazy accessor for the deferred directory-attribute list (applied at
 * the end of sftp_parallel_wait; see sftp-parallel-internal.h). */
static struct sftp_hpn_dirattr_list *
parallel_dirattrs(struct sftp_parallel *fleet)
{
	if (fleet->dirattrs == NULL)
		fleet->dirattrs = xcalloc(1, sizeof(*fleet->dirattrs));
	return fleet->dirattrs;
}

static void
parallel_ul_enter_dir(struct sftp_upload_sink *sink, const char *src,
    const char *dst)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	(void)src;	/* shared signature, only the serial sink prints it */
	/* Lay out this already-created directory for Lustre before any files
	 * land in it, then enter the enumerate phase. */
	maybe_apply_lustre_layout(ctx->fleet, ctx->conn, dst);
	sftp_parallel_set_walker_phase(ctx->fleet, SFTP_WKP_ENUM);
}

static int
parallel_ul_xfer_file(struct sftp_upload_sink *sink, const char *src,
    const char *dst, const struct stat *src_sb)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	sftp_parallel_set_walker_phase(ctx->fleet, SFTP_WKP_SUBMIT);
	if (sftp_parallel_submit_upload(ctx->fleet, ctx->conn, src, dst,
	    src_sb->st_size, src_sb->st_mode, ctx->resume, ctx->verify) != 0) {
		if (sftp_parallel_is_aborting(ctx->fleet)) {
			debug("submit \"%s\" refused (abort in progress)", src);
			sftp_parallel_walker_record_failure(ctx->fleet, src,
			    "interrupted");
		} else {
			error("submit \"%s\" -> \"%s\" failed", src, dst);
			sftp_parallel_walker_record_failure(ctx->fleet, src,
			    "submit failed");
		}
		return -1;
	}
	return 0;
}

static void
parallel_ul_before_mkdir(struct sftp_upload_sink *sink)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	sftp_parallel_set_walker_phase(ctx->fleet, SFTP_WKP_MKDIR);
}

static void
parallel_ul_defer_dir(struct sftp_upload_sink *sink, const char *dst,
    const Attrib *attrs)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	sftp_hpn_dirattrs_defer_remote(parallel_dirattrs(ctx->fleet), dst,
	    attrs);
}

static void
parallel_ul_fail(struct sftp_upload_sink *sink, const char *path,
    const char *reason)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	sftp_parallel_walker_record_failure(ctx->fleet, path, reason);
}

static int
parallel_ul_aborting(struct sftp_upload_sink *sink)
{
	struct parallel_ul_sink	*ctx = (struct parallel_ul_sink *)sink;

	return sftp_parallel_is_aborting(ctx->fleet);
}

int
sftp_parallel_upload_dir(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify)
{
	struct parallel_ul_sink	 sink = {
		.base = {
			.enter_dir = parallel_ul_enter_dir,
			.xfer_file = parallel_ul_xfer_file,
			.before_mkdir = parallel_ul_before_mkdir,
			.defer_dir = parallel_ul_defer_dir,
			.fail = parallel_ul_fail,
			.aborting = parallel_ul_aborting,
		},
		.fleet = fleet,
		.conn = conn,
		.resume = resume,
		.verify = verify,
	};
	struct stat		 root_sb;
	Attrib			 root_attrs;
	int			 root_created = 0, rc;

	if (fleet == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		pm_mprintf("Entering %s\n", src);
	/* Register this command's roots as prefixes so whole-file verify items
	 * store paths relative to them (upload: local root = src, remote = dst).
	 * Gated on the orchestrator's verify_transfer (same flag the park checks);
	 * the per-command `verify` arg is not reliably set for putv. */
	if (fleet->cfg.verify_transfer) {
		parallel_verify_prefix_register(fleet, src);
		parallel_verify_prefix_register(fleet, dst);
	}
	/* Create the root destination directory before walking; deeper
	 * directories are created by their parent level's pipelined mkdir
	 * batch, so sftp_upload_walk_consume assumes dst exists. */
	if (stat(src, &root_sb) == -1 || !S_ISDIR(root_sb.st_mode)) {
		error("stat local \"%s\": not a directory", src);
		sftp_parallel_walker_record_failure(fleet, src,
		    "not a directory");
		return -1;
	}
	sftp_hpn_dir_attrs_from_stat(&root_sb,
	    sftp_parallel_preserve_flag(fleet), &root_attrs);
	if (sftp_hpn_ensure_remote_dir(conn, dst, &root_attrs,
	    &root_created) != 0) {
		sftp_parallel_walker_record_failure(fleet, dst,
		    "cannot create or access destination directory");
		return -1;
	}
	rc = sftp_upload_walk_consume(conn, src, dst, 0, HPN_WALK_MAX_DEPTH,
	    root_created, sftp_parallel_preserve_flag(fleet),
	    sftp_parallel_follow_link_flag(fleet), &sink.base);
	sftp_parallel_set_walker_phase(fleet, SFTP_WKP_DONE);
	return rc;
}

static int
parallel_dl_make_dir(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, Attrib *attrs)
{
	struct parallel_dl_sink	*ctx = (struct parallel_dl_sink *)sink;
	mode_t			 mode, tmpmode;
	Attrib			 defrd_attrs;

	(void)src;	/* parallel prints the root once at the caller, not per-dir */
	if (sftp_hpn_ensure_local_dir(dst, attrs, &mode, &tmpmode) != 0) {
		sftp_parallel_walker_record_failure(ctx->fleet, dst,
		    "cannot create local directory");
		return -1;
	}
	maybe_apply_lustre_layout_local(ctx->fleet, ctx->conn, dst);
	defrd_attrs = *attrs;
	if (!ctx->preserve_flag)
		defrd_attrs.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	if (ctx->preserve_flag || mode != tmpmode)
		sftp_hpn_dirattrs_defer_local(parallel_dirattrs(ctx->fleet),
		    dst, mode, tmpmode, &defrd_attrs);
	return 0;
}

static int
parallel_dl_xfer_file(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, Attrib *attrs)
{
	struct parallel_dl_sink	*ctx = (struct parallel_dl_sink *)sink;
	off_t			 fsize = 0;
	mode_t			 fmode = 0666;

	if (attrs->flags & SSH2_FILEXFER_ATTR_SIZE)
		fsize = (off_t)attrs->size;
	if (attrs->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		fmode = attrs->perm;

	/* Streaming hands files over during the discover-tree drain, which
	 * enumerates far faster than the fleet transfers. Wait for the fleet
	 * to fall below its outstanding-file ceiling before adding another, so
	 * the walk's memory tracks the ceiling instead of the tree. Blocking
	 * here stops us reading the reply, which back-pressures the server. */
	sftp_parallel_await_capacity(ctx->fleet);

	if (sftp_parallel_submit_download(ctx->fleet, ctx->conn, src, dst,
	    fsize, fmode, ctx->resume, ctx->verify) != 0) {
		if (sftp_parallel_is_aborting(ctx->fleet)) {
			debug("submit download \"%s\" refused (abort in "
			    "progress)", src);
			sftp_parallel_walker_record_failure(ctx->fleet, src,
			    "interrupted");
		} else {
			error("submit download \"%s\" -> \"%s\" failed", src,
			    dst);
			sftp_parallel_walker_record_failure(ctx->fleet, src,
			    "submit failed");
		}
		return -1;
	}
	return 0;
}

static void
parallel_dl_fail(struct sftp_tree_dl_sink *sink, const char *path,
    const char *reason)
{
	struct parallel_dl_sink	*ctx = (struct parallel_dl_sink *)sink;

	sftp_parallel_walker_record_failure(ctx->fleet, path, reason);
}

static int
parallel_dl_aborting(struct sftp_tree_dl_sink *sink)
{
	struct parallel_dl_sink	*ctx = (struct parallel_dl_sink *)sink;

	return sftp_parallel_is_aborting(ctx->fleet);
}

static void
parallel_dl_set_total(struct sftp_tree_dl_sink *sink, off_t total_bytes,
    size_t nfiles)
{
	struct parallel_dl_sink	*ctx = (struct parallel_dl_sink *)sink;

	sftp_parallel_progress_set_total(ctx->fleet, total_bytes, nfiles);
}

int
sftp_parallel_download_dir(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify)
{
	if (fleet == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		pm_mprintf("Retrieving %s\n", src);
	/* Register this command's roots as prefixes (download: local root = dst,
	 * remote = src). Gated on verify_transfer (same flag the park checks). */
	if (fleet->cfg.verify_transfer) {
		parallel_verify_prefix_register(fleet, dst);
		parallel_verify_prefix_register(fleet, src);
	}
	{
		struct parallel_dl_sink sink = {
			.base = {
				.make_dir = parallel_dl_make_dir,
				.xfer_file = parallel_dl_xfer_file,
				.fail = parallel_dl_fail,
				.aborting = parallel_dl_aborting,
				.set_total = parallel_dl_set_total,
				/* Submitting only enqueues work for the fleet,
				 * so files can be handed over as they are
				 * discovered instead of after the stream
				 * drains. See streams_files. */
				.streams_files = 1,
			},
			.fleet = fleet,
			.conn = conn,
			.preserve_flag = sftp_parallel_preserve_flag(fleet),
			.resume = resume,
			.verify = verify,
		};
		/* HPN: one streamed enumeration when the server supports it,
		 * else the recursive readdir fallback; both replay through the
		 * same parallel sink. This sink hands each file over as its
		 * record arrives rather than queueing the tree, which is legal
		 * only because submitting enqueues work for the fleet and
		 * sends nothing on the connection carrying the reply. See
		 * streams_files. */
		/* The submit path queries the destination filesystem's stripe
		 * geometry once and caches it. Do that now: during a streamed
		 * enumeration the connection is carrying the reply and cannot
		 * also carry that query. */
		if (sftp_conn_has_discover_tree(conn))
			sftp_parallel_prewarm_fs_info(fleet, conn, src);
		int rc = sftp_conn_has_discover_tree(conn) ?
		    sftp_tree_download_consume(conn, src, dst, NULL,
		        sftp_parallel_follow_link_flag(fleet), &sink.base) :
		    sftp_readdir_download_consume(conn, src, dst, 0,
		        HPN_WALK_MAX_DEPTH, NULL,
		        sftp_parallel_follow_link_flag(fleet), &sink.base);
		sftp_parallel_set_walker_phase(fleet, SFTP_WKP_DONE);
		return rc;
	}
}
