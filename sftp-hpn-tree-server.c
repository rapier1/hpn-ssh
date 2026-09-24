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

/* sftp-hpn-tree-server.c - server side of the chunked tree walk.
 *
 * The server enumerates a directory subtree in batches. tree-open stats
 * and opens the root and returns a handle. Each tree-read resumes the
 * walk from where the last one stopped and emits up to the requested
 * number of records, then a BATCH_END marker, or END once the tree is
 * exhausted. Between reads the walk is paused: the open directories
 * from the root down to the current one stay open in the handle, one
 * per depth. That is what lets the client transfer each batch before
 * asking for the next, with memory bounded by one batch rather than
 * the whole tree.
 *
 * The walk is iterative over an explicit stack of levels, so it can
 * stop after any record and resume later. Records are emitted in the
 * same order the recursive walk produced: a directory's record precedes
 * its contents, so parents precede children on the wire.
 *
 * One tree handle may be open per session. A second tree-open is
 * refused. See hpn-chunked-tree-walk-design.md. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-server.h"
#include "sftp-hpn-tree.h"
#include "sftp-hpn-tree-server.h"

/* Tree slots of the handle table, implemented in sftp-server.c so this
 * file needs nothing of the table internals. */
extern int    handle_new_tree(void *opaque);
extern void  *handle_get_tree(int handle);
extern void   handle_free_tree(int handle);
extern int    handle_is_tree(int handle);

/* Records buffered per reply message before it is written out. */
#define TREE_MSG_RECORDS	256

/* Byte ceiling on the same message. A record carries the root-relative
 * path, which grows with depth, so a record count alone does not bound
 * the message: 256 records averaging a kilobyte of path would overflow
 * SFTP_MAX_MSG_LENGTH, and the client treats an over-long message as
 * fatal. The reserve covers the message header plus one full-length
 * record, since the trigger is tested after the record is appended. */
#define TREE_MSG_MAX_BYTES \
    ((size_t)SFTP_MAX_MSG_LENGTH - PATH_MAX - 1024)

/* One open directory on the walk's current path. dev and ino identify
 * it for the symlink loop check and are filled only when following
 * symlinks, the only way a directory can reappear beneath itself. */
struct tree_level {
	DIR	*dir;
	char	*abspath;
	char	*relpath;	/* root-relative, "" at the root */
	dev_t	 dev;
	ino_t	 ino;
	int	 id_valid;
};

/* The walk state kept in a tree handle between reads. depth indexes
 * the top of the stack and is -1 once the walk has finished. */
struct hpn_tree_state {
	int			 follow;
	int			 depth;
	struct tree_level	 level[HPN_WALK_MAX_DEPTH];
};

/* The reply being built by one tree-read. recbuf holds the records of
 * the message in progress. sent counts every record emitted for this
 * request, against the limit the client asked for. */
struct tree_emit {
	u_int		 id;
	struct sshbuf	*oqueue;
	struct sshbuf	*recbuf;
	uint32_t	 count;
	uint32_t	 sent;
	uint32_t	 limit;
};

/* The one tree handle this session may have open, or -1. */
static int tree_handle = -1;

/* Wrap recbuf in an EXTENDED_REPLY message (version, kind, count,
 * records), enqueue it and write it out now rather than letting a whole
 * batch pile up in oqueue. Resets recbuf for the next message. */
static void
tree_flush(struct tree_emit *emit, u_char kind)
{
	struct sshbuf	*msg;
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, emit->id)) != 0 ||
	    (r = sshbuf_put_u8(msg, HPN_TREE_VERSION)) != 0 ||
	    (r = sshbuf_put_u8(msg, kind)) != 0 ||
	    (r = sshbuf_put_u32(msg, emit->count)) != 0 ||
	    (r = sshbuf_putb(msg, emit->recbuf)) != 0)
		fatal_fr(r, "compose tree message");
	if ((r = sshbuf_put_stringb(emit->oqueue, msg)) != 0)
		fatal_fr(r, "enqueue tree message");
	sshbuf_free(msg);
	flush_oqueue_blocking(emit->oqueue);
	sshbuf_reset(emit->recbuf);
	emit->count = 0;
}

/* Append one record and write the message out once it is full. */
static void
tree_add(struct tree_emit *emit, const char *relpath, u_char rectype,
    const Attrib *attrs, uint32_t status)
{
	int r;

	if ((r = sftp_tree_put_record(emit->recbuf, relpath, rectype, attrs,
	    status)) != 0)
		fatal_fr(r, "encode tree record");
	emit->sent++;
	if (++emit->count >= TREE_MSG_RECORDS ||
	    sshbuf_len(emit->recbuf) >= TREE_MSG_MAX_BYTES)
		tree_flush(emit, HPN_TREE_CHUNK_DATA);
}

/* Is st one of the directories from the root down to the current one?
 * A followed symlink pointing back at an ancestor would otherwise
 * re-enumerate that subtree once per link, which the depth cap bounds
 * only in path length. */
static int
tree_on_path(const struct hpn_tree_state *state, const struct stat *st)
{
	int i;

	for (i = 0; i <= state->depth; i++) {
		if (state->level[i].id_valid &&
		    state->level[i].dev == st->st_dev &&
		    state->level[i].ino == st->st_ino)
			return 1;
	}
	return 0;
}

/* Open one directory for the walk. Below the root, and only when the
 * client asked not to follow symlinks, refuse a final component that has
 * become a symlink. The entry was classified by an earlier lstat, and
 * the name can be replaced between that decision and this open, which
 * would redirect the walk outside the requested tree. O_NOFOLLOW covers
 * exactly the component at risk. The root is named by the client and
 * opens as given. Platforms without fdopendir keep the plain path open,
 * which is what OpenSSH's own OPENDIR handler does. */
static DIR *
tree_opendir(const char *abspath, int depth, int follow)
{
#ifdef HAVE_FDOPENDIR
	DIR	*dir;
	int	 fd, saved_errno, flags = O_RDONLY | O_DIRECTORY;

	if (depth > 0 && !follow)
		flags |= O_NOFOLLOW;
	if ((fd = open(abspath, flags)) == -1)
		return NULL;
	if ((dir = fdopendir(fd)) == NULL) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
	}
	return dir;
#else
	return opendir(abspath);
#endif
}

/* Push a directory onto the walk as the new current level. Logs the
 * same "opendir" line sftp-server's OPENDIR handler writes, at the same
 * point, before the open, so administrators' tooling sees one line per
 * directory as it does against a stock server. Takes ownership of both
 * paths on success. Returns 0, or -1 with errno set and the paths not
 * taken. The caller checks the depth cap first. */
static int
tree_push(struct hpn_tree_state *state, char *abspath, char *relpath)
{
	struct tree_level	*level;
	struct stat		 st;
	int			 depth = state->depth + 1;

	logit("opendir \"%s\"", abspath);
	level = &state->level[depth];
	if ((level->dir = tree_opendir(abspath, depth, state->follow)) == NULL)
		return -1;
	level->abspath = abspath;
	level->relpath = relpath;
	level->id_valid = 0;
	if (state->follow && fstat(dirfd(level->dir), &st) == 0) {
		level->dev = st.st_dev;
		level->ino = st.st_ino;
		level->id_valid = 1;
	}
	state->depth = depth;
	return 0;
}

/* Close the current level and return to its parent. */
static void
tree_pop(struct hpn_tree_state *state)
{
	struct tree_level *level = &state->level[state->depth];

	closedir(level->dir);
	free(level->abspath);
	free(level->relpath);
	memset(level, 0, sizeof(*level));
	state->depth--;
}

/* Replace *st with the link target's stat. Named because it mutates
 * *st: the classification below reads st as either the lstat of the
 * entry or the stat of its target depending on whether this ran.
 * Returns 1 on success, 0 if the target is unreachable, with errno
 * set. */
static int
tree_resolve_link(const char *abspath, struct stat *st)
{
	return stat(abspath, st) == 0;
}

/* Classify one directory entry and emit its record. A directory is
 * also pushed, so its contents come next. "." and ".." are skipped. An
 * entry that cannot be examined or opened emits one ERROR record and
 * the walk goes on, so one bad subtree never aborts it.
 *
 * A symlink is emitted as a SYMLINK record and not descended, unless
 * follow is set, in which case the target is stat'd and the entry is
 * treated as that target. A broken link emits an ERROR record. A target
 * that resolves to a directory already on the path is a loop: it emits
 * an ERROR record and is not descended. */
static void
tree_entry(struct hpn_tree_state *state, struct tree_emit *emit,
    const char *name)
{
	struct tree_level	*level = &state->level[state->depth];
	struct stat		 st;
	Attrib			 attrs;
	char			*child_abs, *child_rel;

	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return;
	xasprintf(&child_abs, "%s/%s", level->abspath, name);
	if (*level->relpath == '\0')
		child_rel = xstrdup(name);
	else
		xasprintf(&child_rel, "%s/%s", level->relpath, name);

	if (lstat(child_abs, &st) != 0) {
		tree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
		    errno_to_sftp_status(errno));
		goto done;
	}
	if (S_ISLNK(st.st_mode) && !state->follow) {
		stat_to_attrib(&st, &attrs);
		tree_add(emit, child_rel, HPN_DTREE_REC_SYMLINK, &attrs, 0);
		goto done;
	}
	if (S_ISLNK(st.st_mode) && !tree_resolve_link(child_abs, &st)) {
		tree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
		    errno_to_sftp_status(errno));
		goto done;
	}
	stat_to_attrib(&st, &attrs);
	if (S_ISDIR(st.st_mode) && tree_on_path(state, &st)) {
		tree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
		    SSH2_FX_FAILURE);
	} else if (S_ISDIR(st.st_mode)) {
		tree_add(emit, child_rel, HPN_DTREE_REC_DIR, &attrs, 0);
		/* Report the cap rather than skipping quietly. The DIR
		 * record is already out, so a silent skip would leave the
		 * client with a listing that looks complete. The ERROR
		 * record reaches the client's existing arm, which fails
		 * the transfer, as the readdir walk does at this depth. */
		if (state->depth + 1 >= HPN_WALK_MAX_DEPTH) {
			error_f("max directory depth %d reached at \"%s\"",
			    HPN_WALK_MAX_DEPTH, child_abs);
			tree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
			    SSH2_FX_FAILURE);
		} else if (tree_push(state, child_abs, child_rel) == 0) {
			/* Now owned by the level. */
			return;
		} else {
			tree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
			    errno_to_sftp_status(errno));
		}
	} else if (S_ISREG(st.st_mode)) {
		tree_add(emit, child_rel, HPN_DTREE_REC_REG, &attrs, 0);
	} else {
		tree_add(emit, child_rel, HPN_DTREE_REC_OTHER, &attrs, 0);
	}
 done:
	free(child_abs);
	free(child_rel);
}

/* Walk until the request's record limit is reached or the tree is
 * exhausted. readdir returns NULL both at the end of a directory and on
 * error, told apart only by errno, which it does not clear on success.
 * Without the reset a failure part way through would read as a short
 * directory. */
static void
tree_walk_batch(struct hpn_tree_state *state, struct tree_emit *emit)
{
	struct tree_level	*level;
	struct dirent		*entry;

	while (state->depth >= 0 && emit->sent < emit->limit) {
		level = &state->level[state->depth];
		errno = 0;
		if ((entry = readdir(level->dir)) == NULL) {
			if (errno != 0) {
				error_f("readdir \"%s\": %s", level->abspath,
				    strerror(errno));
				tree_add(emit, level->relpath,
				    HPN_DTREE_REC_ERROR, NULL,
				    errno_to_sftp_status(errno));
			}
			tree_pop(state);
			continue;
		}
		tree_entry(state, emit, entry->d_name);
	}
}

/* Free a walk state, closing whatever is still open. */
static void
tree_state_free(struct hpn_tree_state *state)
{
	while (state->depth >= 0)
		tree_pop(state);
	free(state);
}

/* Compose and enqueue the SSH2_FXP_HANDLE reply for a new tree. */
static void
tree_send_handle(struct sshbuf *oqueue, u_int id, int handle)
{
	struct sshbuf	*msg;
	u_char		 hbuf[sizeof(uint32_t)];
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	put_u32(hbuf, (uint32_t)handle);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
		fatal_fr(r, "compose handle reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue handle reply");
	sshbuf_free(msg);
}

int
sftp_hpn_tree_is_handle(int handle)
{
	return handle_is_tree(handle);
}

int
sftp_hpn_tree_close(int handle)
{
	struct hpn_tree_state *state = handle_get_tree(handle);

	if (state == NULL)
		return SSH2_FX_FAILURE;
	tree_state_free(state);
	handle_free_tree(handle);
	tree_handle = -1;
	return SSH2_FX_OK;
}

/* Handle an hpn-tree-open request: string root, uint32 flags. The root
 * is checked and opened here, so a missing, unreadable or non-directory
 * root fails the request with a status rather than starting a walk
 * that emits one error. */
void
sftp_hpn_tree_open(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	struct hpn_tree_state	*state;
	struct stat		 st;
	char			*root = NULL, *relpath;
	uint32_t		 flags = 0;
	u_int			 status = SSH2_FX_FAILURE;
	int			 handle, r;

	if ((r = sshbuf_get_cstring(iqueue, &root, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0) {
		error_f("parse hpn-tree-open request: %s", ssh_err(r));
		send_status_oqueue(oqueue, id, SSH2_FX_BAD_MESSAGE);
		free(root);
		return;
	}
	debug3("request %u: hpn-tree-open \"%s\" flags=0x%x", id, root,
	    flags);

	if (tree_handle != -1) {
		error_f("hpn-tree-open \"%s\": a tree is already open", root);
		goto fail;
	}
	if (stat(root, &st) != 0) {
		status = errno_to_sftp_status(errno);
		goto fail;
	}
	if (!S_ISDIR(st.st_mode)) {
		error_f("hpn-tree-open \"%s\": not a directory", root);
		goto fail;
	}

	state = xcalloc(1, sizeof(*state));
	state->follow = (flags & HPN_TREE_FOLLOW_SYMLINKS) != 0;
	state->depth = -1;
	relpath = xstrdup("");
	if (tree_push(state, root, relpath) != 0) {
		status = errno_to_sftp_status(errno);
		free(state);
		free(relpath);
		goto fail;
	}
	/* The root level owns both paths from here. */
	root = NULL;
	if ((handle = handle_new_tree(state)) < 0) {
		error_f("hpn-tree-open: handle table full");
		tree_state_free(state);
		goto fail;
	}
	tree_handle = handle;
	tree_send_handle(oqueue, id, handle);
	return;

 fail:
	send_status_oqueue(oqueue, id, status);
	free(root);
}

/* Handle an hpn-tree-read request: string handle, uint32 max-records.
 * Emits up to that many records as DATA messages, then BATCH_END while
 * the tree has more, or END once it is exhausted. A read after END
 * replies END again. Zero, or more than HPN_TREE_MAX_BATCH, means the
 * maximum. */
void
sftp_hpn_tree_read(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	struct hpn_tree_state	*state;
	struct tree_emit	 emit;
	u_char			*hbuf = NULL;
	size_t			 hlen = 0;
	uint32_t		 max_records = 0;
	int			 handle, r;

	if ((r = sshbuf_get_string(iqueue, &hbuf, &hlen)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &max_records)) != 0) {
		error_f("parse hpn-tree-read request: %s", ssh_err(r));
		send_status_oqueue(oqueue, id, SSH2_FX_BAD_MESSAGE);
		free(hbuf);
		return;
	}
	if (hlen != sizeof(uint32_t)) {
		error_f("hpn-tree-read: bad handle length %zu", hlen);
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		free(hbuf);
		return;
	}
	handle = (int)get_u32(hbuf);
	free(hbuf);
	if ((state = handle_get_tree(handle)) == NULL) {
		error_f("hpn-tree-read: handle %d is not an open tree", handle);
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		return;
	}
	if (max_records == 0 || max_records > HPN_TREE_MAX_BATCH)
		max_records = HPN_TREE_MAX_BATCH;
	debug3("request %u: hpn-tree-read handle %d max %u", id, handle,
	    max_records);

	emit.id = id;
	emit.oqueue = oqueue;
	emit.count = 0;
	emit.sent = 0;
	emit.limit = max_records;
	if ((emit.recbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	tree_walk_batch(state, &emit);

	/* Flush any partial DATA message, then the marker. */
	if (emit.count > 0)
		tree_flush(&emit, HPN_TREE_CHUNK_DATA);
	if (state->depth < 0)
		tree_flush(&emit, HPN_TREE_CHUNK_END);
	else
		tree_flush(&emit, HPN_TREE_CHUNK_BATCH_END);
	sshbuf_free(emit.recbuf);
}
