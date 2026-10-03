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

/* The chunked tree walk's shared pieces: the codec for one record, used by
 * the server's walk emitter (sftp-hpn-tree-server.c) and the client's
 * consumer (sftp-hpn-client.c), and the check the client applies to every
 * relative path a record carries. The record layout and the message
 * framing around it are in sftp-hpn-tree.h. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>	/* struct stat, in sftp-common.h prototypes */
#include <limits.h>	/* PATH_MAX, bounding a peer-supplied relative path */
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "sftp-common.h"
#include "sftp-hpn-tree.h"

/* Append one record to msg. Every type but ERROR carries attrs. An ERROR
 * record carries an SSH2_FX_* status instead, saying why the server could
 * not read the entry. Returns 0 or an SSH_ERR_* code. */
int
sftp_tree_put_record(struct sshbuf *msg, const char *relpath, u_char rectype,
    const Attrib *attrs, u_int32_t status)
{
	int r;

	if ((r = sshbuf_put_cstring(msg, relpath)) != 0 ||
	    (r = sshbuf_put_u8(msg, rectype)) != 0)
		return r;
	if (rectype == HPN_DTREE_REC_ERROR)
		return sshbuf_put_u32(msg, status);
	return encode_attrib(msg, attrs);
}

/* Parse one record from msg. Allocates *relpath, which the caller frees
 * even on error, since it stays allocated if a later field fails. *status
 * is set only for ERROR records, and *attrs is filled for all other types.
 * Returns 0 or an SSH_ERR_* code. */
int
sftp_tree_get_record(struct sshbuf *msg, char **relpath, u_char *rectype,
    Attrib *attrs, u_int32_t *status)
{
	int r;

	*relpath = NULL;
	*status = 0;
	if ((r = sshbuf_get_cstring(msg, relpath, NULL)) != 0 ||
	    (r = sshbuf_get_u8(msg, rectype)) != 0)
		return r;
	if (*rectype == HPN_DTREE_REC_ERROR)
		return sshbuf_get_u32(msg, status);
	return decode_attrib(msg, attrs);
}

/* Validate a tree walk relative path before a client builds local or
 * remote paths from it. The server generated it, but we never trust the
 * peer. It is the whole-relpath analogue of the per-name
 * SFTP_DIRECTORY_CHARS guard the readdir walk applies, and it splits on the
 * same separator set. On Cygwin a backslash is a separator to the runtime,
 * so a validator that only knows '/' would pass "..\\..\\etc\\passwd" as one
 * harmless-looking component and let the peer write outside the transfer
 * root.
 *
 * Rejects, in order: an empty path, one at or past PATH_MAX, an absolute
 * path, an empty component (a trailing or doubled separator), ".", and
 * "..".
 *
 * The length bound is not only hygiene. A bundled download lists every
 * member's path in one request whose budget reserves a single PATH_MAX of
 * overshoot (BUNDLE_DL_FETCH_REQ_MAX). One longer path makes that request
 * too long to send, and the client dies with "Outbound message too long".
 *
 * Returns 1 if safe, 0 otherwise. */
int
sftp_tree_relpath_ok(const char *rel)
{
	const char *path = rel;

	if (rel == NULL || *rel == '\0')
		return 0;
	if (strlen(rel) >= PATH_MAX)
		return 0;
	if (strchr(HPN_WALK_SEPARATORS, *rel) != NULL)
		return 0;
	for (;;) {
		size_t len = strcspn(path, HPN_WALK_SEPARATORS);

		if (len == 0)
			return 0;
		if (len == 1 && path[0] == '.')
			return 0;
		if (len == 2 && path[0] == '.' && path[1] == '.')
			return 0;
		if (path[len] == '\0')
			break;
		path += len + 1;
	}
	return 1;
}
