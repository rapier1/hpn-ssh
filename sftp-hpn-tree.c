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
 * hpn-discover-tree record codec.
 *
 * Direction-neutral encode/decode for one directory-tree record, shared by
 * the server-side walk emitter (sftp-hpn-server.c) and the client consumer
 * (sftp-hpn-client.c).  A record is:
 *
 *     string  relative-path
 *     byte    rec-type            (HPN_DTREE_REC_*)
 *     ATTRS   attrib              (all types except ERROR)
 *     uint32  status              (ERROR only: SSH2_FX_*)
 *
 * See sftp-hpn-tree.h for the surrounding chunk framing and the design in
 * hpn-discover-tree-design.md.
 */

#include <sys/types.h>
#include <sys/stat.h>	/* struct stat, referenced by sftp-common.h prototypes */
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "sftp-common.h"
#include "sftp-hpn-tree.h"

/*
 * Append one record to m.  attrs are encoded for every type except ERROR,
 * which instead carries an SSH2_FX_* status describing why the subtree at
 * relpath could not be read.  Returns 0 or an SSH_ERR_* code.
 */
int
sftp_tree_put_record(struct sshbuf *msg, const char *relpath, u_char rectype,
    const Attrib *a, u_int32_t status)
{
	int r;

	if ((r = sshbuf_put_cstring(msg, relpath)) != 0 ||
	    (r = sshbuf_put_u8(msg, rectype)) != 0)
		return r;
	if (rectype == HPN_DTREE_REC_ERROR)
		return sshbuf_put_u32(msg, status);
	return encode_attrib(msg, a);
}

/*
 * Parse one record from m.  Allocates *relpath (caller frees).  *status is
 * set only for ERROR records; *a is filled for all other types.  Returns 0
 * or an SSH_ERR_* code; on error *relpath is NULL.
 */
int
sftp_tree_get_record(struct sshbuf *msg, char **relpath, u_char *rectype,
    Attrib *a, u_int32_t *status)
{
	int r;

	*relpath = NULL;
	*status = 0;
	if ((r = sshbuf_get_cstring(msg, relpath, NULL)) != 0 ||
	    (r = sshbuf_get_u8(msg, rectype)) != 0)
		return r;
	if (*rectype == HPN_DTREE_REC_ERROR)
		return sshbuf_get_u32(msg, status);
	return decode_attrib(msg, a);
}

/*
 * Validate a discover-tree relative path before a client builds local or
 * remote paths from it.  The server generated it, but we never trust the
 * peer: reject an absolute path or any ".." component so a hostile or buggy
 * server cannot escape the transfer root.  The whole-relpath analogue of the
 * per-name SFTP_DIRECTORY_CHARS guard the readdir walk applies.  Returns 1 if
 * safe, 0 otherwise.
 */
int
sftp_tree_relpath_ok(const char *rel)
{
	const char *p = rel;

	if (rel == NULL || *rel == '\0' || *rel == '/')
		return 0;
	while (*p != '\0') {
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p) : strlen(p);

		if (len == 2 && p[0] == '.' && p[1] == '.')
			return 0;
		if (slash == NULL)
			break;
		p = slash + 1;
	}
	return 1;
}
