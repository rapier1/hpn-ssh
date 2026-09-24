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
 * sftp_dtree_read_fuzz.cc - libFuzzer harness for the client side of an
 * hpn-dtree-read@hpnssh.org reply, the batched directory tree walk.
 *
 * The server controls every byte of a reply, so this is the client's
 * remote-facing parse surface for recursive downloads. The input is the
 * post-framing message body, after the SSH2_FXP_EXTENDED_REPLY type byte
 * and the request id:
 *
 *     byte    version               (HPN_DTREE_VERSION)
 *     byte    kind                  (HPN_DTREE_CHUNK_*)
 *     uint32  record-count
 *     record[record-count]
 *
 * The header sequence mirrors sftp_tree_walk_read in sftp-hpn-client.c,
 * which reads from a live connection and so cannot take a buffer. Every
 * record then goes through the product's own codec, sftp_tree_get_record
 * (sftp-hpn-tree.c, with decode_attrib from sftp-common.c underneath),
 * and its path through the product's validator, sftp_tree_relpath_ok,
 * exactly as the read's callback path does. Those two are where a hostile
 * server can do damage, and the harness links the real objects for them.
 *
 * Bad input should make a step return SSH_ERR_* or the validator refuse.
 * What matters is no crash and no undefined behavior under the sanitizer.
 *
 * Build target lives in regress/misc/fuzz-harness/Makefile. Run with
 *   ./sftp_dtree_read_fuzz sftp_dtree_read_corpus
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "sftp-common.h"
#include "sftp-hpn-tree.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int log_inited = 0;
	struct sshbuf *msg;
	u_char version, kind;
	uint32_t count, i;
	int r;

	if (!log_inited) {
		log_init("sftp_dtree_read_fuzz",
		    SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
		log_inited = 1;
	}

	if ((msg = sshbuf_from(data, size)) == NULL)
		return 0;

	/* The header, in the read's order. A version or kind the read would
	 * refuse still gets its records decoded here, since the codec is the
	 * surface under test and a future version could reach it. */
	if ((r = sshbuf_get_u8(msg, &version)) != 0 ||
	    (r = sshbuf_get_u8(msg, &kind)) != 0 ||
	    (r = sshbuf_get_u32(msg, &count)) != 0) {
		sshbuf_free(msg);
		return 0;
	}
	(void)version;
	(void)kind;

	/* The count is peer-supplied. The read bounds it against the request,
	 * and here the buffer bounds it: a count past the data fails on the
	 * first record that is not there. */
	for (i = 0; i < count; i++) {
		char *relpath = NULL;
		u_char rectype = 0;
		Attrib attrs;
		uint32_t status = 0;

		attrib_clear(&attrs);
		r = sftp_tree_get_record(msg, &relpath, &rectype, &attrs,
		    &status);
		if (r != 0) {
			free(relpath);
			break;
		}
		/* Touch what the callback would use, so a sanitizer finding
		 * on an uninitialized field has somewhere to fire. */
		(void)sftp_tree_relpath_ok(relpath);
		if (relpath != NULL)
			(void)strlen(relpath);
		(void)rectype;
		(void)attrs.size;
		(void)attrs.perm;
		(void)status;
		free(relpath);
	}

	sshbuf_free(msg);
	return 0;
}

} /* extern "C" */
