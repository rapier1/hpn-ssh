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

/* sftp_bundle_fetch_parse_fuzz.cc - libFuzzer harness for the server's
 * decode of the hpn-bundle-fetch@hpnssh.org request.
 *
 * The input is the post-framing request body, after the SSH_FXP_EXTENDED
 * type, the request id and the extension name:
 *
 *   u32      flags
 *   u32      n_paths
 *   for i in [0, n_paths):  cstring  path
 *
 * It is the one bundle request whose decode scales with the client's
 * input: n_paths drives a calloc and a per-path cstring loop. The
 * harness mirrors the decode in process_hpn_bundle_fetch
 * (sftp-hpn-bundle-server.c) including the count bound, taken from the
 * shared header, that rejects an absurd n_paths before the allocation.
 * It stops where the decode stops. The filesystem side, open, fstat and
 * the writer, is not fuzzed, the same split sftp_fs_info_fuzz uses.
 *
 * Goal: decode bugs reachable by a malicious client, short reads, a
 * cstring length prefix beyond the bytes present, a count larger than
 * the paths supplied, and leaks on the mid-list error path. sshbuf's
 * bounds checks should turn all of these into clean SSH_ERR_* returns,
 * and ASan checks the calloc and free accounting on every exit.
 *
 * Built by regress/misc/fuzz-harness/Makefile. Run as
 *   ./sftp_bundle_fetch_parse_fuzz <corpus_dir> */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "sftp-hpn-bundle.h"	/* BUNDLE_BATCH_MAX_FILES */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int log_inited = 0;
	if (!log_inited) {
		log_init("sftp_bundle_fetch_parse_fuzz",
		    SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
		log_inited = 1;
	}

	struct sshbuf *iqueue = sshbuf_from(data, size);
	if (iqueue == NULL)
		return 0;

	uint32_t flags = 0, n_paths = 0, i;
	char **paths = NULL;
	int r;

	/* Mirror process_hpn_bundle_fetch's decode. */
	if ((r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &n_paths)) != 0)
		goto out;

	/* The server's bound. Without it a fuzzed n_paths of 0xffffffff
	 * asks for a 32 GiB calloc and the run tests the allocator's OOM
	 * path instead of the decode. */
	if (n_paths == 0 || n_paths > BUNDLE_BATCH_MAX_FILES)
		goto out;

	paths = (char **)calloc(n_paths, sizeof(*paths));
	if (paths == NULL)
		goto out;

	for (i = 0; i < n_paths; i++) {
		if ((r = sshbuf_get_cstring(iqueue, &paths[i], NULL)) != 0)
			goto out;
	}

	(void)flags;

 out:
	/* Free every slot on every path, as the server does. calloc left
	 * the unfilled ones NULL, and ASan flags any leak or double free. */
	if (paths != NULL) {
		for (i = 0; i < n_paths; i++)
			free(paths[i]);
		free(paths);
	}
	sshbuf_free(iqueue);
	return 0;
}

} /* extern "C" */
