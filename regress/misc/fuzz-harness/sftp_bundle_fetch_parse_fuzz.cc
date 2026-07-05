/*
 * sftp_bundle_fetch_parse_fuzz.cc - libFuzzer harness for the server-side
 * request parser of the HPN-SSH hpn-bundle-fetch@hpnssh.org extension.
 *
 * The on-the-wire request (after the SSH_FXP_EXTENDED type byte, the
 * request id, and the extension-name cstring) is:
 *
 *   u32      flags
 *   u32      n_paths
 *   for i in [0, n_paths):  cstring  path
 *
 * This is the one bundle request with a genuinely client-scaled decode:
 * n_paths drives a calloc and a per-path cstring loop.  The harness
 * mirrors process_hpn_bundle_fetch's decode sequence exactly
 * (sftp-hpn-bundle-server.c), INCLUDING the n_paths sanity bound
 * (0 < n_paths <= 65535) that guards the allocation, so a malicious
 * n_paths that far exceeds the bytes actually present is rejected before
 * the loop rather than driving an over-large allocation or an
 * out-of-bytes read.  We stop at the decode: the filesystem side
 * (open/fstat/writer_add_file) is skipped, matching the "fuzz the wire
 * parser, not the FS" split used by sftp_fs_info_fuzz.
 *
 * Goal: catch decode bugs reachable by a malicious client - short-read
 * panics, cstring length-prefix overflow, the n_paths-vs-available-bytes
 * mismatch, leaks on the mid-list error path.  sshbuf's bounds checks
 * should make all of these clean SSH_ERR_* returns; this verifies that
 * against structured mutation, and ASan verifies the calloc/free
 * accounting on every early-exit path.
 *
 * Build target lives in regress/misc/fuzz-harness/Makefile.  Run with
 *   ./sftp_bundle_fetch_parse_fuzz <corpus_dir>
 *
 * NB: the input bytes ARE the post-framing request body (flags onward);
 * the fuzzer mutates the decoded fields directly without spending cycles
 * on SFTP framing the parser never sees.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"

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

	uint32_t flags = 0, n_paths = 0;
	char **paths = NULL;
	uint32_t n_collected = 0, i;
	int r;

	/* Mirror process_hpn_bundle_fetch's header decode. */
	if ((r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &n_paths)) != 0)
		goto out;

	/* Exact bound from the parser: reject implausible counts before the
	 * allocation.  Without this a fuzzed n_paths of 0xffffffff would ask
	 * for a 32 GiB calloc - the product guards it, so the harness must
	 * too or it just tests the allocator's OOM path. */
	if (n_paths == 0 || n_paths > 65535)
		goto out;

	paths = (char **)calloc(n_paths, sizeof(*paths));
	if (paths == NULL)
		goto out;

	for (i = 0; i < n_paths; i++) {
		if ((r = sshbuf_get_cstring(iqueue, &paths[i], NULL)) != 0)
			goto out;
		n_collected++;
	}

	(void)flags;

 out:
	/* Free exactly what was collected, on every path (success or the
	 * mid-list short-read break) - ASan flags any leak or double-free. */
	if (paths != NULL) {
		for (i = 0; i < n_collected; i++)
			free(paths[i]);
		free(paths);
	}
	sshbuf_free(iqueue);
	return 0;
}

} /* extern "C" */
