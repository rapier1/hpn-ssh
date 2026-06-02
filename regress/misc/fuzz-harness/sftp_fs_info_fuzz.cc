/*
 * sftp_fs_info_fuzz.cc - libFuzzer harness for the client-side reply
 * parser of the HPN-SSH hpn-fs-info@hpnssh.org SFTP extension.
 *
 * The on-the-wire reply (after the SSH_FXP_EXTENDED_REPLY type byte
 * and the request id) is:
 *
 *   cstring  fs_type        e.g. "lustre"
 *   u64      stripe_size    Lustre/GPFS only; 0 otherwise
 *   u32      stripe_count   Lustre only; 0 otherwise
 *   u64      block_size     optimal I/O block size
 *
 * The fuzzer feeds arbitrary bytes through the same sshbuf_get_*
 * sequence that sftp_fs_info() runs in sftp-client.c (around the
 * "parse reply:" diagnostic).  Goal: catch decoder bugs that could
 * be triggered by a malicious or compromised server - short-read
 * panics, cstring length-prefix overflow, etc.  All of those would
 * normally be caught by sshbuf's bounds checks; this harness verifies
 * that assumption against structured mutation.
 *
 * Build target lives in regress/misc/fuzz-harness/Makefile.  Run with
 *   ./sftp_fs_info_fuzz <corpus_dir>
 *
 * NB: we deliberately do NOT recreate the SFTP framing (type byte +
 * request id) - the input bytes ARE the post-framing payload, so the
 * fuzzer can mutate the on-wire reply body directly without wasting
 * cycles on bytes the parser would skip anyway.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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
		log_init("sftp_fs_info_fuzz",
		    SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
		log_inited = 1;
	}

	struct sshbuf *msg = sshbuf_from(data, size);
	if (msg == NULL)
		return 0;

	char    *fs_type = NULL;
	uint64_t stripe_size = 0;
	uint32_t stripe_count = 0;
	uint64_t block_size = 0;
	int      r;

	/*
	 * Mirror the cstring + u64 + u32 + u64 sequence in sftp-client.c's
	 * sftp_fs_info().  Each step exercises bounds checks inside
	 * sshbuf.  We're not asserting success - bad inputs SHOULD make
	 * these return SSH_ERR_*, what matters is no UB / no crash.
	 */
	if ((r = sshbuf_get_cstring(msg, &fs_type, NULL)) == 0 &&
	    (r = sshbuf_get_u64(msg, &stripe_size)) == 0 &&
	    (r = sshbuf_get_u32(msg, &stripe_count)) == 0 &&
	    (r = sshbuf_get_u64(msg, &block_size)) == 0) {
		/*
		 * Successful parse - touch each output so out-of-band
		 * sanitizer findings (e.g. uninitialized read) have
		 * somewhere to fire.  snprintf rather than strlcpy because
		 * the harness compile line in oss-fuzz doesn't pull in
		 * openbsd-compat/include, and snprintf is portable. */
		char buf[32];
		snprintf(buf, sizeof(buf), "%s", fs_type ? fs_type : "");
		(void)buf;
		(void)stripe_size;
		(void)stripe_count;
		(void)block_size;
	}

	free(fs_type);
	sshbuf_free(msg);
	return 0;
}

} /* extern "C" */
