/*
 * sftp_tar_parser_fuzz.cc - libFuzzer harness for the HPN-SSH bundle
 * codec parser (sftp_hpn_tar_parser_feed, sftp-hpn-tar.c).
 *
 * The codec is NOT tar: it is a minimal length-prefixed binary record
 * stream (u8 type, u32 mode, u64 mtime, u64 size, u16 path_len, path;
 * a lone HPN_REC_END byte terminates).  No 512-byte blocks, no octal,
 * no magic - see sftp-hpn-tar.c.  ("tar" survives only in the file name
 * and API prefix.)
 *
 * This is the single highest-value memory-safety target in the bundle
 * path.  The parser consumes an ENTIRELY adversary-controlled byte
 * stream in both directions:
 *   - upload   : the SERVER feeds client-sent WRITE payloads to it
 *                (sftp_hpn_server_bundle_write in sftp-hpn-bundle-server.c
 *                 is a thin wrapper: an offset-monotonic check, then a
 *                 direct parser_feed - so this harness also covers that
 *                 WRITE handler's decode surface).
 *   - download : the CLIENT feeds server-sent bundle bytes to it
 *                (bundle_dl_stream_drain_one in sftp-hpn-bundle-client.c).
 *
 * NB (2026-07-05): the retired sftp_bundle_extract_fuzz harness linked
 * -larchive and fuzzed libarchive's tar reader.  libarchive was removed
 * from the product on 2026-05-31 and replaced by this in-tree codec, so
 * that harness exercised code we no longer ship.  THIS harness targets
 * the parser the product actually runs.
 *
 * The fuzzer feeds arbitrary bytes to parser_feed in one or more chunks
 * (the wire delivers the stream in SFTP WRITE/READ-sized pieces, so a
 * split feed exercises the parser's cross-chunk header-reassembly state
 * that a single-shot feed would not - the first input byte picks the
 * chunk size, 1..256, so the fuzzer steers the split boundary; the
 * 23-byte-fixed + path_len header can straddle a feed boundary).  Goal:
 * short-read panics, size/path_len arithmetic overflow, size/offset
 * mishandling, OOB in the fixed-field decode, end-record edge cases.
 *
 * The callbacks mirror what the real consumers do MINUS the filesystem:
 * validate the entry path (server-side bundle_path_is_safe, copied
 * below and kept in sync), and enforce the data_cb size-accounting
 * contract the real client relies on (bundle_dl_data_cb bounds each
 * write against the declared entry size).  No fd is opened, so iteration
 * stays fast.
 *
 * Build target lives in regress/misc/fuzz-harness/Makefile.  Run with
 *   ./sftp_tar_parser_fuzz <corpus_dir>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern "C" {

#include "log.h"
#include "sftp-hpn-tar.h"

/* --- KEEP IN SYNC WITH sftp-hpn-server.c:bundle_path_is_safe --------- */
static int
bundle_path_is_safe(const char *p, const char *dest_dir)
{
	const char *start, *q;

	if (p == NULL || *p == '\0')
		return 0;
	if (*p == '/' && dest_dir != NULL && *dest_dir != '\0')
		return 0;
	start = p;
	for (q = p; ; q++) {
		if (*q == '/' || *q == '\0') {
			size_t len = (size_t)(q - start);
			if (len == 2 && start[0] == '.' && start[1] == '.')
				return 0;
			if (*q == '\0')
				break;
			start = q + 1;
		}
	}
	return 1;
}
/* --- END KEEP-IN-SYNC ------------------------------------------------ */

/*
 * Per-entry state the callbacks thread through the parser.  entry_cb
 * records the declared size so data_cb can enforce the same
 * "never deliver more than declared" invariant the real client
 * (bundle_dl_data_cb) uses as defense-in-depth against a parser
 * regression.
 */
struct cb_ctx {
	uint64_t cur_declared;
	uint64_t cur_written;
};

static int
h_entry_cb(void *vctx, const char *path, uint64_t size, mode_t mode,
    time_t mtime)
{
	struct cb_ctx *c = (struct cb_ctx *)vctx;
	(void)mode;
	(void)mtime;
	/* Touch the path through the traversal validator on every entry -
	 * server extraction gates each pathname this way. */
	(void)bundle_path_is_safe(path, "");
	(void)bundle_path_is_safe(path, "bundle-dest");
	c->cur_declared = size;
	c->cur_written = 0;
	return 0;
}

static int
h_data_cb(void *vctx, const u_char *data, size_t len)
{
	struct cb_ctx *c = (struct cb_ctx *)vctx;
	/* Mirror bundle_dl_data_cb's overflow guard: the parser must never
	 * deliver more bytes than the entry declared.  Subtraction form
	 * avoids overflow in the check itself. */
	if ((uint64_t)len > c->cur_declared - c->cur_written)
		return -1;
	/* Read every delivered byte so a sanitizer fires on any OOB the
	 * parser handed us a bad (ptr,len) for. */
	volatile u_char sink = 0;
	for (size_t i = 0; i < len; i++)
		sink ^= data[i];
	(void)sink;
	c->cur_written += (uint64_t)len;
	return 0;
}

static int
h_entry_end_cb(void *vctx)
{
	(void)vctx;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int log_inited = 0;
	if (!log_inited) {
		log_init("sftp_tar_parser_fuzz",
		    SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);
		log_inited = 1;
	}

	static const struct sftp_hpn_tar_callbacks cb = {
		h_entry_cb, h_data_cb, h_entry_end_cb
	};
	struct cb_ctx ctx = { 0, 0 };

	struct sftp_hpn_tar_parser *p = sftp_hpn_tar_parser_new(&cb, &ctx);
	if (p == NULL)
		return 0;

	/*
	 * Feed in wire-sized chunks so cross-chunk header reassembly is
	 * exercised.  The first byte selects a chunk size in [1, 512] so
	 * the fuzzer can steer the split boundary (a header spanning two
	 * feeds is a distinct code path from a header delivered whole).
	 */
	size_t chunk = 512;
	const uint8_t *cur = data;
	size_t remaining = size;
	if (remaining > 0) {
		chunk = (size_t)data[0] + 1;   /* 1..256 */
		cur++;
		remaining--;
	}

	while (remaining > 0) {
		size_t n = remaining < chunk ? remaining : chunk;
		int r = sftp_hpn_tar_parser_feed(p, cur, n);
		if (r != 0) {
			/* r == 1 (clean EOA) or r == -1 (parse error): both
			 * mean stop.  Further feeds after either are a caller
			 * error, not a parser bug. */
			(void)sftp_hpn_tar_parser_error(p);
			break;
		}
		cur += n;
		remaining -= n;
	}

	sftp_hpn_tar_parser_free(p);
	return 0;
}

} /* extern "C" */
