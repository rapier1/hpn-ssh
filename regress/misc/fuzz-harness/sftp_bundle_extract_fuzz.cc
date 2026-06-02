/*
 * sftp_bundle_extract_fuzz.cc - libFuzzer harness for the server-side
 * tar-extraction path of the HPN-SSH bundle extension
 * (hpn-bundle-open@hpnssh.org).
 *
 * Targets the part of sftp_hpn_server_bundle_close (sftp-hpn-server.c)
 * that:
 *   1. wraps client-supplied bytes in archive_read_open + tar format,
 *   2. iterates archive_read_next_header, and
 *   3. validates each archive_entry_pathname() with bundle_path_is_safe.
 *
 * Highest-value coverage point: tar parsers are the canonical bug
 * surface for archive extractors, and the path-traversal validator is
 * a defense-in-depth control we want exercised by structured-mutation
 * fuzzing.
 *
 * What this harness does NOT cover:
 *   - The full SFTP request/response framing.  That's deliberate;
 *     framing is shared with vanilla SFTP and already covered upstream.
 *   - File creation / parent-dir mkdir_p / fsync paths.  Those touch
 *     the filesystem and would slow fuzz iteration; we just validate
 *     pathnames and skip the open().
 *
 * Build target lives in regress/misc/fuzz-harness/Makefile.  Run with
 *   ./sftp_bundle_extract_fuzz <corpus_dir>
 *
 * NB: bundle_path_is_safe is `static` in sftp-hpn-server.c and the
 * server TU pulls in heavy server-only dependencies (sftp-server.c,
 * handle table, etc.) that we don't want linked into a fuzz harness.
 * Inline a verbatim copy here with a sync comment - if you change
 * the validator in sftp-hpn-server.c, mirror the change below.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

extern "C" {

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

struct mem_ctx {
	const uint8_t *p;
	size_t         remaining;
};

static la_ssize_t
mem_read_cb(struct archive *a, void *cd, const void **buffer)
{
	(void)a;
	struct mem_ctx *ctx = (struct mem_ctx *)cd;
	if (ctx->remaining == 0)
		return 0;
	*buffer = ctx->p;
	la_ssize_t r = (la_ssize_t)ctx->remaining;
	ctx->p         += ctx->remaining;
	ctx->remaining  = 0;
	return r;
}

/*
 * Exercise both dest_dir modes (empty and non-empty) because
 * bundle_path_is_safe behaves differently with respect to absolute
 * paths in each mode.  Cheap to run both.
 */
static void
fuzz_one_pass(const uint8_t *data, size_t size, const char *dest_dir)
{
	struct archive *a = archive_read_new();
	if (a == NULL)
		return;

	archive_read_support_format_tar(a);

	struct mem_ctx ctx = { data, size };
	if (archive_read_open(a, &ctx, NULL, mem_read_cb, NULL) != ARCHIVE_OK) {
		archive_read_free(a);
		return;
	}

	struct archive_entry *ae;
	for (;;) {
		int r = archive_read_next_header(a, &ae);
		if (r == ARCHIVE_EOF || r == ARCHIVE_FATAL)
			break;
		if (r != ARCHIVE_OK && r != ARCHIVE_WARN)
			break;

		const char *path = archive_entry_pathname(ae);
		/*
		 * Trigger the validator on every entry.  We don't care about
		 * the return value - libFuzzer cares about whether the call
		 * crashes, reads OOB, or trips a sanitizer.
		 */
		(void)bundle_path_is_safe(path, dest_dir);

		/* archive_entry_pathname_utf8 is a separate accessor with its
		 * own internal state; touching it widens coverage slightly. */
		(void)archive_entry_pathname_utf8(ae);
	}

	archive_read_free(a);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Empty-dest_dir mode mirrors the orchestrator's default (paths
	 * interpreted relative to the SFTP user's CWD). */
	fuzz_one_pass(data, size, "");

	/* Non-empty-dest_dir mode mirrors the "extract under a dir"
	 * call site (where bundle_path_is_safe also rejects absolute
	 * tar pathnames). */
	fuzz_one_pass(data, size, "bundle-dest");
	return 0;
}

} /* extern "C" */
