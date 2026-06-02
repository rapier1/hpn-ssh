/*
 * mkcorpus_sftp_bundle_extract.c - generate seed corpus for
 * sftp_bundle_extract_fuzz.
 *
 * Writes a handful of small tarballs to ./sftp_bundle_extract_corpus/.
 * Each seed exercises a different point on the tar-pathname spectrum
 * the harness cares about:
 *
 *   normal.tar       - single entry, plain ASCII name
 *   multi.tar        - three entries
 *   deep.tar         - nested directory path (a/b/c/d.txt)
 *   utf8.tar         - non-ASCII pathname
 *   traversal.tar    - entry with "..", which bundle_path_is_safe MUST reject
 *   absolute.tar     - entry with leading "/", which bundle_path_is_safe
 *                      rejects when dest_dir is non-empty
 *
 * Why include the rejection-path seeds: libFuzzer mutates from seeds,
 * so giving it inputs that BOTH reach the validator (valid tar framing)
 * AND trigger different validator branches makes mutation productive
 * from the first generation.  Without these, every mutation cycle has
 * to first re-derive valid tar framing from scratch.
 *
 * Built and invoked by regress/misc/fuzz-harness/Makefile's `corpus`
 * target, and by oss-fuzz's build.sh.
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <archive.h>
#include <archive_entry.h>

#define CORPUS_DIR "sftp_bundle_extract_corpus"

static void
write_tar(const char *out_name, const char * const *paths, size_t npaths)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, out_name);

	struct archive *a = archive_write_new();
	if (a == NULL)
		errx(1, "archive_write_new");
	archive_write_set_format_ustar(a);
	if (archive_write_open_filename(a, path) != ARCHIVE_OK)
		errx(1, "archive_write_open_filename %s: %s",
		    path, archive_error_string(a));

	for (size_t i = 0; i < npaths; i++) {
		struct archive_entry *ae = archive_entry_new();
		if (ae == NULL)
			errx(1, "archive_entry_new");
		archive_entry_set_pathname(ae, paths[i]);
		archive_entry_set_size(ae, 0);
		archive_entry_set_filetype(ae, AE_IFREG);
		archive_entry_set_perm(ae, 0644);
		if (archive_write_header(a, ae) != ARCHIVE_OK)
			errx(1, "archive_write_header %s: %s",
			    paths[i], archive_error_string(a));
		archive_entry_free(ae);
	}

	if (archive_write_close(a) != ARCHIVE_OK)
		errx(1, "archive_write_close: %s", archive_error_string(a));
	archive_write_free(a);
}

int main(void)
{
	if (mkdir(CORPUS_DIR, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir " CORPUS_DIR);

	{
		const char *p[] = { "a.txt" };
		write_tar("normal.tar", p, 1);
	}
	{
		const char *p[] = { "one.txt", "two.txt", "three.txt" };
		write_tar("multi.tar", p, 3);
	}
	{
		const char *p[] = { "a/b/c/d.txt" };
		write_tar("deep.tar", p, 1);
	}
	{
		/* UTF-8 BMP characters in pathname.  bundle_path_is_safe
		 * treats path bytes opaquely so this should pass; the value
		 * is in exercising archive_entry_pathname_utf8 too. */
		const char *p[] = { "caf\xc3\xa9/r\xc3\xa9sum\xc3\xa9.txt" };
		write_tar("utf8.tar", p, 1);
	}
	{
		const char *p[] = { "../../etc/passwd" };
		write_tar("traversal.tar", p, 1);
	}
	{
		const char *p[] = { "/tmp/anywhere" };
		write_tar("absolute.tar", p, 1);
	}

	fprintf(stderr, "wrote 6 seeds to %s/\n", CORPUS_DIR);
	return 0;
}
