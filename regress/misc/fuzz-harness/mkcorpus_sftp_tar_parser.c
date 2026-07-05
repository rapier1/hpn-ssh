/*
 * mkcorpus_sftp_tar_parser.c - generate seed corpus for
 * sftp_tar_parser_fuzz by driving the in-tree bundle-codec *writer*
 * (sftp-hpn-tar.c) to emit valid streams.
 *
 * The codec is a length-prefixed binary record stream, not tar (see
 * sftp-hpn-tar.c).  Parser and writer are a matched pair, so a stream
 * the writer produces is exactly the shape the parser expects - the
 * ideal starting point from which the fuzzer mutates.  Building the
 * corpus this way also smoke-exercises the writer end-to-end with a
 * spread of structured inputs (empty file, sub-record and record-sized
 * files, a long path that stresses the u16 path_len field and the
 * writer's max-path check, several files in one stream), so the two
 * codec halves stay in sync as seeds.
 *
 * The writer opens and reads real files, so we stage temp files under a
 * scratch dir, pack them, capture the produced bytes, and drop each
 * stream as a seed in ./sftp_tar_parser_corpus/.
 *
 * Built with plain CFLAGS (no sanitizer/fuzzer) and links
 * ../../../sftp-hpn-tar.o.  Invoked by the Makefile `corpus` target and
 * by oss-fuzz's build.sh.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <time.h>

#include "sftp-hpn-tar.h"

#define CORPUS_DIR "sftp_tar_parser_corpus"
#define SCRATCH    CORPUS_DIR "/.scratch"

struct file_spec {
	const char *name;      /* archive path (also the on-disk basename) */
	size_t      size;      /* bytes of 'A' to write */
	mode_t      mode;
};

/* Write 'sz' bytes of 0x41 to SCRATCH/basename-of(name); return full path
 * in 'out'.  The archive path may contain '/', so derive the on-disk name
 * from a per-file counter to keep the scratch dir flat. */
static void
stage_file(int idx, size_t sz, char *out, size_t outlen)
{
	snprintf(out, outlen, "%s/f%d", SCRATCH, idx);
	int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		err(1, "open %s", out);
	static const char blk[4096] = { [0 ... 4095] = 'A' };
	size_t left = sz;
	while (left > 0) {
		size_t n = left < sizeof(blk) ? left : sizeof(blk);
		if (write(fd, blk, n) != (ssize_t)n)
			err(1, "write %s", out);
		left -= n;
	}
	close(fd);
}

/* Pack the given specs into one tar stream and write it as a seed. */
static void
write_seed(const char *seed, const struct file_spec *specs, int n)
{
	struct sftp_hpn_tar_writer *w = sftp_hpn_tar_writer_new();
	if (w == NULL)
		errx(1, "writer_new");

	char disk[512];
	for (int i = 0; i < n; i++) {
		stage_file(i, specs[i].size, disk, sizeof(disk));
		if (sftp_hpn_tar_writer_add_file(w, disk, specs[i].name,
		    specs[i].mode, (uint64_t)specs[i].size, (time_t)1000000000)
		    < 0) {
			/* A spec the writer legitimately rejects (e.g. an
			 * over-long name) is not seed-worthy; skip the whole
			 * seed rather than emit a truncated stream. */
			fprintf(stderr, "  %s: writer rejected \"%s\", skipping seed\n",
			    seed, specs[i].name);
			sftp_hpn_tar_writer_free(w);
			return;
		}
	}
	sftp_hpn_tar_writer_finish(w);

	char path[512];
	snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, seed);
	FILE *f = fopen(path, "wb");
	if (f == NULL)
		err(1, "fopen %s", path);

	u_char buf[8192];
	for (;;) {
		ssize_t got = sftp_hpn_tar_writer_pack_next(w, buf, sizeof(buf));
		if (got < 0)
			errx(1, "pack_next: %s",
			    sftp_hpn_tar_writer_error(w));
		if (got == 0)
			break;   /* EOA + trailing zero blocks emitted */
		if (fwrite(buf, (size_t)got, 1, f) != 1)
			err(1, "fwrite %s", path);
	}
	fclose(f);
	sftp_hpn_tar_writer_free(w);
}

int
main(void)
{
	if (mkdir(CORPUS_DIR, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir " CORPUS_DIR);
	if (mkdir(SCRATCH, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir " SCRATCH);

	/* empty.bin - a single zero-length entry (header, no data blocks). */
	const struct file_spec empty[] = { { "empty", 0, 0644 } };
	write_seed("empty.bin", empty, 1);

	/* small.bin - one small file (13 data bytes; the codec length-
	 * prefixes the data, no block padding). */
	const struct file_spec small[] = { { "small.txt", 13, 0644 } };
	write_seed("small.bin", small, 1);

	/* r512.bin - one exactly-512-byte file: no block boundary exists in
	 * this codec, but 512 is a common chunking size worth a seed. */
	const struct file_spec block[] = { { "block.dat", 512, 0600 } };
	write_seed("r512.bin", block, 1);

	/* longname.bin - a > 100-byte path to stress the u16 path_len field
	 * and the writer's max-path handling (the codec stores the path
	 * whole; there is no name/prefix split). */
	const struct file_spec longname[] = {
	    { "a/very/deep/directory/tree/that/exceeds/one/hundred/"
	      "characters/so/the/long/path/handling/is/exercised/file.dat",
	      64, 0644 }
	};
	write_seed("longname.bin", longname, 1);

	/* multi.bin - several entries in one stream (inter-entry state). */
	const struct file_spec multi[] = {
	    { "dir/a", 100, 0644 },
	    { "dir/b", 0, 0644 },
	    { "dir/sub/c", 4096, 0755 },
	};
	write_seed("multi.bin", multi, 3);

	/* Clean up scratch files (best effort). */
	for (int i = 0; i < 8; i++) {
		char p[512];
		snprintf(p, sizeof(p), "%s/f%d", SCRATCH, i);
		unlink(p);
	}
	rmdir(SCRATCH);

	fprintf(stderr, "wrote seeds to %s/\n", CORPUS_DIR);
	return 0;
}
