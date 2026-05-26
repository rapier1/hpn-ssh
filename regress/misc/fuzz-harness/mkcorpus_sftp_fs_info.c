/*
 * mkcorpus_sftp_fs_info.c — generate seed corpus for sftp_fs_info_fuzz.
 *
 * Writes a handful of small wire-format blobs to ./sftp_fs_info_corpus/.
 * Each seed is a valid (or boundary-valid) post-framing payload for the
 * hpn-fs-info@hpnssh.org reply:
 *
 *   cstring fs_type     (u32 length + bytes, no NUL)
 *   u64     stripe_size
 *   u32     stripe_count
 *   u64     block_size
 *
 * Seeds:
 *   lustre.bin     — fs_type="lustre", stripe_size=1MiB,
 *                    stripe_count=8, block_size=1MiB
 *   ext4.bin       — fs_type="ext4", zeros for stripe fields,
 *                    block_size=4KiB
 *   gpfs.bin       — fs_type="gpfs", zeros for stripe fields,
 *                    block_size=1MiB
 *   empty.bin      — fs_type="" (length-zero cstring)
 *   maxname.bin    — fs_type set to a 31-byte string (one less than
 *                    the parser's strlcpy limit of 32, so the
 *                    successful-parse branch still fires)
 *
 * All integers are big-endian per SSH wire format.  We write the
 * bytes by hand rather than pulling in sshbuf to keep this generator
 * dependency-free and reviewable.
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

#define CORPUS_DIR "sftp_fs_info_corpus"

static void
put_u32(unsigned char *p, uint32_t v)
{
	p[0] = (v >> 24) & 0xff;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >>  8) & 0xff;
	p[3] =  v        & 0xff;
}

static void
put_u64(unsigned char *p, uint64_t v)
{
	put_u32(p,     (uint32_t)(v >> 32));
	put_u32(p + 4, (uint32_t)(v & 0xffffffffu));
}

static void
write_blob(const char *name, const char *fs_type,
    uint64_t stripe_size, uint32_t stripe_count, uint64_t block_size)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, name);

	size_t ft_len = strlen(fs_type);
	/* 4 (cstring length) + ft_len + 8 (u64) + 4 (u32) + 8 (u64) */
	size_t total = 4 + ft_len + 8 + 4 + 8;

	unsigned char *buf = malloc(total);
	if (buf == NULL)
		err(1, "malloc");

	unsigned char *p = buf;
	put_u32(p, (uint32_t)ft_len);          p += 4;
	memcpy(p, fs_type, ft_len);            p += ft_len;
	put_u64(p, stripe_size);               p += 8;
	put_u32(p, stripe_count);              p += 4;
	put_u64(p, block_size);                p += 8;

	FILE *f = fopen(path, "wb");
	if (f == NULL)
		err(1, "fopen %s", path);
	if (fwrite(buf, total, 1, f) != 1)
		err(1, "fwrite %s", path);
	fclose(f);
	free(buf);
}

int main(void)
{
	if (mkdir(CORPUS_DIR, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir " CORPUS_DIR);

	write_blob("lustre.bin",  "lustre", 1048576ull, 8, 1048576ull);
	write_blob("ext4.bin",    "ext4",   0,         0, 4096);
	write_blob("gpfs.bin",    "gpfs",   0,         0, 1048576ull);
	write_blob("empty.bin",   "",       0,         0, 0);
	write_blob("maxname.bin", "A_LONG_FILESYSTEM_TYPE_NAME_31",
	    0, 0, 65536);

	fprintf(stderr, "wrote 5 seeds to %s/\n", CORPUS_DIR);
	return 0;
}
