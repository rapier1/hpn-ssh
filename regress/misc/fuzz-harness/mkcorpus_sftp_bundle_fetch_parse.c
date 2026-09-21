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

/* mkcorpus_sftp_bundle_fetch_parse.c - seed corpus for
 * sftp_bundle_fetch_parse_fuzz.
 *
 * Emits post-framing hpn-bundle-fetch@hpnssh.org request bodies to
 * ./sftp_bundle_fetch_parse_corpus/:
 *
 *   u32  flags
 *   u32  n_paths
 *   for i in [0, n_paths): cstring path   (u32 length + bytes, no NUL)
 *
 * Each seed sits next to one of the decode's branches: the minimal
 * valid request, a multi-path list, an empty path, a count larger than
 * the paths supplied, and bytes left over after the last path.
 *
 * Integers are big-endian per the SSH wire format, written by hand so
 * the generator has no dependencies. Built with plain CFLAGS by the
 * Makefile's corpus target. */

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#define CORPUS_DIR "sftp_bundle_fetch_parse_corpus"

/* Grow-on-demand byte buffer for hand-assembling a wire blob. */
struct wb {
	unsigned char *p;
	size_t         len, cap;
};

static void
wb_need(struct wb *b, size_t extra)
{
	if (b->len + extra <= b->cap)
		return;
	size_t ncap = b->cap ? b->cap * 2 : 64;
	while (ncap < b->len + extra)
		ncap *= 2;
	b->p = realloc(b->p, ncap);
	if (b->p == NULL)
		err(1, "realloc");
	b->cap = ncap;
}

static void
wb_u32(struct wb *b, uint32_t v)
{
	wb_need(b, 4);
	b->p[b->len++] = (v >> 24) & 0xff;
	b->p[b->len++] = (v >> 16) & 0xff;
	b->p[b->len++] = (v >>  8) & 0xff;
	b->p[b->len++] =  v        & 0xff;
}

/* cstring = u32 length prefix + raw bytes (no NUL on the wire). */
static void
wb_cstring(struct wb *b, const char *s)
{
	size_t n = strlen(s);
	wb_u32(b, (uint32_t)n);
	wb_need(b, n);
	memcpy(b->p + b->len, s, n);
	b->len += n;
}

static void
wb_raw(struct wb *b, const void *d, size_t n)
{
	wb_need(b, n);
	memcpy(b->p + b->len, d, n);
	b->len += n;
}

static void
dump(const char *name, struct wb *b)
{
	char path[256];
	snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, name);
	FILE *f = fopen(path, "wb");
	if (f == NULL)
		err(1, "fopen %s", path);
	if (b->len && fwrite(b->p, b->len, 1, f) != 1)
		err(1, "fwrite %s", path);
	fclose(f);
	free(b->p);
	b->p = NULL; b->len = b->cap = 0;
}

int
main(void)
{
	if (mkdir(CORPUS_DIR, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir " CORPUS_DIR);

	struct wb b = { 0, 0, 0 };

	/* one.bin - flags=0, one path. */
	wb_u32(&b, 0); wb_u32(&b, 1); wb_cstring(&b, "/home/user/file.dat");
	dump("one.bin", &b);

	/* multi.bin - flags set, three paths. */
	wb_u32(&b, 0x1); wb_u32(&b, 3);
	wb_cstring(&b, "a.txt"); wb_cstring(&b, "dir/b.txt");
	wb_cstring(&b, "/abs/c.txt");
	dump("multi.bin", &b);

	/* emptypath.bin - one zero-length path (length-0 cstring). */
	wb_u32(&b, 0); wb_u32(&b, 1); wb_cstring(&b, "");
	dump("emptypath.bin", &b);

	/* short.bin - claims 4 paths, supplies 1 (short-read branch). */
	wb_u32(&b, 0); wb_u32(&b, 4); wb_cstring(&b, "only-one");
	dump("short.bin", &b);

	/* trailing.bin - claims 1 path, then extra bytes after it
	 * (parser stops at n_paths; leftover is ignored - exercises that). */
	wb_u32(&b, 0); wb_u32(&b, 1); wb_cstring(&b, "p");
	wb_raw(&b, "\xde\xad\xbe\xef", 4);
	dump("trailing.bin", &b);

	/* zero.bin - n_paths of 0, rejected by the count bound. */
	wb_u32(&b, 0); wb_u32(&b, 0);
	dump("zero.bin", &b);

	/* huge.bin - n_paths of 0xffffffff, rejected by the count bound
	 * before it can drive the allocation. */
	wb_u32(&b, 0); wb_u32(&b, 0xffffffff); wb_cstring(&b, "p");
	dump("huge.bin", &b);

	/* badlen.bin - a cstring length prefix far beyond the bytes
	 * present, for sshbuf's bounds check. */
	wb_u32(&b, 0); wb_u32(&b, 1); wb_u32(&b, 0xffffffff);
	wb_raw(&b, "pq", 2);
	dump("badlen.bin", &b);

	fprintf(stderr, "wrote 8 seeds to %s/\n", CORPUS_DIR);
	return 0;
}
