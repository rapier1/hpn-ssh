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
 * mkcorpus_sftp_dtree_read.c - generate the seed corpus for
 * sftp_dtree_read_fuzz.
 *
 * Writes hpn-dtree-read reply message bodies to ./sftp_dtree_read_corpus/.
 * The records are emitted through the product's own encoder,
 * sftp_tree_put_record, so every seed starts from framing the parser
 * accepts and the fuzzer mutates from there. Seeds:
 *
 *   data-mixed.bin    - one DATA message with all five record types under
 *                       nested paths, the shape a real batch has
 *   data-one.bin      - a DATA message carrying a single REG record
 *   batch-end.bin     - BATCH_END with no records
 *   end.bin           - END with no records
 *   long-path.bin     - a record whose path is one byte under PATH_MAX,
 *                       the validator's length limit
 *   dotdot.bin        - a record with a ".." component, which the
 *                       validator refuses
 *   bad-version.bin   - a DATA message with an unknown version byte
 *   empty-data.bin    - DATA with a zero record count
 *   marker-records.bin - END carrying a record, which the read refuses
 *
 * Built and invoked by regress/misc/fuzz-harness/Makefile's `corpus`
 * target.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-tree.h"

#define CORPUS_DIR "sftp_dtree_read_corpus"

/* Start a message body: version, kind and the record count. The count is
 * written as given, so a seed can lie about it. */
static struct sshbuf *
message(u_char version, u_char kind, uint32_t count)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		err(1, "sshbuf_new");
	if ((r = sshbuf_put_u8(msg, version)) != 0 ||
	    (r = sshbuf_put_u8(msg, kind)) != 0 ||
	    (r = sshbuf_put_u32(msg, count)) != 0)
		errx(1, "compose header: %s", ssh_err(r));
	return msg;
}

/* Append one record with plausible attributes for its type. */
static void
record(struct sshbuf *msg, const char *relpath, u_char rectype,
    uint64_t size, uint32_t perm, uint32_t status)
{
	Attrib attrs;
	int r;

	attrib_clear(&attrs);
	attrs.flags = SSH2_FILEXFER_ATTR_SIZE | SSH2_FILEXFER_ATTR_PERMISSIONS |
	    SSH2_FILEXFER_ATTR_ACMODTIME;
	attrs.size = size;
	attrs.perm = perm;
	attrs.atime = 1700000000;
	attrs.mtime = 1700000000;
	if ((r = sftp_tree_put_record(msg, relpath, rectype, &attrs,
	    status)) != 0)
		errx(1, "encode record %s: %s", relpath, ssh_err(r));
}

/* Write the message body to a seed file and free it. */
static void
seed(const char *name, struct sshbuf *msg)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, name);
	if ((f = fopen(path, "wb")) == NULL)
		err(1, "fopen %s", path);
	if (sshbuf_len(msg) > 0 &&
	    fwrite(sshbuf_ptr(msg), sshbuf_len(msg), 1, f) != 1)
		err(1, "fwrite %s", path);
	if (fclose(f) != 0)
		err(1, "fclose %s", path);
	sshbuf_free(msg);
}

int
main(void)
{
	struct sshbuf *msg;
	char longpath[PATH_MAX];

	if (mkdir(CORPUS_DIR, 0777) != 0 && errno != EEXIST)
		err(1, "mkdir %s", CORPUS_DIR);

	msg = message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_DATA, 6);
	record(msg, "dir", HPN_DTREE_REC_DIR, 4096, 0755, 0);
	record(msg, "dir/file.dat", HPN_DTREE_REC_REG, 1048576, 0644, 0);
	record(msg, "dir/link", HPN_DTREE_REC_SYMLINK, 8, 0777, 0);
	record(msg, "dir/fifo", HPN_DTREE_REC_OTHER, 0, 0600, 0);
	record(msg, "dir/sub", HPN_DTREE_REC_DIR, 4096, 0700, 0);
	record(msg, "dir/sub/locked", HPN_DTREE_REC_ERROR, 0, 0,
	    SSH2_FX_PERMISSION_DENIED);
	seed("data-mixed.bin", msg);

	msg = message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_DATA, 1);
	record(msg, "one.txt", HPN_DTREE_REC_REG, 12, 0644, 0);
	seed("data-one.bin", msg);

	seed("batch-end.bin",
	    message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_BATCH_END, 0));
	seed("end.bin", message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_END, 0));

	/* One byte under the validator's PATH_MAX limit, as "a/a/a/...". */
	memset(longpath, 'a', sizeof(longpath) - 2);
	longpath[sizeof(longpath) - 2] = '\0';
	for (size_t i = 1; i < sizeof(longpath) - 2; i += 2)
		longpath[i] = '/';
	msg = message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_DATA, 1);
	record(msg, longpath, HPN_DTREE_REC_REG, 1, 0644, 0);
	seed("long-path.bin", msg);

	msg = message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_DATA, 1);
	record(msg, "dir/../escape", HPN_DTREE_REC_REG, 1, 0644, 0);
	seed("dotdot.bin", msg);

	msg = message(HPN_DTREE_VERSION + 1, HPN_DTREE_CHUNK_DATA, 1);
	record(msg, "future.txt", HPN_DTREE_REC_REG, 1, 0644, 0);
	seed("bad-version.bin", msg);

	seed("empty-data.bin",
	    message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_DATA, 0));

	msg = message(HPN_DTREE_VERSION, HPN_DTREE_CHUNK_END, 1);
	record(msg, "stray.txt", HPN_DTREE_REC_REG, 1, 0644, 0);
	seed("marker-records.bin", msg);

	return 0;
}
