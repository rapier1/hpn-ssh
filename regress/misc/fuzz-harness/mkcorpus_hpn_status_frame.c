/*
 * Seed-corpus generator for hpn_status_frame_fuzz: emits a handful of
 * well-formed frame streams through the real encoders (which also gives
 * the encoders a smoke test), each prefixed with the chunk-size byte the
 * fuzz harness consumes.  Usage: mkcorpus_hpn_status_frame <outdir>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hpn-status-frame.h"

static void
write_seed(const char *dir, const char *name, const u_char *buf, size_t len)
{
	char path[1024];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if ((f = fopen(path, "w")) == NULL) {
		perror(path);
		exit(1);
	}
	if (fwrite(buf, 1, len, f) != len) {
		perror("fwrite");
		exit(1);
	}
	fclose(f);
	printf("%s: %zu bytes\n", path, len);
}

int
main(int argc, char **argv)
{
	u_char buf[4096];
	u_char longpath[1024];
	size_t o;
	struct hpns_hello h;
	struct hpns_progress p;
	struct hpns_end e;
	struct hpns_filefail ff;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <outdir>\n", argv[0]);
		return 1;
	}

	memset(&h, 0, sizeof(h));
	h.proto_ver = HPNS_VERSION;
	h.caps = 0;
	h.total_bytes = 2147483648ULL;
	h.total_files = 60;
	h.streams = 4;

	memset(&p, 0, sizeof(p));
	p.bytes_done = 1073741824ULL;
	p.bytes_total = 2147483648ULL;
	p.rate_bps = 250000000ULL;
	p.eta_sec = 4;
	p.files_done = 30;
	p.files_total = 60;
	p.workers_active = 4;
	p.workers_stalled = 1;
	p.flags = HPNS_F_VERIFY;

	memset(&e, 0, sizeof(e));
	e.bytes_done = 2147483648ULL;
	e.files_done = 60;
	e.files_failed = 0;
	e.ok = 1;

	/* full session: HELLO, two PROGRESS, END; chunk size 7 to force
	 * frames to straddle feed boundaries */
	o = 0;
	buf[o++] = 7;
	o += hpns_encode_hello(buf + o, &h);
	o += hpns_encode_progress(buf + o, &p);
	p.bytes_done = p.bytes_total;
	p.eta_sec = 0;
	o += hpns_encode_progress(buf + o, &p);
	o += hpns_encode_end(buf + o, &e);
	write_seed(argv[1], "session", buf, o);

	/* single frames, byte-at-a-time feed */
	o = 0;
	buf[o++] = 1;
	o += hpns_encode_hello(buf + o, &h);
	write_seed(argv[1], "hello", buf, o);

	o = 0;
	buf[o++] = 1;
	o += hpns_encode_progress(buf + o, &p);
	write_seed(argv[1], "progress", buf, o);

	/* truncated frame (valid header, missing payload tail) */
	o = 0;
	buf[o++] = 3;
	o += hpns_encode_end(buf + o, &e);
	write_seed(argv[1], "truncated", buf, o - 5);

	/* failing session: HELLO, PROGRESS, two FILEFAILs, END(ok=0).  The
	 * verify path is UTF-8 (non-Latin) to seed the byte-transparent case. */
	memset(&ff, 0, sizeof(ff));
	o = 0;
	buf[o++] = 7;
	o += hpns_encode_hello(buf + o, &h);
	o += hpns_encode_progress(buf + o, &p);
	ff.kind = HPNS_FF_VERIFY;
	ff.path = (const u_char *)"/data/\346\227\245\346\234\254\350\252\236.bin";
	ff.path_len = (uint16_t)strlen((const char *)ff.path);
	o += hpns_encode_filefail(buf + o, &ff);
	ff.kind = HPNS_FF_TRANSFER;
	ff.path = (const u_char *)"/data/incomplete.tar";
	ff.path_len = (uint16_t)strlen((const char *)ff.path);
	o += hpns_encode_filefail(buf + o, &ff);
	e.files_failed = 1;
	e.ok = 0;
	o += hpns_encode_end(buf + o, &e);
	write_seed(argv[1], "session-failed", buf, o);

	/* single FILEFAIL, byte-at-a-time */
	o = 0;
	buf[o++] = 1;
	ff.kind = HPNS_FF_VERIFY;
	ff.path = (const u_char *)"file.dat";
	ff.path_len = 8;
	o += hpns_encode_filefail(buf + o, &ff);
	write_seed(argv[1], "filefail", buf, o);

	/* empty path (path_len 0, path NULL) */
	o = 0;
	buf[o++] = 1;
	ff.kind = HPNS_FF_TRANSFER;
	ff.path = NULL;
	ff.path_len = 0;
	o += hpns_encode_filefail(buf + o, &ff);
	write_seed(argv[1], "filefail-empty", buf, o);

	/* over-cap path: encoder must clamp to HPNS_FILEFAIL_MAXPATH so the
	 * emitted frame stays parseable (caller sets HPNS_FF_TRUNCATED) */
	memset(longpath, 'A', sizeof(longpath));
	o = 0;
	buf[o++] = 5;
	ff.kind = HPNS_FF_VERIFY | HPNS_FF_TRUNCATED;
	ff.path = longpath;
	ff.path_len = (uint16_t)sizeof(longpath);
	o += hpns_encode_filefail(buf + o, &ff);
	write_seed(argv[1], "filefail-clamped", buf, o);

	return 0;
}
