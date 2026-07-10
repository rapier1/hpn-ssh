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
 * hpn3scp-proto.c - control protocol emit/parse (see hpn3scp-proto.h).
 */

#include "includes.h"

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "hpn3scp-proto.h"

static FILE *proto_out = NULL;
static int human_mode = 0;

void
proto_init(FILE *out)
{
	proto_out = out;
}

void
proto_set_human(int on)
{
	human_mode = on;
}

int
proto_human(void)
{
	return human_mode;
}

static FILE *
po(void)
{
	return proto_out != NULL ? proto_out : stdout;
}

/*
 * Wire-safe byte set for percent-encoding.  Explicit ASCII test, NOT the
 * locale-sensitive isalnum(): the protocol must read identically under any
 * LC_*.  ':' '/' '@' '+' '.' '_' '-' stay literal so fingerprints, hosts,
 * and paths remain human-readable; space, '=', '%', newline, control, and
 * high-bit bytes are all encoded so no delimiter or multibyte sequence ever
 * appears raw.
 */
static int
pct_safe(u_char c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '.' || c == '_' || c == '-' || c == ':' ||
	    c == '/' || c == '@' || c == '+');
}

/* encode exactly inlen bytes (may contain NUL/high-bit); truncates to fit out */
static void
pct_encode_n(char *out, size_t outlen, const u_char *in, size_t inlen)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t i, o = 0;

	if (outlen == 0)
		return;
	for (i = 0; i < inlen; i++) {
		u_char c = in[i];

		if (pct_safe(c)) {
			if (o + 1 >= outlen)
				break;
			out[o++] = (char)c;
		} else {
			if (o + 3 >= outlen)
				break;
			out[o++] = '%';
			out[o++] = hex[c >> 4];
			out[o++] = hex[c & 0x0f];
		}
	}
	out[o] = '\0';
}

/* NUL-terminated convenience wrapper over pct_encode_n */
static void
pct_encode(char *out, size_t outlen, const char *in)
{
	pct_encode_n(out, outlen, (const u_char *)in, strlen(in));
}

static int
hexval(u_char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static void
pct_decode(char *out, size_t outlen, const char *in)
{
	const u_char *p = (const u_char *)in;
	size_t o = 0;

	if (outlen == 0)
		return;
	while (*p != '\0' && o + 1 < outlen) {
		/* short-circuit: p[2] is only read when p[1] is a hex digit,
		 * so it is at most the NUL terminator - never out of bounds */
		if (*p == '%' && hexval(p[1]) >= 0 && hexval(p[2]) >= 0) {
			out[o++] = (char)((hexval(p[1]) << 4) | hexval(p[2]));
			p += 3;
		} else {
			out[o++] = (char)*p++;
		}
	}
	out[o] = '\0';
}

/* --- events out --- */

void
proto_emit_phase(const char *name)
{
	char enc[128];

	if (human_mode) {
		debug("phase %s", name);	/* visible under -v */
		return;
	}
	pct_encode(enc, sizeof(enc), name);
	fprintf(po(), "EVENT phase name=%s\n", enc);
	fflush(po());
}

void
proto_emit_resolved(const char *src, const char *dst, int streams)
{
	char es[512], ed[512];

	if (human_mode) {
		debug("%s -> %s (%d streams)", src, dst, streams);
		return;
	}
	pct_encode(es, sizeof(es), src);
	pct_encode(ed, sizeof(ed), dst);
	fprintf(po(), "EVENT resolved src=%s dst=%s streams=%d\n",
	    es, ed, streams);
	fflush(po());
}

void
proto_emit_need_decision_hostkey(const char *fp, const char *sshfp,
    const char *token)
{
	char efp[256], esf[64], etok[256];

	if (human_mode) {
		/* human-mode decisions are prompted interactively before this
		 * point; reaching here means no prompt was possible */
		fprintf(stderr, "hpn3scp: host key %s needs confirmation "
		    "(sshfp: %s)\n", fp, sshfp);
		return;
	}
	pct_encode(efp, sizeof(efp), fp);
	pct_encode(esf, sizeof(esf), sshfp);
	pct_encode(etok, sizeof(etok), token);
	fprintf(po(), "EVENT need_decision kind=accept_hostkey fp=%s "
	    "sshfp=%s token=%s\n", efp, esf, etok);
	fflush(po());
}

void
proto_emit_need_decision_identity(const char *reason)
{
	char er[256];

	if (human_mode) {
		fprintf(stderr, "hpn3scp: an identity is needed: %s\n", reason);
		return;
	}
	pct_encode(er, sizeof(er), reason);
	fprintf(po(), "EVENT need_decision kind=use_identity reason=%s\n", er);
	fflush(po());
}

void
proto_emit_progress(uint64_t bytes, uint64_t total, uint64_t rate,
    uint64_t rate_inst, uint32_t eta, uint32_t files_done,
    uint32_t files_total, uint16_t workers, uint16_t stalled,
    int verifying, int resuming)
{
	if (human_mode)
		return;		/* the local meter renders progress instead */
	fprintf(po(), "EVENT progress bytes=%" PRIu64 " total=%" PRIu64
	    " rate=%" PRIu64 " rate_inst=%" PRIu64 " eta=%" PRIu32
	    " files_done=%" PRIu32 " files_total=%" PRIu32
	    " workers=%u stalled=%u verifying=%d resuming=%d\n",
	    bytes, total, rate, rate_inst, eta, files_done, files_total,
	    (unsigned)workers, (unsigned)stalled, verifying ? 1 : 0,
	    resuming ? 1 : 0);
	fflush(po());
}

void
proto_emit_warning(const char *msg)
{
	char em[512];

	if (human_mode) {
		fprintf(stderr, "hpn3scp: warning: %s\n", msg);
		return;
	}
	pct_encode(em, sizeof(em), msg);
	fprintf(po(), "EVENT warning msg=%s\n", em);
	fflush(po());
}

void
proto_emit_error(const char *msg)
{
	char em[512];

	if (human_mode) {
		fprintf(stderr, "hpn3scp: %s\n", msg);
		return;
	}
	pct_encode(em, sizeof(em), msg);
	fprintf(po(), "EVENT error msg=%s\n", em);
	fflush(po());
}

void
proto_emit_file_fail(unsigned int kind, const unsigned char *path,
    size_t path_len)
{
	char enc[2048];		/* >= 3 * max frame path (509) + 1, all escaped */

	if (human_mode)
		return;		/* the source's stderr already shows the detail */
	pct_encode_n(enc, sizeof(enc), path, path_len);
	fprintf(po(), "EVENT file_fail kind=%u path=%s\n", kind, enc);
	fflush(po());
}

void
proto_emit_done(int ok, int exit_status, unsigned files,
    unsigned verify_failed, unsigned transfer_failed)
{
	if (human_mode)
		return;		/* the exit status says it for a human */
	fprintf(po(), "EVENT done ok=%d exit=%d files=%u verify_failed=%u "
	    "transfer_failed=%u\n", ok ? 1 : 0, exit_status, files,
	    verify_failed, transfer_failed);
	fflush(po());
}

/* --- decisions in --- */

int
proto_read_decision(FILE *in, struct proto_decision *d)
{
	char line[2048], *tok, *eq, *save = NULL;

	memset(d, 0, sizeof(*d));
	if (fgets(line, sizeof(line), in) == NULL)
		return -1;			/* EOF or read error */
	line[strcspn(line, "\r\n")] = '\0';

	tok = strtok_r(line, " ", &save);
	if (tok == NULL || strcmp(tok, "DECISION") != 0) {
		d->kind = PROTO_DEC_NONE;	/* not ours; caller ignores */
		return 0;
	}
	if ((tok = strtok_r(NULL, " ", &save)) == NULL) {
		d->kind = PROTO_DEC_UNKNOWN;
		return 0;
	}
	if (strcmp(tok, "accept_hostkey") == 0)
		d->kind = PROTO_DEC_ACCEPT_HOSTKEY;
	else if (strcmp(tok, "use_identity") == 0)
		d->kind = PROTO_DEC_USE_IDENTITY;
	else if (strcmp(tok, "cancel") == 0)
		d->kind = PROTO_DEC_CANCEL;
	else {
		d->kind = PROTO_DEC_UNKNOWN;
		return 0;
	}

	/* key=value fields; base-10 strtol is locale-independent */
	while ((tok = strtok_r(NULL, " ", &save)) != NULL) {
		if ((eq = strchr(tok, '=')) == NULL)
			continue;
		*eq++ = '\0';
		if (strcmp(tok, "token") == 0)
			pct_decode(d->token, sizeof(d->token), eq);
		else if (strcmp(tok, "accept") == 0)
			d->accept = (int)strtol(eq, NULL, 10);
		else if (strcmp(tok, "path") == 0)
			pct_decode(d->path, sizeof(d->path), eq);
	}
	return 0;
}
