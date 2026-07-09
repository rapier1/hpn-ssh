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
 * hpn-status-frame.c - HPN status-relay frame encode/decode + parser.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * See hpn-status-frame.h for the wire format and contract, and
 * hpn-status-relay-design.md for the full design.  Deliberately depends
 * on libc only: the fuzz harness links this object directly against the
 * parser without pulling in the rest of the tree.
 */

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include "sshbuf.h"	/* PEEK/POKE big-endian buffer accessors */
#include "hpn-status-frame.h"

/* write the 8-byte header; returns HPNS_HDR_LEN */
static size_t
hpns_put_hdr(u_char *buf, u_char type, uint16_t plen)
{
	POKE_U32(buf, HPNS_MAGIC);
	buf[4] = HPNS_VERSION;
	buf[5] = type;
	POKE_U16(buf + 6, plen);
	return HPNS_HDR_LEN;
}

/* encode a HELLO frame into buf (>= HPNS_HDR_LEN + HPNS_HELLO_LEN);
 * returns the total frame length */
size_t
hpns_encode_hello(u_char *buf, const struct hpns_hello *h)
{
	size_t o = hpns_put_hdr(buf, HPNS_T_HELLO, HPNS_HELLO_LEN);

	buf[o] = h->proto_ver;
	POKE_U32(buf + o + 1, h->caps);
	POKE_U64(buf + o + 5, h->total_bytes);
	POKE_U32(buf + o + 13, h->total_files);
	POKE_U32(buf + o + 17, h->streams);
	return o + HPNS_HELLO_LEN;
}

/* encode a PROGRESS frame; returns the total frame length */
size_t
hpns_encode_progress(u_char *buf, const struct hpns_progress *p)
{
	size_t o = hpns_put_hdr(buf, HPNS_T_PROGRESS, HPNS_PROGRESS_LEN);

	POKE_U64(buf + o, p->bytes_done);
	POKE_U64(buf + o + 8, p->bytes_total);
	POKE_U64(buf + o + 16, p->rate_bps);
	POKE_U32(buf + o + 24, p->eta_sec);
	POKE_U32(buf + o + 28, p->files_done);
	POKE_U32(buf + o + 32, p->files_total);
	POKE_U16(buf + o + 36, p->workers_active);
	POKE_U16(buf + o + 38, p->workers_stalled);
	POKE_U16(buf + o + 40, p->flags);
	POKE_U16(buf + o + 42, 0);		/* pad */
	return o + HPNS_PROGRESS_LEN;
}

/* encode an END frame; returns the total frame length */
size_t
hpns_encode_end(u_char *buf, const struct hpns_end *e)
{
	size_t o = hpns_put_hdr(buf, HPNS_T_END, HPNS_END_LEN);

	POKE_U64(buf + o, e->bytes_done);
	POKE_U32(buf + o + 8, e->files_done);
	POKE_U32(buf + o + 12, e->files_failed);
	buf[o + 16] = e->ok;
	return o + HPNS_END_LEN;
}

/*
 * encode a FILEFAIL frame; path_len is clamped to HPNS_FILEFAIL_MAXPATH so a
 * caller bug can never emit an over-cap (unparseable) frame - the caller sets
 * HPNS_FF_TRUNCATED in kind when it clips.  buf must be >= HPNS_HDR_LEN +
 * HPNS_FILEFAIL_HDR + path_len.  Returns the total frame length.
 */
size_t
hpns_encode_filefail(u_char *buf, const struct hpns_filefail *ff)
{
	uint16_t n = ff->path_len;
	size_t o;

	if (n > HPNS_FILEFAIL_MAXPATH)
		n = HPNS_FILEFAIL_MAXPATH;
	o = hpns_put_hdr(buf, HPNS_T_FILEFAIL,
	    (uint16_t)(HPNS_FILEFAIL_HDR + n));
	buf[o] = ff->kind;
	POKE_U16(buf + o + 1, n);
	if (n > 0 && ff->path != NULL)
		memcpy(buf + o + HPNS_FILEFAIL_HDR, ff->path, n);
	return o + HPNS_FILEFAIL_HDR + n;
}

/* strict decoder: payload length must match exactly; -1 on mismatch */
int
hpns_decode_hello(const u_char *p, uint16_t plen, struct hpns_hello *h)
{
	if (plen != HPNS_HELLO_LEN)
		return -1;
	h->proto_ver = p[0];
	h->caps = PEEK_U32(p + 1);
	h->total_bytes = PEEK_U64(p + 5);
	h->total_files = PEEK_U32(p + 13);
	h->streams = PEEK_U32(p + 17);
	return 0;
}

/* strict decoder: payload length must match exactly; -1 on mismatch */
int
hpns_decode_progress(const u_char *p, uint16_t plen, struct hpns_progress *o)
{
	if (plen != HPNS_PROGRESS_LEN)
		return -1;
	o->bytes_done = PEEK_U64(p);
	o->bytes_total = PEEK_U64(p + 8);
	o->rate_bps = PEEK_U64(p + 16);
	o->eta_sec = PEEK_U32(p + 24);
	o->files_done = PEEK_U32(p + 28);
	o->files_total = PEEK_U32(p + 32);
	o->workers_active = PEEK_U16(p + 36);
	o->workers_stalled = PEEK_U16(p + 38);
	o->flags = PEEK_U16(p + 40);
	return 0;
}

/* strict decoder: payload length must match exactly; -1 on mismatch */
int
hpns_decode_end(const u_char *p, uint16_t plen, struct hpns_end *e)
{
	if (plen != HPNS_END_LEN)
		return -1;
	e->bytes_done = PEEK_U64(p);
	e->files_done = PEEK_U32(p + 8);
	e->files_failed = PEEK_U32(p + 12);
	e->ok = p[16];
	return 0;
}

/*
 * strict decoder: the declared path_len must account for exactly the payload
 * (plen == HPNS_FILEFAIL_HDR + path_len); -1 otherwise.  path is left as an
 * opaque borrowed pointer into the caller's buffer - never interpreted here.
 */
int
hpns_decode_filefail(const u_char *p, uint16_t plen, struct hpns_filefail *ff)
{
	uint16_t path_len;

	if (plen < HPNS_FILEFAIL_HDR)
		return -1;
	path_len = PEEK_U16(p + 1);
	if ((size_t)plen != (size_t)HPNS_FILEFAIL_HDR + path_len)
		return -1;
	ff->kind = p[0];
	ff->path_len = path_len;
	ff->path = path_len > 0 ? p + HPNS_FILEFAIL_HDR : NULL;
	return 0;
}

/*
 * Feed input bytes to the incremental parser.  Returns 0 and consumes
 * all input on success (any complete frames are delivered via cb);
 * returns -1 on protocol failure with *unconsumed = count of trailing
 * input bytes never buffered (the buffered prefix remains in
 * parser->buf[0..have) for the caller's passthrough flush).
 */
int
hpns_parser_feed(struct hpns_parser *ps, const u_char *data, size_t len,
    hpns_frame_cb cb, void *ctx, size_t *unconsumed)
{
	uint16_t plen;
	size_t n, flen, space;

	if (unconsumed != NULL)
		*unconsumed = len;
	if (ps->failed)
		return -1;

	for (;;) {
		/* pull in as much input as fits alongside what we hold */
		space = sizeof(ps->buf) - ps->have;
		n = len < space ? len : space;
		if (n > 0) {
			memcpy(ps->buf + ps->have, data, n);
			ps->have += n;
			data += n;
			len -= n;
			if (unconsumed != NULL)
				*unconsumed = len;
		}

		/* drain complete frames */
		while (ps->have >= HPNS_HDR_LEN) {
			if (PEEK_U32(ps->buf) != HPNS_MAGIC ||
			    ps->buf[4] != HPNS_VERSION) {
				ps->failed = 1;
				return -1;
			}
			plen = PEEK_U16(ps->buf + 6);
			if (plen > HPNS_MAX_PAYLOAD) {
				ps->failed = 1;
				return -1;
			}
			flen = HPNS_HDR_LEN + plen;
			if (ps->have < flen)
				break;		/* incomplete: need input */
			if (cb != NULL)
				cb(ps->buf[5], ps->buf + HPNS_HDR_LEN,
				    plen, ctx);
			memmove(ps->buf, ps->buf + flen, ps->have - flen);
			ps->have -= flen;
		}

		if (len == 0)
			return 0;
		/*
		 * Input remains but no complete frame drained: only possible
		 * mid-frame with a full buffer, which cannot happen because
		 * every valid frame fits the buffer.  The loop always makes
		 * progress; iterate to pull the rest in.
		 */
	}
}
