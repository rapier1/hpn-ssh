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

/* hpn-status-frame.c - status-frame encoding, decoding, and parsing.
 *
 * hpn-status-frame.h defines the wire format and the contract. This file
 * depends on no other object in the tree, because the fuzz harness links
 * it alone. Use only macros from other tree headers, never their
 * functions. */

#include "includes.h"

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include "sshbuf.h"	/* PEEK/POKE big-endian buffer accessors */
#include "misc.h"	/* MINIMUM */
#include "hpn-status-frame.h"

/* Write the frame header at buf: the "HPNS" marker, the protocol version,
 * the frame type, and the payload length. Returns HPNS_HDR_LEN, the offset
 * where the payload starts. */
static size_t
hpns_put_hdr(u_char *buf, u_char type, uint16_t plen)
{
	POKE_U32(buf, HPNS_MAGIC);
	buf[4] = HPNS_VERSION;
	buf[5] = type;
	POKE_U16(buf + 6, plen);
	return HPNS_HDR_LEN;
}

/* Encode a HELLO frame into buf, which must hold HPNS_HDR_LEN +
 * HPNS_HELLO_LEN bytes. Returns the total frame length. */
size_t
hpns_encode_hello(u_char *buf, const struct hpns_hello *hello)
{
	size_t hdr_len = hpns_put_hdr(buf, HPNS_T_HELLO, HPNS_HELLO_LEN);

	buf[hdr_len] = hello->proto_ver;
	POKE_U32(buf + hdr_len + 1, hello->caps);
	POKE_U64(buf + hdr_len + 5, hello->total_bytes);
	POKE_U32(buf + hdr_len + 13, hello->total_files);
	POKE_U32(buf + hdr_len + 17, hello->streams);
	return hdr_len + HPNS_HELLO_LEN;
}

/* Encode a PROGRESS frame into buf, which must hold HPNS_HDR_LEN +
 * HPNS_PROGRESS_LEN bytes. Returns the total frame length. */
size_t
hpns_encode_progress(u_char *buf, const struct hpns_progress *progress)
{
	size_t hdr_len = hpns_put_hdr(buf, HPNS_T_PROGRESS, HPNS_PROGRESS_LEN);

	POKE_U64(buf + hdr_len, progress->bytes_done);
	POKE_U64(buf + hdr_len + 8, progress->bytes_total);
	POKE_U64(buf + hdr_len + 16, progress->rate_bps);
	POKE_U64(buf + hdr_len + 24, progress->rate_inst_bps);
	POKE_U32(buf + hdr_len + 32, progress->eta_sec);
	POKE_U32(buf + hdr_len + 36, progress->files_done);
	POKE_U32(buf + hdr_len + 40, progress->files_total);
	POKE_U16(buf + hdr_len + 44, progress->workers_active);
	POKE_U16(buf + hdr_len + 46, progress->workers_stalled);
	POKE_U16(buf + hdr_len + 48, progress->flags);
	POKE_U16(buf + hdr_len + 50, 0);		/* pad */
	return hdr_len + HPNS_PROGRESS_LEN;
}

/* Encode an END frame into buf, which must hold HPNS_HDR_LEN +
 * HPNS_END_LEN bytes. Returns the total frame length. */
size_t
hpns_encode_end(u_char *buf, const struct hpns_end *end)
{
	size_t hdr_len = hpns_put_hdr(buf, HPNS_T_END, HPNS_END_LEN);

	POKE_U64(buf + hdr_len, end->bytes_done);
	POKE_U32(buf + hdr_len + 8, end->files_done);
	POKE_U32(buf + hdr_len + 12, end->files_failed);
	buf[hdr_len + 16] = end->ok;
	return hdr_len + HPNS_END_LEN;
}

/* Encode a FILEFAIL frame into buf, which must hold HPNS_HDR_LEN +
 * HPNS_FILEFAIL_HDR + path_len bytes. Returns the total frame length.
 * path_len is clamped to HPNS_FILEFAIL_MAXPATH, so a caller bug can never
 * produce an over-cap frame that the parser would reject. The caller sets
 * HPNS_FF_TRUNCATED in kind when it clips. A NULL path goes out empty. */
size_t
hpns_encode_filefail(u_char *buf, const struct hpns_filefail *filefail)
{
	uint16_t path_len = filefail->path_len;
	size_t hdr_len;

	if (filefail->path == NULL)
		path_len = 0;
	if (path_len > HPNS_FILEFAIL_MAXPATH)
		path_len = HPNS_FILEFAIL_MAXPATH;
	hdr_len = hpns_put_hdr(buf, HPNS_T_FILEFAIL,
	    (uint16_t)(HPNS_FILEFAIL_HDR + path_len));
	buf[hdr_len] = filefail->kind;
	POKE_U16(buf + hdr_len + 1, path_len);
	if (path_len > 0)
		memcpy(buf + hdr_len + HPNS_FILEFAIL_HDR, filefail->path, path_len);
	return hdr_len + HPNS_FILEFAIL_HDR + path_len;
}

/* Encode a FILEDONE frame into buf, which must hold HPNS_HDR_LEN +
 * HPNS_FILEDONE_HDR + path_len bytes. Returns the total frame length. The
 * path is clamped as in FILEFAIL, the caller sets HPNS_FD_TRUNCATED in
 * status when it clips, and a NULL path goes out empty. */
size_t
hpns_encode_filedone(u_char *buf, const struct hpns_filedone *filedone)
{
	uint16_t path_len = filedone->path_len;
	size_t hdr_len;

	if (filedone->path == NULL)
		path_len = 0;
	if (path_len > HPNS_FILEDONE_MAXPATH)
		path_len = HPNS_FILEDONE_MAXPATH;
	hdr_len = hpns_put_hdr(buf, HPNS_T_FILEDONE,
	    (uint16_t)(HPNS_FILEDONE_HDR + path_len));
	buf[hdr_len] = filedone->status;
	POKE_U64(buf + hdr_len + 1, filedone->size);
	POKE_U16(buf + hdr_len + 9, path_len);
	if (path_len > 0)
		memcpy(buf + hdr_len + HPNS_FILEDONE_HDR, filedone->path, path_len);
	return hdr_len + HPNS_FILEDONE_HDR + path_len;
}

/* Decode a HELLO payload. Returns 0, or -1 if plen is not exactly
 * HPNS_HELLO_LEN. */
int
hpns_decode_hello(const u_char *payload, uint16_t plen,
    struct hpns_hello *hello)
{
	if (plen != HPNS_HELLO_LEN)
		return -1;
	hello->proto_ver = payload[0];
	hello->caps = PEEK_U32(payload + 1);
	hello->total_bytes = PEEK_U64(payload + 5);
	hello->total_files = PEEK_U32(payload + 13);
	hello->streams = PEEK_U32(payload + 17);
	return 0;
}

/* Decode a PROGRESS payload. Returns 0, or -1 if plen is not exactly
 * HPNS_PROGRESS_LEN. */
int
hpns_decode_progress(const u_char *payload, uint16_t plen,
    struct hpns_progress *progress)
{
	if (plen != HPNS_PROGRESS_LEN)
		return -1;
	progress->bytes_done = PEEK_U64(payload);
	progress->bytes_total = PEEK_U64(payload + 8);
	progress->rate_bps = PEEK_U64(payload + 16);
	progress->rate_inst_bps = PEEK_U64(payload + 24);
	progress->eta_sec = PEEK_U32(payload + 32);
	progress->files_done = PEEK_U32(payload + 36);
	progress->files_total = PEEK_U32(payload + 40);
	progress->workers_active = PEEK_U16(payload + 44);
	progress->workers_stalled = PEEK_U16(payload + 46);
	progress->flags = PEEK_U16(payload + 48);
	return 0;
}

/* Decode an END payload. Returns 0, or -1 if plen is not exactly
 * HPNS_END_LEN. */
int
hpns_decode_end(const u_char *payload, uint16_t plen, struct hpns_end *end)
{
	if (plen != HPNS_END_LEN)
		return -1;
	end->bytes_done = PEEK_U64(payload);
	end->files_done = PEEK_U32(payload + 8);
	end->files_failed = PEEK_U32(payload + 12);
	end->ok = payload[16];
	return 0;
}

/* Decode a FILEFAIL payload. Returns 0, or -1 unless plen is exactly
 * HPNS_FILEFAIL_HDR plus the declared path_len. path points into the
 * caller's payload as opaque bytes and is never interpreted here. */
int
hpns_decode_filefail(const u_char *payload, uint16_t plen,
    struct hpns_filefail *filefail)
{
	uint16_t path_len;

	if (plen < HPNS_FILEFAIL_HDR)
		return -1;
	path_len = PEEK_U16(payload + 1);
	if ((size_t)plen != (size_t)HPNS_FILEFAIL_HDR + path_len)
		return -1;
	filefail->kind = payload[0];
	filefail->path_len = path_len;
	filefail->path = NULL;
	if (path_len > 0)
		filefail->path = payload + HPNS_FILEFAIL_HDR;
	return 0;
}

/* Decode a FILEDONE payload, with the same length check and path
 * handling as FILEFAIL. */
int
hpns_decode_filedone(const u_char *payload, uint16_t plen,
    struct hpns_filedone *filedone)
{
	uint16_t path_len;

	if (plen < HPNS_FILEDONE_HDR)
		return -1;
	path_len = PEEK_U16(payload + 9);
	if ((size_t)plen != (size_t)HPNS_FILEDONE_HDR + path_len)
		return -1;
	filedone->status = payload[0];
	filedone->size = PEEK_U64(payload + 1);
	filedone->path_len = path_len;
	filedone->path = NULL;
	if (path_len > 0)
		filedone->path = payload + HPNS_FILEDONE_HDR;
	return 0;
}

/* Feed input bytes to the incremental parser, delivering each complete
 * frame to cb. Returns 0 once all input is consumed. On a protocol
 * failure it returns -1, and so does every later call. *unconsumed is
 * then the count of trailing input bytes never buffered, and the buffered
 * prefix stays in parser->buf[0..have) for the caller's passthrough
 * flush. */
int
hpns_parser_feed(struct hpns_parser *parser, const u_char *data, size_t len,
    hpns_frame_cb cb, void *ctx, size_t *unconsumed)
{
	uint16_t plen;
	size_t copy_len, flen, space;

	if (unconsumed != NULL)
		*unconsumed = len;
	if (parser->failed)
		return -1;

	for (;;) {
		/* pull in as much input as fits alongside what we hold */
		space = sizeof(parser->buf) - parser->have;
		copy_len = MINIMUM(len, space);
		if (copy_len > 0) {
			memcpy(parser->buf + parser->have, data, copy_len);
			parser->have += copy_len;
			data += copy_len;
			len -= copy_len;
			if (unconsumed != NULL)
				*unconsumed = len;
		}

		/* drain complete frames */
		while (parser->have >= HPNS_HDR_LEN) {
			/* Fail on anything other than HPNS frame & version */
			if (PEEK_U32(parser->buf) != HPNS_MAGIC ||
			    parser->buf[4] != HPNS_VERSION) {
				parser->failed = 1;
				return -1;
			}
			/* payload length & reject oversized bufs */
			plen = PEEK_U16(parser->buf + 6);
			if (plen > HPNS_MAX_PAYLOAD) {
				parser->failed = 1;
				return -1;
			}
			/* whole frame length */
			flen = HPNS_HDR_LEN + plen;
			if (parser->have < flen)
				break;		/* incomplete: need input */
			/* send frame type and buf to the given callback */
			if (cb != NULL)
				cb(parser->buf[5], parser->buf + HPNS_HDR_LEN,
				    plen, ctx);
			/* drop the processed frame and move forward */
			memmove(parser->buf, parser->buf + flen,
			    parser->have - flen);
			parser->have -= flen;
		}

		if (len == 0)
			return 0;
		/* Input remains only when the buffer filled. A full buffer
		 * always holds a complete frame, because every valid frame
		 * fits, so the drain above made room and the next pass pulls
		 * in more. */
	}
}

/* The bytes hpns_pct_encode() writes as themselves. This is an explicit
 * ASCII test, not the locale-sensitive isalnum(), so the output reads the
 * same under any LC_* setting. ':' '/' '@' '+' '.' '_' '-' stay literal
 * so fingerprints, hosts, and paths remain readable. Space, '=', '%',
 * newline, control, and high-bit bytes are always encoded, so no
 * delimiter or multibyte sequence ever appears raw. */
static int
pct_safe(u_char byte)
{
	return ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
	    (byte >= '0' && byte <= '9') ||
	    byte == '.' || byte == '_' || byte == '-' || byte == ':' ||
	    byte == '/' || byte == '@' || byte == '+');
}

/* Percent-encode inlen bytes of in into out. A byte that fails
 * pct_safe() becomes %XX. Output that does not fit stops at a whole
 * input byte, never partway through an escape. */
void
hpns_pct_encode(char *out, size_t outlen, const u_char *in, size_t inlen)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t i, used = 0;

	if (outlen == 0)
		return;
	for (i = 0; i < inlen; i++) {
		u_char byte = in[i];

		/* each branch keeps room for the closing NUL */
		if (pct_safe(byte)) {
			if (used + 1 >= outlen)
				break;
			out[used++] = (char)byte;
		} else {
			if (used + 3 >= outlen)
				break;
			out[used++] = '%';
			out[used++] = hex[byte >> 4];
			out[used++] = hex[byte & 0x0f];
		}
	}
	out[used] = '\0';
}

/* The word for a FILEDONE status, with the flag bits ignored. These are
 * also the transfer log's words, so the log and the EVENT stream read
 * the same. A value with no word reads "unknown". */
const char *
hpns_fd_status_word(u_char status)
{
	/* switch on the enum so -Wswitch flags a status without a word */
	switch ((enum hpns_fd_status)(status & HPNS_FD_STATUSMASK)) {
	case HPNS_FD_SUCCESS:	return "success";
	case HPNS_FD_SKIPPED:	return "skipped";
	case HPNS_FD_VERIFIED:	return "verified";
	case HPNS_FD_REPAIRED:	return "repaired";
	case HPNS_FD_FAILED:	return "failed";
	case HPNS_FD_COUNT:	break;
	}
	return "unknown";
}

/* The final status of a file whose verify phase ran. failed covers a
 * mismatch that could not be repaired and a file that could not be
 * verified. repaired means a mismatch was found and fixed. Every verify
 * site calls this, so the precedence lives only here. */
enum hpns_fd_status
hpns_fd_verify_status(int failed, int repaired)
{
	if (failed)
		return HPNS_FD_FAILED;
	if (repaired)
		return HPNS_FD_REPAIRED;
	return HPNS_FD_VERIFIED;
}
