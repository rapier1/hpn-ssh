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
 * hpn-status-frame.h - HPN status-relay frames.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * See hpn-status-relay-design.md for the full design.
 *
 * A transfer client whose stdout is a pipe emits these small binary
 * frames instead of ANSI progress-meter text when armed via the
 * HPN_ENABLE_REMOTE_PROGRESS environment variable.  The launching
 * hpnscp (scp -R "third party" transfers) parses them from the launch
 * ssh's stdout and renders a local meter.  Numbers only, by design: no
 * strings ever cross this channel, so the consumer never renders
 * remote-controlled text (terminal-escape injection is structurally
 * excluded).  The stream is telemetry, never control: consumers must
 * treat any protocol error as "stop parsing, fall back to passthrough"
 * and take transfer success/failure from the transport exit status.
 *
 * Wire format, all integers network byte order.  8-byte header:
 *     u32 magic  0x48504E53 ("HPNS")
 *     u8  ver    1
 *     u8  type   HPNS_T_*
 *     u16 payload_len   (hard cap HPNS_MAX_PAYLOAD)
 * Payloads are fixed-size per type; unknown types with a sane header
 * must be skipped by consumers (forward compatibility).
 *
 * Implementation is in hpn-status-frame.c, which deliberately depends
 * on libc only so the fuzz harness can link the parser directly.
 */

#ifndef HPN_STATUS_FRAME_H
#define HPN_STATUS_FRAME_H

#include <sys/types.h>
#include <stdint.h>

#define HPNS_MAGIC		0x48504e53u	/* "HPNS" */
#define HPNS_VERSION		1
#define HPNS_HDR_LEN		8
#define HPNS_MAX_PAYLOAD	512

/* frame types */
#define HPNS_T_HELLO		1
#define HPNS_T_PROGRESS		2
#define HPNS_T_END		3
#define HPNS_T_FILEFAIL		4

/* fixed payload sizes */
#define HPNS_HELLO_LEN		21
#define HPNS_PROGRESS_LEN	52
#define HPNS_PROGRESS_LEN_V0	44	/* legacy, before rate_inst_bps: the
					 * decoder still accepts it so a new
					 * consumer meters an older HPN source */
#define HPNS_END_LEN		17

/*
 * FILEFAIL is variable-length: a 3-byte fixed head (kind + path_len)
 * plus up to HPNS_FILEFAIL_MAXPATH opaque path bytes.  One frame per
 * failed file.
 */
#define HPNS_FILEFAIL_HDR	3
#define HPNS_FILEFAIL_MAXPATH	(HPNS_MAX_PAYLOAD - HPNS_FILEFAIL_HDR)

/* FILEFAIL kind byte: reason in the low 7 bits, flags in the high bit */
#define HPNS_FF_KINDMASK	0x7f
#define HPNS_FF_TRANSFER	0		/* transfer never completed */
#define HPNS_FF_VERIFY		1	/* transferred but failed verification */
#define HPNS_FF_TRUNCATED	0x80		/* path too long, clipped */

/* HELLO capability bits (advertised by the emitter; all reserved) */
#define HPNS_CAP_PULL		0x00000001u	/* future request/response */

/* PROGRESS flag bits */
#define HPNS_F_VERIFY		0x0001		/* verify phase in progress */

#define HPNS_ETA_UNKNOWN	0xffffffffu

/* first frame: version + capabilities + what is known of the totals */
struct hpns_hello {
	u_char		proto_ver;
	uint32_t	caps;
	uint64_t	total_bytes;	/* 0 = not yet known */
	uint32_t	total_files;	/* 0 = not yet known */
	uint32_t	streams;	/* effective -j; 1 = serial */
};

/* periodic (~1 Hz) aggregate snapshot; counts are authoritative */
struct hpns_progress {
	uint64_t	bytes_done;
	uint64_t	bytes_total;	/* may grow; 0 = unknown */
	uint64_t	rate_bps;	/* smoothed */
	uint64_t	rate_inst_bps;	/* last-interval rate, unsmoothed.
					 * Measured at the source against its
					 * own clock; a consumer cannot derive
					 * it from frame arrival times. */
	uint32_t	eta_sec;	/* HPNS_ETA_UNKNOWN = unknown */
	uint32_t	files_done;
	uint32_t	files_total;	/* 0 = unknown */
	uint16_t	workers_active;
	uint16_t	workers_stalled;
	uint16_t	flags;		/* HPNS_F_* */
};

/* final frame; advisory only - exit status comes from the transport */
struct hpns_end {
	uint64_t	bytes_done;
	uint32_t	files_done;
	uint32_t	files_failed;
	u_char		ok;
};

/*
 * Per-file failure detail: one frame per failed file, emitted before END
 * when the relay is armed.  Variable length.  path is carried as OPAQUE
 * bytes - the parser never interprets or renders them; the consumer must
 * neutralize (percent-encode) before the path is ever displayed.  On
 * decode, path borrows into the parser's frame buffer: not owned, not
 * NUL-terminated, valid only for the duration of the frame callback.
 */
struct hpns_filefail {
	u_char		kind;		/* HPNS_FF_* reason | flags */
	uint16_t	path_len;	/* opaque bytes at path (<= MAXPATH) */
	const u_char	*path;		/* borrowed; copy/encode before reuse */
};

/*
 * Incremental frame parser (the consumer side; this is the one piece of
 * code that faces remote input, so it is deliberately tiny and is the
 * fuzz target).  Holds at most one frame of buffered bytes.  On any
 * header validation failure it latches `failed`; the caller must switch
 * to passthrough, flushing parser->buf[0..have) plus whatever input it
 * reports unconsumed.  Frames with valid headers but unknown types are
 * delivered to the callback, which should ignore types it doesn't know.
 */
struct hpns_parser {
	u_char	buf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];
	size_t	have;
	int	failed;
};

typedef void (*hpns_frame_cb)(u_char type, const u_char *payload,
    uint16_t plen, void *ctx);

/* encoders: fill buf (>= HPNS_HDR_LEN + payload), return frame length */
size_t	hpns_encode_hello(u_char *, const struct hpns_hello *);
size_t	hpns_encode_progress(u_char *, const struct hpns_progress *);
size_t	hpns_encode_end(u_char *, const struct hpns_end *);
size_t	hpns_encode_filefail(u_char *, const struct hpns_filefail *);

/* strict decoders: payload length must match exactly; -1 on mismatch */
int	hpns_decode_hello(const u_char *, uint16_t, struct hpns_hello *);
int	hpns_decode_progress(const u_char *, uint16_t,
	    struct hpns_progress *);
int	hpns_decode_end(const u_char *, uint16_t, struct hpns_end *);
int	hpns_decode_filefail(const u_char *, uint16_t,
	    struct hpns_filefail *);

/*
 * Feed input bytes.  Returns 0 and consumes all input on success (any
 * complete frames are delivered via the callback); returns -1 on
 * protocol failure with *unconsumed = count of trailing input bytes
 * never buffered (the buffered prefix is in parser->buf[0..have)).
 */
int	hpns_parser_feed(struct hpns_parser *, const u_char *, size_t,
	    hpns_frame_cb, void *, size_t *);

#endif /* HPN_STATUS_FRAME_H */
