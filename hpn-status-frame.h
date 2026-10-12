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

/* hpn-status-frame.h - the status-relay frame format.
 *
 * A transfer client whose stdout is a pipe emits these small binary
 * frames instead of ANSI meter text when HPN_ENABLE_REMOTE_PROGRESS is
 * set. The launcher of a third-party transfer, hpnscp -R or hpn3scp,
 * parses them from the remote side's stdout and paints a local meter.
 *
 * The stream is telemetry, never control. A consumer treats any protocol
 * error as the end of parsing, passes the remaining bytes through as is,
 * and takes success or failure from the transport's exit status. The
 * only text that crosses the channel is the file paths in FILEFAIL and
 * FILEDONE. They are opaque bytes that the parser never interprets, and a
 * consumer percent-encodes them before display, so remote text never
 * reaches a terminal raw.
 *
 * Wire format, with all integers in network byte order. The 8-byte
 * header is
 *     u32 magic        0x48504E53, "HPNS", which marks a frame
 *     u8  version      1
 *     u8  type         HPNS_T_*
 *     u16 payload_len  at most HPNS_MAX_PAYLOAD
 * Each type has a fixed payload size, except FILEFAIL and FILEDONE, which
 * end in a variable-length path. A consumer skips a frame of an unknown
 * type when its header is valid, so new types do not break old readers. */

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
#define HPNS_T_FILEDONE		5

/* fixed payload sizes */
#define HPNS_HELLO_LEN		21
#define HPNS_PROGRESS_LEN	52
#define HPNS_END_LEN		17

/* FILEFAIL is one frame per failed file. Its payload is a 3-byte fixed
 * part, the kind and the path length, followed by up to
 * HPNS_FILEFAIL_MAXPATH opaque path bytes. */
#define HPNS_FILEFAIL_HDR	3
#define HPNS_FILEFAIL_MAXPATH	(HPNS_MAX_PAYLOAD - HPNS_FILEFAIL_HDR)

/* FILEFAIL kind byte: reason in the low 7 bits, flags in the high bit */
#define HPNS_FF_KINDMASK	0x7f
#define HPNS_FF_TRANSFER	0		/* transfer never completed */
#define HPNS_FF_VERIFY		1	/* transferred but failed verification */
#define HPNS_FF_TRUNCATED	0x80		/* path too long, clipped */

/* FILEDONE is one frame per file with its final transfer-log status, sent
 * only when HPN_ENABLE_REMOTE_PROGRESS is "log". The consumer builds its
 * transfer log, or a GUI its file list, from these. It has the same shape
 * as FILEFAIL, an 11-byte fixed part followed by opaque path bytes, and
 * the consumer percent-encodes the path before writing it anywhere,
 * including a log file. */
#define HPNS_FILEDONE_HDR	11	/* status u8 + size u64 + path_len u16 */
#define HPNS_FILEDONE_MAXPATH	(HPNS_MAX_PAYLOAD - HPNS_FILEDONE_HDR)

/* FILEDONE status byte: an enum hpns_fd_status value in the low 7 bits,
 * flags in the high bit. */
#define HPNS_FD_STATUSMASK	0x7f
#define HPNS_FD_TRUNCATED	0x80		/* path too long, clipped */

/* HELLO capability bits, advertised by the emitter. None is set yet.
 *
 * PULL reserves the request mode planned for the GUI launcher. Today the
 * stream runs one way, from the source to the launcher. In pull mode the
 * launcher could also send requests to the source on its stdin, but only
 * after HELLO advertises this bit, so a source that never sets it never
 * reads remote input. */
#define HPNS_CAP_PULL		0x00000001u

/* PROGRESS flag bits. Consumers ignore unknown bits, so a new bit does
 * not break old readers. */
#define HPNS_F_VERIFY		0x0001		/* verify phase in progress */
#define HPNS_F_RESUME		0x0002		/* resume check, hashing the
						 * existing partial file */
/* This frame is a serial file boundary, and bytes_done is the finished
 * file's exact end state. Only per-file meters set it. A fleet's file
 * counts rise on ordinary ticks and never do. */
#define HPNS_F_BOUNDARY		0x0004
/* bytes_total and files_total are real values, even when 0. Without the
 * flag the field is not known yet, whatever it holds. */
#define HPNS_F_TOTAL_KNOWN	0x0008
#define HPNS_F_FILES_KNOWN	0x0010

/* eta_sec when no ETA can be given */
#define HPNS_ETA_UNKNOWN	0xffffffffu

/* A file's final status, sent in FILEDONE and written by the transfer
 * log. Each file gets the most specific status that applies. VERIFIED
 * and REPAIRED both imply the transfer succeeded. HPNS_FD_COUNT is not a
 * status. It bounds the valid values. */
enum hpns_fd_status {
	HPNS_FD_SUCCESS = 0,	/* transferred, no verify phase */
	HPNS_FD_SKIPPED = 1,	/* resume: target identical or larger */
	HPNS_FD_VERIFIED = 2,	/* transferred and verify matched */
	HPNS_FD_REPAIRED = 3,	/* verify mismatch, repaired */
	HPNS_FD_FAILED = 4,	/* transfer or verify failed */
	HPNS_FD_COUNT
};

/* The first frame: the protocol version, the capabilities, and what is
 * known of the totals. */
struct hpns_hello {
	u_char		proto_ver;	/* HPNS_VERSION */
	uint32_t	caps;		/* HPNS_CAP_* */
	uint64_t	total_bytes;	/* 0 = not yet known */
	uint32_t	total_files;	/* 0 = not yet known */
	uint32_t	streams;	/* effective -j, 0 if not yet known */
};

/* A snapshot of the whole transfer, sent about once a second. Its counts
 * are authoritative. */
struct hpns_progress {
	uint64_t	bytes_done;
	uint64_t	bytes_total;	/* may grow, HPNS_F_TOTAL_KNOWN */
	uint64_t	rate_bps;	/* smoothed */
	/* The last interval's rate, unsmoothed. The source measures it against
	 * its own clock, which a consumer cannot recover from frame arrival
	 * times. */
	uint64_t	rate_inst_bps;
	uint32_t	eta_sec;	/* or HPNS_ETA_UNKNOWN */
	uint32_t	files_done;
	uint32_t	files_total;	/* see HPNS_F_FILES_KNOWN */
	uint16_t	workers_active;
	uint16_t	workers_stalled;
	uint16_t	flags;		/* HPNS_F_* */
};

/* The last frame. It is advisory, because the transport's exit status
 * decides success. */
struct hpns_end {
	uint64_t	bytes_done;
	uint32_t	files_done;
	uint32_t	files_failed;
	u_char		ok;
};

/* One failed file, sent before END. path is opaque bytes, which the
 * parser never interprets and a consumer percent-encodes before display.
 * On decode, path points into the parser's frame buffer. It is not owned
 * or NUL-terminated, and it is valid only during the frame callback. */
struct hpns_filefail {
	u_char		kind;		/* HPNS_FF_* reason and flags */
	uint16_t	path_len;	/* at most HPNS_FILEFAIL_MAXPATH */
	const u_char	*path;		/* borrowed, copy before keeping */
};

/* One file's final status, an enum hpns_fd_status value. path follows
 * the same rules as in hpns_filefail. */
struct hpns_filedone {
	u_char		status;		/* HPNS_FD_* value and flags */
	uint64_t	size;		/* file size in bytes */
	uint16_t	path_len;	/* at most HPNS_FILEDONE_MAXPATH */
	const u_char	*path;		/* borrowed, copy before keeping */
};

/* The consumer's incremental frame parser. It is the one piece of this
 * code that faces remote input, so it is kept small and is the fuzz
 * target. It buffers at most one frame. When a header fails validation it
 * sets failed, and the caller must switch to passthrough, flushing
 * parser->buf[0..have) and whatever input the parser reports unconsumed.
 * A frame of an unknown type with a valid header still reaches the
 * callback, which ignores types it does not know. */
struct hpns_parser {
	u_char	buf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];
	size_t	have;		/* bytes held in buf */
	int	failed;		/* set on a bad header, never cleared */
};

/* Called once for each complete frame, with its type, its payload and
 * payload length, and the caller's context. */
typedef void (*hpns_frame_cb)(u_char, const u_char *, uint16_t, void *);

/* The encoders. Each writes one frame into the buffer and returns its
 * total length. A buffer of HPNS_HDR_LEN + HPNS_MAX_PAYLOAD bytes always
 * suffices. */
size_t	hpns_encode_hello(u_char *, const struct hpns_hello *);
size_t	hpns_encode_progress(u_char *, const struct hpns_progress *);
size_t	hpns_encode_end(u_char *, const struct hpns_end *);
size_t	hpns_encode_filefail(u_char *, const struct hpns_filefail *);
size_t	hpns_encode_filedone(u_char *, const struct hpns_filedone *);

/* The decoders. Each returns 0, or -1 if the payload length does not
 * match its type's layout exactly. */
int	hpns_decode_hello(const u_char *, uint16_t, struct hpns_hello *);
int	hpns_decode_progress(const u_char *, uint16_t,
	    struct hpns_progress *);
int	hpns_decode_end(const u_char *, uint16_t, struct hpns_end *);
int	hpns_decode_filefail(const u_char *, uint16_t,
	    struct hpns_filefail *);
int	hpns_decode_filedone(const u_char *, uint16_t,
	    struct hpns_filedone *);

/* Feed input bytes to the parser, delivering each complete frame to the
 * callback. Returns 0 once all input is consumed. On a protocol failure
 * it returns -1, and so does every later call. The last argument then
 * holds the count of trailing input bytes never buffered, and the
 * buffered prefix stays in parser->buf[0..have). */
int	hpns_parser_feed(struct hpns_parser *, const u_char *, size_t,
	    hpns_frame_cb, void *, size_t *);

/* Percent-encode a byte string, which may hold NUL or high-bit bytes,
 * into a NUL-terminated buffer of the given size. Only A-Z, a-z, 0-9,
 * and . _ - : / @ + pass through. Every other byte becomes %XX. Output
 * that does not fit is truncated. */
void	hpns_pct_encode(char *, size_t, const u_char *, size_t);

/* The word for a FILEDONE status value, such as "success", with the flag
 * bits ignored. A value with no word returns "unknown". */
const char *hpns_fd_status_word(u_char);

/* The word for a FILEFAIL reason, "transfer" or "verify", with the flag
 * bit ignored. A reason with no word returns "unknown". */
const char *hpns_ff_kind_word(u_char);

/* The final status of a file whose verify phase ran: FAILED when it
 * failed or could not be verified, otherwise REPAIRED or VERIFIED. */
enum hpns_fd_status hpns_fd_verify_status(int, int);

#endif /* HPN_STATUS_FRAME_H */
