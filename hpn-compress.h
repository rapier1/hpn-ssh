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

/* hpn-compress.h - zstd transport compression (zstd@hpnssh.org).
 *
 * The fast replacement for the transport's zlib compression. It uses the
 * same insertion points, the same delayed start after authentication, and
 * the same stream reset at each rekey, with zstd doing the work.
 *
 * All zstd knowledge lives here, and packet.c only dispatches on the
 * negotiated method. The client's level governs both directions. It
 * reaches the server as a marker in the client's compression proposal
 * (see hpn_zstd_client_proposal). */

#ifndef HPN_COMPRESS_H
#define HPN_COMPRESS_H

/* The method name, and the level range that -z, ZstdLevel, and the
 * server's marker check accept. A stream with no level from the client
 * runs at the default. */
#define HPN_ZSTD_COMP_NAME	"zstd@hpnssh.org"
#define HPN_ZSTD_LEVEL_MIN	1
#define HPN_ZSTD_LEVEL_MAX	19
#define HPN_ZSTD_LEVEL_DEFAULT	3

/* 1.0x in the thousandths that hpn_zstd_in_ratio_milli reports. */
#define HPN_ZSTD_RATIO_ONE	1000

struct ssh;
struct sshbuf;
struct hpn_zstd_out;	/* opaque, the outgoing stream */
struct hpn_zstd_in;	/* opaque, the incoming stream */

/* Start a direction's stream, or reset it at a rekey. The outgoing level
 * is clamped to the range above. Both return 0 or an SSH_ERR_* code, and
 * SSH_ERR_FEATURE_UNSUPPORTED when built without libzstd. */
int	hpn_zstd_out_start(struct hpn_zstd_out **, int);
int	hpn_zstd_in_start(struct hpn_zstd_in **);

/* Free a direction's stream and clear the pointer. A NULL stream is
 * fine. */
void	hpn_zstd_out_free(struct hpn_zstd_out **);
void	hpn_zstd_in_free(struct hpn_zstd_in **);

/* Per-packet transforms with the contracts of packet.c's zlib
 * compress_buffer and uncompress_buffer: consume all of the input and
 * append to the output. The compressor flushes each call, so every packet
 * decodes on arrival, as zlib's Z_PARTIAL_FLUSH gives. The decompressor
 * fails a packet that expands past HPN_ZSTD_PACKET_RAW_MAX
 * (hpn-compress.c). */
int	hpn_zstd_compress(struct hpn_zstd_out *, struct sshbuf *,
	    struct sshbuf *);
int	hpn_zstd_uncompress(struct hpn_zstd_in *, struct sshbuf *,
	    struct sshbuf *);

/* The incoming decompression ratio in thousandths, which scales the
 * channel window. */
u_int	hpn_zstd_in_ratio_milli(struct hpn_zstd_in *);

/* Server side. The compression fields of the throughput log line. The
 * string is static and good until the next call. */
const char *hpn_zstd_log_fields(const struct hpn_zstd_out *,
	    const struct hpn_zstd_in *, int);

/* The client's compression proposal for zstd at a level: the method and
 * a marker that carries the level, so the server compresses at it too.
 * The string is static and good until the next call. */
const char *hpn_zstd_client_proposal(int);

/* Server side. Take the client's level from its compression proposal. */
void	hpn_zstd_take_peer_level(struct ssh *, const char *);

#endif /* HPN_COMPRESS_H */
