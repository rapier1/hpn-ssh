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
 * hpn-compress.h - zstd transport compression (zstd@hpnssh.org).
 *
 * The fast replacement for the transport's zlib compression: same
 * insertion points, same delayed (post-auth) semantics, same
 * stream-reset-on-rekey lifecycle - just zstd doing the work.  Each
 * HPN worker is its own hpnssh session, so N workers give N
 * independent compressor pairs; the parallelism the single-threaded
 * zlib path could never have falls out of the fleet design.
 *
 * All zstd knowledge lives here; packet.c only dispatches on the
 * negotiated method.  Compression level is a LOCAL parameter per
 * direction (there is no protocol field for it): the client's -z int
 * governs its outbound stream, the server's ZstdLevel its own.
 */

#ifndef HPN_COMPRESS_H
#define HPN_COMPRESS_H

#define HPN_ZSTD_COMP_NAME	"zstd@hpnssh.org"
#define HPN_ZSTD_LEVEL_MIN	1
#define HPN_ZSTD_LEVEL_MAX	19
#define HPN_ZSTD_LEVEL_DEFAULT	3

struct sshbuf;
struct hpn_zstd_out;	/* opaque; one per outbound direction */
struct hpn_zstd_in;	/* opaque; one per inbound direction */

/*
 * Start (or, on rekey, reset) a direction's stream.  Levels outside
 * [MIN, MAX] are clamped.  Both return SSH_ERR_* on failure and
 * SSH_ERR_FEATURE_UNSUPPORTED when built without libzstd.
 */
int	hpn_zstd_out_start(struct hpn_zstd_out **outp, int level);
int	hpn_zstd_in_start(struct hpn_zstd_in **inp);
void	hpn_zstd_out_free(struct hpn_zstd_out **outp);
void	hpn_zstd_in_free(struct hpn_zstd_in **inp);

/*
 * Per-packet transform, mirroring packet.c's zlib compress_buffer /
 * uncompress_buffer contracts: consume all of `in`, append to `out`.
 * The compressor flushes per call so each packet is decodable on
 * arrival (the zstd analogue of zlib's Z_PARTIAL_FLUSH).
 */
int	hpn_zstd_compress(struct hpn_zstd_out *o, struct sshbuf *in,
	    struct sshbuf *out);
int	hpn_zstd_uncompress(struct hpn_zstd_in *i, struct sshbuf *in,
	    struct sshbuf *out);

#endif /* HPN_COMPRESS_H */
