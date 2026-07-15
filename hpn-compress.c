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
 * hpn-compress.c - zstd transport compression (see hpn-compress.h).
 */

#include "includes.h"

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "hpn-compress.h"

#ifdef HAVE_LIBZSTD

#include <zstd.h>

/*
 * Decompressor window cap: the compressor at levels 1-19 never uses a
 * window above 8 MiB (windowLog 23), so 24 (16 MiB) accepts every
 * frame we can negotiate while bounding the memory an authenticated
 * peer's frames can demand - a cap the zlib path never had.
 */
#define HPN_ZSTD_WINDOW_LOG_MAX	24

/* transform chunk; matches the spirit of zlib's 4 KiB working buffer
 * but sized for zstd's appetite */
#define HPN_ZSTD_IOBUF		(16 * 1024)

struct hpn_zstd_out {
	ZSTD_CCtx *cctx;
	int level;
	unsigned long long raw_in;	/* pre-compression bytes (diag) */
	unsigned long long comp_out;	/* post-compression bytes (diag) */
};

struct hpn_zstd_in {
	ZSTD_DCtx *dctx;
	unsigned long long comp_in;	/* wire (compressed) bytes seen */
	unsigned long long raw_out;	/* plaintext (decompressed) bytes */
};

static int
clamp_level(int level)
{
	if (level < HPN_ZSTD_LEVEL_MIN)
		return HPN_ZSTD_LEVEL_MIN;
	if (level > HPN_ZSTD_LEVEL_MAX)
		return HPN_ZSTD_LEVEL_MAX;
	return level;
}

int
hpn_zstd_out_start(struct hpn_zstd_out **outp, int level)
{
	struct hpn_zstd_out *o = *outp;

	level = clamp_level(level);
	if (o == NULL) {
		if ((o = calloc(1, sizeof(*o))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((o->cctx = ZSTD_createCCtx()) == NULL) {
			free(o);
			return SSH_ERR_ALLOC_FAIL;
		}
		*outp = o;
	} else {
		/* rekey: fresh stream, mirroring deflateEnd+deflateInit */
		ZSTD_CCtx_reset(o->cctx, ZSTD_reset_session_and_parameters);
	}
	if (ZSTD_isError(ZSTD_CCtx_setParameter(o->cctx,
	    ZSTD_c_compressionLevel, level)))
		return SSH_ERR_INTERNAL_ERROR;
	o->level = level;
	debug("Enabling zstd compression at level %d.", level);
	return 0;
}

int
hpn_zstd_in_start(struct hpn_zstd_in **inp)
{
	struct hpn_zstd_in *i = *inp;

	if (i == NULL) {
		if ((i = calloc(1, sizeof(*i))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((i->dctx = ZSTD_createDCtx()) == NULL) {
			free(i);
			return SSH_ERR_ALLOC_FAIL;
		}
		*inp = i;
	} else {
		ZSTD_DCtx_reset(i->dctx, ZSTD_reset_session_and_parameters);
	}
	if (ZSTD_isError(ZSTD_DCtx_setParameter(i->dctx,
	    ZSTD_d_windowLogMax, HPN_ZSTD_WINDOW_LOG_MAX)))
		return SSH_ERR_INTERNAL_ERROR;
	return 0;
}

void
hpn_zstd_out_free(struct hpn_zstd_out **outp)
{
	struct hpn_zstd_out *o = *outp;

	if (o == NULL)
		return;
	debug("compress outgoing (zstd): raw data %llu, compressed %llu, "
	    "factor %.2f", o->raw_in, o->comp_out,
	    o->raw_in == 0 ? 0.0 : (double)o->comp_out / o->raw_in);
	ZSTD_freeCCtx(o->cctx);
	free(o);
	*outp = NULL;
}

void
hpn_zstd_in_free(struct hpn_zstd_in **inp)
{
	if (*inp == NULL)
		return;
	ZSTD_freeDCtx((*inp)->dctx);
	free(*inp);
	*inp = NULL;
}

int
hpn_zstd_compress(struct hpn_zstd_out *o, struct sshbuf *in,
    struct sshbuf *out)
{
	u_char buf[HPN_ZSTD_IOBUF];
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	size_t ret;
	int r;

	if (o == NULL || o->cctx == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	if (sshbuf_len(in) == 0)
		return 0;
	o->raw_in += sshbuf_len(in);
	zin.src = sshbuf_ptr(in);
	zin.size = sshbuf_len(in);
	zin.pos = 0;
	/*
	 * Flush per packet so the frame is decodable on arrival - the
	 * peer must be able to process every packet as it lands, exactly
	 * as zlib's Z_PARTIAL_FLUSH guarantees.  Loop until the input is
	 * consumed AND the flush has fully drained (ret == 0).
	 */
	do {
		zout.dst = buf;
		zout.size = sizeof(buf);
		zout.pos = 0;
		ret = ZSTD_compressStream2(o->cctx, &zout, &zin,
		    ZSTD_e_flush);
		if (ZSTD_isError(ret)) {
			error_f("zstd compress: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INVALID_FORMAT;
		}
		if (zout.pos > 0) {
			o->comp_out += zout.pos;
			if ((r = sshbuf_put(out, buf, zout.pos)) != 0)
				return r;
		}
	} while (zin.pos < zin.size || ret != 0);
	return 0;
}

int
hpn_zstd_uncompress(struct hpn_zstd_in *i, struct sshbuf *in,
    struct sshbuf *out)
{
	u_char buf[HPN_ZSTD_IOBUF];
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	size_t ret;
	int r;

	if (i == NULL || i->dctx == NULL)
		return SSH_ERR_INTERNAL_ERROR;
	if (sshbuf_len(in) == 0)
		return 0;
	i->comp_in += sshbuf_len(in);
	zin.src = sshbuf_ptr(in);
	zin.size = sshbuf_len(in);
	zin.pos = 0;
	do {
		zout.dst = buf;
		zout.size = sizeof(buf);
		zout.pos = 0;
		ret = ZSTD_decompressStream(i->dctx, &zout, &zin);
		if (ZSTD_isError(ret)) {
			error_f("zstd uncompress: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INVALID_FORMAT;
		}
		if (zout.pos > 0) {
			i->raw_out += zout.pos;
			if ((r = sshbuf_put(out, buf, zout.pos)) != 0)
				return r;
		}
		/* Loop while input remains, or while the last call filled
		 * the whole output buffer (more may be buffered inside). */
	} while (zin.pos < zin.size || zout.pos == zout.size);
	return 0;
}

/*
 * Decompression expansion ratio (plaintext / wire) as fixed point scaled
 * by 1000 - so 2:1 returns 2000.  Returns 1000 (1.0x) until >=1 MiB has
 * been decompressed so window sizing does not act on a noisy early
 * estimate; clamped to [1.0x, 100x].  Used to convert the receiver's
 * wire-level rcv_space BDP into a plaintext channel-window BDP.
 */
u_int
hpn_zstd_in_ratio_milli(struct hpn_zstd_in *i)
{
	unsigned long long r;

	if (i == NULL || i->comp_in < (1ULL << 20))
		return 1000;
	r = i->raw_out * 1000ULL / i->comp_in;
	if (r < 1000ULL)
		r = 1000ULL;		/* never size below the wire BDP */
	if (r > 100000ULL)
		r = 100000ULL;
	return (u_int)r;
}

#else /* !HAVE_LIBZSTD */

u_int
hpn_zstd_in_ratio_milli(struct hpn_zstd_in *i)
{
	return 1000;
}

int
hpn_zstd_out_start(struct hpn_zstd_out **outp, int level)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

int
hpn_zstd_in_start(struct hpn_zstd_in **inp)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

void
hpn_zstd_out_free(struct hpn_zstd_out **outp)
{
}

void
hpn_zstd_in_free(struct hpn_zstd_in **inp)
{
}

int
hpn_zstd_compress(struct hpn_zstd_out *o, struct sshbuf *in,
    struct sshbuf *out)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

int
hpn_zstd_uncompress(struct hpn_zstd_in *i, struct sshbuf *in,
    struct sshbuf *out)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

#endif /* HAVE_LIBZSTD */
