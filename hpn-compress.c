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

/* hpn-compress.c - zstd transport compression (see hpn-compress.h). */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "packet.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "xmalloc.h"
#include "hpn-compress.h"

/* The marker that carries the client's level to the server, inside the
 * client's compression proposal. It is not a method, so the server never
 * picks it, and a server that does not know it ignores it. */
#define HPN_ZSTD_MARKER_PREFIX	"zstd-level-"
#define HPN_ZSTD_MARKER_SUFFIX	"@hpnssh.org"

/* The client's compression proposal for zstd at level: the method, then
 * the marker. The string is static and good until the next call. */
const char *
hpn_zstd_client_proposal(int level)
{
	static char proposal[64];

	snprintf(proposal, sizeof(proposal), "%s,%s%d%s", HPN_ZSTD_COMP_NAME,
	    HPN_ZSTD_MARKER_PREFIX, level, HPN_ZSTD_MARKER_SUFFIX);
	return proposal;
}

/* Take the level from the client's marker for what the server sends. A
 * proposal without a marker, or with a level out of range, leaves the
 * level as it was. */
void
hpn_zstd_take_peer_level(struct ssh *ssh, const char *proposal)
{
	size_t plen = strlen(HPN_ZSTD_MARKER_PREFIX);
	size_t slen = strlen(HPN_ZSTD_MARKER_SUFFIX);
	char *list, *cp, *name;
	const char *errstr;
	size_t nlen;
	int level;

	if (proposal == NULL)
		return;
	list = cp = xstrdup(proposal);
	while ((name = strsep(&cp, ",")) != NULL) {
		nlen = strlen(name);
		if (nlen <= plen + slen ||
		    strncmp(name, HPN_ZSTD_MARKER_PREFIX, plen) != 0 ||
		    strcmp(name + nlen - slen, HPN_ZSTD_MARKER_SUFFIX) != 0)
			continue;
		name[nlen - slen] = '\0';
		level = (int)strtonum(name + plen, HPN_ZSTD_LEVEL_MIN,
		    HPN_ZSTD_LEVEL_MAX, &errstr);
		if (errstr != NULL)
			debug_f("ignoring the zstd level marker: level %s",
			    errstr);
		else {
			debug_f("the client asked for zstd level %d", level);
			ssh_packet_set_zstd_level(ssh, level);
		}
		break;
	}
	free(list);
}

#ifdef HAVE_LIBZSTD

#include <zstd.h>

/* The decompressor's window limit, as a power of two. The compressor at
 * levels 1 to 19 never uses a window above 8 MiB (windowLog 23), so 16 MiB
 * accepts every frame we negotiate while bounding the memory an
 * authenticated peer's frames can demand. The zlib path has no such cap. */
#define HPN_ZSTD_WINDOW_LOG_MAX	24

/* The stack buffer each compress or uncompress pass fills before copying
 * to the output. zlib's path uses 4 KiB, and zstd works in larger blocks. */
#define HPN_ZSTD_IOBUF		(16 * 1024)

/* Outgoing state: the zstd context, its level, and the byte counts the
 * debug summary reports when it is freed. */
struct hpn_zstd_out {
	ZSTD_CCtx *cctx;
	int level;
	uint64_t raw_in;	/* bytes before compression */
	uint64_t comp_out;	/* bytes after compression */
};

/* Incoming state: the zstd context and the byte counts behind the
 * decompression ratio, which scales the channel window. */
struct hpn_zstd_in {
	ZSTD_DCtx *dctx;
	uint64_t comp_in;	/* compressed bytes from the wire */
	uint64_t raw_out;	/* bytes after decompression */
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
	    "factor %.2f", (unsigned long long)o->raw_in,
	    (unsigned long long)o->comp_out,
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
	uint64_t r;

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
