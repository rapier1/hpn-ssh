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

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif

#include "log.h"
#include "misc.h"
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

/* The compression fields at the end of the server's throughput log line:
 * method, level, and the factor for IN and for OUT. */
#define HPN_ZSTD_LOG_FIELDS	";Comp: %s;Level: %s;Comp_in: %s;Comp_out: %s"

#ifdef HAVE_LIBZSTD

/* The decompressor's window limit, as a power of two. The compressor at
 * levels 1 to 19 never uses a window above 8 MiB (windowLog 23), so 16 MiB
 * accepts every frame we negotiate while bounding the decoder memory an
 * authenticated peer's frames can demand. HPN_ZSTD_PACKET_RAW_MAX bounds
 * the output. */
#define HPN_ZSTD_WINDOW_LOG_MAX	24

/* The stack buffer each compress or uncompress pass fills before copying
 * to the output. zlib's path uses 4 KiB, and zstd works in larger blocks. */
#define HPN_ZSTD_IOBUF		(16 * 1024)

/* The most one packet may decompress to: twice upstream's PACKET_MAX_SIZE,
 * for headroom. A zstd RLE block expands 4 bytes to 128 KiB, so without a
 * limit one packet could grow the output buffer to SSHBUF_SIZE_MAX. */
#define HPN_ZSTD_PACKET_RAW_MAX	(512 * 1024)

/* The decompression ratio stays at 1.0x until this many compressed bytes
 * have arrived, and never reports above 100x. */
#define HPN_ZSTD_RATIO_WARMUP	(1024 * 1024)
#define HPN_ZSTD_RATIO_MAX	(100 * HPN_ZSTD_RATIO_ONE)

/* Outgoing state: the zstd context, its level, and its byte counts. The
 * counts feed the debug summary. The level and counts feed the server's
 * throughput log line. */
struct hpn_zstd_out {
	ZSTD_CCtx *cctx;
	int level;		/* after clamp_level */
	uint64_t raw_in;	/* bytes before compression */
	uint64_t comp_out;	/* bytes after compression */
};

/* Incoming state: the zstd context and its byte counts. The counts feed
 * the decompression ratio that scales the channel window, the debug
 * summary, and the server's throughput log line. */
struct hpn_zstd_in {
	ZSTD_DCtx *dctx;
	uint64_t comp_in;	/* compressed bytes from the wire */
	uint64_t raw_out;	/* bytes after decompression */
};

/* Hold the level to HPN_ZSTD_LEVEL_MIN through HPN_ZSTD_LEVEL_MAX, the
 * range HPN_ZSTD_WINDOW_LOG_MAX assumes. The -z options, ZstdLevel, and
 * the client's marker are range-checked already. The level the server
 * takes from the sshd-auth state in ssh_packet_set_state is not. */
static int
clamp_level(int level)
{
	int clamped = MAXIMUM(HPN_ZSTD_LEVEL_MIN,
	    MINIMUM(level, HPN_ZSTD_LEVEL_MAX));

	if (clamped != level)
		error_f("zstd level %d out of range, using %d",
		    level, clamped);
	return clamped;
}

/* Start the outgoing stream at level. The first call allocates the state
 * and stores it in *outp. Each later call comes at a rekey and resets the
 * stream and its parameters before the level is set again. */
int
hpn_zstd_out_start(struct hpn_zstd_out **outp, int level)
{
	struct hpn_zstd_out *comp = *outp;
	size_t ret;

	level = clamp_level(level);
	if (comp == NULL) {
		if ((comp = calloc(1, sizeof(*comp))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((comp->cctx = ZSTD_createCCtx()) == NULL) {
			free(comp);
			return SSH_ERR_ALLOC_FAIL;
		}
		*outp = comp;
	} else {
		/* A rekey starts a fresh stream, as start_compression_out
		 * does for zlib with deflateEnd and deflateInit. */
		ret = ZSTD_CCtx_reset(comp->cctx,
		    ZSTD_reset_session_and_parameters);
		if (ZSTD_isError(ret)) {
			error_f("zstd reset: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INTERNAL_ERROR;
		}
	}
	ret = ZSTD_CCtx_setParameter(comp->cctx, ZSTD_c_compressionLevel,
	    level);
	if (ZSTD_isError(ret)) {
		error_f("zstd set level %d: %s", level, ZSTD_getErrorName(ret));
		return SSH_ERR_INTERNAL_ERROR;
	}
	comp->level = level;
	debug("Enabling zstd compression at level %d.", level);
	return 0;
}

/* Start the incoming stream. The first call allocates the state and
 * stores it in *inp. Each later call comes at a rekey and resets the
 * stream and its parameters before the window limit is set again. The
 * byte counts carry across a rekey, so the ratio covers the session. */
int
hpn_zstd_in_start(struct hpn_zstd_in **inp)
{
	struct hpn_zstd_in *decomp = *inp;
	size_t ret;

	if (decomp == NULL) {
		if ((decomp = calloc(1, sizeof(*decomp))) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if ((decomp->dctx = ZSTD_createDCtx()) == NULL) {
			free(decomp);
			return SSH_ERR_ALLOC_FAIL;
		}
		*inp = decomp;
	} else {
		/* A rekey starts a fresh stream, as start_compression_in
		 * does for zlib with inflateEnd and inflateInit. */
		ret = ZSTD_DCtx_reset(decomp->dctx,
		    ZSTD_reset_session_and_parameters);
		if (ZSTD_isError(ret)) {
			error_f("zstd reset: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INTERNAL_ERROR;
		}
	}
	ret = ZSTD_DCtx_setParameter(decomp->dctx, ZSTD_d_windowLogMax,
	    HPN_ZSTD_WINDOW_LOG_MAX);
	if (ZSTD_isError(ret)) {
		error_f("zstd set window limit: %s", ZSTD_getErrorName(ret));
		return SSH_ERR_INTERNAL_ERROR;
	}
	return 0;
}

/* Log the outgoing byte counts, as packet.c does for zlib when the
 * connection closes, then free the state and clear *outp. */
void
hpn_zstd_out_free(struct hpn_zstd_out **outp)
{
	struct hpn_zstd_out *comp = *outp;

	if (comp == NULL)
		return;
	debug("compress outgoing (zstd): raw data %llu, compressed %llu, "
	    "factor %.2f", (unsigned long long)comp->raw_in,
	    (unsigned long long)comp->comp_out,
	    comp->raw_in == 0 ? 0.0 : (double)comp->comp_out / comp->raw_in);
	ZSTD_freeCCtx(comp->cctx);
	free(comp);
	*outp = NULL;
}

/* Log the incoming byte counts, as packet.c does for zlib when the
 * connection closes, then free the state and clear *inp. */
void
hpn_zstd_in_free(struct hpn_zstd_in **inp)
{
	struct hpn_zstd_in *decomp = *inp;

	if (decomp == NULL)
		return;
	debug("compress incoming (zstd): raw data %llu, compressed %llu, "
	    "factor %.2f", (unsigned long long)decomp->raw_out,
	    (unsigned long long)decomp->comp_in,
	    decomp->raw_out == 0 ? 0.0 :
	    (double)decomp->comp_in / decomp->raw_out);
	ZSTD_freeDCtx(decomp->dctx);
	free(decomp);
	*inp = NULL;
}

/* Compress all of in onto the end of out and flush, so the peer can
 * decode the packet as soon as it lands. The flush is the zstd
 * counterpart of the Z_PARTIAL_FLUSH in compress_buffer. */
int
hpn_zstd_compress(struct hpn_zstd_out *comp, struct sshbuf *in,
    struct sshbuf *out)
{
	u_char buf[HPN_ZSTD_IOBUF];
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	size_t ret;
	int r;

	if (comp == NULL) {
		error_f("no zstd stream");
		return SSH_ERR_INTERNAL_ERROR;
	}
	if (sshbuf_len(in) == 0)
		return 0;
	comp->raw_in += sshbuf_len(in);
	zin.src = sshbuf_ptr(in);
	zin.size = sshbuf_len(in);
	zin.pos = 0;
	/* Loop until the input is consumed and the flush has drained. A
	 * return of 0 means nothing is left inside the context. */
	do {
		zout.dst = buf;
		zout.size = sizeof(buf);
		zout.pos = 0;
		ret = ZSTD_compressStream2(comp->cctx, &zout, &zin,
		    ZSTD_e_flush);
		if (ZSTD_isError(ret)) {
			error_f("zstd compress: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INVALID_FORMAT;
		}
		if (zout.pos > 0) {
			comp->comp_out += zout.pos;
			if ((r = sshbuf_put(out, buf, zout.pos)) != 0)
				return r;
		}
	} while (zin.pos < zin.size || ret != 0);
	return 0;
}

/* Decompress all of in onto the end of out. The sender flushed after
 * each packet, so the packet decodes from in alone. */
int
hpn_zstd_uncompress(struct hpn_zstd_in *decomp, struct sshbuf *in,
    struct sshbuf *out)
{
	u_char buf[HPN_ZSTD_IOBUF];
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	size_t ret;
	size_t packet_raw = 0;
	int r;

	if (decomp == NULL) {
		error_f("no zstd stream");
		return SSH_ERR_INTERNAL_ERROR;
	}
	if (sshbuf_len(in) == 0)
		return 0;
	decomp->comp_in += sshbuf_len(in);
	zin.src = sshbuf_ptr(in);
	zin.size = sshbuf_len(in);
	zin.pos = 0;
	/* Loop while input remains, or while the last call filled
	 * the whole output buffer (more may be buffered inside). */
	do {
		zout.dst = buf;
		zout.size = sizeof(buf);
		zout.pos = 0;
		ret = ZSTD_decompressStream(decomp->dctx, &zout, &zin);
		if (ZSTD_isError(ret)) {
			error_f("zstd uncompress: %s", ZSTD_getErrorName(ret));
			return SSH_ERR_INVALID_FORMAT;
		}
		if (zout.pos > 0) {
			packet_raw += zout.pos;
			if (packet_raw > HPN_ZSTD_PACKET_RAW_MAX) {
				error_f("zstd packet expands past %d bytes",
				    HPN_ZSTD_PACKET_RAW_MAX);
				return SSH_ERR_INVALID_FORMAT;
			}
			decomp->raw_out += zout.pos;
			if ((r = sshbuf_put(out, buf, zout.pos)) != 0)
				return r;
		}
	} while (zin.pos < zin.size || zout.pos == zout.size);
	return 0;
}

/* The decompression ratio, raw bytes over wire bytes, in thousandths, so
 * 2:1 returns 2000. It stays at 1.0x until HPN_ZSTD_RATIO_WARMUP wire bytes
 * have arrived, so the window does not act on a noisy early estimate, and
 * it is held to 1.0x through 100x. channel_tcpwinsz scales its wire-level
 * receive signal by it to size the plaintext channel window. */
u_int
hpn_zstd_in_ratio_milli(struct hpn_zstd_in *decomp)
{
	uint64_t ratio_milli;

	if (decomp == NULL || decomp->comp_in < HPN_ZSTD_RATIO_WARMUP)
		return HPN_ZSTD_RATIO_ONE;
	ratio_milli = decomp->raw_out * HPN_ZSTD_RATIO_ONE / decomp->comp_in;
	/* Below 1.0x the window would be sized under the wire BDP. */
	return (u_int)MAXIMUM(HPN_ZSTD_RATIO_ONE,
	    MINIMUM(ratio_milli, HPN_ZSTD_RATIO_MAX));
}

/* The compression fields of the server's throughput log line. IN and OUT
 * are as the client sees them, so Comp_in is the factor of what the server
 * sent and Comp_out the factor of what it received. A factor is compressed
 * bytes over raw bytes, as in the debug summaries. Here it has three
 * places, so 0.000 means better than 2000:1 and is not an error. A field
 * with no zstd stream behind it reads N/A, and the method then reads zlib
 * or none. The string is static and good until the next call. */
const char *
hpn_zstd_log_fields(const struct hpn_zstd_out *comp,
    const struct hpn_zstd_in *decomp, int zlib_started)
{
	static char fields[96];
	char level[16] = "N/A", factor_in[16] = "N/A", factor_out[16] = "N/A";
	const char *method = zlib_started ? "zlib" : "none";

	if (comp != NULL) {
		method = "zstd";
		snprintf(level, sizeof(level), "%d", comp->level);
		if (comp->raw_in > 0)
			snprintf(factor_in, sizeof(factor_in), "%.3f",
			    (double)comp->comp_out / comp->raw_in);
	}
	if (decomp != NULL) {
		method = "zstd";
		if (decomp->raw_out > 0)
			snprintf(factor_out, sizeof(factor_out), "%.3f",
			    (double)decomp->comp_in / decomp->raw_out);
	}
	snprintf(fields, sizeof(fields), HPN_ZSTD_LOG_FIELDS, method, level,
	    factor_in, factor_out);
	return fields;
}

#else /* !HAVE_LIBZSTD */

/* Built without libzstd. compression_alg_list never offers zstd@hpnssh.org
 * and choose_comp never accepts it, so no stream is ever started and the
 * state pointers stay NULL. These stubs only satisfy the calls in packet.c. */

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
hpn_zstd_compress(struct hpn_zstd_out *comp, struct sshbuf *in,
    struct sshbuf *out)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

int
hpn_zstd_uncompress(struct hpn_zstd_in *decomp, struct sshbuf *in,
    struct sshbuf *out)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}

u_int
hpn_zstd_in_ratio_milli(struct hpn_zstd_in *decomp)
{
	return HPN_ZSTD_RATIO_ONE;
}

const char *
hpn_zstd_log_fields(const struct hpn_zstd_out *comp,
    const struct hpn_zstd_in *decomp, int zlib_started)
{
	static char fields[96];

	snprintf(fields, sizeof(fields), HPN_ZSTD_LOG_FIELDS,
	    zlib_started ? "zlib" : "none", "N/A", "N/A", "N/A");
	return fields;
}

#endif /* HAVE_LIBZSTD */

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

/* Server side, at every KEX. Take the level for what the server sends
 * from the marker in the client's proposal. A proposal without a marker,
 * or with a level out of range, leaves the level as it was. */
void
hpn_zstd_take_peer_level(struct ssh *ssh, const char *proposal)
{
	size_t prefix_len = strlen(HPN_ZSTD_MARKER_PREFIX);
	size_t suffix_len = strlen(HPN_ZSTD_MARKER_SUFFIX);
	char *list, *cp, *name;
	const char *errstr;
	size_t name_len;
	int level;

	if (proposal == NULL)
		return;
	/* strsep and the suffix cut below both write into the string, so
	 * parse a copy. */
	list = cp = xstrdup(proposal);
	while ((name = strsep(&cp, ",")) != NULL) {
		/* A marker is the prefix, at least one character, and the
		 * suffix. Method names fail one of these tests. */
		name_len = strlen(name);
		if (name_len <= prefix_len + suffix_len ||
		    strncmp(name, HPN_ZSTD_MARKER_PREFIX, prefix_len) != 0 ||
		    strcmp(name + name_len - suffix_len,
		    HPN_ZSTD_MARKER_SUFFIX) != 0)
			continue;
		/* End the string at the suffix so strtonum sees only the
		 * level. */
		name[name_len - suffix_len] = '\0';
		/* A level out of range or with stray characters fails here,
		 * and the level then stays as it was. A broken or hostile
		 * client cannot move it. */
		level = (int)strtonum(name + prefix_len, HPN_ZSTD_LEVEL_MIN,
		    HPN_ZSTD_LEVEL_MAX, &errstr);
		if (errstr != NULL)
			debug_f("ignoring the zstd level marker: level %s",
			    errstr);
		else {
			debug_f("the client asked for zstd level %d", level);
			ssh_packet_set_zstd_level(ssh, level);
		}
		/* Only the first marker counts. */
		break;
	}
	free(list);
}
