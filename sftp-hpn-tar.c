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
 * sftp-hpn-tar.c - HPN-SSH bundle codec.
 *
 * See sftp-hpn-tar.h for API + design.  Used on all four bundle code
 * paths (client UL/DL, server UL/DL).
 *
 * Format: a minimal length-prefixed binary record stream.  It is NOT tar
 * and is read only by HPN-SSH at the other end of the same connection, so
 * it carries no tar-compatibility baggage (no 512-byte blocks, no padding,
 * no octal fields, no per-record checksum, no magic, no uid/gid).  Each
 * entry is:
 *
 *     u8   type      HPN_REC_FILE (1)
 *     u32  mode      POSIX permission bits
 *     u64  mtime     seconds since the epoch
 *     u64  size      file data length in bytes
 *     u16  path_len  archive-path length (PATH_MAX < 64 KiB)
 *     u8[path_len]   archive path (no NUL; length-prefixed)
 *     u8[size]       file data
 *
 * The stream ends with a lone HPN_REC_END (0) byte where the next entry's
 * type byte would be.  All integers are big-endian (the stream can cross
 * architectures), serialised with the tree's POKE/PEEK macros.
 *
 * Implementation notes:
 *
 *  - Both state machines stream bytes through the caller's buffer.  The
 *    writer read()s source bytes straight into the output buffer; the
 *    parser delivers file bytes via data_cb straight from the wire buffer.
 *    No internal data copy, no padding.
 *
 *  - Per-direction scratch is the fixed record header plus its path
 *    (SFTP_HPN_TAR_HDR_MAX).  Any larger buffering is in the caller.
 *
 *  - Empty files (size == 0) skip the DATA state entirely.
 *
 *  - Mid-entry shrink-during-pack is detected (read() returns 0 with bytes
 *    still expected) and reported as an error: the size already went out in
 *    the header, so the stream cannot be repaired - the bundle bails and the
 *    orchestrator retries through the single-file path.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xmalloc.h"
#include "log.h"
#include "sshbuf.h"		/* POKE/PEEK big-endian field macros */
#include "sftp-hpn-tar.h"

/* ── Record layout ───────────────────────────────────────────────────────── */

#define HPN_REC_END	0u	/* lone type byte that ends the stream */
#define HPN_REC_FILE	1u	/* a regular-file entry follows */

/* Fixed record-header prefix, big-endian: type(1) mode(4) mtime(8) size(8)
 * path_len(2).  The variable-length path then runs from HPN_REC_OFF_PATH. */
#define HPN_REC_OFF_TYPE	0
#define HPN_REC_OFF_MODE	1
#define HPN_REC_OFF_MTIME	5
#define HPN_REC_OFF_SIZE	13
#define HPN_REC_OFF_PATHLEN	21
#define HPN_REC_OFF_PATH	23
#define HPN_REC_FIXED_HDR	23	/* bytes before the path */

/* ── Writer ──────────────────────────────────────────────────────────────── */

enum writer_state {
	WS_IDLE,	/* between files; advance to HEADER if more queued */
	WS_HEADER,	/* emitting the record header (fixed prefix + path) */
	WS_DATA,	/* reading source file and emitting data */
	WS_EOA,		/* emitting the trailing end-of-stream byte */
	WS_DONE,	/* nothing more to produce */
	WS_ERROR,	/* unrecoverable; pack_next returns -1 */
};

struct writer_file {
	char    *src_path;
	char    *archive_path;
	mode_t   mode;
	uint64_t size;
	time_t   mtime;
	struct writer_file *next;
};

struct sftp_hpn_tar_writer {
	enum writer_state state;
	struct writer_file *q_head;
	struct writer_file *q_tail;
	int   finish_signalled;

	/* Current entry state. */
	struct writer_file *cur;	/* the entry currently being emitted */
	int      cur_fd;		/* open() result for cur->src_path */
	uint64_t cur_data_emitted;	/* bytes of data written into out so far */
	u_char   hdr_buf[SFTP_HPN_TAR_HDR_MAX];	/* fixed prefix + path */
	size_t   hdr_total;		/* full header size (prefix + path) */
	size_t   hdr_pos;		/* bytes of hdr_buf already emitted */

	int      eoa_pending;		/* 1 = the end byte still owed */

	char    *err;			/* malloc'd; freed by writer_free */
};

static void
writer_set_error(struct sftp_hpn_tar_writer *w, const char *fmt, ...)
{
	va_list ap;
	int     r;

	if (w == NULL || w->err != NULL)
		return;	/* preserve first error */
	w->state = WS_ERROR;
	va_start(ap, fmt);
	r = vasprintf(&w->err, fmt, ap);
	va_end(ap);
	if (r < 0)
		w->err = NULL;	/* allocation failed; error is still set */
}

struct sftp_hpn_tar_writer *
sftp_hpn_tar_writer_new(void)
{
	struct sftp_hpn_tar_writer *w;

	w = calloc(1, sizeof(*w));
	if (w == NULL)
		return NULL;
	w->state  = WS_IDLE;
	w->cur_fd = -1;
	return w;
}

void
sftp_hpn_tar_writer_free(struct sftp_hpn_tar_writer *w)
{
	struct writer_file *f, *next;

	if (w == NULL)
		return;
	if (w->cur_fd >= 0)
		(void)close(w->cur_fd);
	for (f = w->q_head; f != NULL; f = next) {
		next = f->next;
		free(f->src_path);
		free(f->archive_path);
		free(f);
	}
	free(w->err);
	free(w);
}

int
sftp_hpn_tar_writer_add_file(struct sftp_hpn_tar_writer *w,
    const char *src_path, const char *archive_path,
    mode_t mode, uint64_t size, time_t mtime)
{
	struct writer_file *f;

	if (w == NULL || w->state == WS_ERROR || w->finish_signalled)
		return -1;
	if (src_path == NULL || archive_path == NULL ||
	    *src_path == '\0' || *archive_path == '\0')
		return -1;
	if (strlen(archive_path) > SFTP_HPN_TAR_MAX_PATH)
		return -1;	/* longer than PATH_MAX */
	f = calloc(1, sizeof(*f));
	if (f == NULL)
		return -1;
	f->src_path     = strdup(src_path);
	f->archive_path = strdup(archive_path);
	if (f->src_path == NULL || f->archive_path == NULL) {
		free(f->src_path);
		free(f->archive_path);
		free(f);
		return -1;
	}
	f->mode  = mode;
	f->size  = size;
	f->mtime = mtime;
	if (w->q_tail == NULL)
		w->q_head = f;
	else
		w->q_tail->next = f;
	w->q_tail = f;
	return 0;
}

void
sftp_hpn_tar_writer_finish(struct sftp_hpn_tar_writer *w)
{
	if (w == NULL)
		return;
	w->finish_signalled = 1;
}

/*
 * Build the record header for *cur into w->hdr_buf, reset w->hdr_pos to 0.
 * Returns 0 on success; -1 if the path is empty / oversized (caller moves
 * the writer to WS_ERROR via writer_set_error).
 */
static int
writer_build_header(struct sftp_hpn_tar_writer *w)
{
	struct writer_file *f = w->cur;
	size_t plen = strlen(f->archive_path);

	if (plen == 0 || plen > SFTP_HPN_TAR_MAX_PATH)
		return -1;
	w->hdr_buf[HPN_REC_OFF_TYPE] = (u_char)HPN_REC_FILE;
	POKE_U32(w->hdr_buf + HPN_REC_OFF_MODE, (u_int32_t)(f->mode & 07777));
	POKE_U64(w->hdr_buf + HPN_REC_OFF_MTIME, (u_int64_t)f->mtime);
	POKE_U64(w->hdr_buf + HPN_REC_OFF_SIZE, f->size);
	POKE_U16(w->hdr_buf + HPN_REC_OFF_PATHLEN, (u_int16_t)plen);
	memcpy(w->hdr_buf + HPN_REC_OFF_PATH, f->archive_path, plen);
	w->hdr_total = HPN_REC_FIXED_HDR + plen;
	w->hdr_pos   = 0;
	return 0;
}

/* Advance the writer out of WS_IDLE: dequeue the next file and build its
 * header, or - if the queue is drained and finish() was called - move to the
 * trailing end byte.  No-op when not in WS_IDLE. */
static void
writer_advance_idle(struct sftp_hpn_tar_writer *w)
{
	struct writer_file *f;

	if (w->state != WS_IDLE)
		return;
	if (w->q_head == NULL) {
		if (w->finish_signalled) {
			w->state       = WS_EOA;
			w->eoa_pending = 1;
		}
		return;
	}
	f = w->q_head;
	w->q_head = f->next;
	if (w->q_head == NULL)
		w->q_tail = NULL;
	f->next = NULL;
	w->cur  = f;
	w->cur_data_emitted = 0;
	if (writer_build_header(w) < 0) {
		writer_set_error(w, "header build failed for \"%s\"",
		    f->archive_path);
		return;
	}
	w->state = WS_HEADER;
}

/* Free the current entry and return to WS_IDLE. */
static void
writer_finish_entry(struct sftp_hpn_tar_writer *w)
{
	free(w->cur->src_path);
	free(w->cur->archive_path);
	free(w->cur);
	w->cur   = NULL;
	w->state = WS_IDLE;
}

ssize_t
sftp_hpn_tar_writer_pack_next(struct sftp_hpn_tar_writer *w,
    u_char *out, size_t max_bytes)
{
	size_t written = 0;

	if (w == NULL || out == NULL)
		return -1;
	if (w->state == WS_ERROR)
		return -1;
	if (w->state == WS_DONE)
		return 0;

	while (written < max_bytes) {
		if (w->state == WS_IDLE) {
			writer_advance_idle(w);
			if (w->state == WS_ERROR)
				return -1;
			if (w->state == WS_IDLE)
				break;	/* nothing queued, not finished yet */
		}

		if (w->state == WS_HEADER) {
			size_t avail = w->hdr_total - w->hdr_pos;
			size_t take  = (max_bytes - written) < avail
			    ? (max_bytes - written) : avail;
			memcpy(out + written, w->hdr_buf + w->hdr_pos, take);
			w->hdr_pos += take;
			written    += take;
			if (w->hdr_pos != w->hdr_total)
				continue;	/* header not fully emitted */
			/* Header done.  Empty file: advance; else open the
			 * source and stream its data. */
			if (w->cur->size == 0) {
				writer_finish_entry(w);
				continue;
			}
			w->cur_fd = open(w->cur->src_path, O_RDONLY);
			if (w->cur_fd < 0) {
				writer_set_error(w, "open \"%s\": %s",
				    w->cur->src_path, strerror(errno));
				return -1;
			}
			w->state = WS_DATA;
			continue;
		}

		if (w->state == WS_DATA) {
			uint64_t left = w->cur->size - w->cur_data_emitted;
			size_t   take = (max_bytes - written) < left
			    ? (max_bytes - written) : (size_t)left;
			ssize_t  n;

			if (take == 0) {		/* all data emitted */
				(void)close(w->cur_fd);
				w->cur_fd = -1;
				writer_finish_entry(w);
				continue;
			}
			n = read(w->cur_fd, out + written, take);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				writer_set_error(w, "read \"%s\": %s",
				    w->cur->src_path, strerror(errno));
				return -1;
			}
			if (n == 0) {
				/* Source shrank after add_file reported size;
				 * the header already committed `size`, so the
				 * stream cannot be repaired - fail the bundle. */
				writer_set_error(w,
				    "\"%s\" shrank during read "
				    "(%llu of %llu bytes)",
				    w->cur->src_path,
				    (unsigned long long)w->cur_data_emitted,
				    (unsigned long long)w->cur->size);
				return -1;
			}
			written             += (size_t)n;
			w->cur_data_emitted += (uint64_t)n;
			continue;
		}

		if (w->state == WS_EOA) {
			if (!w->eoa_pending) {
				w->state = WS_DONE;
				break;
			}
			out[written++]  = (u_char)HPN_REC_END;
			w->eoa_pending  = 0;
			w->state        = WS_DONE;
			break;
		}
	}

	if (written == 0 && w->state == WS_DONE)
		return 0;
	return (ssize_t)written;
}

const char *
sftp_hpn_tar_writer_error(struct sftp_hpn_tar_writer *w)
{
	return (w == NULL) ? NULL : w->err;
}

/* ── Parser ──────────────────────────────────────────────────────────────── */

enum parser_state {
	PS_HEADER,	/* accumulating a record header (prefix + path) */
	PS_DATA,	/* delivering file bytes to data_cb */
	PS_DONE,	/* end byte seen; further feed() is an error */
	PS_ERROR,
};

struct sftp_hpn_tar_parser {
	enum parser_state state;
	const struct sftp_hpn_tar_callbacks *cb;
	void   *ctx;

	u_char  hdr_buf[SFTP_HPN_TAR_HDR_MAX];	/* fixed prefix + path */
	size_t  hdr_total;	/* full header size; 0 until path_len is read */
	size_t  hdr_pos;

	uint64_t cur_size;	/* declared size of current entry */
	uint64_t cur_received;	/* bytes of data delivered to data_cb */

	char *err;
};

static void
parser_set_error(struct sftp_hpn_tar_parser *p, const char *fmt, ...)
{
	va_list ap;
	int     r;

	if (p == NULL || p->err != NULL)
		return;
	p->state = PS_ERROR;
	va_start(ap, fmt);
	r = vasprintf(&p->err, fmt, ap);
	va_end(ap);
	if (r < 0)
		p->err = NULL;
}

struct sftp_hpn_tar_parser *
sftp_hpn_tar_parser_new(const struct sftp_hpn_tar_callbacks *cb, void *ctx)
{
	struct sftp_hpn_tar_parser *p;

	if (cb == NULL)
		return NULL;
	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return NULL;
	p->cb    = cb;
	p->ctx   = ctx;
	p->state = PS_HEADER;
	return p;
}

void
sftp_hpn_tar_parser_free(struct sftp_hpn_tar_parser *p)
{
	if (p == NULL)
		return;
	free(p->err);
	free(p);
}

/*
 * Process w->hdr_buf as a fully-collected record header (fixed prefix + path).
 * Invokes entry_cb (and entry_end_cb immediately for empty files).  Sets state
 * to PS_DATA or PS_HEADER.  Returns 0 on success, -1 on error.
 */
static int
parser_handle_header(struct sftp_hpn_tar_parser *p)
{
	uint32_t mode_v  = PEEK_U32(p->hdr_buf + HPN_REC_OFF_MODE);
	uint64_t mtime_v = PEEK_U64(p->hdr_buf + HPN_REC_OFF_MTIME);
	uint64_t size_v  = PEEK_U64(p->hdr_buf + HPN_REC_OFF_SIZE);
	uint64_t plen    = PEEK_U16(p->hdr_buf + HPN_REC_OFF_PATHLEN);
	char     path[SFTP_HPN_TAR_MAX_PATH + 1];

	if (plen == 0 || plen > SFTP_HPN_TAR_MAX_PATH) {
		parser_set_error(p, "record bad/oversized path length");
		return -1;
	}
	memcpy(path, p->hdr_buf + HPN_REC_OFF_PATH, (size_t)plen);
	path[plen] = '\0';

	/*
	 * size_v is a client controlled 64-bit field that the consumers
	 * malloc((size_t)size) and posix_fallocate() up front, before any data
	 * arrives. A malicious client could potentially use this to craft a DOS
         * attack by claiming to have a ridiculously large size. 
         * The bundle path only ever carries small whole files (a file
	 * is bundle-eligible only below HPNBundleSize/4, and HPNBundleSize is
	 * itself capped at HPN_BUNDLE_SIZE_MAX), so a record larger than a whole
	 * bundle's maximum is never legitimate - reject it before the consumers
	 * reserve resources.  HPN_BUNDLE_SIZE_MAX < SIZE_MAX on every supported
	 * platform, so this also subsumes the ILP32 size_t-truncation case the
	 * previous SIZE_MAX guard handled.
	 */
	if (size_v > HPN_BUNDLE_SIZE_MAX) {
		parser_set_error(p, "record size %llu exceeds bundle maximum %llu",
		    (unsigned long long)size_v,
		    (unsigned long long)HPN_BUNDLE_SIZE_MAX);
		return -1;
	}

	if (p->cb->entry_cb != NULL &&
	    p->cb->entry_cb(p->ctx, path, size_v, (mode_t)(mode_v & 07777),
	    (time_t)mtime_v) != 0) {
		parser_set_error(p, "entry_cb rejected \"%s\"", path);
		return -1;
	}

	p->cur_size     = size_v;
	p->cur_received = 0;
	if (size_v == 0) {
		if (p->cb->entry_end_cb != NULL &&
		    p->cb->entry_end_cb(p->ctx) != 0) {
			parser_set_error(p, "entry_end_cb failed");
			return -1;
		}
		p->state = PS_HEADER;
	} else {
		p->state = PS_DATA;
	}
	return 0;
}

int
sftp_hpn_tar_parser_feed(struct sftp_hpn_tar_parser *p,
    const u_char *data, size_t len)
{
	if (p == NULL || data == NULL)
		return -1;
	if (p->state == PS_ERROR)
		return -1;
	if (p->state == PS_DONE) {
		parser_set_error(p, "feed after end-of-stream");
		return -1;
	}

	while (len > 0) {
		if (p->state == PS_HEADER) {
			size_t target, need, take;

			/* The very first byte of a record is the type: either
			 * the lone end marker, or a file entry. */
			if (p->hdr_pos == 0) {
				u_char type = *data;
				data++; len--; p->hdr_pos = 1;
				if (type == HPN_REC_END) {
					p->state = PS_DONE;
					return 1;	/* clean end */
				}
				if (type != HPN_REC_FILE) {
					parser_set_error(p,
					    "bad record type 0x%02x",
					    (unsigned)type);
					return -1;
				}
				p->hdr_buf[HPN_REC_OFF_TYPE] = type;
				p->hdr_total = 0;	/* path_len not read yet */
				continue;
			}

			/* Collect the rest of the fixed prefix, then the path. */
			target = (p->hdr_total != 0)
			    ? p->hdr_total : (size_t)HPN_REC_FIXED_HDR;
			need = target - p->hdr_pos;
			take = len < need ? len : need;
			memcpy(p->hdr_buf + p->hdr_pos, data, take);
			p->hdr_pos += take;
			data       += take;
			len        -= take;
			if (p->hdr_total == 0 &&
			    p->hdr_pos == (size_t)HPN_REC_FIXED_HDR) {
				uint64_t plen =
				    PEEK_U16(p->hdr_buf + HPN_REC_OFF_PATHLEN);
				if (plen == 0 ||
				    plen > SFTP_HPN_TAR_MAX_PATH) {
					parser_set_error(p,
					    "record bad/oversized path length");
					return -1;
				}
				p->hdr_total = HPN_REC_FIXED_HDR + (size_t)plen;
			}
			if (p->hdr_total != 0 && p->hdr_pos == p->hdr_total) {
				if (parser_handle_header(p) < 0)
					return -1;
				p->hdr_pos   = 0;
				p->hdr_total = 0;
			}
			continue;
		}

		if (p->state == PS_DATA) {
			uint64_t left = p->cur_size - p->cur_received;
			size_t   take = len < left ? len : (size_t)left;

			if (p->cb->data_cb != NULL && take > 0 &&
			    p->cb->data_cb(p->ctx, data, take) != 0) {
				parser_set_error(p, "data_cb failed");
				return -1;
			}
			data            += take;
			len             -= take;
			p->cur_received += (uint64_t)take;
			if (p->cur_received == p->cur_size) {
				if (p->cb->entry_end_cb != NULL &&
				    p->cb->entry_end_cb(p->ctx) != 0) {
					parser_set_error(p,
					    "entry_end_cb failed");
					return -1;
				}
				p->state = PS_HEADER;	/* next record */
			}
			continue;
		}

		/* Should be unreachable. */
		parser_set_error(p, "internal: unknown parser state %d",
		    (int)p->state);
		return -1;
	}
	return 0;
}

const char *
sftp_hpn_tar_parser_error(struct sftp_hpn_tar_parser *p)
{
	return (p == NULL) ? NULL : p->err;
}
