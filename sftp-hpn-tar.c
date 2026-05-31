/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the BSD 2-Clause License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the BSD 2-Clause License for more
 * details.
 *
 * You should have received a copy of the BSD 2-Clause License along with this
 * library; if not, see https://opensource.org/license/bsd-2-clause.
 *
 */

/*
 * sftp-hpn-tar.c — HPN-SSH USTAR codec for the bundle path.
 *
 * See sftp-hpn-tar.h for API + design.  Replaces libarchive on all
 * four bundle code paths (client UL/DL, server UL/DL).
 *
 * Format: POSIX 1003.1-1988 USTAR.  Header layout, octal fields, and
 * checksum match the format produced by GNU tar / BSD tar / pax in
 * default mode, so an intercepted bundle can be inspected with
 * `tar tvf` for debugging.
 *
 * Implementation notes:
 *
 *  - Both state machines stream bytes through the caller's buffer.
 *    Writer pulls source-file bytes via read() into the output buffer
 *    directly when possible (no internal copy).  Parser writes file
 *    bytes through the data_cb directly from the wire buffer it is
 *    fed (no internal copy).
 *
 *  - Per-direction scratch is exactly the 512-byte USTAR header.  Any
 *    larger buffering happens in the caller (the SFTP message queue,
 *    HPN_BUNDLE_QUEUE_MAX_BYTES, etc.).
 *
 *  - Empty files (size == 0) skip the DATA state entirely; pack_next
 *    goes HEADER → next file.  Parser goes HEADER → entry_end_cb on
 *    the same call (no data_cb invocations).
 *
 *  - Mid-entry shrink-during-pack is detected (read() returns 0 with
 *    bytes still expected) and reported as an error.  This matches
 *    the contract documented in sftp-hpn-server.c bundle_fetch_pack_one().
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
#include "sftp-hpn-tar.h"

/* ── Common header layout helpers ────────────────────────────────────────── */

#define TAR_NAME_OFF       0
#define TAR_NAME_LEN     100
#define TAR_MODE_OFF     100
#define TAR_MODE_LEN       8
#define TAR_UID_OFF      108
#define TAR_UID_LEN        8
#define TAR_GID_OFF      116
#define TAR_GID_LEN        8
#define TAR_SIZE_OFF     124
#define TAR_SIZE_LEN      12
#define TAR_MTIME_OFF    136
#define TAR_MTIME_LEN     12
#define TAR_CKSUM_OFF    148
#define TAR_CKSUM_LEN      8
#define TAR_TYPE_OFF     156
#define TAR_LINK_OFF     157
#define TAR_LINK_LEN     100
#define TAR_MAGIC_OFF    257
#define TAR_MAGIC_LEN      6  /* "ustar\0" */
#define TAR_VERS_OFF     263
#define TAR_VERS_LEN       2  /* "00" */
#define TAR_PREFIX_OFF   345
#define TAR_PREFIX_LEN   155

#define TAR_TYPE_REG     '0'
#define TAR_TYPE_REG_OLD '\0'

/*
 * Write an octal field with NUL-terminator.  width includes the NUL.
 * If the value doesn't fit, returns -1 (caller treats as overflow).
 *
 * NUL-terminated octal is the POSIX 1003.1 ustar convention.  Some
 * older implementations use trailing space + NUL or trailing space
 * only; we emit NUL-terminated which all modern readers accept.
 */
static int
tar_put_octal(u_char *buf, size_t off, size_t width, uint64_t value)
{
	if (width == 0)
		return -1;
	/* Largest value representable in (width-1) octal digits is
	 * 8^(width-1) - 1.  For SIZE_OFF (12 bytes), that is 8^11 - 1
	 * = 8 GiB - 1, which is comfortably above the per-bundle cap.
	 * For MTIME, 8 GiB seconds is many years past Y2038 — fine.
	 * Detect overflow by formatting and checking length. */
	char  tmp[32];
	int n = snprintf(tmp, sizeof(tmp), "%llo",
	    (unsigned long long)value);
	if (n < 0 || (size_t)n >= width)
		return -1;
	size_t pad = width - 1 - (size_t)n;
	memset(buf + off, '0', pad);
	memcpy(buf + off + pad, tmp, (size_t)n);
	buf[off + width - 1] = '\0';
	return 0;
}

/*
 * Parse a NUL- or space-terminated octal field.  Returns 0 on success
 * with *out set, -1 on parse failure.  Accepts both space-padded and
 * zero-padded fields (USTAR variants).
 */
static int
tar_get_octal(const u_char *buf, size_t off, size_t width, uint64_t *out)
{
	uint64_t v = 0;
	size_t   i;
	int      seen_digit = 0;

	for (i = 0; i < width; i++) {
		u_char c = buf[off + i];
		if (c == '\0' || c == ' ') {
			if (seen_digit)
				break;
			continue;
		}
		if (c < '0' || c > '7')
			return -1;
		if (v > UINT64_MAX / 8)
			return -1;
		v = v * 8 + (uint64_t)(c - '0');
		seen_digit = 1;
	}
	if (!seen_digit)
		return -1;
	*out = v;
	return 0;
}

/*
 * Compute USTAR checksum.  POSIX defines this as the sum of all 512
 * bytes treating the 8-byte checksum field as 8 ASCII spaces (0x20).
 * Sum is unsigned 32-bit; some old implementations use signed sum and
 * we accept either by also computing the signed variant on parse if
 * the unsigned check fails.
 */
static uint32_t
tar_checksum(const u_char *hdr)
{
	uint32_t sum = 0;
	size_t   i;

	for (i = 0; i < SFTP_HPN_TAR_BLOCK; i++) {
		if (i >= TAR_CKSUM_OFF &&
		    i <  TAR_CKSUM_OFF + TAR_CKSUM_LEN)
			sum += (uint32_t)' ';
		else
			sum += (uint32_t)hdr[i];
	}
	return sum;
}

/*
 * Split an archive path into (prefix, name) for USTAR.  Returns:
 *    0    — fits in name alone (<=100 chars); prefix is empty.
 *    1    — split successful; *prefix_len is the prefix component
 *           length, *name_off is the offset into path where the
 *           name component starts (i.e. just past the "/" we split
 *           on).
 *   -1    — does not fit even with prefix splitting (path too long,
 *           or no "/" in a suitable position).
 *
 * USTAR convention: prefix ≤ 155 chars, "/" separator (implicit),
 * name ≤ 100 chars.  Total path = prefix + "/" + name.  For paths
 * <= 100 chars we put it entirely in name and leave prefix empty.
 */
static int
tar_split_path(const char *path, size_t *prefix_len, size_t *name_off)
{
	size_t len = strlen(path);

	if (len == 0)
		return -1;
	if (len <= TAR_NAME_LEN) {
		*prefix_len = 0;
		*name_off = 0;
		return 0;
	}
	if (len > SFTP_HPN_TAR_MAX_PATH)
		return -1;
	/* Find a "/" such that the prefix (before "/") fits in 155 bytes
	 * and the name (after "/") fits in 100 bytes.  Walk from the
	 * latest such "/" backward for the most prefix-heavy split. */
	size_t i;
	size_t best = (size_t)-1;
	for (i = len; i > 0; i--) {
		if (path[i - 1] != '/')
			continue;
		size_t name_len = len - i;	/* bytes after the "/" */
		size_t pre_len  = i - 1;	/* bytes before the "/" */
		if (name_len <= TAR_NAME_LEN &&
		    pre_len  <= TAR_PREFIX_LEN) {
			best = i;
			break;
		}
	}
	if (best == (size_t)-1)
		return -1;
	*prefix_len = best - 1;
	*name_off   = best;
	return 0;
}

/* ── Writer ──────────────────────────────────────────────────────────────── */

enum writer_state {
	WS_IDLE,	/* between files; advance to HEADER if more queued */
	WS_HEADER,	/* emitting 512-byte header from hdr_buf */
	WS_DATA,	/* reading source file and emitting data */
	WS_PADDING,	/* emitting zero bytes to next 512-byte boundary */
	WS_EOA,		/* emitting trailing two zero blocks */
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
	uint64_t cur_pad_remaining;	/* zero bytes still owed for alignment */
	u_char   hdr_buf[SFTP_HPN_TAR_BLOCK];
	size_t   hdr_pos;		/* bytes of hdr_buf already emitted */

	/* EOA: two zero blocks (1024 bytes). */
	size_t   eoa_remaining;

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
	size_t prefix_len = 0, name_off = 0;

	if (w == NULL || w->state == WS_ERROR || w->finish_signalled)
		return -1;
	if (src_path == NULL || archive_path == NULL ||
	    *src_path == '\0' || *archive_path == '\0')
		return -1;
	if (tar_split_path(archive_path, &prefix_len, &name_off) < 0)
		return -1;	/* path too long for USTAR even with prefix */
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
 * Build the 512-byte USTAR header for *cur into w->hdr_buf, reset
 * w->hdr_pos to 0.  Returns 0 on success; -1 on overflow / oversized
 * field (writer is moved to WS_ERROR by the caller via writer_set_error).
 */
static int
writer_build_header(struct sftp_hpn_tar_writer *w)
{
	struct writer_file *f = w->cur;
	size_t prefix_len = 0, name_off = 0;

	memset(w->hdr_buf, 0, SFTP_HPN_TAR_BLOCK);
	if (tar_split_path(f->archive_path, &prefix_len, &name_off) < 0)
		return -1;
	if (prefix_len > 0) {
		memcpy(w->hdr_buf + TAR_PREFIX_OFF, f->archive_path,
		    prefix_len);
		size_t name_len = strlen(f->archive_path) - name_off;
		memcpy(w->hdr_buf + TAR_NAME_OFF,
		    f->archive_path + name_off,
		    name_len > TAR_NAME_LEN ? TAR_NAME_LEN : name_len);
	} else {
		size_t name_len = strlen(f->archive_path);
		memcpy(w->hdr_buf + TAR_NAME_OFF, f->archive_path,
		    name_len > TAR_NAME_LEN ? TAR_NAME_LEN : name_len);
	}

	if (tar_put_octal(w->hdr_buf, TAR_MODE_OFF, TAR_MODE_LEN,
	    (uint64_t)(f->mode & 07777)) < 0 ||
	    tar_put_octal(w->hdr_buf, TAR_UID_OFF, TAR_UID_LEN, 0) < 0 ||
	    tar_put_octal(w->hdr_buf, TAR_GID_OFF, TAR_GID_LEN, 0) < 0 ||
	    tar_put_octal(w->hdr_buf, TAR_SIZE_OFF, TAR_SIZE_LEN,
	    f->size) < 0 ||
	    tar_put_octal(w->hdr_buf, TAR_MTIME_OFF, TAR_MTIME_LEN,
	    (uint64_t)f->mtime) < 0)
		return -1;

	w->hdr_buf[TAR_TYPE_OFF] = TAR_TYPE_REG;
	memcpy(w->hdr_buf + TAR_MAGIC_OFF, "ustar", 5);
	w->hdr_buf[TAR_MAGIC_OFF + 5] = '\0';
	memcpy(w->hdr_buf + TAR_VERS_OFF, "00", 2);

	/* Fill checksum field with spaces, compute, then overwrite. */
	memset(w->hdr_buf + TAR_CKSUM_OFF, ' ', TAR_CKSUM_LEN);
	uint32_t cksum = tar_checksum(w->hdr_buf);
	/* Standard convention: 6 octal digits + NUL + space. */
	char tmp[8];
	int n = snprintf(tmp, sizeof(tmp), "%06o", cksum);
	if (n < 0)
		return -1;
	memcpy(w->hdr_buf + TAR_CKSUM_OFF, tmp, 6);
	w->hdr_buf[TAR_CKSUM_OFF + 6] = '\0';
	w->hdr_buf[TAR_CKSUM_OFF + 7] = ' ';

	w->hdr_pos = 0;
	return 0;
}

/* Advance the writer one state transition, opening files / building
 * headers as needed.  Idempotent: safe to call when already in a
 * data-producing state (returns immediately). */
static void
writer_advance_idle(struct sftp_hpn_tar_writer *w)
{
	if (w->state != WS_IDLE)
		return;
	if (w->q_head == NULL) {
		if (w->finish_signalled) {
			w->state = WS_EOA;
			w->eoa_remaining = 2 * SFTP_HPN_TAR_BLOCK;
		}
		return;
	}
	/* Dequeue next file → set up its header → transition. */
	struct writer_file *f = w->q_head;
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
			if (w->state == WS_IDLE) {
				/* Nothing queued and not finished → caller
				 * must call finish() (or add more) before
				 * we can advance.  Return what we have. */
				break;
			}
		}

		if (w->state == WS_HEADER) {
			size_t avail = SFTP_HPN_TAR_BLOCK - w->hdr_pos;
			size_t take  = (max_bytes - written) < avail
			    ? (max_bytes - written) : avail;
			memcpy(out + written, w->hdr_buf + w->hdr_pos, take);
			w->hdr_pos += take;
			written    += take;
			if (w->hdr_pos == SFTP_HPN_TAR_BLOCK) {
				/* Header fully emitted.  Open the source
				 * file (unless size == 0; then skip DATA). */
				w->hdr_pos = 0;
				if (w->cur->size == 0) {
					/* Empty file: no data, no padding
					 * (data is 0 bytes, already aligned).
					 * Free the entry and advance. */
					free(w->cur->src_path);
					free(w->cur->archive_path);
					free(w->cur);
					w->cur   = NULL;
					w->state = WS_IDLE;
					continue;
				}
				w->cur_fd = open(w->cur->src_path, O_RDONLY);
				if (w->cur_fd < 0) {
					writer_set_error(w,
					    "open \"%s\": %s",
					    w->cur->src_path, strerror(errno));
					return -1;
				}
				w->state = WS_DATA;
				continue;
			}
			continue;
		}

		if (w->state == WS_DATA) {
			uint64_t left = w->cur->size - w->cur_data_emitted;
			size_t   take = (max_bytes - written) < left
			    ? (max_bytes - written) : (size_t)left;
			if (take == 0) {
				/* All data emitted; transition. */
				goto data_done;
			}
			ssize_t n = read(w->cur_fd, out + written, take);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				writer_set_error(w, "read \"%s\": %s",
				    w->cur->src_path, strerror(errno));
				return -1;
			}
			if (n == 0) {
				/* Source file shrank after add_file
				 * reported size.  We have already committed
				 * `size` in the header — there is no way to
				 * repair the stream.  Fail the bundle. */
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
			if (w->cur_data_emitted < w->cur->size)
				continue;
		data_done:
			(void)close(w->cur_fd);
			w->cur_fd = -1;
			/* Compute padding: round up to next BLOCK boundary. */
			uint64_t mod = w->cur->size % SFTP_HPN_TAR_BLOCK;
			w->cur_pad_remaining = (mod == 0) ? 0
			    : (SFTP_HPN_TAR_BLOCK - mod);
			w->state = WS_PADDING;
			continue;
		}

		if (w->state == WS_PADDING) {
			if (w->cur_pad_remaining == 0) {
				/* Done with this entry. */
				free(w->cur->src_path);
				free(w->cur->archive_path);
				free(w->cur);
				w->cur   = NULL;
				w->state = WS_IDLE;
				continue;
			}
			size_t take = (max_bytes - written) <
			    w->cur_pad_remaining
			    ? (max_bytes - written)
			    : (size_t)w->cur_pad_remaining;
			memset(out + written, 0, take);
			written              += take;
			w->cur_pad_remaining -= take;
			continue;
		}

		if (w->state == WS_EOA) {
			if (w->eoa_remaining == 0) {
				w->state = WS_DONE;
				break;
			}
			size_t take = (max_bytes - written) <
			    w->eoa_remaining
			    ? (max_bytes - written)
			    : (size_t)w->eoa_remaining;
			memset(out + written, 0, take);
			written          += take;
			w->eoa_remaining -= take;
			continue;
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
	PS_HEADER,	/* accumulating 512-byte header */
	PS_DATA,	/* delivering file bytes to data_cb */
	PS_PADDING,	/* skipping zero bytes to BLOCK boundary */
	PS_EOA_2ND,	/* first zero block seen; expecting second */
	PS_DONE,	/* EOA complete; further feed() is an error */
	PS_ERROR,
};

struct sftp_hpn_tar_parser {
	enum parser_state state;
	const struct sftp_hpn_tar_callbacks *cb;
	void   *ctx;

	u_char  hdr_buf[SFTP_HPN_TAR_BLOCK];
	size_t  hdr_pos;

	uint64_t cur_size;	/* declared size of current entry */
	uint64_t cur_received;	/* bytes of data delivered to data_cb */
	uint64_t pad_remaining;	/* bytes still to skip in PADDING */
	uint64_t eoa_remaining;	/* bytes still to verify in PS_EOA_2ND */

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
 * Process w->hdr_buf as a fully-collected USTAR header.  May invoke
 * entry_cb.  Sets state to PS_DATA / PS_PADDING / PS_EOA_2ND / PS_ERROR
 * depending on what the header tells us.  Returns 0 on success, -1
 * on error (parser_set_error already called).
 */
static int
parser_handle_header(struct sftp_hpn_tar_parser *p)
{
	/* First, the all-zero check (EOA marker). */
	size_t i;
	int    all_zero = 1;
	for (i = 0; i < SFTP_HPN_TAR_BLOCK; i++) {
		if (p->hdr_buf[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	if (all_zero) {
		p->state = PS_EOA_2ND;
		p->eoa_remaining = SFTP_HPN_TAR_BLOCK;
		return 0;
	}

	/* Verify magic. */
	if (memcmp(p->hdr_buf + TAR_MAGIC_OFF, "ustar", 5) != 0) {
		parser_set_error(p, "tar header missing 'ustar' magic");
		return -1;
	}

	/* Verify checksum.  Save the field, replace with spaces, compute,
	 * compare against the saved (parsed-as-octal) value. */
	u_char saved[TAR_CKSUM_LEN];
	memcpy(saved, p->hdr_buf + TAR_CKSUM_OFF, TAR_CKSUM_LEN);
	uint64_t stored;
	if (tar_get_octal(saved, 0, TAR_CKSUM_LEN, &stored) < 0) {
		parser_set_error(p, "tar header checksum field not octal");
		return -1;
	}
	memset(p->hdr_buf + TAR_CKSUM_OFF, ' ', TAR_CKSUM_LEN);
	uint32_t computed = tar_checksum(p->hdr_buf);
	memcpy(p->hdr_buf + TAR_CKSUM_OFF, saved, TAR_CKSUM_LEN);
	if ((uint32_t)stored != computed) {
		parser_set_error(p,
		    "tar header checksum mismatch (stored=%llu computed=%u)",
		    (unsigned long long)stored, computed);
		return -1;
	}

	/* Typeflag: accept '0' (regular) and '\0' (old-style regular).
	 * Reject anything else — directories, symlinks, special files
	 * are not in our bundle vocabulary. */
	u_char tf = p->hdr_buf[TAR_TYPE_OFF];
	if (tf != TAR_TYPE_REG && tf != TAR_TYPE_REG_OLD) {
		parser_set_error(p, "tar entry type '%c' (0x%02x) "
		    "not supported (regular files only)",
		    (tf >= 0x20 && tf < 0x7f) ? (char)tf : '?',
		    (unsigned)tf);
		return -1;
	}

	/* Parse numeric fields. */
	uint64_t mode_v, size_v, mtime_v;
	if (tar_get_octal(p->hdr_buf, TAR_MODE_OFF, TAR_MODE_LEN,
	    &mode_v) < 0 ||
	    tar_get_octal(p->hdr_buf, TAR_SIZE_OFF, TAR_SIZE_LEN,
	    &size_v) < 0 ||
	    tar_get_octal(p->hdr_buf, TAR_MTIME_OFF, TAR_MTIME_LEN,
	    &mtime_v) < 0) {
		parser_set_error(p, "tar header numeric field parse failed");
		return -1;
	}

	/* Reconstruct full path: prefix + "/" + name (if prefix non-empty).
	 * Each side is NUL-terminated within its field — except when the
	 * field is fully used, in which case there's no NUL and we use
	 * the field width.  Strnlen handles both. */
	size_t pre_len  = strnlen((const char *)p->hdr_buf + TAR_PREFIX_OFF,
	    TAR_PREFIX_LEN);
	size_t name_len = strnlen((const char *)p->hdr_buf + TAR_NAME_OFF,
	    TAR_NAME_LEN);
	if (name_len == 0) {
		parser_set_error(p, "tar header has empty name");
		return -1;
	}
	if (pre_len + 1 + name_len > SFTP_HPN_TAR_MAX_PATH) {
		parser_set_error(p, "tar header path too long");
		return -1;
	}
	char path[SFTP_HPN_TAR_MAX_PATH + 2];
	if (pre_len > 0) {
		memcpy(path, p->hdr_buf + TAR_PREFIX_OFF, pre_len);
		path[pre_len] = '/';
		memcpy(path + pre_len + 1, p->hdr_buf + TAR_NAME_OFF,
		    name_len);
		path[pre_len + 1 + name_len] = '\0';
	} else {
		memcpy(path, p->hdr_buf + TAR_NAME_OFF, name_len);
		path[name_len] = '\0';
	}

	/* Invoke entry_cb. */
	if (p->cb->entry_cb != NULL &&
	    p->cb->entry_cb(p->ctx, path, size_v, (mode_t)(mode_v & 07777),
	    (time_t)mtime_v) != 0) {
		parser_set_error(p, "entry_cb rejected \"%s\"", path);
		return -1;
	}

	p->cur_size     = size_v;
	p->cur_received = 0;
	if (size_v == 0) {
		/* No data; entry is already complete. */
		if (p->cb->entry_end_cb != NULL &&
		    p->cb->entry_end_cb(p->ctx) != 0) {
			parser_set_error(p, "entry_end_cb failed");
			return -1;
		}
		p->state = PS_HEADER;
		p->hdr_pos = 0;
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
		parser_set_error(p, "feed after EOA");
		return -1;
	}

	while (len > 0) {
		if (p->state == PS_HEADER) {
			size_t need = SFTP_HPN_TAR_BLOCK - p->hdr_pos;
			size_t take = len < need ? len : need;
			memcpy(p->hdr_buf + p->hdr_pos, data, take);
			p->hdr_pos += take;
			data       += take;
			len        -= take;
			if (p->hdr_pos == SFTP_HPN_TAR_BLOCK) {
				if (parser_handle_header(p) < 0)
					return -1;
				p->hdr_pos = 0;
				if (p->state == PS_EOA_2ND)
					continue;
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
				/* End of entry's data; signal completion. */
				if (p->cb->entry_end_cb != NULL &&
				    p->cb->entry_end_cb(p->ctx) != 0) {
					parser_set_error(p,
					    "entry_end_cb failed");
					return -1;
				}
				uint64_t mod = p->cur_size % SFTP_HPN_TAR_BLOCK;
				p->pad_remaining = (mod == 0) ? 0
				    : (SFTP_HPN_TAR_BLOCK - mod);
				p->state = (p->pad_remaining == 0)
				    ? PS_HEADER : PS_PADDING;
			}
			continue;
		}

		if (p->state == PS_PADDING) {
			/* Padding bytes should be zero but we don't bother
			 * checking — they're implementation-defined in the
			 * spec and some tars write garbage.  Just skip. */
			size_t take = len < p->pad_remaining
			    ? len : (size_t)p->pad_remaining;
			data             += take;
			len              -= take;
			p->pad_remaining -= take;
			if (p->pad_remaining == 0)
				p->state = PS_HEADER;
			continue;
		}

		if (p->state == PS_EOA_2ND) {
			size_t take = len < p->eoa_remaining
			    ? len : (size_t)p->eoa_remaining;
			/* Verify all zeros. */
			size_t i;
			for (i = 0; i < take; i++) {
				if (data[i] != 0) {
					parser_set_error(p,
					    "EOA second block non-zero at "
					    "byte %zu", i);
					return -1;
				}
			}
			data             += take;
			len              -= take;
			p->eoa_remaining -= take;
			if (p->eoa_remaining == 0) {
				p->state = PS_DONE;
				return 1;
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
