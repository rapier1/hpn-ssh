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

/* sftp-hpn-bundle-codec.c - the bundle codec: a streaming writer that
 * packs files into the bundle record stream and a streaming parser that
 * unpacks it, used by both ends in both directions. The record format and
 * the API are in sftp-hpn-bundle-codec.h; the integers are big-endian
 * through the tree's POKE and PEEK macros. This is a "tar like" protocol
 * but is not tar. We originally tried this using libarchive but it was far too
 * heavy for what we are doing.
 *
 * Both state machines stream through the caller's buffer and copy no
 * file data: the writer reads source bytes straight into the output
 * buffer, and the parser hands file bytes to data_cb straight from the
 * input. Each keeps one record header, the fixed prefix and its path, as
 * scratch; any larger buffering is the caller's. An empty file skips the
 * data state. When asked, the writer also hashes each entry's data with
 * XXH3 as it reads it, so a verified upload needs no second read of the
 * source.
 *
 * A file that shrinks while it is packed, read() returning 0 before the
 * size its header promised, is an error: that size is already on the
 * wire and cannot be taken back, so the bundle fails and the orchestrator
 * retries its files through the single-file path. */

#include "includes.h"

#include <sys/types.h>
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
#include "misc.h"		/* MINIMUM */
#include "sshbuf.h"		/* POKE/PEEK big-endian field macros */
#include "sftp-hpn-bundle-codec.h"

#define XXH_INLINE_ALL		/* xxhash is header-only; inline the XXH3 API */
#include "xxhash.h"

#define HPN_REC_END	0	/* lone type byte that ends the stream */
#define HPN_REC_FILE	1	/* a regular-file entry follows */

/* Fixed record-header prefix, big-endian: type(1) mode(4) mtime(8) size(8)
 * path_len(2). The variable-length path then runs from HPN_REC_OFF_PATH. */
#define HPN_REC_OFF_TYPE	0
#define HPN_REC_OFF_MODE	1
#define HPN_REC_OFF_MTIME	5
#define HPN_REC_OFF_SIZE	13
#define HPN_REC_OFF_PATHLEN	21
/* The path follows the fixed prefix, so it starts where the prefix ends. */
#define HPN_REC_OFF_PATH	SFTP_HPN_BUNDLE_FIXED_HDR

/* Writer states, stepped through by pack_next() as it emits the stream. */
enum writer_state {
	WS_IDLE,	/* between files; advance to HEADER if more queued */
	WS_HEADER,	/* emitting the record header (fixed prefix + path) */
	WS_DATA,	/* reading source file and emitting data */
	WS_END,		/* emitting the trailing end-of-stream byte */
	WS_DONE,	/* nothing more to produce */
	WS_ERROR,	/* unrecoverable; pack_next returns -1 */
};

/* Parser states, stepped through by feed() as the stream arrives. */
enum parser_state {
	PS_HEADER,	/* accumulating a record header (prefix + path) */
	PS_DATA,	/* delivering file bytes to data_cb */
	PS_DONE,	/* end byte seen; further feed() is an error */
	PS_ERROR,	/* unrecoverable; feed returns -1 */
};

/* One file queued by add_file(): the local path to read, the record header
 * fields, and where to deliver its hash. Freed once it has been packed. */
struct writer_file {
	char    *src_path;
	char    *archive_path;
	mode_t   mode;
	uint64_t size;
	time_t   mtime;
	/* Where to deliver the entry's source hash, NULL when not wanted. */
	uint64_t *hash_out;
	int      *hash_valid_out;
	struct writer_file *next;
};

/* The streaming writer: the queue of files still to pack and the state of
 * the one being emitted. Opaque to callers, who get it from writer_new(). */
struct sftp_hpn_bundle_writer {
	enum writer_state state;
	struct writer_file *q_head;
	struct writer_file *q_tail;
	int   finish_signalled;

	/* Current entry state. */
	struct writer_file *cur;	/* the entry currently being emitted */
	int      cur_fd;		/* open() result for cur->src_path */
	uint64_t cur_data_emitted;	/* bytes of data written into out so far */
	/* Streaming XXH3 of cur's data, kept across entries and reset for
	 * each one that asked for its hash; NULL until first needed. */
	XXH3_state_t *hash_state;
	int      hash_active;		/* cur's data is being hashed */
	u_char   hdr_buf[SFTP_HPN_BUNDLE_HDR_MAX];	/* fixed prefix + path */
	size_t   hdr_total;		/* full header size (prefix + path) */
	size_t   hdr_pos;		/* bytes of hdr_buf already emitted */

	char    *err;			/* malloc'd; freed by writer_free */
};

/* The streaming parser: the record header being collected and the progress
 * of the entry being delivered. Opaque to callers, who get it from
 * parser_new(). */
struct sftp_hpn_bundle_parser {
	enum parser_state state;
	const struct sftp_hpn_bundle_callbacks *cb;
	void   *ctx;

	u_char  hdr_buf[SFTP_HPN_BUNDLE_HDR_MAX];	/* fixed prefix + path */
	size_t  hdr_total;	/* full header size; 0 until path_len is read */
	size_t  hdr_pos;	/* bytes of hdr_buf filled so far */

	uint64_t cur_size;	/* declared size of current entry */
	uint64_t cur_received;	/* bytes of data delivered to data_cb */

	char *err;		/* malloc'd; freed by parser_free */
};

/* Put the writer in WS_ERROR and record why. Only the first error is kept,
 * since later ones are usually its fallout. */
static void
writer_set_error(struct sftp_hpn_bundle_writer *writer, const char *fmt, ...)
{
	va_list ap;

	if (writer == NULL || writer->err != NULL)
		return;	/* preserve first error */
	writer->state = WS_ERROR;
	va_start(ap, fmt);
	xvasprintf(&writer->err, fmt, ap);
	va_end(ap);
}

/* Allocate an idle writer with an empty queue and no file open. */
struct sftp_hpn_bundle_writer *
sftp_hpn_bundle_writer_new(void)
{
	struct sftp_hpn_bundle_writer *writer;

	writer = xcalloc(1, sizeof(*writer));
	writer->state  = WS_IDLE;
	writer->cur_fd = -1;
	return writer;
}

/* Release one queued file and its path copies. */
static void
writer_file_free(struct writer_file *file)
{
	free(file->src_path);
	free(file->archive_path);
	free(file);
}

/* Free the writer, its queue and the entry in flight, closing an open
 * source file. Safe on NULL. */
void
sftp_hpn_bundle_writer_free(struct sftp_hpn_bundle_writer *writer)
{
	struct writer_file *file, *next;

	if (writer == NULL)
		return;
	if (writer->cur_fd >= 0)
		(void)close(writer->cur_fd);
	if (writer->cur != NULL)
		writer_file_free(writer->cur);
	for (file = writer->q_head; file != NULL; file = next) {
		next = file->next;
		writer_file_free(file);
	}
	if (writer->hash_state != NULL)
		XXH3_freeState(writer->hash_state);
	free(writer->err);
	free(writer);
}

/* Queue a file after those already queued. Only its paths and header
 * fields are kept; the file is opened when pack_next() reaches it. */
int
sftp_hpn_bundle_writer_add_file(struct sftp_hpn_bundle_writer *writer,
    const char *src_path, const char *archive_path,
    mode_t mode, uint64_t size, time_t mtime,
    uint64_t *hash_out, int *hash_valid_out)
{
	struct writer_file *file;

	if (writer == NULL || writer->state == WS_ERROR || writer->finish_signalled)
		return -1;
	if (src_path == NULL || archive_path == NULL ||
	    *src_path == '\0' || *archive_path == '\0')
		return -1;
	if (strlen(archive_path) > SFTP_HPN_BUNDLE_MAX_PATH)
		return -1;	/* longer than PATH_MAX */
	if ((hash_out == NULL) != (hash_valid_out == NULL))
		return -1;	/* the hash pointers come as a pair */
	/* not valid until writer_finish_entry() has hashed the whole file */
	if (hash_valid_out != NULL)
		*hash_valid_out = 0;
	file = xcalloc(1, sizeof(*file));
	file->src_path     = xstrdup(src_path);
	file->archive_path = xstrdup(archive_path);
	file->mode  = mode;
	file->size  = size;
	file->mtime = mtime;
	file->hash_out = hash_out;
	file->hash_valid_out = hash_valid_out;
	if (writer->q_tail == NULL)
		writer->q_head = file;
	else
		writer->q_tail->next = file;
	writer->q_tail = file;
	return 0;
}

/* Mark the queue closed. pack_next() emits the end byte once the last
 * queued file is packed. */
void
sftp_hpn_bundle_writer_finish(struct sftp_hpn_bundle_writer *writer)
{
	if (writer == NULL)
		return;
	writer->finish_signalled = 1;
}

/* Build the record header for cur into hdr_buf and rewind hdr_pos.
 * add_file() has already checked the path length. */
static void
writer_build_header(struct sftp_hpn_bundle_writer *writer)
{
	struct writer_file *file = writer->cur;
	size_t plen = strlen(file->archive_path);

	writer->hdr_buf[HPN_REC_OFF_TYPE] = (u_char)HPN_REC_FILE;
	POKE_U32(writer->hdr_buf + HPN_REC_OFF_MODE, (u_int32_t)(file->mode & 07777));
	POKE_U64(writer->hdr_buf + HPN_REC_OFF_MTIME, (u_int64_t)file->mtime);
	POKE_U64(writer->hdr_buf + HPN_REC_OFF_SIZE, file->size);
	POKE_U16(writer->hdr_buf + HPN_REC_OFF_PATHLEN, (u_int16_t)plen);
	memcpy(writer->hdr_buf + HPN_REC_OFF_PATH, file->archive_path, plen);
	writer->hdr_total = SFTP_HPN_BUNDLE_FIXED_HDR + plen;
	writer->hdr_pos   = 0;
}

/* Advance the writer out of WS_IDLE: dequeue the next file and build its
 * header, or, if the queue is drained and finish() was called, move to the
 * trailing end byte. No-op when not in WS_IDLE. */
static void
writer_advance_idle(struct sftp_hpn_bundle_writer *writer)
{
	struct writer_file *file;

	if (writer->state != WS_IDLE)
		return;
	/* queue drained: the end byte is next once finish() has been called */
	if (writer->q_head == NULL) {
		if (writer->finish_signalled)
			writer->state = WS_END;
		return;
	}
	/* unlink the head of the queue and make it the entry being packed */
	file = writer->q_head;
	writer->q_head = file->next;
	if (writer->q_head == NULL)
		writer->q_tail = NULL;
	file->next = NULL;
	writer->cur = file;
	/* reset the per-entry state */
	writer->cur_data_emitted = 0;
	/* start the entry's hash if the caller asked for one */
	writer->hash_active = 0;
	if (file->hash_out != NULL) {
		if (writer->hash_state == NULL &&
		    (writer->hash_state = XXH3_createState()) == NULL)
			fatal_f("XXH3_createState: out of memory");
		(void)XXH3_64bits_reset(writer->hash_state);
		writer->hash_active = 1;
	}
	/* header first, then its data */
	writer_build_header(writer);
	writer->state = WS_HEADER;
}

/* Deliver the entry's hash when one was kept, free the entry and return
 * to WS_IDLE. */
static void
writer_finish_entry(struct sftp_hpn_bundle_writer *writer)
{
	if (writer->hash_active) {
		*writer->cur->hash_out =
		    (uint64_t)XXH3_64bits_digest(writer->hash_state);
		/* set hash_valid_out to 1 to show hash is complete */
		*writer->cur->hash_valid_out = 1;
		/* and we aren't actively computing the hash anymore */
		writer->hash_active = 0;
	}
	writer_file_free(writer->cur);
	writer->cur   = NULL;
	writer->state = WS_IDLE;
}

/* Fill out with up to max_bytes of the stream: each queued file's record
 * header, then its data read straight into out, then the end byte once
 * finish() has been called. Returns the bytes written, 0 at the end of the
 * stream or -1 on error. */
ssize_t
sftp_hpn_bundle_writer_pack_next(struct sftp_hpn_bundle_writer *writer,
    u_char *out, size_t max_bytes)
{
	size_t written = 0;

	if (writer == NULL || out == NULL)
		return -1;
	if (writer->state == WS_ERROR)
		return -1;
	if (writer->state == WS_DONE)
		return 0;

	while (written < max_bytes) {
		if (writer->state == WS_IDLE) {
			writer_advance_idle(writer);
			if (writer->state == WS_IDLE)
				break;	/* nothing queued, not finished yet */
		}

		if (writer->state == WS_HEADER) {
			size_t avail = writer->hdr_total - writer->hdr_pos;
			size_t take = MINIMUM(max_bytes - written, avail);
			memcpy(out + written, writer->hdr_buf + writer->hdr_pos, take);
			writer->hdr_pos += take;
			written         += take;
			if (writer->hdr_pos != writer->hdr_total)
				continue;	/* header not fully emitted */
			/* Header done. Empty file: advance; else open the
			 * source and stream its data. */
			if (writer->cur->size == 0) {
				writer_finish_entry(writer);
				continue;
			}
			writer->cur_fd = open(writer->cur->src_path, O_RDONLY);
			if (writer->cur_fd < 0) {
				writer_set_error(writer, "open \"%s\": %s",
				    writer->cur->src_path, strerror(errno));
				return -1;
			}
			writer->state = WS_DATA;
			continue;
		}

		if (writer->state == WS_DATA) {
			uint64_t left = writer->cur->size - writer->cur_data_emitted;
			size_t   take = (size_t)MINIMUM(max_bytes - written, left);
			ssize_t  nread;

			if (take == 0) {		/* all data emitted */
				(void)close(writer->cur_fd);
				writer->cur_fd = -1;
				writer_finish_entry(writer);
				continue;
			}
			nread = read(writer->cur_fd, out + written, take);
			if (nread < 0) {
				if (errno == EINTR)
					continue;
				writer_set_error(writer, "read \"%s\": %s",
				    writer->cur->src_path, strerror(errno));
				return -1;
			}
			if (nread == 0) {
				/* The source shrank after add_file() took its
				 * size. The header already sent that size, so
				 * the stream cannot be repaired. Fail the
				 * bundle. */
				writer_set_error(writer,
				    "\"%s\" shrank during read "
				    "(%llu of %llu bytes)",
				    writer->cur->src_path,
				    (unsigned long long)writer->cur_data_emitted,
				    (unsigned long long)writer->cur->size);
				return -1;
			}
			if (writer->hash_active)
				(void)XXH3_64bits_update(writer->hash_state,
				    out + written, (size_t)nread);
			written += (size_t)nread;
			writer->cur_data_emitted += (uint64_t)nread;
			continue;
		}

		if (writer->state == WS_END) {
			out[written++] = (u_char)HPN_REC_END;
			writer->state  = WS_DONE;
			break;
		}
	}

	return (ssize_t)written;
}

/* The first error the writer hit, or NULL if it has none. The string
 * belongs to the writer. */
const char *
sftp_hpn_bundle_writer_error(struct sftp_hpn_bundle_writer *writer)
{
	if (writer == NULL)
		return NULL;
	return writer->err;
}

/* Put the parser in PS_ERROR and record why. Only the first error is kept,
 * since later ones are usually its fallout. */
static void
parser_set_error(struct sftp_hpn_bundle_parser *parser, const char *fmt, ...)
{
	va_list ap;

	if (parser == NULL || parser->err != NULL)
		return;
	parser->state = PS_ERROR;
	va_start(ap, fmt);
	xvasprintf(&parser->err, fmt, ap);
	va_end(ap);
}

/* Allocate a parser that expects a record header first. NULL only when
 * cb is NULL. */
struct sftp_hpn_bundle_parser *
sftp_hpn_bundle_parser_new(const struct sftp_hpn_bundle_callbacks *cb, void *ctx)
{
	struct sftp_hpn_bundle_parser *parser;

	if (cb == NULL)
		return NULL;
	parser = xcalloc(1, sizeof(*parser));
	parser->cb    = cb;
	parser->ctx   = ctx;
	parser->state = PS_HEADER;
	return parser;
}

/* Free the parser and its error string. Safe on NULL. */
void
sftp_hpn_bundle_parser_free(struct sftp_hpn_bundle_parser *parser)
{
	if (parser == NULL)
		return;
	free(parser->err);
	free(parser);
}

/* Act on a fully collected record header in hdr_buf: check its size, hand
 * the entry to entry_cb, and move to PS_DATA, or straight back to PS_HEADER
 * through entry_end_cb for an empty file. feed() has already checked the
 * path length (plen). Returns -1 on error. */
static int
parser_handle_header(struct sftp_hpn_bundle_parser *parser)
{
	uint32_t mode_v  = PEEK_U32(parser->hdr_buf + HPN_REC_OFF_MODE);
	uint64_t mtime_v = PEEK_U64(parser->hdr_buf + HPN_REC_OFF_MTIME);
	uint64_t size_v  = PEEK_U64(parser->hdr_buf + HPN_REC_OFF_SIZE);
	uint64_t plen    = PEEK_U16(parser->hdr_buf + HPN_REC_OFF_PATHLEN);
	char     path[SFTP_HPN_BUNDLE_MAX_PATH + 1];

	memcpy(path, parser->hdr_buf + HPN_REC_OFF_PATH, (size_t)plen);
	path[plen] = '\0';

	/*
	 * size_v comes from the peer, and the consumers malloc() and
	 * posix_fallocate() that much before any data arrives, so a
	 * malicious peer could claim a huge size to exhaust memory or disk.
	 * Bundles only carry small whole files (a file qualifies only below
	 * HPNBundleSize/4, and HPNBundleSize is capped at
	 * HPN_BUNDLE_SIZE_MAX), so a record larger than a whole bundle is
	 * never legitimate. Rejecting it here also keeps (size_t)size_v
	 * from truncating on ILP32, since HPN_BUNDLE_SIZE_MAX < SIZE_MAX.
	 */
	if (size_v > HPN_BUNDLE_SIZE_MAX) {
		parser_set_error(parser,
		    "record size %llu exceeds bundle maximum %llu",
		    (unsigned long long)size_v,
		    (unsigned long long)HPN_BUNDLE_SIZE_MAX);
		return -1;
	}

	/* Hand the consumers permission bits only. setuid, setgid and
	 * sticky are dropped here so every bundle extract, client download
	 * and server upload alike, matches the serial and parallel paths.
	 * Neither preserves ownership, so a transfer must not create a file
	 * with those bits set. */
	if (parser->cb->entry_cb != NULL &&
	    parser->cb->entry_cb(parser->ctx, path, size_v, (mode_t)(mode_v & 0777),
	    (time_t)mtime_v) != 0) {
		parser_set_error(parser, "entry_cb rejected \"%s\"", path);
		return -1;
	}

	/* track the entry's data so feed() knows when it is complete */
	parser->cur_size = size_v;
	parser->cur_received = 0;
	/* an empty file has no data: finish it now and expect the next header */
	if (size_v == 0) {
		if (parser->cb->entry_end_cb != NULL &&
		    parser->cb->entry_end_cb(parser->ctx) != 0) {
			parser_set_error(parser, "entry_end_cb failed");
			return -1;
		}
		parser->state = PS_HEADER;
	} else {
		/* data follows; feed() finishes the entry when it has all of it */
		parser->state = PS_DATA;
	}
	return 0;
}

/* Consume len bytes of the stream, collecting each record header and
 * passing file data to data_cb as it arrives. Returns 0 when it needs more
 * input, 1 at the end byte, or -1 on error. */
int
sftp_hpn_bundle_parser_feed(struct sftp_hpn_bundle_parser *parser,
    const u_char *data, size_t len)
{
	if (parser == NULL || data == NULL)
		return -1;
	/* a failed parser stays failed; a finished one takes no more input */
	if (parser->state == PS_ERROR)
		return -1;
	if (parser->state == PS_DONE) {
		parser_set_error(parser, "feed after end-of-stream");
		return -1;
	}

	/* each pass consumes some input in the current state */
	while (len > 0) {
		/* read the header */
		if (parser->state == PS_HEADER) {
			size_t target, need, take;

			/* a record's first byte is its type: the end marker or
			 * a file entry */
			if (parser->hdr_pos == 0) {
				u_char type = *data;
				data++;
				len--;
				parser->hdr_pos = 1;
				if (type == HPN_REC_END) {
					parser->state = PS_DONE;
					/* nothing may follow the end marker */
					if (len > 0) {
						parser_set_error(parser, "%zu bytes "
						    "after the end marker", len);
						return -1;
					}
					return 1;	/* clean end */
				}
				if (type != HPN_REC_FILE) {
					parser_set_error(parser,
					    "bad record type 0x%02x",
					    (unsigned)type);
					return -1;
				}
				parser->hdr_buf[HPN_REC_OFF_TYPE] = type;
				parser->hdr_total = 0;	/* path_len not read yet */
				continue;
			}

			/* collect the rest of the fixed prefix, then the path */
			if (parser->hdr_total != 0)
				target = parser->hdr_total;
			else
				target = SFTP_HPN_BUNDLE_FIXED_HDR;
			need = target - parser->hdr_pos;
			take = MINIMUM(len, need);
			memcpy(parser->hdr_buf + parser->hdr_pos, data, take);
			parser->hdr_pos += take;
			data += take;
			len -= take;
			/* prefix complete: path_len gives the full header size */
			if (parser->hdr_total == 0 &&
			    parser->hdr_pos == SFTP_HPN_BUNDLE_FIXED_HDR) {
				uint64_t plen =
				    PEEK_U16(parser->hdr_buf + HPN_REC_OFF_PATHLEN);
				if (plen == 0 ||
				    plen > SFTP_HPN_BUNDLE_MAX_PATH) {
					parser_set_error(parser,
					    "record bad/oversized path length");
					return -1;
				}
				parser->hdr_total =
				    SFTP_HPN_BUNDLE_FIXED_HDR + (size_t)plen;
			}
			/* header complete: hand it over and rewind for the next */
			if (parser->hdr_total != 0 &&
			    parser->hdr_pos == parser->hdr_total) {
				if (parser_handle_header(parser) < 0)
					return -1;
				parser->hdr_pos = 0;
				parser->hdr_total = 0;
			}
			continue;
		}
		/* read the data */
		if (parser->state == PS_DATA) {
			uint64_t left = parser->cur_size - parser->cur_received;
			size_t take = (size_t)MINIMUM(len, left);

			/* pass this entry's bytes on, never more than it declared */
			if (parser->cb->data_cb != NULL && take > 0 &&
			    parser->cb->data_cb(parser->ctx, data, take) != 0) {
				parser_set_error(parser, "data_cb failed");
				return -1;
			}
			data += take;
			len -= take;
			parser->cur_received += (uint64_t)take;
			/* all of the entry's data is in: finish it */
			if (parser->cur_received == parser->cur_size) {
				if (parser->cb->entry_end_cb != NULL &&
				    parser->cb->entry_end_cb(parser->ctx) != 0) {
					parser_set_error(parser,
					    "entry_end_cb failed");
					return -1;
				}
				parser->state = PS_HEADER;	/* next record */
			}
			continue;
		}

		/* no other state can get here */
		parser_set_error(parser, "internal: unknown parser state %d",
		    (int)parser->state);
		return -1;
	}
	return 0;
}

/* The first error the parser hit, or NULL if it has none. The string
 * belongs to the parser. */
const char *
sftp_hpn_bundle_parser_error(struct sftp_hpn_bundle_parser *parser)
{
	if (parser == NULL)
		return NULL;
	return parser->err;
}
