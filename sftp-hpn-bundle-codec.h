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
 * sftp-hpn-bundle-codec.h - HPN-SSH bundle codec.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Carries small files in bulk on both the bundle upload and download
 * paths, both client- and server-side.
 *
 * Two streaming state machines, mirror images:
 *
 *   writer  - used by the client upload path and the server download
 *             (hpn-bundle-fetch) path. The caller queues files, then
 *             pulls bytes with pack_next(), which produces the stream on
 *             demand without holding the whole bundle in memory.
 *
 *   parser  - used by the server upload extract path and the client
 *             download extract path. The caller pushes wire bytes with
 *             parser_feed(), and the parser calls back as it reaches each
 *             entry's header, data and end.
 *
 * Format (HPN-internal; read only by HPN-SSH at the other end of the same
 * connection, so it carries no tar/archive compatibility baggage):
 *
 *   A minimal length-prefixed binary record per file:
 *     u8   type      (1 = file)
 *     u32  mode       POSIX permission bits
 *     u64  mtime      seconds since the epoch
 *     u64  size       file data length
 *     u16  path_len   archive-path length (PATH_MAX < 64 KiB)
 *     u8[path_len]    archive path (length-prefixed; no NUL)
 *     u8[size]        file data
 *   The next record follows with no padding, and a lone type 0 byte ends
 *   the stream. All integers are big-endian, since the stream can cross
 *   architectures. There are no 512-byte blocks, octal fields, checksums,
 *   magic or uid/gid. Every entry is a regular file: no symlinks,
 *   directories or special files.
 *
 * Error model: a bundle is all-or-nothing. Any failure while packing or
 * unpacking puts the codec in an error state. The caller abandons the
 * bundle, and the orchestrator retries its files through the single-file
 * path.
 *
 * Threading: the codec keeps no shared state and takes no locks. Each
 * writer or parser belongs to one thread, the worker or transfer that
 * created it.
 */

#ifndef _SFTP_HPN_BUNDLE_CODEC_H
#define _SFTP_HPN_BUNDLE_CODEC_H

#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

/* Maximum pathname the codec carries. The path is a variable-length,
 * length-prefixed field, so the only limit is PATH_MAX. */
#define SFTP_HPN_BUNDLE_MAX_PATH	((unsigned)PATH_MAX)

/* Fixed record-header prefix before the variable-length path:
 * type(1) + mode(4) + mtime(8) + size(8) + path_len(2). */
#define SFTP_HPN_BUNDLE_FIXED_HDR	23

/* Worst-case header scratch = the fixed prefix plus a PATH_MAX path. */
#define SFTP_HPN_BUNDLE_HDR_MAX \
    (SFTP_HPN_BUNDLE_FIXED_HDR + SFTP_HPN_BUNDLE_MAX_PATH)

/* defined in sftp-hpn-bundle-codec.c */
struct sftp_hpn_bundle_writer;
struct sftp_hpn_bundle_parser;

/*
 * Callbacks the parser makes as it reaches each entry. ctx is the value
 * given to parser_new(), passed back unchanged. A non-zero return from
 * any callback fails the parser, and the caller abandons the bundle.
 *
 * For each entry, in order:
 *   entry_cb      - the header is complete. The caller may open the
 *                   output file, check the path and preallocate.
 *   data_cb       - file bytes, in one or more calls that total the
 *                   declared size. Not called for an empty file.
 *   entry_end_cb  - all of the entry's bytes have arrived. The caller
 *                   closes the file and applies its mode and mtime.
 */
struct sftp_hpn_bundle_callbacks {
	int (*entry_cb)(void *ctx, const char *, uint64_t, mode_t, time_t);
	int (*data_cb)(void *ctx, const u_char *, size_t);
	int (*entry_end_cb)(void *ctx);
};

/* Construct an empty writer. Never returns NULL. Free it with
 * sftp_hpn_bundle_writer_free(). */
struct sftp_hpn_bundle_writer *sftp_hpn_bundle_writer_new(void);

/* Free a writer, its queue and the entry in flight, closing any open
 * source file. Safe on NULL. */
void sftp_hpn_bundle_writer_free(struct sftp_hpn_bundle_writer *);

/*
 * Queue a file for inclusion in the bundle stream.
 *
 *   src_path       - local path the writer opens and reads. Required.
 *   archive_path   - path as it appears in the record header, at most
 *                    SFTP_HPN_BUNDLE_MAX_PATH bytes.
 *   mode           - permission bits; only the low 12 are sent.
 *   size           - bytes to pack. The header commits to it, so a file
 *                    that shrinks before it is packed fails the bundle.
 *   mtime          - modification time in seconds since the epoch.
 *   hash_out,      - both given or both NULL. When given, hash_out gets
 *   hash_valid_out   the XXH3 of the entry's data once it is packed, and
 *                    *hash_valid_out is then set to 1.
 *
 * Returns 0 on success or -1 on an empty or too-long path, or when only
 * one of the hash pointers is given.
 * On -1 the writer's queue is unchanged.
 */
int sftp_hpn_bundle_writer_add_file(struct sftp_hpn_bundle_writer *,
    const char *src_path, const char *archive_path,
    mode_t mode, uint64_t size, time_t mtime,
    uint64_t *hash_out, int *hash_valid_out);

/* Close the queue. Once the last queued file is packed, pack_next()
 * emits the end byte and then returns 0. Before finish(), pack_next()
 * streams what is queued and returns 0 when it runs out, which is not
 * the end of the stream. Calling finish() again has no effect. */
void sftp_hpn_bundle_writer_finish(struct sftp_hpn_bundle_writer *);

/*
 * Pack the next part of the stream into out.
 *
 * Returns:
 *    > 0  - bytes written into out, at most max_bytes.
 *    0    - nothing more to produce: the end of the stream after
 *           finish(), or an empty queue before it.
 *   -1    - codec error; sftp_hpn_bundle_writer_error() says why. The
 *           stream on the wire is now invalid, so the caller must
 *           abandon the bundle.
 */
ssize_t sftp_hpn_bundle_writer_pack_next(struct sftp_hpn_bundle_writer *,
    u_char *out, size_t max_bytes);

/* Why pack_next() failed, or NULL if it has not. The string belongs to
 * the writer; do not free it. */
const char *sftp_hpn_bundle_writer_error(struct sftp_hpn_bundle_writer *);

/* Construct a parser. cb and ctx must stay valid for the parser's
 * lifetime. Returns NULL only when cb is NULL. */
struct sftp_hpn_bundle_parser *sftp_hpn_bundle_parser_new(
    const struct sftp_hpn_bundle_callbacks *cb, void *ctx);

/* Free the parser. Safe on NULL. */
void sftp_hpn_bundle_parser_free(struct sftp_hpn_bundle_parser *);

/*
 * Feed bytes from the wire into the parser. All of them are consumed
 * before it returns, and the callbacks run during the call.
 *
 * Returns:
 *    0  - all bytes consumed; feed more.
 *    1  - the end byte was the last byte given; the stream is complete.
 *         Any bytes after it, now or in a later call, are an error.
 *   -1  - parse error; sftp_hpn_bundle_parser_error() says why. The
 *         caller must abandon the bundle.
 */
int sftp_hpn_bundle_parser_feed(struct sftp_hpn_bundle_parser *,
    const u_char *, size_t);

/* Why feed() failed, or NULL if it has not. The string belongs to the
 * parser; do not free it. */
const char *sftp_hpn_bundle_parser_error(struct sftp_hpn_bundle_parser *);

#endif /* _SFTP_HPN_BUNDLE_CODEC_H */
