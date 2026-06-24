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
 * sftp-hpn-tar.h - HPN-SSH bundle codec.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Carries small files in bulk on both the bundle upload and download
 * paths, both client- and server-side.
 *
 * Two streaming state machines, mirror images:
 *
 *   writer  - used by the client upload path and the server download
 *             (hpn-bundle-fetch) path.  Caller adds files to a pack
 *             list, then drives byte production via pack_next() which
 *             generates tar bytes on demand without holding the whole
 *             bundle in memory.
 *
 *   parser  - used by the server upload extract path and the client
 *             download extract path.  Caller feeds wire bytes via
 *             parse_feed(); parser invokes callbacks as each entry's
 *             header / data / end is recognised.
 *
 * Format (HPN-internal; read only by HPN-SSH at the other end of the same
 * connection, so it carries no tar/archive compatibility baggage):
 *
 *   A minimal length-prefixed binary record per file -
 *     u8   type      (1 = file)
 *     u32  mode       POSIX permission bits
 *     u64  mtime      seconds since the epoch
 *     u64  size       file data length
 *     u16  path_len   archive-path length (PATH_MAX < 64 KiB)
 *     u8[path_len]    archive path (length-prefixed; no NUL)
 *     u8[size]        file data
 *   - then the next record, with no padding.  A lone type=0 byte ends the
 *     stream.  All integers are big-endian (the stream can cross
 *     architectures).  No 512-byte blocks, no octal, no checksum, no magic,
 *     no uid/gid.
 *   - No symlinks, dirs, or special files; all entries are regular files.
 *
 * Error model: bundle is all-or-nothing.  Any per-entry failure
 * during mid-stream pack or unpack causes the codec to enter an
 * error state; caller must abandon the bundle and the orchestrator
 * will retry through the single-file path.  Matches the bail-out
 * model documented in sftp-hpn-server.c bundle_fetch_pack_one().
 *
 * Threading: each worker is a separate process (fork()ed by the
 * parallel orchestrator), so the codec is not thread-safe by design.
 * One writer / parser instance per worker, single-threaded use.
 */

#ifndef _SFTP_HPN_TAR_H
#define _SFTP_HPN_TAR_H

#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

/* Maximum pathname the codec carries.  The path is a variable-length,
 * length-prefixed field, so the only limit is PATH_MAX. */
#define SFTP_HPN_TAR_MAX_PATH	((unsigned)PATH_MAX)

/* Fixed record-header prefix before the variable-length path:
 * type(1) + mode(4) + mtime(8) + size(8) + path_len(2). */
#define SFTP_HPN_TAR_FIXED_HDR	23u

/* Worst-case header scratch = the fixed prefix plus a PATH_MAX path. */
#define SFTP_HPN_TAR_HDR_MAX	(SFTP_HPN_TAR_FIXED_HDR + SFTP_HPN_TAR_MAX_PATH)

/* ── Writer ──────────────────────────────────────────────────────────────── */

struct sftp_hpn_tar_writer;

/*
 * Construct an empty writer.  Returns NULL on allocation failure.
 * Free with sftp_hpn_tar_writer_free().
 */
struct sftp_hpn_tar_writer *sftp_hpn_tar_writer_new(void);

/*
 * Release a writer and any resources it holds.  Safe on NULL.  If a
 * file is currently open for read (we were mid-entry), it is closed.
 */
void sftp_hpn_tar_writer_free(struct sftp_hpn_tar_writer *w);

/*
 * Queue a file for inclusion in the tar stream.
 *
 *   src_path      - local path the writer will open() and read from.
 *                   May be NULL only if you are using the in-memory
 *                   variant (not supported; src_path is required).
 *   archive_path  - path as it appears in the tar header.  Subject
 *                   to SFTP_HPN_TAR_MAX_PATH.
 *   mode          - POSIX permissions bits (only low 12 bits used).
 *   size          - file size in bytes; MUST match the actual file
 *                   size at pack_next() time or the codec returns
 *                   error (matches our "bundle bails on mid-stream
 *                   truncation" contract).
 *   mtime         - modification time in seconds since the epoch.
 *
 * Returns 0 on success or -1 on error (path too long, OOM, etc.).
 * On -1 the writer's queue is unchanged.
 */
int sftp_hpn_tar_writer_add_file(struct sftp_hpn_tar_writer *w,
    const char *src_path, const char *archive_path,
    mode_t mode, uint64_t size, time_t mtime);

/*
 * Signal that no more files will be added.  After calling this,
 * pack_next() will emit the trailing two zero blocks once the last
 * queued file has been packed, then return 0 (EOF).
 *
 * Safe to call exactly once.  Calling pack_next() before finish()
 * is valid (it streams what's queued so far) but pack_next() will
 * never return 0 until finish() is called.
 */
void sftp_hpn_tar_writer_finish(struct sftp_hpn_tar_writer *w);

/*
 * Pack tar bytes into the caller's buffer.
 *
 * Returns:
 *    > 0  - number of bytes written into out (up to max_bytes).
 *    0    - EOA reached and trailing zero blocks emitted; no more
 *           bytes will be produced.  Only returned after finish().
 *   -1    - codec error.  Inspect sftp_hpn_tar_writer_error() for
 *           a human-readable message.  Caller MUST abandon the
 *           bundle (the on-wire tar stream is now invalid).
 *
 * Implementation: state machine pulls from the file queue lazily,
 * opens the source file only when its EMIT_HEADER state is reached,
 * reads chunks from disk only when EMIT_DATA needs them.  No internal
 * buffering beyond the 512-byte header scratch.
 */
ssize_t sftp_hpn_tar_writer_pack_next(struct sftp_hpn_tar_writer *w,
    u_char *out, size_t max_bytes);

/* Human-readable error string after pack_next() returns -1.  May be
 * a static string; do not free.  NULL if no error has been recorded. */
const char *sftp_hpn_tar_writer_error(struct sftp_hpn_tar_writer *w);

/*
 * Optional per-entry data observer.  As each entry is packed, on_data() is
 * invoked with the bytes just read from the source (before the caller sends
 * them), the entry's archive_path, and `final` nonzero on the entry's last
 * chunk.  An empty file emits one call with data=NULL, len=0, final=1.  The
 * codec interprets nothing - this is how the verify layer taps source bytes
 * to hash them without the codec knowing about hashing.
 */
struct sftp_hpn_tar_data_tap {
	void (*on_data)(void *arg, const char *archive_path,
	    const u_char *data, size_t len, int final);
	void *arg;
};
void sftp_hpn_tar_writer_set_data_tap(struct sftp_hpn_tar_writer *w,
    const struct sftp_hpn_tar_data_tap *tap);

/* ── Parser ──────────────────────────────────────────────────────────────── */

struct sftp_hpn_tar_parser;

/*
 * Callbacks invoked by the parser as entries and their bytes are
 * recognised.  Caller supplies ctx (parser passes it back unchanged).
 *
 * Callback return value:
 *    0  - continue parsing
 *   !0  - abort parser with error
 *
 * Lifecycle for each entry:
 *   1. entry_cb       - header parsed; caller may open output fd,
 *                       validate path, pre-allocate via fallocate(),
 *                       etc.  If callback returns non-zero the entry
 *                       is treated as a per-entry failure and bundle
 *                       is abandoned.
 *   2. data_cb         (one or more calls) - file bytes.  Total bytes
 *                      across all data_cb calls equals the entry's
 *                      declared size.  May be 0 calls for empty files.
 *   3. entry_end_cb   - entry's bytes fully delivered.  Caller closes
 *                      fd, applies perms/mtime, etc.
 */
struct sftp_hpn_tar_callbacks {
	int (*entry_cb)(void *ctx, const char *path, uint64_t size,
	    mode_t mode, time_t mtime);
	int (*data_cb)(void *ctx, const u_char *data, size_t len);
	int (*entry_end_cb)(void *ctx);
};

/*
 * Construct a parser.  cb and ctx must remain valid for the lifetime
 * of the parser.  Returns NULL on allocation failure.
 */
struct sftp_hpn_tar_parser *sftp_hpn_tar_parser_new(
    const struct sftp_hpn_tar_callbacks *cb, void *ctx);

/*
 * Release the parser.  Safe on NULL.
 */
void sftp_hpn_tar_parser_free(struct sftp_hpn_tar_parser *p);

/*
 * Feed bytes from the wire into the parser.  Bytes are consumed
 * synchronously; callbacks may be invoked during this call.
 *
 * Returns:
 *    0  - bytes consumed, continue feeding.
 *    1  - two-block all-zero EOA seen; parser has finished cleanly.
 *         Any further feed() calls are an error.
 *   -1  - parse error.  Inspect sftp_hpn_tar_parser_error() for a
 *         human-readable message.  Caller MUST abandon the bundle.
 */
int sftp_hpn_tar_parser_feed(struct sftp_hpn_tar_parser *p,
    const u_char *data, size_t len);

/* Human-readable error string after feed() returns -1.  May be a
 * static string; do not free.  NULL if no error has been recorded. */
const char *sftp_hpn_tar_parser_error(struct sftp_hpn_tar_parser *p);

#endif /* _SFTP_HPN_TAR_H */
