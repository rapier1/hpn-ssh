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

/* sftp-hpn-bundle-client.c - client side of the SFTP bundle protocol.
 *
 * Download, hpn-bundle-fetch@hpnssh.org: bundle_dl_stream and the parser
 * callbacks, the fire/drain wire helpers, and sftp_hpn_bundle_download.
 * DATA bytes flow wire -> drain_one -> parser_feed -> file write with no
 * intermediate buffering, so per-worker memory is bounded by the
 * in-flight read depth times the chunk size (BUNDLE_DL_QUEUE_MAX_BYTES)
 * plus about 1 KiB of parser state. Reads are fired ahead through the
 * adaptive read-ahead controller, and the parser's end-of-archive
 * signal says when to stop, so there is no orphan-drain ID mismatch.
 *
 * Upload, hpn-bundle-open@hpnssh.org: bundle_write_ctx, bundle_drain_n,
 * bundle_ul_send_write, and sftp_hpn_bundle_upload.
 *
 * Only the two public functions are external. They and their entry
 * struct types are declared in sftp-client.h. */

#include "includes.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"		/* monotime_double, mkdir_p */
#include "sftp-common.h"	/* Attrib, needed by sftp-client.h */
#include "sshbuf.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-client.h"	/* struct sftp_hpn_conn + adaptive rdahead API */
#include "sftp-hpn-bundle.h"
#include "sftp-hpn-tar.h"
#include "sftp-hpn-bundle-pool.h"	/* shared writer pool (extract overlap) */

/* Per-READ chunk size. 128 KiB matches the default SFTP_MAX_READ_LENGTH
 * ceiling on most servers, so each READ returns one full pack block. */
#define BUNDLE_DL_CHUNK_BYTES   (128 * 1024)

/* Sanity ceiling on outstanding READs. The working depth comes from the
 * memory cap below and the adaptive read-ahead controller. */
#define BUNDLE_DL_MAX_INFLIGHT  1024

/* Ceiling on in-flight READ bytes, in_flight * BUNDLE_DL_CHUNK_BYTES.
 * 32 MiB is 256 chunks, enough to fill 10 Gbps at 25 ms RTT or 1 Gbps
 * at 250 ms. This is what bounds per-worker memory and BDP fill. It
 * must hold at least one chunk or the fire loop could never start. */
#define BUNDLE_DL_QUEUE_MAX_BYTES  (32 * 1024 * 1024)

/* Bundle flag constants (HPN_BUNDLE_FLAG_*) and HPN_BUNDLE_BLOCK_BYTES
 * live in sftp-hpn-bundle.h, included above, the single source of truth
 * shared with the server side. */

/* Hard ceiling on outstanding WRITE STATUS replies, the fallback depth
 * when the read-ahead controller reports none, and the size of the
 * per-WRITE byte ring (ctx->wsizes). A queued STATUS is about 13 bytes
 * on the wire, so 4096 stays far below any socket or channel buffer. */
#define BUNDLE_MAX_INFLIGHT     4096

/* A STATUS read slower than DRAIN_SLOW_GAP_SEC counts as slow. The last
 * DRAIN_GAP_RING gaps are kept so a failed drain can be told dead (sudden
 * silence after fast acks) from alive but slow (gaps throughout). */
#define DRAIN_SLOW_GAP_SEC      0.5
#define DRAIN_GAP_RING          48

/* Download stream context. Tracks SFTP wire state (in-flight count via
 * counters, since READ IDs are sequential) and per-entry parser state
 * (open output fd, current path, last-mkdir cache). A pointer to this
 * struct is the parser's ctx, so the entry/data/end callbacks reach every
 * download-side field. */
struct bundle_dl_stream {
	struct sftp_conn *conn;
	const u_char     *handle;
	size_t            handle_len;

	/* SFTP wire pipeline tracking. IDs are sequential within
	 * the receive loop because nothing else allocates msg_id. */
	u_int    first_read_id;
	u_int    chunks_sent;
	u_int    chunks_received;
	uint64_t fire_off;

	/* Caller-supplied download-entry list, used by entry_cb to map
	 * tar pathnames back to local destinations. */
	struct sftp_hpn_bundle_download_entry *entries;
	int      n_entries;
	int      preserve_flag;

	/* holds -f: flush each extracted file to disk before its fd is
	 * closed. The writer pool does this itself; the serial path below
	 * has to. */
	int      fsync_flag;

	/* Per-entry state set by entry_cb. */

	/* Index into entries[], or -1 when the tar path is not in the
	 * requested set. */
	int         cur_idx;
	int         cur_fd;	/* open output fd, or -1 */

	/* local_path of the current entry. entries[] owns the storage. */
	const char *cur_local;
	time_t   cur_mtime;	/* used by entry_end_cb */
	mode_t   cur_mode;	/* used by entry_end_cb (exact-mode fchmod) */

	/* Bytes written for the current entry. The ftruncate to the real
	 * size at entry end and the abort-path truncate both rely on it. */
	uint64_t cur_written;

	/* Pool (parallel extract) state, active when pool != NULL. In pool
	 * mode entry_cb buffers the whole file (cur_buf), data_cb fills it
	 * (offset tracked by cur_written), and entry_end_cb hands it off as a
	 * job; the writer threads do the open/write/close. */
	struct bundle_write_pool *pool;	/* writer pool, or NULL (serial path) */
	u_char  *cur_buf;	/* pool: current file's data buffer (owns) */
	uint64_t cur_size;	/* pool: declared size from the tar header */

	/* Most recently created parent dir, so repeats can be skipped. */
	char    *last_mkdir_dir;

	/* Optional received-payload counter for a serial-flush progress meter;
	 * NULL when the caller does not meter (parallel workers). */
	off_t   *progress;
};

/* Context for the tar codec's write path. WRITEs are pipelined: the
 * pack loop in sftp_hpn_bundle_upload sends each SSH_FXP_WRITE without
 * waiting for its STATUS. Replies are drained cap/2 at a time whenever
 * the in-flight count reaches the read-ahead depth, and fully before
 * SSH_FXP_CLOSE.
 *
 * Because rids come from sftp_conn_alloc_msg_id and SFTP replies are
 * returned in request order, no per-request tracking is needed: the
 * rid of drain #k is first_rid + k. */
struct bundle_write_ctx {
	struct sftp_conn *conn;
	const u_char *handle;
	size_t        handle_len;
	off_t         offset;        /* monotonically increasing */
	int           any_fail;      /* sticky: any WRITE/STATUS failed */

	/* Sticky: a transport break (read error, malformed reply, rid
	 * desync), never a server refusal. Only this condemns the
	 * connection. */
	int           conn_lost;

	uint64_t      n_sent;        /* WRITEs sent */
	uint64_t      n_drained;     /* STATUS replies successfully drained */
	u_int         first_rid;     /* rid of WRITE #0; valid when n_sent > 0 */

	/* Ring of per-WRITE byte counts so bundle_drain_n can feed the exact
	 * ack size into sftp_hpn_rdahead_account(). Slot n_sent % wsizes_cap
	 * on store, the slot of the WRITE being drained on read. Sized to
	 * BUNDLE_MAX_INFLIGHT, the in-flight ceiling, so slots are never
	 * reused before they are read. NULL if allocation failed, in which
	 * case the controller feed becomes a no-op and send/drain still work. */
	uint32_t     *wsizes;
	uint32_t      wsizes_cap;

	/* Drain-stall record, reset with the ctx for each upload and reported
	 * by the always-on DRAIN-FAIL log in bundle_drain_n and by the
	 * HPN_PARALLEL_TRACE timing line. drain_last_ok_s is the monotime of
	 * the last good STATUS, and drain_gap_ring holds the last
	 * DRAIN_GAP_RING STATUS waits so a stuck drain's shape can be
	 * reconstructed. */
	double        drain_last_ok_s;
	double        drain_max_gap_s;
	uint32_t      drain_slow_count;
	uint32_t      drain_gap_n;
	double        drain_gap_ring[DRAIN_GAP_RING];
};

/* Forward declarations for the parser callbacks (defined below). */
static int bundle_dl_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime);
static int bundle_dl_data_cb(void *ctx, const u_char *data, size_t len);
static int bundle_dl_entry_end_cb(void *ctx);

/* Parser callback table for the download side, handed to
 * sftp_hpn_tar_parser_new with a struct bundle_dl_stream as ctx. */
static const struct sftp_hpn_tar_callbacks bundle_dl_callbacks = {
	.entry_cb     = bundle_dl_entry_cb,
	.data_cb      = bundle_dl_data_cb,
	.entry_end_cb = bundle_dl_entry_end_cb,
};

/* ------ Parser callbacks ------ */

/* Match a tar record pathname back to an entries[] slot. The server
 * sets the pathname to the original remote_path verbatim, so this is
 * an exact string match. Linear scan. bundles are 32-256 entries. */
static int
bundle_dl_lookup_entry(struct sftp_hpn_bundle_download_entry *entries, int n_entries,
    const char *tar_path)
{
	int i;
	for (i = 0; i < n_entries; i++) {
		/* A NULL remote_path is legal because the unit constructor
		 * allows a NULL source, so skip the slot instead of comparing. */
		if (entries[i].remote_path != NULL &&
		    strcmp(entries[i].remote_path, tar_path) == 0)
			return i;
	}
	return -1;
}

/* Parser entry callback. Maps the record to its entries[] slot, creates
 * the parent directory, then either allocates the pool buffer or opens
 * the output file. Returns 0 to continue, also for a record outside the
 * requested set whose bytes are then discarded, or -1 to fail the
 * bundle. */
static int
bundle_dl_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime)
{
	struct bundle_dl_stream *stream = ctx;
	int idx;
	char *tmp, *dir;
	mode_t perm;

	if (path == NULL || *path == '\0') {
		error_f("hpn-bundle-fetch: empty pathname in tar record");
		return -1;
	}
	idx = bundle_dl_lookup_entry(stream->entries, stream->n_entries, path);
	stream->cur_idx = idx;
	if (idx < 0) {
		debug_f("hpn-bundle-fetch: tar record \"%s\" not in "
		    "entries[]; skipping", path);
		stream->cur_fd    = -1;
		stream->cur_local = NULL;
		return 0;
	}
	if (stream->entries[idx].local_path == NULL) {
		error_f("hpn-bundle-fetch: entry %d local_path NULL", idx);
		return -1;
	}
	stream->cur_local = stream->entries[idx].local_path;
	stream->cur_mtime = mtime;
	stream->cur_mode = mode;
	stream->cur_written = 0;
	tmp = xstrdup(stream->cur_local);
	dir = dirname(tmp);

	/* Pre-create the parent directory. */
	if (*dir != '\0' && strcmp(dir, ".") != 0) {
		/* Skip mkdir_p when the parent is the one created for the
		 * previous entry. Consecutive entries usually share a parent,
		 * so this saves most of the calls. */
		if (stream->last_mkdir_dir == NULL ||
		    strcmp(stream->last_mkdir_dir, dir) != 0) {
			if (mkdir_p(dir, 0755) != 0) {
				error_f("mkdir_p \"%s\": %s",
				    dir, strerror(errno));
				free(tmp);
				return -1;
			}
			free(stream->last_mkdir_dir);
			stream->last_mkdir_dir = xstrdup(dir);
		}
	}
	free(tmp);

	if (stream->pool != NULL) {
		/* Parallel path: buffer this file in RAM; a pool thread does the
		 * open/write/close so the per-file create round-trips overlap.
		 * The parent dir was already mkdir'd above (serial, cached). */
		stream->cur_size = size;
		stream->cur_buf  = (size > 0) ? malloc((size_t)size) : NULL;
		if (size > 0 && stream->cur_buf == NULL) {
			error_f("hpn-bundle-fetch: malloc(%llu) for \"%s\"",
			    (unsigned long long)size, stream->cur_local);
			return -1;
		}
		return 0;
	}

	/* Create mode for the output file: the source permission bits
	 * under -p, else 0644. Both are subject to umask here; -p forces
	 * the exact bits with fchmod in bundle_dl_entry_end_cb. */
	perm = 0644;
	if (stream->preserve_flag)
		perm = mode & 0777;

	/* Open without O_TRUNC, mirroring the upload extractor. The size is
	 * set by ftruncate in bundle_dl_entry_end_cb, which only a completed
	 * entry reaches, so an unfinished partial can only overwrite a prefix
	 * with identical bytes and never shrinks the file. An aborted stream
	 * truncates to the bytes written, see the fetch cleanup, so the
	 * partial is visibly short rather than fallocate-padded, which a
	 * size-only resume would take for complete. */
	stream->cur_fd = open(stream->cur_local, O_WRONLY | O_CREAT, perm);
	if (stream->cur_fd < 0) {
		error_f("open \"%s\": %s", stream->cur_local, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* Pre-allocate extents. */
	if (size > 0)
		(void)posix_fallocate(stream->cur_fd, 0, (off_t)size);
#endif
	return 0;
}

/* Parser data callback. Appends a slice of the current record to the
 * pool buffer or writes it to the open fd, and advances the progress
 * counter. Bytes of a record outside the requested set are discarded.
 * Returns 0, or -1 to fail the bundle. */
static int
bundle_dl_data_cb(void *ctx, const u_char *data, size_t len)
{
	struct bundle_dl_stream *stream = ctx;
	size_t remaining;

	if (stream->cur_idx < 0) {
		/* Record outside the requested set: discard. The server packs
		 * only the paths we asked for, so this is defensive. */
		return 0;
	}
	if (stream->progress != NULL)
		*stream->progress += (off_t)len;
	if (stream->pool != NULL) {
		/* Pool path: accumulate into the per-file buffer for a writer
		 * thread. The parser already clamps delivered data to the declared
		 * size, but bound the memcpy here too so a parser regression
		 * cannot overflow the buffer. The subtraction form cannot
		 * overflow because cur_written <= cur_size always holds. */
		if ((uint64_t)len > (stream->cur_size - stream->cur_written)) {
			error_f("bundle entry data exceeds declared size %llu",
			    (unsigned long long)stream->cur_size);
			return -1;
		}
		if (stream->cur_buf != NULL && len > 0)
			memcpy(stream->cur_buf + stream->cur_written, data, len);
		stream->cur_written += (uint64_t)len;
		return 0;
	}

	remaining = len;
	while (remaining > 0) {
		ssize_t nwritten = write(stream->cur_fd, data, remaining);
		if (nwritten < 0) {
			if (errno == EINTR)
				continue;
			error_f("write \"%s\": %s",
			    stream->cur_local, strerror(errno));
			return -1;
		}
		data      += nwritten;
		remaining -= (size_t)nwritten;
	}
	/* Count only bytes actually on disk: the abort-path ftruncate in the
	 * fetch cleanup uses cur_written as the resume point, which must
	 * never overshoot what was written. */
	stream->cur_written += (uint64_t)len;
	return 0;
}

/* Parser end-of-record callback. Pool path: hand the buffered file to
 * a writer thread. Serial path: apply -p metadata, set the final size,
 * fsync under -f, and close. Marks the entry successful. Returns 0, or
 * -1 to fail the bundle. */
static int
bundle_dl_entry_end_cb(void *ctx)
{
	struct bundle_dl_stream *stream = ctx;
	int rc = 0;

	if (stream->pool != NULL) {
		/* Parallel path: hand the complete file to the writer pool.
		 * Per-file success is optimistic (set below); an actual write
		 * failure surfaces via the pool's error flag at finish, which
		 * fails the whole bundle (the codec's all-or-nothing model). */
		if (stream->cur_idx >= 0) {
			struct bundle_write_job *job = calloc(1, sizeof(*job));
			if (job == NULL) {
				error_f("hpn-bundle-fetch: write-job alloc failed");
				free(stream->cur_buf);
				stream->cur_buf = NULL;
				stream->cur_idx = -1;
				stream->cur_local = NULL;
				return -1;
			}
			/* entries[] owns cur_local; the job takes ownership of
			 * cur_buf. */
			job->full_path = xstrdup(stream->cur_local);
			job->mode      = stream->cur_mode;
			job->mtime     = stream->cur_mtime;
			job->data      = stream->cur_buf;
			job->len       = (size_t)stream->cur_size;
			stream->cur_buf = NULL;
			if (bundle_pool_enqueue(stream->pool, job) != 0) {
				free(job->full_path);
				free(job->data);
				free(job);
				stream->cur_idx = -1;
				stream->cur_local = NULL;
				return -1;	/* a writer already failed; bail */
			}
			stream->entries[stream->cur_idx].result = 0;
		}
		stream->cur_idx   = -1;
		stream->cur_local = NULL;
		return 0;
	}

	if (stream->cur_fd >= 0) {
		/* Set the final size here, at entry completion, in place of the
		 * O_TRUNC that bundle_dl_entry_cb omits. cur_written equals the
		 * declared entry size at this point, and the truncate also clears
		 * any stale tail of a larger pre-existing file. */
		if (ftruncate(stream->cur_fd, (off_t)stream->cur_written) != 0) {
			error_f("ftruncate \"%s\": %s",
			    stream->cur_local, strerror(errno));
			rc = -1;
		}
		if (stream->preserve_flag) {
			struct timespec times[2];
			/* Exact mode: open(O_CREAT, perm) is subject to umask
			 * and ignored on a pre-existing file; force it here to
			 * match real SFTP -p. After the ftruncate, which updates
			 * mtime whenever it changes the size. */
			(void)fchmod(stream->cur_fd,
			    (mode_t)(stream->cur_mode & 0777));
			times[0].tv_sec = stream->cur_mtime;
			times[0].tv_nsec = 0;
			times[1].tv_sec = stream->cur_mtime;
			times[1].tv_nsec = 0;
			(void)futimens(stream->cur_fd, times);
		}
		/* fsync before the close and treat failure as a real error. -f
		 * promises the data is on disk when the command succeeds. */
		if (stream->fsync_flag && fsync(stream->cur_fd) != 0) {
			error_f("fsync \"%s\": %s",
			    stream->cur_local, strerror(errno));
			rc = -1;
		}
		if (close(stream->cur_fd) != 0) {
			error_f("close \"%s\": %s",
			    stream->cur_local, strerror(errno));
			rc = -1;
		}
		stream->cur_fd = -1;
	}
	if (stream->cur_idx >= 0 && rc == 0)
		stream->entries[stream->cur_idx].result = 0;
	stream->cur_idx = -1;
	stream->cur_local = NULL;
	return rc;
}

/* ------ Wire-level fire/drain helpers ------ */

/* Fire one READ. Returns 0 on success, -1 if the READ could not be
 * composed or sent. */
static int
bundle_dl_stream_fire_one(struct bundle_dl_stream *stream)
{
	struct sshbuf *msg;
	u_int read_id;
	int r;

	read_id = sftp_conn_alloc_msg_id(stream->conn);
	if (stream->chunks_sent == 0)
		stream->first_read_id = read_id;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, read_id)) != 0 ||
	    (r = sshbuf_put_string(msg, stream->handle, stream->handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, stream->fire_off)) != 0 ||
	    (r = sshbuf_put_u32(msg, BUNDLE_DL_CHUNK_BYTES)) != 0) {
		error_f("compose hpn-bundle-fetch READ: %s", ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	r = send_msg(stream->conn, msg);
	sshbuf_free(msg);
	if (r != 0)
		return -1;
	stream->chunks_sent++;
	stream->fire_off += BUNDLE_DL_CHUNK_BYTES;
	return 0;
}

/* Drain one outstanding reply and feed any DATA bytes through the
 * codec parser inline. No intermediate queue. Returns:
 *    0  - DATA reply consumed (parser fed); continue
 *    1  - parser signalled EOA (the end marker seen); stop firing
 *    2  - STATUS reply with SSH_FX_EOF received from server
 *         (server has no more bytes; we should stop firing).
 *         May happen before EOA if we asked for more bytes than the
 *         bundle has; treated identically to (1) for the caller.
 *   -1  - error. */
static int
bundle_dl_stream_drain_one(struct bundle_dl_stream *stream,
    struct sftp_hpn_tar_parser *parser)
{
	struct sshbuf *msg = NULL;
	u_int recv_id, status, expected_id;
	u_char type;
	double t_start;
	int r;

	expected_id = stream->first_read_id + stream->chunks_received;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	t_start = monotime_double();
	if (get_msg(stream->conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}
	if (monotime_double() - t_start >
	    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
		sftp_conn_rdahead_backpressure_signal(stream->conn);

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &recv_id)) != 0) {
		error_f("parse hpn-bundle-fetch reply header: %s",
		    ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	/* Never true in normal operation. It catches orphan replies left by
	 * an earlier aborted operation, a request interleaved with the READs,
	 * or a peer that reorders replies. */
	if (recv_id != expected_id) {
		error_f("hpn-bundle-fetch: id mismatch want=%u got=%u "
		    "(chunks_received=%u)", expected_id, recv_id,
		    stream->chunks_received);
		sshbuf_free(msg);
		return -1;
	}
	stream->chunks_received++;

	/* we have data. process it */
	if (type == SSH2_FXP_DATA) {
		const u_char *data = NULL;
		size_t dlen = 0;
		int feed_rc;

		/* Point the parser at the payload inside msg rather than
		 * copying it; msg is freed after the feed. */
		if ((r = sshbuf_get_string_direct(msg, &data, &dlen)) != 0) {
			error_f("parse hpn-bundle-fetch DATA: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		sftp_conn_rdahead_account(stream->conn, dlen);
		/* Live-byte counter for the watchdog: received tar-stream
		 * bytes are the download twin of the upload send-side bump
		 * in bundle_ul_send_write. */
		sftp_conn_live_account(stream->conn, dlen);
		feed_rc = sftp_hpn_tar_parser_feed(parser, data, dlen);
		sshbuf_free(msg);
		if (feed_rc < 0) {
			error_f("hpn-bundle-fetch parser: %s",
			    sftp_hpn_tar_parser_error(parser));
			return -1;
		}
		if (feed_rc == 1)
			return 1;
		return 0;
	}

	/* status message. */
	if (type == SSH2_FXP_STATUS) {
		/* get the code */
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("parse hpn-bundle-fetch STATUS: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		/* Permission denied. If HPN policy tag exists
		 * mark for later abort. */
		if (status == SSH2_FX_PERMISSION_DENIED)
			sftp_conn_check_policy_tag(stream->conn, msg);
		sshbuf_free(msg);
		/* end of bundle. return */
		if (status == SSH2_FX_EOF)
			return 2;
		/* server error. report it. */
		error_f("hpn-bundle-fetch server error: %u "
		    "(chunks_received=%u)", status,
		    stream->chunks_received - 1);
		return -1;
	}
	error_f("hpn-bundle-fetch: unexpected reply type %u",
	    (unsigned)type);
	sshbuf_free(msg);
	return -1;
}

/* Consume the replies to READs still in flight when the stream ends or
 * aborts. The fire loop cannot know where the pack ends, so requests
 * are always outstanding at that point: after a clean end they answer
 * EOF, after an abort they carry DATA nobody will write. Either way
 * they must be read off the channel, or the next get_msg on this
 * connection, the CLOSE included, would take one as its own reply. */
static int
bundle_dl_stream_drain_inflight(struct bundle_dl_stream *stream)
{
	while (stream->chunks_sent > stream->chunks_received) {
		struct sshbuf *msg;
		u_int recv_id, status, expected_id;
		u_char type;
		int r;

		expected_id = stream->first_read_id + stream->chunks_received;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if (get_msg(stream->conn, msg) != 0) {
			sshbuf_free(msg);
			return -1;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &recv_id)) != 0) {
			error_f("hpn-bundle-fetch drain: header: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		/* Causes: see the id check in bundle_dl_stream_drain_one. */
		if (recv_id != expected_id) {
			error_f("hpn-bundle-fetch drain: id mismatch "
			    "want=%u got=%u", expected_id, recv_id);
			sshbuf_free(msg);
			return -1;
		}
		stream->chunks_received++;
		/* A server-error STATUS (e.g. PERMISSION_DENIED) is a
		 * well-formed, in-order reply, not a transport fault: discard
		 * it and keep draining so the pipeline stays in sync. Bailing
		 * here would strand the remaining replies and desync the CLOSE
		 * (the download twin of the bundle_drain_n write-side fix).
		 * Only the transport faults above (read error / bad header /
		 * id mismatch) abort the resync. */
		if (type == SSH2_FXP_STATUS &&
		    sshbuf_get_u32(msg, &status) == 0 &&
		    status != SSH2_FX_EOF)
			debug2_f("hpn-bundle-fetch drain: discarding server "
			    "STATUS %u to resync", status);
		sshbuf_free(msg);
	}
	return 0;
}

/* ------ Public entry point ------ */

/* Fetch a bundle of small files in one streamed transaction: open the
 * bundle handle, keep READs in flight up to the read-ahead cap, feed
 * each DATA reply to the tar parser whose callbacks write the files,
 * then drain, join the writer pool and CLOSE. Failure classification
 * for the caller happens after cleanup, from the connection state. */
int
sftp_hpn_bundle_download(struct sftp_conn *conn,
    struct sftp_hpn_bundle_download_entry *entries, int n_entries,
    const struct sftp_bundle_opts *opts, off_t *progress)
{
	const int preserve_flag = opts->preserve;
	const int fsync_flag = opts->fsync;
	const int writer_pool = opts->writer_pool;
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t  handle_len = 0;
	u_int   open_id, flags;
	struct  bundle_dl_stream stream;
	struct  sftp_hpn_tar_parser *parser = NULL;
	int     i, r, rc = -1;
	int     done = 0;

	/* Reset the request policy denial flag for this bundle attempt. */
	sftp_conn_clear_policy_denied(conn);

	memset(&stream, 0, sizeof(stream));
	stream.cur_idx = -1;
	stream.cur_fd  = -1;

	for (i = 0; i < n_entries; i++)
		entries[i].result = -1;

	if (n_entries <= 0)
		return SFTP_HPN_BUNDLE_OK;
	if (!sftp_conn_has_hpn_bundle_fetch(conn)) {
		debug_f("hpn-bundle-fetch: server does not advertise extension");
		return SFTP_HPN_BUNDLE_SERVER_CANT;  /* permanent */
	}

	debug_f("hpn-bundle-fetch: n=%d preserve=%d", n_entries, preserve_flag);

	/* Send hpn-bundle-fetch@hpnssh.org and collect HANDLE */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	open_id = sftp_conn_alloc_msg_id(conn);
	flags = preserve_flag ? HPN_BUNDLE_FLAG_PRESERVE : 0;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, open_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg,
	        "hpn-bundle-fetch@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0 ||
	    (r = sshbuf_put_u32(msg, (u_int)n_entries)) != 0) {
		error_f("compose hpn-bundle-fetch header: %s", ssh_err(r));
		goto cleanup;
	}
	for (i = 0; i < n_entries; i++) {
		const char *path = entries[i].remote_path;
		if ((r = sshbuf_put_cstring(msg, path ? path : "")) != 0) {
			error_f("compose hpn-bundle-fetch path[%d]: %s",
			    i, ssh_err(r));
			goto cleanup;
		}
	}
	if (send_msg(conn, msg) != 0)
		goto cleanup;
	sshbuf_reset(msg);

	handle = get_handle(conn, open_id, &handle_len,
	    "hpn-bundle-fetch n=%d", n_entries);
	if (handle == NULL) {
		debug_f("hpn-bundle-fetch: server refused open");
		goto cleanup;
	}

	/* Streaming receive: SFTP wire -> parser -> output files */
	stream.conn          = conn;
	stream.handle        = handle;
	stream.handle_len    = handle_len;
	stream.entries       = entries;
	stream.n_entries     = n_entries;
	stream.preserve_flag = preserve_flag;
	stream.fsync_flag    = fsync_flag;
	stream.progress      = progress;

	/* Parallel extract: a writer pool overlaps the per-file open/write/
	 * close on the local (possibly networked) destination, mirroring the
	 * server-side upload extract. On by default; the user disables it via
	 * HPNWriterPool=no (writer_pool == 0). A NULL spawn falls back to
	 * serial, harmless. */
	if (writer_pool) {
		stream.pool = bundle_write_pool_new(bundle_writer_threads(),
		    preserve_flag, fsync_flag, bundle_writer_budget());
		if (stream.pool != NULL)
			debug_f("hpn-bundle-fetch: writer pool active (%d threads)",
			    bundle_writer_threads());
	}

	parser = sftp_hpn_tar_parser_new(&bundle_dl_callbacks, &stream);
	if (parser == NULL) {
		error_f("sftp_hpn_tar_parser_new failed");
		goto cleanup;
	}

	/* Fire/drain main loop: keep in-flight at the adaptive cap until
	 * the parser signals EOA or the server signals EOF. IDs are
	 * sequential within this loop so chunks_received counts as the
	 * expected_id offset (no per-request ring needed). */
	while (!done) {
		u_int    in_flight = stream.chunks_sent -
		    stream.chunks_received;
		uint32_t target;
		int      drain_rc;

		target = sftp_conn_rdahead_cap(conn, BUNDLE_DL_MAX_INFLIGHT);
		if (target == 0 || target > BUNDLE_DL_MAX_INFLIGHT)
			target = BUNDLE_DL_MAX_INFLIGHT;

		/* Top up to target, bounded by the in-flight memory cap. */
		while (in_flight < target) {
			size_t projected = (size_t)(in_flight + 1) *
			    BUNDLE_DL_CHUNK_BYTES;
			if (projected > BUNDLE_DL_QUEUE_MAX_BYTES)
				break;
			if (bundle_dl_stream_fire_one(&stream) != 0)
				goto cleanup;
			in_flight++;
		}

		drain_rc = bundle_dl_stream_drain_one(&stream, parser);
		if (drain_rc < 0)
			goto cleanup;
		/* 1: the parser saw end-of-archive. 2: the server answered
		 * EOF first, the bundle being shorter than the reads fired
		 * for it. Either way stop firing and drain what is left. */
		if (drain_rc > 0)
			done = 1;
	}

	if (bundle_dl_stream_drain_inflight(&stream) != 0)
		goto cleanup;

	/* All entries parsed and enqueued; drain the pool and join the
	 * writers. A nonzero return means a file failed, which fails the
	 * whole bundle. */
	if (stream.pool != NULL) {
		int pool_rc = bundle_write_pool_finish(stream.pool);
		stream.pool = NULL;
		if (pool_rc != 0) {
			error_f("hpn-bundle-fetch: writer pool reported a "
			    "failed file");
			goto cleanup;
		}
	}

	rc = 0;

 cleanup:
	if (stream.pool != NULL)	/* abnormal teardown: join + free pool */
		(void)bundle_write_pool_finish(stream.pool);
	free(stream.cur_buf);		/* a file buffered but not yet enqueued */
	if (parser != NULL)
		sftp_hpn_tar_parser_free(parser);
	if (stream.cur_fd >= 0) {
		/* Aborted mid-entry (a completed entry closes its fd in
		 * entry_end_cb). Truncate to the bytes actually written:
		 * drops the posix_fallocate padding and any stale tail of a
		 * pre-existing file, so the partial is visibly short and a
		 * later size-only resume appends from the right offset, the
		 * same state an aborted plain-SFTP download leaves. */
		(void)ftruncate(stream.cur_fd, (off_t)stream.cur_written);
		(void)close(stream.cur_fd);
	}
	free(stream.last_mkdir_dir);

	/* Resync before CLOSE: a mid-stream failure can leave READ replies
	 * on the wire, and the CLOSE STATUS must not be confused with one.
	 * No-op on the normal path, which drained above, and skipped on a
	 * dead connection. */
	if (handle != NULL && !sftp_conn_is_dead(conn) &&
	    bundle_dl_stream_drain_inflight(&stream) != 0) {
		/* The reply stream is out of step, so neither the CLOSE nor
		 * anything after it can be trusted. Condemn the connection so
		 * the caller replaces it; the server drops the handle with it. */
		error_f("hpn-bundle-fetch: resync failed, "
		    "abandoning connection");
		sftp_conn_set_dead(conn);
	}

	/* Send CLOSE and consume STATUS reply. */
	if (handle != NULL && !sftp_conn_is_dead(conn)) {
		u_int close_id;

		sshbuf_reset(msg);
		close_id = sftp_conn_alloc_msg_id(conn);
		if (sshbuf_put_u8(msg, SSH2_FXP_CLOSE) == 0 &&
		    sshbuf_put_u32(msg, close_id) == 0 &&
		    sshbuf_put_string(msg, handle, handle_len) == 0)
			(void)send_msg(conn, msg);
		sshbuf_reset(msg);
		/* Consume and ignore the CLOSE STATUS reply. */
		(void)get_msg(conn, msg);
	}
	free(handle);
	sshbuf_free(msg);
	/* The pool path marks entries 0 at enqueue, before the writer has
	 * persisted them. Success is validated by bundle_write_pool_finish
	 * above; on any failure those 0s cannot be trusted, so force every
	 * entry back to -1 and let the caller re-queue the batch. The bundle
	 * is all-or-nothing, and a re-transfer of files that did land is
	 * harmless. */
	if (rc != 0) {
		for (i = 0; i < n_entries; i++)
			entries[i].result = -1;
	}
	/* Same cause-scoping as the upload path. A dead conn means this
	 * worker's transport failed and the units stay bundle-eligible; a
	 * live conn means the server refused or lacks the extension, a
	 * permanent per-file fallback. */
	if (rc != 0) {
		if (sftp_conn_saw_policy_denied(conn))
			rc = SFTP_HPN_BUNDLE_POLICY_DENIED;
		else
			rc = sftp_conn_is_dead(conn)
			    ? SFTP_HPN_BUNDLE_TRANSPORT_FAILED
			    : SFTP_HPN_BUNDLE_SERVER_CANT;
	}
	return rc;
}

/* Drain up to `limit` outstanding WRITE STATUS replies. Pass SIZE_MAX to
 * drain all of them. The caller must not issue the SSH_FXP_CLOSE before
 * every WRITE has been drained, or the CLOSE STATUS would be confused
 * with a WRITE STATUS.
 *
 * Two failure classes, kept distinct:
 *   - Server refusal: a well-formed STATUS with a non-OK code (e.g.
 *     PERMISSION_DENIED). The transport is fine; the server simply said
 *     no. Sets any_fail, accounts the STATUS, and keeps draining so the
 *     pipeline stays in sync. conn_lost stays clear, the connection
 *     survives, and the bundle is classified SERVER_CANT (permanent).
 *   - Transport break: a read error, a malformed reply, or a rid desync.
 *     Sets any_fail and conn_lost and stops; the caller condemns the
 *     connection and the bundle is classified TRANSPORT_FAILED (retry).
 * Returns 0 if every drained STATUS was OK, -1 otherwise. */
static int
bundle_drain_n(struct bundle_write_ctx *ctx, size_t limit)
{
	struct sshbuf *msg = NULL;
	uint64_t outstanding;
	int r, rc = 0;

	if (ctx->any_fail)
		return -1;
	outstanding = ctx->n_sent - ctx->n_drained;
	/* make sure we have work to do */
	if (limit > outstanding)
		limit = (size_t)outstanding;
	if (limit == 0)
		return 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	while (limit-- > 0) {
		u_char type;
		u_int status, reply_rid; /* rid = request id */
		u_int expected_rid = ctx->first_rid + (u_int)ctx->n_drained;
		double t_status_start, t_now, gap;

		sshbuf_reset(msg);
		/* Time the STATUS read so the bundle path can signal the
		 * read-ahead controller on a wedge, the same mechanism as the
		 * per-file path in sftp-client.c. Essentially the amount of
		 * time a get_msg() is blocked waiting for the server to reply to
		 * a WRITE. Catches a path that backs up after the controller
		 * has settled high. We are using the term "gap" for this. */
		t_status_start = monotime_double();

		/* we couldn't read a reply so build the error log */
		if (get_msg(ctx->conn, msg) != 0) {
			/* Always-on drain-stall record. fail_block is how long
			 * this final read blocked before EOF or error.
			 * last_ok_age is the silence since the last good
			 * STATUS. Small gaps then a long silence mean sudden
			 * death. Large gaps throughout mean alive but slow. */
			double now = monotime_double();
			double fail_block = now - t_status_start;
			double last_ok_age;
			char gaps[512];
			size_t gaps_len = 0;
			uint32_t gi, gstart = 0;

			if (ctx->drain_last_ok_s > 0.0)
				last_ok_age = now - ctx->drain_last_ok_s;
			else
				last_ok_age = fail_block;
			if (ctx->drain_gap_n > DRAIN_GAP_RING)
				gstart = ctx->drain_gap_n - DRAIN_GAP_RING;
			gaps[0] = '\0';
			/* build a list of the existing gaps for the logs */
			for (gi = gstart; gi < ctx->drain_gap_n &&
			    gaps_len < sizeof(gaps) - 8; gi++) {
				int written = snprintf(gaps + gaps_len,
				    sizeof(gaps) - gaps_len, "%.2f ",
				    ctx->drain_gap_ring[gi % DRAIN_GAP_RING]);
				if (written < 0)
					break;
				gaps_len += (size_t)written;
			}
			logit("bundle DRAIN-FAIL conn=%p drained=%llu/%llu "
			    "fail_block=%.2fs last_ok_age=%.2fs max_gap=%.2fs "
			    "slow=%u gaps=[ %s]",
			    (void *)ctx->conn,
			    (unsigned long long)ctx->n_drained,
			    (unsigned long long)ctx->n_sent,
			    fail_block, last_ok_age, ctx->drain_max_gap_s,
			    ctx->drain_slow_count, gaps);
			error_f("bundle drain: connection closed waiting "
			    "for WRITE STATUS (drained %llu/%llu)",
			    (unsigned long long)ctx->n_drained,
			    (unsigned long long)ctx->n_sent);
			ctx->any_fail = 1;
			ctx->conn_lost = 1;
			rc = -1;
			break;
		}

		/* Bookkeeping on every good reply for the DRAIN-FAIL record:
		 * store this gap in the ring (drain_gap_n counts every reply,
		 * so the ring (size: 48) keeps the newest DRAIN_GAP_RING of them),
		 * track the largest gap and how many exceeded DRAIN_SLOW_GAP_SEC,
		 * and note the time of this reply. A gap past the read-ahead
		 * controller's threshold also tells it to back off. */
		t_now = monotime_double();
		gap = t_now - t_status_start;
		ctx->drain_gap_ring[ctx->drain_gap_n % DRAIN_GAP_RING] = gap;
		ctx->drain_gap_n++;
		if (gap > ctx->drain_max_gap_s)
			ctx->drain_max_gap_s = gap;
		if (gap > DRAIN_SLOW_GAP_SEC)
			ctx->drain_slow_count++;
		ctx->drain_last_ok_s = t_now;

		/* if the gap is more than the limit then the path is backing
		 * up and we need to signal the controller to cut the
		 * in-flight depth in half */
		if (gap > SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
			sftp_conn_rdahead_backpressure_signal(ctx->conn);

		/* get the status. reject malformed status or non status msgs */
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &reply_rid)) != 0 ||
		    type != SSH2_FXP_STATUS ||
		    (r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("bundle drain: malformed STATUS reply "
			    "(type=%u r=%d)", type, r);
			ctx->any_fail = 1;
			ctx->conn_lost = 1;
			rc = -1;
			break;
		}

		/* somehow we didn't get the request id we expected */
		if (reply_rid != expected_rid) {
			error_f("bundle drain: rid mismatch "
			    "(got %u expected %u)", reply_rid, expected_rid);
			ctx->any_fail = 1;
			ctx->conn_lost = 1;
			rc = -1;
			break;
		}
		if (status != SSH2_FX_OK) {
			/* A refusal (e.g. PERMISSION_DENIED, a read-only mount,
			 * quota), not a transport fault: the connection is
			 * healthy and replied in order. Count the STATUS as
			 * drained and keep going so the pipeline stays in sync,
			 * and leave conn_lost clear so the caller classifies
			 * SERVER_CANT rather than respawning into the same
			 * refusal. Log only the first refusal to avoid a
			 * per-WRITE storm. */
			if (!ctx->any_fail)
				error_f("bundle drain: WRITE STATUS %u "
				    "(rid=%u) - server refused", status,
				    reply_rid);
			/* If the server tagged this a -P/-p request policy
			 * denial (HPN_POLICY_DENIED_TAG), the caller aborts the
			 * whole transfer rather than re-denying every file.
			 * Check every denial, not only the first refusal that
			 * is logged. */
			if (status == SSH2_FX_PERMISSION_DENIED)
				sftp_conn_check_policy_tag(ctx->conn, msg);
			ctx->any_fail = 1;
			rc = -1;
			ctx->n_drained++;
			continue;
		}
		ctx->n_drained++;
		/* Feed the adaptive read-ahead controller with the true
		 * size of the just-acked WRITE so its throughput
		 * measurement reflects actual bytes moved, not request
		 * count. No-op when allocation failed (wsizes == NULL)
		 * or when adaptation is disabled. */
		if (ctx->wsizes != NULL)
			sftp_conn_rdahead_account(ctx->conn,
			    ctx->wsizes[(ctx->n_drained - 1) %
			    ctx->wsizes_cap]);
	}
	sshbuf_free(msg);
	return rc;
}

/* Send one WRITE carrying the next slice of the codec stream. When the
 * in-flight count has reached the read-ahead depth, drain half the
 * pipeline first. Returns 0 on success, -1 on any failure, with
 * ctx->any_fail set. */
static int
bundle_ul_send_write(struct bundle_write_ctx *ctx,
    const u_char *buffer, size_t length)
{
	struct sshbuf *msg;
	u_int rid;
	uint32_t cap;
	size_t drain_n;
	int r;

	if (ctx->any_fail)
		return -1;

	/* Adaptive back-pressure: cap outstanding WRITEs at the read-ahead
	 * controller's current depth. When the cap is reached, drain half
	 * of the in-flight WRITEs so the pipeline stays one window deep
	 * instead of thrashing on every WRITE. */
	cap = sftp_conn_rdahead_cap(ctx->conn, BUNDLE_MAX_INFLIGHT);
	if (cap == 0 || cap > BUNDLE_MAX_INFLIGHT)
		cap = BUNDLE_MAX_INFLIGHT;
	if ((ctx->n_sent - ctx->n_drained) >= cap) {
		drain_n = cap / 2;
		if (drain_n == 0)
			drain_n = 1;
		if (bundle_drain_n(ctx, drain_n) < 0) {
			ctx->any_fail = 1;
			return -1;
		}
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	rid = sftp_conn_alloc_msg_id(ctx->conn);
	if (ctx->n_sent == 0)
		ctx->first_rid = rid;

	/* build the bundle data msg and fail on errors */
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
	    (r = sshbuf_put_u32(msg, rid)) != 0 ||
	    (r = sshbuf_put_string(msg, ctx->handle, ctx->handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, (uint64_t)ctx->offset)) != 0 ||
	    (r = sshbuf_put_string(msg, buffer, length)) != 0) {
		error_f("compose bundle WRITE: %s", ssh_err(r));
		sshbuf_free(msg);
		ctx->any_fail = 1;
		return -1;
	}

	/* Remember this WRITE's byte count in its ring slot. A STATUS
	 * reply carries no size, so bundle_drain_n reads it back from here
	 * to feed the read-ahead controller real bytes. */
	if (ctx->wsizes != NULL)
		ctx->wsizes[ctx->n_sent % ctx->wsizes_cap] = (uint32_t)length;
	r = send_msg(ctx->conn, msg);
	sshbuf_free(msg);
	if (r != 0) {
		/* send_msg has logged the cause and marked the connection
		 * dead. Nothing went out, so nothing is accounted. */
		ctx->any_fail = 1;
		ctx->conn_lost = 1;
		return -1;
	}

	/* Feed the watchdog's live-byte counter on the send side. STATUSes
	 * arrive in cap/2 bursts, so on a slow path the first ack could land
	 * after the watchdog's born-dead window and a healthy worker would
	 * be killed at 0 bytes. send_msg paces under the bandwidth limit, so
	 * this counts from the first second, and a wedged server still goes
	 * silent once the in-flight cap fills. */
	sftp_conn_live_account(ctx->conn, length);

	ctx->n_sent++;
	ctx->offset += (off_t)length;
	return 0;
}

/* Upload a bundle of small files in one streamed transaction, the client
 * side of hpn-bundle-open@hpnssh.org. The codec packs the files into its
 * length-prefixed record stream, sent as one OPEN, pipelined WRITEs and a
 * CLOSE; process_hpn_bundle_open in sftp-hpn-bundle-server.c feeds the
 * bytes back through the codec to recreate the files under dest_dir.
 *
 * Wire format:
 *   client -> server:
 *     SSH_FXP_EXTENDED { id, "hpn-bundle-open@hpnssh.org",
 *                       string dest_dir, uint32 flags }
 *       flags (HPN_BUNDLE_FLAG_*): bit 0 preserve metadata, bit 1 fsync
 *       each file, bit 2 extract without the server's writer pool
 *   server -> client:
 *     SSH_FXP_HANDLE { id, handle }            on success
 *     SSH_FXP_STATUS { id, status }            on failure
 *   client -> server: SSH_FXP_WRITE x N with handle, carrying codec bytes
 *   server -> client: SSH_FXP_STATUS x N (one per WRITE)
 *   client -> server: SSH_FXP_CLOSE with handle
 *   server -> client: SSH_FXP_STATUS { id, overall result }
 *
 * Without the extension the function returns SERVER_CANT. It never falls
 * back to per-file transfers itself. */
int
sftp_hpn_bundle_upload(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_hpn_bundle_upload_entry *entries, int n_entries,
    const struct sftp_bundle_opts *opts)
{
	const int preserve_flag = opts->preserve;
	const int fsync_flag = opts->fsync;
	const int writer_pool = opts->writer_pool;
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t handle_len = 0;
	u_int open_id, close_id, status, reply_rid;
	u_int flags;
	u_char type;
	struct sftp_hpn_tar_writer *writer = NULL;
	struct bundle_write_ctx ctx = { 0 };
	u_char  outbuf[HPN_BUNDLE_BLOCK_BYTES];  /* per-WRITE payload buf */
	int i, r;
	/* Generic failure until cleanup reclassifies it as SERVER_CANT or
	 * TRANSPORT_FAILED. 0 is success. */
	int rc = -1;
	/* ENV-VAR HPN_PARALLEL_TRACE per-bundle timing breakdown (seconds). */
	double t_enter = 0, t_open_done = 0, t_send_start = 0;
	double t_send_done = 0, t_drain_done = 0, t_close_done = 0;
	uint64_t bytes_total = 0;
	int files_queued = 0;

	for (i = 0; i < n_entries; i++)
		entries[i].result = -1;   /* pessimistic; flip to 0 on success */

	if (n_entries <= 0)
		return SFTP_HPN_BUNDLE_OK;
	if (!sftp_conn_has_hpn_bundle(conn)) {
		debug_f("hpn-bundle: server does not advertise extension");
		return SFTP_HPN_BUNDLE_SERVER_CANT;  /* permanent */
	}

	/* Per-WRITE size ring for the adaptive read-ahead controller.
	 * NULL on alloc failure is non-fatal (controller-feed becomes a
	 * no-op). */
	ctx.wsizes_cap = BUNDLE_MAX_INFLIGHT;
	ctx.wsizes = calloc(ctx.wsizes_cap, sizeof(uint32_t));
	if (ctx.wsizes == NULL)
		debug_f("hpn-bundle: wsizes calloc failed; "
		    "rdahead controller will see zero-byte acks");

	/* Reset the request policy denial flag for this bundle attempt. */
	sftp_conn_clear_policy_denied(conn);

	debug_f("hpn-bundle upload: n=%d dest=\"%s\" preserve=%d fsync=%d",
	    n_entries, remote_dest_dir, preserve_flag, fsync_flag);
	t_enter = monotime_double();

	/* ------ Send hpn-bundle-open@hpnssh.org and collect HANDLE ------ */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	open_id = sftp_conn_alloc_msg_id(conn);
	/* set our flags */
	flags = 0;
	if (preserve_flag)
		flags |= HPN_BUNDLE_FLAG_PRESERVE;
	if (fsync_flag)
		flags |= HPN_BUNDLE_FLAG_FSYNC;
	if (!writer_pool)
		flags |= HPN_BUNDLE_FLAG_NO_POOL;

	/* create the bundle open msg. fail on error */
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, open_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hpn-bundle-open@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_cstring(msg, remote_dest_dir)) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0)
		fatal_fr(r, "compose hpn-bundle-open");
	if (send_msg(conn, msg) != 0)
		goto cleanup;
	sshbuf_reset(msg);

	/* The base dir is often empty (entries carry their own paths), so a
	 * "%s" would render as hpn-bundle-open "": describe the batch by file
	 * count instead, which is always meaningful. */
	handle = get_handle(conn, open_id, &handle_len,
	    "hpn-bundle-open (%d files)", n_entries);
	if (handle == NULL) {
		debug_f("hpn-bundle: server refused open");
		goto cleanup;
	}
	t_open_done = monotime_double();

	/* ------ Build the tar writer ------ */
	ctx.conn       = conn;
	ctx.handle     = handle;
	ctx.handle_len = handle_len;

	writer = sftp_hpn_tar_writer_new();
	if (writer == NULL) {
		error_f("sftp_hpn_tar_writer_new failed");
		goto cleanup;
	}

	/* Queue every requested entry. Per-entry stat() failures are logged
	 * and skipped. The writer pulls bytes lazily from disk when pack_next
	 * reaches the entry's DATA state, so files are not opened until
	 * needed. */
	for (i = 0; i < n_entries; i++) {
		struct stat sb;
		mode_t      perm;
		time_t      mtime;

		if (entries[i].local_path == NULL ||
		    entries[i].remote_path == NULL)
			continue;
		/* Deliberate re-stat: cheap (attr cache is warm from the
		 * walk) and keeps the tar header's size/mtime fresh. */
		if (stat(entries[i].local_path, &sb) < 0) {
			error("hpn-bundle: stat local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			continue;
		}
		if (!S_ISREG(sb.st_mode)) {
			debug2_f("hpn-bundle: \"%s\" not regular, skip",
			    entries[i].local_path);
			continue;
		}

		perm = 0644;
		mtime = time(NULL);
		if (preserve_flag) {
			perm = sb.st_mode & 07777;
			mtime = sb.st_mtime;
		}

		/* add a file to the bundle */
		if (sftp_hpn_tar_writer_add_file(writer,
		    entries[i].local_path, entries[i].remote_path,
		    perm, (uint64_t)sb.st_size, mtime) < 0) {
			error_f("hpn-bundle: writer_add_file \"%s\" "
			    "rejected (path too long?)",
			    entries[i].remote_path);
			continue;
		}
		/* Mark queued. Flipped back to -1 if a later pack or drain
		 * fails. */
		entries[i].result = 0;
		files_queued++;
	}
	sftp_hpn_tar_writer_finish(writer);

	/* ------ Pack/send loop ------ */
	t_send_start = monotime_double();
	for (;;) {
		ssize_t produced = sftp_hpn_tar_writer_pack_next(writer,
		    outbuf, sizeof(outbuf));
		if (produced < 0) {
			error_f("hpn-bundle: pack: %s",
			    sftp_hpn_tar_writer_error(writer));
			goto cleanup;
		}
		if (produced == 0)
			break;	/* EOA reached, all bytes sent */
		bytes_total += (uint64_t)produced;
		if (bundle_ul_send_write(&ctx, outbuf, (size_t)produced) != 0)
			goto cleanup;
	}
	t_send_done = monotime_double();

	/* Drain the deferred WRITE STATUSes before SSH_FXP_CLOSE. */
	if (bundle_drain_n(&ctx, SIZE_MAX) < 0) {
		debug_f("hpn-bundle: WRITE drain reported failure");
		goto cleanup;
	}
	t_drain_done = monotime_double();

	/* ------ Close the bundle handle, collect overall STATUS ------ */
	close_id = sftp_conn_alloc_msg_id(conn);
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(msg, close_id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose bundle CLOSE");
	(void)send_msg(conn, msg);
	sshbuf_reset(msg);

	if (get_msg(conn, msg) != 0) {
		error_f("hpn-bundle: connection closed before "
		    "CLOSE reply");
		goto cleanup;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &reply_rid)) != 0) {
		error_f("hpn-bundle: malformed CLOSE reply");
		goto cleanup;
	}
	if (reply_rid != close_id) {
		error_f("hpn-bundle: CLOSE reply rid=%u expected %u",
		    reply_rid, close_id);
		goto cleanup;
	}
	if (type != SSH2_FXP_STATUS ||
	    (r = sshbuf_get_u32(msg, &status)) != 0) {
		error_f("hpn-bundle: malformed CLOSE reply");
		goto cleanup;
	}
	if (status != SSH2_FX_OK) {
		error_f("hpn-bundle: CLOSE failed status=%u "
		    "(rid=%u expected %u)",
		    status, reply_rid, close_id);
		goto cleanup;
	}

	t_close_done = monotime_double();
	if (getenv("HPN_PARALLEL_TRACE") != NULL) {
		uint32_t cap_final =
		    sftp_conn_rdahead_cap(conn, BUNDLE_MAX_INFLIGHT);
		/* ENV-VAR HPN_PARALLEL_TRACE: developer-only per-bundle timing
		 * breakdown. `enter` is absolute monotonic seconds, so the
		 * inter-bundle idle for a given worker (conn) in post-
		 * processing is enter[k+1] - (enter[k] + total[k]). open,
		 * drain and close are the three serialized RTT-bound
		 * handshakes; send is the data phase, including any mid-bundle
		 * drains. Never required for normal operation. */
		logit("hpn-bundle TIMING conn=%p enter=%.3f files=%d "
		    "nwrite=%llu bytes=%llu cap=%u open=%.3f send=%.3f "
		    "drain=%.3f close=%.3f total=%.3f dmaxgap=%.3f dslow=%u",
		    (void *)conn, t_enter, files_queued,
		    (unsigned long long)ctx.n_sent,
		    (unsigned long long)bytes_total, cap_final,
		    t_open_done - t_enter, t_send_done - t_send_start,
		    t_drain_done - t_send_done, t_close_done - t_drain_done,
		    t_close_done - t_enter,
		    ctx.drain_max_gap_s, ctx.drain_slow_count);
	}

	rc = 0;   /* success; entries[].result already 0 from above */

 cleanup:
	/* If we sent WRITEs but bailed before draining, consume the
	 * matching STATUSes so the next op on this conn doesn't read
	 * them as its own reply. A non-OK STATUS encountered here is a
	 * server refusal, not a transport break, so it does not condemn
	 * the connection. Only a genuine transport loss does, and conn_lost,
	 * set inside bundle_drain_n on a read error, a malformed reply or a
	 * rid desync, is the authoritative signal for that. Gate
	 * sftp_conn_set_dead on it rather than on the drain's -1, which
	 * also fires on a plain refusal. */
	if (rc != 0 && ctx.n_sent > ctx.n_drained) {
		int saved_fail = ctx.any_fail;
		ctx.any_fail = 0;
		(void)bundle_drain_n(&ctx, SIZE_MAX);
		ctx.any_fail = saved_fail;
	}
	if (rc != 0 && ctx.conn_lost)
		sftp_conn_set_dead(conn);
	if (rc != 0) {
		for (i = 0; i < n_entries; i++)
			entries[i].result = -1;
	}
	sftp_hpn_tar_writer_free(writer);
	free(handle);
	free(ctx.wsizes);
	sshbuf_free(msg);

	/* Classify the failure for the caller's bundle-eligibility decision.
	 * Done here, after the cleanup re-drain may have marked the conn
	 * dead, so it reflects the final connection state: a dead conn means
	 * this worker's transport died mid-bundle (the units bundle fine on
	 * a healthy worker, so they stay eligible); a live conn means the
	 * server refused or lacks the extension (permanent, mark them
	 * ineligible). */
	if (rc != 0) {
		if (sftp_conn_saw_policy_denied(conn))
			rc = SFTP_HPN_BUNDLE_POLICY_DENIED;
		else
			rc = sftp_conn_is_dead(conn)
			    ? SFTP_HPN_BUNDLE_TRANSPORT_FAILED
			    : SFTP_HPN_BUNDLE_SERVER_CANT;
	}
	return rc;
}
