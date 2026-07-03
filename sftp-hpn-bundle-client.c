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
 * sftp-hpn-bundle-client.c - client-side SFTP bundle protocol.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Extracted from sftp-hpn-client.c on 2026-05-31 as part of the
 * structural refactor described in project_hpn_code_organization_vision.md.
 *
 * Contents:
 *   - Download: hpn-bundle-fetch@hpnssh.org
 *       * bundle_dl_stream state machine + parser callbacks
 *       * fire/drain wire helpers, env-var memory cap
 *       * sftp_hpn_bundle_download (public entry; declared in sftp-client.h)
 *   - Upload: hpn-bundle-open@hpnssh.org
 *       * bundle_write_ctx + bundle_drain_n / bundle_ul_send_write
 *       * sftp_hpn_bundle_upload (public entry; declared in sftp-client.h)
 *
 * Everything that's not a public entry point is static; the module's
 * external surface is exactly the two public functions plus their
 * declared struct types in sftp-client.h.
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

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
#include "misc.h"		/* monotime_double */
#include "sftp-common.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-client.h"	/* struct sftp_hpn_conn + adaptive rdahead API */
#include "sftp-hpn-bundle.h"
#include "sftp-hpn-bundle-client.h"
#include "sftp-hpn-tar.h"
#include "sftp-hpn-bundle-pool.h"	/* shared writer pool (extract overlap) */

/* ── BEGIN Phase 5: hpn-bundle-fetch download ─────────────────────────────
 *
 * Implements the client side of `hpn-bundle-fetch@hpnssh.org`.  Symmetric
 * twin of sftp_hpn_bundle_upload (defined later in this file).
 *
 * 2026-05-31 libarchive removal: the queue + libarchive read_cb path is
 * replaced by the sftp-hpn-tar codec.  DATA bytes flow wire →
 * drain_one → parser_feed → file write, with no intermediate buffering.
 * Per-worker memory is bounded by the in-flight read depth × chunk
 * size (HPN_BUNDLE_QUEUE_MAX_BYTES) plus ~1 KiB parser state.
 *
 * Pipelining: still fire-N-reads-ahead via the adaptive read-ahead
 * controller, so the wire stays saturated.  But there's no orphan-
 * drain ID-mismatch concern because we KNOW when to stop firing (the
 * parser tells us via PS_DONE after the EOA two zero blocks).
 */

/*
 * Match a tar record pathname back to an entries[] slot.  The server
 * sets the pathname to the original remote_path verbatim, so this is
 * an exact string match.  Linear scan - bundles are 32–256 entries.
 */
static int
bundle_dl_lookup_entry(struct sftp_hpn_bundle_download_entry *entries, int n,
    const char *tar_path)
{
	int i;
	for (i = 0; i < n; i++) {
		if (entries[i].remote_path != NULL &&
		    strcmp(entries[i].remote_path, tar_path) == 0)
			return i;
	}
	return -1;
}

/*
 * Per-READ chunk size for bundle downloads.  128 KiB matches the
 * default SFTP_MAX_READ_LENGTH ceiling on most server builds, so each
 * READ returns one full block from the server's streaming pack.
 */
#define BUNDLE_DL_CHUNK_BYTES   (128u * 1024u)

/*
 * Safety bound on outstanding (unread) READ requests.  Operational
 * depth is normally driven by the in-flight memory cap below and the
 * adaptive read-ahead controller; this is just a sanity ceiling.
 */
#define BUNDLE_DL_MAX_INFLIGHT  1024u

/*
 * Default per-worker memory ceiling on in-flight READ requests, in
 * bytes.  Bounds (in_flight × CHUNK_BYTES) ≤ this value.  Overridable
 * at runtime via HPN_BUNDLE_QUEUE_MAX_BYTES.  32 MiB / 128 KiB = 256
 * outstanding chunks - enough for ~10 Gbps × 25 ms or 1 Gbps × 250 ms.
 *
 * Note: with the codec replacing libarchive, client-side memory is
 * actually dominated by the SSH transport's input buffer, not by any
 * client-managed queue (there is none).  The cap controls how many
 * READs we have in flight, which is what determines BDP fill.
 */
#define BUNDLE_DL_QUEUE_MAX_BYTES_DEFAULT  (32u * 1024u * 1024u)

/*
 * Download stream context.  Tracks SFTP wire state (in-flight count
 * via counters, since READ IDs are sequential) and per-entry parser
 * state (open output fd, current path, last-mkdir cache).  Pointer to
 * this struct is the parser's ctx, so entry/data/end callbacks have
 * access to all download-side fields.
 */
struct bundle_dl_stream {
	struct sftp_conn *conn;
	const u_char     *handle;
	size_t            handle_len;

	/* SFTP wire pipeline tracking - IDs are sequential within
	 * the receive loop because nothing else allocates msg_id. */
	u_int    first_read_id;
	int      first_read_id_set;
	u_int    chunks_sent;
	u_int    chunks_received;
	uint64_t fire_off;
	int      eoa_seen;	/* parser returned 1 from feed() */

	size_t   max_inflight_bytes;	/* HPN_BUNDLE_QUEUE_MAX_BYTES */

	/* Caller-supplied download-entry list, used by entry_cb to map
	 * tar pathnames back to local destinations. */
	struct sftp_hpn_bundle_download_entry *entries;
	int      n_entries;
	int      preserve_flag;

	/* Per-entry state set by entry_cb. */
	int         cur_idx;	/* index into entries[], -1 if tar path
				 * not in our requested set */
	int         cur_fd;	/* open output fd, or -1 */
	const char *cur_local;	/* local_path for current entry (entries[]
				 * owns the storage; we just point at it) */
	time_t   cur_mtime;	/* used by entry_end_cb */
	mode_t   cur_mode;	/* used by entry_end_cb (exact-mode fchmod) */
	uint64_t cur_written;	/* bytes written for the current entry; used to
				 * ftruncate the file to its real size */

	/* Pool (parallel extract) state - active when pool != NULL.  In pool
	 * mode entry_cb buffers the whole file (cur_buf), data_cb fills it
	 * (offset tracked by cur_written), and entry_end_cb hands it off as a
	 * job; the writer threads do the open/write/close. */
	struct bundle_write_pool *pool;	/* writer pool, or NULL (serial path) */
	u_char  *cur_buf;	/* pool: current file's data buffer (owns) */
	uint64_t cur_size;	/* pool: declared size from the tar header */

	/* (D) Most-recently-mkdir_p'd parent dir - skip repeats. */
	char    *last_mkdir_dir;

	/* Sticky error: data_cb / entry_end_cb / etc. failed. */
	int      error;
};

/*
 * ENV-VAR HPN_BUNDLE_QUEUE_MAX_BYTES - developer-only: per-worker
 * memory ceiling on in-flight READ requests for the bundle download
 * path.  Bounds in_flight_count × BUNDLE_DL_CHUNK_BYTES ≤ this value.
 *
 * Default: BUNDLE_DL_QUEUE_MAX_BYTES_DEFAULT (32 MiB).  Accepts K/M/G
 * suffix (parsed via the openbsd-compat scan_scaled helper).  Values
 * below one chunk are clamped up.  Higher values let us saturate
 * fatter BDPs; lower values bound memory (and indirectly, server-side
 * bundle accumulator commitment) at the cost of throughput when
 * extract can't keep up with the wire.
 *
 * Renamed from HPN_BUNDLE_DL_QUEUE_MAX_BYTES (2026-05-31) when the
 * upload path gained the symmetric cap.  See benchmark/env-vars-reference.md.
 *
 * The previous in-file bundle_dl_parse_bytes helper was deduplicated
 * against the server-side parse_bytes_arg by routing both through
 * scan_scaled (2026-05-31 cleanup) - the rest of the codebase uses
 * scan_scaled for the same job, so the bundle modules now follow the
 * project idiom.
 */
static size_t
bundle_dl_queue_max_bytes(void)
{
	static size_t cached     = 0;
	static int    initialized = 0;
	const char   *ev;
	long long     llv;
	size_t        v = 0;

	if (initialized)
		return cached;
	ev = getenv("HPN_BUNDLE_QUEUE_MAX_BYTES");
	if (ev != NULL && *ev != '\0' &&
	    scan_scaled((char *)ev, &llv) == 0 &&
	    llv > 0 && (unsigned long long)llv <= SIZE_MAX)
		v = (size_t)llv;
	if (v == 0)
		v = BUNDLE_DL_QUEUE_MAX_BYTES_DEFAULT;
	if (v < BUNDLE_DL_CHUNK_BYTES)
		v = BUNDLE_DL_CHUNK_BYTES;
	cached     = v;
	initialized = 1;
	debug_f("hpn-bundle inflight cap %zu bytes (%zu chunks)",
	    cached, cached / BUNDLE_DL_CHUNK_BYTES);
	return cached;
}

/* ── Parser callbacks ───────────────────────────────────────────────── */

static int
bundle_dl_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime)
{
	struct bundle_dl_stream *s = ctx;
	int idx;

	if (path == NULL || *path == '\0') {
		error_f("hpn-bundle-fetch: empty pathname in tar record");
		return -1;
	}
	idx = bundle_dl_lookup_entry(s->entries, s->n_entries, path);
	s->cur_idx = idx;
	if (idx < 0) {
		debug_f("hpn-bundle-fetch: tar record \"%s\" not in "
		    "entries[]; skipping", path);
		s->cur_fd    = -1;
		s->cur_local = NULL;
		return 0;
	}
	if (s->entries[idx].local_path == NULL) {
		error_f("hpn-bundle-fetch: entry %d local_path NULL", idx);
		return -1;
	}
	s->cur_local = s->entries[idx].local_path;
	s->cur_mtime = mtime;
	s->cur_mode = mode;
	s->cur_written = 0;

	/* (D) pre-create parent dir, skipping the call if it matches the
	 * most-recent dir we already created. */
	{
		char *tmp = xstrdup(s->cur_local);
		char *dir = dirname(tmp);
		if (dir != NULL && *dir != '\0' &&
		    strcmp(dir, ".") != 0) {
			if (s->last_mkdir_dir == NULL ||
			    strcmp(s->last_mkdir_dir, dir) != 0) {
				if (mkdir_p(dir, 0755) != 0 &&
				    errno != EEXIST) {
					error_f("mkdir_p \"%s\": %s",
					    dir, strerror(errno));
					free(tmp);
					return -1;
				}
				free(s->last_mkdir_dir);
				s->last_mkdir_dir = xstrdup(dir);
			}
		}
		free(tmp);
	}

	if (s->pool != NULL) {
		/* Parallel path: buffer this file in RAM; a pool thread does the
		 * open/write/close so the per-file create round-trips overlap.
		 * The parent dir was already mkdir'd above (serial, cached). */
		s->cur_size = size;
		s->cur_buf  = (size > 0) ? malloc((size_t)size) : NULL;
		if (size > 0 && s->cur_buf == NULL) {
			error_f("hpn-bundle-fetch: malloc(%llu) for \"%s\"",
			    (unsigned long long)size, s->cur_local);
			return -1;
		}
		return 0;
	}

	mode_t perm = s->preserve_flag ? (mode & 07777) : 0644;
	/*
	 * HPN bundle-truncation fix (#4), download side: open WITHOUT O_TRUNC,
	 * mirroring the upload extractor.  The authoritative size is set by
	 * ftruncate() in bundle_dl_entry_end_cb (only a completed entry reaches
	 * it), so a never-completed partial can only overwrite a prefix with
	 * identical bytes and can never shrink the file.  An aborted stream
	 * instead truncates the in-flight entry to the bytes it actually wrote
	 * (see the fetch cleanup path), so the partial ends visibly short
	 * rather than fallocate-padded to full size, which a size-only resume
	 * would mistake for a complete file.
	 */
	s->cur_fd = open(s->cur_local, O_WRONLY | O_CREAT, perm);
	if (s->cur_fd < 0) {
		error_f("open \"%s\": %s", s->cur_local, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* (E) pre-allocate extents. */
	if (size > 0)
		(void)posix_fallocate(s->cur_fd, 0, (off_t)size);
#endif
	return 0;
}

static int
bundle_dl_data_cb(void *ctx, const u_char *data, size_t len)
{
	struct bundle_dl_stream *s = ctx;
	size_t remaining;

	if (s->cur_idx < 0) {
		/* Tar entry not in our requested set - discard bytes.
		 * (Shouldn't normally happen since the server packs only
		 * the paths we asked for.) */
		return 0;
	}
	if (s->pool != NULL) {
		/* Parallel path: accumulate into the per-file buffer; a pool
		 * thread writes it once the entry completes. */
		/* Defense-in-depth: the parser already clamps delivered data to
		 * the declared entry size, but bound the memcpy locally too so a
		 * parser regression cannot overflow the cur_size-sized buffer.
		 * Subtraction form avoids overflow in the check itself
		 * (cur_written <= cur_size is the maintained invariant). */
		if ((uint64_t)len > s->cur_size - s->cur_written) {
			error_f("bundle entry data exceeds declared size %llu",
			    (unsigned long long)s->cur_size);
			return -1;
		}
		if (s->cur_buf != NULL && len > 0)
			memcpy(s->cur_buf + s->cur_written, data, len);
		s->cur_written += (uint64_t)len;
		return 0;
	}

	if (s->cur_fd < 0)
		return -1;

	remaining = len;
	while (remaining > 0) {
		ssize_t n = write(s->cur_fd, data, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			error_f("write \"%s\": %s",
			    s->cur_local, strerror(errno));
			return -1;
		}
		data      += n;
		remaining -= (size_t)n;
	}
	/* Count only bytes actually on disk: the abort-path ftruncate in the
	 * fetch cleanup uses cur_written as the resume point, which must
	 * never overshoot what was written. */
	s->cur_written += (uint64_t)len;
	return 0;
}

static int
bundle_dl_entry_end_cb(void *ctx)
{
	struct bundle_dl_stream *s = ctx;
	int rc = 0;

	if (s->pool != NULL) {
		/* Parallel path: hand the complete file to the writer pool.
		 * Per-file success is optimistic (set below); an actual write
		 * failure surfaces via the pool's error flag at finish, which
		 * fails the whole bundle (the codec's all-or-nothing model). */
		if (s->cur_idx >= 0) {
			struct bundle_write_job *job = calloc(1, sizeof(*job));
			if (job == NULL) {
				error_f("hpn-bundle-fetch: write-job alloc failed");
				free(s->cur_buf); s->cur_buf = NULL;
				s->cur_idx = -1; s->cur_local = NULL;
				return -1;
			}
			job->full_path = xstrdup(s->cur_local); /* entries[] owns cur_local */
			job->mode      = s->cur_mode;
			job->mtime     = s->cur_mtime;
			job->data      = s->cur_buf;	/* transfer ownership */
			job->len       = (size_t)s->cur_size;
			s->cur_buf     = NULL;
			if (bundle_pool_enqueue(s->pool, job) != 0) {
				free(job->full_path);
				free(job->data);
				free(job);
				s->cur_idx = -1; s->cur_local = NULL;
				return -1;	/* a writer already failed; bail */
			}
			s->entries[s->cur_idx].result = 0;
		}
		s->cur_idx   = -1;
		s->cur_local = NULL;
		return 0;
	}

	if (s->cur_fd >= 0) {
		if (s->preserve_flag) {
			struct timespec ts[2];
			/* Exact mode: open(O_CREAT, perm) is subject to umask
			 * and ignored on a pre-existing file; force it here to
			 * match real SFTP -p. */
			(void)fchmod(s->cur_fd, (mode_t)(s->cur_mode & 07777));
			ts[0].tv_sec = s->cur_mtime; ts[0].tv_nsec = 0;
			ts[1].tv_sec = s->cur_mtime; ts[1].tv_nsec = 0;
			(void)futimens(s->cur_fd, ts);
		}
		/*
		 * HPN bundle-truncation fix (#4), download side: set the
		 * authoritative size at entry completion (replaces the open-time
		 * O_TRUNC dropped in bundle_dl_entry_cb).  cur_written == the
		 * declared entry size here; this also clears any stale tail when
		 * overwriting a larger pre-existing file.
		 */
		if (ftruncate(s->cur_fd, (off_t)s->cur_written) != 0) {
			error_f("ftruncate \"%s\": %s",
			    s->cur_local, strerror(errno));
			rc = -1;
		}
		if (close(s->cur_fd) != 0) {
			error_f("close \"%s\": %s",
			    s->cur_local, strerror(errno));
			rc = -1;
		}
		s->cur_fd = -1;
	}
	if (s->cur_idx >= 0 && rc == 0)
		s->entries[s->cur_idx].result = 0;
	s->cur_idx = -1;
	s->cur_local = NULL;
	return rc;
}

static const struct sftp_hpn_tar_callbacks bundle_dl_callbacks = {
	.entry_cb     = bundle_dl_entry_cb,
	.data_cb      = bundle_dl_data_cb,
	.entry_end_cb = bundle_dl_entry_end_cb,
};

/* ── Wire-level fire/drain helpers ───────────────────────────────────── */

/* Fire one READ.  Returns 0 on success, -1 on transport / OOM error. */
static int
bundle_dl_stream_fire_one(struct bundle_dl_stream *s)
{
	struct sshbuf *msg;
	u_int read_id;
	int r;

	read_id = sftp_conn_alloc_msg_id(s->conn);
	if (!s->first_read_id_set) {
		s->first_read_id     = read_id;
		s->first_read_id_set = 1;
	}
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, read_id)) != 0 ||
	    (r = sshbuf_put_string(msg, s->handle, s->handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, s->fire_off)) != 0 ||
	    (r = sshbuf_put_u32(msg, BUNDLE_DL_CHUNK_BYTES)) != 0) {
		error_f("compose hpn-bundle-fetch READ: %s", ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	if (send_msg(s->conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}
	sshbuf_free(msg);
	s->chunks_sent++;
	s->fire_off += BUNDLE_DL_CHUNK_BYTES;
	return 0;
}

/*
 * Drain one outstanding reply and feed any DATA bytes through the
 * codec parser inline.  No intermediate queue.  Returns:
 *    0  - DATA reply consumed (parser fed); continue
 *    1  - parser signalled EOA (two zero blocks seen); stop firing
 *    2  - STATUS reply with SSH_FX_EOF received from server
 *         (server has no more bytes; we should stop firing).
 *         May happen before EOA if we asked for more bytes than the
 *         bundle has; treated identically to (1) for the caller.
 *   -1  - error.
 */
static int
bundle_dl_stream_drain_one(struct bundle_dl_stream *s,
    struct sftp_hpn_tar_parser *parser)
{
	struct sshbuf *msg = NULL;
	u_int recv_id, status, expected_id;
	u_char type;
	double t_start;
	int r;

	expected_id = s->first_read_id + s->chunks_received;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	t_start = monotime_double();
	if (get_msg(s->conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}
	if (monotime_double() - t_start >
	    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
		sftp_conn_rdahead_backpressure_signal(s->conn);

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &recv_id)) != 0) {
		error_f("parse hpn-bundle-fetch reply header: %s",
		    ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	if (recv_id != expected_id) {
		error_f("hpn-bundle-fetch: id mismatch want=%u got=%u "
		    "(chunks_received=%u)", expected_id, recv_id,
		    s->chunks_received);
		sshbuf_free(msg);
		return -1;
	}
	s->chunks_received++;

	if (type == SSH2_FXP_DATA) {
		u_char *data = NULL;
		size_t  dlen = 0;
		int pr;
		if ((r = sshbuf_get_string(msg, &data, &dlen)) != 0) {
			error_f("parse hpn-bundle-fetch DATA: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		sshbuf_free(msg);
		sftp_conn_rdahead_account(s->conn, dlen);
		pr = sftp_hpn_tar_parser_feed(parser, data, dlen);
		free(data);
		if (pr < 0) {
			error_f("hpn-bundle-fetch parser: %s",
			    sftp_hpn_tar_parser_error(parser));
			s->error = 1;
			return -1;
		}
		return (pr == 1) ? 1 : 0;
	}
	if (type == SSH2_FXP_STATUS) {
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("parse hpn-bundle-fetch STATUS: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		/* HPN: read the policy tag (if any) before freeing msg. */
		if (status == SSH2_FX_PERMISSION_DENIED)
			sftp_conn_check_policy_tag(s->conn, msg);
		sshbuf_free(msg);
		if (status == SSH2_FX_EOF)
			return 2;
		error_f("hpn-bundle-fetch server error: %u "
		    "(chunks_received=%u)", status,
		    s->chunks_received - 1);
		return -1;
	}
	error_f("hpn-bundle-fetch: unexpected reply type %u",
	    (unsigned)type);
	sshbuf_free(msg);
	return -1;
}

/* Drain remaining outstanding replies after EOA / EOF, discarding any
 * DATA payload.  Same purpose as before the codec swap - keep the
 * channel state consistent before CLOSE. */
static int
bundle_dl_stream_drain_inflight(struct bundle_dl_stream *s)
{
	while (s->chunks_sent > s->chunks_received) {
		struct sshbuf *msg;
		u_int recv_id, status, expected_id;
		u_char type;
		int r;

		expected_id = s->first_read_id + s->chunks_received;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if (get_msg(s->conn, msg) != 0) {
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
		if (recv_id != expected_id) {
			error_f("hpn-bundle-fetch drain: id mismatch "
			    "want=%u got=%u", expected_id, recv_id);
			sshbuf_free(msg);
			return -1;
		}
		s->chunks_received++;
		/* A server-error STATUS (e.g. PERMISSION_DENIED) is a
		 * well-formed, in-order reply, not a transport fault: discard
		 * it and keep draining so the pipeline stays in sync.  Bailing
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

/* ── Public entry point ─────────────────────────────────────────────── */

int
sftp_hpn_bundle_download(struct sftp_conn *conn,
    struct sftp_hpn_bundle_download_entry *entries, int n,
    int preserve_flag, int writer_pool)
{
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t  handle_len = 0;
	u_int   open_id, flags;
	struct  bundle_dl_stream stream;
	struct  sftp_hpn_tar_parser *parser = NULL;
	int     i, r, rc = -1;
	int     done = 0;

	/* HPN: scope the policy-denied signal to this bundle attempt. */
	sftp_conn_clear_policy_denied(conn);

	memset(&stream, 0, sizeof(stream));
	stream.cur_idx = -1;
	stream.cur_fd  = -1;

	for (i = 0; i < n; i++)
		entries[i].result = -1;

	if (n <= 0)
		return SFTP_HPN_BUNDLE_OK;
	if (!sftp_conn_has_hpn_bundle_fetch(conn)) {
		debug_f("hpn-bundle-fetch: server does not advertise extension");
		return SFTP_HPN_BUNDLE_SERVER_CANT;  /* permanent */
	}

	debug_f("hpn-bundle-fetch: n=%d preserve=%d", n, preserve_flag);

	/* ── Send hpn-bundle-fetch@hpnssh.org and collect HANDLE ─────── */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	open_id = sftp_conn_alloc_msg_id(conn);
	flags = preserve_flag ? HPN_BUNDLE_FLAG_PRESERVE : 0;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, open_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg,
	        "hpn-bundle-fetch@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0 ||
	    (r = sshbuf_put_u32(msg, (u_int)n)) != 0) {
		error_f("compose hpn-bundle-fetch header: %s", ssh_err(r));
		goto cleanup;
	}
	for (i = 0; i < n; i++) {
		const char *p = entries[i].remote_path;
		if ((r = sshbuf_put_cstring(msg, p ? p : "")) != 0) {
			error_f("compose hpn-bundle-fetch path[%d]: %s",
			    i, ssh_err(r));
			goto cleanup;
		}
	}
	if (send_msg(conn, msg) != 0)
		goto cleanup;
	sshbuf_reset(msg);

	handle = get_handle(conn, open_id, &handle_len,
	    "hpn-bundle-fetch n=%d", n);
	if (handle == NULL) {
		debug_f("hpn-bundle-fetch: server refused open");
		goto cleanup;
	}

	/* ── Streaming receive: SFTP wire → parser → output files ────── */
	stream.conn         = conn;
	stream.handle       = handle;
	stream.handle_len   = handle_len;
	stream.entries      = entries;
	stream.n_entries    = n;
	stream.preserve_flag = preserve_flag;
	stream.max_inflight_bytes = bundle_dl_queue_max_bytes();

	/* Parallel extract: a writer pool overlaps the per-file open/write/
	 * close on the local (possibly networked) destination, mirroring the
	 * server-side upload extract.  On by default; the user disables it via
	 * HPNWriterPool=no (writer_pool == 0).  A NULL spawn falls back to
	 * serial, harmless. */
	if (writer_pool) {
		stream.pool = bundle_write_pool_new(bundle_writer_threads(),
		    preserve_flag, 0 /* do_fsync */, bundle_writer_budget());
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
	 * the parser signals EOA or the server signals EOF.  IDs are
	 * sequential within this loop so chunks_received counts as the
	 * expected_id offset (no per-request ring needed). */
	while (!done) {
		u_int    in_flight = stream.chunks_sent -
		    stream.chunks_received;
		uint32_t target;

		if (stream.error)
			goto cleanup;

		target = sftp_conn_rdahead_cap(conn, BUNDLE_DL_MAX_INFLIGHT);
		if (target == 0 || target > BUNDLE_DL_MAX_INFLIGHT)
			target = BUNDLE_DL_MAX_INFLIGHT;

		/* Top up to target, bounded by the in-flight memory cap. */
		while (in_flight < target) {
			size_t projected = (size_t)(in_flight + 1) *
			    BUNDLE_DL_CHUNK_BYTES;
			if (projected > stream.max_inflight_bytes)
				break;
			if (bundle_dl_stream_fire_one(&stream) != 0)
				goto cleanup;
			in_flight++;
		}

		if (in_flight == 0) {
			/* No reads in flight (cap is below CHUNK_BYTES?
			 * That should have been clamped - log + fail). */
			error_f("hpn-bundle-fetch: stuck with zero in-flight "
			    "(max_inflight_bytes=%zu)",
			    stream.max_inflight_bytes);
			goto cleanup;
		}

		int dr = bundle_dl_stream_drain_one(&stream, parser);
		if (dr < 0)
			goto cleanup;
		if (dr == 1) {
			/* Parser hit EOA - stop firing, drain orphans. */
			stream.eoa_seen = 1;
			done = 1;
		} else if (dr == 2) {
			/* Server hit EOF before we saw EOA - bundle was
			 * shorter than we asked for.  Parser may or may
			 * not have seen its end-of-archive depending on
			 * what the server packed; either way we stop. */
			done = 1;
		}
	}

	if (bundle_dl_stream_drain_inflight(&stream) != 0)
		goto cleanup;

	/* All entries parsed + enqueued; drain the pool and join the writers.
	 * A nonzero return = some file failed -> fail the whole bundle. */
	if (stream.pool != NULL) {
		int perr = bundle_write_pool_finish(stream.pool);
		stream.pool = NULL;
		if (perr != 0) {
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
		 * entry_end_cb).  Truncate to the bytes actually written:
		 * drops the posix_fallocate padding and any stale tail of a
		 * pre-existing file, so the partial is visibly short and a
		 * later size-only resume appends from the right offset - the
		 * same state an aborted plain-SFTP download leaves. */
		(void)ftruncate(stream.cur_fd, (off_t)stream.cur_written);
		(void)close(stream.cur_fd);
	}
	free(stream.last_mkdir_dir);

	/* Resync before CLOSE: a mid-stream failure (e.g. a refused read that
	 * sent us to cleanup) can leave outstanding READ replies on the wire.
	 * Consume them now - drain_inflight tolerates a server-error STATUS and
	 * keeps draining - so the CLOSE STATUS is not confused with a stray
	 * DATA/STATUS that get_msg would flag as a protocol violation and kill
	 * the worker.  No-op on the normal path (already drained above) and
	 * skipped on a dead connection. */
	if (handle != NULL && !sftp_conn_is_dead(conn))
		(void)bundle_dl_stream_drain_inflight(&stream);

	/* Send CLOSE and consume STATUS reply. */
	if (handle != NULL) {
		u_int close_id;
		if (msg == NULL && (msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		sshbuf_reset(msg);
		close_id = sftp_conn_alloc_msg_id(conn);
		if (sshbuf_put_u8(msg, SSH2_FXP_CLOSE) == 0 &&
		    sshbuf_put_u32(msg, close_id) == 0 &&
		    sshbuf_put_string(msg, handle, handle_len) == 0)
			(void)send_msg(conn, msg);
		sshbuf_reset(msg);
		/* Consume and ignore the CLOSE STATUS reply. */
		(void)get_msg(conn, msg);
		free(handle);
	}
	if (msg != NULL)
		sshbuf_free(msg);
	/*
	 * The pool path flips entries[].result to 0 at enqueue time, before
	 * the writer thread has persisted the file.  On success that is
	 * validated by bundle_write_pool_finish() above (rc stays -1 unless
	 * every queued write succeeded); on ANY failure those optimistic 0s
	 * cannot be trusted - a deferred writer failure would otherwise be
	 * finalized as success and the file silently lost.  Force every entry
	 * back to failed so the worker re-queues the whole batch via the
	 * per-file path (the bundle is all-or-nothing; a re-transfer of the
	 * files that did land is harmless).
	 */
	if (rc != 0) {
		for (i = 0; i < n; i++)
			entries[i].result = -1;
	}
	/* Same cause-scoping as the upload path: dead conn => this worker's
	 * transport failed (keep units bundle-eligible); live conn => server
	 * refused / lacks the extension (permanent single-file fallback). */
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

/* ── BEGIN Phase 5: hpn-bundle upload ──────────────────────────────────────
 *
 * Implements the client side of `hpn-bundle-open@hpnssh.org`.  Many small
 * files are packed into a tar (ustar) byte stream by the hand-rolled tar
 * codec and delivered to the server through a single OPEN, multiple WRITEs,
 * and a CLOSE on the SFTP connection.  Server-side handler (in
 * sftp-hpn-server.c process_hpn_bundle_open) feeds the bytes back through
 * the tar codec to recreate the file tree.
 *
 * Wire format:
 *   client -> server:
 *     SSH_FXP_EXTENDED { id, "hpn-bundle-open@hpnssh.org",
 *                       string dest_dir, uint32 flags }
 *       flags bit 0 = preserve metadata, bit 1 = fsync each file
 *   server -> client:
 *     SSH_FXP_HANDLE { id, opaque handle }   on success
 *     SSH_FXP_STATUS { id, status }          on failure
 *   client -> server: SSH_FXP_WRITE x N with handle, carrying tar bytes
 *   server -> client: SSH_FXP_STATUS x N (one per WRITE)
 *   client -> server: SSH_FXP_CLOSE with handle
 *   server -> client: SSH_FXP_STATUS { id, overall result }
 *
 * Caller must check sftp_conn_has_hpn_bundle() before calling
 * sftp_hpn_bundle_upload.  This function does not transparently fall back.
 */

/* Bundle flag constants (HPN_BUNDLE_FLAG_*) and HPN_BUNDLE_BLOCK_BYTES
 * live in sftp-hpn-bundle.h (included above) - single source of truth
 * shared with the server side. */

/*
 * Hard ceiling on outstanding (unread) STATUS replies.  The adaptive
 * read-ahead controller (sftp_hpn_rdahead_*) drives the *operational*
 * depth - small on LAN (RDAHEAD_FLOOR == 64) growing toward this cap on
 * fat HPC pipes.  This constant serves two roles:
 *   1. Upper bound the controller probes toward (its `cap`).
 *   2. Sizing the per-WRITE size ring buffer (ctx->wsizes) used by
 *      bundle_drain_n to feed accurate byte counts back into the
 *      controller's throughput measurement.
 * Each queued STATUS is ~13 bytes on the wire so 4096 is well under any
 * plausible socket / channel buffer.  When HPN_RDAHEAD=fixed disables
 * adaptation, sftp_hpn_rdahead_cap() returns this fallback and we revert
 * to the legacy flat 4096 pipeline.
 */
#define BUNDLE_MAX_INFLIGHT     4096

/*
 * Drain-stall instrumentation (the 2026-06-05 fleet-freeze investigation).
 * A STATUS read that blocks longer than DRAIN_SLOW_GAP_SEC is "slow"; the
 * recent inter-STATUS gaps are kept in a small ring so a stuck/failed drain
 * can be classified dead (sudden silence after fast acks) vs alive-but-slow
 * (gaps trickling throughout) - the discriminator for fail-fast vs decouple.
 */
#define DRAIN_SLOW_GAP_SEC      0.5
#define DRAIN_GAP_RING          48

/*
 * Context for the tar codec's write path.  WRITEs are pipelined: each
 * callback invocation sends one SSH_FXP_WRITE without blocking on the
 * server's STATUS reply.  STATUSes accumulate in the SSH channel; they
 * are drained in bulk before SSH_FXP_CLOSE.
 *
 * Because rids come from sftp_conn_alloc_msg_id and SFTP replies are
 * returned in request order, we don't need to track each pending rid
 * individually - the rid of drain #k is simply first_rid + k.
 */
struct bundle_write_ctx {
	struct sftp_conn *conn;
	const u_char *handle;
	size_t        handle_len;
	off_t         offset;        /* monotonically increasing */
	int           any_fail;      /* sticky: any WRITE/STATUS failed */
	int           conn_lost;     /* sticky: a genuine transport break (read
				      * error / malformed reply / rid desync), as
				      * opposed to a server refusal (a non-OK
				      * STATUS).  Only a transport break condemns
				      * the connection; a refusal leaves it alive
				      * so the bundle is classified SERVER_CANT
				      * (permanent) rather than respawn-retried. */

	uint64_t      n_sent;        /* WRITEs sent */
	uint64_t      n_drained;     /* STATUS replies successfully drained */
	u_int         first_rid;     /* rid of WRITE #0; valid when n_sent > 0 */

	/*
	 * Ring of per-WRITE byte counts so bundle_drain_n can feed the
	 * exact ack size into sftp_hpn_rdahead_account().  Indexed by
	 * (n_sent % wsizes_cap) on store, (n_drained % wsizes_cap) on read.
	 * Always sized to BUNDLE_MAX_INFLIGHT - the ceiling on inflight
	 * means index reuse is safe.  NULL if allocation failed; the
	 * controller-feed becomes a no-op and we still send/drain correctly.
	 */
	uint32_t     *wsizes;
	uint32_t      wsizes_cap;

	/*
	 * ENV-VAR HPN_BUNDLE_TIMING drain-stall timeline (per-bundle; ctx is
	 * zeroed per upload).  drain_last_ok_s is the monotime of the most
	 * recent good STATUS; drain_gap_ring holds the last DRAIN_GAP_RING
	 * inter-STATUS waits so a stuck drain's shape can be reconstructed.
	 */
	double        drain_last_ok_s;
	double        drain_max_gap_s;
	uint32_t      drain_slow_count;
	uint32_t      drain_gap_n;
	double        drain_gap_ring[DRAIN_GAP_RING];
};

/*
 * Drain up to `n` outstanding WRITE STATUS replies.  Pass SIZE_MAX to
 * drain all of them.  The caller is responsible for not issuing the
 * SSH_FXP_CLOSE before all WRITEs have been drained (otherwise the CLOSE
 * STATUS would be confused with a WRITE STATUS).
 *
 * Two failure classes, kept distinct:
 *   - Server refusal: a well-formed STATUS with a non-OK code (e.g.
 *     PERMISSION_DENIED).  The transport is fine; the server simply said
 *     no.  Sets any_fail, accounts the STATUS, and keeps draining so the
 *     pipeline stays in sync.  conn_lost is NOT set - the connection
 *     survives and the bundle is classified SERVER_CANT (permanent).
 *   - Transport break: a read error, a malformed reply, or a rid desync.
 *     Sets any_fail AND conn_lost and stops; the caller condemns the
 *     connection and the bundle is classified TRANSPORT_FAILED (retry).
 * Returns 0 if every drained STATUS was OK, -1 otherwise.
 */
static int
bundle_drain_n(struct bundle_write_ctx *ctx, size_t n)
{
	struct sshbuf *msg = NULL;
	uint64_t outstanding;
	int r, rc = 0;

	if (ctx->any_fail)
		return -1;
	outstanding = ctx->n_sent - ctx->n_drained;
	if (n > outstanding)
		n = (size_t)outstanding;
	if (n == 0)
		return 0;

	if ((msg = sshbuf_new()) == NULL) {
		ctx->any_fail = 1;
		return -1;
	}
	while (n-- > 0) {
		u_char type;
		u_int status, reply_rid;
		u_int expected_rid =
		    ctx->first_rid + (u_int)ctx->n_drained;
		double t_status_start;

		sshbuf_reset(msg);
		/* Time the STATUS read so the bundle path can also signal
		 * the rdahead controller on a wedge (same mechanism as the
		 * per-file path in sftp-client.c).  Catches the bundle
		 * Pattern 1 stall from the 2026-05-30 campaign when the
		 * controller has already settled high and the path
		 * subsequently backs up. */
		t_status_start = monotime_double();
		if (get_msg(ctx->conn, msg) != 0) {
			/*
			 * Always-on drain-stall record (the fleet-freeze
			 * discriminator).  fail_block is how long THIS final
			 * read blocked before EOF/error; last_ok_age is the
			 * silence since the last good STATUS.  Small gaps then
			 * a long silence => sudden death (dead); large gaps
			 * throughout => alive-but-slow (peer-stall).
			 */
			double now = monotime_double();
			double fail_block = now - t_status_start;
			double last_ok_age = (ctx->drain_last_ok_s > 0.0)
			    ? now - ctx->drain_last_ok_s : fail_block;
			char gaps[512];
			size_t gp = 0;
			uint32_t gi, gstart =
			    (ctx->drain_gap_n > DRAIN_GAP_RING)
			    ? ctx->drain_gap_n - DRAIN_GAP_RING : 0;
			gaps[0] = '\0';
			for (gi = gstart; gi < ctx->drain_gap_n &&
			    gp < sizeof(gaps) - 8; gi++) {
				int w = snprintf(gaps + gp, sizeof(gaps) - gp,
				    "%.2f ",
				    ctx->drain_gap_ring[gi % DRAIN_GAP_RING]);
				if (w < 0)
					break;
				gp += (size_t)w;
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
		{
			double t_now = monotime_double();
			double gap = t_now - t_status_start;
			ctx->drain_gap_ring[ctx->drain_gap_n % DRAIN_GAP_RING]
			    = gap;
			ctx->drain_gap_n++;
			if (gap > ctx->drain_max_gap_s)
				ctx->drain_max_gap_s = gap;
			if (gap > DRAIN_SLOW_GAP_SEC)
				ctx->drain_slow_count++;
			ctx->drain_last_ok_s = t_now;
			if (gap > SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
				sftp_conn_rdahead_backpressure_signal(ctx->conn);
		}
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
		if (reply_rid != expected_rid) {
			error_f("bundle drain: rid mismatch "
			    "(got %u expected %u)", reply_rid, expected_rid);
			ctx->any_fail = 1;
			ctx->conn_lost = 1;
			rc = -1;
			break;
		}
		if (status != SSH2_FX_OK) {
			/*
			 * The server refused this WRITE (e.g. PERMISSION_DENIED
			 * from a -P write policy, a read-only mount, quota, or a
			 * mid-stream ACL denial).  This is an authoritative
			 * per-WRITE refusal, NOT a transport failure: the
			 * connection is healthy and replied in order.  Record
			 * the failure but account the consumed STATUS (advance
			 * n_drained) and keep draining the rest of the pipeline
			 * so it stays in sync - breaking here would strand the
			 * remaining STATUSes and desync the next op.  conn_lost
			 * is deliberately NOT set: leaving the connection alive
			 * makes the caller classify this SERVER_CANT (permanent)
			 * instead of a phantom transport death that respawns and
			 * retries the same doomed WRITE forever.  Log only the
			 * first refusal in this drain to avoid a per-WRITE storm.
			 */
			if (!ctx->any_fail) {
				error_f("bundle drain: WRITE STATUS %u "
				    "(rid=%u) - server refused", status,
				    reply_rid);
				/* HPN: if the server tagged this a -P/-p policy
				 * denial, the caller aborts the whole transfer
				 * rather than re-denying every file. */
				if (status == SSH2_FX_PERMISSION_DENIED)
					sftp_conn_check_policy_tag(ctx->conn,
					    msg);
			}
			ctx->any_fail = 1;
			rc = -1;
			ctx->n_drained++;
			continue;
		}
		ctx->n_drained++;
		/* Feed the adaptive read-ahead controller with the true
		 * size of the just-acked WRITE so its throughput
		 * measurement reflects actual bytes moved, not request
		 * count.  No-op when allocation failed (wsizes == NULL)
		 * or when adaptation is disabled. */
		if (ctx->wsizes != NULL)
			sftp_conn_rdahead_account(ctx->conn,
			    ctx->wsizes[(ctx->n_drained - 1) %
			    ctx->wsizes_cap]);
	}
	sshbuf_free(msg);
	return rc;
}

/*
 * Send one bundle WRITE.  Drives the same adaptive back-pressure gate
 * that the old libarchive callback did, but now driven directly from
 * the codec-pack loop in sftp_hpn_bundle_upload.
 *
 * Returns 0 on success, -1 on transport / OOM error.  Sets
 * ctx->any_fail on any failure.
 */
static int
bundle_ul_send_write(struct bundle_write_ctx *ctx,
    const u_char *buffer, size_t length)
{
	struct sshbuf *msg;
	u_int rid;
	int r;

	if (ctx->any_fail)
		return -1;

	/*
	 * Adaptive back-pressure: cap outstanding WRITEs at the read-ahead
	 * controller's current depth.  Before this gate the bundle path
	 * used a fixed 4096-deep pipeline that filled kernel pipe + TCP
	 * buffers and stalled get_msg waiting on STATUS.  When the cap is
	 * reached we drain half the inflight to keep the pipeline
	 * single-window-deep instead of thrashing on every WRITE.
	 */
	{
		uint32_t cap = sftp_conn_rdahead_cap(ctx->conn,
		    BUNDLE_MAX_INFLIGHT);
		if (cap == 0)
			cap = BUNDLE_MAX_INFLIGHT;
		if ((ctx->n_sent - ctx->n_drained) >= cap) {
			size_t drain_n = cap / 2;
			if (drain_n == 0)
				drain_n = 1;
			if (bundle_drain_n(ctx, drain_n) < 0) {
				error_f("bundle drain: server status failure");
				ctx->any_fail = 1;
				return -1;
			}
		}
	}

	if ((msg = sshbuf_new()) == NULL) {
		ctx->any_fail = 1;
		return -1;
	}

	rid = sftp_conn_alloc_msg_id(ctx->conn);
	if (ctx->n_sent == 0)
		ctx->first_rid = rid;
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
	if (ctx->wsizes != NULL)
		ctx->wsizes[ctx->n_sent % ctx->wsizes_cap] = (uint32_t)length;
	send_msg(ctx->conn, msg);
	sshbuf_free(msg);

	ctx->n_sent++;
	ctx->offset += (off_t)length;
	return 0;
}

int
sftp_hpn_bundle_upload(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_hpn_bundle_upload_entry *entries, int n,
    int preserve_flag, int fsync_flag, int writer_pool, uint64_t bundle_size)
{
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t handle_len = 0;
	u_int open_id;
	u_int flags;
	struct sftp_hpn_tar_writer *writer = NULL;
	struct bundle_write_ctx ctx = { 0 };
	u_char  outbuf[HPN_BUNDLE_BLOCK_BYTES];  /* per-WRITE payload buf */
	int i, r;
	int rc = -1;   /* generic failure; reclassified to SERVER_CANT vs
			* TRANSPORT_FAILED at cleanup.  0 = success (OK). */
	/* ENV-VAR HPN_BUNDLE_TIMING per-bundle timing breakdown (seconds). */
	double t_enter = 0, t_open_done = 0, t_send_start = 0;
	double t_send_done = 0, t_drain_done = 0, t_close_done = 0;
	uint64_t bytes_total = 0;
	int files_queued = 0;

	for (i = 0; i < n; i++)
		entries[i].result = -1;   /* pessimistic; flip to 0 on success */

	if (n <= 0)
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

	/* HPN: scope the policy-denied signal to this bundle attempt. */
	sftp_conn_clear_policy_denied(conn);

	debug_f("hpn-bundle upload: n=%d dest=\"%s\" preserve=%d fsync=%d",
	    n, remote_dest_dir, preserve_flag, fsync_flag);
	t_enter = monotime_double();

	/* ── Send hpn-bundle-open@hpnssh.org and collect HANDLE ─────────── */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	open_id = sftp_conn_alloc_msg_id(conn);
	flags = (preserve_flag ? HPN_BUNDLE_FLAG_PRESERVE : 0)
	      | (fsync_flag    ? HPN_BUNDLE_FLAG_FSYNC    : 0)
	      | (writer_pool   ? 0 : HPN_BUNDLE_FLAG_NO_POOL);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, open_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hpn-bundle-open@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_cstring(msg, remote_dest_dir)) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0 ||
	    (r = sshbuf_put_u64(msg, bundle_size)) != 0)
		fatal_fr(r, "compose hpn-bundle-open");
	send_msg(conn, msg);
	sshbuf_reset(msg);

	/* The base dir is often empty (entries carry their own paths), so a
	 * "%s" would render as hpn-bundle-open "": describe the batch by file
	 * count instead, which is always meaningful. */
	handle = get_handle(conn, open_id, &handle_len,
	    "hpn-bundle-open (%d files)", n);
	if (handle == NULL) {
		debug_f("hpn-bundle: server refused open");
		goto cleanup;
	}
	t_open_done = monotime_double();

	/* ── Build the tar writer ────────────────────────────────────────── */
	ctx.conn       = conn;
	ctx.handle     = handle;
	ctx.handle_len = handle_len;

	writer = sftp_hpn_tar_writer_new();
	if (writer == NULL) {
		error_f("sftp_hpn_tar_writer_new failed");
		goto cleanup;
	}

	/* Queue every requested entry.  Per-entry stat() failures are
	 * logged + skipped (matching the pre-codec behaviour); the
	 * writer pulls bytes lazily from disk when pack_next reaches the
	 * entry's DATA state, so we don't open() files until needed. */
	for (i = 0; i < n; i++) {
		struct stat sb;
		mode_t      perm;
		time_t      mtime;

		if (entries[i].local_path == NULL ||
		    entries[i].remote_path == NULL)
			continue;
		/* (F) skip stat if the walker already provided size+mtime -
		 * not currently in the entry struct, so stat() until that
		 * field gets added.  TODO: extend the entry struct. */
		if (stat(entries[i].local_path, &sb) < 0) {
			error("hpn-bundle: stat local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			continue;
		}
		if (!S_ISREG(sb.st_mode)) {
			debug_f("hpn-bundle: \"%s\" not regular, skip",
			    entries[i].local_path);
			continue;
		}
		perm  = preserve_flag ? (sb.st_mode & 07777) : 0644;
		mtime = preserve_flag ? sb.st_mtime          : time(NULL);
		if (sftp_hpn_tar_writer_add_file(writer,
		    entries[i].local_path, entries[i].remote_path,
		    perm, (uint64_t)sb.st_size, mtime) < 0) {
			error_f("hpn-bundle: writer_add_file \"%s\" "
			    "rejected (path too long?)",
			    entries[i].remote_path);
			continue;
		}
		entries[i].result = 0;	/* mark queued; flipped back to -1
					 * if a later pack/drain fails */
		files_queued++;
	}
	sftp_hpn_tar_writer_finish(writer);

	/* ── Pack/send loop ─────────────────────────────────────────────── */
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
			break;	/* EOA reached - all bytes sent */
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
	if (ctx.any_fail) {
		debug_f("hpn-bundle: WRITE phase reported failure");
		goto cleanup;
	}
	t_drain_done = monotime_double();

	/* ── Close the bundle handle, collect overall STATUS ────────────── */
	{
		u_int close_id = sftp_conn_alloc_msg_id(conn);
		u_char type;
		u_int status, reply_rid;

		sshbuf_reset(msg);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
		    (r = sshbuf_put_u32(msg, close_id)) != 0 ||
		    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
			fatal_fr(r, "compose bundle CLOSE");
		send_msg(conn, msg);
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
	}

	t_close_done = monotime_double();
	if (getenv("HPN_BUNDLE_TIMING") != NULL) {
		uint32_t cap_final =
		    sftp_conn_rdahead_cap(conn, BUNDLE_MAX_INFLIGHT);
		/*
		 * ENV-VAR HPN_BUNDLE_TIMING: developer-only per-bundle timing
		 * breakdown.  `enter` is absolute monotonic seconds, so the
		 * inter-bundle idle for a given worker (conn) in post-
		 * processing is enter[k+1] - (enter[k] + total[k]).  open/
		 * drain/close are the three serialized RTT-bound handshakes;
		 * send is the data phase (includes any mid-bundle drains).
		 * Never required for normal operation.
		 */
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

	rc = 0;   /* success - entries[].result already set to 0 above */

 cleanup:
	/* If we sent WRITEs but bailed before draining, consume the
	 * matching STATUSes so the next op on this conn doesn't read
	 * them as its own reply.  A non-OK STATUS encountered here is a
	 * server refusal, not a transport break, so it does NOT condemn
	 * the connection - only a genuine transport loss does.  conn_lost
	 * (set inside bundle_drain_n on a read error / malformed reply /
	 * rid desync) is the authoritative "transport actually broke"
	 * signal, so gate sftp_conn_set_dead on it rather than on the
	 * drain's -1 (which also fires on a plain refusal). */
	if (rc != 0 && ctx.n_sent > ctx.n_drained) {
		int saved_fail = ctx.any_fail;
		ctx.any_fail = 0;
		(void)bundle_drain_n(&ctx, SIZE_MAX);
		ctx.any_fail = saved_fail;
	}
	if (rc != 0 && ctx.conn_lost)
		sftp_conn_set_dead(conn);
	if (rc != 0) {
		for (i = 0; i < n; i++)
			entries[i].result = -1;
	}
	if (writer != NULL)
		sftp_hpn_tar_writer_free(writer);
	free(handle);
	free(ctx.wsizes);
	if (msg != NULL)
		sshbuf_free(msg);
	/*
	 * Classify the failure for the caller's bundle-eligibility decision.
	 * Done here (after the cleanup re-drain may have marked the conn dead)
	 * so it reflects the final connection state: a dead conn means THIS
	 * worker's transport died mid-bundle (the units bundle fine on a
	 * healthy worker - keep them eligible); a live conn means the server
	 * refused / lacks the extension (permanent - mark ineligible).
	 */
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

/* ── END Phase 5 ───────────────────────────────────────────────────────── */
