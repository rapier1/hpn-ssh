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
 * sftp-hpn-bundle-server.c - server-side SFTP bundle protocol.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Extracted from sftp-hpn-server.c on 2026-05-31 as part of the
 * structural refactor described in project_hpn_code_organization_vision.md.
 *
 * Contents:
 *   - struct hpn_bundle_state + lifecycle (UPLOAD parser-driven,
 *     FETCH writer-driven)
 *   - Env-driven enable toggle (HPN_USE_BUNDLE from sshd-session)
 *   - Parser callbacks (entry_cb opens output fd + (D) mkdir cache +
 *     (E) fallocate; data_cb writes inline; entry_end_cb closes +
 *     applies metadata)
 *   - sftp_hpn_server_bundle_write / _read / _close handlers
 *   - sftp_hpn_server_is_bundle_handle / _enabled accessors
 *   - process_hpn_bundle_open / _fetch RPC handlers (called via the
 *     dispatcher in sftp-hpn-server.c)
 *
 * Cross-file linkage:
 *   - handle_new_bundle / _get / _free / _is_bundle are extern functions
 *     implemented in sftp-server.c (handle table internals).
 *   - sftp-hpn-tar.h provides the streaming codec (parser + writer).
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"		/* mkdir_p */
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-bundle.h"	/* HPN_BUNDLE_FLAG_* */
#include "sftp-hpn-server.h"	/* public accessor prototypes + ext names */
#include "sftp-hpn-bundle-server.h"
#include "sftp-hpn-tar.h"
#include "sftp-hpn-bundle-pool.h"	/* shared writer pool (extract overlap) */

/* Bundle handle mode: upload (client streams WRITE-by-WRITE, server
 * extracts at close) vs. fetch (server packs tar up-front, client
 * drains via READ, close just releases). */
enum hpn_bundle_mode {
	HPN_BUNDLE_MODE_UPLOAD = 0,   /* hpn-bundle-open */
	HPN_BUNDLE_MODE_FETCH  = 1,   /* hpn-bundle-fetch */
};

/* ── Bundle handle state (codec-based) ──────────────────────────────────
 *
 * Both UPLOAD and FETCH bundles stream through the sftp-hpn-tar codec
 * instead of buffering the whole tar in RAM.  Memory per worker is
 * O(1) - just the codec's 512-byte header scratch + the currently-open
 * output file (UPLOAD) or the currently-reading input file (FETCH).
 *
 * UPLOAD path (hpn-bundle-open):
 *   bundle_state holds a parser + per-entry tracking (open fd, remaining
 *   bytes, mode/mtime, last-mkdir cache for dir pre-create optimisation).
 *   sftp_hpn_server_bundle_write feeds the parser; entry callbacks open
 *   the output file, write bytes, then close + apply metadata.
 *
 * FETCH path (hpn-bundle-fetch):
 *   bundle_state holds a writer with all paths queued (finish() called
 *   at OPEN time).  sftp_hpn_server_bundle_read drives pack_next() to
 *   produce bytes on demand into the SFTP DATA reply. */

struct hpn_bundle_state {
	enum hpn_bundle_mode mode;
	char    *dest_dir;          /* UPLOAD: dir to extract into; FETCH: NULL */
	uint32_t flags;             /* HPN_BUNDLE_FLAG_*, see sftp-hpn-bundle.h */

	/* UPLOAD-mode fields. */
	struct sftp_hpn_tar_parser *parser;
	uint64_t bytes_received;    /* cumulative WRITE bytes fed to parser */
	uint64_t next_write_off;    /* expected SSH_FXP_WRITE offset */
	/* Per-entry state set by the parser callbacks. */
	char    *cur_full_path;     /* malloc'd dest_dir + "/" + entry path */
	int      cur_fd;            /* open output fd, or -1 */
	uint64_t cur_size;          /* declared size from header */
	mode_t   cur_mode;
	time_t   cur_mtime;
	char    *last_mkdir_dir;    /* last parent dir already mkdir_p'd (D) */

	/* Parallel writer pool (NULL = serial inline writes; set when the pool
	 * is enabled - on by default, unless the operator disabled it via
	 * HPNWriterPool or the client sent HPN_BUNDLE_FLAG_NO_POOL).  When
	 * active the parser callbacks buffer each file and hand a complete-file
	 * job to the pool, so the per-file open/write/close (Lustre MDS
	 * round-trips) overlap. */
	struct bundle_write_pool *pool;
	u_char  *cur_job_buf;       /* pool: current file's data buffer */
	size_t   cur_job_filled;    /* pool: bytes accumulated so far */

	/* FETCH-mode fields. */
	struct sftp_hpn_tar_writer *writer;
	uint64_t bytes_produced;    /* cumulative pack_next bytes returned */
	uint64_t next_read_off;     /* expected SSH_FXP_READ offset */
	uint64_t fetch_total_size;  /* sum of declared file sizes (logged) */
};

/* Flag constants and HPN_BUNDLE_BLOCK_BYTES live in sftp-hpn-bundle.h, the
 * shared HPN-only header.  Single source of truth for client + server. */

/*
 * Operator master toggle (sshd_config: HPNUseBundle).  When 0, the
 * server omits the hpn-bundle* extensions from SSH_FXP_VERSION and
 * refuses bundle-open / bundle-fetch with SSH2_FX_OP_UNSUPPORTED.
 * Read from the HPN_USE_BUNDLE env var that sshd-session sets from
 * options.hpn_use_bundle.  Defaults to 1 when the env var is absent
 * or unparseable (preserves prior behaviour for callers that haven't
 * propagated the option).
 *
 * Cached after the first lookup so the hot path is a simple read.
 */
static int    bundle_enabled    = -1;   /* -1 = uninitialised */

/*
 * Compose and enqueue an SSH_FXP_STATUS failure reply on oqueue.
 * Shared by the fail labels of process_hpn_bundle_open and
 * process_hpn_bundle_fetch - both handlers reply with the same
 * 5-field STATUS shape on error (only the error-tag string differs,
 * which we pass through for the fatal_fr() log line).
 */
static void
bundle_send_status_failure(struct sshbuf *oqueue, u_int id, int status,
    const char *tag)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, (u_int)status)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose %s", tag);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue %s", tag);
	sshbuf_free(msg);
}

/* HPN operator toggles parsed from argv (-B / -O) in sftp-server.c. */
extern int    sftp_server_hpn_use_bundle(void);
extern int    sftp_server_hpn_writer_pool(void);

static void
bundle_enabled_init(void)
{
	static int initialised = 0;

	if (initialised)
		return;

	/* Operator master toggle (sshd_config: HPNUseBundle), handed to this
	 * process by sshd via the -B argv flag (see sftp_server_hpn_use_bundle
	 * in sftp-server.c).  Defaults to 1 (enabled) when not specified. */
	if (bundle_enabled == -1)
		bundle_enabled = sftp_server_hpn_use_bundle();

	initialised = 1;
	debug_f("hpn-bundle: enabled=%d", bundle_enabled);
}

/* These callbacks live in sftp-server.c so this module doesn't need
 * to know about the handle table internals. */
extern int    handle_new_bundle(void *opaque);
extern void  *handle_get_bundle(int handle);
extern void   handle_free_bundle(int handle);
extern int    handle_is_bundle(int handle);

/* Forward declarations for parser callbacks (defined below) and the
 * path-safety check (defined later in the file). */
static int bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime);
static int bundle_upload_data_cb(void *ctx, const u_char *data, size_t len);
static int bundle_upload_entry_end_cb(void *ctx);
static int bundle_path_is_safe(const char *p, const char *dest_dir);

static const struct sftp_hpn_tar_callbacks bundle_upload_callbacks = {
	.entry_cb     = bundle_upload_entry_cb,
	.data_cb      = bundle_upload_data_cb,
	.entry_end_cb = bundle_upload_entry_end_cb,
};

/* HPN_WRITER_POOL (sshd_config: HPNWriterPool) - operator master toggle for
 * the server-side bundle writer pool.  Absent/unparseable -> 1 (enabled).
 * Mirrors the HPN_USE_BUNDLE toggle; cached after the first lookup. */
static int
bundle_writer_pool_allowed(void)
{
	static int  cached = -1;

	if (cached >= 0)
		return cached;
	/* Operator master toggle (sshd_config: HPNWriterPool), handed in by
	 * sshd via the -O argv flag (see sftp_server_hpn_writer_pool). */
	cached = sftp_server_hpn_writer_pool();
	return cached;
}

static struct hpn_bundle_state *
bundle_state_new(const char *dest_dir, uint32_t flags, uint64_t bundle_size)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->mode     = HPN_BUNDLE_MODE_UPLOAD;
	s->dest_dir = strdup(dest_dir);
	if (s->dest_dir == NULL) {
		free(s);
		return NULL;
	}
	s->flags  = flags;
	s->cur_fd = -1;
	s->parser = sftp_hpn_tar_parser_new(&bundle_upload_callbacks, s);
	if (s->parser == NULL) {
		free(s->dest_dir);
		free(s);
		return NULL;
	}
	/* Writer pool: on by default, unless the operator disabled it
	 * (sshd_config HPNWriterPool no -> HPN_WRITER_POOL env) or the client
	 * asked us to skip it (HPN_BUNDLE_FLAG_NO_POOL).  Operator-off wins. */
	if (bundle_writer_pool_allowed() &&
	    (flags & HPN_BUNDLE_FLAG_NO_POOL) == 0) {
		uint64_t budget = bundle_writer_budget();
		s->pool = bundle_write_pool_new(bundle_writer_threads(),
		    (flags & HPN_BUNDLE_FLAG_PRESERVE) != 0,
		    (flags & HPN_BUNDLE_FLAG_FSYNC) != 0, budget);
		if (s->pool != NULL)
			debug_f("hpn-bundle: writer pool active (%d threads, "
			    "%llu-byte budget)", bundle_writer_threads(),
			    (unsigned long long)budget);
		/* NULL = pool spawn failed; fall back to serial, harmless. */
	}
	return s;
}

/* Fetch-mode counterpart: no dest_dir (server-side reads, doesn't extract),
 * writer is allocated empty; the fetch handler queues paths into it
 * and calls finish() before installing the handle. */
static struct hpn_bundle_state *
bundle_state_new_fetch(uint32_t flags)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->mode   = HPN_BUNDLE_MODE_FETCH;
	s->flags  = flags;
	s->cur_fd = -1;
	s->writer = sftp_hpn_tar_writer_new();
	if (s->writer == NULL) {
		free(s);
		return NULL;
	}
	return s;
}

static void
bundle_state_free(struct hpn_bundle_state *s)
{
	if (s == NULL)
		return;
	if (s->pool != NULL)		/* abnormal teardown: join + free pool */
		(void)bundle_write_pool_finish(s->pool);
	free(s->cur_job_buf);
	if (s->cur_fd >= 0)
		(void)close(s->cur_fd);
	free(s->cur_full_path);
	free(s->last_mkdir_dir);
	if (s->parser != NULL)
		sftp_hpn_tar_parser_free(s->parser);
	if (s->writer != NULL)
		sftp_hpn_tar_writer_free(s->writer);
	free(s->dest_dir);
	free(s);
}

int
sftp_hpn_server_is_bundle_handle(int handle)
{
	return handle_is_bundle(handle);
}

int
sftp_hpn_server_bundle_enabled(void)
{
	bundle_enabled_init();	/* ensures bundle_enabled is populated */
	return bundle_enabled;
}

/* Compose the full destination path for one tar entry.  Returns a
 * malloc'd string on success or NULL on OOM / unsafe path.  *out_safe
 * is set to 0 (unsafe path; caller fails the bundle) or 1 (OK). */
static char *
bundle_compose_path(const char *dest_dir, const char *entry_path, int *out_safe)
{
	char *full;

	*out_safe = 0;
	if (!bundle_path_is_safe(entry_path, dest_dir))
		return NULL;
	if (*dest_dir == '\0') {
		full = strdup(entry_path);
	} else {
		size_t full_len = strlen(dest_dir) + 1 +
		    strlen(entry_path) + 1;
		full = malloc(full_len);
		if (full != NULL)
			snprintf(full, full_len, "%s/%s",
			    dest_dir, entry_path);
	}
	if (full == NULL)
		return NULL;
	*out_safe = 1;
	return full;
}

/* Parser entry callback: header parsed, open output fd, mkdir parent.
 *
 * The "last-mkdir-dir" cache (D) skips redundant mkdir_p calls when many
 * consecutive entries share the same parent directory - the common case
 * for many-small bundles.  Without it every file in a 1000-file bundle
 * does its own dirname() + stat() + mkdir() walk; with it most calls
 * are a single strcmp. */
static int
bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime)
{
	struct hpn_bundle_state *s = ctx;
	int    safe;
	int    preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;

	s->cur_full_path = bundle_compose_path(s->dest_dir, path, &safe);
	if (!safe) {
		error("hpn-bundle: REJECTED unsafe tar pathname \"%s\" "
		    "(\"..\" component, or absolute path with non-empty "
		    "dest_dir); possible path-traversal attempt", path);
		return -1;
	}
	if (s->cur_full_path == NULL) {
		error_f("hpn-bundle: out of memory composing path");
		return -1;
	}
	/* Pre-create parent directory.  Skip if last_mkdir_dir matches. */
	{
		char *full_copy = strdup(s->cur_full_path);
		if (full_copy != NULL) {
			char *parent = dirname(full_copy);
			if (parent != NULL && strcmp(parent, ".") != 0 &&
			    strcmp(parent, "/") != 0) {
				if (s->last_mkdir_dir == NULL ||
				    strcmp(s->last_mkdir_dir, parent) != 0) {
					(void)mkdir_p(parent, 0755);
					free(s->last_mkdir_dir);
					s->last_mkdir_dir = strdup(parent);
				}
			}
			free(full_copy);
		}
	}

	if (s->pool != NULL) {
		/* Parallel path: buffer this file; a pool thread does the
		 * open/write/close so the per-file MDS round-trips overlap.
		 * The parent dir was already mkdir'd above (serial, cached). */
		s->cur_size  = size;
		s->cur_mode  = mode;
		s->cur_mtime = mtime;
		s->cur_job_buf = (size > 0) ? malloc((size_t)size) : NULL;
		s->cur_job_filled = 0;
		if (size > 0 && s->cur_job_buf == NULL) {
			error_f("hpn-bundle: malloc(%llu) for \"%s\"",
			    (unsigned long long)size, s->cur_full_path);
			return -1;
		}
		return 0;
	}

	mode_t perm = preserve ? (mode & 07777) : 0644;
	/*
	 * HPN bundle-truncation fix (#4): open WITHOUT O_TRUNC.  A connection
	 * that dies mid-bundle leaves a lagging server still draining buffered
	 * tar; an O_TRUNC open by that dead writer would truncate the file the
	 * re-send has already written.  Without O_TRUNC the dead writer can only
	 * overwrite a prefix with identical bytes and can never shrink the file;
	 * the authoritative size is set by ftruncate() in entry_end_cb, which
	 * only a writer that COMPLETES the entry reaches.
	 */
	s->cur_fd = open(s->cur_full_path, O_WRONLY | O_CREAT, perm);
	if (s->cur_fd < 0) {
		error_f("hpn-bundle: open \"%s\": %s",
		    s->cur_full_path, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* (E) Pre-allocate extents for fewer fragments + faster sequential
	 * writes on extents-based FS (ext4 / xfs / lustre).  Failure is
	 * non-fatal - write() will just allocate on demand. */
	if (size > 0)
		(void)posix_fallocate(s->cur_fd, 0, (off_t)size);
#endif
	s->cur_size  = size;
	s->cur_mode  = mode;
	s->cur_mtime = mtime;
	return 0;
}

static int
bundle_upload_data_cb(void *ctx, const u_char *data, size_t len)
{
	struct hpn_bundle_state *s = ctx;
	size_t remaining;

	if (s->pool != NULL) {
		/* Parallel path: accumulate into the per-file buffer; the pool
		 * thread writes it once the entry completes. */
		/* Defense-in-depth: the parser already clamps delivered data to
		 * the declared entry size, but bound the memcpy locally too so a
		 * parser regression cannot overflow the cur_size-sized buffer.
		 * Written as a subtraction to avoid overflow in the check itself
		 * (cur_job_filled <= cur_size is the maintained invariant). */
		if (len > (size_t)s->cur_size - s->cur_job_filled) {
			error_f("bundle entry data exceeds declared size %llu",
			    (unsigned long long)s->cur_size);
			return -1;
		}
		if (s->cur_job_buf != NULL && len > 0)
			memcpy(s->cur_job_buf + s->cur_job_filled, data, len);
		s->cur_job_filled += len;
		s->bytes_received += (uint64_t)len;
		return 0;
	}

	remaining = len;
	if (s->cur_fd < 0)
		return -1;	/* shouldn't happen - parser always pairs */
	while (remaining > 0) {
		ssize_t n = write(s->cur_fd, data, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			error_f("hpn-bundle: write \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			return -1;
		}
		data      += n;
		remaining -= (size_t)n;
	}
	s->bytes_received += (uint64_t)len;
	return 0;
}

static int
bundle_upload_entry_end_cb(void *ctx)
{
	struct hpn_bundle_state *s = ctx;
	int preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (s->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;
	int rc       = 0;

	if (s->pool != NULL) {
		/* Parallel path: hand the complete file to the writer pool. */
		struct bundle_write_job *job = calloc(1, sizeof(*job));
		if (job == NULL) {
			error_f("hpn-bundle: write-job alloc failed");
			free(s->cur_job_buf);   s->cur_job_buf   = NULL;
			free(s->cur_full_path); s->cur_full_path = NULL;
			return -1;
		}
		job->full_path = s->cur_full_path;	/* transfer ownership */
		job->mode      = s->cur_mode;
		job->mtime     = s->cur_mtime;
		job->data      = s->cur_job_buf;	/* transfer ownership */
		job->len       = (size_t)s->cur_size;
		s->cur_full_path = NULL;
		s->cur_job_buf   = NULL;
		if (bundle_pool_enqueue(s->pool, job) != 0) {
			free(job->full_path);
			free(job->data);
			free(job);
			return -1;	/* a writer already failed; bail */
		}
		return 0;
	}

	if (s->cur_fd >= 0) {
		if (preserve) {
			struct timespec ts[2];
			/* Exact mode: open(O_CREAT, perm) is subject to umask
			 * and is ignored entirely on a pre-existing file, so
			 * force the bits here to match real SFTP -p. */
			(void)fchmod(s->cur_fd, (mode_t)(s->cur_mode & 07777));
			ts[0].tv_sec = s->cur_mtime; ts[0].tv_nsec = 0;
			ts[1].tv_sec = s->cur_mtime; ts[1].tv_nsec = 0;
			(void)futimens(s->cur_fd, ts);
		}
		/*
		 * HPN bundle-truncation fix (#4): set the authoritative file size
		 * here, at entry completion (replaces the open-time O_TRUNC dropped
		 * in bundle_upload_entry_cb).  Only a writer that finished the entry
		 * reaches this point, so a dead connection's abandoned partial never
		 * shrinks the file; also clears any stale tail left when overwriting
		 * a larger pre-existing file.
		 */
		if (ftruncate(s->cur_fd, (off_t)s->cur_size) != 0) {
			error_f("hpn-bundle: ftruncate \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			rc = -1;
		}
		if (do_fsync && fsync(s->cur_fd) != 0) {
			error_f("hpn-bundle: fsync \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			rc = -1;
		}
		if (close(s->cur_fd) != 0) {
			error_f("hpn-bundle: close \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			rc = -1;
		}
		s->cur_fd = -1;
	}
	free(s->cur_full_path);
	s->cur_full_path = NULL;
	s->cur_size = 0;
	return rc;
}

int
sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;
	if (s->mode != HPN_BUNDLE_MODE_UPLOAD) {
		error_f("hpn-bundle: WRITE on non-upload bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
	/* Client writes monotonically; reject gaps or overlaps. */
	if (off != s->next_write_off) {
		error_f("hpn-bundle write offset mismatch: got %llu "
		    "have %llu",
		    (unsigned long long)off,
		    (unsigned long long)s->next_write_off);
		return SSH2_FX_FAILURE;
	}
	if (s->parser == NULL)
		return SSH2_FX_FAILURE;
	/* Feed bytes straight to the parser; entry callbacks open files
	 * and write data inline (no accumulator).  Streaming preserves
	 * O(1) per-worker memory regardless of bundle size. */
	int pr = sftp_hpn_tar_parser_feed(s->parser, data, len);
	if (pr < 0) {
		error_f("hpn-bundle WRITE: parser error: %s",
		    sftp_hpn_tar_parser_error(s->parser));
		return SSH2_FX_FAILURE;
	}
	s->next_write_off += len;
	return SSH2_FX_OK;
}

int
sftp_hpn_server_bundle_read(int handle, uint64_t off, u_char *out_buf,
    size_t len, size_t *out_len)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL || out_buf == NULL || out_len == NULL)
		return SSH2_FX_FAILURE;
	if (s->mode != HPN_BUNDLE_MODE_FETCH) {
		error_f("hpn-bundle: READ on non-fetch bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
	if (s->writer == NULL) {
		*out_len = 0;
		return SSH2_FX_EOF;
	}
	/* SFTP READs arrive in offset order on a single channel.  Reject
	 * backward seeks loudly - streaming codec can't replay produced
	 * bytes.  Forward "gaps" (off > bytes_produced) are silently
	 * absorbed: they happen naturally when a previous read returned
	 * fewer than CHUNK_BYTES because the bundle ended mid-chunk.  The
	 * client fires each read at fixed chunk_index × CHUNK_BYTES, so
	 * once one read is short, every subsequent read has off >
	 * bytes_produced.  We just produce whatever's left (probably 0,
	 * past the EOA marker) and return EOF.  Without this graceful
	 * absorbtion the client's drain-of-orphan-reads sees STATUS
	 * FAILURE replies, bails the drain, and the next bundle's READs
	 * collide with leftover orphan replies on the wire - surfacing as
	 * "ID mismatch" sftp_conn_die calls and worker abort. */
	if (off < s->bytes_produced) {
		error_f("hpn-bundle READ: backward seek %llu (next %llu)",
		    (unsigned long long)off,
		    (unsigned long long)s->bytes_produced);
		return SSH2_FX_FAILURE;
	}

	/* Fill up to `len` bytes by looping pack_next.  Returns 0 when
	 * EOA has been emitted and no more bytes will follow. */
	size_t produced = 0;
	while (produced < len) {
		ssize_t n = sftp_hpn_tar_writer_pack_next(s->writer,
		    out_buf + produced, len - produced);
		if (n < 0) {
			error_f("hpn-bundle READ: writer error: %s",
			    sftp_hpn_tar_writer_error(s->writer));
			return SSH2_FX_FAILURE;
		}
		if (n == 0)
			break;	/* EOA */
		produced += (size_t)n;
	}
	*out_len = produced;
	s->bytes_produced += produced;
	if (produced == 0)
		return SSH2_FX_EOF;
	return SSH2_FX_OK;
}

/*
 * Validate a tar entry pathname before composing it into a destination
 * path.  Rejects:
 *   - NULL or empty
 *   - any "/"-separated component equal to ".." (traversal - always
 *     anomalous for a bundle producer; plain SFTP OPEN never has
 *     reason to encode a "../" climb in a single pathname)
 *   - leading "/" ONLY when dest_dir is non-empty.  When dest_dir is
 *     empty the protocol explicitly delegates path interpretation to
 *     the server's standard SFTP path-resolution (mirroring plain
 *     SFTP OPEN semantics, including absolute paths the user has
 *     permission to write); when dest_dir is non-empty an absolute
 *     pathname composed as "dest_dir/" + "/abs/path" produces weird
 *     semantics that the protocol never intends.
 *
 * Returns 1 if the pathname is safe to extract under the given
 * dest_dir, 0 if it must be rejected.
 */
static int
bundle_path_is_safe(const char *p, const char *dest_dir)
{
	const char *start, *q;

	if (p == NULL || *p == '\0')
		return 0;
	if (*p == '/' && dest_dir != NULL && *dest_dir != '\0')
		return 0;
	start = p;
	for (q = p; ; q++) {
		if (*q == '/' || *q == '\0') {
			size_t len = (size_t)(q - start);
			if (len == 2 && start[0] == '.' && start[1] == '.')
				return 0;
			if (*q == '\0')
				break;
			start = q + 1;
		}
	}
	return 1;
}

int
sftp_hpn_server_bundle_close(int handle, u_int id, struct sshbuf *oqueue)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;

	/* Fetch-mode handles already finished their server-side work in the
	 * hpn-bundle-fetch handler (queued paths + finish()).  Close is just
	 * a resource release; the writer's destructor closes any open input
	 * file and discards the queue. */
	if (s->mode == HPN_BUNDLE_MODE_FETCH) {
		debug_f("hpn-bundle close (fetch): handle=%d produced=%llu",
		    handle, (unsigned long long)s->bytes_produced);
		bundle_state_free(s);
		handle_free_bundle(handle);
		return SSH2_FX_OK;
	}

	/* UPLOAD: streaming extract already happened during the WRITE
	 * sequence.  All that remains is to verify the parser reached EOA
	 * (signalled by the trailing two zero blocks) and release the
	 * state.  If the parser hasn't seen EOA we accept that as success
	 * (matches the prior libarchive behaviour where an empty / partial
	 * stream simply produced no extracted files) but log it. */
	int status = SSH2_FX_OK;
	int preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (s->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;

	debug_f("hpn-bundle close: handle=%d dest=\"%s\" received=%llu "
	    "preserve=%d fsync=%d",
	    handle, s->dest_dir,
	    (unsigned long long)s->bytes_received, preserve, do_fsync);

	const char *perr = sftp_hpn_tar_parser_error(s->parser);
	if (perr != NULL) {
		error_f("hpn-bundle close: parser error: %s", perr);
		status = SSH2_FX_FAILURE;
	}

	/* Drain + join the writer pool (if active) before replying, so every
	 * file is on disk and any write error is reflected in the status (and
	 * a post-transfer verify reads back fully-written files). */
	if (s->pool != NULL) {
		if (bundle_write_pool_finish(s->pool) != 0)
			status = SSH2_FX_FAILURE;
		s->pool = NULL;
	}

	bundle_state_free(s);
	handle_free_bundle(handle);
	return status;
}

/*
 * Process the hpn-bundle-open@hpnssh.org extended request.
 * Allocates a bundle handle and replies with SSH_FXP_HANDLE.
 * On error replies with SSH_FXP_STATUS / SSH2_FX_FAILURE.
 */
void
process_hpn_bundle_open(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *dest_dir = NULL;
	uint32_t flags = 0;
	uint64_t bundle_size = 0;
	struct sshbuf *msg = NULL;
	struct hpn_bundle_state *s = NULL;
	int handle = -1;
	int r, status = SSH2_FX_FAILURE;

	/* Operator master toggle: refuse bundle ops with OP_UNSUPPORTED
	 * when sshd_config has HPNUseBundle=no.  Belt-and-suspenders -
	 * the extension is normally not advertised in that mode, but a
	 * misbehaving client could still send a bundle-open. */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-open refused: HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}

	if ((r = sshbuf_get_cstring(iqueue, &dest_dir, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &bundle_size)) != 0) {
		error_f("parse hpn-bundle-open: %s", ssh_err(r));
		goto fail;
	}
	debug3("request %u: hpn-bundle-open dest=\"%s\" flags=0x%x bundle=%llu",
	    id, dest_dir, flags, (unsigned long long)bundle_size);

	/* Make sure the destination directory exists (mkdir -p semantics).
	 * Don't fail if it already exists.  Empty dest_dir means the client
	 * is supplying absolute (or otherwise pre-rooted) per-record paths;
	 * the per-entry extract loop handles parent-directory creation on
	 * each record, so the up-front mkdir is unnecessary in that case. */
	if (*dest_dir != '\0' &&
	    mkdir_p(dest_dir, 0755) != 0 && errno != EEXIST) {
		error_f("hpn-bundle-open: mkdir_p \"%s\": %s",
		    dest_dir, strerror(errno));
		status = errno == ENOENT ? SSH2_FX_NO_SUCH_FILE
		       : errno == EACCES ? SSH2_FX_PERMISSION_DENIED
		       :                   SSH2_FX_FAILURE;
		goto fail;
	}

	s = bundle_state_new(dest_dir, flags, bundle_size);
	if (s == NULL) {
		status = SSH2_FX_FAILURE;
		goto fail;
	}

	handle = handle_new_bundle(s);
	if (handle < 0) {
		error_f("hpn-bundle-open: handle table full");
		bundle_state_free(s);
		status = SSH2_FX_FAILURE;
		goto fail;
	}

	/* Reply with SSH_FXP_HANDLE - standard SFTP framing. */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	u_char hbuf[sizeof(int32_t)];
	put_u32(hbuf, (uint32_t)handle);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
		fatal_fr(r, "compose bundle handle reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle handle reply");
	sshbuf_free(msg);
	free(dest_dir);
	return;

 fail:
	bundle_send_status_failure(oqueue, id, status, "bundle open failure");
	free(dest_dir);
}

/*
 * Process the hpn-bundle-fetch@hpnssh.org extended request.
 *
 * Wire format (after extension name):
 *   u32 flags
 *   u32 n_paths
 *   for i in [0, n_paths): cstring path
 *
 * Streaming model (2026-05-31 libarchive removal):
 *   1. Read each path, stat() it for size/perms/mtime.
 *   2. Queue (src_path, archive_path, mode, size, mtime) into the
 *      writer state machine.
 *   3. Call writer_finish() to signal EOA.
 *   4. Install the bundle_state on the handle table; reply HANDLE.
 *
 * The actual file reads + tar packing happen lazily inside
 * sftp_hpn_server_bundle_read() as the client drains via SSH_FXP_READ.
 * Server memory stays O(1) per bundle (one open file at a time +
 * 512-byte header scratch).
 *
 * Error model: bundle is all-or-nothing.  A per-path stat() failure or
 * non-regular file is logged and skipped (matching upload-side per-
 * entry skip).  There is no per-bundle byte cap and none is needed:
 * streaming keeps server memory O(1) regardless of total bundle size
 * (only one input file is open at a time).  The single client-scaled
 * allocation is the path list, hard-bounded to 65535 entries below.
 * Mid-pack failures surface in bundle_read as SSH2_FX_FAILURE.
 */
void
process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	uint32_t flags = 0, n_paths = 0;
	char **paths = NULL;
	uint32_t n_collected = 0;
	struct hpn_bundle_state *s = NULL;
	struct sshbuf *msg = NULL;
	int handle = -1;
	int r, status = SSH2_FX_FAILURE;
	uint32_t i;

	/* Operator master toggle (same as bundle-open). */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-fetch refused: HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}

	if ((r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &n_paths)) != 0) {
		error_f("parse hpn-bundle-fetch header: %s", ssh_err(r));
		goto fail;
	}
	if (n_paths == 0 || n_paths > 65535) {
		error_f("hpn-bundle-fetch: implausible n_paths=%u", n_paths);
		goto fail;
	}
	paths = calloc(n_paths, sizeof(*paths));
	if (paths == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}
	for (i = 0; i < n_paths; i++) {
		if ((r = sshbuf_get_cstring(iqueue, &paths[i], NULL)) != 0) {
			error_f("parse hpn-bundle-fetch path[%u]: %s",
			    i, ssh_err(r));
			goto fail;
		}
		n_collected++;
	}

	debug3("request %u: hpn-bundle-fetch n=%u flags=0x%x",
	    id, n_paths, flags);

	s = bundle_state_new_fetch(flags);
	if (s == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}

	bundle_enabled_init();
	for (i = 0; i < n_paths; i++) {
		struct stat sb;
		int fd = open(paths[i], O_RDONLY);
		if (fd < 0) {
			error_f("hpn-bundle-fetch: open \"%s\": %s",
			    paths[i], strerror(errno));
			continue;
		}
		if (fstat(fd, &sb) < 0) {
			error_f("hpn-bundle-fetch: fstat \"%s\": %s",
			    paths[i], strerror(errno));
			(void)close(fd);
			continue;
		}
		(void)close(fd);
		if (!S_ISREG(sb.st_mode)) {
			debug_f("hpn-bundle-fetch: \"%s\" not regular, skip",
			    paths[i]);
			continue;
		}
		uint64_t fsize = (uint64_t)sb.st_size;
		if (sftp_hpn_tar_writer_add_file(s->writer,
		    paths[i], paths[i],
		    sb.st_mode, fsize, sb.st_mtime) < 0) {
			error_f("hpn-bundle-fetch: writer_add_file "
			    "\"%s\" rejected (path too long?)", paths[i]);
			continue;
		}
		s->fetch_total_size += fsize;
	}
	sftp_hpn_tar_writer_finish(s->writer);

	handle = handle_new_bundle(s);
	if (handle < 0) {
		error_f("hpn-bundle-fetch: handle table full");
		goto fail;
	}

	debug_f("hpn-bundle-fetch: handle=%d n_paths=%u total_size=%llu",
	    handle, n_paths,
	    (unsigned long long)s->fetch_total_size);

	s = NULL;	/* ownership transferred to handle table */

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	{
		u_char hbuf[sizeof(int32_t)];
		put_u32(hbuf, (uint32_t)handle);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
			fatal_fr(r, "compose bundle-fetch handle reply");
	}
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle-fetch handle reply");
	sshbuf_free(msg);

	for (i = 0; i < n_collected; i++)
		free(paths[i]);
	free(paths);
	return;

 fail:
	if (s != NULL)
		bundle_state_free(s);
	for (i = 0; i < n_collected; i++)
		free(paths[i]);
	free(paths);
	bundle_send_status_failure(oqueue, id, status, "bundle-fetch failure");
}
