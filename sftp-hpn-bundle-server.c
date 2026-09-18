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

/* sftp-hpn-bundle-server.c - server side of the SFTP bundle protocol.
 *
 * Upload, hpn-bundle-open@hpnssh.org: process_hpn_bundle_open creates
 * the handle, sftp_hpn_server_bundle_write feeds each WRITE payload to
 * the sftp-hpn-tar.h parser, and the parser callbacks (entry_cb,
 * data_cb, entry_end_cb) extract the entries. With the writer pool
 * active, the default, each file is buffered whole and handed to a
 * pool thread. With it off the callbacks open, write and close inline.
 * sftp_hpn_server_bundle_close checks that the end marker arrived,
 * joins the pool and releases the state.
 *
 * Download, hpn-bundle-fetch@hpnssh.org: process_hpn_bundle_fetch
 * checks each requested file, queues it into the sftp-hpn-tar.h writer
 * and installs the handle. sftp_hpn_server_bundle_read packs archive
 * bytes on demand for each READ. Close only releases the state.
 *
 * The handle table slots (handle_new_bundle and friends) live in
 * sftp-server.c. Both extended-request handlers are called from the
 * dispatcher in sftp-hpn-server.c. The operator toggles HPNUseBundle
 * and HPNWriterPool arrive as sftp-server argv flags (-B and -O). */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "misc.h"		/* mkdir_p, put_u32 */
#include "sftp.h"
#include "sftp-hpn-bundle.h"	/* HPN_BUNDLE_FLAG_* */
#include "sftp-hpn-bundle-server.h"
#include "sftp-hpn-tar.h"
#include "sftp-hpn-bundle-pool.h"	/* shared writer pool (extract overlap) */

/* Bundle handle mode. An upload handle extracts entries as the WRITEs
 * arrive and close checks for the end of archive. A fetch handle queues
 * the files at open and packs them on demand as the READs arrive. */
enum hpn_bundle_mode {
	HPN_BUNDLE_MODE_UPLOAD = 0,   /* hpn-bundle-open */
	HPN_BUNDLE_MODE_FETCH  = 1    /* hpn-bundle-fetch */
};

/* Per-handle bundle state. An upload handle owns the parser, the
 * per-entry fields the callbacks fill in, and the writer pool when it is
 * active. A fetch handle owns the writer, with every file queued and
 * finished at open time. The other mode's fields stay zero, apart from
 * cur_fd, which is -1 so the destructor never closes fd 0. With the
 * pool active, memory per handle is the file being accumulated plus the
 * pool's byte budget of queued files. Inline writes buffer nothing. */
struct hpn_bundle_state {
	enum hpn_bundle_mode mode;
	char    *dest_dir;          /* UPLOAD: dir to extract into; FETCH: NULL */
	uint32_t flags;             /* HPN_BUNDLE_FLAG_*, see sftp-hpn-bundle.h */

	/* UPLOAD-mode fields. */
	struct sftp_hpn_tar_parser *parser;
	uint64_t bytes_received;    /* file data bytes the parser delivered */
	uint64_t next_write_offset; /* expected SSH_FXP_WRITE offset */
	int      end_seen;          /* the parser saw the end marker */
	/* Per-entry state set by the parser callbacks. */
	char    *cur_full_path;     /* malloc'd path of the current entry */
	int      cur_fd;            /* open output fd, or -1 */
	uint64_t cur_size;          /* declared size from header */
	mode_t   cur_mode;          /* from the entry header */
	time_t   cur_mtime;         /* from the entry header */
	char    *last_mkdir_dir;    /* last parent dir already mkdir_p'd */

	/* Writer pool, NULL when writes are inline. */
	struct bundle_write_pool *pool;
	u_char  *cur_job_buf;       /* pool: current file's data buffer */
	size_t   cur_job_filled;    /* pool: bytes accumulated so far */

	/* FETCH-mode fields. */
	struct sftp_hpn_tar_writer *writer;
	uint64_t bytes_produced;    /* cumulative pack_next bytes returned */
	uint64_t fetch_total_size;  /* sum of declared file sizes (logged) */
};

/* HPN operator toggles parsed from argv (-B and -O) in sftp-server.c. */
extern int    sftp_server_hpn_use_bundle(void);
extern int    sftp_server_hpn_writer_pool(void);

/* Bundle slots of the handle table, implemented in sftp-server.c so this
 * file needs nothing of the table internals. */
extern int    handle_new_bundle(void *opaque);
extern void  *handle_get_bundle(int handle);
extern void   handle_free_bundle(int handle);
extern int    handle_is_bundle(int handle);

/* Parser callbacks, the path-safety check and the state destructor,
 * defined below. */
static int bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime);
static int bundle_upload_data_cb(void *ctx, const u_char *data, size_t len);
static int bundle_upload_entry_end_cb(void *ctx);
static int bundle_path_is_safe(const char *path, const char *dest_dir);
static void bundle_state_free(struct hpn_bundle_state *state);

static const struct sftp_hpn_tar_callbacks bundle_upload_callbacks = {
	.entry_cb     = bundle_upload_entry_cb,
	.data_cb      = bundle_upload_data_cb,
	.entry_end_cb = bundle_upload_entry_end_cb,
};

/* Compose and enqueue an SSH_FXP_STATUS failure reply on oqueue. Shared
 * by the fail labels of both extended-request handlers, which differ
 * only in the tag used for the fatal log line. */
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

/* Compose and enqueue the SSH_FXP_HANDLE reply both extended-request
 * handlers send on success. */
static void
bundle_send_handle_reply(struct sshbuf *oqueue, u_int id, int handle)
{
	struct sshbuf *msg;
	u_char hbuf[sizeof(uint32_t)];
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	put_u32(hbuf, (uint32_t)handle);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
		fatal_fr(r, "compose handle reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue handle reply");
	sshbuf_free(msg);
}

/* Allocate the state for an upload handle: the parser and, when the
 * operator allows it and the client did not opt out, the writer pool.
 * Returns NULL on allocation failure. A pool that fails to start is
 * logged and the callbacks then write inline. */
static struct hpn_bundle_state *
bundle_state_new(const char *dest_dir, uint32_t flags)
{
	struct hpn_bundle_state *state;
	uint64_t budget;
	int threads;

	if ((state = calloc(1, sizeof(*state))) == NULL)
		return NULL;
	state->mode   = HPN_BUNDLE_MODE_UPLOAD;
	state->flags  = flags;
	state->cur_fd = -1;
	state->dest_dir = strdup(dest_dir);
	if (state->dest_dir != NULL)
		state->parser = sftp_hpn_tar_parser_new(
		    &bundle_upload_callbacks, state);
	if (state->dest_dir == NULL || state->parser == NULL) {
		bundle_state_free(state);
		return NULL;
	}
	/* Writer pool, unless the operator turned it off (HPNWriterPool) or
	 * the client sent HPN_BUNDLE_FLAG_NO_POOL. */
	if (sftp_server_hpn_writer_pool() &&
	    (flags & HPN_BUNDLE_FLAG_NO_POOL) == 0) {
		budget = bundle_writer_budget();
		threads = bundle_writer_threads();
		state->pool = bundle_write_pool_new(threads,
		    (flags & HPN_BUNDLE_FLAG_PRESERVE) != 0,
		    (flags & HPN_BUNDLE_FLAG_FSYNC) != 0, budget);
		if (state->pool != NULL)
			debug_f("hpn-bundle: writer pool active (%d threads, "
			    "%llu-byte budget)", threads,
			    (unsigned long long)budget);
		else
			error_f("hpn-bundle: writer pool failed to start, "
			    "writing inline");
	}
	return state;
}

/* Allocate the state for a fetch handle: an empty writer that the fetch
 * handler fills and finishes before installing the handle. There is no
 * dest_dir, the server only reads, and the request's flags are not kept
 * because nothing on the fetch path reads them. Returns NULL on
 * allocation failure. */
static struct hpn_bundle_state *
bundle_state_new_fetch(void)
{
	struct hpn_bundle_state *state;

	if ((state = calloc(1, sizeof(*state))) == NULL)
		return NULL;
	state->mode   = HPN_BUNDLE_MODE_FETCH;
	state->cur_fd = -1;	/* so bundle_state_free never closes fd 0 */
	if ((state->writer = sftp_hpn_tar_writer_new()) == NULL) {
		bundle_state_free(state);
		return NULL;
	}
	return state;
}

/* Release a bundle state at any point in its life. Safe on NULL. A pool
 * still attached means an abnormal teardown, so it is joined here and
 * its error flag is dropped. */
static void
bundle_state_free(struct hpn_bundle_state *state)
{
	if (state == NULL)
		return;
	(void)bundle_write_pool_finish(state->pool);
	free(state->cur_job_buf);
	if (state->cur_fd >= 0)
		(void)close(state->cur_fd);
	free(state->cur_full_path);
	free(state->last_mkdir_dir);
	sftp_hpn_tar_parser_free(state->parser);
	sftp_hpn_tar_writer_free(state->writer);
	free(state->dest_dir);
	free(state);
}

/* Is this handle a bundle? */
int
sftp_hpn_server_is_bundle_handle(int handle)
{
	return handle_is_bundle(handle);
}

/* Did the operator leave bundles on (HPNUseBundle)? */
int
sftp_hpn_server_bundle_enabled(void)
{
	return sftp_server_hpn_use_bundle();
}

/* Join dest_dir and an entry path into a malloc'd destination path. An
 * empty dest_dir means the entry path is used as sent. Returns NULL on
 * allocation failure. */
static char *
bundle_compose_path(const char *dest_dir, const char *entry_path)
{
	char *full;
	size_t full_len;

	if (*dest_dir == '\0')
		return strdup(entry_path);
	full_len = strlen(dest_dir) + 1 + strlen(entry_path) + 1;
	if ((full = malloc(full_len)) == NULL)
		return NULL;
	snprintf(full, full_len, "%s/%s", dest_dir, entry_path);
	return full;
}

/* Parser entry callback, one per entry header. Checks and composes the
 * destination path and makes sure its parent directory exists, then
 * either allocates the whole-file buffer for the writer pool or opens
 * the output file for inline writes. The last_mkdir_dir cache skips the
 * mkdir_p walk when consecutive entries share a parent, the common case
 * for bundles of many small files. */
static int
bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime)
{
	struct hpn_bundle_state *state = ctx;
	char *full_copy, *parent;
	mode_t perm;

	if (!bundle_path_is_safe(path, state->dest_dir)) {
		error_f("hpn-bundle: rejected entry pathname \"%s\" (empty, "
		    "has a \"..\" component, or absolute with dest_dir set)",
		    path);
		return -1;
	}
	state->cur_full_path = bundle_compose_path(state->dest_dir, path);
	if (state->cur_full_path == NULL) {
		error_f("hpn-bundle: out of memory composing path");
		return -1;
	}
	state->cur_size  = size;
	state->cur_mode  = mode;
	state->cur_mtime = mtime;

	full_copy = strdup(state->cur_full_path);
	if (full_copy != NULL) {
		parent = dirname(full_copy);
		if (strcmp(parent, ".") != 0 && strcmp(parent, "/") != 0) {
			if (state->last_mkdir_dir == NULL ||
			    strcmp(state->last_mkdir_dir, parent) != 0) {
				(void)mkdir_p(parent, 0755);
				free(state->last_mkdir_dir);
				state->last_mkdir_dir = strdup(parent);
			}
		}
		free(full_copy);
	}

	if (state->pool != NULL) {
		/* A pool thread does the open, write and close, so only the
		 * file buffer is set up here. */
		state->cur_job_filled = 0;
		state->cur_job_buf = NULL;
		if (size > 0) {
			state->cur_job_buf = malloc((size_t)size);
			if (state->cur_job_buf == NULL) {
				error_f("hpn-bundle: malloc(%llu) for \"%s\"",
				    (unsigned long long)size,
				    state->cur_full_path);
				return -1;
			}
		}
		return 0;
	}

	perm = 0644;		/* what a plain SFTP upload without -p gets */
	if (state->flags & HPN_BUNDLE_FLAG_PRESERVE)
		perm = mode;

	/* No O_TRUNC. A connection that dies mid-bundle can leave a lagging
	 * server still draining buffered records while the client's re-send
	 * writes the same file. Without O_TRUNC that stale writer can only
	 * overwrite a prefix with identical bytes and never shrink the file.
	 * The size is set by the ftruncate in entry_end_cb, which only a
	 * writer that completes the entry reaches. */
	state->cur_fd = open(state->cur_full_path, O_WRONLY | O_CREAT, perm);
	if (state->cur_fd < 0) {
		error_f("hpn-bundle: open \"%s\": %s",
		    state->cur_full_path, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* Preallocate the extents. Fewer fragments and faster sequential
	 * writes on extent-based filesystems. Failure is harmless, write()
	 * allocates on demand. */
	if (size > 0)
		(void)posix_fallocate(state->cur_fd, 0, (off_t)size);
#endif
	return 0;
}

/* Parser data callback. Appends the bytes to the pool buffer when the
 * pool is active, otherwise writes them to the file entry_cb opened.
 * The parser clamps delivered data to the declared entry size, so the
 * bound check on the pool path only guards against a parser regression
 * overflowing the buffer. */
static int
bundle_upload_data_cb(void *ctx, const u_char *data, size_t len)
{
	struct hpn_bundle_state *state = ctx;
	size_t remaining;
	ssize_t written;

	if (state->pool != NULL) {
		/* Subtraction rather than addition so the check itself cannot
		 * overflow. cur_job_filled <= cur_size always holds. */
		if (len > (size_t)state->cur_size - state->cur_job_filled) {
			error_f("hpn-bundle: entry data exceeds declared size "
			    "%llu", (unsigned long long)state->cur_size);
			return -1;
		}
		if (len > 0)
			memcpy(state->cur_job_buf + state->cur_job_filled,
			    data, len);
		state->cur_job_filled += len;
	} else {
		remaining = len;
		while (remaining > 0) {
			written = write(state->cur_fd, data, remaining);
			if (written < 0) {
				if (errno == EINTR)
					continue;
				error_f("hpn-bundle: write \"%s\": %s",
				    state->cur_full_path, strerror(errno));
				return -1;
			}
			data += written;
			remaining -= (size_t)written;
		}
	}
	state->bytes_received += (uint64_t)len;
	return 0;
}

/* Parser end-of-entry callback. With the pool active, hands the buffered
 * file to a pool thread as one job. Inline, sets the final size, applies
 * the preserved mode and mtime, optionally fsyncs, and closes the file.
 * Returns -1 on any failure, which abandons the bundle. */
static int
bundle_upload_entry_end_cb(void *ctx)
{
	struct hpn_bundle_state *state = ctx;
	struct bundle_write_job *job;
	struct timespec times[2];
	int preserve = (state->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (state->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;
	int rc = 0;

	if (state->pool != NULL) {
		/* The job takes over the path and the data buffer. On failure
		 * they stay with the state and bundle_state_free releases
		 * them. */
		if ((job = calloc(1, sizeof(*job))) == NULL) {
			error_f("hpn-bundle: write-job alloc failed");
			return -1;
		}
		job->full_path = state->cur_full_path;
		job->mode      = state->cur_mode;
		job->mtime     = state->cur_mtime;
		job->data      = state->cur_job_buf;
		job->len       = (size_t)state->cur_size;
		state->cur_full_path = NULL;
		state->cur_job_buf   = NULL;
		if (bundle_pool_enqueue(state->pool, job) != 0) {
			/* A writer thread has already failed. */
			free(job->full_path);
			free(job->data);
			free(job);
			return -1;
		}
		return 0;
	}

	/* Set the size here rather than with O_TRUNC at open, see the
	 * comment in bundle_upload_entry_cb. */
	if (ftruncate(state->cur_fd, (off_t)state->cur_size) != 0) {
		error_f("hpn-bundle: ftruncate \"%s\": %s",
		    state->cur_full_path, strerror(errno));
		rc = -1;
	}
	if (preserve) {
		/* open(O_CREAT, perm) is subject to umask and ignored on a
		 * pre-existing file, so force the bits here, after the
		 * ftruncate, which updates mtime whenever it changes the
		 * size. */
		(void)fchmod(state->cur_fd, state->cur_mode);
		times[0].tv_sec = state->cur_mtime;
		times[0].tv_nsec = 0;
		times[1].tv_sec = state->cur_mtime;
		times[1].tv_nsec = 0;
		(void)futimens(state->cur_fd, times);
	}
	if (do_fsync && fsync(state->cur_fd) != 0) {
		error_f("hpn-bundle: fsync \"%s\": %s",
		    state->cur_full_path, strerror(errno));
		rc = -1;
	}
	if (close(state->cur_fd) != 0) {
		error_f("hpn-bundle: close \"%s\": %s",
		    state->cur_full_path, strerror(errno));
		rc = -1;
	}
	state->cur_fd = -1;
	free(state->cur_full_path);
	state->cur_full_path = NULL;
	return rc;
}

/* WRITE on an upload bundle handle. The payload must continue where the
 * previous one ended, then it goes straight into the parser, whose
 * callbacks extract the entries. Any parser error fails the bundle. */
int
sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	struct hpn_bundle_state *state = handle_get_bundle(handle);
	int rc;

	if (state == NULL)
		return SSH2_FX_FAILURE;
	if (state->mode != HPN_BUNDLE_MODE_UPLOAD) {
		error_f("hpn-bundle: WRITE on non-upload bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
	/* The client writes sequentially, so a gap or overlap is a bug. */
	if (off != state->next_write_offset) {
		error_f("hpn-bundle: WRITE offset %llu, expected %llu",
		    (unsigned long long)off,
		    (unsigned long long)state->next_write_offset);
		return SSH2_FX_FAILURE;
	}
	rc = sftp_hpn_tar_parser_feed(state->parser, data, len);
	if (rc < 0) {
		error_f("hpn-bundle: parser error: %s",
		    sftp_hpn_tar_parser_error(state->parser));
		return SSH2_FX_FAILURE;
	}
	if (rc == 1)		/* parser_feed returns 1 at the end marker */
		state->end_seen = 1;
	state->next_write_offset += len;
	return SSH2_FX_OK;
}

/* READ on a fetch bundle handle. Packs up to len bytes of archive into
 * out_buf and reports how many in *out_len. Returns SSH2_FX_EOF once
 * the archive is exhausted. */
int
sftp_hpn_server_bundle_read(int handle, uint64_t off, u_char *out_buf,
    size_t len, size_t *out_len)
{
	struct hpn_bundle_state *state = handle_get_bundle(handle);
	size_t produced = 0;
	/* ssize_t because pack_next returns -1 when a source file fails to
	 * open or read, or shrinks under it. */
	ssize_t packed;

	if (state == NULL || out_buf == NULL || out_len == NULL)
		return SSH2_FX_FAILURE;
	if (state->mode != HPN_BUNDLE_MODE_FETCH) {
		error_f("hpn-bundle: READ on non-fetch bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
	/* READs arrive in offset order. A backward seek is a client bug,
	 * the codec cannot replay what it produced. A forward gap is
	 * normal: reads before the end of the archive are always filled,
	 * and the client fires reads ahead at fixed chunk offsets, so once
	 * the archive ends mid-chunk every read still in flight starts past
	 * bytes_produced. Those get whatever is left, usually nothing, and
	 * then EOF. */
	if (off < state->bytes_produced) {
		error_f("hpn-bundle: READ backward seek to %llu, next is %llu",
		    (unsigned long long)off,
		    (unsigned long long)state->bytes_produced);
		return SSH2_FX_FAILURE;
	}
	/* pack_next returns 0 only at the end of the archive. */
	while (produced < len) {
		packed = sftp_hpn_tar_writer_pack_next(state->writer,
		    out_buf + produced, len - produced);
		if (packed < 0) {
			error_f("hpn-bundle: READ writer error: %s",
			    sftp_hpn_tar_writer_error(state->writer));
			return SSH2_FX_FAILURE;
		}
		if (packed == 0)
			break;
		/* packed is positive here, the cast only documents the sign. */
		produced += (size_t)packed;
	}
	*out_len = produced;
	state->bytes_produced += produced;
	if (produced == 0)
		return SSH2_FX_EOF;
	return SSH2_FX_OK;
}

/* Validate an entry pathname from the wire before it is joined to
 * dest_dir. Empty paths and any ".." component are rejected, the client
 * never produces either. An absolute path is rejected only when
 * dest_dir is set, since "dest_dir/" + "/abs" means nothing. With an
 * empty dest_dir the client is supplying complete paths and the usual
 * SFTP path resolution applies, absolute ones included. Returns 1 when
 * the path may be extracted, 0 when it must be rejected. */
static int
bundle_path_is_safe(const char *path, const char *dest_dir)
{
	const char *component, *scan;
	size_t component_len;

	if (path == NULL || *path == '\0')
		return 0;
	if (*path == '/' && *dest_dir != '\0')
		return 0;
	component = path;
	/* hand rolled split on '/' and reject on '..' */
	for (scan = path; ; scan++) {
		if (*scan != '/' && *scan != '\0')
			continue;
		component_len = (size_t)(scan - component);
		if (component_len == 2 && component[0] == '.' &&
		    component[1] == '.')
			return 0;
		if (*scan == '\0')
			break;
		component = scan + 1;
	}
	return 1;
}

/* CLOSE on a bundle handle. A fetch handle only releases its state. An
 * upload handle also fails on a parser error or a missing end marker,
 * and joins the writer pool so every file is on disk and any write
 * failure is in the status before the reply goes out. Always frees the
 * handle. */
int
sftp_hpn_server_bundle_close(int handle)
{
	struct hpn_bundle_state *state = handle_get_bundle(handle);
	const char *parser_error;
	int status = SSH2_FX_OK;

	if (state == NULL)
		return SSH2_FX_FAILURE;
	if (state->mode == HPN_BUNDLE_MODE_FETCH) {
		debug_f("hpn-bundle: close fetch handle=%d produced=%llu",
		    handle, (unsigned long long)state->bytes_produced);
	} else {
		debug_f("hpn-bundle: close upload handle=%d dest=\"%s\" "
		    "received=%llu flags=0x%x", handle, state->dest_dir,
		    (unsigned long long)state->bytes_received, state->flags);
		parser_error = sftp_hpn_tar_parser_error(state->parser);
		if (parser_error != NULL) {
			error_f("hpn-bundle: close with parser error: %s",
			    parser_error);
			status = SSH2_FX_FAILURE;
		} else if (!state->end_seen) {
			error_f("hpn-bundle: close before the end marker, "
			    "received=%llu",
			    (unsigned long long)state->bytes_received);
			status = SSH2_FX_FAILURE;
		}
		/* bundle_write_pool_finish frees the pool, so clear the
		 * pointer before bundle_state_free sees it. */
		if (bundle_write_pool_finish(state->pool) != 0)
			status = SSH2_FX_FAILURE;
		state->pool = NULL;
	}
	bundle_state_free(state);
	handle_free_bundle(handle);
	return status;
}

/* Handle an hpn-bundle-open@hpnssh.org request. The payload is string
 * dest_dir and u32 flags. Creates the destination directory and an
 * upload handle and replies with SSH_FXP_HANDLE, or with SSH_FXP_STATUS
 * on failure. */
void
process_hpn_bundle_open(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *dest_dir = NULL;
	uint32_t flags = 0;
	struct hpn_bundle_state *state;
	int handle, saved_errno;
	int r, status = SSH2_FX_FAILURE;

	/* Refuse when HPNUseBundle is off. The extension is not advertised
	 * then, but a client may still try. */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-open: refused, HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}
	if ((r = sshbuf_get_cstring(iqueue, &dest_dir, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0) {
		error_f("hpn-bundle-open: parse: %s", ssh_err(r));
		goto fail;
	}
	debug3("request %u: hpn-bundle-open dest=\"%s\" flags=0x%x",
	    id, dest_dir, flags);

	/* Create the destination directory. An empty dest_dir means the
	 * entries carry complete paths and entry_cb creates each parent. */
	if (*dest_dir != '\0' && mkdir_p(dest_dir, 0755) != 0) {
		saved_errno = errno;
		error_f("hpn-bundle-open: mkdir_p \"%s\": %s",
		    dest_dir, strerror(saved_errno));
		if (saved_errno == ENOENT)
			status = SSH2_FX_NO_SUCH_FILE;
		else if (saved_errno == EACCES)
			status = SSH2_FX_PERMISSION_DENIED;
		goto fail;
	}
	if ((state = bundle_state_new(dest_dir, flags)) == NULL) {
		error_f("hpn-bundle-open: out of memory");
		goto fail;
	}
	if ((handle = handle_new_bundle(state)) < 0) {
		error_f("hpn-bundle-open: handle table full");
		bundle_state_free(state);
		goto fail;
	}
	bundle_send_handle_reply(oqueue, id, handle);
	free(dest_dir);
	return;

 fail:
	bundle_send_status_failure(oqueue, id, status, "bundle open failure");
	free(dest_dir);
}

/* Handle an hpn-bundle-fetch@hpnssh.org request. The payload is u32
 * flags, u32 n_paths and n_paths cstring paths. Each file is checked
 * and queued into the writer, the archive is finished, and the reply
 * is SSH_FXP_HANDLE. Packing happens later, in
 * sftp_hpn_server_bundle_read, as the client reads. A path that cannot
 * be opened or is not a regular file is logged and left out; the client
 * sees the missing record and fetches that file on its own. A file that
 * fails while being packed fails the bundle in bundle_read. */
void
process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	uint32_t flags = 0, n_paths = 0, n_queued = 0, i;
	char **paths = NULL;
	struct hpn_bundle_state *state = NULL;
	struct stat file_stat;
	uint64_t file_size;
	int fd, handle;
	int r, status = SSH2_FX_FAILURE;

	/* Refuse when HPNUseBundle is off, as in bundle-open. */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-fetch: refused, HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}
	if ((r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &n_paths)) != 0) {
		error_f("hpn-bundle-fetch: parse header: %s", ssh_err(r));
		goto fail;
	}
	/* The client never batches more than BUNDLE_BATCH_MAX_FILES, and
	 * the path list is the one allocation the request sizes. */
	if (n_paths == 0 || n_paths > BUNDLE_BATCH_MAX_FILES) {
		error_f("hpn-bundle-fetch: implausible n_paths=%u", n_paths);
		goto fail;
	}
	if ((paths = calloc(n_paths, sizeof(*paths))) == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}
	for (i = 0; i < n_paths; i++) {
		if ((r = sshbuf_get_cstring(iqueue, &paths[i], NULL)) != 0) {
			error_f("hpn-bundle-fetch: parse path[%u]: %s",
			    i, ssh_err(r));
			goto fail;
		}
	}
	debug3("request %u: hpn-bundle-fetch n=%u flags=0x%x",
	    id, n_paths, flags);

	if ((state = bundle_state_new_fetch()) == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}
	/* Open rather than stat, so a file this user cannot read is left
	 * out here instead of failing the whole bundle when pack_next
	 * reaches it. */
	for (i = 0; i < n_paths; i++) {
		if ((fd = open(paths[i], O_RDONLY)) < 0) {
			error_f("hpn-bundle-fetch: open \"%s\": %s",
			    paths[i], strerror(errno));
			continue;
		}
		if (fstat(fd, &file_stat) < 0) {
			error_f("hpn-bundle-fetch: fstat \"%s\": %s",
			    paths[i], strerror(errno));
			(void)close(fd);
			continue;
		}
		(void)close(fd);
		if (!S_ISREG(file_stat.st_mode)) {
			debug2_f("hpn-bundle-fetch: \"%s\" not regular, "
			    "left out", paths[i]);
			continue;
		}
		file_size = (uint64_t)file_stat.st_size;
		if (sftp_hpn_tar_writer_add_file(state->writer, paths[i],
		    paths[i], file_stat.st_mode, file_size,
		    file_stat.st_mtime) < 0) {
			error_f("hpn-bundle-fetch: writer rejected \"%s\" "
			    "(path too long or out of memory)", paths[i]);
			continue;
		}
		state->fetch_total_size += file_size;
		n_queued++;
	}
	/* Queue the end marker. Nothing can be added after this. */
	sftp_hpn_tar_writer_finish(state->writer);

	if ((handle = handle_new_bundle(state)) < 0) {
		error_f("hpn-bundle-fetch: handle table full");
		goto fail;
	}
	debug_f("hpn-bundle-fetch: handle=%d queued=%u of %u total_size=%llu",
	    handle, n_queued, n_paths,
	    (unsigned long long)state->fetch_total_size);
	bundle_send_handle_reply(oqueue, id, handle);
	for (i = 0; i < n_paths; i++)
		free(paths[i]);
	free(paths);
	return;

 fail:
	bundle_state_free(state);
	if (paths != NULL) {
		for (i = 0; i < n_paths; i++)
			free(paths[i]);
	}
	free(paths);
	bundle_send_status_failure(oqueue, id, status, "bundle-fetch failure");
}
