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
 * sftp-hpn-bundle-server.c - server-side SFTP bundle protocol.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Extracted from sftp-hpn-server.c on 2026-05-31 as part of the
 * structural refactor described in project_hpn_code_organization_vision.md.
 *
 * Contents:
 *   - struct hpn_bundle_state + lifecycle (UPLOAD parser-driven,
 *     FETCH writer-driven)
 *   - Per-bundle and total-process byte caps + env-driven init
 *     (HPN_USE_BUNDLE / HPN_MAX_BUNDLE_SIZE from sshd-session)
 *   - Parser callbacks (entry_cb opens output fd + (D) mkdir cache +
 *     (E) fallocate; data_cb writes inline; entry_end_cb closes +
 *     applies metadata)
 *   - sftp_hpn_server_bundle_write / _read / _close handlers
 *   - sftp_hpn_server_is_bundle_handle / _enabled / _per_cap accessors
 *   - sftp_hpn_server_set_bundle_caps  (sftp-server.c CLI -B / -T)
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
 *   produce bytes on demand into the SFTP DATA reply.
 *
 * Per-bundle and total-process byte caps still apply (see bundle_per_cap
 * / bundle_total_cap), but enforcement shifts: instead of capping the
 * accumulator's allocation, we track total bytes that have flowed
 * through this bundle and trip the cap if exceeded.  The total cap is
 * sized via fetch_total_size (FETCH: sum of declared file sizes)
 * and bytes_received (UPLOAD: bytes parsed). */
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

	/* FETCH-mode fields. */
	struct sftp_hpn_tar_writer *writer;
	uint64_t bytes_produced;    /* cumulative pack_next bytes returned */
	uint64_t next_read_off;     /* expected SSH_FXP_READ offset */
	uint64_t fetch_total_size;  /* sum of declared file sizes (cap check) */

	/* INSTR-BUNDLE-TIMING: server-side per-bundle extraction profiling.
	 * Temporary; back out by removing everything tagged INSTR-BUNDLE-TIMING. */
	double   ist_open_s;        /* INSTR-BUNDLE-TIMING: monotonic time at open */
	double   ist_write_s;       /* INSTR-BUNDLE-TIMING: cumulative write() time */
	double   ist_fsync_s;       /* INSTR-BUNDLE-TIMING: cumulative fsync() time */
	double   ist_fsync_max_s;   /* INSTR-BUNDLE-TIMING: worst single fsync() */
	uint32_t ist_files;         /* INSTR-BUNDLE-TIMING: files extracted */
};

/* Flag constants and HPN_BUNDLE_BLOCK_BYTES live in sftp-hpn-bundle.h, the
 * shared HPN-only header.  Single source of truth for client + server. */

/* ── Server-side bundle accumulator caps ─────────────────────────────────
 *
 * SFTP is normally bounded by SFTP_MAX_MSG_LENGTH (256 KiB per message).
 * Bundle handles break that invariant: an upload bundle accepts a long
 * sequence of WRITEs into a malloc'd accumulator, and a download bundle
 * pre-allocates a tar buffer sized by the client's path list.  Without a
 * server-side cap a malicious or misconfigured client can drive the
 * server to OOM.
 *
 * Caps are process-local - sftp-server is forked per user connection by
 * sshd, so the "total across handles" cap is per-connection.  Per-system
 * memory protection (RLIMIT_AS, sshd's MaxStartups) is the OS's
 * responsibility.
 *
 * Default per-bundle cap is 64 MiB; default total cap is 1.5 GiB.
 *
 * Both are tunable via the sftp-server -B (per-bundle) and -T (total)
 * CLI flags, which the operator sets on the sshd_config Subsystem line:
 *
 *   Subsystem  sftp  /usr/libexec/hpnsftp-server -B 64M -T 1500M
 *
 * sftp-server.c parses the flags and calls sftp_hpn_server_set_bundle_caps
 * before the SFTP main loop runs.  Unset flags leave the compiled
 * defaults in place.  Additionally, sshd_config's HPNMaxBundleSize
 * propagates through the HPN_MAX_BUNDLE_SIZE env var that sshd-session
 * sets, and bundle_caps_init merges it with the -B path.
 */
#define HPN_BUNDLE_PER_CAP_DEFAULT   ((size_t)64   * 1024 * 1024)        /* 64 MiB */
#define HPN_BUNDLE_PER_CAP_MIN       ((size_t)1    * 1024 * 1024)        /* 1 MiB */
#define HPN_BUNDLE_PER_CAP_MAX       ((size_t)1024 * 1024 * 1024)        /* 1 GiB */
#define HPN_BUNDLE_TOTAL_CAP_DEFAULT ((size_t)1536 * 1024 * 1024)        /* 1.5 GiB */
#define HPN_BUNDLE_TOTAL_CAP_MIN     ((size_t)16   * 1024 * 1024)        /* 16 MiB */
#define HPN_BUNDLE_TOTAL_CAP_MAX     ((size_t)16ULL * 1024 * 1024 * 1024) /* 16 GiB */

static size_t bundle_per_cap   = 0;   /* 0 = uninitialised */
static size_t bundle_total_cap = 0;
static size_t bundle_total_bytes = 0; /* sum of accum_cap across open handles */

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
 * Parse a K/M/G-suffixed byte count via the openbsd-compat helper
 * scan_scaled().  Returns the parsed value on success, or 0 if spec
 * is NULL/empty/unparseable/negative or would overflow size_t.
 * Callers treat 0 as "no value supplied" - 0 itself is never a
 * valid cap.  Thin wrapper kept here so the call sites stay clean
 * (cast + bounds check live in one place).  The previous in-module
 * parse_bytes_arg was deduplicated against bundle-client.c's
 * bundle_dl_parse_bytes by routing both through scan_scaled
 * (2026-05-31 cleanup).
 */
static size_t
bundle_parse_scaled(const char *spec)
{
	long long llv;

	if (spec == NULL || *spec == '\0')
		return 0;
	if (scan_scaled((char *)spec, &llv) != 0)
		return 0;
	if (llv <= 0 || (unsigned long long)llv > SIZE_MAX)
		return 0;
	return (size_t)llv;
}

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

/*
 * Clamp value into [lo, hi], warning to stderr on either boundary so
 * the operator notices that their request was adjusted.
 */
static size_t
clamp_cap(const char *flag, size_t v, size_t lo, size_t hi)
{
	if (v < lo) {
		fprintf(stderr,
		    "%s %zu bytes is below minimum %zu MiB; clamping.\n",
		    flag, v, lo / (1024 * 1024));
		return lo;
	}
	if (v > hi) {
		fprintf(stderr,
		    "%s %zu bytes is above maximum %zu MiB; clamping.\n",
		    flag, v, hi / (1024 * 1024));
		return hi;
	}
	return v;
}

void
sftp_hpn_server_set_bundle_caps(const char *per_arg, const char *total_arg)
{
	if (per_arg != NULL && *per_arg != '\0') {
		size_t v = bundle_parse_scaled(per_arg);
		if (v == 0)
			fatal("Invalid -B value \"%s\"", per_arg);
		bundle_per_cap = clamp_cap("-B", v,
		    HPN_BUNDLE_PER_CAP_MIN, HPN_BUNDLE_PER_CAP_MAX);
	}
	if (total_arg != NULL && *total_arg != '\0') {
		size_t v = bundle_parse_scaled(total_arg);
		if (v == 0)
			fatal("Invalid -T value \"%s\"", total_arg);
		bundle_total_cap = clamp_cap("-T", v,
		    HPN_BUNDLE_TOTAL_CAP_MIN, HPN_BUNDLE_TOTAL_CAP_MAX);
	}
}

static void
bundle_caps_init(void)
{
	static int initialised = 0;
	const char *ev;

	if (initialised)
		return;

	/* HPN_MAX_BUNDLE_SIZE (sshd_config: HPNMaxBundleSize) - server-
	 * side hard cap on per-bundle accumulator.  Overrides the -B
	 * CLI default if the env var is set and the operator did not
	 * already pass -B explicitly (CLI -B takes precedence). */
	if (bundle_per_cap == 0) {
		ev = getenv("HPN_MAX_BUNDLE_SIZE");
		if (ev != NULL && *ev != '\0') {
			size_t v = bundle_parse_scaled(ev);
			if (v > 0)
				bundle_per_cap = clamp_cap("HPNMaxBundleSize",
				    v, HPN_BUNDLE_PER_CAP_MIN,
				    HPN_BUNDLE_PER_CAP_MAX);
		}
	}
	if (bundle_per_cap == 0)
		bundle_per_cap = HPN_BUNDLE_PER_CAP_DEFAULT;
	if (bundle_total_cap == 0)
		bundle_total_cap = HPN_BUNDLE_TOTAL_CAP_DEFAULT;

	/* HPN_USE_BUNDLE (sshd_config: HPNUseBundle) - master toggle.
	 * Absent / unparseable defaults to 1 (enabled). */
	if (bundle_enabled == -1) {
		ev = getenv("HPN_USE_BUNDLE");
		if (ev != NULL && *ev != '\0') {
			if (strcmp(ev, "0") == 0 || strcmp(ev, "no") == 0)
				bundle_enabled = 0;
			else
				bundle_enabled = 1;
		} else {
			bundle_enabled = 1;
		}
	}

	initialised = 1;
	debug_f("hpn-bundle: enabled=%d per_cap=%zu MiB total_cap=%zu MiB",
	    bundle_enabled,
	    bundle_per_cap   / (1024*1024),
	    bundle_total_cap / (1024*1024));
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

static struct hpn_bundle_state *
bundle_state_new(const char *dest_dir, uint32_t flags)
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
	/* Release total-cap accounting: subtract the larger of declared-
	 * total (FETCH) or bytes-received (UPLOAD) - whichever this bundle
	 * contributed to the running counter. */
	uint64_t contributed = (s->mode == HPN_BUNDLE_MODE_FETCH)
	    ? s->fetch_total_size
	    : s->bytes_received;
	if (contributed > 0) {
		if (bundle_total_bytes >= contributed)
			bundle_total_bytes -= (size_t)contributed;
		else
			bundle_total_bytes = 0;
	}
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
	bundle_caps_init();	/* ensures bundle_enabled is populated */
	return bundle_enabled;
}

size_t
sftp_hpn_server_bundle_per_cap(void)
{
	bundle_caps_init();
	if (!bundle_enabled)
		return 0;
	return bundle_per_cap;
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

	/* Per-bundle cap: bytes_received + new entry size must stay in
	 * bounds.  Using uint64 arithmetic; overflow check first. */
	bundle_caps_init();
	if (size > UINT64_MAX - s->bytes_received ||
	    s->bytes_received + size > bundle_per_cap) {
		error_f("hpn-bundle: entry \"%s\" would exceed per-bundle cap "
		    "(have %llu, +size %llu > cap %zu)",
		    path,
		    (unsigned long long)s->bytes_received,
		    (unsigned long long)size,
		    bundle_per_cap);
		return -1;
	}

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

	mode_t perm = preserve ? (mode & 07777) : 0644;
	s->cur_fd = open(s->cur_full_path, O_WRONLY | O_CREAT | O_TRUNC, perm);
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
	size_t remaining = len;

	if (s->cur_fd < 0)
		return -1;	/* shouldn't happen - parser always pairs */
	double _w0 = monotime_double();	/* INSTR-BUNDLE-TIMING */
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
	s->ist_write_s += monotime_double() - _w0;	/* INSTR-BUNDLE-TIMING */
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

	if (s->cur_fd >= 0) {
		s->ist_files++;	/* INSTR-BUNDLE-TIMING: count extracted file */
		if (preserve) {
			struct timespec ts[2];
			ts[0].tv_sec = s->cur_mtime; ts[0].tv_nsec = 0;
			ts[1].tv_sec = s->cur_mtime; ts[1].tv_nsec = 0;
			(void)futimens(s->cur_fd, ts);
		}
		if (do_fsync) {
			double _f0 = monotime_double();	/* INSTR-BUNDLE-TIMING */
			int _fr = fsync(s->cur_fd);
			double _fd = monotime_double() - _f0;	/* INSTR-BUNDLE-TIMING */
			s->ist_fsync_s += _fd;	/* INSTR-BUNDLE-TIMING */
			if (_fd > s->ist_fsync_max_s)	/* INSTR-BUNDLE-TIMING */
				s->ist_fsync_max_s = _fd;	/* INSTR-BUNDLE-TIMING */
			if (_fr != 0) {
				error_f("hpn-bundle: fsync \"%s\": %s",
				    s->cur_full_path, strerror(errno));
				rc = -1;
			}
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

/* INSTR-BUNDLE-TIMING: append one per-bundle server-extraction record to
 * $HPN_BUNDLE_TIMING_DIR/<pid>.log.  Env unset/empty => no-op.  One file per
 * sftp-server PID (sshd forks one per channel) avoids interleaved writes; the
 * client-side observe script globs them back and removes them.  Back the probe
 * out by deleting this function, its call below, and the struct fields. */
static void
ist_bundle_emit(int handle, struct hpn_bundle_state *s)
{
	static FILE *fp = (FILE *)-1;	/* (FILE*)-1 = not yet tried to open */
	struct timeval tv;
	double wall;

	if (fp == (FILE *)-1) {
		const char *dir = getenv("HPN_BUNDLE_TIMING_DIR");
		char path[1024];
		if (dir == NULL || *dir == '\0') { fp = NULL; return; }
		(void)mkdir_p(dir, 0755);
		snprintf(path, sizeof(path), "%s/%ld.log", dir, (long)getpid());
		fp = fopen(path, "a");
	}
	if (fp == NULL)
		return;
	gettimeofday(&tv, NULL);
	wall = monotime_double() - s->ist_open_s;
	fprintf(fp, "HPNSRV ts=%.3f pid=%ld handle=%d files=%u bytes=%llu "
	    "wall_ms=%.1f write_ms=%.1f fsync_ms=%.1f fsync_max_ms=%.1f\n",
	    (double)tv.tv_sec + (double)tv.tv_usec / 1e6, (long)getpid(),
	    handle, s->ist_files, (unsigned long long)s->bytes_received,
	    wall * 1e3, s->ist_write_s * 1e3, s->ist_fsync_s * 1e3,
	    s->ist_fsync_max_s * 1e3);
	fflush(fp);
}

int
sftp_hpn_server_bundle_close(int handle)
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

	ist_bundle_emit(handle, s);	/* INSTR-BUNDLE-TIMING */

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
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0) {
		error_f("parse hpn-bundle-open: %s", ssh_err(r));
		goto fail;
	}
	debug3("request %u: hpn-bundle-open dest=\"%s\" flags=0x%x",
	    id, dest_dir, flags);

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

	s = bundle_state_new(dest_dir, flags);
	if (s == NULL) {
		status = SSH2_FX_FAILURE;
		goto fail;
	}
	s->ist_open_s = monotime_double();	/* INSTR-BUNDLE-TIMING */

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
 * entry skip), but the per-bundle size cap is enforced before the
 * handle is installed so an abusive client can't pin too much server
 * memory.  Mid-pack failures surface in bundle_read as
 * SSH2_FX_FAILURE.
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

	bundle_caps_init();
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
		if (fsize > UINT64_MAX - s->fetch_total_size ||
		    s->fetch_total_size + fsize > bundle_per_cap) {
			error_f("hpn-bundle-fetch: total size would exceed "
			    "per-bundle cap (have %llu, +%llu > cap %zu)",
			    (unsigned long long)s->fetch_total_size,
			    (unsigned long long)fsize, bundle_per_cap);
			goto fail;
		}
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

	if (s->fetch_total_size > SIZE_MAX - bundle_total_bytes ||
	    bundle_total_bytes + (size_t)s->fetch_total_size >
	    bundle_total_cap) {
		error_f("hpn-bundle-fetch: would exceed total-across-handles "
		    "cap (have %zu, +%llu > cap %zu)",
		    bundle_total_bytes,
		    (unsigned long long)s->fetch_total_size,
		    bundle_total_cap);
		goto fail;
	}
	bundle_total_bytes += (size_t)s->fetch_total_size;

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
