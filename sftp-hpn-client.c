/*
 * sftp-hpn-client.c — HPN-SSH extensions to the SFTP client connection.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Isolating HPN-specific logic here keeps sftp-client.c's diff against
 * upstream small and mechanical.
 *
 * Contents:
 *   - sftp_hpn_conn_init / sftp_hpn_conn_free
 *   - sftp_conn_is_dead      (public API declared in sftp-client.h)
 *   - sftp_set_live_counter  (public API declared in sftp-client.h)
 *   - Fault injection (TEST/DEBUG only): fi_state, fi_pv_state,
 *     fi_state_init, fi_pv_state_init, sftp_hpn_check_fault
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#include "includes.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stdio.h>

#include "xmalloc.h"
#include "log.h"
#include "sftp-hpn-client.h"

#ifdef HPN_FAULT_INJECTION
static struct {
	uint64_t       threshold;  /* byte threshold; 0 = disabled */
	int            kills_left; /* remaining kill slots; INT_MAX = unlimited */
	pthread_once_t once;
} fi_state = { 0, 0, PTHREAD_ONCE_INIT };

/* Parallel struct for SFTP_FAULT_PROTOCOL — triggers protocol violation. */
static struct {
	uint64_t       threshold;
	int            kills_left;
	pthread_once_t once;
} fi_pv_state = { 0, 0, PTHREAD_ONCE_INIT };

/*
 * Parsed once from SFTP_FAULT_INJECT=<bytes>[:<max_kills>].
 *   bytes     — worker connection dies after sending this many bytes.
 *   max_kills — optional; at most this many workers are killed (default: all).
 * Example: SFTP_FAULT_INJECT=150000:2  kills at most 2 out of N workers.
 */
static void
fi_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_INJECT");
	if (ev == NULL)
		return;
	char *ep;
	uint64_t bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fi_state.threshold  = bytes;
	fi_state.kills_left = (*ep == ':') ? (int)strtol(ep + 1, NULL, 10)
	                                   : INT_MAX;
}

/*
 * Parsed once from SFTP_FAULT_PROTOCOL=<bytes>[:<max_kills>].
 *   bytes     — worker fires a protocol violation after sending this many bytes.
 *   max_kills — optional; at most this many workers trigger the fault.
 * Example: SFTP_FAULT_PROTOCOL=150000:1  triggers one protocol violation.
 */
static void
fi_pv_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_PROTOCOL");
	if (ev == NULL)
		return;
	char *ep;
	uint64_t bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fi_pv_state.threshold  = bytes;
	fi_pv_state.kills_left = (*ep == ':') ? (int)strtol(ep + 1, NULL, 10)
	                                      : INT_MAX;
}
#endif /* HPN_FAULT_INJECTION */

struct sftp_hpn_conn *
sftp_hpn_conn_init(void)
{
	return xcalloc(1, sizeof(struct sftp_hpn_conn));
}

void
sftp_hpn_conn_free(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	freezero(hpn, sizeof(*hpn));
}

/*
 * Internal helper called by sftp_conn_is_dead() in sftp-client.c.
 * Operates on struct sftp_hpn_conn directly to avoid a dependency on
 * the opaque struct sftp_conn definition.
 */
int
sftp_hpn_is_dead(struct sftp_hpn_conn *hpn)
{
	return hpn != NULL && hpn->dead;
}

int
sftp_hpn_is_protocol_violation(struct sftp_hpn_conn *hpn)
{
	return hpn != NULL && hpn->protocol_violation;
}

void
sftp_hpn_set_protocol_violation(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	hpn->dead = 1;
	hpn->protocol_violation = 1;
}

/*
 * Mark a connection as dead with prominent diagnostic logging, without
 * terminating the process. See header comment for full semantics.
 *
 * Implementation detail: format the message into a stack buffer (avoid
 * heap allocation in error paths), call error() at the standard ERROR
 * log level, then set hpn->dead so subsequent RPC calls bail.
 */
void
sftp_hpn_conn_die(struct sftp_hpn_conn *hpn, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	/* Distinctive prefix so these are easy to grep out of logs:
	 * "sftp: connection died: <reason>" */
	error("sftp: connection died: %s", buf);

	if (hpn != NULL)
		hpn->dead = 1;
}

/*
 * Internal helper called by sftp_set_live_counter() in sftp-client.c.
 * Registers the parallel orchestrator's live-bytes counter and arms the
 * fault injection threshold if SFTP_FAULT_INJECT is set (TEST/DEBUG).
 */
void
sftp_hpn_set_live_counter(struct sftp_hpn_conn *hpn, volatile uint64_t *counter)
{
	if (hpn == NULL)
		return;
	hpn->live_counter = counter;

#ifdef HPN_FAULT_INJECTION
	pthread_once(&fi_state.once, fi_state_init);
	if (fi_state.threshold > 0) {
		hpn->fault_after_bytes = fi_state.threshold;
		error("sftp: fault injection enabled: "
		    "connection will die after %llu bytes sent",
		    (unsigned long long)fi_state.threshold);
	}
	pthread_once(&fi_pv_state.once, fi_pv_state_init);
	if (fi_pv_state.threshold > 0) {
		hpn->fault_pv_after_bytes = fi_pv_state.threshold;
		error("sftp: protocol-violation fault injection enabled: "
		    "connection will report protocol violation after %llu bytes sent",
		    (unsigned long long)fi_pv_state.threshold);
	}
#endif /* HPN_FAULT_INJECTION */
}

#ifdef HPN_FAULT_INJECTION
/*
 * Called by send_msg after each successful write.  Accumulates bytes sent
 * and fires the first armed fault trigger whose threshold is reached.
 * Protocol-violation fault (SFTP_FAULT_PROTOCOL) is checked first; connection-
 * death fault (SFTP_FAULT_INJECT) is checked second.  Each uses an independent
 * atomic kill-slot counter so exactly max_kills workers trigger the fault.
 *
 * Returns 0 normally.
 * Returns -1 and sets hpn->dead (and hpn->protocol_violation if applicable)
 * when a fault fires; the caller must close the connection file descriptors.
 */
int
sftp_hpn_check_fault(struct sftp_hpn_conn *hpn, size_t bytes)
{
	if (hpn == NULL)
		return 0;

	/* Only accumulate if at least one fault type is armed. */
	if (hpn->fault_after_bytes == 0 && hpn->fault_pv_after_bytes == 0)
		return 0;

	hpn->fault_bytes_sent += bytes;

	/* Check protocol-violation fault first (higher priority signal). */
	if (hpn->fault_pv_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_pv_after_bytes) {
		int prev = __atomic_fetch_sub(&fi_pv_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating protocol "
			    "violation after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			sftp_hpn_set_protocol_violation(hpn);
			return -1;
		}
		/* No slot — restore and disarm for this connection. */
		__atomic_fetch_add(&fi_pv_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		hpn->fault_pv_after_bytes = 0;
	}

	/* Check connection-death fault. */
	if (hpn->fault_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_after_bytes) {
		int prev = __atomic_fetch_sub(&fi_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating connection "
			    "death after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			hpn->dead = 1;
			return -1;
		}
		/* No slot — restore and disarm for this connection. */
		__atomic_fetch_add(&fi_state.kills_left, 1, __ATOMIC_SEQ_CST);
		hpn->fault_after_bytes = 0;
	}

	return 0;
}
#endif /* HPN_FAULT_INJECTION */

/* ── BEGIN Phase 5: hpn-bundle-fetch download ─────────────────────────────
 *
 * Implements the client side of `hpn-bundle-fetch@hpnssh.org`.  Symmetric
 * twin of sftp_hpn_bundle_upload (defined later in this file).  Both
 * live in this HPN-only module so the bundle wire protocol stays out
 * of the upstream-aligned sftp-client.c.
 *
 * Wire protocol:
 *
 *   client → server  SSH_FXP_EXTENDED { id,
 *                       "hpn-bundle-fetch@hpnssh.org",
 *                       u32 flags,
 *                       u32 n_paths,
 *                       cstring path_0 … cstring path_{n-1} }
 *   server → client  SSH_FXP_HANDLE   { id, handle }
 *
 *   client drains tar bytes via repeated SSH_FXP_READ on `handle` until
 *   SSH2_FX_EOF, then SSH_FXP_CLOSE.  Server's process_read routes
 *   bundle-handle reads to sftp_hpn_server_bundle_read (returns bytes
 *   from a pre-packed accumulator).
 *
 * Per-entry result accounting: server packs every requested path it can
 * read (skipping unreadable ones).  Client tracks each tar record it
 * extracts and marks the matching entry as ok; entries that never appear
 * in the tar stay marked -1.  Path matching is on the tar header
 * pathname, which the server sets to the original remote_path.
 */

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sftp-common.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-bundle.h"

/*
 * Match a tar record pathname back to an entries[] slot.  Server-side
 * packing uses the verbatim remote_path as the pathname, so this is an
 * exact string match.  Linear scan — bundles are 32–256 entries; not
 * worth a hash.
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

/* mkdir -p for a local directory path.  Used so tar entries like
 * a/b/c.dat get parent directories created at extract time. */
static int
bundle_dl_mkdir_p(const char *dirpath, mode_t mode)
{
	char *copy, *p;
	int rc = 0;

	if (dirpath == NULL || *dirpath == '\0')
		return -1;
	copy = xstrdup(dirpath);
	p = copy;
	if (*p == '/')
		p++;
	for (; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(copy, mode) != 0 && errno != EEXIST) {
			rc = -1;
			goto out;
		}
		*p = '/';
	}
	if (mkdir(copy, mode) != 0 && errno != EEXIST)
		rc = -1;
 out:
	free(copy);
	return rc;
}

/*
 * Drain READ replies until we have at least one byte to give back,
 * EOF, or an error.  Stores result in `*out` and `*out_len`.
 * Returns 0 on success (including EOF, where *out_len == 0),
 * -1 on transport/protocol failure.
 */
static int
bundle_dl_read_one(struct sftp_conn *conn, const u_char *handle,
    size_t handle_len, uint64_t off, u_int chunk,
    u_char **out, size_t *out_len, int *eof_out)
{
	struct sshbuf *msg = NULL;
	u_int read_id, recv_id, status;
	u_char type;
	int r;

	*out = NULL;
	*out_len = 0;
	*eof_out = 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	read_id = sftp_conn_alloc_msg_id(conn);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, read_id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, off)) != 0 ||
	    (r = sshbuf_put_u32(msg, chunk)) != 0) {
		error_f("compose hpn-bundle-fetch READ: %s", ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	if (send_msg(conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}
	sshbuf_reset(msg);

	if (get_msg(conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &recv_id)) != 0) {
		error_f("parse hpn-bundle-fetch reply header: %s", ssh_err(r));
		sshbuf_free(msg);
		return -1;
	}
	if (recv_id != read_id) {
		error_f("hpn-bundle-fetch: id mismatch want=%u got=%u",
		    read_id, recv_id);
		sshbuf_free(msg);
		return -1;
	}

	if (type == SSH2_FXP_DATA) {
		u_char *data = NULL;
		size_t  dlen = 0;
		if ((r = sshbuf_get_string(msg, &data, &dlen)) != 0) {
			error_f("parse hpn-bundle-fetch DATA: %s", ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		*out = data;
		*out_len = dlen;
		sshbuf_free(msg);
		return 0;
	}
	if (type == SSH2_FXP_STATUS) {
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("parse hpn-bundle-fetch STATUS: %s",
			    ssh_err(r));
			sshbuf_free(msg);
			return -1;
		}
		sshbuf_free(msg);
		if (status == SSH2_FX_EOF) {
			*eof_out = 1;
			return 0;
		}
		error_f("hpn-bundle-fetch server error: %u", status);
		return -1;
	}
	error_f("hpn-bundle-fetch: unexpected reply type %u", (unsigned)type);
	sshbuf_free(msg);
	return -1;
}

/*
 * libarchive read-callback context: holds a single staged buffer
 * returned by bundle_dl_read_one.  archive_read_open_callback hands
 * libarchive a pointer/length pair on each callback call; we satisfy
 * by streaming one SFTP READ reply at a time.
 */
struct bundle_dl_read_ctx {
	struct sftp_conn *conn;
	const u_char     *handle;
	size_t            handle_len;
	uint64_t          off;        /* next READ offset */
	u_int             chunk;      /* per-READ length */
	int               eof;
	u_char           *staged;     /* current staged buffer (free on next call) */
	size_t            staged_len;
};

static la_ssize_t
bundle_dl_archive_read_cb(struct archive *a, void *client_data,
    const void **buf_out)
{
	struct bundle_dl_read_ctx *ctx = client_data;
	(void)a;

	free(ctx->staged);
	ctx->staged = NULL;
	ctx->staged_len = 0;

	if (ctx->eof) {
		*buf_out = NULL;
		return 0;
	}

	if (bundle_dl_read_one(ctx->conn, ctx->handle, ctx->handle_len,
	    ctx->off, ctx->chunk, &ctx->staged, &ctx->staged_len,
	    &ctx->eof) != 0)
		return -1;

	if (ctx->staged_len == 0 || ctx->eof) {
		*buf_out = NULL;
		return 0;
	}
	ctx->off += ctx->staged_len;
	*buf_out = ctx->staged;
	return (la_ssize_t)ctx->staged_len;
}

/*
 * Extract one tar record into entries[entry_idx].local_path.  Returns 0
 * on success, -1 on per-file failure (caller continues with next entry).
 */
static int
bundle_dl_extract_one(struct archive *a, struct archive_entry *ae,
    const char *local_path, int preserve)
{
	int fd = -1;
	int rc = -1;

	/* Create parent directories.  dirname() may modify its arg. */
	{
		char *tmp = xstrdup(local_path);
		char *dir = dirname(tmp);
		if (dir != NULL && *dir != '\0' &&
		    strcmp(dir, ".") != 0 &&
		    bundle_dl_mkdir_p(dir, 0755) != 0 &&
		    errno != EEXIST) {
			error_f("mkdir_p \"%s\": %s", dir, strerror(errno));
			free(tmp);
			goto out;
		}
		free(tmp);
	}

	mode_t perm = preserve ? (mode_t)(archive_entry_perm(ae) & 07777)
	                       : (mode_t)0644;
	fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, perm);
	if (fd < 0) {
		error_f("open \"%s\": %s", local_path, strerror(errno));
		goto out;
	}

	{
		const void *blk;
		size_t      blk_size;
		la_int64_t  blk_off;
		int ar;

		while ((ar = archive_read_data_block(a, &blk, &blk_size,
		    &blk_off)) == ARCHIVE_OK) {
			if (lseek(fd, (off_t)blk_off, SEEK_SET) ==
			    (off_t)-1) {
				error_f("lseek \"%s\": %s", local_path,
				    strerror(errno));
				goto out;
			}
			size_t left = blk_size;
			const u_char *p = blk;
			while (left > 0) {
				ssize_t n = write(fd, p, left);
				if (n < 0) {
					if (errno == EINTR)
						continue;
					error_f("write \"%s\": %s",
					    local_path, strerror(errno));
					goto out;
				}
				p    += n;
				left -= n;
			}
		}
		if (ar != ARCHIVE_EOF) {
			error_f("archive_read_data_block \"%s\": %s",
			    local_path, archive_error_string(a));
			goto out;
		}
	}

	if (preserve) {
		time_t mt = (time_t)archive_entry_mtime(ae);
		struct timespec ts[2];
		ts[0].tv_sec = mt; ts[0].tv_nsec = 0;
		ts[1].tv_sec = mt; ts[1].tv_nsec = 0;
		(void)futimens(fd, ts);
	}

	rc = 0;
 out:
	if (fd >= 0)
		(void)close(fd);
	return rc;
}

int
sftp_hpn_bundle_download(struct sftp_conn *conn,
    struct sftp_hpn_bundle_download_entry *entries, int n,
    int preserve_flag)
{
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t handle_len = 0;
	u_int  open_id, flags;
	struct archive *a = NULL;
	struct archive_entry *ae;
	struct bundle_dl_read_ctx ctx = { 0 };
	int i, r, rc = -1;

	for (i = 0; i < n; i++)
		entries[i].result = -1;

	if (n <= 0)
		return 0;
	if (!sftp_conn_has_hpn_bundle_fetch(conn)) {
		debug_f("hpn-bundle-fetch: server does not advertise extension");
		return -1;
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

	/* ── Drain tar bytes through libarchive and extract entries ──── */
	ctx.conn       = conn;
	ctx.handle     = handle;
	ctx.handle_len = handle_len;
	ctx.off        = 0;
	/* 128 KiB matches the upload-side HPN_BUNDLE_BLOCK_BYTES; aligns with
	 * the server's libarchive write-block boundary for cache friendliness. */
	ctx.chunk      = 128 * 1024;

	a = archive_read_new();
	if (a == NULL) {
		error_f("archive_read_new failed");
		goto cleanup;
	}
	if (archive_read_support_format_tar(a) != ARCHIVE_OK ||
	    archive_read_open(a, &ctx, NULL,
	        bundle_dl_archive_read_cb, NULL) != ARCHIVE_OK) {
		error_f("archive_read_open: %s", archive_error_string(a));
		goto cleanup;
	}

	while ((r = archive_read_next_header(a, &ae)) == ARCHIVE_OK) {
		const char *tar_path = archive_entry_pathname(ae);
		if (tar_path == NULL || *tar_path == '\0') {
			error_f("hpn-bundle-fetch: empty pathname in tar record");
			continue;
		}
		int idx = bundle_dl_lookup_entry(entries, n, tar_path);
		if (idx < 0) {
			debug_f("hpn-bundle-fetch: tar record \"%s\" "
			    "not in entries[]; skipping", tar_path);
			continue;
		}
		if (entries[idx].local_path == NULL) {
			error_f("hpn-bundle-fetch: entry %d local_path NULL",
			    idx);
			continue;
		}
		if (bundle_dl_extract_one(a, ae, entries[idx].local_path,
		    preserve_flag) == 0)
			entries[idx].result = 0;
	}
	if (r != ARCHIVE_EOF) {
		error_f("archive_read_next_header: %s", archive_error_string(a));
		goto cleanup;
	}

	rc = 0;

 cleanup:
	if (a != NULL) {
		archive_read_close(a);
		archive_read_free(a);
	}
	free(ctx.staged);

	/* Close the bundle handle.  We don't strictly need to wait for the
	 * STATUS — the server releases the accumulator either way — but
	 * draining it keeps the RPC stream tidy. */
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
		(void)get_msg(conn, msg);   /* consume STATUS reply */
		free(handle);
	}
	if (msg != NULL)
		sshbuf_free(msg);
	return rc;
}

/* ── BEGIN Phase 5: hpn-bundle upload ──────────────────────────────────────
 *
 * Implements the client side of `hpn-bundle-open@hpnssh.org`.  Many small
 * files are packed into a tar (ustar) byte stream by libarchive and
 * delivered to the server through a single OPEN, multiple WRITEs, and a
 * CLOSE on the SFTP connection.  Server-side handler (in sftp-hpn-server.c
 * process_hpn_bundle_open) feeds the bytes back through libarchive to
 * recreate the file tree.
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
 * live in sftp-hpn-bundle.h (included above) — single source of truth
 * shared with the server side. */

/*
 * Defensive cap on outstanding (unread) STATUS replies.  Each queued
 * STATUS is ~13 bytes on the wire, so 4096 is well under any plausible
 * socket / channel buffer.  In practice the default 4 MiB bundle at the
 * 128 KiB libarchive block size below queues only ~32 STATUSes per
 * bundle — the cap exists only so a user cranking HPNBundleSize very
 * high doesn't fill kernel buffers and deadlock.
 */
#define BUNDLE_MAX_INFLIGHT     4096

/*
 * Context for libarchive's write callback.  WRITEs are pipelined: each
 * callback invocation sends one SSH_FXP_WRITE without blocking on the
 * server's STATUS reply.  STATUSes accumulate in the SSH channel; they
 * are drained in bulk before SSH_FXP_CLOSE.
 *
 * Because rids come from sftp_conn_alloc_msg_id and SFTP replies are
 * returned in request order, we don't need to track each pending rid
 * individually — the rid of drain #k is simply first_rid + k.
 */
struct bundle_write_ctx {
	struct sftp_conn *conn;
	const u_char *handle;
	size_t        handle_len;
	off_t         offset;        /* monotonically increasing */
	int           any_fail;      /* sticky: any WRITE/STATUS failed */

	uint64_t      n_sent;        /* WRITEs sent */
	uint64_t      n_drained;     /* STATUS replies successfully drained */
	u_int         first_rid;     /* rid of WRITE #0; valid when n_sent > 0 */
};

/*
 * Drain up to `n` outstanding WRITE STATUS replies.  Pass SIZE_MAX to
 * drain all of them.  Sets ctx->any_fail on any read error or unexpected
 * reply; the caller is responsible for not issuing the SSH_FXP_CLOSE
 * before all WRITEs have been drained (otherwise the CLOSE STATUS would
 * be confused with a WRITE STATUS).
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

		sshbuf_reset(msg);
		if (get_msg(ctx->conn, msg) != 0) {
			error_f("bundle drain: connection closed waiting "
			    "for WRITE STATUS (drained %llu/%llu)",
			    (unsigned long long)ctx->n_drained,
			    (unsigned long long)ctx->n_sent);
			ctx->any_fail = 1;
			rc = -1;
			break;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &reply_rid)) != 0 ||
		    type != SSH2_FXP_STATUS ||
		    (r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("bundle drain: malformed STATUS reply "
			    "(type=%u r=%d)", type, r);
			ctx->any_fail = 1;
			rc = -1;
			break;
		}
		if (reply_rid != expected_rid) {
			error_f("bundle drain: rid mismatch "
			    "(got %u expected %u)", reply_rid, expected_rid);
			ctx->any_fail = 1;
			rc = -1;
			break;
		}
		if (status != SSH2_FX_OK) {
			error_f("bundle drain: WRITE STATUS %u "
			    "(rid=%u)", status, reply_rid);
			ctx->any_fail = 1;
			rc = -1;
			break;
		}
		ctx->n_drained++;
	}
	sshbuf_free(msg);
	return rc;
}

static la_ssize_t
bundle_archive_write_cb(struct archive *a, void *client_data,
    const void *buffer, size_t length)
{
	struct bundle_write_ctx *ctx = client_data;
	struct sshbuf *msg;
	u_int rid;
	int r;

	if (ctx->any_fail)
		return -1;

	/* Defensive drain: keep outstanding WRITEs bounded so kernel
	 * channel buffers don't fill on pathologically large bundles.
	 * For the default 4 MiB bundle / 128 KiB block this never trips. */
	if ((ctx->n_sent - ctx->n_drained) >= BUNDLE_MAX_INFLIGHT) {
		if (bundle_drain_n(ctx, BUNDLE_MAX_INFLIGHT / 2) < 0) {
			archive_set_error(a, EIO,
			    "bundle drain: server status failure");
			return -1;
		}
	}

	if ((msg = sshbuf_new()) == NULL) {
		archive_set_error(a, ENOMEM, "sshbuf_new failed");
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
		archive_set_error(a, EIO, "compose bundle WRITE: %s",
		    ssh_err(r));
		sshbuf_free(msg);
		ctx->any_fail = 1;
		return -1;
	}
	send_msg(ctx->conn, msg);
	sshbuf_free(msg);

	ctx->n_sent++;
	ctx->offset += (off_t)length;
	/* STATUS reply for this WRITE is left in the channel buffer; the
	 * close-time drain (in sftp_hpn_bundle_upload) reads it later. */
	return (la_ssize_t)length;
}

int
sftp_hpn_bundle_upload(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_hpn_bundle_upload_entry *entries, int n,
    int preserve_flag, int fsync_flag)
{
	struct sshbuf *msg = NULL;
	u_char *handle = NULL;
	size_t handle_len = 0;
	u_int open_id;
	u_int flags;
	struct archive *a = NULL;
	struct bundle_write_ctx ctx = { 0 };
	int i, r;
	int rc = -1;

	for (i = 0; i < n; i++)
		entries[i].result = -1;   /* pessimistic; flip to 0 on success */

	if (n <= 0)
		return 0;
	if (!sftp_conn_has_hpn_bundle(conn)) {
		debug_f("hpn-bundle: server does not advertise extension");
		return -1;
	}

	debug_f("hpn-bundle upload: n=%d dest=\"%s\" preserve=%d fsync=%d",
	    n, remote_dest_dir, preserve_flag, fsync_flag);

	/* ── Send hpn-bundle-open@hpnssh.org and collect HANDLE ─────────── */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	open_id = sftp_conn_alloc_msg_id(conn);
	flags = (preserve_flag ? HPN_BUNDLE_FLAG_PRESERVE : 0)
	      | (fsync_flag    ? HPN_BUNDLE_FLAG_FSYNC    : 0);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, open_id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hpn-bundle-open@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_cstring(msg, remote_dest_dir)) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0)
		fatal_fr(r, "compose hpn-bundle-open");
	send_msg(conn, msg);
	sshbuf_reset(msg);

	handle = get_handle(conn, open_id, &handle_len,
	    "hpn-bundle-open \"%s\"", remote_dest_dir);
	if (handle == NULL) {
		debug_f("hpn-bundle: server refused open");
		goto cleanup;
	}

	/* ── Stream tar bytes through libarchive ────────────────────────── */
	ctx.conn       = conn;
	ctx.handle     = handle;
	ctx.handle_len = handle_len;

	a = archive_write_new();
	if (a == NULL)
		fatal_f("archive_write_new failed");
	/* ustar is the universal "tar" format.  Could be pax for larger
	 * filenames / timestamps, but ustar is the lowest common denominator. */
	if (archive_write_set_format_ustar(a) != ARCHIVE_OK ||
	    archive_write_set_bytes_per_block(a, HPN_BUNDLE_BLOCK_BYTES)
	        != ARCHIVE_OK ||
	    archive_write_open(a, &ctx, NULL,
	        bundle_archive_write_cb, NULL) != ARCHIVE_OK) {
		error_f("libarchive setup: %s", archive_error_string(a));
		goto cleanup;
	}

	for (i = 0; i < n; i++) {
		struct archive_entry *ae;
		int fd;
		struct stat sb;
		off_t bytes_remaining;
		u_char buf[65536];

		fd = open(entries[i].local_path, O_RDONLY);
		if (fd < 0) {
			error("hpn-bundle: open local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			/* Skip this entry; remaining files still uploaded. */
			continue;
		}
		if (fstat(fd, &sb) < 0) {
			error("hpn-bundle: fstat \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			close(fd);
			continue;
		}

		ae = archive_entry_new();
		archive_entry_set_pathname(ae, entries[i].remote_path);
		archive_entry_set_size(ae, (la_int64_t)sb.st_size);
		archive_entry_set_filetype(ae, AE_IFREG);
		if (preserve_flag) {
			archive_entry_set_perm(ae, sb.st_mode & 07777);
			archive_entry_set_mtime(ae, sb.st_mtime, 0);
		} else {
			archive_entry_set_perm(ae, 0644);
			archive_entry_set_mtime(ae, time(NULL), 0);
		}
		if (archive_write_header(a, ae) != ARCHIVE_OK) {
			error_f("libarchive write_header for \"%s\": %s",
			    entries[i].remote_path, archive_error_string(a));
			archive_entry_free(ae);
			close(fd);
			goto cleanup;
		}

		bytes_remaining = sb.st_size;
		while (bytes_remaining > 0) {
			ssize_t got = read(fd, buf,
			    (size_t)(bytes_remaining < (off_t)sizeof(buf)
			        ? bytes_remaining : (off_t)sizeof(buf)));
			if (got <= 0) {
				error("hpn-bundle: read \"%s\": %s",
				    entries[i].local_path,
				    got < 0 ? strerror(errno) : "EOF");
				archive_entry_free(ae);
				close(fd);
				goto cleanup;
			}
			if (archive_write_data(a, buf, (size_t)got) < 0) {
				error_f("libarchive write_data \"%s\": %s",
				    entries[i].remote_path,
				    archive_error_string(a));
				archive_entry_free(ae);
				close(fd);
				goto cleanup;
			}
			bytes_remaining -= got;
		}

		archive_entry_free(ae);
		close(fd);
		entries[i].result = 0;
	}

	if (archive_write_close(a) != ARCHIVE_OK) {
		error_f("libarchive write_close: %s", archive_error_string(a));
		goto cleanup;
	}

	/* Drain the deferred WRITE STATUSes before we send SSH_FXP_CLOSE —
	 * otherwise the CLOSE reply would interleave with leftover WRITE
	 * replies in the channel and the rid match would fail. */
	if (bundle_drain_n(&ctx, SIZE_MAX) < 0) {
		debug_f("hpn-bundle: WRITE drain reported failure");
		goto cleanup;
	}
	if (ctx.any_fail) {
		debug_f("hpn-bundle: WRITE phase reported failure");
		goto cleanup;
	}

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
		    (r = sshbuf_get_u32(msg, &reply_rid)) != 0 ||
		    type != SSH2_FXP_STATUS ||
		    (r = sshbuf_get_u32(msg, &status)) != 0) {
			error_f("hpn-bundle: malformed CLOSE reply");
			goto cleanup;
		}
		if (reply_rid != close_id || status != SSH2_FX_OK) {
			error_f("hpn-bundle: CLOSE failed status=%u "
			    "(rid=%u expected %u)",
			    status, reply_rid, close_id);
			goto cleanup;
		}
	}

	rc = 0;   /* success — entries[].result already set to 0 above */

 cleanup:
	/* If we sent WRITEs but bailed before draining, the channel still
	 * has the matching STATUSes queued.  Try to consume them so the
	 * next operation on this conn doesn't read them as its own reply.
	 * If the drain itself fails (e.g. connection died), mark the conn
	 * dead so the orchestrator tears down this worker — leaving the
	 * channel in an undefined state would corrupt later transfers. */
	if (rc != 0 && ctx.n_sent > ctx.n_drained) {
		int saved_fail = ctx.any_fail;
		ctx.any_fail = 0;
		if (bundle_drain_n(&ctx, SIZE_MAX) < 0)
			sftp_conn_set_dead(conn);
		ctx.any_fail = saved_fail;
	}
	if (rc != 0) {
		for (i = 0; i < n; i++)
			entries[i].result = -1;
	}
	if (a != NULL)
		archive_write_free(a);
	free(handle);
	if (msg != NULL)
		sshbuf_free(msg);
	return rc;
}

/* ── END Phase 5 ───────────────────────────────────────────────────────── */
