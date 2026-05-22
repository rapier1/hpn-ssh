/* $OpenBSD: sftp-client.c,v 1.185 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* XXX: memleaks */
/* XXX: signed vs unsigned */
/* XXX: remove all logging, only return status codes */
/* XXX: copy between two remote sites */

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/uio.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"
#include "atomicio.h"
#include "progressmeter.h"
#include "misc.h"
#include "utf8.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-hpn.h" /* HPN */

extern volatile sig_atomic_t interrupted;
extern int showprogress;

/*
 * Per-stream isolation audit (feature-parallel-streams, Phase 1 step 1).
 *
 * Every API in this file accepts struct sftp_conn *, and that struct (defined
 * below) holds all per-connection state: fd pair, request ID counter,
 * protocol version, server extension bits, and bandwidth limiters. The file
 * has no file-scope state that requires locking; helper functions are
 * stateless or take state through parameters. Two extern globals
 * (interrupted, showprogress) are read-only from here. Two struct sftp_conn
 * instances can therefore coexist in separate threads without sharing state,
 * provided each owns a distinct fd pair and is touched by at most one thread
 * at a time.
 *
 * Concurrency hazards live OUTSIDE this file:
 *   - progressmeter.c is a single global; concurrent start/stop/refresh from
 *     workers will collide. Parallel mode must use aggregate-driven progress
 *     reporting rather than per-file calls into start_progress_meter.
 *     Verified (Phase 1 step 3): every start_progress_meter / stop_progress_meter
 *     call site in this file is guarded by the extern int showprogress, so
 *     the orchestrator can suppress per-file calls by setting showprogress=0
 *     before invoking sftp_download/sftp_upload from workers, then drive a
 *     single aggregate progress meter from the producer/reporter thread.
 *   - progressmeter.c installs a SIGALRM handler. Under pthreads the worker
 *     threads must mask SIGALRM so timer ticks deliver only to the
 *     producer/main thread.
 *   - sftp.c keeps a single sshpid; the parallel orchestrator tracks an
 *     array of pids (master + N workers).
 *
 * If any new file-scope state is introduced here, parallelizability must be
 * reconsidered.
 */

/* Default size of buffer for up/download (fix sftp.1 scp.1 if changed) */
#define DEFAULT_COPY_BUFLEN	131072	/* 128 KB; raised from 32 KB for HPN */

/* Default number of concurrent xfer requests (fix sftp.1 scp.1 if changed) */
/* 1024 xfer requests * 128 KB = 128 MB in-flight; sized to not cap HPN channel window */
#define DEFAULT_NUM_REQUESTS	1024

/* Minimum amount of data to read at a time */
#define MIN_READ_SIZE	512

/* Maximum depth to descend in directory trees */
#define MAX_DIR_DEPTH 64

/* Directory separator characters */
#ifdef HAVE_CYGWIN
# define SFTP_DIRECTORY_CHARS      "/\\"
#else /* HAVE_CYGWIN */
# define SFTP_DIRECTORY_CHARS      "/"
#endif /* HAVE_CYGWIN */

struct sftp_conn {
	int fd_in;
	int fd_out;
	struct sftp_hpn_conn *hpn;  /* HPN: per-connection extensions (dead flag,
				     * live counter, fault injection) */
	u_int download_buflen;
	u_int upload_buflen;
	u_int num_requests;
	u_int version;
	u_int msg_id;
#define SFTP_EXT_POSIX_RENAME		0x00000001
#define SFTP_EXT_STATVFS		0x00000002
#define SFTP_EXT_FSTATVFS		0x00000004
#define SFTP_EXT_HARDLINK		0x00000008
#define SFTP_EXT_FSYNC			0x00000010
#define SFTP_EXT_LSETSTAT		0x00000020
#define SFTP_EXT_LIMITS			0x00000040
#define SFTP_EXT_PATH_EXPAND		0x00000080
#define SFTP_EXT_COPY_DATA		0x00000100
#define SFTP_EXT_GETUSERSGROUPS_BY_ID	0x00000200
#define SFTP_EXT_HPN_FS_INFO		0x00000400
#define SFTP_EXT_HPN_BUNDLE		0x00000800
	u_int exts;
	uint64_t limit_kbps;
	struct bwlimit bwlimit_in, bwlimit_out;
};

/* Tracks in-progress requests during file transfers */
struct request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

static u_char *
get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...) __attribute__((format(printf, 4, 5)));

static struct request *
request_enqueue(struct requests *requests, u_int id, size_t len,
    uint64_t offset)
{
	struct request *req;

	req = xcalloc(1, sizeof(*req));
	req->id = id;
	req->len = len;
	req->offset = offset;
	TAILQ_INSERT_TAIL(requests, req, tq);
	return req;
}

static struct request *
request_find(struct requests *requests, u_int id)
{
	struct request *req;

	for (req = TAILQ_FIRST(requests);
	    req != NULL && req->id != id;
	    req = TAILQ_NEXT(req, tq))
		;
	return req;
}

static int
sftpio(void *_bwlimit, size_t amount)
{
	struct bwlimit *bwlimit = (struct bwlimit *)_bwlimit;

	refresh_progress_meter(0);
	if (bwlimit != NULL)
		bandwidth_limit(bwlimit, amount);
	return 0;
}

static int
send_msg(struct sftp_conn *conn, struct sshbuf *m)
{
	u_char mlen[4];
	struct iovec iov[2];
	size_t msg_len = sshbuf_len(m);

	if (conn->hpn->dead) /* HPN */
		return -1;

	if (msg_len > SFTP_MAX_MSG_LENGTH)
		fatal("Outbound message too long %zu", msg_len);

	/* Send length first */
	put_u32(mlen, msg_len);
	iov[0].iov_base = mlen;
	iov[0].iov_len = sizeof(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = msg_len;

	if (atomiciov6(writev, conn->fd_out, iov, 2, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : NULL) !=
	    msg_len + sizeof(mlen)) {
		error("sftp: send: %s", strerror(errno));
		conn->hpn->dead = 1; /* HPN */
		sshbuf_reset(m);
		return -1;
	}

	sshbuf_reset(m);

#ifdef HPN_FAULT_INJECTION
	if (sftp_hpn_check_fault(conn->hpn, msg_len + sizeof(mlen)) != 0) {
		close(conn->fd_in);
		close(conn->fd_out);
		conn->fd_in = conn->fd_out = -1;
		return -1;
	}
#endif /* HPN_FAULT_INJECTION */

	return 0;
}

static int
get_msg_extended(struct sftp_conn *conn, struct sshbuf *m, int initial)
{
	u_int msg_len;
	u_char *p;
	int r;

	if (conn->hpn->dead) /* HPN */
		return -1;

	sshbuf_reset(m);
	if ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	if (atomicio6(read, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL) != 4) {
		if (errno == EPIPE || errno == ECONNRESET)
			debug("sftp: connection closed");
		else
			debug("sftp: read: %s", strerror(errno));
		conn->hpn->dead = 1; /* HPN */
		return -1;
	}

	if ((r = sshbuf_get_u32(m, &msg_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", msg_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	if ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	if (atomicio6(read, conn->fd_in, p, msg_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL)
	    != msg_len) {
		if (errno == EPIPE)
			debug("sftp: connection closed");
		else
			debug("sftp: read: %s", strerror(errno));
		conn->hpn->dead = 1; /* HPN */
		return -1;
	}
	return 0;
}

static int
get_msg(struct sftp_conn *conn, struct sshbuf *m)
{
	return get_msg_extended(conn, m, 0);
}

static void
send_string_request(struct sftp_conn *conn, u_int id, u_int code, const char *s,
    u_int len)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
	sshbuf_free(msg);
}

static void
send_string_attrs_request(struct sftp_conn *conn, u_int id, u_int code,
    const void *s, u_int len, Attrib *a)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
	sshbuf_free(msg);
}

static u_int
get_status(struct sftp_conn *conn, u_int expected_id)
{
	struct sshbuf *msg;
	u_char type;
	u_int id, status;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (get_msg(conn, msg) != 0) {
		sshbuf_free(msg);
		return SSH2_FX_CONNECTION_LOST;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "compose");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) — possible MITM or "
		    "server protocol corruption", id, expected_id);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}
	if (type != SSH2_FXP_STATUS) {
		error_f("expected SSH2_FXP_STATUS(%u) packet, got %u — "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_STATUS, type);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}

	if ((r = sshbuf_get_u32(msg, &status)) != 0)
		fatal_fr(r, "parse");
	sshbuf_free(msg);

	debug3("SSH2_FXP_STATUS %u", status);

	return status;
}

static u_char *
get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...)
{
	struct sshbuf *msg;
	u_int id, status;
	u_char type;
	u_char *handle;
	char errmsg[256];
	va_list args;
	int r;

	va_start(args, errfmt);
	if (errfmt != NULL)
		vsnprintf(errmsg, sizeof(errmsg), errfmt, args);
	va_end(args);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (get_msg(conn, msg) != 0) {
		sshbuf_free(msg);
		return NULL;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error("%s: ID mismatch (%u != %u) — possible MITM or "
		    "server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, id, expected_id);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return NULL;
	}
	if (type == SSH2_FXP_STATUS) {
		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		if (errfmt != NULL)
			error("%s: %s", errmsg, fx2txt(status));
		sshbuf_free(msg);
		return NULL;
	} else if (type != SSH2_FXP_HANDLE) {
		error("%s: expected SSH2_FXP_HANDLE(%u) packet, got %u — "
		    "possible MITM or server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, SSH2_FXP_HANDLE, type);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return NULL;
	}

	if ((r = sshbuf_get_string(msg, &handle, len)) != 0)
		fatal_fr(r, "parse handle");
	sshbuf_free(msg);

	return handle;
}

static int
get_decode_stat(struct sftp_conn *conn, u_int expected_id, int quiet, Attrib *a)
{
	struct sshbuf *msg;
	u_int id;
	u_char type;
	int r;
	Attrib attr;

	if (a != NULL)
		memset(a, '\0', sizeof(*a));
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (get_msg(conn, msg) != 0) {
		sshbuf_free(msg);
		return -1;
	}

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) — possible MITM or "
		    "server protocol corruption", id, expected_id);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return -1;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		if (quiet)
			debug("stat remote: %s", fx2txt(status));
		else
			error("stat remote: %s", fx2txt(status));
		sshbuf_free(msg);
		return -1;
	} else if (type != SSH2_FXP_ATTRS) {
		error_f("expected SSH2_FXP_ATTRS(%u) packet, got %u — "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_ATTRS, type);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return -1;
	}
	if ((r = decode_attrib(msg, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		sshbuf_free(msg);
		return -1;
	}
	/* success */
	if (a != NULL)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);
	sshbuf_free(msg);

	return 0;
}

static int
get_decode_statvfs(struct sftp_conn *conn, struct sftp_statvfs *st,
    u_int expected_id, int quiet)
{
	struct sshbuf *msg;
	u_char type;
	u_int id;
	uint64_t flag;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg(conn, msg);

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) — possible MITM or "
		    "server protocol corruption", id, expected_id);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return -1;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		if (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		else
			error("remote statvfs: %s", fx2txt(status));
		sshbuf_free(msg);
		return -1;
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, "
		    "got %u — possible MITM or server protocol corruption",
		    SSH2_FXP_EXTENDED_REPLY, type);
		sshbuf_free(msg);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return -1;
	}

	memset(st, 0, sizeof(*st));
	if ((r = sshbuf_get_u64(msg, &st->f_bsize)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_frsize)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_blocks)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_bfree)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_bavail)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_files)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_ffree)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_favail)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_fsid)) != 0 ||
	    (r = sshbuf_get_u64(msg, &flag)) != 0 ||
	    (r = sshbuf_get_u64(msg, &st->f_namemax)) != 0)
		fatal_fr(r, "parse statvfs");

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

	sshbuf_free(msg);

	return 0;
}

struct sftp_conn *
sftp_init(int fd_in, int fd_out, u_int transfer_buflen, u_int num_requests,
    uint64_t limit_kbps)
{
	u_char type;
	struct sshbuf *msg;
	struct sftp_conn *ret;
	int r;

	ret = xcalloc(1, sizeof(*ret));
	ret->hpn = sftp_hpn_conn_init(); /* HPN */
	ret->msg_id = 1;
	ret->fd_in = fd_in;
	ret->fd_out = fd_out;
	ret->download_buflen = ret->upload_buflen =
	    transfer_buflen ? transfer_buflen : DEFAULT_COPY_BUFLEN;
	ret->num_requests =
	    num_requests ? num_requests : DEFAULT_NUM_REQUESTS;
	ret->exts = 0;
	ret->limit_kbps = 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_msg(ret, msg);

	get_msg_extended(ret, msg, 1);

	/* Expecting a VERSION reply */
	if ((r = sshbuf_get_u8(msg, &type)) != 0)
		fatal_fr(r, "parse type");
	if (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(msg);
		free(ret);
		return(NULL);
	}
	if ((r = sshbuf_get_u32(msg, &ret->version)) != 0)
		fatal_fr(r, "parse version");

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	while (sshbuf_len(msg) > 0) {
		char *name;
		u_char *value;
		size_t vlen;
		int known = 0;

		if ((r = sshbuf_get_cstring(msg, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string(msg, &value, &vlen)) != 0)
			fatal_fr(r, "parse extension");
		if (strcmp(name, "posix-rename@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_POSIX_RENAME;
			known = 1;
		} else if (strcmp(name, "statvfs@openssh.com") == 0 &&
		    strcmp((char *)value, "2") == 0) {
			ret->exts |= SFTP_EXT_STATVFS;
			known = 1;
		} else if (strcmp(name, "fstatvfs@openssh.com") == 0 &&
		    strcmp((char *)value, "2") == 0) {
			ret->exts |= SFTP_EXT_FSTATVFS;
			known = 1;
		} else if (strcmp(name, "hardlink@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_HARDLINK;
			known = 1;
		} else if (strcmp(name, "fsync@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_FSYNC;
			known = 1;
		} else if (strcmp(name, "lsetstat@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_LSETSTAT;
			known = 1;
		} else if (strcmp(name, "limits@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_LIMITS;
			known = 1;
		} else if (strcmp(name, "expand-path@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_PATH_EXPAND;
			known = 1;
		} else if (strcmp(name, "copy-data") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_COPY_DATA;
			known = 1;
		} else if (strcmp(name,
		    "users-groups-by-id@openssh.com") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_GETUSERSGROUPS_BY_ID;
			known = 1;
		} else if (strcmp(name, "hpn-fs-info@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_HPN_FS_INFO;
			known = 1;
		} else if (strcmp(name, "hpn-bundle@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* Phase 5: server can accept tar-format bundles via
			 * the hpn-bundle-open@hpnssh.org extension. */
			ret->exts |= SFTP_EXT_HPN_BUNDLE;
			known = 1;
		}
		if (known) {
			debug2("Server supports extension \"%s\" revision %s",
			    name, value);
		} else {
			debug2("Unrecognised server extension \"%s\"", name);
		}
		free(name);
		free(value);
	}

	sshbuf_free(msg);

	/* Query the server for its limits */
	if (ret->exts & SFTP_EXT_LIMITS) {
		struct sftp_limits limits;
		if (sftp_get_limits(ret, &limits) != 0)
			fatal_f("limits failed");

		/* If the caller did not specify, find a good value */
		if (transfer_buflen == 0) {
			ret->download_buflen = MINIMUM(limits.read_length,
			    SFTP_MAX_MSG_LENGTH - 1024);
			ret->upload_buflen = MINIMUM(limits.write_length,
			    SFTP_MAX_MSG_LENGTH - 1024);
			ret->download_buflen = MAXIMUM(ret->download_buflen, 64);
			ret->upload_buflen = MAXIMUM(ret->upload_buflen, 64);
			debug3("server upload/download buffer sizes "
			    "%llu / %llu; using %u / %u",
			    (unsigned long long)limits.write_length,
			    (unsigned long long)limits.read_length,
			    ret->upload_buflen, ret->download_buflen);
		}
	}

	/* Some filexfer v.0 servers don't support large packets */
	if (ret->version == 0) {
		ret->download_buflen = MINIMUM(ret->download_buflen, 20480);
		ret->upload_buflen = MINIMUM(ret->upload_buflen, 20480);
	}

	ret->limit_kbps = limit_kbps;
	if (ret->limit_kbps > 0) {
		bandwidth_limit_init(&ret->bwlimit_in, ret->limit_kbps,
		    ret->download_buflen);
		bandwidth_limit_init(&ret->bwlimit_out, ret->limit_kbps,
		    ret->upload_buflen);
	}

	return ret;
}

void
sftp_free(struct sftp_conn *conn)
{
	if (conn == NULL)
		return;
	sftp_hpn_conn_free(conn->hpn); /* HPN */
	freezero(conn, sizeof(*conn));
}

u_int
sftp_proto_version(struct sftp_conn *conn)
{
	return conn->version;
}

/* HPN: thin wrappers — logic lives in sftp-client-hpn.c */
int
sftp_conn_is_dead(struct sftp_conn *conn)
{
	return conn != NULL && sftp_hpn_is_dead(conn->hpn);
}

int
sftp_conn_is_protocol_violation(struct sftp_conn *conn)
{
	return conn != NULL && sftp_hpn_is_protocol_violation(conn->hpn);
}

void
sftp_set_live_counter(struct sftp_conn *conn, volatile uint64_t *counter)
{
	if (conn != NULL)
		sftp_hpn_set_live_counter(conn->hpn, counter);
}

void
sftp_conn_die(struct sftp_conn *conn, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	sftp_hpn_conn_die(conn != NULL ? conn->hpn : NULL, "%s", buf);
}
/* END HPN */

int
sftp_get_limits(struct sftp_conn *conn, struct sftp_limits *limits)
{
	u_int id, msg_id;
	u_char type;
	struct sshbuf *msg;
	int r;

	if ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		return -1;
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message limits@openssh.com I:%u", id);

	get_msg(conn, msg);

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &msg_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, msg_id);
	if (id != msg_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    msg_id, id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		return -1;
	}
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		sshbuf_free(msg);
		return -1;
	}

	memset(limits, 0, sizeof(*limits));
	if ((r = sshbuf_get_u64(msg, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	sshbuf_free(msg);

	return 0;
}

int
sftp_close(struct sftp_conn *conn, const u_char *handle, u_int handle_len)
{
	u_int id, status;
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		debug("close remote: %s", fx2txt(status));

	sshbuf_free(msg);

	return status == SSH2_FX_OK ? 0 : -1;
}


static int
sftp_lsreaddir(struct sftp_conn *conn, const char *path, int print_flag,
    SFTP_DIRENT ***dir)
{
	struct sshbuf *msg;
	u_int count, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	int status = SSH2_FX_FAILURE;
	int r;

	if (dir)
		*dir = NULL;

	id = conn->msg_id++;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_msg(conn, msg);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	if (handle == NULL) {
		sshbuf_free(msg);
		return -1;
	}

	if (dir) {
		ents = 0;
		*dir = xcalloc(1, sizeof(**dir));
		(*dir)[0] = NULL;
	}

	for (; !interrupted;) {
		id = expected_id = conn->msg_id++;

		debug3("Sending SSH2_FXP_READDIR I:%u", id);

		sshbuf_reset(msg);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_READDIR)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
			fatal_fr(r, "compose READDIR");
		send_msg(conn, msg);

		sshbuf_reset(msg);

		get_msg(conn, msg);

		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");

		debug3("Received reply T:%u I:%u", type, id);

		if (id != expected_id) {
			error_f("ID mismatch (%u != %u) - possible protocol corruption",
			    id, expected_id);
			sftp_hpn_set_protocol_violation(conn->hpn);
			status = -1;
			goto out;
		}

		if (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			if ((r = sshbuf_get_u32(msg, &rstatus)) != 0)
				fatal_fr(r, "parse status");
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			if (rstatus == SSH2_FX_EOF)
				break;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			goto out;
		} else if (type != SSH2_FXP_NAME) {
			error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_NAME, type);
			sftp_hpn_set_protocol_violation(conn->hpn);
			status = -1;
			goto out;
		}

		if ((r = sshbuf_get_u32(msg, &count)) != 0)
			fatal_fr(r, "parse count");
		if (count > SSHBUF_SIZE_MAX)
			fatal_f("nonsensical number of entries");
		if (count == 0)
			break;
		debug3("Received %d SSH2_FXP_NAME responses", count);
		for (i = 0; i < count; i++) {
			char *filename, *longname;
			Attrib a;

			if ((r = sshbuf_get_cstring(msg, &filename,
			    NULL)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &longname,
			    NULL)) != 0)
				fatal_fr(r, "parse filenames");
			if ((r = decode_attrib(msg, &a)) != 0) {
				error_fr(r, "couldn't decode attrib");
				free(filename);
				free(longname);
				goto out;
			}

			if (print_flag)
				mprintf("%s\n", longname);

			/*
			 * Directory entries should never contain '/'
			 * These can be used to attack recursive ops
			 * (e.g. send '../../../../etc/passwd')
			 */
			if (strpbrk(filename, SFTP_DIRECTORY_CHARS) != NULL) {
				error("Server sent suspect path \"%s\" "
				    "during readdir of \"%s\"", filename, path);
			} else if (dir) {
				*dir = xreallocarray(*dir, ents + 2, sizeof(**dir));
				(*dir)[ents] = xcalloc(1, sizeof(***dir));
				(*dir)[ents]->filename = xstrdup(filename);
				(*dir)[ents]->longname = xstrdup(longname);
				memcpy(&(*dir)[ents]->a, &a, sizeof(a));
				(*dir)[++ents] = NULL;
			}
			free(filename);
			free(longname);
		}
	}
	status = 0;

 out:
	sshbuf_free(msg);
	sftp_close(conn, handle, handle_len);
	free(handle);

	if (status != 0 && dir != NULL) {
		/* Don't return results on error */
		sftp_free_dirents(*dir);
		*dir = NULL;
	} else if (interrupted && dir != NULL && *dir != NULL) {
		/* Don't return partial matches on interrupt */
		sftp_free_dirents(*dir);
		*dir = xcalloc(1, sizeof(**dir));
		**dir = NULL;
	}

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_readdir(struct sftp_conn *conn, const char *path, SFTP_DIRENT ***dir)
{
	return sftp_lsreaddir(conn, path, 0, dir);
}

void sftp_free_dirents(SFTP_DIRENT **s)
{
	int i;

	if (s == NULL)
		return;
	for (i = 0; s[i]; i++) {
		free(s[i]->filename);
		free(s[i]->longname);
		free(s[i]);
	}
	free(s);
}

int
sftp_rm(struct sftp_conn *conn, const char *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_REMOVE \"%s\"", path);

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_REMOVE, path, strlen(path));
	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote delete %s: %s", path, fx2txt(status));
	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_mkdir(struct sftp_conn *conn, const char *path, Attrib *a, int print_flag)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_MKDIR \"%s\"", path);

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_MKDIR, path,
	    strlen(path), a);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK && print_flag)
		error("remote mkdir \"%s\": %s", path, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_rmdir(struct sftp_conn *conn, const char *path)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_RMDIR \"%s\"", path);

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_RMDIR, path,
	    strlen(path));

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote rmdir \"%s\": %s", path, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_stat(struct sftp_conn *conn, const char *path, int quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_STAT \"%s\"", path);

	id = conn->msg_id++;

	send_string_request(conn, id,
	    conn->version == 0 ? SSH2_FXP_STAT_VERSION_0 : SSH2_FXP_STAT,
	    path, strlen(path));

	return get_decode_stat(conn, id, quiet, a);
}

int
sftp_lstat(struct sftp_conn *conn, const char *path, int quiet, Attrib *a)
{
	u_int id;

	if (conn->version == 0) {
		do_log2(quiet ? SYSLOG_LEVEL_DEBUG1 : SYSLOG_LEVEL_INFO,
		    "Server version does not support lstat operation");
		return sftp_stat(conn, path, quiet, a);
	}

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_LSTAT, path,
	    strlen(path));

	return get_decode_stat(conn, id, quiet, a);
}

#ifdef notyet
int
sftp_fstat(struct sftp_conn *conn, const u_char *handle, u_int handle_len,
    int quiet, Attrib *a)
{
	u_int id;

	debug2("Sending SSH2_FXP_FSTAT \"%s\"");

	id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_FSTAT, handle,
	    handle_len);

	return get_decode_stat(conn, id, quiet, a);
}
#endif

int
sftp_setstat(struct sftp_conn *conn, const char *path, Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_SETSTAT \"%s\"", path);

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_SETSTAT, path,
	    strlen(path), a);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote setstat \"%s\": %s", path, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_fsetstat(struct sftp_conn *conn, const u_char *handle, u_int handle_len,
    Attrib *a)
{
	u_int status, id;

	debug2("Sending SSH2_FXP_FSETSTAT");

	id = conn->msg_id++;
	send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT, handle,
	    handle_len, a);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote fsetstat: %s", fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

/* Implements both the realpath and expand-path operations */
static char *
sftp_realpath_expand(struct sftp_conn *conn, const char *path, int expand)
{
	struct sshbuf *msg;
	u_int expected_id, count, id;
	char *filename, *longname;
	Attrib a;
	u_char type;
	int r;
	const char *what = "SSH2_FXP_REALPATH";

	if (expand)
		what = "expand-path@openssh.com";
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	expected_id = id = conn->msg_id++;
	if (expand) {
		debug2("Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) "
		    "\"%s\"", path);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_cstring(msg,
		    "expand-path@openssh.com")) != 0 ||
		    (r = sshbuf_put_cstring(msg, path)) != 0)
			fatal_fr(r, "compose %s", what);
		send_msg(conn, msg);
	} else {
		debug2("Sending SSH2_FXP_REALPATH \"%s\"", path);
		send_string_request(conn, id, SSH2_FXP_REALPATH,
		    path, strlen(path));
	}
	get_msg(conn, msg);
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		return NULL;
	}

	if (type == SSH2_FXP_STATUS) {
		u_int status;
		char *errmsg;

		if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0)
			fatal_fr(r, "parse status");
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		sshbuf_free(msg);
		return NULL;
	} else if (type != SSH2_FXP_NAME) {
		error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_NAME, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		return NULL;
	}

	if ((r = sshbuf_get_u32(msg, &count)) != 0)
		fatal_fr(r, "parse count");
	if (count != 1)
		fatal("Got multiple names (%d) from %s", count, what);

	if ((r = sshbuf_get_cstring(msg, &filename, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &longname, NULL)) != 0 ||
	    (r = decode_attrib(msg, &a)) != 0)
		fatal_fr(r, "parse filename/attrib");

	debug3("%s %s -> %s", what, path, filename);

	free(longname);

	sshbuf_free(msg);

	return(filename);
}

char *
sftp_realpath(struct sftp_conn *conn, const char *path)
{
	return sftp_realpath_expand(conn, path, 0);
}

int
sftp_can_expand_path(struct sftp_conn *conn)
{
	return (conn->exts & SFTP_EXT_PATH_EXPAND) != 0;
}

char *
sftp_expand_path(struct sftp_conn *conn, const char *path)
{
	if (!sftp_can_expand_path(conn)) {
		debug3_f("no server support, fallback to realpath");
		return sftp_realpath_expand(conn, path, 0);
	}
	return sftp_realpath_expand(conn, path, 1);
}

int
sftp_copy(struct sftp_conn *conn, const char *oldpath, const char *newpath)
{
	Attrib junk, attr;
	struct sshbuf *msg;
	u_char *old_handle, *new_handle;
	u_int mode, status, id;
	size_t old_handle_len, new_handle_len;
	int r;

	/* Return if the extension is not supported */
	if ((conn->exts & SFTP_EXT_COPY_DATA) == 0) {
		error("Server does not support copy-data extension");
		return -1;
	}

	/* Make sure the file exists, and we can copy its perms */
	if (sftp_stat(conn, oldpath, 0, &attr) != 0)
		return -1;

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	if (attr.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = attr.perm & 0777;

		if (!S_ISREG(attr.perm)) {
			error("Cannot copy non-regular file: %s", oldpath);
			return -1;
		}
	} else {
		/* NB: The user's umask will apply to this */
		mode = 0666;
	}

	/* Set up the new perms for the new file */
	attrib_clear(&attr);
	attr.perm = mode;
	attr.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(msg, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	sshbuf_reset(msg);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	if (old_handle == NULL) {
		sshbuf_free(msg);
		return -1;
	}

	/* Open the new file for writing */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FXF_WRITE|SSH2_FXF_CREAT|
	    SSH2_FXF_TRUNC)) != 0 ||
	    (r = encode_attrib(msg, &attr)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, newpath);

	sshbuf_reset(msg);

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	if (new_handle == NULL) {
		sshbuf_free(msg);
		free(old_handle);
		return -1;
	}

	/* Copy the file data */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "copy-data")) != 0 ||
	    (r = sshbuf_put_string(msg, old_handle, old_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0 ||
	    (r = sshbuf_put_string(msg, new_handle, new_handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, 0)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message copy-data \"%s\" 0 0 -> \"%s\" 0",
	       oldpath, newpath);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("Couldn't copy file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	/* Clean up everything */
	sshbuf_free(msg);
	sftp_close(conn, old_handle, old_handle_len);
	sftp_close(conn, new_handle, new_handle_len);
	free(old_handle);
	free(new_handle);

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_rename(struct sftp_conn *conn, const char *oldpath, const char *newpath,
    int force_legacy)
{
	struct sshbuf *msg;
	u_int status, id;
	int r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send rename request */
	id = conn->msg_id++;
	if (use_ext) {
		debug2("Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) "
		    "\"%s\" to \"%s\"", oldpath, newpath);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_cstring(msg,
		    "posix-rename@openssh.com")) != 0)
			fatal_fr(r, "compose posix-rename");
	} else {
		debug2("Sending SSH2_FXP_RENAME \"%s\" to \"%s\"",
		    oldpath, newpath);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_RENAME)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0)
			fatal_fr(r, "compose rename");
	}
	if ((r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose paths");
	send_msg(conn, msg);
	debug3("Sent message %s \"%s\" -> \"%s\"",
	    use_ext ? "posix-rename@openssh.com" :
	    "SSH2_FXP_RENAME", oldpath, newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_hardlink(struct sftp_conn *conn, const char *oldpath, const char *newpath)
{
	struct sshbuf *msg;
	u_int status, id;
	int r;

	if ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		return -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send link request */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hardlink@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message hardlink@openssh.com \"%s\" -> \"%s\"",
	    oldpath, newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_symlink(struct sftp_conn *conn, const char *oldpath, const char *newpath)
{
	struct sshbuf *msg;
	u_int status, id;
	int r;

	if (conn->version < 3) {
		error("This server does not support the symlink operation");
		return(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Send symlink request */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_SYMLINK)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_cstring(msg, newpath)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_SYMLINK \"%s\" -> \"%s\"", oldpath,
	    newpath);
	sshbuf_free(msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_fsync(struct sftp_conn *conn, u_char *handle, u_int handle_len)
{
	struct sshbuf *msg;
	u_int status, id;
	int r;

	/* Silently return if the extension is not supported */
	if ((conn->exts & SFTP_EXT_FSYNC) == 0)
		return -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Send fsync request */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fsync@openssh.com I:%u", id);
	sshbuf_free(msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
char *
sftp_readlink(struct sftp_conn *conn, const char *path)
{
	struct sshbuf *msg;
	u_int expected_id, count, id;
	char *filename, *longname;
	Attrib a;
	u_char type;
	int r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	get_msg(conn, msg);
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		return NULL;
	}

	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(msg);
		return(NULL);
	} else if (type != SSH2_FXP_NAME) {
		error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_NAME, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		return NULL;
	}

	if ((r = sshbuf_get_u32(msg, &count)) != 0)
		fatal_fr(r, "parse count");
	if (count != 1)
		fatal("Got multiple names (%d) from SSH_FXP_READLINK", count);

	if ((r = sshbuf_get_cstring(msg, &filename, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &longname, NULL)) != 0 ||
	    (r = decode_attrib(msg, &a)) != 0)
		fatal_fr(r, "parse filenames/attrib");

	debug3("SSH_FXP_READLINK %s -> %s", path, filename);

	free(longname);

	sshbuf_free(msg);

	return filename;
}
#endif

int
sftp_statvfs(struct sftp_conn *conn, const char *path, struct sftp_statvfs *st,
    int quiet)
{
	struct sshbuf *msg;
	u_int id;
	int r;

	if ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	id = conn->msg_id++;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	return get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
int
sftp_fstatvfs(struct sftp_conn *conn, const u_char *handle, u_int handle_len,
    struct sftp_statvfs *st, int quiet)
{
	struct sshbuf *msg;
	u_int id;

	if ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	id = conn->msg_id++;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	return get_decode_statvfs(conn, st, id, quiet);
}
#endif

int
sftp_lsetstat(struct sftp_conn *conn, const char *path, Attrib *a)
{
	struct sshbuf *msg;
	u_int status, id;
	int r;

	if ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	id = conn->msg_id++;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

static void
send_read_request(struct sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, const u_char *handle, u_int handle_len)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, offset)) != 0 ||
	    (r = sshbuf_put_u32(msg, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);
}

static int
send_open(struct sftp_conn *conn, const char *path, const char *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	struct sshbuf *msg;
	int r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = NULL;
	*handle_lenp = 0;

	if (a == NULL) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Send open request */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, openmode)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_msg(conn, msg);
	sshbuf_free(msg);
	debug3("Sent %s message SSH2_FXP_OPEN I:%u P:%s M:0x%04x",
	    tag, id, path, openmode);
	if ((handle = get_handle(conn, id, &handle_len,
	    "%s open \"%s\"", tag, path)) == NULL)
		return -1;
	/* success */
	*handlep = handle;
	*handle_lenp = handle_len;
	return 0;
}

static const char *
progress_meter_path(const char *path)
{
	const char *progresspath;

	if ((progresspath = strrchr(path, '/')) == NULL)
		return path;
	progresspath++;
	if (*progresspath == '\0')
		return path;
	return progresspath;
}

int
sftp_download(struct sftp_conn *conn, const char *remote_path,
    const char *local_path, Attrib *a, int preserve_flag, int resume_flag,
    int fsync_flag, int inplace_flag)
{
	struct sshbuf *msg;
	u_char *handle;
	int local_fd = -1, write_error;
	int read_error, write_errno, lmodified = 0, reordered = 0, r;
	uint64_t offset = 0, size, highwater = 0, maxack = 0;
	u_int mode, id, buflen, num_req, max_req, status = SSH2_FX_OK;
	off_t progress_counter;
	size_t handle_len;
	struct stat st;
	struct requests requests;
	struct request *req;
	u_char type;
	Attrib attr;

	debug2_f("download remote \"%s\" to local \"%s\"",
	    remote_path, local_path);

	TAILQ_INIT(&requests);

	if (a == NULL) {
		if (sftp_stat(conn, remote_path, 0, &attr) != 0)
			return -1;
		a = &attr;
	}

	/* Do not preserve set[ug]id here, as we do not preserve ownership */
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = a->perm & 0777;
	else
		mode = 0666;

	if ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download %s: not a regular file", remote_path);
		return(-1);
	}

	if (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	else
		size = 0;

	buflen = conn->download_buflen;

	/* Send open request */
	if (send_open(conn, remote_path, "remote", SSH2_FXF_READ, NULL,
	    &handle, &handle_len) != 0)
		return -1;

	local_fd = open(local_path, O_WRONLY | O_CREAT |
	((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	if (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		goto fail;
	}
	if (resume_flag) {
		if (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			goto fail;
		}
		if (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			goto fail;
		}
		if ((uint64_t)st.st_size > size) {
			error("Unable to resume download of \"%s\": "
			    "local file is larger than remote", local_path);
 fail:
			sftp_close(conn, handle, handle_len);
			free(handle);
			if (local_fd != -1)
				close(local_fd);
			return -1;
		}
		offset = highwater = maxack = st.st_size;
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = num_req = 0;
	max_req = 1;
	progress_counter = offset;

	if (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	while (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		if (interrupted) {
			if (num_req == 0) /* If we haven't started yet... */
				break;
			max_req = 0;
		}

		/* Send some more requests */
		while (num_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    num_req, max_req);
			req = request_enqueue(&requests, conn->msg_id++,
			    buflen, offset);
			offset += buflen;
			num_req++;
			send_read_request(conn, req->id, req->offset,
			    req->len, handle, handle_len);
		}

		sshbuf_reset(msg);
		if (get_msg(conn, msg) != 0)
			break;
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		if ((req = request_find(&requests, id)) == NULL)
			fatal("Unexpected reply %u", id);

		switch (type) {
		case SSH2_FXP_STATUS:
			if ((r = sshbuf_get_u32(msg, &status)) != 0)
				fatal_fr(r, "parse status");
			if (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			break;
		case SSH2_FXP_DATA:
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			if (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);
			lmodified = 1;
			if ((lseek(local_fd, req->offset, SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} else {
				/*
				 * Track both the highest offset acknowledged
				 * and the highest *contiguous* offset
				 * acknowledged.
				 * We'll need the latter for ftruncate()ing
				 * interrupted transfers.
				 */
				if (maxack < req->offset + len)
					maxack = req->offset + len;
				if (!reordered && req->offset <= highwater)
					highwater = maxack;
				else if (!reordered && req->offset > highwater)
					reordered = 1;
			}
			progress_counter += len;
			if (conn->hpn->live_counter != NULL) /* HPN */
				__atomic_fetch_add(conn->hpn->live_counter, len,
				    __ATOMIC_RELAXED);
			free(data);

			if (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} else {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, num_req);
				req->id = conn->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id,
				    req->offset, req->len, handle, handle_len);
				/* Reduce the request size */
				if (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			if (max_req > 0) { /* max_req = 0 iff EOF received */
				if (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    num_req);
					max_req = 1;
				} else if (max_req < conn->num_requests) {
					++max_req;
				}
			}
			break;
		default:
			error_f("Expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_DATA, type);
			sftp_hpn_set_protocol_violation(conn->hpn);
			read_error = 1;
			/*
			 * Drain the in-flight TAILQ inline so the outer while
			 * exits on the NEXT condition check (num_req == 0 &&
			 * max_req == 0) rather than waiting for get_msg() to
			 * fail.  This guarantees the "requests still in queue"
			 * sanity fatal() below is unreachable on the protocol-
			 * violation path, and avoids one extra get_msg() RTT
			 * against a connection we already know is dead.
			 */
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = 0;
			max_req = 0;
			break;
		}
	}

	if (showprogress && size)
		stop_progress_meter();

	/* Sanity check */
	if (TAILQ_FIRST(&requests) != NULL)
		fatal("Transfer complete, but requests still in queue");

	if (!read_error && !write_error && !interrupted) {
		/* we got everything */
		highwater = maxack;
	}

	/*
	 * Truncate at highest contiguous point to avoid holes on interrupt,
	 * or unconditionally if writing in place.
	 */
	if (inplace_flag || read_error || write_error || interrupted) {
		if (reordered && resume_flag &&
		    (read_error || write_error || interrupted)) {
			error("Unable to resume download of \"%s\": "
			    "server reordered requests", local_path);
		}
		debug("truncating at %llu", (unsigned long long)highwater);
		if (ftruncate(local_fd, highwater) == -1)
			error("local ftruncate \"%s\": %s", local_path,
			    strerror(errno));
	}
	if (read_error) {
		error("read remote \"%s\" : %s", remote_path, fx2txt(status));
		status = -1;
		sftp_close(conn, handle, handle_len);
	} else if (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		status = SSH2_FX_FAILURE;
		sftp_close(conn, handle, handle_len);
	} else {
		if (sftp_close(conn, handle, handle_len) != 0 || interrupted)
			status = SSH2_FX_FAILURE;
		else
			status = SSH2_FX_OK;
		/* Override umask and utimes if asked */
#ifdef HAVE_FCHMOD
		if (preserve_flag && fchmod(local_fd, mode) == -1)
#else
		if (preserve_flag && chmod(local_path, mode) == -1)
#endif /* HAVE_FCHMOD */
			error("local chmod \"%s\": %s", local_path,
			    strerror(errno));
		if (preserve_flag &&
		    (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
			struct timeval tv[2];
			tv[0].tv_sec = a->atime;
			tv[1].tv_sec = a->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			if (utimes(local_path, tv) == -1)
				error("local set times \"%s\": %s",
				    local_path, strerror(errno));
		}
		if (resume_flag && !lmodified)
			logit("File \"%s\" was not modified", local_path);
		else if (fsync_flag) {
			debug("syncing \"%s\"", local_path);
			if (fsync(local_fd) == -1)
				error("local sync \"%s\": %s",
				    local_path, strerror(errno));
		}
	}
	close(local_fd);
	sshbuf_free(msg);
	free(handle);

	return status == SSH2_FX_OK ? 0 : -1;
}

static int
download_dir_internal(struct sftp_conn *conn, const char *src, const char *dst,
    int depth, Attrib *dirattrib, int preserve_flag, int print_flag,
    int resume_flag, int fsync_flag, int follow_link_flag, int inplace_flag)
{
	int i, ret = 0;
	SFTP_DIRENT **dir_entries;
	char *filename, *new_src = NULL, *new_dst = NULL;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;

	if (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		return -1;
	}

	debug2_f("download dir remote \"%s\" to local \"%s\"", src, dst);

	if (dirattrib == NULL) {
		if (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			return -1;
		}
		dirattrib = &ldirattrib;
	}
	if (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);

	if (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	} else {
		debug("download remote \"%s\": server "
		    "did not send permissions", dst);
	}

	if (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		return -1;
	}

	if (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		return -1;
	}

	for (i = 0; dir_entries[i] != NULL && !interrupted; i++) {
		free(new_dst);
		free(new_src);

		filename = dir_entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		a = &dir_entries[i]->a;
		if (S_ISLNK(a->perm)) {
			if (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			if (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				continue;
			}
			a = &lsym;
		}

		if (S_ISDIR(a->perm)) {
			if (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			if (download_dir_internal(conn, new_src, new_dst,
			    depth + 1, a, preserve_flag,
			    print_flag, resume_flag,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} else if (S_ISREG(a->perm)) {
			if (sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag) == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			}
		} else
			logit("download \"%s\": not a regular file", new_src);

	}
	free(new_dst);
	free(new_src);

	if (preserve_flag) {
		if (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
			struct timeval tv[2];
			tv[0].tv_sec = dirattrib->atime;
			tv[1].tv_sec = dirattrib->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			if (utimes(dst, tv) == -1)
				error("local set times on \"%s\": %s",
				    dst, strerror(errno));
		} else
			debug("Server did not send times for directory "
			    "\"%s\"", dst);
	}

	if (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s", dst,
		    strerror(errno));

	sftp_free_dirents(dir_entries);

	return ret;
}

int
sftp_download_dir(struct sftp_conn *conn, const char *src, const char *dst,
    Attrib *dirattrib, int preserve_flag, int print_flag, int resume_flag,
    int fsync_flag, int follow_link_flag, int inplace_flag)
{
	char *src_canon;
	int ret;

	if ((src_canon = sftp_realpath(conn, src)) == NULL) {
		error("download \"%s\": path canonicalization failed", src);
		return -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, fsync_flag,
	    follow_link_flag, inplace_flag);
	free(src_canon);
	return ret;
}

/*
 * Core write loop shared by sftp_upload and sftp_upload_batch.
 * See sftp-client.h sftp_upload_batch for design notes.
 *
 * Does NOT close local_fd or call sftp_close on the remote handle.
 * resume_offset: 0 for normal uploads; caller has already seeked local_fd
 *   when non-zero.
 */
static int
do_upload_body(struct sftp_conn *conn,
    int local_fd, off_t local_size,
    const u_char *handle, size_t handle_len,
    Attrib *a,
    const char *local_path, const char *remote_path,
    int preserve_flag, int fsync_flag, int inplace_flag,
    int resume, off_t resume_offset)
{
	u_int id, status = SSH2_FX_OK, status2, reordered = 0;
	off_t offset, progress_counter;
	u_char type, *data;
	struct sshbuf *msg;
	Attrib t;
	uint32_t startid, ackid;
	uint64_t highwater = resume_offset, maxack = 0;
	struct request *ack = NULL;
	struct requests acks;
	int r;

	TAILQ_INIT(&acks);

	id = conn->msg_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	offset = progress_counter = resume_offset;
	if (showprogress) {
		start_progress_meter(progress_meter_path(local_path),
		    local_size, &progress_counter);
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	for (;;) {
		int len;

		/*
		 * Can't use atomicio here because it returns 0 on EOF,
		 * thus losing the last block of the file.
		 * Simulate an EOF on interrupt, allowing ACKs from the
		 * server to drain.
		 */
		if (interrupted || status != SSH2_FX_OK)
			len = 0;
		else do
			len = read(local_fd, data, conn->upload_buflen);
		while ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		if (len == -1) {
			fatal("read local \"%s\": %s",
			    local_path, strerror(errno));
		} else if (len != 0) {
			ack = request_enqueue(&acks, ++id, len, offset);
			sshbuf_reset(msg);
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, ack->id)) != 0 ||
			    (r = sshbuf_put_string(msg, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose");
			if (send_msg(conn, msg) != 0)
				break;
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} else if (TAILQ_FIRST(&acks) == NULL)
			break;

		if (ack == NULL) {
			/* Was fatal("Unexpected ACK %u", id); — would crash the
			 * entire orchestrator if this worker is one of N in a
			 * parallel-streams transfer.  Mark this connection dead
			 * and bail to the worker thread's safety net, which
			 * checks conn->dead and triggers respawn. */
			sftp_conn_die(conn, "Unexpected ACK %u", id);
			status = -1;
			break;
		}

		if (id == startid || len == 0 ||
		    id - ackid >= conn->num_requests) {
			u_int rid;

			sshbuf_reset(msg);
			if (get_msg(conn, msg) != 0)
				break;
			if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
			    (r = sshbuf_get_u32(msg, &rid)) != 0)
				fatal_fr(r, "parse");

			if (type != SSH2_FXP_STATUS) {
				/* Was fatal("Expected SSH2_FXP_STATUS..."). */
				sftp_conn_die(conn,
				    "Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);
				status = -1;
				break;
			}

			if ((r = sshbuf_get_u32(msg, &status2)) != 0)
				fatal_fr(r, "parse status");
			debug3("SSH2_FXP_STATUS %u", status2);
			if (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			if ((ack = request_find(&acks, rid)) == NULL) {
				/* Was fatal("Can't find request for ID %u"). */
				sftp_conn_die(conn,
				    "Can't find request for ID %u", rid);
				status = -1;
				break;
			}
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (unsigned long long)ack->offset);
			++ackid;
			progress_counter += ack->len;
			if (conn->hpn->live_counter != NULL) /* HPN */
				__atomic_fetch_add(conn->hpn->live_counter, ack->len,
				    __ATOMIC_RELAXED);
			/*
			 * Track both the highest offset acknowledged and the
			 * highest *contiguous* offset acknowledged.
			 * We'll need the latter for ftruncate()ing
			 * interrupted transfers.
			 */
			if (maxack < ack->offset + ack->len)
				maxack = ack->offset + ack->len;
			if (!reordered && ack->offset <= highwater)
				highwater = maxack;
			else if (!reordered && ack->offset > highwater) {
				debug3_f("server reordered ACKs");
				reordered = 1;
			}
			free(ack);
		}
		offset += len;
		if (offset < 0)
			fatal_f("offset < 0");
	}
	sshbuf_free(msg);

	if (showprogress)
		stop_progress_meter();
	free(data);

	if (status == SSH2_FX_OK && !interrupted)
		highwater = maxack;
	if (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		status = SSH2_FX_FAILURE;
	}

	if (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&t);
		t.flags = SSH2_FILEXFER_ATTR_SIZE;
		t.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &t);
	}

	/* Override umask and utimes if asked */
	if (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, a);

	if (fsync_flag)
		(void)sftp_fsync(conn, (u_char *)(uintptr_t)handle, handle_len);

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_upload(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int preserve_flag, int resume,
    int fsync_flag, int inplace_flag)
{
	int r, local_fd;
	u_int openmode;
	u_char *handle;
	struct stat sb;
	Attrib a, c;
	size_t handle_len;
	off_t resume_offset = 0;
	int status = 0;

	debug2_f("upload local \"%s\" to remote \"%s\"",
	    local_path, remote_path);

	if ((local_fd = open(local_path, O_RDONLY)) == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		return(-1);
	}
	if (fstat(local_fd, &sb) == -1) {
		error("fstat local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		return(-1);
	}
	if (!S_ISREG(sb.st_mode)) {
		error("local \"%s\" is not a regular file", local_path);
		close(local_fd);
		return(-1);
	}
	stat_to_attrib(&sb, &a);

	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 0777;
	if (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	if (resume) {
		/* Get remote file size if it exists */
		if (sftp_stat(conn, remote_path, 0, &c) != 0) {
			close(local_fd);
			return -1;
		}

		if ((off_t)c.size >= sb.st_size) {
			error("resume \"%s\": destination file "
			    "same size or larger", local_path);
			close(local_fd);
			return -1;
		}

		if (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			return -1;
		}
		resume_offset = (off_t)c.size;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	if (resume)
		openmode |= SSH2_FXF_APPEND;
	else if (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	/* Send open request */
	if (send_open(conn, remote_path, "dest", openmode, &a,
	    &handle, &handle_len) != 0) {
		close(local_fd);
		return -1;
	}

	r = do_upload_body(conn, local_fd, sb.st_size,
	    handle, handle_len, &a,
	    local_path, remote_path,
	    preserve_flag, fsync_flag, inplace_flag,
	    resume, resume_offset);

	if (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		r = -1;
	}

	if (sftp_close(conn, handle, handle_len) != 0)
		status = -1;

	free(handle);

	return (r != 0 || status != 0) ? -1 : 0;
}

int
sftp_fs_info(struct sftp_conn *conn, const char *path, struct sftp_fs_info *info)
{
	struct sshbuf *msg;
	u_char type;
	u_int id;
	char *fs_type = NULL;
	int r;

	memset(info, 0, sizeof(*info));

	if ((conn->exts & SFTP_EXT_HPN_FS_INFO) == 0)
		return -1;

	debug2("Sending SSH2_FXP_EXTENDED(hpn-fs-info@hpnssh.org) \"%s\"", path);
	id = conn->msg_id++;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hpn-fs-info@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	get_msg_extended(conn, msg, 0);
	if ((r = sshbuf_get_u8(msg, &type)) != 0)
		fatal_fr(r, "parse type");
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY, got %u", type);
		sshbuf_free(msg);
		return -1;
	}
	if ((r = sshbuf_get_u32(msg, &id)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &fs_type, NULL)) != 0 ||
	    (r = sshbuf_get_u64(msg, &info->stripe_size)) != 0 ||
	    (r = sshbuf_get_u32(msg, &info->stripe_count)) != 0 ||
	    (r = sshbuf_get_u64(msg, &info->block_size)) != 0) {
		debug_f("parse reply: %s", ssh_err(r));
		free(fs_type);
		sshbuf_free(msg);
		return -1;
	}
	strlcpy(info->fs_type, fs_type, sizeof(info->fs_type));
	free(fs_type);
	sshbuf_free(msg);
	debug3("hpn-fs-info: fs=%s stripe_size=%llu stripe_count=%u block_size=%llu",
	    info->fs_type, (unsigned long long)info->stripe_size,
	    info->stripe_count, (unsigned long long)info->block_size);
	return 0;
}

/*
 * Pre-create a remote file at size bytes (O_CREAT|O_TRUNC) so that parallel
 * range-upload workers can open it with O_WRONLY and write their byte ranges
 * concurrently without racing on file creation.
 */
int
sftp_precreate(struct sftp_conn *conn, const char *remote_path, off_t size)
{
	u_char *handle = NULL;
	size_t handle_len;
	Attrib a;
	int r;

	attrib_clear(&a);
	a.flags = SSH2_FILEXFER_ATTR_SIZE;
	a.size  = (uint64_t)size;

	if (send_open(conn, remote_path, "precreate",
	    SSH2_FXF_WRITE | SSH2_FXF_CREAT | SSH2_FXF_TRUNC,
	    &a, &handle, &handle_len) != 0)
		return -1;
	r = sftp_close(conn, handle, handle_len);
	free(handle);
	return r;
}

int
sftp_upload_range(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t range_offset, off_t range_length)
{
	struct sshbuf *msg;
	struct request {
		u_int id;
		size_t len;
		uint64_t offset;
		TAILQ_ENTRY(request) tq;
	};
	TAILQ_HEAD(, request) acks;
	struct request *ack;
	u_char *handle = NULL, *data = NULL, type;
	size_t handle_len;
	u_int id, ackid, startid;
	uint32_t status = SSH2_FX_OK;
	off_t offset, bytes_left;
	int local_fd = -1, ret = -1, r;

	TAILQ_INIT(&acks);

	if ((local_fd = open(local_path, O_RDONLY)) < 0) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		return -1;
	}
	if (lseek(local_fd, range_offset, SEEK_SET) < 0) {
		error("lseek \"%s\" to %lld: %s", local_path,
		    (long long)range_offset, strerror(errno));
		goto out;
	}
	/* Open remote without O_CREAT/O_TRUNC — file was pre-created. */
	if (send_open(conn, remote_path, "range-dest",
	    SSH2_FXF_WRITE, NULL, &handle, &handle_len) != 0)
		goto out;

	data = xmalloc(conn->upload_buflen);
	id = conn->msg_id;
	startid = ackid = id + 1;
	offset = range_offset;
	bytes_left = range_length;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	for (;;) {
		int len = 0;
		size_t outstanding = id - ackid + 1;

		/* Send new requests while there is data and pipeline capacity. */
		while (bytes_left > 0 && outstanding < conn->num_requests &&
		    status == SSH2_FX_OK) {
			size_t want = conn->upload_buflen;
			if ((off_t)want > bytes_left)
				want = (size_t)bytes_left;
			do
				len = read(local_fd, data, want);
			while (len == -1 &&
			    (errno == EINTR || errno == EAGAIN ||
			     errno == EWOULDBLOCK));
			if (len <= 0)
				break;

			ack = xcalloc(1, sizeof(*ack));
			ack->id     = ++id;
			ack->len    = (size_t)len;
			ack->offset = (uint64_t)offset;
			TAILQ_INSERT_TAIL(&acks, ack, tq);

			sshbuf_reset(msg);
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, ack->id)) != 0 ||
			    (r = sshbuf_put_string(msg, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, (uint64_t)offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, (size_t)len)) != 0)
				fatal_fr(r, "compose write");
			send_msg(conn, msg);

			offset    += len;
			bytes_left -= len;
			outstanding = id - ackid + 1;
		}

		/* Drain one ACK per iteration. */
		if (TAILQ_EMPTY(&acks))
			break;
		ack = TAILQ_FIRST(&acks);
		sshbuf_reset(msg);
		/* Check get_msg_extended return — connection death (EPIPE)
		 * already sets conn->hpn->dead inside get_msg_extended.
		 * Without this check, the subsequent parse would fatal_fr
		 * on the empty msg buffer and crash the orchestrator. */
		if (get_msg_extended(conn, msg, 0) != 0) {
			status = SSH2_FX_FAILURE;
			break;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &ackid)) != 0)
			fatal_fr(r, "parse status");
		if (type != SSH2_FXP_STATUS) {
			/* Was fatal_f("expected SSH2_FXP_STATUS..."). */
			sftp_conn_die(conn,
			    "expected SSH2_FXP_STATUS(%u), got %u",
			    SSH2_FXP_STATUS, type);
			status = SSH2_FX_FAILURE;
			break;
		}
		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status code");
		if (status != SSH2_FX_OK) {
			error("write remote \"%s\" at offset %llu: %s",
			    remote_path, (unsigned long long)ack->offset,
			    fx2txt(status));
		} else if (conn->hpn->live_counter != NULL) {
			/* Report incremental progress so the orchestrator's
			 * bps measurement window sees a steady stream of
			 * bytes rather than a step at range completion.
			 * Without this the scaler reads bps=0 mid-range and
			 * misfires the saturation signal. */
			__atomic_fetch_add(conn->hpn->live_counter,
			    (uint64_t)ack->len, __ATOMIC_RELAXED);
		}
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	sshbuf_free(msg);

	if (sftp_close(conn, handle, handle_len) != 0)
		status = SSH2_FX_FAILURE;

	ret = (status == SSH2_FX_OK) ? 0 : -1;
 out:
	while ((ack = TAILQ_FIRST(&acks)) != NULL) {
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	close(local_fd);
	free(handle);
	free(data);
	return ret;
}

int
sftp_download_range(struct sftp_conn *conn, const char *remote_path,
    const char *local_path, off_t range_offset, off_t range_length)
{
	struct sshbuf *msg;
	struct requests requests;
	struct request *req;
	u_char *handle = NULL, type;
	size_t handle_len;
	u_int id, buflen, num_req, max_req, status = SSH2_FX_OK;
	uint64_t remote_offset;
	off_t bytes_left;
	int local_fd = -1, read_error = 0, write_error = 0, write_errno = 0;
	int ret = -1, r;

	TAILQ_INIT(&requests);

	/* Open remote file for reading. */
	if (send_open(conn, remote_path, "range-src",
	    SSH2_FXF_READ, NULL, &handle, &handle_len) != 0)
		return -1;

	/* Open pre-created local file for writing; no O_CREAT/O_TRUNC —
	 * the orchestrator pre-created it at the correct size. */
	if ((local_fd = open(local_path, O_WRONLY)) < 0) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		goto out;
	}

	buflen = conn->download_buflen;
	num_req = 0;
	max_req = 1;
	remote_offset = (uint64_t)range_offset;
	bytes_left = range_length;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	while (num_req > 0 || (bytes_left > 0 && max_req > 0)) {
		/* Fill the pipeline with read requests. */
		while (bytes_left > 0 && num_req < max_req) {
			size_t want = buflen;
			if ((off_t)want > bytes_left)
				want = (size_t)bytes_left;
			req = request_enqueue(&requests, conn->msg_id++,
			    want, remote_offset);
			send_read_request(conn, req->id, req->offset,
			    (u_int)req->len, handle, handle_len);
			remote_offset += want;
			bytes_left    -= (off_t)want;
			num_req++;
		}

		sshbuf_reset(msg);
		if (get_msg_extended(conn, msg, 0) != 0) {
			read_error = 1;
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = max_req = 0;
			break;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		if ((req = request_find(&requests, id)) == NULL)
			fatal_f("unexpected reply id %u", id);

		switch (type) {
		case SSH2_FXP_STATUS:
			if ((r = sshbuf_get_u32(msg, &status)) != 0)
				fatal_fr(r, "parse status");
			if (status == SSH2_FX_EOF)
				error("read remote \"%s\": unexpected EOF "
				    "within range", remote_path);
			else
				error("read remote \"%s\": %s",
				    remote_path, fx2txt(status));
			read_error = 1;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = max_req = 0;
			break;
		case SSH2_FXP_DATA: {
			u_char *data;
			size_t len;
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			if (len > req->len)
				fatal("received more data than requested "
				    "%zu > %zu", len, req->len);
			if ((lseek(local_fd, (off_t)req->offset,
			    SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
			} else if (conn->hpn->live_counter != NULL) {
				__atomic_fetch_add(conn->hpn->live_counter,
				    (uint64_t)len, __ATOMIC_RELAXED);
			}
			free(data);
			if (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} else {
				/* Short read — re-request remainder. */
				req->id = conn->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id, req->offset,
				    (u_int)req->len, handle, handle_len);
			}
			if (max_req > 0 && max_req < conn->num_requests)
				max_req++;
			break;
		}
		default:
			error_f("expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption",
			    SSH2_FXP_DATA, type);
			sftp_hpn_set_protocol_violation(conn->hpn);
			read_error = 1;
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = max_req = 0;
			break;
		}
	}
	sshbuf_free(msg);

	if (TAILQ_FIRST(&requests) != NULL)
		fatal("range download complete but requests still in queue");

	if (read_error)
		sftp_close(conn, handle, handle_len);
	else if (write_error) {
		error("write local \"%s\": %s", local_path,
		    strerror(write_errno));
		sftp_close(conn, handle, handle_len);
	} else
		ret = (sftp_close(conn, handle, handle_len) == 0) ? 0 : -1;

 out:
	if (local_fd != -1)
		close(local_fd);
	free(handle);
	return ret;
}

/* Internal state for one file in a batch upload. */
struct batch_file {
	int      local_fd;     /* -1 if local open failed */
	struct stat sb;
	Attrib   a;
	u_char  *handle;       /* NULL if remote open failed */
	size_t   handle_len;
	u_int    open_id;
	u_int    close_id;
	u_int    write_id;     /* request ID for small-file single-write (0=none) */
	int      failed;
};

/*
 * Mark every entry in the batch that has not already been recorded as
 * failed as failed.  Used by sftp_upload_batch when a collection phase
 * hits a dead connection or a protocol problem mid-batch: rather than
 * calling fatal_fr (which terminates the entire process — catastrophic
 * for parallel workers handling unrelated transfers), we abandon the
 * batch.  The caller (worker_thread) re-queues each failed entry via
 * worker_process_result on a fresh connection.
 */
static void
batch_fail_all_remaining(struct batch_file *bs,
    struct sftp_upload_batch_entry *entries, int n, int *any_fail)
{
	int i;
	for (i = 0; i < n; i++) {
		if (!bs[i].failed) {
			bs[i].failed = 1;
			entries[i].result = -1;
			*any_fail = 1;
		}
	}
}

/* ── BEGIN Phase 4 gap 1: sliding-window batch send/finish ────────────────
 *
 * Implementation note: the original sftp_upload_batch did all 5 phases
 * back-to-back.  Splitting into send (phases 1-4) and finish (phase 5)
 * lets the caller pipeline: the next batch's OPENs (phase 1) can be on
 * the wire while the previous batch's CLOSE STATUSes (phase 5) are still
 * coming back.  Saves ~1 RTT per batch boundary.
 *
 * Wire ordering when send is called with prev != NULL:
 *   1. Send THIS batch's OPENs (phase 1)
 *   2. Drain PREV's CLOSE STATUSes (the prev_finish step) — they should be
 *      arriving / arrived since prev's CLOSEs were sent before this call
 *   3. Collect THIS batch's HANDLEs (phase 2)
 *   4. The rest of phases 3-4 for this batch
 *
 * The overlap: between step 1 (we send opens) and step 2 (we read close
 * statuses), the server is processing both — sending close statuses for
 * prev AND opening files for the current batch — concurrently.
 *
 * To disable at runtime: HPN_NO_BATCH_PIPELINE=1.  Forces the worker to
 * fall back to the un-pipelined sftp_upload_batch() entry point.  Useful
 * for A/B testing or for bisecting regressions.
 */

struct sftp_upload_batch_pending {
	struct sftp_upload_batch_entry *entries;
	struct batch_file              *bs;
	int                             n;
	int                             any_fail;
};

/* Phase 5 + cleanup, factored out for use by both finish and error paths. */
static int
batch_phase5_and_cleanup(struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, struct batch_file *bs,
    int n, int any_fail_in)
{
	struct sshbuf *msg;
	int i, r, any_fail = any_fail_in;

	debug_f("batch upload phase 5: collecting %d close replies", n);
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	for (i = 0; i < n; i++) {
		u_char type;
		u_int status, rid;

		if (bs[i].handle == NULL)
			continue;
		if (get_msg(conn, msg) != 0) {
			error_f("batch close: connection closed while "
			    "collecting responses (entry %d/%d)", i, n);
			batch_fail_all_remaining(bs, entries, n, &any_fail);
			sshbuf_free(msg);
			goto cleanup;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			error_fr(r, "parse batch close response");
			batch_fail_all_remaining(bs, entries, n, &any_fail);
			sshbuf_free(msg);
			goto cleanup;
		}
		if (type != SSH2_FXP_STATUS) {
			error_f("batch close: expected SSH2_FXP_STATUS(%d), "
			    "got %d — connection may be corrupt",
			    SSH2_FXP_STATUS, type);
			sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
			batch_fail_all_remaining(bs, entries, n, &any_fail);
			sshbuf_free(msg);
			goto cleanup;
		}
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse batch close status");
			batch_fail_all_remaining(bs, entries, n, &any_fail);
			sshbuf_free(msg);
			goto cleanup;
		}
		if (rid != bs[i].close_id) {
			error_f("batch close ID mismatch: got %u expected %u "
			    "— possible MITM or server corruption",
			    rid, bs[i].close_id);
			sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
			batch_fail_all_remaining(bs, entries, n, &any_fail);
			sshbuf_free(msg);
			goto cleanup;
		}
		if (status != SSH2_FX_OK) {
			error("batch close \"%s\": %s",
			    entries[i].remote_path, fx2txt(status));
			if (!bs[i].failed) {
				bs[i].failed = 1;
				entries[i].result = -1;
				any_fail = 1;
			}
		}
		free(bs[i].handle);
		bs[i].handle = NULL;
	}
	sshbuf_free(msg);

 cleanup:
	for (i = 0; i < n; i++) {
		if (bs[i].local_fd >= 0)
			close(bs[i].local_fd);
		free(bs[i].handle);
	}
	free(bs);

	return any_fail ? -1 : 0;
}

int
sftp_upload_batch_finish(struct sftp_conn *conn,
    struct sftp_upload_batch_pending *pending)
{
	int rc;
	if (pending == NULL)
		return 0;
	rc = batch_phase5_and_cleanup(conn, pending->entries, pending->bs,
	    pending->n, pending->any_fail);
	free(pending);
	return rc;
}

struct sftp_upload_batch_pending *
sftp_upload_batch_send(struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, int n,
    int preserve_flag, int fsync_flag, int inplace_flag,
    struct sftp_upload_batch_pending *prev)
{
	struct sftp_upload_batch_pending *new_p;
	struct batch_file *bs;
	struct sshbuf *msg;
	u_int openmode = SSH2_FXF_WRITE | SSH2_FXF_CREAT | SSH2_FXF_TRUNC;
	int i, r, any_fail = 0;

	if (n <= 0) {
		if (prev != NULL)
			(void)sftp_upload_batch_finish(conn, prev);
		return NULL;
	}

	debug_f("batch upload: n=%d preserve=%d fsync=%d inplace=%d",
	    n, preserve_flag, fsync_flag, inplace_flag);

	bs = xcalloc(n, sizeof(*bs));
	for (i = 0; i < n; i++) {
		bs[i].local_fd = -1;
		entries[i].result = 0;
	}

	/*
	 * Phase 1: open each local file and send the corresponding
	 * SSH_FXP_OPEN request without waiting for the handle reply.
	 * All N requests go out in a burst; the server queues them.
	 */
	debug_f("batch upload phase 1: sending %d SSH_FXP_OPEN requests", n);
	for (i = 0; i < n; i++) {
		if ((bs[i].local_fd = open(entries[i].local_path, O_RDONLY)) == -1) {
			error("batch open local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			bs[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
			/*
			 * We still need to send a placeholder open so that the
			 * handle-collection phase can account for it.  Skip
			 * instead: send_open_async below is only called when
			 * local_fd >= 0.  We handle the gap in Phase 2 by
			 * only collecting handles for non-failed entries.
			 *
			 * BUT: since we send opens only for good entries, the
			 * id sequence must skip failed entries too.  Track which
			 * entries actually sent an open via open_id==0 meaning
			 * "no open sent".
			 */
			bs[i].open_id = 0;
			continue;
		}
		if (fstat(bs[i].local_fd, &bs[i].sb) == -1) {
			error("batch fstat local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			close(bs[i].local_fd);
			bs[i].local_fd = -1;
			bs[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
			bs[i].open_id = 0;
			continue;
		}
		stat_to_attrib(&bs[i].sb, &bs[i].a);
		bs[i].a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
		bs[i].a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
		bs[i].a.perm &= 0777;
		if (!preserve_flag)
			bs[i].a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

		/* Send SSH_FXP_OPEN without waiting for the handle reply. */
		bs[i].open_id = conn->msg_id++;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
		    (r = sshbuf_put_u32(msg, bs[i].open_id)) != 0 ||
		    (r = sshbuf_put_cstring(msg, entries[i].remote_path)) != 0 ||
		    (r = sshbuf_put_u32(msg, openmode)) != 0 ||
		    (r = encode_attrib(msg, &bs[i].a)) != 0)
			fatal_fr(r, "compose batch open");
		send_msg(conn, msg);
		sshbuf_free(msg);
	}

	/*
	 * Drain the previous batch's deferred close STATUSes here, between
	 * phase 1 (this batch's OPENs sent) and phase 2 (collect this batch's
	 * HANDLEs).  The OPENs we just sent are now in flight to the server,
	 * which will also send back the close STATUSes for the prev batch
	 * (whose CLOSEs were sent before this call).  By draining now we
	 * overlap server processing of THIS batch's opens with collection of
	 * PREV batch's close statuses — saving ~1 RTT per batch boundary.
	 *
	 * If the drain fails (connection died, protocol violation), prev's
	 * remaining entries are marked failed inside finish; we still proceed
	 * with this batch.  If this batch's connection is dead too, phase 2
	 * below will fail naturally.
	 */
	if (prev != NULL) {
		(void)sftp_upload_batch_finish(conn, prev);
		prev = NULL;
	}

	/*
	 * Phase 2: collect handles in the same order the opens were sent.
	 * One RTT covers all N replies.
	 */
	debug_f("batch upload phase 2: collecting %d handles", n);
	for (i = 0; i < n; i++) {
		if (bs[i].open_id == 0)
			continue; /* no open was sent for this entry */
		bs[i].handle = get_handle(conn, bs[i].open_id,
		    &bs[i].handle_len,
		    "batch dest open \"%s\"", entries[i].remote_path);
		if (bs[i].handle == NULL) {
			close(bs[i].local_fd);
			bs[i].local_fd = -1;
			bs[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
		}
	}

	/*
	 * Phase 3a: burst-write all small files (size <= upload_buflen).
	 * Each file fits in a single SSH_FXP_WRITE; we send all N requests
	 * without collecting ACKs, so N round-trips collapse to one.
	 * Large files and empty files are skipped here; they are handled
	 * in Phase 3d below.
	 */
	debug_f("batch upload phase 3: transferring %d files", n);
	{
		u_char *data = xmalloc(conn->upload_buflen);

		for (i = 0; i < n; i++) {
			ssize_t len;

			if (bs[i].failed || bs[i].handle == NULL)
				continue;
			if (bs[i].sb.st_size > (off_t)conn->upload_buflen)
				continue; /* large file — handled in phase 3d */
			if (bs[i].sb.st_size == 0) {
				/* Empty file: remote is already zeroed by TRUNC open. */
				close(bs[i].local_fd);
				bs[i].local_fd = -1;
				continue;
			}
			/* Read the entire file in one shot. */
			do {
				len = read(bs[i].local_fd, data,
				    (size_t)bs[i].sb.st_size);
			} while (len == -1 && (errno == EINTR ||
			    errno == EAGAIN || errno == EWOULDBLOCK));
			close(bs[i].local_fd);
			bs[i].local_fd = -1;
			if (len <= 0) {
				error("read local \"%s\": %s",
				    entries[i].local_path, strerror(errno));
				bs[i].failed = 1;
				entries[i].result = -1;
				any_fail = 1;
				continue;
			}
			/* Send SSH_FXP_WRITE; ACK collected in phase 3b. */
			bs[i].write_id = conn->msg_id++;
			if ((msg = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, bs[i].write_id)) != 0 ||
			    (r = sshbuf_put_string(msg, bs[i].handle,
			    bs[i].handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, 0)) != 0 ||       /* offset=0 */
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose batch write");
			send_msg(conn, msg);
			sshbuf_free(msg);
		}
		free(data);
	}

	/*
	 * Phase 3b: collect STATUS replies for all small-file writes.
	 * The server responds in request order; one RTT covers all N.
	 *
	 * On dead connection or protocol violation here we abandon the
	 * rest of the batch (mark all unfailed entries failed, skip to
	 * cleanup).  Calling fatal_fr in this loop would terminate the
	 * whole process — catastrophic for parallel workers handling
	 * unrelated transfers — so we degrade gracefully instead.
	 */
	{
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		for (i = 0; i < n; i++) {
			u_char type;
			u_int status, rid;

			if (bs[i].write_id == 0)
				continue; /* no write sent for this entry */
			if (get_msg(conn, msg) != 0) {
				error_f("batch write: connection closed while "
				    "collecting responses (entry %d/%d)", i, n);
				batch_fail_all_remaining(bs, entries, n, &any_fail);
				sshbuf_free(msg);
				goto send_failed;
			}
			if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
			    (r = sshbuf_get_u32(msg, &rid)) != 0) {
				error_fr(r, "parse batch write response");
				batch_fail_all_remaining(bs, entries, n, &any_fail);
				sshbuf_free(msg);
				goto send_failed;
			}
			if (type != SSH2_FXP_STATUS) {
				error_f("batch write: expected SSH2_FXP_STATUS(%d), "
				    "got %d — connection may be corrupt",
				    SSH2_FXP_STATUS, type);
				sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
				batch_fail_all_remaining(bs, entries, n, &any_fail);
				sshbuf_free(msg);
				goto send_failed;
			}
			if ((r = sshbuf_get_u32(msg, &status)) != 0) {
				error_fr(r, "parse batch write status");
				batch_fail_all_remaining(bs, entries, n, &any_fail);
				sshbuf_free(msg);
				goto send_failed;
			}
			if (rid != bs[i].write_id) {
				error_f("batch write ID mismatch: got %u expected "
				    "%u — possible MITM or server corruption",
				    rid, bs[i].write_id);
				sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
				batch_fail_all_remaining(bs, entries, n, &any_fail);
				sshbuf_free(msg);
				goto send_failed;
			}
			if (conn->hpn->live_counter != NULL) /* HPN */
				__atomic_fetch_add(conn->hpn->live_counter,
				    (uint64_t)bs[i].sb.st_size, __ATOMIC_RELAXED);
			if (status != SSH2_FX_OK) {
				error("write remote \"%s\": %s",
				    entries[i].remote_path, fx2txt(status));
				bs[i].failed = 1;
				entries[i].result = -1;
				any_fail = 1;
			}
		}
		sshbuf_free(msg);
	}

	/*
	 * Phase 3c: apply preserve / fsync to successfully written small files.
	 */
	for (i = 0; i < n; i++) {
		if (bs[i].failed || bs[i].handle == NULL)
			continue;
		if (bs[i].sb.st_size > (off_t)conn->upload_buflen)
			continue; /* large file — handled below */
		if (preserve_flag)
			sftp_fsetstat(conn, bs[i].handle, bs[i].handle_len,
			    &bs[i].a);
		if (fsync_flag)
			(void)sftp_fsync(conn, bs[i].handle, bs[i].handle_len);
	}

	/*
	 * Phase 3d: large files — one at a time via do_upload_body.
	 * preserve and fsync are applied inside do_upload_body per file.
	 */
	for (i = 0; i < n; i++) {
		if (bs[i].failed || bs[i].handle == NULL)
			continue;
		if (bs[i].sb.st_size <= (off_t)conn->upload_buflen)
			continue; /* small file — already handled */
		debug_f("batch upload large file %d/%d: %s -> %s (%lld bytes)",
		    i + 1, n, entries[i].local_path, entries[i].remote_path,
		    (long long)bs[i].sb.st_size);
		r = do_upload_body(conn, bs[i].local_fd, bs[i].sb.st_size,
		    bs[i].handle, bs[i].handle_len, &bs[i].a,
		    entries[i].local_path, entries[i].remote_path,
		    preserve_flag, fsync_flag, inplace_flag,
		    /*resume=*/0, /*resume_offset=*/0);
		if (close(bs[i].local_fd) == -1) {
			error("batch close local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			r = -1;
		}
		bs[i].local_fd = -1;
		if (r != 0) {
			bs[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
		}
	}

	/*
	 * Phase 4: send all SSH_FXP_CLOSE requests in a burst (no waiting).
	 */
	debug_f("batch upload phase 4: sending %d SSH_FXP_CLOSE requests", n);
	for (i = 0; i < n; i++) {
		if (bs[i].handle == NULL)
			continue;
		bs[i].close_id = conn->msg_id++;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
		    (r = sshbuf_put_u32(msg, bs[i].close_id)) != 0 ||
		    (r = sshbuf_put_string(msg, bs[i].handle,
		    bs[i].handle_len)) != 0)
			fatal_fr(r, "compose batch close");
		send_msg(conn, msg);
		sshbuf_free(msg);
	}

	/* Phase 5 is deferred to sftp_upload_batch_finish — packaged into
	 * a pending struct and returned to the caller, who calls finish
	 * either inline (legacy sftp_upload_batch wrapper) or later, after
	 * sending the next batch's phase 1 OPENs (sliding-window pipelining). */
	new_p = xcalloc(1, sizeof(*new_p));
	new_p->entries  = entries;
	new_p->bs       = bs;
	new_p->n        = n;
	new_p->any_fail = any_fail;
	return new_p;

 send_failed:
	/* Phase 3b error path: connection dead or protocol violation BEFORE
	 * we sent phase 4 CLOSEs.  Mark every entry failed, clean up the
	 * batch state, and return NULL.  Phase 4 CLOSEs are NOT sent, so
	 * there is nothing for finish to collect — return NULL signals this
	 * to the caller. */
	for (i = 0; i < n; i++) {
		if (bs[i].local_fd >= 0)
			close(bs[i].local_fd);
		free(bs[i].handle);
	}
	free(bs);
	return NULL;
}

int
sftp_upload_batch(struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, int n,
    int preserve_flag, int fsync_flag, int inplace_flag)
{
	struct sftp_upload_batch_pending *p;

	p = sftp_upload_batch_send(conn, entries, n,
	    preserve_flag, fsync_flag, inplace_flag, NULL);
	if (p == NULL) {
		/* send_failed marked entries; if n was 0, also -1 with no work */
		return n > 0 ? -1 : 0;
	}
	return sftp_upload_batch_finish(conn, p);
}
/* ── END Phase 4 gap 1 ──────────────────────────────────────────────────── */

/* ── BEGIN Phase 5: hpn-bundle upload ──────────────────────────────────────
 *
 * Implements the client side of `hpn-bundle-open@hpnssh.org`.  Many small
 * files are packed into a tar (ustar) byte stream by libarchive and
 * delivered to the server through a single OPEN, multiple WRITEs, and a
 * CLOSE on the SFTP connection.  Server-side handler (see sftp-server.c
 * process_extended_hpn_bundle_open) feeds the bytes back through
 * libarchive to recreate the file tree.
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
 * sftp_upload_bundle.  This function does not transparently fall back.
 *
 * libarchive integration: compile-time optional via WITH_LIBARCHIVE.
 * When unavailable, sftp_upload_bundle is a stub that returns -1.
 */

#ifdef WITH_LIBARCHIVE
# include <archive.h>
# include <archive_entry.h>
#endif

int
sftp_conn_has_hpn_bundle(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HPN_BUNDLE) != 0;
}

#ifndef WITH_LIBARCHIVE
/* Stub when libarchive is not compiled in.  Caller will fall back to
 * per-file uploads. */
int
sftp_upload_bundle(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_upload_bundle_entry *entries, int n,
    int preserve_flag, int fsync_flag)
{
	int i;
	(void)conn; (void)remote_dest_dir;
	(void)preserve_flag; (void)fsync_flag;
	for (i = 0; i < n; i++)
		entries[i].result = -1;
	debug_f("hpn-bundle: not compiled in (missing libarchive)");
	return -1;
}
#else  /* WITH_LIBARCHIVE */

/* Bundle flags carried in the SSH_FXP_EXTENDED open request. */
#define HPN_BUNDLE_FLAG_PRESERVE   0x00000001U
#define HPN_BUNDLE_FLAG_FSYNC      0x00000002U

/*
 * Defensive cap on outstanding (unread) STATUS replies.  Each queued
 * STATUS is ~13 bytes on the wire, so 4096 is well under any plausible
 * socket / channel buffer.  In practice the default 4 MiB bundle at the
 * 128 KiB libarchive block size below queues only ~32 STATUSes per
 * bundle — the cap exists only so a user cranking HPN_BUNDLE_TARGET_BYTES
 * very high doesn't fill kernel buffers and deadlock.
 */
#define BUNDLE_MAX_INFLIGHT     4096

/*
 * libarchive output block size.  Each block becomes one SSH_FXP_WRITE
 * message; with SFTP_MAX_MSG_LENGTH = 256 KiB the practical ceiling is
 * just under that.  128 KiB matches DEFAULT_TRANSFER_BUFLEN and the size
 * the rest of the client uses for file uploads.
 */
#define BUNDLE_BLOCK_BYTES      (128 * 1024)

/*
 * Context for libarchive's write callback.  WRITEs are pipelined: each
 * callback invocation sends one SSH_FXP_WRITE without blocking on the
 * server's STATUS reply.  STATUSes accumulate in the SSH channel; they
 * are drained in bulk before SSH_FXP_CLOSE.
 *
 * Because rids come from conn->msg_id++ and SFTP replies are returned in
 * request order, we don't need to track each pending rid individually —
 * the rid of drain #k is simply first_rid + k.
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

	rid = ctx->conn->msg_id++;
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
	 * close-time drain (in sftp_upload_bundle) reads it later. */
	return (la_ssize_t)length;
}

int
sftp_upload_bundle(struct sftp_conn *conn,
    const char *remote_dest_dir,
    struct sftp_upload_bundle_entry *entries, int n,
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
	open_id = conn->msg_id++;
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
	    archive_write_set_bytes_per_block(a, BUNDLE_BLOCK_BYTES)
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
		u_int close_id = conn->msg_id++;
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
			conn->hpn->dead = 1;
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

#endif /* WITH_LIBARCHIVE */
/* ── END Phase 5 ────────────────────────────────────────────────────────── */

static int
upload_dir_internal(struct sftp_conn *conn, const char *src, const char *dst,
    int depth, int preserve_flag, int print_flag, int resume, int fsync_flag,
    int follow_link_flag, int inplace_flag)
{
	int created = 0, ret = 0;
	DIR *dirp;
	struct dirent *dp;
	char *filename, *new_src = NULL, *new_dst = NULL;
	struct stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;

	debug2_f("upload local dir \"%s\" to remote \"%s\"", src, dst);

	if (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		return -1;
	}

	if (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	if (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	if (sftp_mkdir(conn, dst, &a, 0) == 0)
		created = 1;
	else {
		if (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			return -1;
		if (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			return -1;
		}
	}
	a.perm = saved_perm;

	if ((dirp = opendir(src)) == NULL) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		return -1;
	}

	while (((dp = readdir(dirp)) != NULL) && !interrupted) {
		if (dp->d_ino == 0)
			continue;
		free(new_dst);
		free(new_src);
		filename = dp->d_name;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			continue;
		if (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			continue;
		}
		if (S_ISLNK(sb.st_mode)) {
			if (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			if (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				continue;
			}
		}
		if (S_ISDIR(sb.st_mode)) {
			if (upload_dir_internal(conn, new_src, new_dst,
			    depth + 1, preserve_flag, print_flag, resume,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} else if (S_ISREG(sb.st_mode)) {
			if (sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, fsync_flag,
			    inplace_flag) == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} else
			logit("%s: not a regular file", filename);
	}
	free(new_dst);
	free(new_src);

	if (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(void) closedir(dirp);
	return ret;
}

int
sftp_upload_dir(struct sftp_conn *conn, const char *src, const char *dst,
    int preserve_flag, int print_flag, int resume, int fsync_flag,
    int follow_link_flag, int inplace_flag)
{
	char *dst_canon;
	int ret;

	if ((dst_canon = sftp_realpath(conn, dst)) == NULL) {
		error("upload \"%s\": path canonicalization failed", dst);
		return -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, fsync_flag, follow_link_flag, inplace_flag);

	free(dst_canon);
	return ret;
}

static void
handle_dest_replies(struct sftp_conn *to, const char *to_path, int synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	struct sshbuf *msg;
	u_char type;
	u_int id, status;
	int r;
	struct pollfd pfd;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Try to eat replies from the upload side */
	while (*nreqsp > 0) {
		debug3_f("%u outstanding replies", *nreqsp);
		if (!synchronous) {
			/* Bail out if no data is ready to be read */
			pfd.fd = to->fd_in;
			pfd.events = POLLIN;
			if ((r = poll(&pfd, 1, 0)) == -1) {
				if (errno == EINTR)
					break;
				fatal_f("poll: %s", strerror(errno));
			} else if (r == 0)
				break; /* fd not ready */
		}
		sshbuf_reset(msg);
		get_msg(to, msg);

		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "dest parse");
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		if (type != SSH2_FXP_STATUS) {
			error_f("Expected SSH2_FXP_STATUS(%d) packet, got %d - "
			    "possible protocol corruption", SSH2_FXP_STATUS, type);
			sftp_hpn_set_protocol_violation(to->hpn);
			if (*write_errorp == 0)
				*write_errorp = SSH2_FX_CONNECTION_LOST;
			/*
			 * NOTE: *nreqsp is intentionally NOT decremented on
			 * this exit path - we break with replies still
			 * "outstanding".  Callers (sftp_crossload, scp) must
			 * check *write_errorp for completion; do not trust
			 * *nreqsp == 0 to mean "all writes acked" without
			 * also verifying *write_errorp == 0.
			 */
			break;
		}
		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse dest status");
		debug3("dest SSH2_FXP_STATUS %u", status);
		if (status != SSH2_FX_OK) {
			/* record first error */
			if (*write_errorp == 0)
				*write_errorp = status;
		}
		/*
		 * XXX this doesn't do full reply matching like sftp_upload and
		 * so cannot gracefully truncate terminated uploads at a
		 * high-water mark. ATM the only caller of this function (scp)
		 * doesn't support transfer resumption, so this doesn't matter
		 * a whole lot.
		 *
		 * To be safe, sftp_crossload truncates the destination file to
		 * zero length on upload failure, since we can't trust the
		 * server not to have reordered replies that could have
		 * inserted holes where none existed in the source file.
		 *
		 * XXX we could get a more accurate progress bar if we updated
		 * the counter based on the reply from the destination...
		 */
		(*nreqsp)--;
	}
	debug3_f("done: %u outstanding replies", *nreqsp);
	sshbuf_free(msg);
}

int
sftp_crossload(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *a, int preserve_flag)
{
	struct sshbuf *msg;
	int write_error, read_error, r;
	uint64_t offset = 0, size;
	u_int id, buflen, num_req, max_req, status = SSH2_FX_OK;
	u_int num_upload_req;
	off_t progress_counter;
	u_char *from_handle, *to_handle;
	size_t from_handle_len, to_handle_len;
	struct requests requests;
	struct request *req;
	u_char type;
	Attrib attr;

	debug2_f("crossload src \"%s\" to dst \"%s\"", from_path, to_path);

	TAILQ_INIT(&requests);

	if (a == NULL) {
		if (sftp_stat(from, from_path, 0, &attr) != 0)
			return -1;
		a = &attr;
	}

	if ((a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
	    (!S_ISREG(a->perm))) {
		error("download \"%s\": not a regular file", from_path);
		return(-1);
	}
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		size = a->size;
	else
		size = 0;

	buflen = from->download_buflen;
	if (buflen > to->upload_buflen)
		buflen = to->upload_buflen;

	/* Send open request to read side */
	if (send_open(from, from_path, "origin", SSH2_FXF_READ, NULL,
	    &from_handle, &from_handle_len) != 0)
		return -1;

	/* Send open request to write side */
	a->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a->perm &= 0777;
	if (!preserve_flag)
		a->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	if (send_open(to, to_path, "dest",
	    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
	    &to_handle, &to_handle_len) != 0) {
		sftp_close(from, from_handle, from_handle_len);
		return -1;
	}

	/* Read from remote "from" and write to remote "to" */
	offset = 0;
	write_error = read_error = num_req = num_upload_req = 0;
	max_req = 1;
	progress_counter = 0;

	if (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(from_path),
		    size, &progress_counter);
	}
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	while (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		if (interrupted) {
			if (num_req == 0) /* If we haven't started yet... */
				break;
			max_req = 0;
		}

		/* Send some more requests */
		while (num_req < max_req) {
			debug3("Request range %llu -> %llu (%d/%d)",
			    (unsigned long long)offset,
			    (unsigned long long)offset + buflen - 1,
			    num_req, max_req);
			req = request_enqueue(&requests, from->msg_id++,
			    buflen, offset);
			offset += buflen;
			num_req++;
			send_read_request(from, req->id, req->offset,
			    req->len, from_handle, from_handle_len);
		}

		/* Try to eat replies from the upload side (nonblocking) */
		handle_dest_replies(to, to_path, 0,
		    &num_upload_req, &write_error);

		sshbuf_reset(msg);
		get_msg(from, msg);
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		if ((req = request_find(&requests, id)) == NULL)
			fatal("Unexpected reply %u", id);

		switch (type) {
		case SSH2_FXP_STATUS:
			if ((r = sshbuf_get_u32(msg, &status)) != 0)
				fatal_fr(r, "parse status");
			if (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			break;
		case SSH2_FXP_DATA:
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0)
				fatal_fr(r, "parse data");
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			if (len > req->len)
				fatal("Received more data than asked for "
				    "%zu > %zu", len, req->len);

			/* Write this chunk out to the destination */
			sshbuf_reset(msg);
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, to->msg_id++)) != 0 ||
			    (r = sshbuf_put_string(msg, to_handle,
			    to_handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, req->offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose write");
			send_msg(to, msg);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%zu",
			    id, (unsigned long long)offset, len);
			num_upload_req++;
			progress_counter += len;
			free(data);

			if (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} else {
				/* Resend the request for the missing data */
				debug3("Short data block, re-requesting "
				    "%llu -> %llu (%2d)",
				    (unsigned long long)req->offset + len,
				    (unsigned long long)req->offset +
				    req->len - 1, num_req);
				req->id = from->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(from, req->id,
				    req->offset, req->len,
				    from_handle, from_handle_len);
				/* Reduce the request size */
				if (len < buflen)
					buflen = MAXIMUM(MIN_READ_SIZE, len);
			}
			if (max_req > 0) { /* max_req = 0 iff EOF received */
				if (size > 0 && offset > size) {
					/* Only one request at a time
					 * after the expected EOF */
					debug3("Finish at %llu (%2d)",
					    (unsigned long long)offset,
					    num_req);
					max_req = 1;
				} else if (max_req < from->num_requests) {
					++max_req;
				}
			}
			break;
		default:
			error_f("Expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_DATA, type);
			sftp_hpn_set_protocol_violation(from->hpn);
			read_error = 1;
			/* See sftp_download() switch-default for rationale. */
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = 0;
			max_req = 0;
			break;
		}
	}

	if (showprogress && size)
		stop_progress_meter();

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", num_upload_req);
	handle_dest_replies(to, to_path, 1, &num_upload_req, &write_error);

	/* Sanity check */
	if (TAILQ_FIRST(&requests) != NULL)
		fatal("Transfer complete, but requests still in queue");
	/* Truncate at 0 length on interrupt or error to avoid holes at dest */
	if (read_error || write_error || interrupted) {
		debug("truncating \"%s\" at 0", to_path);
		sftp_close(to, to_handle, to_handle_len);
		free(to_handle);
		if (send_open(to, to_path, "dest",
		    SSH2_FXF_WRITE|SSH2_FXF_CREAT|SSH2_FXF_TRUNC, a,
		    &to_handle, &to_handle_len) != 0) {
			error("dest truncate \"%s\" failed", to_path);
			to_handle = NULL;
		}
	}
	if (read_error) {
		error("read origin \"%s\": %s", from_path, fx2txt(status));
		status = -1;
		sftp_close(from, from_handle, from_handle_len);
		if (to_handle != NULL)
			sftp_close(to, to_handle, to_handle_len);
	} else if (write_error) {
		error("write dest \"%s\": %s", to_path, fx2txt(write_error));
		status = SSH2_FX_FAILURE;
		sftp_close(from, from_handle, from_handle_len);
		if (to_handle != NULL)
			sftp_close(to, to_handle, to_handle_len);
	} else {
		if (sftp_close(from, from_handle, from_handle_len) != 0 ||
		    interrupted)
			status = -1;
		else
			status = SSH2_FX_OK;
		if (to_handle != NULL) {
			/* Need to resend utimes after write */
			if (preserve_flag)
				sftp_fsetstat(to, to_handle, to_handle_len, a);
			sftp_close(to, to_handle, to_handle_len);
		}
	}
	sshbuf_free(msg);
	free(from_handle);
	free(to_handle);

	return status == SSH2_FX_OK ? 0 : -1;
}

static int
crossload_dir_internal(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    int depth, Attrib *dirattrib, int preserve_flag, int print_flag,
    int follow_link_flag)
{
	int i, ret = 0, created = 0;
	SFTP_DIRENT **dir_entries;
	char *filename, *new_from_path = NULL, *new_to_path = NULL;
	mode_t mode = 0777;
	Attrib *a, curdir, ldirattrib, newdir, lsym;

	debug2_f("crossload dir src \"%s\" to dst \"%s\"", from_path, to_path);

	if (depth >= MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		return -1;
	}

	if (dirattrib == NULL) {
		if (sftp_stat(from, from_path, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" failed", from_path);
			return -1;
		}
		dirattrib = &ldirattrib;
	}
	if (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", from_path);
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", from_path);

	curdir = *dirattrib; /* dirattrib will be clobbered */
	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	if ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for "
		    "directory \"%s\"", to_path);
		curdir.perm = S_IWUSR|S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* We need to be able to write to the directory while we transfer it */
	mode = curdir.perm & 01777;
	curdir.perm = mode | (S_IWUSR|S_IXUSR);

	/*
	 * sftp lacks a portable status value to match errno EEXIST,
	 * so if we get a failure back then we must check whether
	 * the path already existed and is a directory.  Ensure we can
	 * write to the directory we create for the duration of the transfer.
	 */
	if (sftp_mkdir(to, to_path, &curdir, 0) == 0)
		created = 1;
	else {
		if (sftp_stat(to, to_path, 0, &newdir) != 0)
			return -1;
		if (!S_ISDIR(newdir.perm)) {
			error("\"%s\" exists but is not a directory", to_path);
			return -1;
		}
	}
	curdir.perm = mode;

	if (sftp_readdir(from, from_path, &dir_entries) == -1) {
		error("origin readdir \"%s\" failed", from_path);
		return -1;
	}

	for (i = 0; dir_entries[i] != NULL && !interrupted; i++) {
		free(new_from_path);
		free(new_to_path);

		filename = dir_entries[i]->filename;
		new_from_path = sftp_path_append(from_path, filename);
		new_to_path = sftp_path_append(to_path, filename);

		a = &dir_entries[i]->a;
		if (S_ISLNK(a->perm)) {
			if (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			/* Replace the stat contents with the symlink target */
			if (sftp_stat(from, new_from_path, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed",
				    new_from_path);
				ret = -1;
				continue;
			}
			a = &lsym;
		}
		if (S_ISDIR(a->perm)) {
			if (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			if (crossload_dir_internal(from, to,
			    new_from_path, new_to_path,
			    depth + 1, a, preserve_flag,
			    print_flag, follow_link_flag) == -1)
				ret = -1;
		} else if (S_ISREG(a->perm)) {
			if (sftp_crossload(from, to, new_from_path,
			    new_to_path, a, preserve_flag) == -1) {
				error("crossload \"%s\" to \"%s\" failed",
				    new_from_path, new_to_path);
				ret = -1;
			}
		} else {
			logit("origin \"%s\": not a regular file",
			    new_from_path);
		}
	}
	free(new_to_path);
	free(new_from_path);

	if (created || preserve_flag)
		sftp_setstat(to, to_path, &curdir);

	sftp_free_dirents(dir_entries);

	return ret;
}

int
sftp_crossload_dir(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *dirattrib, int preserve_flag, int print_flag, int follow_link_flag)
{
	char *from_path_canon;
	int ret;

	if ((from_path_canon = sftp_realpath(from, from_path)) == NULL) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		return -1;
	}

	ret = crossload_dir_internal(from, to, from_path_canon, to_path, 0,
	    dirattrib, preserve_flag, print_flag, follow_link_flag);
	free(from_path_canon);
	return ret;
}

int
sftp_can_get_users_groups_by_id(struct sftp_conn *conn)
{
	return (conn->exts & SFTP_EXT_GETUSERSGROUPS_BY_ID) != 0;
}

int
sftp_get_users_groups_by_id(struct sftp_conn *conn,
    const u_int *uids, u_int nuids,
    const u_int *gids, u_int ngids,
    char ***usernamesp, char ***groupnamesp)
{
	struct sshbuf *msg, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	char *name, **usernames = NULL, **groupnames = NULL;
	u_char type;
	int r;

	*usernamesp = *groupnamesp = NULL;
	if (!sftp_can_get_users_groups_by_id(conn))
		return SSH_ERR_FEATURE_UNSUPPORTED;

	if ((msg = sshbuf_new()) == NULL ||
	    (uidbuf = sshbuf_new()) == NULL ||
	    (gidbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	expected_id = id = conn->msg_id++;
	debug2("Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)");
	for (i = 0; i < nuids; i++) {
		if ((r = sshbuf_put_u32(uidbuf, uids[i])) != 0)
			fatal_fr(r, "compose uids");
	}
	for (i = 0; i < ngids; i++) {
		if ((r = sshbuf_put_u32(gidbuf, gids[i])) != 0)
			fatal_fr(r, "compose gids");
	}
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg,
	    "users-groups-by-id@openssh.com")) != 0 ||
	    (r = sshbuf_put_stringb(msg, uidbuf)) != 0 ||
	    (r = sshbuf_put_stringb(msg, gidbuf)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	get_msg(conn, msg);
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		return -1;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;
		char *errmsg;

		if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0)
			fatal_fr(r, "parse status");
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		sshbuf_free(msg);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		return -1;
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_EXTENDED_REPLY, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
		sshbuf_free(msg);
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		return -1;
	}

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = NULL;
	if ((r = sshbuf_froms(msg, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(msg, &gidbuf)) != 0)
		fatal_fr(r, "parse response");
	if (nuids > 0) {
		usernames = xcalloc(nuids, sizeof(*usernames));
		for (i = 0; i < nuids; i++) {
			if ((r = sshbuf_get_cstring(uidbuf, &name, NULL)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			if (*name == '\0') {
				free(name);
				name = NULL;
			}
			usernames[i] = name;
		}
	}
	if (ngids > 0) {
		groupnames = xcalloc(ngids, sizeof(*groupnames));
		for (i = 0; i < ngids; i++) {
			if ((r = sshbuf_get_cstring(gidbuf, &name, NULL)) != 0)
				fatal_fr(r, "parse user name");
			/* Handle unresolved names */
			if (*name == '\0') {
				free(name);
				name = NULL;
			}
			groupnames[i] = name;
		}
	}
	if (sshbuf_len(uidbuf) != 0)
		fatal_f("unexpected extra username data");
	if (sshbuf_len(gidbuf) != 0)
		fatal_f("unexpected extra groupname data");
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	sshbuf_free(msg);
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	return 0;
}

char *
sftp_path_append(const char *p1, const char *p2)
{
	char *ret;
	size_t len = strlen(p1) + strlen(p2) + 2;

	ret = xmalloc(len);
	strlcpy(ret, p1, len);
	if (p1[0] != '\0' && p1[strlen(p1) - 1] != '/')
		strlcat(ret, "/", len);
	strlcat(ret, p2, len);

	return(ret);
}

/*
 * Arg p must be dynamically allocated.  It will either be returned or
 * freed and a replacement allocated.  Caller must free returned string.
 */
char *
sftp_make_absolute(char *p, const char *pwd)
{
	char *abs_str;

	/* Derelativise */
	if (p && !path_absolute(p)) {
		abs_str = sftp_path_append(pwd, p);
		free(p);
		return(abs_str);
	} else
		return(p);
}

int
sftp_remote_is_dir(struct sftp_conn *conn, const char *path)
{
	Attrib a;

	/* XXX: report errors? */
	if (sftp_stat(conn, path, 1, &a) != 0)
		return(0);
	if (!(a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS))
		return(0);
	return S_ISDIR(a.perm);
}


/* Check whether path returned from glob(..., GLOB_MARK, ...) is a directory */
int
sftp_globpath_is_dir(const char *pathname)
{
	size_t l = strlen(pathname);

	return l > 0 && pathname[l - 1] == '/';
}

