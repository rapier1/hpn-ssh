/* $OpenBSD: sftp-client.c,v 1.186 2026/06/29 01:53:21 djm Exp $ */
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
#include "sftp-hpn-client.h" /* HPN */
#include "sftp-hpn-server.h" /* hpn-check-file + heartbeat protocol constants */
#include "sftp-client-internal.h" /* sftp_conn_verify_transfer_enabled */

#define XXH_INLINE_ALL
#include "xxhash.h"

extern _Atomic sig_atomic_t interrupted;
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
	u_int last_status;	/* most recent SSH2_FXP_STATUS code seen by
				 * get_status/get_handle; lets callers
				 * classify permanent failures (HPN) */
	int saw_perm_denied;	/* HPN: set by get_status/get_handle whenever a
				 * reply is SSH2_FX_PERMISSION_DENIED.  Read by
				 * the parallel worker's retry deciders to set
				 * u->no_retry - a refusal is permanent, so
				 * retrying only burns the budget.  Unlike
				 * last_status it survives the post-failure CLOSE
				 * (an OK close would overwrite last_status).
				 * Reset at each unit/batch status-read boundary
				 * so it is scoped to one unit/batch. */
	int saw_policy_denied;	/* HPN: a refused op was tagged by the server as
				 * a -P/-p request-policy denial (HPN_POLICY_-
				 * DENIED_TAG in the STATUS message), as opposed
				 * to a filesystem error.  Lets the bundle path
				 * abort the whole transfer (every file of this
				 * class is refused) instead of falling back per
				 * file.  Reset at each bundle attempt. */
	int fd_in;
	int fd_out;
	struct sftp_hpn_conn *hpn;  /* HPN: per-connection extensions (dead flag,
				     * live counter) */
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
#define SFTP_EXT_HPN_CHECK_FILE		0x00000400
#define SFTP_EXT_HPN_FS_INFO		0x00000800
#define SFTP_EXT_HPN_BUNDLE		0x00001000
#define SFTP_EXT_HPN_BUNDLE_FETCH	0x00002000
#define SFTP_EXT_HASH_RANGE		0x00004000
#define SFTP_EXT_HPN_FILE_LAYOUT	0x00008000
	u_int exts;
	/* HPN: operator's per-user parallel-worker cap advertised by the
	 * server in SSH2_FXP_VERSION (hpn-max-workers@hpnssh.org).
	 * -1 = not advertised (stock / non-HPN server); 0 = advertised with
	 * no cap (HPN server, admin set none); N>0 = advertised cap. */
	int hpn_max_workers_cap;
	uint64_t limit_kbps;
	struct bwlimit bwlimit_in, bwlimit_out;
	struct sshbuf *msg;	/* persistent message buffer, reset by send_msg/get_msg */
};

/* Tracks in-progress requests during file transfers */
struct request {
	u_int id;
	size_t len;
	uint64_t offset;
	TAILQ_ENTRY(request) tq;
};
TAILQ_HEAD(requests, request);

u_char *
get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...) __attribute__((format(printf, 4, 5)));

/* Forward declarations for hash helpers used by sftp_download (verified resume) */

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

/* HPN: send_msg / get_msg / get_handle dropped `static` qualifier so
 * HPN-only client code (sftp-hpn-client.c) can implement extension
 * helpers like sftp_hpn_bundle_download without redefining the SFTP
 * transport layer.  Declarations live in sftp-client-internal.h. */
int
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
		/* EPIPE/EBADF mean the connection is simply GONE - the ssh
		 * child died, or the orchestrator's abort closed the fd under
		 * us (every worker hits this at once on a user interrupt).
		 * That condition is always surfaced better elsewhere (respawn
		 * notice, transfer-health summary), so keep it out of the
		 * user's face; anything else is a real send error. */
		if (errno == EPIPE || errno == EBADF)
			debug("sftp: send: %s", strerror(errno));
		else
			error("sftp: send: %s", strerror(errno));
		conn->hpn->dead = 1; /* HPN */
		sshbuf_reset(m);
		return -1;
	}

	sshbuf_reset(m);

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
	{
	size_t got = atomicio6(read, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL);
	if (got != 4) {
		int e = errno;
		if (e == EPIPE || e == ECONNRESET)
			debug("sftp: connection closed");
		else
			debug("sftp: read: %s", strerror(e));
		/*
		 * ENV-VAR HPN_PARALLEL_TRACE: surface who closed the transport
		 * pipe.  got=0 between messages = clean peer EOF (transport
		 * exited / server closed the channel); a partial read = peer
		 * vanished mid-message.  The pipe to the ssh child is local,
		 * so this is almost always EOF, not a TCP errno.
		 */
		if (getenv("HPN_PARALLEL_TRACE") != NULL)
			logit("sftp CONN-DIAG: get_msg hdr-read got=%zu/4 "
			    "errno=%d(%s)", got, e,
			    e == 0 ? "EOF" : strerror(e));
		conn->hpn->dead = 1; /* HPN */
		return -1;
	}
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
	{
	size_t gotb = atomicio6(read, conn->fd_in, p, msg_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL);
	if (gotb != msg_len) {
		int e = errno;
		if (e == EPIPE)
			debug("sftp: connection closed");
		else
			debug("sftp: read: %s", strerror(e));
		if (getenv("HPN_PARALLEL_TRACE") != NULL)
			logit("sftp CONN-DIAG: get_msg body-read got=%zu/%u "
			    "errno=%d(%s)", gotb, msg_len, e,
			    e == 0 ? "EOF" : strerror(e));
		conn->hpn->dead = 1; /* HPN */
		return -1;
	}
	}

	return 0;
}

int
get_msg(struct sftp_conn *conn, struct sshbuf *m)
{
	return get_msg_extended(conn, m, 0);
}

static void
send_string_request(struct sftp_conn *conn, u_int id, u_int code, const char *s,
    u_int len)
{
	struct sshbuf *msg = conn->msg;
	int r;

	/*
	 * Reset before building: response-reading helpers (e.g. get_status)
	 * do not consume the full STATUS packet - error-message and
	 * language-tag strings are left unread.  Without this reset, those
	 * leftover bytes would be prepended to the outgoing request by
	 * send_msg(), corrupting the message stream.
	 */
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u", conn->fd_out, code, id);
}

static void
send_string_attrs_request(struct sftp_conn *conn, u_int id, u_int code,
    const void *s, u_int len, Attrib *a)
{
	struct sshbuf *msg = conn->msg;
	int r;

	/* Reset for the same reason as send_string_request above. */
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, code)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, s, len)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fd %d T:%u I:%u F:0x%04x M:%05o",
	    conn->fd_out, code, id, a->flags, a->perm);
}

static u_int
get_status(struct sftp_conn *conn, u_int expected_id)
{
	struct sshbuf *msg = conn->msg;
	u_char type;
	u_int id, status;
	int r;

	/* Recycled conn->msg buffer (18.10 feature-sftp-allocs); error
	 * returns instead of fatal (parallel-streams fault isolation). */
	if (get_msg(conn, msg) != 0)
		return SSH2_FX_CONNECTION_LOST;
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "compose");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}
	if (type != SSH2_FXP_STATUS) {
		error_f("expected SSH2_FXP_STATUS(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_STATUS, type);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}

	if ((r = sshbuf_get_u32(msg, &status)) != 0)
		fatal_fr(r, "parse");

	debug3("SSH2_FXP_STATUS %u", status);

	conn->last_status = status; /* HPN: permanent-failure classification */
	if (status == SSH2_FX_PERMISSION_DENIED) {
		conn->saw_perm_denied = 1; /* HPN: sticky no-retry signal */
		sftp_conn_check_policy_tag(conn, msg); /* HPN: policy-abort */
	}
	return status;
}

u_char *
get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...)
{
	struct sshbuf *msg = conn->msg;
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

	if (get_msg(conn, msg) != 0)
		return NULL;
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error("%s: ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return NULL;
	}
	if (type == SSH2_FXP_STATUS) {
		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		conn->last_status = status; /* HPN */
		if (status == SSH2_FX_PERMISSION_DENIED) {
			conn->saw_perm_denied = 1; /* HPN: sticky no-retry */
			sftp_conn_check_policy_tag(conn, msg); /* HPN */
		}
		if (errfmt != NULL)
			error("%s: %s", errmsg, fx2txt(status));
		return NULL;
	} else if (type != SSH2_FXP_HANDLE) {
		error("%s: expected SSH2_FXP_HANDLE(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, SSH2_FXP_HANDLE, type);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return NULL;
	}

	if ((r = sshbuf_get_string(msg, &handle, len)) != 0)
		fatal_fr(r, "parse handle");

	return handle;
}

static int
get_decode_stat(struct sftp_conn *conn, u_int expected_id, int quiet, Attrib *a)
{
	struct sshbuf *msg = conn->msg;
	u_int id;
	u_char type;
	int r;
	Attrib attr;

	if (a != NULL)
		memset(a, '\0', sizeof(*a));
	if (get_msg(conn, msg) != 0)
		return -1;

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
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
		return -1;
	} else if (type != SSH2_FXP_ATTRS) {
		error_f("expected SSH2_FXP_ATTRS(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_ATTRS, type);
		sftp_hpn_set_protocol_violation(conn->hpn); /* HPN */
		return -1;
	}
	if ((r = decode_attrib(msg, &attr)) != 0) {
		error_fr(r, "decode_attrib");
		return -1;
	}
	/* success */
	if (a != NULL)
		*a = attr;
	debug3("Received stat reply T:%u I:%u F:0x%04x M:%05o",
	    type, id, attr.flags, attr.perm);

	return 0;
}

static int
get_decode_statvfs(struct sftp_conn *conn, struct sftp_statvfs *st,
    u_int expected_id, int quiet)
{
	struct sshbuf *msg = conn->msg;
	u_char type;
	u_int id;
	uint64_t flag;
	int r;

	if (get_msg(conn, msg) != 0)
		return -1;

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received statvfs reply T:%u I:%u", type, id);
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
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
		return -1;
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, "
		    "got %u - possible MITM or server protocol corruption",
		    SSH2_FXP_EXTENDED_REPLY, type);
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

	return 0;
}

struct sftp_conn *
sftp_init(int fd_in, int fd_out, u_int transfer_buflen, u_int num_requests,
    uint64_t limit_kbps)
{
	u_char type;
	struct sftp_conn *ret;
	struct sshbuf *msg;
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
	/* HPN: seed the adaptive read-ahead controller with -R as its ceiling. */
	sftp_hpn_rdahead_init(ret->hpn, ret->num_requests);
	ret->exts = 0;
	ret->hpn_max_workers_cap = -1;	/* -1 until/unless the server advertises */
	ret->limit_kbps = 0;

	if ((ret->msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	msg = ret->msg;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_msg(ret, msg);

	if (get_msg_extended(ret, msg, 1) < 0) {
		/*
		 * The transport closed the connection before the SFTP
		 * handshake completed (e.g. it refused the requested cipher
		 * and exited with its own message). Let that message stand
		 * rather than reporting a bogus "type 0" packet.
		 */
		sshbuf_free(ret->msg);
		free(ret);
		return(NULL);
	}

	/* Expecting a VERSION reply */
	if ((r = sshbuf_get_u8(msg, &type)) != 0)
		fatal_fr(r, "parse type");
	if (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		sshbuf_free(ret->msg);
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
		} else if (strcmp(name, "hpn-check-file@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			ret->exts |= SFTP_EXT_HPN_CHECK_FILE;
			known = 1;
		} else if (strcmp(name, "sftp-hash-range@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* Chunked resume: per-range XXH3 batching so a verified
			 * resume re-transfers only mismatched chunks instead of
			 * the whole file on size-match-hash-mismatch.  See
			 * project-chunked-resume-plan memory. */
			ret->exts |= SFTP_EXT_HASH_RANGE;
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
		} else if (strcmp(name, "hpn-bundle-fetch@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* Phase 5: server can produce tar-format bundles from
			 * a list of paths via hpn-bundle-fetch@hpnssh.org. */
			ret->exts |= SFTP_EXT_HPN_BUNDLE_FETCH;
			known = 1;
		} else if (strcmp(name, "hpn-file-layout@hpnssh.org") == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* Server can apply a Lustre stripe layout to a
			 * destination directory before files land there.
			 * Used by HPNLustreStripeCount auto-stripe.  See
			 * sftp-hpn-server.h for wire format. */
			ret->exts |= SFTP_EXT_HPN_FILE_LAYOUT;
			known = 1;
		} else if (strcmp(name, "hpn-max-workers@hpnssh.org") == 0) {
			/* Operator's per-user parallel-worker cap.  The value
			 * is a decimal count, not a revision: 0 = HPN server
			 * with no cap, N>0 = cap.  The orchestrator clamps -j
			 * to it (and applies a conservative default when this
			 * is absent, i.e. a non-HPN server). */
			const char *errstr = NULL;
			long long v = strtonum((char *)value, 0,
			    1000000, &errstr);
			/* Parse generously; the orchestrator clamps to the
			 * hard SFTP_PARALLEL_MAX_WORKERS ceiling. */
			if (errstr == NULL)
				ret->hpn_max_workers_cap = (int)v;
			else
				ret->hpn_max_workers_cap = 0; /* malformed = no cap */
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
	sshbuf_free(conn->msg);        /* recycled message buffer */
	sftp_hpn_conn_free(conn->hpn); /* HPN per-conn state */
	freezero(conn, sizeof(*conn));
}

u_int
sftp_proto_version(struct sftp_conn *conn)
{
	return conn->version;
}

/*
 * HPN: the operator's per-user parallel-worker cap as advertised by the
 * server (hpn-max-workers@hpnssh.org).  Returns -1 when the server did not
 * advertise it (a stock / non-HPN server), 0 when advertised with no cap,
 * or the positive cap otherwise.  The orchestrator uses this to clamp -j.
 */
int
sftp_hpn_max_workers_cap(struct sftp_conn *conn)
{
	return conn->hpn_max_workers_cap;
}

/* HPN: thin wrappers - logic lives in sftp-hpn-client.c */
int
sftp_conn_is_dead(struct sftp_conn *conn)
{
	return conn != NULL && sftp_hpn_is_dead(conn->hpn);
}

/* HPN: permanent-denial signal accessors (struct sftp_conn is opaque to
 * callers; the parallel worker uses these to set no_retry on a refusal). */
int
sftp_conn_saw_perm_denied(struct sftp_conn *conn)
{
	return conn != NULL && conn->saw_perm_denied;
}

void
sftp_conn_clear_perm_denied(struct sftp_conn *conn)
{
	if (conn != NULL)
		conn->saw_perm_denied = 0;
}

int
sftp_conn_saw_policy_denied(struct sftp_conn *conn)
{
	return conn != NULL && conn->saw_policy_denied;
}

void
sftp_conn_clear_policy_denied(struct sftp_conn *conn)
{
	if (conn != NULL)
		conn->saw_policy_denied = 0;
}

/*
 * Called right after a PERMISSION_DENIED status code is read, with `msg`
 * positioned at the status reply's error-message string.  If that message
 * carries HPN_POLICY_DENIED_TAG the refusal came from the server's -P/-p
 * request policy (not a filesystem error), so latch saw_policy_denied.
 * Consumes the message string from `msg`; harmless on a buffer that has none.
 */
void
sftp_conn_check_policy_tag(struct sftp_conn *conn, struct sshbuf *msg)
{
	char *errmsg = NULL;

	if (conn == NULL || msg == NULL)
		return;
	if (sshbuf_get_cstring(msg, &errmsg, NULL) == 0 && errmsg != NULL &&
	    strstr(errmsg, HPN_POLICY_DENIED_TAG) != NULL)
		conn->saw_policy_denied = 1;
	free(errmsg);
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
sftp_set_yield_flag(struct sftp_conn *conn, volatile int *flag)
{
	if (conn != NULL)
		sftp_hpn_set_yield_flag(conn->hpn, flag);
}

/* Cooperative yield requested for this connection (tail redistribution)?
 * Checked once per loop iteration by the range transfer paths. */
static int
yield_requested(struct sftp_conn *conn)
{
	return conn->hpn->yield_flag != NULL &&
	    __atomic_load_n(conn->hpn->yield_flag, __ATOMIC_RELAXED);
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
	struct sshbuf *msg = conn->msg;
	int r;

	if ((conn->exts & SFTP_EXT_LIMITS) == 0) {
		error("Server does not support limits@openssh.com extension");
		return -1;
	}

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "limits@openssh.com")) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message limits@openssh.com I:%u", id);

	if (get_msg(conn, msg) != 0)
		return -1;

	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &msg_id)) != 0)
		fatal_fr(r, "parse");

	debug3("Received limits reply T:%u I:%u", type, msg_id);
	if (id != msg_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    msg_id, id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		return -1;
	}
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
		    SSH2_FXP_EXTENDED_REPLY, type);
		/* Disable the limits extension */
		conn->exts &= ~SFTP_EXT_LIMITS;
		return -1;
	}

	memset(limits, 0, sizeof(*limits));
	if ((r = sshbuf_get_u64(msg, &limits->packet_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->read_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->write_length)) != 0 ||
	    (r = sshbuf_get_u64(msg, &limits->open_handles)) != 0)
		fatal_fr(r, "parse limits");

	return 0;
}

int
sftp_close(struct sftp_conn *conn, const u_char *handle, u_int handle_len)
{
	u_int id, status;
	struct sshbuf *msg = conn->msg;
	int r;

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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

	return status == SSH2_FX_OK ? 0 : -1;
}


static int
sftp_lsreaddir(struct sftp_conn *conn, const char *path, int print_flag,
    SFTP_DIRENT ***dir)
{
	struct sshbuf *msg = conn->msg;
	u_int count, id, i, expected_id, ents = 0;
	size_t handle_len;
	u_char type, *handle;
	int status = SSH2_FX_FAILURE;
	int r;

	if (dir)
		*dir = NULL;

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;

	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPENDIR)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose OPENDIR");
	send_msg(conn, msg);

	handle = get_handle(conn, id, &handle_len,
	    "remote readdir(\"%s\")", path);
	if (handle == NULL)
		return -1;

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

		if (get_msg(conn, msg) != 0) {
			status = -1;
			goto out;
		}

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
	struct sshbuf *msg = conn->msg;
	u_int expected_id, count, id;
	char *filename, *longname;
	Attrib a;
	u_char type;
	int r;
	const char *what = "SSH2_FXP_REALPATH";

	if (expand)
		what = "expand-path@openssh.com";

	expected_id = id = conn->msg_id++;
	if (expand) {
		/* Reset for the same reason as send_string_request. */
		sshbuf_reset(msg);
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
	if (get_msg(conn, msg) != 0)
		return NULL;
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
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
		return NULL;
	} else if (type != SSH2_FXP_NAME) {
		error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_NAME, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
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

	struct sshbuf *msg = conn->msg;

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, oldpath)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FXF_READ)) != 0 ||
	    (r = encode_attrib(msg, &junk)) != 0)
		fatal_fr(r, "buffer error");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_OPEN I:%u P:%s", id, oldpath);

	old_handle = get_handle(conn, id, &old_handle_len,
	    "remote open(\"%s\")", oldpath);
	if (old_handle == NULL)
		return -1;

	/* Open the new file for writing */
	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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

	new_handle = get_handle(conn, id, &new_handle_len,
	    "remote open(\"%s\")", newpath);
	if (new_handle == NULL) {
		free(old_handle);
		return -1;
	}

	/* Copy the file data */
	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r, use_ext = (conn->exts & SFTP_EXT_POSIX_RENAME) && !force_legacy;

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote rename \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_hardlink(struct sftp_conn *conn, const char *oldpath, const char *newpath)
{
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r;

	if ((conn->exts & SFTP_EXT_HARDLINK) == 0) {
		error("Server does not support hardlink@openssh.com extension");
		return -1;
	}
	debug2("Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) "
	    "\"%s\" to \"%s\"", oldpath, newpath);

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote link \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_symlink(struct sftp_conn *conn, const char *oldpath, const char *newpath)
{
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r;

	if (conn->version < 3) {
		error("This server does not support the symlink operation");
		return(SSH2_FX_OP_UNSUPPORTED);
	}
	debug2("Sending SSH2_FXP_SYMLINK \"%s\" to \"%s\"", oldpath, newpath);

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote symlink file \"%s\" to \"%s\": %s", oldpath,
		    newpath, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

int
sftp_fsync(struct sftp_conn *conn, u_char *handle, u_int handle_len)
{
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r;

	/* Silently return if the extension is not supported */
	if ((conn->exts & SFTP_EXT_FSYNC) == 0)
		return -1;
	debug2("Sending SSH2_FXP_EXTENDED(fsync@openssh.com)");

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	/* Send fsync request */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	debug3("Sent message fsync@openssh.com I:%u", id);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote fsync: %s", fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

#ifdef notyet
char *
sftp_readlink(struct sftp_conn *conn, const char *path)
{
	struct sshbuf *msg = conn->msg;
	u_int expected_id, count, id;
	char *filename, *longname;
	Attrib a;
	u_char type;
	int r;

	debug2("Sending SSH2_FXP_READLINK \"%s\"", path);

	expected_id = id = conn->msg_id++;
	send_string_request(conn, id, SSH2_FXP_READLINK, path, strlen(path));

	if (get_msg(conn, msg) != 0)
		return NULL;
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
		return NULL;
	}

	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		return(NULL);
	} else if (type != SSH2_FXP_NAME) {
		error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_NAME, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
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

	return filename;
}
#endif

int
sftp_statvfs(struct sftp_conn *conn, const char *path, struct sftp_statvfs *st,
    int quiet)
{
	struct sshbuf *msg = conn->msg;
	u_int id;
	int r;

	if ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;

	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "statvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);

	return get_decode_statvfs(conn, st, id, quiet);
}

#ifdef notyet
int
sftp_fstatvfs(struct sftp_conn *conn, const u_char *handle, u_int handle_len,
    struct sftp_statvfs *st, int quiet)
{
	struct sshbuf *msg = conn->msg;
	u_int id;

	if ((conn->exts & SFTP_EXT_FSTATVFS) == 0) {
		error("Server does not support fstatvfs@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(fstatvfs@openssh.com)");

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;

	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "fstatvfs@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);

	return get_decode_statvfs(conn, st, id, quiet);
}
#endif

int
sftp_lsetstat(struct sftp_conn *conn, const char *path, Attrib *a)
{
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r;

	if ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "lsetstat@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK)
		error("remote lsetstat \"%s\": %s", path, fx2txt(status));

	return status == SSH2_FX_OK ? 0 : -1;
}

static void
send_read_request(struct sftp_conn *conn, u_int id, uint64_t offset,
    u_int len, const u_char *handle, u_int handle_len)
{
	struct sshbuf *msg = conn->msg;
	int r;

	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, offset)) != 0 ||
	    (r = sshbuf_put_u32(msg, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
}

static int
send_open(struct sftp_conn *conn, const char *path, const char *tag,
    u_int openmode, Attrib *a, u_char **handlep, size_t *handle_lenp)
{
	Attrib junk;
	u_char *handle;
	size_t handle_len;
	struct sshbuf *msg = conn->msg;
	int r;
	u_int id;

	debug2("Sending SSH2_FXP_OPEN \"%s\"", path);

	*handlep = NULL;
	*handle_lenp = 0;

	if (a == NULL) {
		attrib_clear(&junk); /* Send empty attributes */
		a = &junk;
	}
	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	/* Send open request */
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, openmode)) != 0 ||
	    (r = encode_attrib(msg, a)) != 0)
		fatal_fr(r, "compose %s open", tag);
	send_msg(conn, msg);
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

/*
 * Serial resume-check meter (HPN): spans the pre-transfer hash work in the
 * verify branches of sftp_upload/sftp_download, so a -Z user sees progress
 * instead of a silent stretch while both ends hash the existing partial.
 * The hash engines feed the counter at heartbeat cadence through the
 * registered pointer (sftp_conn_set_hash_meter_ctr), which is what lets the
 * meter advance while this single thread is blocked in the hash protocol
 * loop.  No-op when showprogress is off (quiet, batch, parallel workers -
 * the orchestrator renders its own aggregate resume-check stretch).
 * end() is idempotent, so convergent exit paths may all call it.
 */
static volatile off_t resume_meter_ctr;
static int resume_meter_on;

static void
resume_check_meter_begin(struct sftp_conn *conn, off_t total)
{
	if (!showprogress || total <= 0)
		return;
	resume_meter_ctr = 0;
	start_progress_meter("resume check", total,
	    (off_t *)&resume_meter_ctr);
	progressmeter_frames_meter_not_a_file();	/* not a file */
	progressmeter_frames_set_phase(HPNS_F_RESUME, 1);	/* phase flag */
	sftp_conn_set_hash_meter_ctr(conn, &resume_meter_ctr);
	resume_meter_on = 1;
}

static void
resume_check_meter_end(struct sftp_conn *conn)
{
	if (!resume_meter_on)
		return;
	sftp_conn_set_hash_meter_ctr(conn, NULL);
	stop_progress_meter();
	resume_meter_on = 0;
}

int
sftp_download(struct sftp_conn *conn, const char *remote_path,
    const char *local_path, Attrib *a, int preserve_flag, int resume_flag,
    int fsync_flag, int inplace_flag, int verify)
{
	struct sshbuf *msg = conn->msg;
	u_char *handle;
	int local_fd = -1, write_error, seen_zerolen = 0;
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

	local_fd = open(local_path,
	    ((resume_flag && verify) ? O_RDWR : O_WRONLY) | O_CREAT |
	    ((resume_flag || inplace_flag) ? 0 : O_TRUNC), mode | S_IWUSR);
	if (local_fd == -1) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		sftp_close(conn, handle, handle_len);
		free(handle);
		return -1;
	}
	if (resume_flag) {
		/* -1=error, 1=identical, 2=target larger than source */
		int skip_ret = -1;
		if (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			goto resume_fail;
		}
		if (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			goto resume_fail;
		}
		if (verify) {
			/*
			 * Verified resume requires hpn-check-file@hpnssh.org.
			 * Check it up front (before inspecting the local file)
			 * so the failure is identical whether the local file
			 * is absent, partial, or full-size - mirroring
			 * sftp_upload.  No silent fallback to a fresh
			 * download; the caller asked for verification.  See
			 * RESUME_INCOMPAT_MSG.
			 */
			if ((conn->exts & SFTP_EXT_HPN_CHECK_FILE) == 0)
				fatal("\"%s\": %s", remote_path,
				    RESUME_INCOMPAT_MSG);
			/* Resume-check meter: spans the hash work below in
			 * WORK-bytes - the overlap is hashed on both ends. */
			resume_check_meter_begin(conn,
			    2 * MINIMUM(st.st_size, (off_t)size));
			if ((uint64_t)st.st_size == size) {
				/*
				 * Chunked-resume fast path: when the server
				 * supports sftp-hash-range@hpnssh.org, hash
				 * per-chunk and re-fetch only mismatched chunks
				 * instead of truncating + re-downloading the
				 * whole file.  Declines (returns -1) on small
				 * files, missing extension, or internal
				 * failure; we fall through to the whole-file
				 * gate below - same correctness, just costlier
				 * on a size-match-hash-mismatch.
				 */
				int chunked =
				    sftp_hpn_try_chunked_resume_download(
				        conn, local_fd, local_path,
				        remote_path, (off_t)size,
				        st.st_size /* dest-EOF clamp */);
				if (chunked >= 0) {
					skip_ret = chunked == 1 ? 1 : 0;
					goto resume_fail;
				}

				uint64_t local_hash, remote_hash;
				int lret, rret;

				/*
				 * Option A: equal size does NOT imply equal
				 * content.  A range-split download pre-creates
				 * the local file at full size, so a crashed
				 * transfer leaves it full-size with sparse-zero
				 * holes.  Hash the whole file on both ends and
				 * skip only if they match; otherwise truncate
				 * and re-download.  Closes the crash-resume
				 * sparse-hole corruption gap.
				 */
				/*
				 * Always strict: hash both ends off the platter
				 * and compare; equal size never implies equal
				 * content.  STRICT is always sent so a pre-Phase-1
				 * server still hashes instead of returning the
				 * (removed) fully-allocated sentinel.
				 */
				sftp_hpn_watchdog_pause(conn->hpn,
				    HPN_HEARTBEAT_REFRESH_SEC);
				/* hash-work op: remote leg first here */
				sftp_conn_hash_op_begin(conn, 2 * size);
				rret = sftp_hpn_hash_remote_file(conn,
				    remote_path, size, &remote_hash);
				sftp_conn_hash_op_leg(conn, size);
				lret = sftp_hpn_xxhash_local_fd(conn, local_fd,
				    size, &local_hash);
				sftp_hpn_watchdog_resume(conn->hpn);
				if (lret == 0 && rret == 0 &&
				    local_hash == remote_hash) {
					debug("verified transfer: "
					    "full-file hash match, "
					    "\"%s\" already complete",
					    local_path);
					skip_ret = 1; /* identical */
					goto resume_fail;
				}
				debug("verified transfer: same size "
				    "but hash mismatch for \"%s\"; "
				    "re-downloading from scratch",
				    local_path);
				if (ftruncate(local_fd, 0) == -1) {
					error("truncate \"%s\": %s",
					    local_path, strerror(errno));
					goto resume_fail;
				}
				/* offset stays 0; fresh download */
			} else if ((uint64_t)st.st_size > size) {
				skip_ret = 2; /* target larger than source */
				goto resume_fail;
			} else if (st.st_size > 0) {
				/*
				 * Chunked verify FIRST (mirrors the upload
				 * side): a lazily-created range-split local
				 * partial grows to its pwrite highwater and
				 * may hold interior holes below that size -
				 * prefix resume would append past them and
				 * corrupt.  Chunks past local EOF are clamped
				 * as known-missing (never hashed) and
				 * re-fetched directly.  Declines fall through
				 * to prefix resume (sequential partials,
				 * sub-threshold files).
				 */
				int dchunked =
				    sftp_hpn_try_chunked_resume_download(
				        conn, local_fd, local_path,
				        remote_path, (off_t)size,
				        st.st_size /* dest-EOF clamp */);
				if (dchunked >= 0) {
					skip_ret = dchunked == 1 ? 1 : 0;
					goto resume_fail;
				}

				uint64_t local_hash, remote_hash;
				int lret, rret;

				/*
				 * Partial local file: hash the overlapping
				 * prefix to decide resume (continue) vs
				 * restart (truncate).  The server always
				 * returns the real prefix hash off the platter
				 * (no trust shortcut), so the comparison below
				 * is exact.
				 */
				sftp_hpn_watchdog_pause(conn->hpn,
				    HPN_HEARTBEAT_REFRESH_SEC);
				/* hash-work op: local leg first here */
				sftp_conn_hash_op_begin(conn,
				    2 * (uint64_t)st.st_size);
				lret = sftp_hpn_xxhash_local_fd(conn, local_fd,
				    (uint64_t)st.st_size, &local_hash);
				sftp_conn_hash_op_leg(conn,
				    (uint64_t)st.st_size);
				rret = sftp_hpn_hash_remote_file(conn,
				    remote_path, (uint64_t)st.st_size,
				    &remote_hash);
				sftp_hpn_watchdog_resume(conn->hpn);
				if (lret == 0 && rret == 0 &&
				    local_hash == remote_hash) {
					debug("verified resume: prefix "
					    "hash match, resuming at "
					    "offset %llu",
					    (unsigned long long)
					    st.st_size);
					offset = highwater = maxack =
					    st.st_size;
				} else {
					debug("verified resume: prefix "
					    "hash mismatch or error; "
					    "restarting download");
					if (ftruncate(local_fd, 0) == -1) {
						error("truncate \"%s\": %s",
						    local_path,
						    strerror(errno));
						goto resume_fail;
					}
					/* offset stays 0 */
				}
			}
			/* st.st_size == 0 (or size-match mismatch, now
			 * truncated): fresh download, offset stays 0 */
		} else {
			/* Plain size-only resume */
			if ((uint64_t)st.st_size > size) {
				skip_ret = 2; /* target larger than source */
				goto resume_fail;
			}
			offset = highwater = maxack = st.st_size;
		}
		goto resume_done;
 resume_fail:
		resume_check_meter_end(conn);
		sftp_close(conn, handle, handle_len);
		free(handle);
		if (local_fd != -1)
			close(local_fd);
		if (skip_ret >= 0)	/* resolved, no transfer meter ran */
			progressmeter_frames_count_file();
		return skip_ret;
 resume_done:
		resume_check_meter_end(conn);
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = num_req = 0;
	max_req = 1;
	progress_counter = offset;

	if (showprogress && size != 0) {
		start_progress_meter(progress_meter_path(remote_path),
		    size, &progress_counter);
	}

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
		/* Time the DATA-reply read so the rdahead controller can
		 * react to a wedged path - same mechanism as the upload-
		 * side STATUS-read instrumentation in do_upload_body.  A
		 * read that blocks longer than the threshold means the
		 * server isn't sending DATA back fast enough (TCP back-
		 * pressure, busy server-side I/O, etc.); signal so the
		 * controller can halve depth and re-probe. */
		{
			double t_data_start = monotime_double();
			if (get_msg(conn, msg) != 0)
				break;
			if (monotime_double() - t_data_start >
			    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
				sftp_hpn_rdahead_backpressure_signal(conn->hpn);
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0)
			fatal_fr(r, "parse");
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		if ((req = request_find(&requests, id)) == NULL) {
			/* Was fatal("Unexpected reply %u", id); - would
			 * crash the entire orchestrator if this worker is
			 * one of N in a parallel-streams transfer.  Mark
			 * this connection dead and bail to the worker
			 * thread's safety net, which checks conn->dead and
			 * triggers respawn. */
			sftp_conn_die(conn, "Unexpected reply %u", id);
			read_error = 1;
			max_req = 0;
			num_req = 0;
			break;
		}

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
			sftp_hpn_bytes_wired_add(conn->hpn, (uint64_t)len);
			if (len == 0) {
				if (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}
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
				} else {
					/* HPN adaptive read-ahead window. */
					max_req = sftp_hpn_rdahead_window(
					    conn->hpn, len, max_req,
					    conn->num_requests);
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

	/*
	 * Requests still queued here means the loop broke early on a dead
	 * connection (get_msg failure, or an unexpected reply) - num_req tracks
	 * the queue, so a clean num_req==0 loop exit always leaves it empty.
	 * This is a survivable per-worker event, NOT a clean completion: drain
	 * the queue, mark the connection dead, and fail the download soft so the
	 * worker's safety net respawns it, rather than fatal()-ing and taking
	 * the whole parallel orchestrator down with it (cf. the "Unexpected
	 * reply" sftp_conn_die above).
	 */
	if (TAILQ_FIRST(&requests) != NULL) {
		if (!sftp_conn_is_dead(conn))
			sftp_conn_die(conn, "download of \"%s\" ended with "
			    "requests still in flight (connection lost)",
			    remote_path);
		while ((req = TAILQ_FIRST(&requests)) != NULL) {
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
		}
		read_error = 1;
	}

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
		if (status == SSH2_FX_PERMISSION_DENIED)
			conn->saw_perm_denied = 1; /* HPN: no-retry */
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
	free(handle);

	/*
	 * Park for the post-transfer verify phase (HPN): every downloaded file -
	 * single-file and recursive, since download_dir_internal funnels through
	 * here - is verified after the command's transfers finish (closing the
	 * classic `get -r` gap).  Only on a clean download.  No-op unless verify
	 * enabled.
	 */
	if (status == SSH2_FX_OK)
		sftp_conn_verify_park(conn, local_path, remote_path,
		    /*local_is_target=*/1);

	return status == SSH2_FX_OK ? 0 : -1;
}

static int
download_dir_internal(struct sftp_conn *conn, const char *src, const char *dst,
    int depth, Attrib *dirattrib, int preserve_flag, int print_flag,
    int resume_flag, int verify, int fsync_flag, int follow_link_flag,
    int inplace_flag)
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
			    print_flag, resume_flag, verify,
			    fsync_flag, follow_link_flag, inplace_flag) == -1)
				ret = -1;
		} else if (S_ISREG(a->perm)) {
			int dr = sftp_download(conn, new_src, new_dst, a,
			    preserve_flag, resume_flag, fsync_flag,
			    inplace_flag, verify);
			if (dr == -1) {
				error("Download of file %s to %s failed",
				    new_src, new_dst);
				ret = -1;
			} else if (dr == 1) {
				/* frame mode: stdout carries binary frames,
				 * text on it corrupts the relay stream */
				fmprintf(progressmeter_frames_active() ?
				    stderr : stdout,
				    "File skipped: %s: Identical.\n",
				    new_src);
			} else if (dr == 2) {
				fmprintf(progressmeter_frames_active() ?
				    stderr : stdout,
				    "File skipped: %s: Target is larger"
				    " than source.\n", new_src);
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
    int verify, int fsync_flag, int follow_link_flag, int inplace_flag)
{
	char *src_canon;
	int ret;

	if ((src_canon = sftp_realpath(conn, src)) == NULL) {
		error("download \"%s\": path canonicalization failed", src);
		return -1;
	}

	ret = download_dir_internal(conn, src_canon, dst, 0,
	    dirattrib, preserve_flag, print_flag, resume_flag, verify,
	    fsync_flag, follow_link_flag, inplace_flag);
	free(src_canon);
	return ret;
}

/*
 * Core write loop shared by sftp_upload and the pipelined batch upload path.
 * See sftp-client.h (sftp_upload_batch_send/finish) for design notes.
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

	/*
	 * HPN 1b: when post-transfer verify is enabled and this is a whole-
	 * file upload (offset 0), tee the source bytes into a streaming XXH3
	 * as we read them, so the verify step need not re-read the source.
	 */
	if (conn->hpn != NULL && conn->hpn->verify_transfer_enabled &&
	    resume_offset == 0)
		sftp_hpn_src_arm(conn->hpn);

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
			/* HPN 1b: hash the source bytes as they are read so the
			 * inline source hash reflects the on-disk source. */
			sftp_hpn_src_feed(conn->hpn, data, (size_t)len);
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
			sftp_hpn_bytes_wired_add(conn->hpn, (uint64_t)len);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} else if (TAILQ_FIRST(&acks) == NULL)
			break;

		if (ack == NULL) {
			/* Was fatal("Unexpected ACK %u", id); - would crash the
			 * entire orchestrator if this worker is one of N in a
			 * parallel-streams transfer.  Mark this connection dead
			 * and bail to the worker thread's safety net, which
			 * checks conn->dead and triggers respawn. */
			sftp_conn_die(conn, "Unexpected ACK %u", id);
			status = -1;
			break;
		}

		/* HPN adaptive read-ahead: cap outstanding writes at the
		 * controller's current depth (num_requests when disabled). */
		if (id == startid || len == 0 ||
		    id - ackid >= sftp_hpn_rdahead_cap(conn->hpn,
		    conn->num_requests)) {
			u_int rid;
			double t_status_start;

			sshbuf_reset(msg);
			/* Time the STATUS read so the rdahead controller
			 * can react to wedged paths (Pattern 2 stall in
			 * the 2026-05-30 campaign).  A read above the
			 * threshold means the pipeline is too deep for
			 * the current path; signal the controller to
			 * halve its depth and re-probe. */
			t_status_start = monotime_double();
			if (get_msg(conn, msg) != 0)
				break;
			if (monotime_double() - t_status_start >
			    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
				sftp_hpn_rdahead_backpressure_signal(conn->hpn);
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
			/* HPN adaptive read-ahead: feed acked bytes. */
			sftp_hpn_rdahead_account(conn->hpn, ack->len);
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

	if (status == SSH2_FX_OK && !interrupted) {
		highwater = maxack;
		/* HPN 1b: whole file read cleanly - finalize the inline hash. */
		sftp_hpn_src_finish(conn->hpn);
	} else {
		/* partial/aborted upload: discard so verify re-reads the source. */
		sftp_hpn_src_dispose(conn->hpn);
	}
	if (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		if (status == SSH2_FX_PERMISSION_DENIED)
			conn->saw_perm_denied = 1; /* HPN: no-retry */
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
    int verify, int fsync_flag, int inplace_flag)
{
	int r, local_fd;
	u_int openmode;
	u_char *handle;
	struct stat sb;
	Attrib a, c = {0};
	size_t handle_len;
	off_t resume_offset = 0;
	int status = 0;
	int effective_inplace = inplace_flag;

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

	/*
	 * Verified resume (verify=1): stat the remote file quietly.  If it
	 * exists and has data, compare XXH3_64bits hashes of the overlapping
	 * prefix.  A match means we can resume; a mismatch (or any error)
	 * means we restart from scratch, forcing truncation of the remote file
	 * regardless of inplace_flag.
	 *
	 * If the server does not advertise hpn-check-file@hpnssh.org we cannot
	 * verify anything, so we fail loudly (fatal below) rather than silently
	 * degrade to a blind size-only resume or a full re-transfer - the
	 * caller explicitly requested hash verification.
	 */
	if (verify) {
		debug3_f("verify=1 inplace_flag=%d exts=0x%x HPN_CHECK_FILE=0x%x",
		    inplace_flag, conn->exts, SFTP_EXT_HPN_CHECK_FILE);
		if ((conn->exts & SFTP_EXT_HPN_CHECK_FILE) == 0) {
			/* No silent fallback - see RESUME_INCOMPAT_MSG. */
			fatal("\"%s\": %s", local_path, RESUME_INCOMPAT_MSG);
		} else if (sftp_stat(conn, remote_path, 1 /* quiet */, &c) == 0
		    && c.size > 0) {
			debug3_f("remote file exists, size=%llu local_size=%llu",
			    (unsigned long long)c.size,
			    (unsigned long long)sb.st_size);
			/* Resume-check meter: spans the hash work below in
			 * WORK-bytes - the overlap is hashed on both ends. */
			resume_check_meter_begin(conn,
			    2 * MINIMUM((off_t)c.size, sb.st_size));
			if ((off_t)c.size == sb.st_size) {
				/*
				 * Chunked-resume fast path: when the server
				 * supports sftp-hash-range@hpnssh.org, hash
				 * per-chunk and re-transfer only mismatched
				 * chunks instead of the whole file.  Declines
				 * (returns -1) on small files, missing
				 * extension, or any internal failure, in which
				 * case we fall through to the whole-file gate
				 * below - same correctness, just costlier on a
				 * size-match-hash-mismatch.
				 */
				int chunked = sftp_hpn_try_chunked_resume_upload(
				    conn, local_fd, local_path, remote_path,
				    sb.st_size, (off_t)c.size /* dest clamp */);
				if (chunked >= 0) {
					resume_check_meter_end(conn);
					close(local_fd);
					progressmeter_frames_count_file();
					return chunked; /* 1=skip, 0=success */
				}

				/*
				 * Option A: equal size does NOT imply equal
				 * content.  A range-split destination is
				 * pre-created at full size, so a crashed
				 * transfer leaves it full-size with sparse-zero
				 * holes.  Hash the whole file on both ends and
				 * only treat it as complete if they match;
				 * otherwise re-upload from scratch.  Closes the
				 * crash-resume sparse-hole corruption gap.
				 */
				uint64_t local_hash, remote_hash;
				int lret, rret;

				/* Hashing on both ends is legitimate
				 * non-byte-transfer work; pause the
				 * orchestrator watchdog for the duration so
				 * its born-dead / silence heuristics don't
				 * kill the worker mid-hash.  Auto-expires;
				 * resume() called explicitly on the success
				 * paths below for promptness. */
				sftp_hpn_watchdog_pause(conn->hpn,
				    HPN_HEARTBEAT_REFRESH_SEC);
				/*
				 * Always strict: hash both ends off the platter
				 * and compare; equal size never implies equal
				 * content.  STRICT is always sent so a pre-Phase-1
				 * server still hashes instead of returning the
				 * (removed) fully-allocated sentinel.
				 * Hash-work op: remote leg first here.
				 */
				sftp_conn_hash_op_begin(conn,
				    2 * (uint64_t)sb.st_size);
				rret = sftp_hpn_hash_remote_file(conn, remote_path,
				    sb.st_size, &remote_hash);
				sftp_conn_hash_op_leg(conn,
				    (uint64_t)sb.st_size);
				lret = sftp_hpn_xxhash_local_fd(conn, local_fd,
				    sb.st_size, &local_hash);
				sftp_hpn_watchdog_resume(conn->hpn);
				if (lret == 0 && rret == 0 &&
				    local_hash == remote_hash) {
					debug("verified transfer: full-file hash "
					    "match, \"%s\" already complete",
					    local_path);
					resume_check_meter_end(conn);
					close(local_fd);
					progressmeter_frames_count_file();
					return 1; /* identical */
				}
				debug("verified transfer: same size but hash "
				    "mismatch for \"%s\"; re-uploading from "
				    "scratch", local_path);
				resume = 0;           /* fresh upload */
				effective_inplace = 0; /* force TRUNC */
			} else if ((off_t)c.size > sb.st_size) {
				resume_check_meter_end(conn);
				close(local_fd);
				progressmeter_frames_count_file();
				return 2; /* target larger than source */
			} else {
				/*
				 * c.size < sb.st_size: partial remote file.
				 * Chunked verify FIRST: a lazily-created
				 * range-split partial grows to its pwrite
				 * highwater and may hold interior holes below
				 * that size - prefix resume would append past
				 * them and corrupt.  Interior holes
				 * hash-mismatch and re-send; chunks past
				 * remote EOF are clamped client-side as
				 * known-missing (never hashed on either end)
				 * and re-sent directly.  Declines (-1) fall
				 * through to prefix resume, reached only for
				 * sequentially written partials and files
				 * below the chunk threshold.
				 */
				int chunked = sftp_hpn_try_chunked_resume_upload(
				    conn, local_fd, local_path, remote_path,
				    sb.st_size, (off_t)c.size /* dest clamp */);
				if (chunked >= 0) {
					resume_check_meter_end(conn);
					close(local_fd);
					progressmeter_frames_count_file();
					return chunked; /* 1=skip, 0=success */
				}
				/*
				 * Hash the overlapping prefix to decide whether
				 * we can safely resume (append) or must restart.
				 */
				uint64_t local_hash, remote_hash;
				int lret, rret;

				sftp_hpn_watchdog_pause(conn->hpn,
				    HPN_HEARTBEAT_REFRESH_SEC);
				/* hash-work op: local leg first here */
				sftp_conn_hash_op_begin(conn, 2 * c.size);
				lret = sftp_hpn_xxhash_local_fd(conn, local_fd,
				    c.size, &local_hash);
				sftp_conn_hash_op_leg(conn, c.size);
				/* Prefix-resume: the server always returns the
				 * real XXH3 of the requested prefix off the
				 * platter, so the compare below is exact. */
				rret = sftp_hpn_hash_remote_file(conn, remote_path,
				    c.size, &remote_hash);
				sftp_hpn_watchdog_resume(conn->hpn);
				debug3_f("lret=%d rret=%d local_hash=%016llx "
				    "remote_hash=%016llx match=%d",
				    lret, rret,
				    (unsigned long long)local_hash,
				    (unsigned long long)remote_hash,
				    (lret == 0 && rret == 0 &&
				    local_hash == remote_hash));
				if (lret == 0 && rret == 0 &&
				    local_hash == remote_hash) {
					debug("verified resume: prefix hash "
					    "match, resuming at offset %llu",
					    (unsigned long long)c.size);
					resume = 1;
				} else {
					debug("verified resume: prefix hash "
					    "mismatch or error; restarting upload");
					resume = 0;           /* force fresh upload */
					effective_inplace = 0; /* force TRUNC */
				}
			}
			/* fall-through paths (mismatch -> fresh upload,
			 * prefix decision) converge here */
			resume_check_meter_end(conn);
		} else {
			debug3_f("remote file absent or empty; fresh upload");
		}
		/* If resume is still 0 (no remote file, empty file, extension
		 * missing, or hash mismatch) we fall through to a fresh upload. */
	}
	debug3_f("after verify: resume=%d effective_inplace=%d",
	    resume, effective_inplace);

	/*
	 * Plain size-only resume (or verify already set resume=1 above).
	 * When verify set resume=1 the stat and size check were already done;
	 * skip them with the !verify guard.
	 */
	if (resume) {
		if (!verify) {
			/* Get remote file size if it exists */
			if (sftp_stat(conn, remote_path, 0, &c) != 0) {
				close(local_fd);
				return -1;
			}
			if ((off_t)c.size == sb.st_size) {
				close(local_fd);
				progressmeter_frames_count_file();
				return 1; /* identical */
			}
			if ((off_t)c.size > sb.st_size) {
				close(local_fd);
				progressmeter_frames_count_file();
				return 2; /* target larger than source */
			}
		}
		if (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			return -1;
		}
		resume_offset = (off_t)c.size;
	}

	/*
	 * If not resuming (fresh upload or verify-restart after hash mismatch),
	 * ensure local_fd is at offset 0.  sftp_hpn_xxhash_local_fd() may have
	 * left it positioned partway through the file.
	 */
	if (!resume && lseek(local_fd, 0, SEEK_SET) == -1) {
		error("lseek local \"%s\": %s", local_path, strerror(errno));
		close(local_fd);
		return -1;
	}

	openmode = SSH2_FXF_WRITE|SSH2_FXF_CREAT;
	if (resume)
		openmode |= SSH2_FXF_APPEND;
	else if (!effective_inplace)
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
	    preserve_flag, fsync_flag, effective_inplace,
	    resume, resume_offset);

	if (close(local_fd) == -1) {
		error("close local \"%s\": %s", local_path, strerror(errno));
		r = -1;
	}

	if (sftp_close(conn, handle, handle_len) != 0)
		status = -1;

	free(handle);

	/*
	 * Park for the post-transfer verify phase (HPN): every uploaded file -
	 * single-file and recursive, since upload_dir_internal funnels through
	 * here - is verified after the command's transfers finish (closing the
	 * classic recursive-verify gap).  Only on a clean upload; resume-skipped
	 * files returned earlier.  No-op unless verify enabled.
	 */
	if (r == 0 && status == 0)
		sftp_conn_verify_park(conn, local_path, remote_path,
		    /*local_is_target=*/0);

	return (r != 0 || status != 0) ? -1 : 0;
}

static int
upload_dir_internal(struct sftp_conn *conn, const char *src, const char *dst,
    int depth, int preserve_flag, int print_flag, int resume, int verify,
    int fsync_flag, int follow_link_flag, int inplace_flag)
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
			    verify, fsync_flag, follow_link_flag,
			    inplace_flag) == -1)
				ret = -1;
		} else if (S_ISREG(sb.st_mode)) {
			int ur = sftp_upload(conn, new_src, new_dst,
			    preserve_flag, resume, verify, fsync_flag,
			    inplace_flag);
			if (ur == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			} else if (ur == 1) {
				fmprintf(progressmeter_frames_active() ?
				    stderr : stdout,	/* keep frames clean */
				    "File skipped: %s: Identical.\n",
				    new_src);
			} else if (ur == 2) {
				fmprintf(progressmeter_frames_active() ?
				    stderr : stdout,
				    "File skipped: %s: Target is larger"
				    " than source.\n", new_src);
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
    int preserve_flag, int print_flag, int resume, int verify,
    int fsync_flag, int follow_link_flag, int inplace_flag)
{
	char *dst_canon;
	int ret;

	if ((dst_canon = sftp_realpath(conn, dst)) == NULL) {
		error("upload \"%s\": path canonicalization failed", dst);
		return -1;
	}

	ret = upload_dir_internal(conn, src, dst_canon, 0, preserve_flag,
	    print_flag, resume, verify, fsync_flag, follow_link_flag,
	    inplace_flag);

	free(dst_canon);
	return ret;
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
 * sftp_create_file - create the remote file if absent, WITHOUT truncating
 * an existing one and WITHOUT pinning a logical size.  Used by the lazy
 * first-writer gate of range-split transfers: the file appears on the
 * remote only once data is actually about to flow, and its size then
 * grows with the pwrite highwater (honest sizes for interrupted
 * transfers; verified resume handles the short file via chunk clamping).
 * Sets *permanent_out on failures that retrying cannot cure
 * (SSH2_FX_PERMISSION_DENIED).
 */
int
sftp_create_file(struct sftp_conn *conn, const char *remote_path, mode_t mode,
    int *permanent_out)
{
	u_char *handle = NULL;
	size_t  handle_len;
	Attrib  a;

	if (permanent_out != NULL)
		*permanent_out = 0;
	attrib_clear(&a);
	a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
	a.perm = mode & 07777;
	if (send_open(conn, remote_path, "lazy-create",
	    SSH2_FXF_WRITE | SSH2_FXF_CREAT, &a, &handle, &handle_len) != 0) {
		/* send_open already logged; classify permission failures so
		 * the unit gives up instead of retrying a permanent error. */
		if (permanent_out != NULL &&
		    conn->last_status == SSH2_FX_PERMISSION_DENIED)
			*permanent_out = 1;
		return -1;
	}
	(void)sftp_close(conn, handle, handle_len);
	free(handle);
	return 0;
}

int
sftp_upload_range(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t range_offset, off_t range_length,
    off_t *acked_out, struct sftp_range_warm *warm, uint64_t *range_hash_out)
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
	u_int id, ackid;
	uint32_t status = SSH2_FX_OK;
	off_t offset = range_offset, bytes_left = range_length;
	off_t first_fail_off = -1;
	int local_fd = -1, ret = -1, r, yielded = 0, teed = 0;

	if (acked_out != NULL)
		*acked_out = 0;
	TAILQ_INIT(&acks);

	/* Defensive: submit_upload_ranges only ever emits positive-length
	 * ranges (its effective_ranges pass drops any <= 0), so a non-positive
	 * length here means a malformed range unit reached the wire.  Reject it
	 * rather than skipping the send loop and returning success, which would
	 * launder the bug as a completed transfer. */
	if (range_length <= 0) {
		error_f("refusing upload range of non-positive length %lld "
		    "for \"%s\"", (long long)range_length, remote_path);
		return -1;
	}

	if ((local_fd = open(local_path, O_RDONLY)) < 0) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		return -1;
	}
	if (lseek(local_fd, range_offset, SEEK_SET) < 0) {
		error("lseek \"%s\" to %lld: %s", local_path,
		    (long long)range_offset, strerror(errno));
		goto out;
	}
	/*
	 * Warm handle: reuse the open remote handle across consecutive same-
	 * file ranges (skips the close/reopen + cold-window dip at the range
	 * boundary).  The caller is expected to keep warm->handle for THIS
	 * remote_path (it closes a stale one on file change); we also verify
	 * warm->path matches here, so a caller-side slip opens fresh rather
	 * than writing this range into the previous file's handle.  Otherwise
	 * open fresh, without O_CREAT/O_TRUNC - the file was pre-created.
	 */
	if (warm != NULL && warm->handle != NULL &&
	    warm->path != NULL && strcmp(warm->path, remote_path) == 0) {
		handle = warm->handle;
		handle_len = warm->handle_len;
	} else if (send_open(conn, remote_path, "range-dest",
	    SSH2_FXF_WRITE, NULL, &handle, &handle_len) != 0)
		goto out;

	data = xmalloc(conn->upload_buflen);
	id = conn->msg_id;
	ackid = id + 1;
	offset = range_offset;
	bytes_left = range_length;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* HPNVerifyTransfer: tee this range's source bytes into a streaming
	 * XXH3 as we read them to send, so the finalize verify can reuse the
	 * hash instead of re-reading the source.  Only when the caller asked
	 * (range_hash_out != NULL).  A range that does not transfer in one
	 * clean pass (yield / partial / retry) leaves acked < range_length;
	 * the caller detects that and re-reads just that range at finalize. */
	if (range_hash_out != NULL && conn->hpn != NULL) {
		sftp_hpn_src_arm(conn->hpn);
		teed = 1;
	}

	for (;;) {
		int len = 0;
		size_t outstanding = id - ackid + 1;

		/* Cooperative yield (HPN tail redistribution): stop sending
		 * NEW writes; the in-order ack drain below runs to completion,
		 * so the contiguous-acked highwater lands exactly at the end
		 * of the last write already sent - the caller requeues only
		 * the untouched remainder. */
		if (!yielded && yield_requested(conn))
			yielded = 1;

		/* Send new requests while there is data and pipeline capacity.
		 * HPN adaptive read-ahead caps the depth (num_requests when
		 * disabled). */
		while (!yielded && bytes_left > 0 &&
		    outstanding < sftp_hpn_rdahead_cap(conn->hpn,
		    conn->num_requests) && status == SSH2_FX_OK) {
			size_t want = conn->upload_buflen;
			if ((off_t)want > bytes_left)
				want = (size_t)bytes_left;
			do
				len = read(local_fd, data, want);
			while (len == -1 &&
			    (errno == EINTR || errno == EAGAIN ||
			     errno == EWOULDBLOCK));
			if (len <= 0) {
				/* Mid-range EOF/read-error: should be
				 * impossible on an intact source (length is
				 * clamped at submit).  Loudly diagnose - the
				 * silent break here masked partial sends as
				 * success until 2026-06-12. */
				error("read local \"%s\" at offset %lld: "
				    "len=%d errno=%s (range [%lld+%lld), "
				    "%lld left)", local_path,
				    (long long)offset, len,
				    len < 0 ? strerror(errno) : "EOF",
				    (long long)range_offset,
				    (long long)range_length,
				    (long long)bytes_left);
				break;
			}

			/* Tee the clean source bytes so the verify hash
			 * reflects the source as read. */
			if (teed)
				sftp_hpn_src_feed(conn->hpn, data, (size_t)len);

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
			sftp_hpn_bytes_wired_add(conn->hpn, (uint64_t)len);

			offset    += len;
			bytes_left -= len;
			outstanding = id - ackid + 1;
		}

		/* Drain one ACK per iteration. */
		if (TAILQ_EMPTY(&acks))
			break;
		ack = TAILQ_FIRST(&acks);
		sshbuf_reset(msg);
		/* Check get_msg_extended return - connection death (EPIPE)
		 * already sets conn->hpn->dead inside get_msg_extended.
		 * Without this check, the subsequent parse would fatal_fr
		 * on the empty msg buffer and crash the orchestrator.
		 *
		 * Time the STATUS read so a wedged-path signal can reach
		 * the rdahead controller - same mechanism as do_upload_body. */
		{
			double t_status_start = monotime_double();
			if (get_msg_extended(conn, msg, 0) != 0) {
				status = SSH2_FX_FAILURE;
				break;
			}
			if (monotime_double() - t_status_start >
			    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
				sftp_hpn_rdahead_backpressure_signal(conn->hpn);
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
			if (status == SSH2_FX_PERMISSION_DENIED)
				conn->saw_perm_denied = 1; /* HPN: no-retry */
			/* Highwater clamp: acks are processed in order, but
			 * the loop keeps draining after a failed write, so
			 * later OK acks would advance the head past a HOLE.
			 * Contiguous progress ends at the first failure. */
			if (first_fail_off < 0 ||
			    (off_t)ack->offset < first_fail_off)
				first_fail_off = (off_t)ack->offset;
		} else {
			/* HPN adaptive read-ahead: feed acked bytes. */
			sftp_hpn_rdahead_account(conn->hpn, ack->len);
			if (conn->hpn->live_counter != NULL) {
				/* Report incremental progress so the
				 * orchestrator's bps window sees a steady
				 * stream rather than a step at range
				 * completion. */
				__atomic_fetch_add(conn->hpn->live_counter,
				    (uint64_t)ack->len, __ATOMIC_RELAXED);
			}
		}
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	sshbuf_free(msg);

	/* GUARD (run BEFORE the close decision so 'status' is final): a range
	 * that did not send every byte is NOT a success, whatever the status
	 * says - the send loop can exit early (local read failure, future
	 * logic changes) and silently finalizing a short range as complete is
	 * data loss.  Fail it; the caller's retry/highwater-resume machinery
	 * finishes the remainder.  A cooperative yield takes this path
	 * deliberately (quietly): the non-success return routes the remainder
	 * through the same requeue machinery, reclassified as voluntary. */
	if (status == SSH2_FX_OK && bytes_left > 0) {
		if (yielded)
			debug("range [%lld+%lld) of \"%s\" yielded with %lld "
			    "bytes unsent", (long long)range_offset,
			    (long long)range_length, local_path,
			    (long long)bytes_left);
		else
			error("range [%lld+%lld) of \"%s\" incomplete at "
			    "success exit (%lld bytes unsent) - failing the "
			    "unit for retry", (long long)range_offset,
			    (long long)range_length, local_path,
			    (long long)bytes_left);
		status = SSH2_FX_FAILURE;
	}

	/*
	 * Warm-handle close decision: leave the handle OPEN for the next same-
	 * file range ONLY on a clean success; otherwise close it now (a
	 * failed, yielded, or wedged handle must never be reused).  On the
	 * leave-open path, ownership of `handle` passes to *warm and we NULL
	 * the local so the out: free does not touch it.
	 */
	if (status == SSH2_FX_OK && warm != NULL) {
		if (warm->handle != handle) {
			/* freshly opened this call - take ownership into *warm */
			free(warm->path);
			warm->handle = handle;
			warm->handle_len = handle_len;
			warm->path = xstrdup(remote_path);
		}
		handle = NULL;
		ret = 0;
	} else {
		if (sftp_close(conn, handle, handle_len) != 0)
			status = SSH2_FX_FAILURE;
		if (warm != NULL && warm->handle == handle) {
			free(warm->path);
			warm->path = NULL;
			warm->handle = NULL;
			warm->handle_len = 0;
		}
		ret = (status == SSH2_FX_OK) ? 0 : -1;
	}
 out:
	debug("upload-range-exit: [%lld+%lld) ret=%d status=%u "
	    "final_offset=%lld bytes_left=%lld outstanding=%s",
	    (long long)range_offset, (long long)range_length, ret, status,
	    (long long)offset, (long long)bytes_left,
	    TAILQ_EMPTY(&acks) ? "none" : "some");
	/*
	 * Contiguous-acked highwater for resume-on-requeue (HPN).  Acks are
	 * processed strictly in order, so everything below the head of the
	 * outstanding list is acknowledged; with the list empty, everything
	 * sent is.  Clamped at the first failed write offset (a hole ends
	 * contiguity).  On success the caller does not need it; on failure
	 * the worker requeues only [range_offset + acked, end).
	 */
	if (acked_out != NULL) {
		off_t hw = TAILQ_EMPTY(&acks) ?
		    offset : (off_t)TAILQ_FIRST(&acks)->offset;

		if (first_fail_off >= 0 && first_fail_off < hw)
			hw = first_fail_off;
		if (hw > range_offset)
			*acked_out = hw - range_offset;
	}
	while ((ack = TAILQ_FIRST(&acks)) != NULL) {
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	/* Finalize the tee.  src_take writes *range_hash_out only when the
	 * teed byte count equals range_length; the caller additionally gates
	 * on a clean (acked == range_length) transfer before trusting it. */
	if (teed) {
		sftp_hpn_src_finish(conn->hpn);
		(void)sftp_hpn_src_take(conn->hpn, (uint64_t)range_length,
		    range_hash_out);
	}
	close(local_fd);
	free(handle);
	free(data);
	return ret;
}

/* Lowest outstanding read offset (HPN highwater helper): everything below
 * the floor of the in-flight request set has been received and written.
 * With nothing outstanding, contiguity extends to next_off. */
static off_t
dl_outstanding_floor(struct requests *q, uint64_t next_off)
{
	struct request *r2;
	off_t hw = (off_t)next_off;

	TAILQ_FOREACH(r2, q, tq) {
		if ((off_t)r2->offset < hw)
			hw = (off_t)r2->offset;
	}
	return hw;
}

int
sftp_download_range(struct sftp_conn *conn, const char *remote_path,
    const char *local_path, off_t range_offset, off_t range_length,
    off_t *acked_out)
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
	int ret = -1, r, yielded = 0;
	off_t contig_hw = -1;	/* HPN: min over failure-site floors/clamps */

	if (acked_out != NULL)
		*acked_out = 0;
	TAILQ_INIT(&requests);

	/* Defensive: see sftp_upload_range - a non-positive range length is a
	 * malformed unit (submit_download_ranges never emits one); reject it
	 * instead of silently "succeeding" on an empty send/recv loop. */
	if (range_length <= 0) {
		error_f("refusing download range of non-positive length %lld "
		    "for \"%s\"", (long long)range_length, remote_path);
		return -1;
	}

	/* Open remote file for reading. */
	if (send_open(conn, remote_path, "range-src",
	    SSH2_FXF_READ, NULL, &handle, &handle_len) != 0)
		return -1;

	/* Open pre-created local file for writing; no O_CREAT/O_TRUNC -
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
		/* Cooperative yield (HPN tail redistribution): stop issuing
		 * NEW read requests; the loop drains everything already in
		 * flight (those bytes were the most expensive to earn on a
		 * slow stream - keep them), then exits with remote_offset at
		 * the end of the last issued request, which is exactly the
		 * highwater the clean-drain math below reports. */
		if (!yielded && yield_requested(conn)) {
			yielded = 1;
			max_req = 0;
		}

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
		/* Time the DATA-reply read so the rdahead controller can
		 * react to a wedged path - same mechanism as the upload-
		 * side STATUS-read instrumentation in sftp_upload_range. */
		double t_data_start = monotime_double();
		if (get_msg_extended(conn, msg, 0) != 0) {
			read_error = 1;
			if (acked_out != NULL) {
				off_t f = dl_outstanding_floor(&requests,
				    remote_offset);
				if (contig_hw < 0 || f < contig_hw)
					contig_hw = f;
			}
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = max_req = 0;
			break;
		}
		if (monotime_double() - t_data_start >
		    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
			sftp_hpn_rdahead_backpressure_signal(conn->hpn);
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
			if (status == SSH2_FX_PERMISSION_DENIED)
				conn->saw_perm_denied = 1; /* HPN: no-retry */
			read_error = 1;
			/* The failing read's own offset bounds contiguity. */
			if (contig_hw < 0 || (off_t)req->offset < contig_hw)
				contig_hw = (off_t)req->offset;
			if (acked_out != NULL) {
				off_t f = dl_outstanding_floor(&requests,
				    remote_offset);
				if (contig_hw < 0 || f < contig_hw)
					contig_hw = f;
			}
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
			sftp_hpn_bytes_wired_add(conn->hpn, (uint64_t)len);
			if ((lseek(local_fd, (off_t)req->offset,
			    SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
				/* Data past this point may be received but
				 * is not on disk; bound contiguity here. */
				if (contig_hw < 0 ||
				    (off_t)req->offset < contig_hw)
					contig_hw = (off_t)req->offset;
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
				/* Short read - re-request remainder. */
				req->id = conn->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id, req->offset,
				    (u_int)req->len, handle, handle_len);
			}
			if (max_req > 0)
				/* HPN adaptive read-ahead window. */
				max_req = sftp_hpn_rdahead_window(conn->hpn,
				    len, max_req, conn->num_requests);
			break;
		}
		default:
			error_f("expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption",
			    SSH2_FXP_DATA, type);
			sftp_hpn_set_protocol_violation(conn->hpn);
			read_error = 1;
			if (acked_out != NULL) {
				off_t f = dl_outstanding_floor(&requests,
				    remote_offset);
				if (contig_hw < 0 || f < contig_hw)
					contig_hw = f;
			}
			while ((req = TAILQ_FIRST(&requests)) != NULL) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
			}
			num_req = max_req = 0;
			break;
		}
	}
	sshbuf_free(msg);

	/*
	 * Same as the single-file path: a non-empty queue here is a dead
	 * connection (early break), not a clean completion.  Fail soft so the
	 * worker respawns instead of fatal()-ing the whole orchestrator.
	 */
	if (TAILQ_FIRST(&requests) != NULL) {
		if (!sftp_conn_is_dead(conn))
			sftp_conn_die(conn, "range download of \"%s\" ended "
			    "with requests still in flight (connection lost)",
			    remote_path);
		if (acked_out != NULL) {
			off_t f = dl_outstanding_floor(&requests,
			    remote_offset);
			if (contig_hw < 0 || f < contig_hw)
				contig_hw = f;
		}
		while ((req = TAILQ_FIRST(&requests)) != NULL) {
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
		}
		read_error = 1;
	}

	/* HPN highwater out: contiguous bytes received AND written from the
	 * range start.  contig_hw < 0 means no failure bounded it (clean
	 * completion or nothing in flight): everything requested landed. */
	if (acked_out != NULL) {
		off_t hw = (contig_hw >= 0) ? contig_hw : (off_t)remote_offset;

		if (hw > range_offset)
			*acked_out = hw - range_offset;
	}

	/* GUARD (twin of upload_range's): a range that did not request and
	 * receive every byte is NOT a success, whatever the error flags say -
	 * the request loop can exit early (max_req collapse, future logic
	 * changes) and silently finalizing a short range as complete is data
	 * loss.  bytes_left counts the unrequested remainder; with no
	 * outstanding requests it must be zero at a genuine completion.  A
	 * cooperative yield takes this path deliberately (quietly): the
	 * non-success return routes the remainder through the same requeue
	 * machinery, and the caller reclassifies it as voluntary. */
	if (!read_error && !write_error && bytes_left > 0) {
		if (yielded)
			debug("range [%lld+%lld) of \"%s\" yielded with %lld "
			    "bytes unrequested", (long long)range_offset,
			    (long long)range_length, remote_path,
			    (long long)bytes_left);
		else
			error("range [%lld+%lld) of \"%s\" incomplete at "
			    "success exit (%lld bytes unrequested) - failing "
			    "the unit for retry", (long long)range_offset,
			    (long long)range_length, remote_path,
			    (long long)bytes_left);
		read_error = 1;
	}

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
 * failed as failed.  Used by the batch upload path when a collection phase
 * hits a dead connection or a protocol problem mid-batch: rather than
 * calling fatal_fr (which terminates the entire process - catastrophic
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
 * Implementation note: an unsplit batch would do all 5 phases back-to-back.
 * Splitting into send (phases 1-4) and finish (phase 5)
 * lets the caller pipeline: the next batch's OPENs (phase 1) can be on
 * the wire while the previous batch's CLOSE STATUSes (phase 5) are still
 * coming back.  Saves ~1 RTT per batch boundary.
 *
 * Wire ordering when send is called with prev != NULL:
 *   1. Send THIS batch's OPENs (phase 1)
 *   2. Drain PREV's CLOSE STATUSes (the prev_finish step) - they should be
 *      arriving / arrived since prev's CLOSEs were sent before this call
 *   3. Collect THIS batch's HANDLEs (phase 2)
 *   4. The rest of phases 3-4 for this batch
 *
 * The overlap: between step 1 (we send opens) and step 2 (we read close
 * statuses), the server is processing both - sending close statuses for
 * prev AND opening files for the current batch - concurrently.
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
			    "got %d - connection may be corrupt",
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
			    "- possible MITM or server corruption",
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
	 * PREV batch's close statuses - saving ~1 RTT per batch boundary.
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
				continue; /* large file - handled in phase 3d */
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
			sftp_hpn_bytes_wired_add(conn->hpn, (uint64_t)len);
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
	 * whole process - catastrophic for parallel workers handling
	 * unrelated transfers - so we degrade gracefully instead.
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
				    "got %d - connection may be corrupt",
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
				    "%u - possible MITM or server corruption",
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
				if (status == SSH2_FX_PERMISSION_DENIED)
					conn->saw_perm_denied = 1; /* HPN */
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
			continue; /* large file - handled below */
		if (preserve_flag)
			sftp_fsetstat(conn, bs[i].handle, bs[i].handle_len,
			    &bs[i].a);
		if (fsync_flag)
			(void)sftp_fsync(conn, bs[i].handle, bs[i].handle_len);
	}

	/*
	 * Phase 3d: large files - one at a time via do_upload_body.
	 * preserve and fsync are applied inside do_upload_body per file.
	 */
	for (i = 0; i < n; i++) {
		if (bs[i].failed || bs[i].handle == NULL)
			continue;
		if (bs[i].sb.st_size <= (off_t)conn->upload_buflen)
			continue; /* small file - already handled */
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

	/* Phase 5 is deferred to sftp_upload_batch_finish - packaged into
	 * a pending struct and returned to the caller, who calls finish later,
	 * after sending the next batch's phase 1 OPENs (sliding-window
	 * pipelining). */
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
	 * there is nothing for finish to collect - return NULL signals this
	 * to the caller. */
	for (i = 0; i < n; i++) {
		if (bs[i].local_fd >= 0)
			close(bs[i].local_fd);
		free(bs[i].handle);
	}
	free(bs);
	return NULL;
}

/* ── END Phase 4 gap 1 ──────────────────────────────────────────────────── */

/* ── BEGIN Phase 5: hpn-bundle accessors ─────────────────────────────────
 *
 * The bundle wire protocol implementations (sftp_hpn_bundle_upload,
 * sftp_hpn_bundle_download) live in sftp-hpn-client.c.  Only the small
 * accessors that need to peek inside struct sftp_conn stay here - they
 * cross the upstream-aligned / HPN boundary minimally.
 */

int
sftp_conn_has_hpn_bundle(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HPN_BUNDLE) != 0;
}

int
sftp_conn_has_hpn_bundle_fetch(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HPN_BUNDLE_FETCH) != 0;
}

int
sftp_conn_has_hpn_check_file(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HPN_CHECK_FILE) != 0;
}

int
sftp_conn_has_hash_range(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HASH_RANGE) != 0;
}

int
sftp_conn_has_file_layout(struct sftp_conn *conn)
{
	return conn && (conn->exts & SFTP_EXT_HPN_FILE_LAYOUT) != 0;
}

/* Allocate the next outbound SFTP message id for `conn`.  Internal-only
 * accessor used by HPN extension code in sftp-hpn-client.c so it doesn't
 * have to know struct sftp_conn's layout (which lives in sftp-client.c).
 * Declared in sftp-client-internal.h. */
u_int
sftp_conn_alloc_msg_id(struct sftp_conn *conn)
{
	return conn->msg_id++;
}

/* Mark `conn` as dead due to a non-recoverable I/O failure.  Public
 * accessor for HPN bundle code in sftp-hpn-client.c - same effect as
 * the direct `conn->hpn->dead = 1` assignment that internal code in
 * this file can do.  Declared in sftp-client-internal.h. */
void
sftp_conn_set_dead(struct sftp_conn *conn)
{
	if (conn != NULL && conn->hpn != NULL)
		conn->hpn->dead = 1;
}

/* Atomic read of the watchdog-pause deadline (monotonic ms).  Public accessor so the
 * parallel orchestrator (which only sees an opaque struct sftp_conn *)
 * can consult it from the watchdog thread without reaching into the
 * struct directly.  Returns 0 if no pause is active or hpn is missing.
 * Declared in sftp-client-internal.h. */
uint64_t
sftp_conn_watchdog_pause_until_ms(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	return __atomic_load_n(&conn->hpn->watchdog_pause_until_ms,
	    __ATOMIC_RELAXED);
}

/* Conn-side wrappers around sftp_hpn_watchdog_pause/_resume.  Declared in
 * sftp-client-internal.h.  Let HPN extension code that works through the
 * opaque struct sftp_conn * pause/resume the watchdog without needing to
 * extract conn->hpn directly. */
void
sftp_conn_watchdog_pause(struct sftp_conn *conn, unsigned int seconds)
{
	if (conn != NULL)
		sftp_hpn_watchdog_pause(conn->hpn, seconds);
}

void
sftp_conn_watchdog_resume(struct sftp_conn *conn)
{
	if (conn != NULL)
		sftp_hpn_watchdog_resume(conn->hpn);
}

/* Adaptive read-ahead controller wrappers.  Declared in
 * sftp-client-internal.h so HPN extension code that works through the
 * opaque struct sftp_conn * (the bundle path) can feed the controller
 * and read its current cap without extracting conn->hpn directly.  Both
 * forward to the sftp_hpn_rdahead_* primitives. */
uint32_t
sftp_conn_rdahead_cap(struct sftp_conn *conn, uint32_t fallback)
{
	if (conn == NULL)
		return fallback;
	return sftp_hpn_rdahead_cap(conn->hpn, fallback);
}

void
sftp_conn_rdahead_account(struct sftp_conn *conn, size_t nbytes)
{
	if (conn != NULL)
		sftp_hpn_rdahead_account(conn->hpn, nbytes);
}

void
sftp_conn_rdahead_backpressure_signal(struct sftp_conn *conn)
{
	if (conn != NULL)
		sftp_hpn_rdahead_backpressure_signal(conn->hpn);
}

/* Live-byte accounting wrapper.  The per-worker live counter (armed via
 * sftp_set_live_counter) is what the parallel watchdog's liveness
 * classifiers read; the per-file/range/batch paths bump it inline where
 * their acks are processed.  The bundle codec works through the opaque
 * struct sftp_conn * and uses this wrapper - without it a worker mid-
 * bundle reads as 0 bytes moved and is killed as born-dead/wedged on
 * any bundle slower than the detection window (throttled or low-
 * bandwidth paths). */
void
sftp_conn_live_account(struct sftp_conn *conn, size_t nbytes)
{
	if (conn != NULL && conn->hpn != NULL &&
	    conn->hpn->live_counter != NULL)
		__atomic_fetch_add(conn->hpn->live_counter, nbytes,
		    __ATOMIC_RELAXED);
}

/* HPNVerifyTransfer state accessors.  Declared in sftp-client-internal.h.
 * Set from sftp.c after ssh_config resolution; read where verify is gated -
 * arming the inline source-hash tee and the classic post-transfer verify
 * phase. */
void
sftp_conn_set_verify_transfer(struct sftp_conn *conn, int enabled)
{
	if (conn != NULL && conn->hpn != NULL)
		conn->hpn->verify_transfer_enabled = enabled ? 1 : 0;
}

int
sftp_conn_verify_transfer_enabled(struct sftp_conn *conn)
{
	return conn != NULL && conn->hpn != NULL &&
	    conn->hpn->verify_transfer_enabled;
}

void
sftp_conn_set_verify_repair(struct sftp_conn *conn, int enabled, int attempts)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	conn->hpn->verify_repair_enabled = enabled ? 1 : 0;
	conn->hpn->verify_repair_attempts = attempts < 1 ? 1 : attempts;
}

/*
 * Park a just-transferred file for the classic post-transfer verify phase.
 * Called at the end of sftp_upload (local_is_target=0) and sftp_download
 * (local_is_target=1).  No-op unless integrity verify is enabled, and skipped
 * on parallel worker conns - the orchestrator's verify phase handles those
 * (live_counter is the per-worker hook, NULL on the main conn).  Records paths
 * only; the hash compare happens later in sftp_conn_verify_run_phase, mirroring
 * the -j upload-everything-then-verify model instead of stalling each file on a
 * synchronous round-trip.
 */
void
sftp_conn_verify_park(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target)
{
	struct sftp_verify_pending_entry *e;

	if (!sftp_conn_verify_transfer_enabled(conn))
		return;
	if (conn->hpn->live_counter != NULL)
		return;
	if (conn->hpn->verify_pending_count >= conn->hpn->verify_pending_cap) {
		size_t newcap = conn->hpn->verify_pending_cap ?
		    conn->hpn->verify_pending_cap * 2 : 64;
		conn->hpn->verify_pending = xreallocarray(
		    conn->hpn->verify_pending, newcap,
		    sizeof(*conn->hpn->verify_pending));
		conn->hpn->verify_pending_cap = newcap;
	}
	e = &conn->hpn->verify_pending[conn->hpn->verify_pending_count++];
	e->local_path = xstrdup(local_path);
	e->remote_path = xstrdup(remote_path);
	e->local_is_target = local_is_target;
}

/*
 * Classic post-transfer verify phase: verify every file parked during the
 * command's transfers, then clear the list.  The single-conn analogue of the
 * -j orchestrator's verify phase - same sftp_hpn_verify_transfer core, same
 * trust_inline_src=0 source re-read (the inline tee cannot span a deferred
 * phase).  Mismatches are recorded on the conn (drained later to the run
 * summary + SFTP_EX_VERIFY_FAILED); they do not fail the transfer.  No-op when
 * nothing was parked (parallel mode, or verify disabled).
 */
void
sftp_conn_verify_run_phase(struct sftp_conn *conn)
{
	size_t i;
	off_t total = 0, counter = 0;
	int meter_on = 0;
	struct stat sb;

	if (conn == NULL || conn->hpn == NULL ||
	    conn->hpn->verify_pending_count == 0)
		return;
	/* Size each parked file for the progress-meter total (stat is cheap;
	 * the per-file verify re-stats anyway).  The byte-based meter mirrors
	 * the transfer meter - bar, rate, ETA - so the user sees the verify
	 * phase is working, not hung.  Gated on showprogress, same as transfers
	 * (off under -q / batch / non-tty). */
	for (i = 0; i < conn->hpn->verify_pending_count; i++) {
		if (stat(conn->hpn->verify_pending[i].local_path, &sb) == 0)
			conn->hpn->verify_pending[i].size = sb.st_size;
		/* WORK-bytes: both ends hash each byte, so the meter total
		 * is 2x (project_hash_work_meter_design). */
		total += 2 * conn->hpn->verify_pending[i].size;
	}
	if (showprogress && total > 0) {
		start_progress_meter("verify", total, &counter);
		progressmeter_frames_meter_not_a_file();	/* not a file */
		progressmeter_frames_set_phase(HPNS_F_VERIFY, 1); /* verify phase */
		/* Bridge the hash engines' per-op progress into the meter
		 * counter so a single big file moves smoothly instead of
		 * jumping 0->100 at completion. */
		sftp_conn_set_hash_meter_ctr(conn, &counter);
		meter_on = 1;
	}
	for (i = 0; i < conn->hpn->verify_pending_count; i++) {
		struct sftp_verify_pending_entry *e =
		    &conn->hpn->verify_pending[i];
		/*
		 * SIGINT aborts the phase, like the transfer loops: stop
		 * verifying on interrupt but keep ripping through the rest of the
		 * list to free it (no network, fast), so nothing leaks and the
		 * interrupt unwinds promptly to the prompt / exit.
		 */
		if (!interrupted) {
			int r = sftp_hpn_verify_repair(conn, e->local_path,
			    e->remote_path, e->local_is_target,
			    /*off=*/0, /*len=*/e->size,
			    /*have_local_hash=*/0, /*local_hash=*/0,
			    conn->hpn->verify_repair_enabled,
			    conn->hpn->verify_repair_attempts);
			if (r == 1) {
				error("VERIFY FAILED: \"%s\" (post-transfer hash "
				    "mismatch - the transferred file does NOT "
				    "match the source)", e->remote_path);
				conn->hpn->verify_failed_paths = xreallocarray(
				    conn->hpn->verify_failed_paths,
				    conn->hpn->verify_failed_count + 1,
				    sizeof(*conn->hpn->verify_failed_paths));
				conn->hpn->verify_failed_paths[
				    conn->hpn->verify_failed_count++] =
				    xstrdup(e->remote_path);
			} else if (r < 0) {
				logit("VERIFY SKIPPED: \"%s\": could not verify "
				    "(server lacks hpn-check-file@hpnssh.org or "
				    "read error)", e->remote_path);
			}
			/* Fold this file's completed work into the bridge
			 * base; the next op's progress continues from it. */
			sftp_conn_hash_meter_base_add(conn,
			    2 * (uint64_t)e->size);
		}
		free(e->local_path);
		free(e->remote_path);
	}
	if (meter_on) {
		sftp_conn_set_hash_meter_ctr(conn, NULL);
		stop_progress_meter();
	}
	conn->hpn->verify_pending_count = 0;
}

/* Files parked for the classic verify phase; lets the caller print a quiet-
 * gated "Verifying N file(s)..." line before sftp_conn_verify_run_phase. */
size_t
sftp_conn_verify_pending_count(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	return conn->hpn->verify_pending_count;
}

/*
 * Hand the classic-path verify failures to the caller; ownership of the array
 * and the strings transfers out and the conn's list resets to empty.  Mirrors
 * sftp_parallel_drain_verify_failures so sftp.c folds classic and parallel
 * mismatches into one summary + exit code.  Returns the count.
 */
size_t
sftp_conn_drain_verify_failures(struct sftp_conn *conn, char ***out_paths,
    size_t *out_used)
{
	size_t n = 0;

	if (out_paths != NULL)
		*out_paths = NULL;
	if (out_used != NULL)
		*out_used = 0;
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	n = conn->hpn->verify_failed_count;
	if (out_paths != NULL)
		*out_paths = conn->hpn->verify_failed_paths;
	if (out_used != NULL)
		*out_used = n;
	conn->hpn->verify_failed_paths = NULL;
	conn->hpn->verify_failed_count = 0;
	return n;
}

uint64_t
sftp_conn_bytes_wired(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	return __atomic_load_n(&conn->hpn->bytes_wired_payload,
	    __ATOMIC_RELAXED);
}

/*
 * Conn-level bridge so callers outside sftp-client.c (the bundle module) can
 * count wire payload the per-file write loops already count via
 * sftp_hpn_bytes_wired_add - without it, bundle-moved bytes never register as
 * "wired" and the end-of-run summary mislabels them as "skipped via resume".
 */
void
sftp_conn_bytes_wired_add(struct sftp_conn *conn, uint64_t n)
{
	if (conn != NULL && conn->hpn != NULL)
		sftp_hpn_bytes_wired_add(conn->hpn, n);
}

/*
 * Unified hash-work accounting (see sftp-hpn-client.h for the model).
 * Engines call begin/leg/progress; unit-completion sites call end; the
 * reporter and watchdog read the stamp-gated live values.
 */
void
sftp_conn_hash_op_begin(struct sftp_conn *conn, uint64_t total_work)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	__atomic_store_n(&conn->hpn->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_total, total_work,
	    __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_stamp_ms,
	    (uint64_t)monotime_ms(), __ATOMIC_RELAXED);
}

/* Entering a leg: subsequent progress reports are offset by `base`
 * (0 for the first leg, the span for the second). */
void
sftp_conn_hash_op_leg(struct sftp_conn *conn, uint64_t base)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	__atomic_store_n(&conn->hpn->hash_work_leg_base, base,
	    __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_stamp_ms,
	    (uint64_t)monotime_ms(), __ATOMIC_RELAXED);
}

/*
 * Cumulative progress within the current leg (heartbeat figures, local
 * read loops).  Publishes done = leg_base + leg_bytes (clamped to the op
 * total), refreshes the liveness stamp, and lands the value on the serial
 * meter bridge when one is registered.
 */
void
sftp_conn_hash_op_progress(struct sftp_conn *conn, uint64_t leg_bytes)
{
	uint64_t done, total;

	if (conn == NULL || conn->hpn == NULL)
		return;
	done = __atomic_load_n(&conn->hpn->hash_work_leg_base,
	    __ATOMIC_RELAXED) + leg_bytes;
	total = __atomic_load_n(&conn->hpn->hash_work_total, __ATOMIC_RELAXED);
	if (total > 0 && done > total)
		done = total;
	__atomic_store_n(&conn->hpn->hash_work_done, done, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_stamp_ms,
	    (uint64_t)monotime_ms(), __ATOMIC_RELAXED);
	if (conn->hpn->hash_meter_ctr != NULL)
		*conn->hpn->hash_meter_ctr =
		    (off_t)(conn->hpn->hash_meter_base + done);
}

/* Unit completion: retire the op.  Callers that fold the op's work into a
 * phase accumulator must capture hash_work_done BEFORE this (the same
 * clear-before-fold discipline as the old inflight handoff). */
void
sftp_conn_hash_op_end(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	__atomic_store_n(&conn->hpn->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_total, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&conn->hpn->hash_work_stamp_ms, 0, __ATOMIC_RELAXED);
	if (conn->hpn->hash_meter_ctr != NULL)
		*conn->hpn->hash_meter_ctr = (off_t)conn->hpn->hash_meter_base;
}

/* Stamp-gated live pair for the reporter: zeros unless refreshed within
 * the last 3 seconds (an engine gone on any path self-clears). */
void
sftp_conn_hash_work_live(struct sftp_conn *conn, uint64_t *done_out,
    uint64_t *total_out)
{
	uint64_t stamp;

	*done_out = 0;
	*total_out = 0;
	if (conn == NULL || conn->hpn == NULL)
		return;
	stamp = __atomic_load_n(&conn->hpn->hash_work_stamp_ms,
	    __ATOMIC_RELAXED);
	if (stamp == 0 || (uint64_t)monotime_ms() - stamp > 3000)
		return;
	*done_out = __atomic_load_n(&conn->hpn->hash_work_done,
	    __ATOMIC_RELAXED);
	*total_out = __atomic_load_n(&conn->hpn->hash_work_total,
	    __ATOMIC_RELAXED);
}

/* Live total only - the watchdog's "provably hashing" gate. */
uint64_t
sftp_conn_hash_op_live_total(struct sftp_conn *conn)
{
	uint64_t done, total;

	sftp_conn_hash_work_live(conn, &done, &total);
	return total;
}

/* Capture the current op's done figure (for completion folds). */
uint64_t
sftp_conn_hash_work_done_get(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	return __atomic_load_n(&conn->hpn->hash_work_done, __ATOMIC_RELAXED);
}

/* Serial meter bridge registration; resets the completed-work base. */
void
sftp_conn_set_hash_meter_ctr(struct sftp_conn *conn, volatile off_t *ctr)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	conn->hpn->hash_meter_ctr = ctr;
	conn->hpn->hash_meter_base = 0;
}

/* Serial multi-op meters (verify phase): fold a completed op's work into
 * the bridge base so the next op's progress continues from it. */
void
sftp_conn_hash_meter_base_add(struct sftp_conn *conn, uint64_t work)
{
	if (conn == NULL || conn->hpn == NULL)
		return;
	conn->hpn->hash_meter_base += work;
	if (conn->hpn->hash_meter_ctr != NULL)
		*conn->hpn->hash_meter_ctr = (off_t)conn->hpn->hash_meter_base;
}

void
sftp_conn_set_lustre_stripe_count(struct sftp_conn *conn, int value)
{
	if (conn != NULL && conn->hpn != NULL)
		conn->hpn->lustre_stripe_count = value;
}

int
sftp_conn_lustre_stripe_count(struct sftp_conn *conn)
{
	if (conn == NULL || conn->hpn == NULL)
		return 0;
	return conn->hpn->lustre_stripe_count;
}

int
sftp_conn_layout_set_declined(struct sftp_conn *conn)
{
	return conn != NULL && conn->hpn != NULL &&
	    conn->hpn->layout_set_declined;
}

void
sftp_conn_set_layout_set_declined(struct sftp_conn *conn, int v)
{
	if (conn != NULL && conn->hpn != NULL)
		conn->hpn->layout_set_declined = v ? 1 : 0;
}

static void
handle_dest_replies(struct sftp_conn *to, const char *to_path, int synchronous,
    u_int *nreqsp, u_int *write_errorp)
{
	struct sshbuf *msg = to->msg;
	u_char type;
	u_int id, status;
	int r;
	struct pollfd pfd;

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
}

int
sftp_crossload(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *a, int preserve_flag)
{
	struct sshbuf *msg = from->msg;
	int write_error, read_error, r, seen_zerolen = 0;
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
		/* Time the DATA-reply read from the source connection so
		 * the rdahead controller on `from` can react to a wedged
		 * download - same mechanism as the other data-side reads.
		 * Note: backpressure here is fired on `from`, not `to` -
		 * the wedge is on the download path. */
		double t_data_start = monotime_double();
		get_msg(from, msg);
		if (monotime_double() - t_data_start >
		    SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC)
			sftp_hpn_rdahead_backpressure_signal(from->hpn);
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
			sftp_hpn_bytes_wired_add(from->hpn, (uint64_t)len);
			if (len == 0) {
				if (seen_zerolen)
					fatal_f("server sent zero data length");
				seen_zerolen = 1;
			}

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
			sftp_hpn_bytes_wired_add(to->hpn, (uint64_t)len);
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
				} else {
					/* HPN adaptive read-ahead
					 * (origin / read side). */
					max_req = sftp_hpn_rdahead_window(
					    from->hpn, len, max_req,
					    from->num_requests);
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

	/*
	 * Same as the download read paths (sftp_download / sftp_download_range):
	 * a non-empty SOURCE-read queue here means the `from` connection broke
	 * mid-transfer, not a clean completion.  Fail soft - mark `from` dead and
	 * set read_error - instead of fatal()-ing the whole process.  (The dest
	 * write side is handled separately above via handle_dest_replies.)
	 */
	if (TAILQ_FIRST(&requests) != NULL) {
		if (!sftp_conn_is_dead(from))
			sftp_conn_die(from, "crossload read of \"%s\" ended "
			    "with requests still in flight (connection lost)",
			    from_path);
		while ((req = TAILQ_FIRST(&requests)) != NULL) {
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
		}
		read_error = 1;
	}
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
	struct sshbuf *msg = conn->msg, *uidbuf, *gidbuf;
	u_int i, expected_id, id;
	char *name, **usernames = NULL, **groupnames = NULL;
	u_char type;
	int r;

	*usernamesp = *groupnamesp = NULL;
	if (!sftp_can_get_users_groups_by_id(conn))
		return SSH_ERR_FEATURE_UNSUPPORTED;

	if ((uidbuf = sshbuf_new()) == NULL ||
	    (gidbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* Reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
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
	if (get_msg(conn, msg) != 0) {
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		return -1;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0)
		fatal_fr(r, "parse");
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_hpn_set_protocol_violation(conn->hpn);
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
		sshbuf_free(uidbuf);
		sshbuf_free(gidbuf);
		return -1;
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_EXTENDED_REPLY, type);
		sftp_hpn_set_protocol_violation(conn->hpn);
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

