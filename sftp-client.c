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
#include "sftp-hpn-client.h"	/* HPN: per-conn state, walk sinks */
#include "sftp-hpn-verify.h"	/* HPN: chunked resume and verify helpers */
#include "sftp-hpn-server.h"	/* HPN: extension names */
#include "sftp-hpn-bundle-server.h"	/* HPN: bundle extension names */
#include "sftp-hpn-tree.h"	/* HPN: dtree extension names, depth cap */
#include "hpn-meter.h"	/* HPN: progress meter core */
#include "sftp-client-internal.h"	/* HPN: sftp_conn accessors */

extern _Atomic sig_atomic_t interrupted;	/* HPN: workers read it */
extern int showprogress;

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
	u_int exts;
	uint64_t limit_kbps;
	struct bwlimit bwlimit_in, bwlimit_out;
	struct sshbuf *msg;	/* HPN: recycled message buffer */
	struct sftp_hpn_conn *hpn;	/* HPN: per-connection HPN state */
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

/* HPN-SSH additions.
 *
 * The defines, structs and file-scope variables in this block are
 * HPN-specific with no upstream counterpart. They are collected here so
 * the upstream declarations above keep their original order and OpenSSH
 * merges do not collide with HPN code. */

/* HPN: thread safety. Each parallel worker drives its own struct
 * sftp_conn on its own thread, and all per-connection state lives in
 * that struct. This file only reads the externs interrupted and
 * showprogress. The file-scope variables below and the serial progress
 * meter are used only when showprogress is set, and the orchestrator
 * clears it while workers run. New file-scope state must follow the
 * same rules. */

/* HPN: request window for the directory setstat and mkdir pipelines. */
#define SFTP_DIR_PIPELINE_WINDOW 64

/* HPN: the HPN walks cap depth with HPN_WALK_MAX_DEPTH. It must equal
 * MAX_DIR_DEPTH, and this is the only file that sees both. See
 * sftp-hpn-tree.h for why. */
#if MAX_DIR_DEPTH != HPN_WALK_MAX_DEPTH
# error "MAX_DIR_DEPTH and HPN_WALK_MAX_DEPTH must match"
#endif

/* HPN: serial download sink for sftp_tree_download_consume and its
 * readdir fallback. It creates local dirs, bundles or downloads regular
 * files and defers directory attrs. It has no fail(), since the
 * consumer's -1 return carries the error. aborting() reports an interrupt
 * or a bundle flush that aborted. */
struct serial_dl_sink {
	struct sftp_tree_dl_sink	base;
	struct sftp_conn	       *conn;
	struct sftp_hpn_bundle_acc     *bundle_acc;
	struct sftp_hpn_dirattr_list   *dirs;
	int				preserve_flag;
	int				print_flag;
	int				resume_flag;
	int				verify;
	int				fsync_flag;
	int				inplace_flag;
	int				flush_aborted;	/* set by xfer_file */
};

/* HPN: serial upload sink for sftp_upload_walk_consume. It bundles or
 * uploads each regular file, defers the remote dir attrs and prints
 * "Entering". It has no fail(), since the driver's -1 return carries the
 * error, and no before_mkdir(), since serial has no walker phases.
 * aborting() reports an interrupt or a bundle flush that aborted. */
struct serial_ul_sink {
	struct sftp_upload_sink		base;
	struct sftp_conn	       *conn;
	struct sftp_hpn_bundle_acc     *bundle_acc;
	struct sftp_hpn_dirattr_list   *dirs;
	int				preserve_flag;
	int				print_flag;
	int				resume;
	int				verify;
	int				fsync_flag;
	int				inplace_flag;
	int				flush_aborted;	/* set by xfer_file */
};

/* HPN: per-file state for the pipelined batch upload. */
struct batch_file {
	int		local_fd;	/* -1 when not open */
	struct stat	sb;
	Attrib		a;
	u_char	       *handle;		/* NULL when not open */
	size_t		handle_len;
	u_int		open_id;
	u_int		close_id;
	u_int		write_id;	/* small-file single WRITE */
	int		write_sent;	/* write_id went out */
	/* What phase 4 sent ahead of a small file's CLOSE (the in-place
	 * size, the -p attrs, the fsync), in send order, for phase 5. */
	u_int		pre_close_ids[3];
	const char     *pre_close_what[3];
	int		npre_close;
	int		failed;
};

/* HPN: a sent batch whose CLOSE replies are still outstanding.
 * sftp_upload_batch_send returns it, and sftp_upload_batch_finish or the
 * next send drains and frees it, files included. entries belongs to the
 * caller and must stay valid until then. */
struct sftp_upload_batch_pending {
	struct sftp_upload_batch_entry *entries;
	struct batch_file	       *files;
	int				nentries;
	int				any_fail;
};

/* HPN: crossload sink, remote to remote through this client. The download
 * drivers walk the origin with conn set to from, and this sink writes each
 * entry to the destination to. make_dir creates the destination directory
 * and defers its setstat. xfer_file crossloads one file. It has no fail(),
 * since crossload is serial and the driver's -1 return carries the error. */
struct crossload_sink {
	struct sftp_tree_dl_sink	base;
	struct sftp_conn	       *from;
	struct sftp_conn	       *to;
	struct sftp_hpn_dirattr_list   *dirs;
	int				preserve_flag;
	int				print_flag;
};

/* HPN: counter and on flag for the serial resume-check meter. Only the
 * serial path touches them, since parallel workers run with showprogress
 * off. */
static off_t resume_meter_counter;
static int resume_meter_on;

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

int
send_msg(struct sftp_conn *conn, struct sshbuf *m)
{
	u_char mlen[4];
	struct iovec iov[2];
	size_t msg_len = sshbuf_len(m);
	struct bwlimit *bw;

	if (conn->hpn->dead) /* HPN */
		return -1;

	/* HPN: a streamed reply owns the connection until it drains (see
	 * reply_stream_active). A request sent now would interleave its reply
	 * with the rest of the stream and break both readers, so die at the
	 * call site that broke the rule rather than corrupt the stream. */
	if (conn->hpn->reply_stream_active)
		fatal_f("request sent while a streamed reply is in flight on "
		    "this connection");

	/* HPN adaptive upload pacing: apply the tighter of the adaptive
	 * ceiling and the user's explicit -l (NULL when neither binds). */
	bw = sftp_conn_pace_bwlimit(conn,
	    conn->limit_kbps > 0 ? &conn->bwlimit_out : NULL,
	    conn->limit_kbps);

	if (msg_len > SFTP_MAX_MSG_LENGTH)
		fatal("Outbound message too long %zu", msg_len);

	/* Send length first */
	put_u32(mlen, msg_len);
	iov[0].iov_base = mlen;
	iov[0].iov_len = sizeof(mlen);
	iov[1].iov_base = (u_char *)sshbuf_ptr(m);
	iov[1].iov_len = msg_len;

	if (atomiciov6(writev, conn->fd_out, iov, 2, sftpio, bw) !=
	    msg_len + sizeof(mlen)) {
		/* HPN: EPIPE and EBADF mean the connection is gone. Either
		 * the ssh child died, or the orchestrator's abort closed the
		 * fd, which every worker hits at once on an interrupt. The
		 * respawn notice and the transfer summary report that better,
		 * so log it at debug. Any other errno is a real send error. */
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

/* HPN: a read from the transport pipe came up short, so the connection is
 * gone. Log it at debug, since the respawn notice and the transfer summary
 * report it better, mark the connection dead and return -1. what names the
 * part of the message being read. */
static int
get_msg_read_failed(struct sftp_conn *conn, const char *what, size_t got,
    size_t want)
{
	int saved_errno = errno;

	if (saved_errno == EPIPE || saved_errno == ECONNRESET)
		debug("sftp: connection closed");
	else
		debug("sftp: read: %s", strerror(saved_errno));
	/* ENV-VAR HPN_PARALLEL_TRACE: show who closed the transport pipe. A
	 * read of 0 between messages is a clean EOF from the peer, and a
	 * partial read means it vanished mid-message. The pipe to the ssh
	 * child is local, so this is almost always EOF, not a TCP errno. */
	if (getenv("HPN_PARALLEL_TRACE") != NULL)
		logit("sftp CONN-DIAG: get_msg %s-read got=%zu/%zu "
		    "errno=%d(%s)", what, got, want, saved_errno,
		    saved_errno == 0 ? "EOF" : strerror(saved_errno));
	conn->hpn->dead = 1;
	return -1;
}

static int
get_msg_extended(struct sftp_conn *conn, struct sshbuf *m, int initial)
{
	u_int msg_len;
	u_char *p;
	size_t got;
	int r;

	if (conn->hpn->dead) /* HPN */
		return -1;

	sshbuf_reset(m);
	if ((r = sshbuf_reserve(m, 4, &p)) != 0)
		fatal_fr(r, "reserve");
	got = atomicio6(read, conn->fd_in, p, 4, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL);
	if (got != 4) /* HPN */
		return get_msg_read_failed(conn, "hdr", got, 4);

	if ((r = sshbuf_get_u32(m, &msg_len)) != 0)
		fatal_fr(r, "sshbuf_get_u32");
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		/* HPN: after the handshake, an oversized message breaks this
		 * connection, not the process, which may hold other workers. */
		if (!initial) {
			error("Received message too long %u", msg_len);
			sftp_conn_set_protocol_violation(conn);
			return -1;
		}
		do_log2(initial ? SYSLOG_LEVEL_ERROR : SYSLOG_LEVEL_FATAL,
		    "Received message too long %u", msg_len);
		fatal("Ensure the remote shell produces no output "
		    "for non-interactive sessions.");
	}

	if ((r = sshbuf_reserve(m, msg_len, &p)) != 0)
		fatal_fr(r, "reserve");
	got = atomicio6(read, conn->fd_in, p, msg_len, sftpio,
	    conn->limit_kbps > 0 ? &conn->bwlimit_in : NULL);
	if (got != msg_len) /* HPN */
		return get_msg_read_failed(conn, "body", got, msg_len);

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

	/* HPN: conn->msg is reused, and a reply reader such as get_status
	 * leaves a STATUS reply's error message and language tag unread.
	 * Reset it, or send_msg would send those bytes ahead of this
	 * request. */
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

	/* HPN: reset conn->msg, as in send_string_request. */
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

/* HPN: keep a STATUS reply's code, so a caller can tell a permission
 * denial from other failures, and latch a denial for the retry policy. A
 * denial from the server's -P/-p policy also latches a policy abort. msg
 * must be positioned at the reply's error message. */
static void
record_status(struct sftp_conn *conn, struct sshbuf *msg, u_int status)
{
	conn->hpn->last_status = status;
	if (status == SSH2_FX_PERMISSION_DENIED) {
		sftp_conn_set_perm_denied(conn);
		sftp_conn_check_policy_tag(conn, msg);
	}
}

static u_int
get_status(struct sftp_conn *conn, u_int expected_id)
{
	struct sshbuf *msg = conn->msg;
	u_char type;
	u_int id, status;
	int r;

	/* HPN: every failure here returns SSH2_FX_CONNECTION_LOST and marks
	 * the connection, so a parallel worker fails its unit instead of
	 * taking the process down. */
	if (get_msg(conn, msg) != 0)
		return SSH2_FX_CONNECTION_LOST;
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		/* HPN: a truncated reply breaks this connection, not the
		 * process, as the checks below do. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return SSH2_FX_CONNECTION_LOST;
	}

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}
	if (type != SSH2_FXP_STATUS) {
		error_f("expected SSH2_FXP_STATUS(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_STATUS, type);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}

	if ((r = sshbuf_get_u32(msg, &status)) != 0) {
		error_fr(r, "parse status");
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return SSH2_FX_CONNECTION_LOST;
	}

	debug3("SSH2_FXP_STATUS %u", status);

	record_status(conn, msg, status); /* HPN */
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
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		/* HPN: a truncated reply breaks this connection, not the
		 * process, as in get_status. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return NULL;
	}

	if (id != expected_id) {
		error("%s: ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, id, expected_id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}
	if (type == SSH2_FXP_STATUS) {
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse status");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			return NULL;
		}
		record_status(conn, msg, status); /* HPN */
		if (errfmt != NULL)
			error("%s: %s", errmsg, fx2txt(status));
		return NULL;
	} else if (type != SSH2_FXP_HANDLE) {
		error("%s: expected SSH2_FXP_HANDLE(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    errfmt == NULL ? __func__ : errmsg, SSH2_FXP_HANDLE, type);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

	if ((r = sshbuf_get_string(msg, &handle, len)) != 0) {
		error_fr(r, "parse handle");
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

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
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		/* HPN: a truncated reply breaks this connection, not the
		 * process, as in get_status. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return -1;
	}

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return -1;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse status");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			return -1;
		}
		if (quiet)
			debug("stat remote: %s", fx2txt(status));
		else
			error("stat remote: %s", fx2txt(status));
		return -1;
	} else if (type != SSH2_FXP_ATTRS) {
		error_f("expected SSH2_FXP_ATTRS(%u) packet, got %u - "
		    "possible MITM or server protocol corruption",
		    SSH2_FXP_ATTRS, type);
		sftp_conn_set_protocol_violation(conn); /* HPN */
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
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		/* HPN: a truncated reply breaks this connection, not the
		 * process, as in get_status. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return -1;
	}

	debug3("Received statvfs reply T:%u I:%u", type, id);
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible MITM or "
		    "server protocol corruption", id, expected_id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return -1;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse status");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			return -1;
		}
		if (quiet)
			debug("remote statvfs: %s", fx2txt(status));
		else
			error("remote statvfs: %s", fx2txt(status));
		return -1;
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("expected SSH2_FXP_EXTENDED_REPLY(%u) packet, "
		    "got %u - possible MITM or server protocol corruption",
		    SSH2_FXP_EXTENDED_REPLY, type);
		sftp_conn_set_protocol_violation(conn); /* HPN */
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
	    (r = sshbuf_get_u64(msg, &st->f_namemax)) != 0) {
		error_fr(r, "parse statvfs");
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return -1;
	}

	st->f_flag = (flag & SSH2_FXE_STATVFS_ST_RDONLY) ? ST_RDONLY : 0;
	st->f_flag |= (flag & SSH2_FXE_STATVFS_ST_NOSUID) ? ST_NOSUID : 0;

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
	/* HPN: num_requests is the read-ahead controller's ceiling. */
	sftp_conn_rdahead_init(ret, ret->num_requests);
	ret->exts = 0;
	ret->limit_kbps = 0;

	/* HPN: the connection keeps this buffer for its later requests. */
	if ((ret->msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	msg = ret->msg;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_INIT)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FILEXFER_VERSION)) != 0)
		fatal_fr(r, "parse");

	send_msg(ret, msg);

	/* HPN: the transport closed before the handshake finished, for
	 * example after refusing the cipher with its own message. Let that
	 * message stand instead of reporting a bogus "type 0" packet. */
	if (get_msg_extended(ret, msg, 1) < 0)
		goto fail;

	/* Expecting a VERSION reply */
	if ((r = sshbuf_get_u8(msg, &type)) != 0) {
		/* HPN: workers call this too, so a bad reply fails the
		 * connection, not the process. */
		error_fr(r, "parse type");
		goto fail;
	}
	if (type != SSH2_FXP_VERSION) {
		error("Invalid packet back from SSH2_FXP_INIT (type %u)",
		    type);
		goto fail; /* HPN */
	}
	if ((r = sshbuf_get_u32(msg, &ret->version)) != 0) {
		error_fr(r, "parse version");
		goto fail; /* HPN */
	}

	debug2("Remote version: %u", ret->version);

	/* Check for extensions */
	while (sshbuf_len(msg) > 0) {
		char *name;
		u_char *value;
		size_t vlen;
		int known = 0;

		if ((r = sshbuf_get_cstring(msg, &name, NULL)) != 0 ||
		    (r = sshbuf_get_string(msg, &value, &vlen)) != 0) {
			error_fr(r, "parse extension");
			free(name);
			goto fail; /* HPN */
		}
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
		} else if (strcmp(name, HPN_EXT_CHECK_FILE) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: the server hashes a file's leading bytes. */
			ret->exts |= SFTP_EXT_HPN_CHECK_FILE;
			known = 1;
		} else if (strcmp(name, HPN_EXT_HASH_RANGE) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: the server hashes many ranges of a file in one
			 * request, so a verified resume resends only the
			 * ranges that differ. */
			ret->exts |= SFTP_EXT_HASH_RANGE;
			known = 1;
		} else if (strcmp(name, HPN_EXT_FS_INFO) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: a path's filesystem type and stripe geometry. */
			ret->exts |= SFTP_EXT_HPN_FS_INFO;
			known = 1;
		} else if (strcmp(name, HPN_EXT_DTREE_OPEN) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: opens a chunked tree walk on the server. */
			ret->exts |= SFTP_EXT_HPN_DTREE_OPEN;
			known = 1;
		} else if (strcmp(name, HPN_EXT_DTREE_READ) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: reads the walk tree-open opened. The download
			 * walks need both, and use them in place of
			 * per-directory readdir. */
			ret->exts |= SFTP_EXT_HPN_DTREE_READ;
			known = 1;
		} else if (strcmp(name, HPN_EXT_BUNDLE) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: the server accepts bundle uploads through
			 * hpn-bundle-open. */
			ret->exts |= SFTP_EXT_HPN_BUNDLE;
			known = 1;
		} else if (strcmp(name, HPN_EXT_BUNDLE_FETCH) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: the server packs a bundle from a list of
			 * paths. */
			ret->exts |= SFTP_EXT_HPN_BUNDLE_FETCH;
			known = 1;
		} else if (strcmp(name, HPN_EXT_FILE_LAYOUT) == 0 &&
		    strcmp((char *)value, "1") == 0) {
			/* HPN: the server sets a Lustre stripe layout on a
			 * destination directory before files land in it.
			 * HPNLustreStripeCount uses it. */
			ret->exts |= SFTP_EXT_HPN_FILE_LAYOUT;
			known = 1;
		} else if (strcmp(name, HPN_EXT_MAX_WORKERS) == 0) {
			const char *errstr;
			int workers;

			/* HPN: the operator's per-user parallel-worker cap,
			 * a count rather than a revision. 0 means no cap. A
			 * malformed value counts as not advertised, so the
			 * conservative default applies. */
			workers = (int)strtonum((char *)value, 0, 1000000,
			    &errstr);
			if (errstr == NULL)
				ret->hpn->hpn_max_workers_cap = workers;
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
		if (sftp_get_limits(ret, &limits) != 0) {
			/* HPN: a worker's connection can drop here. */
			error_f("limits failed");
			goto fail;
		}

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

 fail:
	sftp_free(ret);	/* HPN: also frees msg and the HPN state */
	return(NULL);
}

void
sftp_free(struct sftp_conn *conn)
{
	if (conn == NULL)
		return;
	sshbuf_free(conn->msg);	/* HPN: recycled message buffer */
	sftp_hpn_conn_free(conn->hpn);	/* HPN: per-connection HPN state */
	freezero(conn, sizeof(*conn));
}

u_int
sftp_proto_version(struct sftp_conn *conn)
{
	return conn->version;
}

/* HPN: nonzero once the reporter asks this worker to yield the rest of its
 * range (HPNTailRedistribute). The range transfer loops poll it. */
static int
yield_requested(struct sftp_conn *conn)
{
	return conn->hpn->yield_flag != NULL &&
	    __atomic_load_n(conn->hpn->yield_flag, __ATOMIC_RELAXED);
}

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

	/* HPN: reset for the same reason as send_string_request. */
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
	    (r = sshbuf_get_u32(msg, &msg_id)) != 0) {
		/* HPN: workers query limits too, so a bad reply fails the
		 * connection, not the process. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return -1;
	}

	debug3("Received limits reply T:%u I:%u", type, msg_id);
	if (id != msg_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    msg_id, id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
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
	    (r = sshbuf_get_u64(msg, &limits->open_handles)) != 0) {
		error_fr(r, "parse limits");
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return -1;
	}

	return 0;
}

int
sftp_close(struct sftp_conn *conn, const u_char *handle, u_int handle_len)
{
	u_int id, status;
	struct sshbuf *msg = conn->msg;
	int r;

	/* HPN: reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	id = conn->msg_id++;
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0)
		fatal_fr(r, "parse");
	send_msg(conn, msg);
	debug3("Sent message SSH2_FXP_CLOSE I:%u", id);

	status = get_status(conn, id);
	if (status != SSH2_FX_OK) {
		/* HPN: stay quiet when the connection is gone, since that is
		 * reported where it broke. On a live connection a failed close
		 * may be the only report of a remote write error. */
		if (sftp_conn_is_dead(conn))
			debug("close remote: %s", fx2txt(status));
		else
			error("close remote: %s", fx2txt(status));
	}

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

	/* HPN: reset for the same reason as send_string_request. */
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

		if (get_msg(conn, msg) != 0)
			goto out; /* HPN */

		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0) {
			/* HPN: a parallel walk reads directories on the
			 * control connection while workers transfer, so a
			 * bad reply fails the connection, not the process. */
			error_fr(r, "parse");
			sftp_conn_set_protocol_violation(conn);
			goto out;
		}

		debug3("Received reply T:%u I:%u", type, id);

		if (id != expected_id) {
			error_f("ID mismatch (%u != %u) - possible protocol corruption",
			    id, expected_id);
			sftp_conn_set_protocol_violation(conn); /* HPN */
			goto out;
		}

		if (type == SSH2_FXP_STATUS) {
			u_int rstatus;

			if ((r = sshbuf_get_u32(msg, &rstatus)) != 0) {
				error_fr(r, "parse status");
				sftp_conn_set_protocol_violation(conn); /* HPN */
				goto out;
			}
			debug3("Received SSH2_FXP_STATUS %d", rstatus);
			if (rstatus == SSH2_FX_EOF)
				break;
			error("Couldn't read directory: %s", fx2txt(rstatus));
			goto out;
		} else if (type != SSH2_FXP_NAME) {
			error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_NAME, type);
			sftp_conn_set_protocol_violation(conn); /* HPN */
			goto out;
		}

		if ((r = sshbuf_get_u32(msg, &count)) != 0) {
			error_fr(r, "parse count");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			goto out;
		}
		if (count > SSHBUF_SIZE_MAX) {
			error_f("nonsensical number of entries");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			goto out;
		}
		if (count == 0)
			break;
		debug3("Received %d SSH2_FXP_NAME responses", count);
		for (i = 0; i < count; i++) {
			char *filename, *longname;
			Attrib a;

			if ((r = sshbuf_get_cstring(msg, &filename,
			    NULL)) != 0 ||
			    (r = sshbuf_get_cstring(msg, &longname,
			    NULL)) != 0) {
				error_fr(r, "parse filenames");
				free(filename);
				sftp_conn_set_protocol_violation(conn); /* HPN */
				goto out;
			}
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

/* HPN: apply n SETSTATs with up to SFTP_DIR_PIPELINE_WINDOW in flight,
 * rather than one round trip each. It relies on the server handling
 * requests and replies in order, as OpenSSH's sftp-server does, though the
 * SFTP draft allows reordering. That keeps the caller's order and lets the
 * drain match replies by position. A failed setstat is logged and the rest
 * go ahead, as with sftp_setstat. Returns the number of failures. */
int
sftp_setstat_pipeline(struct sftp_conn *conn, char **paths, Attrib *attrs,
    int n)
{
	u_int *ids;
	u_int status;
	int sent, recv = 0, failures = 0, window;

	if (n <= 0)
		return 0;
	window = MINIMUM(n, SFTP_DIR_PIPELINE_WINDOW);
	ids = xcalloc(n, sizeof(*ids));

	debug2_f("pipelining %d directory setstats (window %d)", n, window);
	/* Fill the window. */
	for (sent = 0; sent < window; sent++) {
		ids[sent] = conn->msg_id++;
		send_string_attrs_request(conn, ids[sent], SSH2_FXP_SETSTAT,
		    paths[sent], strlen(paths[sent]), &attrs[sent]);
	}
	/* Collect the replies in send order, and send the next path as each
	 * one comes back. */
	while (recv < n) {
		status = get_status(conn, ids[recv]);
		if (status == SSH2_FX_CONNECTION_LOST) {
			/* The connection is dead or out of step with the
			 * server. Count every path without a reply as
			 * failed and stop. The unread replies go with the
			 * connection. */
			failures += n - recv;
			break;
		}
		if (status != SSH2_FX_OK) {
			error("remote setstat \"%s\": %s", paths[recv],
			    fx2txt(status));
			failures++;
		}
		recv++;
		/* That reply freed a slot in the window. Send the next
		 * path into it. */
		if (sent < n) {
			ids[sent] = conn->msg_id++;
			send_string_attrs_request(conn, ids[sent],
			    SSH2_FXP_SETSTAT, paths[sent],
			    strlen(paths[sent]), &attrs[sent]);
			sent++;
		}
	}
	free(ids);
	return failures;
}

/* HPN: create n sibling directories with up to SFTP_DIR_PIPELINE_WINDOW
 * MKDIRs in flight, rather than one round trip each. Like
 * sftp_setstat_pipeline, it relies on in-order replies. Each directory gets
 * owner write and search added, as in sftp_hpn_ensure_remote_dir, so a copy
 * of a read-only source directory can still be filled. The deferred setstat
 * restores its real mode. created_out[i] is set when this call created
 * paths[i]. failed_out[i], which may be NULL, is set when paths[i] could not
 * be created, so the caller can skip it. A directory that already existed
 * is neither. Returns the number of failures. */
int
sftp_mkdir_pipeline(struct sftp_conn *conn, char **paths, Attrib *attrs,
    int n, u_char *created_out, u_char *failed_out)
{
	u_int *ids;
	u_int status;
	int *failed;
	Attrib mkdir_attrs;
	int sent, recv = 0, nfailed = 0, failures = 0, window, k;

	if (n <= 0)
		return 0;
	window = MINIMUM(n, SFTP_DIR_PIPELINE_WINDOW);
	ids = xcalloc(n, sizeof(*ids));
	failed = xcalloc(n, sizeof(*failed));
	memset(created_out, 0, (size_t)n);
	if (failed_out != NULL)
		memset(failed_out, 0, (size_t)n);

	/* Phase 1: send every MKDIR and collect the replies. A failure is only
	 * noted here. Checking it with a stat now would read one of the
	 * outstanding MKDIR replies as the stat's own. */
	debug2_f("pipelining %d directory mkdirs (window %d)", n, window);
	/* Fill the window. */
	for (sent = 0; sent < window; sent++) {
		mkdir_attrs = attrs[sent];
		mkdir_attrs.perm |= (S_IWUSR|S_IXUSR);
		ids[sent] = conn->msg_id++;
		send_string_attrs_request(conn, ids[sent], SSH2_FXP_MKDIR,
		    paths[sent], strlen(paths[sent]), &mkdir_attrs);
	}
	/* Collect the replies in send order, and send the next path as each
	 * one comes back. */
	while (recv < n) {
		status = get_status(conn, ids[recv]);
		if (status == SSH2_FX_CONNECTION_LOST) {
			/* The connection is gone. Nothing from here on was
			 * answered, and the failures already noted cannot be
			 * checked with a stat, so all of them count as failed.
			 * Marking them keeps the caller out of directories
			 * that may not exist. */
			failures += nfailed + n - recv;
			if (failed_out != NULL) {
				for (k = 0; k < nfailed; k++)
					failed_out[failed[k]] = 1;
				for (k = recv; k < n; k++)
					failed_out[k] = 1;
			}
			free(ids);
			free(failed);
			return failures;
		}
		if (status == SSH2_FX_OK)
			created_out[recv] = 1;
		else
			failed[nfailed++] = recv;	/* stat it in phase 2 */
		recv++;
		/* That reply freed a slot in the window. Send the next
		 * path into it. */
		if (sent < n) {
			mkdir_attrs = attrs[sent];
			mkdir_attrs.perm |= (S_IWUSR|S_IXUSR);
			ids[sent] = conn->msg_id++;
			send_string_attrs_request(conn, ids[sent],
			    SSH2_FXP_MKDIR, paths[sent],
			    strlen(paths[sent]), &mkdir_attrs);
			sent++;
		}
	}
	free(ids);

	/* Phase 2, usually empty: every reply is in, so a stat per failure is
	 * safe now. A directory that already exists is fine and keeps
	 * created_out at 0, so the caller defers no setstat for it. Anything
	 * else is a real failure. */
	for (k = 0; k < nfailed; k++) {
		int i = failed[k];
		Attrib existing;

		if (sftp_stat(conn, paths[i], 1, &existing) == 0 &&
		    (existing.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
		    S_ISDIR(existing.perm))
			continue;	/* pre-existing directory: tolerate */
		error("remote mkdir \"%s\": failed", paths[i]);
		if (failed_out != NULL)
			failed_out[i] = 1;
		failures++;
	}
	free(failed);
	return failures;
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
	char *filename = NULL, *longname = NULL;	/* HPN */
	Attrib a;
	u_char type;
	int r;
	const char *what = "SSH2_FXP_REALPATH";

	if (expand)
		what = "expand-path@openssh.com";

	expected_id = id = conn->msg_id++;
	if (expand) {
		/* HPN: reset for the same reason as send_string_request. */
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
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		/* HPN: a bad reply fails the connection, not the process, as
		 * in get_status. */
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		return NULL;
	}

	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

	if (type == SSH2_FXP_STATUS) {
		u_int status;
		char *errmsg;

		if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0) {
			error_fr(r, "parse status");
			sftp_conn_set_protocol_violation(conn); /* HPN */
			return NULL;
		}
		error("%s %s: %s", expand ? "expand" : "realpath",
		    path, *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		return NULL;
	} else if (type != SSH2_FXP_NAME) {
		error_f("Expected SSH2_FXP_NAME(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_NAME, type);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

	if ((r = sshbuf_get_u32(msg, &count)) != 0) {
		error_fr(r, "parse count");
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}
	if (count != 1) {
		error("Got multiple names (%d) from %s", count, what);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

	if ((r = sshbuf_get_cstring(msg, &filename, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(msg, &longname, NULL)) != 0 ||
	    (r = decode_attrib(msg, &a)) != 0) {
		error_fr(r, "parse filename/attrib");
		free(filename);
		free(longname);
		sftp_conn_set_protocol_violation(conn); /* HPN */
		return NULL;
	}

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
	struct sshbuf *msg = conn->msg;
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

	attrib_clear(&junk); /* Send empty attributes */

	/* Open the old file for reading */
	/* HPN: reset for the same reason as send_string_request. */
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
	/* HPN: reset for the same reason as send_string_request. */
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
		sftp_close(conn, old_handle, old_handle_len); /* HPN */
		free(old_handle);
		return -1;
	}

	/* Copy the file data */
	/* HPN: reset for the same reason as send_string_request. */
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

	/* HPN: reset for the same reason as send_string_request. */
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

	/* HPN: reset for the same reason as send_string_request. */
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

	/* HPN: reset for the same reason as send_string_request. */
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

	/* HPN: reset for the same reason as send_string_request. */
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

	if (id != expected_id)
		fatal("ID mismatch (%u != %u)", id, expected_id);

	if (type == SSH2_FXP_STATUS) {
		u_int status;

		if ((r = sshbuf_get_u32(msg, &status)) != 0)
			fatal_fr(r, "parse status");
		error("Couldn't readlink: %s", fx2txt(status));
		sshbuf_free(msg);
		return(NULL);
	} else if (type != SSH2_FXP_NAME)
		fatal("Expected SSH2_FXP_NAME(%u) packet, got %u",
		    SSH2_FXP_NAME, type);

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
	struct sshbuf *msg = conn->msg;
	u_int id;
	int r;

	if ((conn->exts & SFTP_EXT_STATVFS) == 0) {
		error("Server does not support statvfs@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"", path);

	/* HPN: reset for the same reason as send_string_request. */
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
	struct sshbuf *msg = conn->msg;
	u_int status, id;
	int r;

	if ((conn->exts & SFTP_EXT_LSETSTAT) == 0) {
		error("Server does not support lsetstat@openssh.com extension");
		return -1;
	}

	debug2("Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"", path);

	/* HPN: reset for the same reason as send_string_request. */
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

	/* HPN: reset for the same reason as send_string_request. */
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_READ)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, handle, handle_len)) != 0 ||
	    (r = sshbuf_put_u64(msg, offset)) != 0 ||
	    (r = sshbuf_put_u32(msg, len)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
}

int
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
	/* HPN: reset for the same reason as send_string_request. */
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

/* HPN: start the serial meter for a verified resume's hash check, which
 * sftp_download and sftp_upload run before any data moves. Without it the
 * user sees nothing while both ends hash the partial file. The hash code
 * advances resume_meter_counter through the pointer registered here, so
 * the meter moves while this thread waits on the hash exchange. Does
 * nothing when showprogress is off, which includes parallel workers. */
static void
resume_check_meter_begin(struct sftp_conn *conn, off_t total)
{
	if (!showprogress || total <= 0)
		return;
	resume_meter_counter = 0;
	/* WORK kind in the hash-byte domain: the core marks it not a file
	 * and raises the resume phase flag for the frame stream. */
	hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_WORK,
	    HPN_METER_DOM_HASH, "resume check", total,
	    &resume_meter_counter, 0);
	sftp_conn_set_hash_meter_ctr(conn, &resume_meter_counter);
	resume_meter_on = 1;
}

/* HPN: stop the resume-check meter. A no-op when begin did not start
 * one, so every exit path can call it. */
static void
resume_check_meter_end(struct sftp_conn *conn)
{
	if (!resume_meter_on)
		return;
	/* Unhook the counter so later hash work does not advance it. */
	sftp_conn_set_hash_meter_ctr(conn, NULL);
	hpn_meter_stop(hpn_meter_serial(), conn);
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
		/* HPN: -1 error, 1 identical, 2 target larger than source. */
		int skip_ret = -1;
		/* HPN: set when the chunked refetch ran its own transfer
		 * meter, which counts the file when it stops. */
		int chunked_metered = 0;
		if (fstat(local_fd, &st) == -1) {
			error("stat local \"%s\": %s",
			    local_path, strerror(errno));
			goto resume_exit;
		}
		if (st.st_size < 0) {
			error("\"%s\" has negative size", local_path);
			goto resume_exit;
		}
		if (verify) {
			int chunked, match;

			/* HPN: verified resume needs hpn-check-file. Check it
			 * before looking at the local file, so the failure is
			 * the same whether that file is absent, partial, or
			 * full size, as in sftp_upload. The caller asked for
			 * verification, so there is no quiet fallback to a
			 * fresh download. */
			if (!sftp_conn_has_hpn_check_file(conn))
				fatal("\"%s\": %s", remote_path,
				    RESUME_INCOMPAT_MSG);
			/* HPN: the resume-check meter counts the hashing below
			 * in work-bytes. Both ends hash the overlap. */
			resume_check_meter_begin(conn,
			    2 * MINIMUM(st.st_size, (off_t)size));
			if ((uint64_t)st.st_size == size) {
				/* HPN: with sftp-hash-range, hash in chunks and
				 * fetch only the chunks that differ, instead of
				 * downloading the whole file again. It declines
				 * with -1 for a small file, a server without the
				 * extension, or an internal failure. The
				 * whole-file check below then decides, which is
				 * as correct but slower on a mismatch. */
				chunked = sftp_hpn_try_chunked_resume_download(
				    conn, local_fd, local_path, remote_path,
				    (off_t)size,
				    st.st_size /* dest-EOF clamp */);
				if (chunked >= 0) {
					if (chunked == 0 && showprogress)
						chunked_metered = 1;
					skip_ret = chunked == 1 ? 1 : 0;
					goto resume_exit;
				}

				/* HPN: equal size does not mean equal content.
				 * A range-split download creates the local file
				 * at full size, so a crash leaves it full size
				 * with holes of zeros. Hash the whole file on
				 * both ends and skip only when they match.
				 * Otherwise truncate and download again. */
				match = sftp_hpn_prefix_match(conn, local_fd,
				    remote_path, size);

				if (match == 1) {
					debug("verified transfer: "
					    "full-file hash match, "
					    "\"%s\" already complete",
					    local_path);
					skip_ret = 1; /* identical */
					goto resume_exit;
				}
				debug("verified transfer: same size "
				    "but hash %s for \"%s\"; "
				    "re-downloading from scratch",
				    match == 0 ? "mismatch" : "failed",
				    local_path);
				if (ftruncate(local_fd, 0) == -1) {
					error("truncate \"%s\": %s",
					    local_path, strerror(errno));
					goto resume_exit;
				}
				/* offset stays 0 for a fresh download */
			} else if ((uint64_t)st.st_size > size) {
				skip_ret = 2; /* target larger than source */
				goto resume_exit;
			} else if (st.st_size > 0) {
				/* HPN: try the chunked check first, as the
				 * upload side does. A range-split partial grows
				 * to its highest write and can hold holes below
				 * that size, which a prefix resume would append
				 * past. Chunks past the local end are fetched
				 * without hashing. A decline falls through to
				 * the prefix resume, for sequential partials and
				 * files under the chunk threshold. */
				chunked = sftp_hpn_try_chunked_resume_download(
				    conn, local_fd, local_path, remote_path,
				    (off_t)size,
				    st.st_size /* dest-EOF clamp */);
				if (chunked >= 0) {
					if (chunked == 0 && showprogress)
						chunked_metered = 1;
					skip_ret = chunked == 1 ? 1 : 0;
					goto resume_exit;
				}

				/* HPN: hash the overlapping prefix to choose
				 * between resuming and restarting. The server
				 * hashes the data on its disk, so the comparison
				 * is exact. */
				match = sftp_hpn_prefix_match(conn, local_fd,
				    remote_path, (uint64_t)st.st_size);

				if (match == 1) {
					debug("verified resume: prefix "
					    "hash match, resuming at "
					    "offset %llu",
					    (unsigned long long)
					    st.st_size);
					offset = highwater = maxack =
					    st.st_size;
				} else {
					debug("verified resume: prefix "
					    "hash %s; restarting download",
					    match == 0 ? "mismatch" :
					    "failed");
					if (ftruncate(local_fd, 0) == -1) {
						error("truncate \"%s\": %s",
						    local_path,
						    strerror(errno));
						goto resume_exit;
					}
					/* offset stays 0 */
				}
			}
			/* An empty local file, or a same-size mismatch that
			 * was truncated, downloads fresh from offset 0. */
		} else {
			/* Plain size-only resume */
			if ((uint64_t)st.st_size > size) {
				skip_ret = 2; /* target larger than source */
				goto resume_exit;
			}
			offset = highwater = maxack = st.st_size;
		}
		goto resume_done;
 resume_exit:
		resume_check_meter_end(conn);
		sftp_close(conn, handle, handle_len);
		free(handle);
		/* HPN: an identical or repaired file still gets -p and -f. */
		if (skip_ret == 0 || skip_ret == 1)
			sftp_hpn_download_finish_local(local_fd, local_path,
			    mode, a, preserve_flag, fsync_flag, skip_ret == 0);
		if (local_fd != -1)
			close(local_fd);
		/* HPN: count a file settled without a transfer meter. A
		 * chunked refetch counted its file itself. */
		if (skip_ret >= 0 && !chunked_metered)
			hpn_pm_count_file();
		return skip_ret;
 resume_done:
		resume_check_meter_end(conn);
	}

	/* Read from remote and write to local */
	write_error = read_error = write_errno = num_req = 0;
	max_req = 1;
	progress_counter = offset;

	if (showprogress && size != 0) {
		hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_FILE,
		    HPN_METER_DOM_TRANSFER,
		    progress_meter_path(remote_path), size,
		    &progress_counter, 1);
	}

	while (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;
		double t_data_start;

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
		/* HPN: time the wait for a DATA reply, as do_upload_body
		 * times its STATUS replies. A wait past the threshold means
		 * the server is slow to send, from TCP backpressure or busy
		 * server I/O, so the read-ahead controller halves its depth
		 * and probes again. */
		t_data_start = monotime_double();
		if (get_msg(conn, msg) != 0)
			break;
		if (monotime_double() - t_data_start > RDAHEAD_BP_THRESHOLD_SEC)
			sftp_conn_rdahead_backpressure_signal(conn);
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0) {
			/* HPN: workers download through here, so a bad reply
			 * fails the connection, not the process. The drain
			 * after the loop fails the file. */
			error_fr(r, "parse");
			sftp_conn_set_protocol_violation(conn);
			break;
		}
		debug3("Received reply T:%u I:%u R:%d", type, id, max_req);

		/* Find the request in our queue */
		if ((req = request_find(&requests, id)) == NULL) {
			/* HPN: an unknown reply id breaks this connection,
			 * not the process. A parallel worker sees the dead
			 * connection and respawns. */
			sftp_conn_die(conn, "Unexpected reply %u", id);
			read_error = 1;
			max_req = 0;
			num_req = 0;
			break;
		}

		switch (type) {
		case SSH2_FXP_STATUS:
			if ((r = sshbuf_get_u32(msg, &status)) != 0) {
				error_fr(r, "parse status");
				sftp_conn_set_protocol_violation(conn); /* HPN */
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			if (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			break;
		case SSH2_FXP_DATA:
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0) {
				error_fr(r, "parse data");
				sftp_conn_set_protocol_violation(conn); /* HPN */
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			if (len > req->len) {
				sftp_conn_die(conn,
				    "Received more data than asked for "
				    "%zu > %zu", len, req->len);
				free(data);
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			sftp_conn_bytes_wired_add(conn, (uint64_t)len);
			if (len == 0) {
				/* HPN: allow one zero-length DATA reply, and
				 * treat a second as a broken server. That fails
				 * the connection, not the process. The drain
				 * after the loop sets read_error. */
				if (seen_zerolen) {
					sftp_conn_die(conn,
					    "server sent zero data length");
					free(data);
					max_req = 0;
					num_req = 0;
					break;
				}
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
			if (!write_error)
				sftp_conn_live_account(conn, len); /* HPN */
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
					/* HPN: adaptive read-ahead window */
					max_req = sftp_conn_rdahead_window(conn,
					    len);
				}
			}
			break;
		default:
			error_f("Expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_DATA, type);
			sftp_conn_set_protocol_violation(conn);
			read_error = 1;
			/* HPN: drain the queue here, so the loop ends at its
			 * next check. That saves a get_msg round trip on a
			 * connection already known to be broken. */
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
		hpn_meter_stop(hpn_meter_serial(), conn);

	/* HPN: requests still queued here mean the loop stopped early on a
	 * broken connection, since a clean exit leaves the queue empty.
	 * Drain it, mark the connection dead, and fail this file. A parallel
	 * worker then respawns instead of ending the run. */
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
		/* HPN: status is still SSH2_FX_OK when the connection died,
		 * and the cause is already logged. Leave out fx2txt's
		 * "No error" then. */
		if (status == SSH2_FX_OK)
			error("read remote \"%s\" failed", remote_path);
		else
			error("read remote \"%s\": %s", remote_path,
			    fx2txt(status));
		if (status == SSH2_FX_PERMISSION_DENIED)
			sftp_conn_set_perm_denied(conn); /* HPN: no-retry */
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
		/* HPN: a verified resume that finds the file identical, or
		 * repairs it in chunks, returns before reaching this block,
		 * so sftp_hpn_download_finish_local copies it for that case,
		 * up to the end marker below. Keep the two in sync. */
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
	} /* HPN: end copied block for sftp_hpn_download_finish_local */
	close(local_fd);
	free(handle);

	/* HPN: park a clean download for the verify phase that runs after
	 * the command's transfers. Single and recursive downloads both pass
	 * through here. A no-op unless verify transfer is on, and skipped
	 * on worker connections, which park through the orchestrator. */
	if (status == SSH2_FX_OK)
		sftp_conn_verify_park(conn, local_path, remote_path,
		    /*local_is_target=*/1, (off_t)size);

	return status == SSH2_FX_OK ? 0 : -1;
}

/* HPN: the serial download sink's make_dir. It creates the local directory
 * writable, so the walk can fill it, and defers its real mode, and its times
 * under -p, to the end of the transfer. */
static int
serial_dl_make_dir(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, const Attrib *attrs)
{
	struct serial_dl_sink	*ctx = (struct serial_dl_sink *)sink;
	mode_t			 mode, tmpmode;

	if (ctx->print_flag && ctx->print_flag != SFTP_PROGRESS_ONLY)
		pm_mprintf("Retrieving %s\n", src);
	if (sftp_hpn_ensure_local_dir(dst, attrs, &mode, &tmpmode) != 0)
		return -1;
	sftp_hpn_dirattrs_defer_local(ctx->dirs, dst, mode, tmpmode, attrs,
	    ctx->preserve_flag);
	return 0;
}

/* HPN: the serial download sink's xfer_file. A small file joins the bundle
 * and is fetched when the bundle flushes. Any other file is downloaded now.
 * Returns -1 when the download or a flush fails. */
static int
serial_dl_xfer_file(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, Attrib *attrs)
{
	struct serial_dl_sink	*ctx = (struct serial_dl_sink *)sink;
	int			 download_result;

	if ((attrs->flags & SSH2_FILEXFER_ATTR_SIZE) &&
	    sftp_hpn_bundle_acc_eligible(ctx->bundle_acc, attrs->size)) {
		/* Add the file, and send the bundle now if that filled it. */
		if (sftp_hpn_bundle_acc_add(ctx->bundle_acc, src, dst,
		    (off_t)attrs->size)) {
			int flush_result = sftp_hpn_bundle_acc_flush(ctx->conn,
			    ctx->bundle_acc, ctx->preserve_flag,
			    ctx->print_flag, ctx->verify, ctx->fsync_flag,
			    ctx->inplace_flag);
			if (flush_result < 0) /* hard failure: stop the walk */
				ctx->flush_aborted = 1;
			if (flush_result != 0)
				return -1;
		}
		return 0;
	}

	download_result = sftp_download(ctx->conn, src, dst, attrs,
	    ctx->preserve_flag, ctx->resume_flag, ctx->fsync_flag,
	    ctx->inplace_flag, ctx->verify);
	if (download_result == -1)
		error("Download of file %s to %s failed", src, dst);
	return sftp_hpn_report_transfer(ctx->conn, download_result, src, dst,
	    (off_t)attrs->size);
}

/* HPN: the serial download sink's aborting. The walk stops on an
 * interrupt, once a bundle flush has aborted, or once the connection is
 * dead, since every later file would fail on it. */
static int
serial_dl_aborting(struct sftp_tree_dl_sink *sink)
{
	struct serial_dl_sink	*ctx = (struct serial_dl_sink *)sink;

	return interrupted || ctx->flush_aborted ||
	    sftp_conn_is_dead(ctx->conn);
}

/* HPN: the serial download sink's notice. It prints a walk notice on its
 * own line above the meter, which repaints below it on its next tick. It
 * follows the meter's own gate, so -q and batch mode print nothing. */
static void
serial_dl_notice(struct sftp_tree_dl_sink *sink, const char *text)
{
	if (showprogress)
		pm_mprintf("%s\n", text);
}

int
sftp_download_dir(struct sftp_conn *conn, const char *src, const char *dst,
    Attrib *dirattrib, int preserve_flag, int print_flag, int resume_flag,
    int verify, int fsync_flag, int follow_link_flag, int inplace_flag)
{
	char *src_canon;
	int ret;
	struct sftp_hpn_bundle_acc bundle_acc;
	struct sftp_hpn_dirattr_list dirs = { NULL, 0, 0 };
	struct serial_dl_sink sink;

	if ((src_canon = sftp_realpath(conn, src)) == NULL) {
		error("download \"%s\": path canonicalization failed", src);
		return -1;
	}

	/* HPN: one bundle accumulator serves the whole walk, so download
	 * bundles span directories, as in the parallel producer. Serial and
	 * -j runs then fetch the same bundles for the same tree. It does
	 * nothing unless the server advertises hpn-bundle-fetch,
	 * HPNUseBundle is on, and the transfer is not a resume, plain or
	 * verified. */
	sftp_hpn_bundle_acc_init(&bundle_acc, conn, resume_flag || verify,
	    /*download*/1);

	sink = (struct serial_dl_sink){
		.base = {
			.make_dir = serial_dl_make_dir,
			.xfer_file = serial_dl_xfer_file,
			.aborting = serial_dl_aborting,
			.notice = serial_dl_notice },
		.conn = conn,
		.bundle_acc = &bundle_acc,
		.dirs = &dirs,
		.preserve_flag = preserve_flag,
		.print_flag = print_flag,
		.resume_flag = resume_flag,
		.verify = verify,
		.fsync_flag = fsync_flag,
		.inplace_flag = inplace_flag };

	/* HPN: use the chunked tree walk when the server has it, else the
	 * readdir fallback. Both feed the same sink, bundle accumulator,
	 * and deferred directory attributes, so the steps below are the
	 * same for either. */
	if (sftp_conn_has_tree_walk(conn))
		ret = sftp_tree_download_consume(conn, src_canon, dst,
		    dirattrib, follow_link_flag, &sink.base);
	else
		ret = sftp_readdir_download_consume(conn, src_canon, dst, 0,
		    MAX_DIR_DEPTH, dirattrib, follow_link_flag, &sink.base);

	/* HPN: fetch the members still pending. Skip this after an
	 * interrupt, since a rerun walks again and nothing new should start
	 * on the way out. A failed flush empties the accumulator and stops
	 * the walk, so after one this does nothing. */
	if (!interrupted) {
		if (sftp_hpn_bundle_acc_flush(conn, &bundle_acc, preserve_flag,
		    print_flag, verify, fsync_flag, inplace_flag) != 0)
			ret = -1;
	}
	sftp_hpn_bundle_acc_free(&bundle_acc);

	/* HPN: apply the deferred directory attributes now that every
	 * file, the final bundle included, has landed. */
	sftp_hpn_dirattrs_apply(conn, &dirs);
	sftp_hpn_dirattrs_free(&dirs);

	free(src_canon);
	return ret;
}

/* HPN: the write loop shared by sftp_upload and the pipelined batch upload
 * (see sftp_upload_batch_send in sftp-client.h). It writes local_fd to the
 * open remote handle from resume_offset, which is 0 for a whole file. For a
 * resume the caller has already seeked local_fd there. It then truncates,
 * preserves, and fsyncs as asked. It closes neither local_fd nor the remote
 * handle. Returns 0 on success, or -1 if the file failed.
 *
 * The loop came from upstream's sftp_upload. A merge will not carry an
 * upstream change to that loop into this copy, so port such changes here
 * by hand. */
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
	Attrib trunc_attrs;
	uint32_t startid, ackid;
	uint64_t highwater = resume_offset, maxack = 0;
	struct request *ack = NULL;
	struct requests acks;
	int r, read_error = 0;

	TAILQ_INIT(&acks);

	id = conn->msg_id;
	startid = ackid = id + 1;
	data = xmalloc(conn->upload_buflen);

	offset = progress_counter = resume_offset;
	if (showprogress) {
		hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_FILE,
		    HPN_METER_DOM_TRANSFER,
		    progress_meter_path(local_path), local_size,
		    &progress_counter, 1);
	}

	/* HPN: when post-transfer verify is on and this is a whole-file
	 * upload, hash the source bytes as they are read, so the verify step
	 * need not read the source again. */
	if (conn->hpn->verify_transfer_enabled && resume_offset == 0)
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
		if (interrupted || read_error || status != SSH2_FX_OK)
			len = 0;
		else do
			len = read(local_fd, data, conn->upload_buflen);
		while ((len == -1) &&
		    (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));

		if (len == -1) {
			/* HPN: fail this file rather than the process, which
			 * may hold other workers. Stop reading and let the
			 * writes already sent drain like an EOF. */
			error("read local \"%s\": %s",
			    local_path, strerror(errno));
			read_error = 1;
			len = 0;
		}
		if (len != 0) {
			/* HPN: hash the source bytes as they are read, so the
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
			sftp_conn_bytes_wired_add(conn, (uint64_t)len);
			debug3("Sent message SSH2_FXP_WRITE I:%u O:%llu S:%u",
			    id, (unsigned long long)offset, len);
		} else if (TAILQ_FIRST(&acks) == NULL)
			break;

		if (ack == NULL) {
			/* HPN: a protocol error kills this connection, not the
			 * process. The worker sees the dead connection and
			 * respawns it. */
			sftp_conn_die(conn, "Unexpected ACK %u", id);
			break;
		}

		/* HPN adaptive read-ahead: cap outstanding writes at the
		 * controller's current depth, which never exceeds
		 * num_requests. */
		if (id == startid || len == 0 ||
		    id - ackid >= sftp_conn_rdahead_cap(conn)) {
			u_int rid;
			double t_status_start;

			sshbuf_reset(msg);
			/* HPN: time the STATUS read so the read-ahead
			 * controller can react to a wedged path. A read
			 * longer than the threshold means the pipeline is
			 * too deep for the path, so the controller halves
			 * its depth and probes again. */
			t_status_start = monotime_double();
			if (get_msg(conn, msg) != 0)
				break;
			if (monotime_double() - t_status_start >
			    RDAHEAD_BP_THRESHOLD_SEC)
				sftp_conn_rdahead_backpressure_signal(conn);
			if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
			    (r = sshbuf_get_u32(msg, &rid)) != 0) {
				/* HPN: a truncated reply fails the connection,
				 * not the process. */
				error_fr(r, "parse");
				sftp_conn_set_protocol_violation(conn);
				break;
			}

			if (type != SSH2_FXP_STATUS) {
				sftp_conn_die(conn,
				    "Expected SSH2_FXP_STATUS(%d) packet, "
				    "got %d", SSH2_FXP_STATUS, type);
				break;
			}

			if ((r = sshbuf_get_u32(msg, &status2)) != 0) {
				error_fr(r, "parse status");
				sftp_conn_set_protocol_violation(conn); /* HPN */
				break;
			}
			debug3("SSH2_FXP_STATUS %u", status2);
			if (status2 != SSH2_FX_OK)
				status = status2; /* remember errors */

			/* Find the request in our queue */
			if ((ack = request_find(&acks, rid)) == NULL) {
				sftp_conn_die(conn,
				    "Can't find request for ID %u", rid);
				break;
			}
			TAILQ_REMOVE(&acks, ack, tq);
			debug3("In write loop, ack for %u %zu bytes at %lld",
			    ack->id, ack->len, (unsigned long long)ack->offset);
			++ackid;
			progress_counter += ack->len;
			sftp_conn_live_account(conn, ack->len); /* HPN */
			/* HPN adaptive read-ahead: feed acked bytes. */
			sftp_conn_rdahead_account(conn, ack->len);
			/* HPN adaptive upload pacing: feed the ack-rate
			 * estimator (see sftp_conn_pace_ack). */
			sftp_conn_pace_ack(conn, ack->len,
			    conn->num_requests);
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
	/* HPN: a loop that broke out early leaves requests queued. */
	while ((ack = TAILQ_FIRST(&acks)) != NULL) {
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	sshbuf_free(msg);

	if (showprogress)
		hpn_meter_stop(hpn_meter_serial(), conn);
	free(data);

	if (status == SSH2_FX_OK && !interrupted && !read_error &&
	    !sftp_conn_is_dead(conn)) {
		highwater = maxack;
		/* HPN: the whole file was read cleanly, so finish the inline
		 * hash. */
		sftp_hpn_src_finish(conn->hpn);
	} else {
		/* HPN: a partial upload. Discard the hash so verify reads the
		 * source again. */
		sftp_hpn_src_dispose(conn->hpn);
	}
	/* HPN: the lost connection was reported where it failed, and every
	 * request below would fail on it too. */
	if (sftp_conn_is_dead(conn))
		return -1;
	if (status != SSH2_FX_OK) {
		error("write remote \"%s\": %s", remote_path, fx2txt(status));
		if (status == SSH2_FX_PERMISSION_DENIED)
			sftp_conn_set_perm_denied(conn); /* HPN: no-retry */
		status = SSH2_FX_FAILURE;
	} else if (read_error)
		status = SSH2_FX_FAILURE;

	if (inplace_flag || (resume && (status != SSH2_FX_OK || interrupted))) {
		debug("truncating at %llu", (unsigned long long)highwater);
		attrib_clear(&trunc_attrs);
		trunc_attrs.flags = SSH2_FILEXFER_ATTR_SIZE;
		trunc_attrs.size = highwater;
		sftp_fsetstat(conn, handle, handle_len, &trunc_attrs);
	}

	/* HPN: a resume that finds the file identical, or repairs it in
	 * chunks, returns before reaching this block, so
	 * sftp_hpn_upload_finish_remote applies the same -p and -f by path
	 * for that case, up to the end marker below. Keep the two in sync. */
	/* Override umask and utimes if asked */
	if (preserve_flag)
		sftp_fsetstat(conn, handle, handle_len, a);

	if (fsync_flag)
		(void)sftp_fsync(conn, (u_char *)(uintptr_t)handle, handle_len);
	/* HPN: end copied block for sftp_hpn_upload_finish_remote */

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
	/* HPN: how a resume settled the file without the transfer loop:
	 * 0 repaired, 1 identical, 2 target larger than source. */
	int skip_ret = 0;
	/* HPN: set when the chunked resend ran its own transfer meter,
	 * which counts the file when it stops. */
	int chunked_metered = 0;

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

	/* HPN: a verified resume stats the remote file quietly. When it exists
	 * and holds data, compare hashes of the overlap. A match resumes, or
	 * skips a file already complete. A mismatch or an error restarts from
	 * scratch and truncates the remote file, even under --inplace. A
	 * server without hpn-check-file cannot verify, and the caller asked
	 * for verification, so that is fatal rather than a quiet fallback. */
	if (verify) {
		int chunked, match;

		debug3_f("verify=1 inplace_flag=%d exts=0x%x HPN_CHECK_FILE=0x%x",
		    inplace_flag, conn->exts, SFTP_EXT_HPN_CHECK_FILE);
		if (!sftp_conn_has_hpn_check_file(conn)) {
			fatal("\"%s\": %s", local_path, RESUME_INCOMPAT_MSG);
		} else if (sftp_stat(conn, remote_path, 1 /* quiet */,
		    &c) == 0 && c.size > 0) {
			debug3_f("remote file exists, size=%llu local_size=%llu",
			    (unsigned long long)c.size,
			    (unsigned long long)sb.st_size);
			/* HPN: the resume-check meter counts the hashing below
			 * in work-bytes. Both ends hash the overlap. */
			resume_check_meter_begin(conn,
			    2 * MINIMUM((off_t)c.size, sb.st_size));
			if ((off_t)c.size == sb.st_size) {
				/* HPN: with sftp-hash-range, hash in chunks and
				 * resend only the chunks that differ, instead
				 * of the whole file. It declines with -1 for a
				 * small file, a server without the extension,
				 * or an internal failure. The whole-file check
				 * below then decides, which is as correct but
				 * slower on a mismatch. */
				chunked = sftp_hpn_try_chunked_resume_upload(
				    conn, local_fd, local_path, remote_path,
				    sb.st_size, (off_t)c.size /* dest clamp */);
				if (chunked >= 0) {
					if (chunked == 0 && showprogress)
						chunked_metered = 1;
					skip_ret = chunked;
					goto resume_exit;
				}

				/* HPN: equal size does not mean equal content.
				 * A range-split upload creates the remote file
				 * at full size, so a crash leaves it full size
				 * with holes of zeros. Hash the whole file on
				 * both ends and skip only when they match.
				 * Otherwise upload it again from scratch. */
				match = sftp_hpn_prefix_match(conn, local_fd,
				    remote_path, (uint64_t)sb.st_size);

				if (match == 1) {
					debug("verified transfer: full-file hash "
					    "match, \"%s\" already complete",
					    local_path);
					skip_ret = 1; /* identical */
					goto resume_exit;
				}
				debug("verified transfer: same size but hash "
				    "%s for \"%s\"; re-uploading from "
				    "scratch", match == 0 ? "mismatch" :
				    "failed", local_path);
				resume = 0;	/* fresh upload */
				effective_inplace = 0;	/* force TRUNC */
			} else if ((off_t)c.size > sb.st_size) {
				skip_ret = 2; /* target larger than source */
				goto resume_exit;
			} else {
				/* HPN: a partial remote file. Try the chunked
				 * check first, as the download side does. A
				 * range-split partial grows to its highest write
				 * and can hold holes below that size, which a
				 * prefix resume would append past. Holes hash
				 * differently and are resent, and chunks past
				 * the remote end are sent without hashing. A
				 * decline falls through to the prefix resume,
				 * for sequential partials and files under the
				 * chunk threshold. */
				chunked = sftp_hpn_try_chunked_resume_upload(
				    conn, local_fd, local_path, remote_path,
				    sb.st_size, (off_t)c.size /* dest clamp */);
				if (chunked >= 0) {
					if (chunked == 0 && showprogress)
						chunked_metered = 1;
					skip_ret = chunked;
					goto resume_exit;
				}
				/* HPN: hash the overlapping prefix to choose
				 * between appending and restarting. */
				match = sftp_hpn_prefix_match(conn, local_fd,
				    remote_path, c.size);

				if (match == 1) {
					debug("verified resume: prefix hash "
					    "match, resuming at offset %llu",
					    (unsigned long long)c.size);
					resume = 1;
				} else {
					debug("verified resume: prefix hash "
					    "%s; restarting upload",
					    match == 0 ? "mismatch" : "failed");
					resume = 0;	/* force fresh upload */
					effective_inplace = 0;	/* force TRUNC */
				}
			}
			/* The mismatch and prefix paths meet here. */
			resume_check_meter_end(conn);
		} else {
			debug3_f("remote file absent or empty; fresh upload");
		}
		/* resume is still 0 for a missing or empty remote file or a
		 * hash mismatch, which upload fresh. */
	}
	debug3_f("after verify: resume=%d effective_inplace=%d",
	    resume, effective_inplace);

	/* HPN: a plain size-only resume, or a verified one that matched
	 * above. Verify already did the stat and the size checks, so skip
	 * them then. */
	if (resume) {
		if (!verify) {
			/* Get remote file size if it exists */
			if (sftp_stat(conn, remote_path, 0, &c) != 0) {
				close(local_fd);
				return -1;
			}
			if ((off_t)c.size == sb.st_size) {
				skip_ret = 1; /* identical */
				goto resume_exit;
			}
			if ((off_t)c.size > sb.st_size) {
				skip_ret = 2; /* target larger than source */
				goto resume_exit;
			}
		}
		if (lseek(local_fd, (off_t)c.size, SEEK_SET) == -1) {
			close(local_fd);
			return -1;
		}
		resume_offset = (off_t)c.size;
	}

	/* HPN: a fresh upload, or a restart after a hash mismatch, reads from
	 * offset 0. The hashing above may have left local_fd partway through
	 * the file. */
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

	/* HPN: park a clean upload for the verify phase that runs after the
	 * command's transfers. Single and recursive uploads both pass
	 * through here. A no-op unless verify transfer is on, and skipped on
	 * worker connections, which park through the orchestrator. */
	if (r == 0 && status == 0)
		sftp_conn_verify_park(conn, local_path, remote_path,
		    /*local_is_target=*/0, sb.st_size);
	else
		sftp_hpn_src_dispose(conn->hpn);	/* HPN: no park takes it */

	return (r != 0 || status != 0) ? -1 : 0;

 resume_exit:
	/* HPN: a resume settled the file without the transfer loop. An
	 * identical or repaired file still gets -p and -f. */
	resume_check_meter_end(conn);
	close(local_fd);
	if (skip_ret == 0 || skip_ret == 1)
		sftp_hpn_upload_finish_remote(conn, remote_path, &a,
		    preserve_flag, fsync_flag, skip_ret == 0);
	/* HPN: a chunked resend counted its file itself. */
	if (!chunked_metered)
		hpn_pm_count_file();
	return skip_ret;
}

/* HPN: the serial upload sink's enter_dir. It prints "Entering src" as
 * upstream's upload walk does. dst, depth and created are for the
 * parallel sink. */
static void
serial_ul_enter_dir(struct sftp_upload_sink *sink, const char *src,
    const char *dst, int depth, int created)
{
	struct serial_ul_sink	*ctx = (struct serial_ul_sink *)sink;

	if (ctx->print_flag && ctx->print_flag != SFTP_PROGRESS_ONLY)
		pm_mprintf("Entering %s\n", src);
}

/* HPN: the serial upload sink's xfer_file. A small file joins the bundle
 * and is sent when the bundle flushes. Any other file is uploaded now.
 * Returns -1 when the upload or a flush fails. */
static int
serial_ul_xfer_file(struct sftp_upload_sink *sink, const char *src,
    const char *dst, const struct stat *src_sb)
{
	struct serial_ul_sink	*ctx = (struct serial_ul_sink *)sink;
	int			 upload_result;

	if (sftp_hpn_bundle_acc_eligible(ctx->bundle_acc,
	    (uint64_t)src_sb->st_size)) {
		/* Add the file, and send the bundle now if that filled it. */
		if (sftp_hpn_bundle_acc_add(ctx->bundle_acc, src, dst,
		    src_sb->st_size)) {
			int flush_result = sftp_hpn_bundle_acc_flush(ctx->conn,
			    ctx->bundle_acc, ctx->preserve_flag,
			    ctx->print_flag, ctx->verify, ctx->fsync_flag,
			    ctx->inplace_flag);
			if (flush_result < 0) /* hard failure: stop the walk */
				ctx->flush_aborted = 1;
			if (flush_result != 0)
				return -1;
		}
		return 0;
	}
	upload_result = sftp_upload(ctx->conn, src, dst, ctx->preserve_flag,
	    ctx->resume, ctx->verify, ctx->fsync_flag, ctx->inplace_flag);
	if (upload_result == -1)
		error("upload \"%s\" to \"%s\" failed", src, dst);
	return sftp_hpn_report_transfer(ctx->conn, upload_result, src, dst,
	    src_sb->st_size);
}

/* HPN: the serial upload sink's defer_dir. It queues the directory's final
 * remote attrs for the end of the transfer. */
static void
serial_ul_defer_dir(struct sftp_upload_sink *sink, const char *dst,
    const Attrib *attrs)
{
	struct serial_ul_sink	*ctx = (struct serial_ul_sink *)sink;

	sftp_hpn_dirattrs_defer_remote(ctx->dirs, dst, attrs);
}

/* HPN: the serial upload sink's aborting. The walk stops on an interrupt,
 * once a bundle flush has aborted, or once the connection is dead, since
 * every later file would fail on it. */
static int
serial_ul_aborting(struct sftp_upload_sink *sink)
{
	struct serial_ul_sink	*ctx = (struct serial_ul_sink *)sink;

	return interrupted || ctx->flush_aborted ||
	    sftp_conn_is_dead(ctx->conn);
}

int
sftp_upload_dir(struct sftp_conn *conn, const char *src, const char *dst,
    int preserve_flag, int print_flag, int resume, int verify,
    int fsync_flag, int follow_link_flag, int inplace_flag)
{
	char *dst_canon;
	int ret;
	int root_created;
	struct stat sb;
	Attrib root_attrs;
	struct sftp_hpn_bundle_acc bundle_acc;
	struct sftp_hpn_dirattr_list dirs = { NULL, 0, 0 };
	struct serial_ul_sink sink;

	if ((dst_canon = sftp_realpath(conn, dst)) == NULL) {
		error("upload \"%s\": path canonicalization failed", dst);
		return -1;
	}

	/* HPN: create the destination root first. The walk expects its dst
	 * to exist, and creates each deeper directory in its parent's
	 * pipelined mkdir batch. */
	if (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		free(dst_canon);
		return -1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		free(dst_canon);
		return -1;
	}
	sftp_hpn_dir_attrs_from_stat(&sb, preserve_flag, &root_attrs);
	if (sftp_hpn_ensure_remote_dir(conn, dst_canon, &root_attrs,
	    &root_created) != 0) {
		free(dst_canon);
		return -1;
	}

	/* HPN: one bundle accumulator serves the whole walk, so upload
	 * bundles span directories, as in the parallel producer. Serial and
	 * -j runs then send the same bundles for the same tree. It does
	 * nothing unless the server supports bundles, HPNUseBundle is on,
	 * and the transfer is not a resume, plain or verified. scp asks for
	 * its -Z upload resume through verify alone. */
	sftp_hpn_bundle_acc_init(&bundle_acc, conn, resume || verify,
	    /*download*/0);

	sink = (struct serial_ul_sink){
		.base = {
			.enter_dir = serial_ul_enter_dir,
			.xfer_file = serial_ul_xfer_file,
			.defer_dir = serial_ul_defer_dir,
			.aborting = serial_ul_aborting },
		.conn = conn,
		.bundle_acc = &bundle_acc,
		.dirs = &dirs,
		.preserve_flag = preserve_flag,
		.print_flag = print_flag,
		.resume = resume,
		.verify = verify,
		.fsync_flag = fsync_flag,
		.inplace_flag = inplace_flag };
	ret = sftp_upload_walk_consume(conn, src, dst_canon, 0, MAX_DIR_DEPTH,
	    root_created, preserve_flag, follow_link_flag, &sink.base);

	/* HPN: send the members still pending. Skip this after an
	 * interrupt, since a rerun walks again and nothing new should start
	 * on the way out. A failed flush empties the accumulator and stops
	 * the walk, so after one this does nothing. */
	if (!interrupted) {
		if (sftp_hpn_bundle_acc_flush(conn, &bundle_acc, preserve_flag,
		    print_flag, verify, fsync_flag, inplace_flag) != 0)
			ret = -1;
	}
	sftp_hpn_bundle_acc_free(&bundle_acc);

	/* HPN: apply the deferred directory attributes now that every
	 * file, the final bundle included, has landed. */
	sftp_hpn_dirattrs_apply(conn, &dirs);
	sftp_hpn_dirattrs_free(&dirs);

	free(dst_canon);
	return ret;
}

/* HPN: ask the server, through hpn-fs-info, which filesystem holds path
 * and how it is striped, for range alignment and Lustre layouts. Fills
 * info and returns 0. Returns -1 with info zeroed when the server lacks the
 * extension or rejects the request, or the connection fails. */
int
sftp_fs_info(struct sftp_conn *conn, const char *path,
    struct sftp_fs_info *info)
{
	struct sshbuf *msg;
	u_char type;
	u_int id, msg_id;
	char *fs_type = NULL;
	int r;

	/* Zero it first, so every failure leaves it empty. */
	memset(info, 0, sizeof(*info));

	if (!sftp_conn_has_fs_info(conn))
		return -1;

	debug2("Sending SSH2_FXP_EXTENDED(%s) \"%s\"", HPN_EXT_FS_INFO, path);
	id = conn->msg_id++;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_FS_INFO)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);
	sshbuf_free(msg);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (get_msg(conn, msg) != 0) {
		debug_f("no reply (connection dead)");
		sshbuf_free(msg);
		return -1;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &msg_id)) != 0) {
		error_fr(r, "parse");
		sftp_conn_set_protocol_violation(conn);
		sshbuf_free(msg);
		return -1;
	}
	if (msg_id != id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    msg_id, id);
		sftp_conn_set_protocol_violation(conn);
		sshbuf_free(msg);
		return -1;
	}
	/* A STATUS here means the server rejected the request. */
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		debug_f("expected SSH2_FXP_EXTENDED_REPLY, got %u", type);
		sshbuf_free(msg);
		return -1;
	}
	if ((r = sshbuf_get_cstring(msg, &fs_type, NULL)) != 0 ||
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

/* HPN: create remote_path if it is absent, without truncating an existing
 * file or setting its size. The range-split transfers call it just before
 * the first write, so the file appears only once data is about to flow and
 * then grows with the data written. An interrupted transfer leaves an honest
 * size, and verified resume handles the short file. Sets *permanent_out
 * when retrying cannot help, which means a permission denial. */
int
sftp_create_file(struct sftp_conn *conn, const char *remote_path, mode_t mode,
    int *permanent_out)
{
	u_char *handle = NULL;
	size_t handle_len;
	Attrib a;

	if (permanent_out != NULL)
		*permanent_out = 0;
	attrib_clear(&a);
	a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
	a.perm = mode & 07777;
	if (send_open(conn, remote_path, "lazy-create",
	    SSH2_FXF_WRITE | SSH2_FXF_CREAT, &a, &handle, &handle_len) != 0) {
		/* send_open has logged the error. A failure that leaves the
		 * connection alive came from the server's own STATUS reply,
		 * so last_status is this open's. A permission denial is
		 * permanent, and the unit gives up rather than retrying. */
		if (permanent_out != NULL && !sftp_conn_is_dead(conn) &&
		    conn->hpn->last_status == SSH2_FX_PERMISSION_DENIED)
			*permanent_out = 1;
		return -1;
	}
	/* The file exists now, and a failed close does not change that. */
	(void)sftp_close(conn, handle, handle_len);
	free(handle);
	return 0;
}

/* HPN: upload one byte range of a local file into the same range of the
 * remote file. The contract is at the prototype in sftp-client.h. */
int
sftp_upload_range(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t range_offset, off_t range_length,
    off_t *acked_out, struct sftp_range_warm *warm, uint64_t *range_hash_out)
{
	struct sshbuf *msg;
	struct requests acks;
	struct request *ack;
	u_char *handle = NULL, *data = NULL, type;
	size_t handle_len;
	u_int id, rid, outstanding = 0;
	uint32_t status = SSH2_FX_OK;
	off_t offset = range_offset, bytes_left = range_length;
	off_t first_fail_off = -1;
	int local_fd = -1, ret = -1, r, yielded = 0, teed = 0, read_failed = 0;

	if (acked_out != NULL)
		*acked_out = 0;
	TAILQ_INIT(&acks);

	/* submit_upload_ranges only emits ranges of positive length, so
	 * anything else is a malformed unit. Fail it, rather than skip the
	 * send loop and report a transfer that never happened. */
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
	/* Reuse the warm handle when the previous range was this same file.
	 * That skips the close and reopen, and the slow start after them. The
	 * caller closes a stale handle when the file changes, and the path
	 * check here opens fresh if it ever does not. Otherwise open without
	 * O_CREAT or O_TRUNC, because the file already exists. */
	if (warm != NULL && warm->handle != NULL &&
	    warm->path != NULL && strcmp(warm->path, remote_path) == 0) {
		handle = warm->handle;
		handle_len = warm->handle_len;
	} else if (send_open(conn, remote_path, "range-dest",
	    SSH2_FXF_WRITE, NULL, &handle, &handle_len) != 0)
		goto out;

	data = xmalloc(conn->upload_buflen);
	id = conn->msg_id;
	offset = range_offset;
	bytes_left = range_length;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* With verify on, hash the source bytes as they are read, so the
	 * verify step can use the hash instead of reading the source again.
	 * The caller asks for it with range_hash_out. A range that does not
	 * finish in one clean pass, through a yield, failure, or retry, acks
	 * less than range_length, and the caller then reads just that range
	 * again at verify time. */
	if (range_hash_out != NULL) {
		sftp_hpn_src_arm(conn->hpn);
		teed = 1;
	}

	for (;;) {
		int len = 0;

		/* A yield stops new writes. The drain below still collects
		 * every write already sent, so the acked offset ends where
		 * the last of them ended, and the caller requeues only the
		 * rest. */
		if (!yielded && yield_requested(conn))
			yielded = 1;

		/* Send writes while there is data and room in the pipeline.
		 * The read-ahead controller sets the depth, which never
		 * exceeds num_requests. */
		while (!yielded && !read_failed && bytes_left > 0 &&
		    outstanding < sftp_conn_rdahead_cap(conn) &&
		    status == SSH2_FX_OK) {
			size_t want = conn->upload_buflen;
			if ((off_t)want > bytes_left)
				want = (size_t)bytes_left;
			do
				len = read(local_fd, data, want);
			while (len == -1 &&
			    (errno == EINTR || errno == EAGAIN ||
			     errno == EWOULDBLOCK));
			if (len <= 0) {
				/* A read failure or early EOF inside the range
				 * means the source changed or is unreadable.
				 * Stop reading. The writes already sent drain,
				 * and the check after the loop fails the range
				 * for retry. */
				error("read local \"%s\" at offset %lld: "
				    "len=%d errno=%s (range [%lld+%lld), "
				    "%lld left)", local_path,
				    (long long)offset, len,
				    len < 0 ? strerror(errno) : "EOF",
				    (long long)range_offset,
				    (long long)range_length,
				    (long long)bytes_left);
				read_failed = 1;
				break;
			}

			/* Hash the bytes as read, so the verify hash
			 * reflects the source. */
			if (teed)
				sftp_hpn_src_feed(conn->hpn, data, (size_t)len);

			ack = request_enqueue(&acks, ++id, (size_t)len,
			    (uint64_t)offset);
			outstanding++;

			sshbuf_reset(msg);
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, ack->id)) != 0 ||
			    (r = sshbuf_put_string(msg, handle,
			    handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, (uint64_t)offset)) != 0 ||
			    (r = sshbuf_put_string(msg, data, (size_t)len)) != 0)
				fatal_fr(r, "compose write");
			send_msg(conn, msg);
			sftp_conn_bytes_wired_add(conn, (uint64_t)len);

			offset    += len;
			bytes_left -= len;
		}

		/* Drain one ACK per iteration. */
		if (TAILQ_EMPTY(&acks))
			break;
		sshbuf_reset(msg);
		/* Time the STATUS read so the read-ahead controller can react
		 * to a wedged path, as in do_upload_body. A dead connection
		 * fails here. */
		{
			double t_status_start = monotime_double();
			if (get_msg(conn, msg) != 0) {
				status = SSH2_FX_FAILURE;
				break;
			}
			if (monotime_double() - t_status_start >
			    RDAHEAD_BP_THRESHOLD_SEC)
				sftp_conn_rdahead_backpressure_signal(conn);
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			/* A truncated reply fails the connection, not the
			 * process, which runs the other workers. */
			error_fr(r, "parse status");
			sftp_conn_set_protocol_violation(conn);
			status = SSH2_FX_FAILURE;
			break;
		}
		if (type != SSH2_FXP_STATUS) {
			sftp_conn_die(conn,
			    "expected SSH2_FXP_STATUS(%u), got %u",
			    SSH2_FXP_STATUS, type);
			status = SSH2_FX_FAILURE;
			break;
		}
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse status code");
			sftp_conn_set_protocol_violation(conn);
			status = SSH2_FX_FAILURE;
			break;
		}
		/* Match the reply to its write by id, like do_upload_body. */
		if ((ack = request_find(&acks, rid)) == NULL) {
			sftp_conn_die(conn, "unexpected reply id %u", rid);
			status = SSH2_FX_FAILURE;
			break;
		}
		if (status != SSH2_FX_OK) {
			error("write remote \"%s\" at offset %llu: %s",
			    remote_path, (unsigned long long)ack->offset,
			    fx2txt(status));
			if (status == SSH2_FX_PERMISSION_DENIED)
				sftp_conn_set_perm_denied(conn); /* HPN: no-retry */
			/* The loop keeps draining after a failed write, and
			 * later successes would move the head of the list
			 * past the hole. Contiguous progress ends at the
			 * lowest failed offset. */
			if (first_fail_off < 0 ||
			    (off_t)ack->offset < first_fail_off)
				first_fail_off = (off_t)ack->offset;
		} else {
			/* HPN adaptive read-ahead: feed acked bytes. */
			sftp_conn_rdahead_account(conn, ack->len);
			/* HPN adaptive upload pacing: feed the ack-rate
			 * estimator (see sftp_conn_pace_ack). */
			sftp_conn_pace_ack(conn, ack->len,
			    conn->num_requests);
			/* Report progress per ack, so the orchestrator's
			 * rate window sees a steady stream rather than a
			 * step when the range completes. */
			sftp_conn_live_account(conn, ack->len);
		}
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
		outstanding--;
	}
	sshbuf_free(msg);

	/* This check runs before the close decision, so status is final. A
	 * range that did not send every byte is not a success, whatever the
	 * status says. Finishing a short range as complete would lose data,
	 * so fail it and let the caller's retry send the rest. A yield takes
	 * this path on purpose, and quietly. The caller sees the failure and
	 * requeues the remainder as a voluntary handoff. */
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

	/* Keep the handle open for the next range of the same file only
	 * after a clean success. A failed, yielded, or wedged handle is never
	 * reused, so close it. When it stays open, *warm owns it, and handle
	 * is cleared so the free at out leaves it alone. */
	if (status == SSH2_FX_OK && warm != NULL) {
		if (warm->handle != handle) {
			/* Opened by this call, so *warm takes it over. A
			 * handle left there for another path is closed
			 * first, rather than leaked. */
			if (warm->handle != NULL) {
				(void)sftp_close(conn, warm->handle,
				    warm->handle_len);
				free(warm->handle);
			}
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
	/* HPN: the contiguous acked offset, so a requeue resumes there. The
	 * list of outstanding writes stays in offset order, so everything
	 * below its head is acknowledged, and with the list empty everything
	 * sent is. A failed write ends contiguity at its offset. On success
	 * the caller does not need it. On failure the worker requeues only
	 * [range_offset + acked, end). */
	if (acked_out != NULL) {
		off_t acked_end = TAILQ_EMPTY(&acks) ?
		    offset : (off_t)TAILQ_FIRST(&acks)->offset;

		if (first_fail_off >= 0 && first_fail_off < acked_end)
			acked_end = first_fail_off;
		if (acked_end > range_offset)
			*acked_out = acked_end - range_offset;
	}
	while ((ack = TAILQ_FIRST(&acks)) != NULL) {
		TAILQ_REMOVE(&acks, ack, tq);
		free(ack);
	}
	/* Finish the hash. src_take writes *range_hash_out only when the
	 * hashed byte count equals range_length, and the caller also checks
	 * that the whole range was acked before trusting it. */
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

/* HPN: give up on every read still outstanding in sftp_download_range and
 * free them. Their data never arrived, so contiguous progress ends at the
 * lowest of their offsets, or at next_off when none is left. *contig_end
 * is lowered to that, where -1 means nothing has bounded it yet. */
static void
dl_abandon_requests(struct requests *requests, uint64_t next_off,
    off_t *contig_end)
{
	struct request *req;
	off_t lowest = (off_t)next_off;

	while ((req = TAILQ_FIRST(requests)) != NULL) {
		if ((off_t)req->offset < lowest)
			lowest = (off_t)req->offset;
		TAILQ_REMOVE(requests, req, tq);
		free(req);
	}
	if (*contig_end < 0 || lowest < *contig_end)
		*contig_end = lowest;
}

/* HPN: download one byte range of a remote file into the same range of the
 * local file. The contract is at the prototype in sftp-client.h. */
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
	double t_data_start;
	int local_fd = -1, read_error = 0, write_error = 0, write_errno = 0;
	int ret = -1, r, yielded = 0, seen_zerolen = 0;
	/* HPN: where contiguous progress stops, the lowest offset any failure
	 * bounded it at. -1 until one does. */
	off_t contig_end = -1;

	if (acked_out != NULL)
		*acked_out = 0;
	TAILQ_INIT(&requests);

	/* submit_download_ranges only emits ranges of positive length, so
	 * anything else is a malformed unit. Fail it, as sftp_upload_range
	 * does, rather than succeed on an empty loop. */
	if (range_length <= 0) {
		error_f("refusing download range of non-positive length %lld "
		    "for \"%s\"", (long long)range_length, remote_path);
		return -1;
	}

	/* Open remote file for reading. */
	if (send_open(conn, remote_path, "range-src",
	    SSH2_FXF_READ, NULL, &handle, &handle_len) != 0)
		return -1;

	/* Open the local file for writing, without O_CREAT or O_TRUNC,
	 * because the orchestrator created it at the right size. */
	if ((local_fd = open(local_path, O_WRONLY)) < 0) {
		error("open local \"%s\": %s", local_path, strerror(errno));
		sftp_close(conn, handle, handle_len);
		goto out;
	}

	buflen = conn->download_buflen;
	num_req = 0;
	/* Start with one read. The read-ahead controller widens the window
	 * as replies arrive. */
	max_req = 1;
	remote_offset = (uint64_t)range_offset;
	bytes_left = range_length;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	while (num_req > 0 || (bytes_left > 0 && max_req > 0)) {
		/* A yield stops new reads. The reads already in flight still
		 * drain, since those bytes were the costliest to get on a
		 * slow stream. The loop then exits with remote_offset at the
		 * end of the last read issued, which is the acked offset the
		 * code below reports. */
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
		/* Time the DATA read so the read-ahead controller can react
		 * to a wedged path, as sftp_upload_range does for its STATUS
		 * reads. */
		t_data_start = monotime_double();
		if (get_msg(conn, msg) != 0) {
			read_error = 1;
			dl_abandon_requests(&requests, remote_offset,
			    &contig_end);
			num_req = max_req = 0;
			break;
		}
		if (monotime_double() - t_data_start > RDAHEAD_BP_THRESHOLD_SEC)
			sftp_conn_rdahead_backpressure_signal(conn);
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0) {
			/* A truncated reply fails the connection, not the
			 * process, as a lost connection does above. */
			error_fr(r, "parse");
			sftp_conn_set_protocol_violation(conn);
			read_error = 1;
			dl_abandon_requests(&requests, remote_offset,
			    &contig_end);
			num_req = max_req = 0;
			break;
		}
		if ((req = request_find(&requests, id)) == NULL) {
			/* This runs in a worker, where fatal would kill the
			 * orchestrator. Mark the connection dead, and the
			 * check after the loop fails the range, as
			 * sftp_download does. */
			sftp_conn_die(conn, "unexpected reply id %u", id);
			read_error = 1;
			num_req = max_req = 0;
			break;
		}

		switch (type) {
		case SSH2_FXP_STATUS:
			/* Any STATUS reply to a read fails the range. The
			 * range lies inside the file, so even EOF means the
			 * file shrank. */
			if ((r = sshbuf_get_u32(msg, &status)) != 0) {
				/* Fail the range below, as a bad message. */
				error_fr(r, "parse status");
				sftp_conn_set_protocol_violation(conn);
				status = SSH2_FX_BAD_MESSAGE;
			}
			if (status == SSH2_FX_EOF)
				error("read remote \"%s\": unexpected EOF "
				    "within range", remote_path);
			else
				error("read remote \"%s\": %s",
				    remote_path, fx2txt(status));
			if (status == SSH2_FX_PERMISSION_DENIED)
				sftp_conn_set_perm_denied(conn); /* HPN: no-retry */
			read_error = 1;
			/* The failed read is still in the list, so its own
			 * offset bounds contiguity too. */
			dl_abandon_requests(&requests, remote_offset,
			    &contig_end);
			num_req = max_req = 0;
			break;
		case SSH2_FXP_DATA: {
			u_char *data;
			size_t len;
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0) {
				error_fr(r, "parse data");
				sftp_conn_set_protocol_violation(conn);
				read_error = 1;
				num_req = max_req = 0;
				break;
			}
			if (len > req->len) {
				/* The same worker hazard as the unexpected
				 * reply id above. Fail the range. */
				sftp_conn_die(conn, "received more data than "
				    "requested %zu > %zu", len, req->len);
				free(data);
				read_error = 1;
				num_req = max_req = 0;
				break;
			}
			if (len == 0) {
				/* The same livelock guard as sftp_download. A
				 * second zero-length DATA reply means a broken
				 * server. */
				if (seen_zerolen) {
					sftp_conn_die(conn,
					    "server sent zero data length");
					free(data);
					read_error = 1;
					num_req = max_req = 0;
					break;
				}
				seen_zerolen = 1;
			}
			sftp_conn_bytes_wired_add(conn, (uint64_t)len);
			/* Later replies are still written after a write error,
			 * as in sftp_download, but only the first error is kept
			 * and nothing more counts as progress. */
			if ((lseek(local_fd, (off_t)req->offset,
			    SEEK_SET) == -1 ||
			    atomicio(vwrite, local_fd, data, len) != len) &&
			    !write_error) {
				write_errno = errno;
				write_error = 1;
				max_req = 0;
				/* Data past this point may have arrived but is
				 * not on disk, so contiguity ends here. */
				if (contig_end < 0 ||
				    (off_t)req->offset < contig_end)
					contig_end = (off_t)req->offset;
			} else if (!write_error)
				sftp_conn_live_account(conn, len);
			free(data);
			if (len == req->len) {
				TAILQ_REMOVE(&requests, req, tq);
				free(req);
				num_req--;
			} else {
				/* Short read. Request the rest. */
				req->id = conn->msg_id++;
				req->len -= len;
				req->offset += len;
				send_read_request(conn, req->id, req->offset,
				    (u_int)req->len, handle, handle_len);
			}
			/* HPN: a yield or a write error set max_req to 0, and
			 * it stays 0. Otherwise the read-ahead controller sets
			 * the window. */
			if (max_req > 0)
				max_req = sftp_conn_rdahead_window(conn, len);
			break;
		}
		default:
			error_f("expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption",
			    SSH2_FXP_DATA, type);
			sftp_conn_set_protocol_violation(conn);
			read_error = 1;
			dl_abandon_requests(&requests, remote_offset,
			    &contig_end);
			num_req = max_req = 0;
			break;
		}
	}
	sshbuf_free(msg);

	/* As in sftp_download, reads still queued here mean the connection
	 * was lost, not that the range finished. Fail the range, so the
	 * worker respawns instead of taking the orchestrator down. */
	if (TAILQ_FIRST(&requests) != NULL) {
		if (!sftp_conn_is_dead(conn))
			sftp_conn_die(conn, "range download of \"%s\" ended "
			    "with requests still in flight (connection lost)",
			    remote_path);
		dl_abandon_requests(&requests, remote_offset, &contig_end);
		read_error = 1;
	}

	/* HPN: the contiguous bytes received and written from the start of
	 * the range. contig_end < 0 means no failure bounded it, so
	 * everything requested landed. */
	if (acked_out != NULL) {
		off_t acked_end = (contig_end >= 0) ?
		    contig_end : (off_t)remote_offset;

		if (acked_end > range_offset)
			*acked_out = acked_end - range_offset;
	}

	/* This check mirrors sftp_upload_range's. A range that did not
	 * request and receive every byte is not a success, whatever the
	 * error flags say. Finishing a short range as complete would lose
	 * data. bytes_left counts what was never requested, and with no reads
	 * outstanding it must be zero when the range really finished. A
	 * yield takes this path on purpose, and quietly. The caller sees the
	 * failure and requeues the remainder as a voluntary handoff. */
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

/* HPN: fail every entry of the batch that is still open and has not
 * already failed, and set *any_fail. Collecting an entry's CLOSE reply
 * frees its handle, so a file that closed cleanly keeps its success. The
 * batch path calls this when collecting replies hits a dead connection or
 * a protocol error. Abandoning the batch, instead of calling fatal, keeps
 * the other parallel workers running. The worker retries each failed entry
 * through worker_finalize_one_entry, on a fresh connection when this one
 * died. */
static void
batch_fail_all_remaining(struct batch_file *files,
    struct sftp_upload_batch_entry *entries, int n, int *any_fail)
{
	int i;

	for (i = 0; i < n; i++) {
		if (files[i].handle != NULL && !files[i].failed) {
			files[i].failed = 1;
			entries[i].result = -1;
			*any_fail = 1;
		}
	}
}

/* HPN: the batch upload is split in two, so consecutive batches overlap.
 * sftp_upload_batch_send runs phases 1 to 4: it sends the OPENs, collects
 * the handles, writes the files, and sends the CLOSEs.
 * sftp_upload_batch_finish runs phase 5 and collects the CLOSE replies.
 * Given the previous batch, send puts this batch's OPENs on the wire, then
 * collects the previous batch's CLOSE replies, then this batch's handles.
 * The server works on both batches at once, which saves about one round
 * trip per batch. */

/* HPN: phase 5 of the batch upload. Collect each file's replies in send
 * order: first those to what phase 4 sent ahead of its CLOSE, then the
 * CLOSE's own. Fail each entry whose close failed. Then close the local
 * files still open and free files. sftp_upload_batch_finish is the only
 * caller. Returns -1 if any entry failed, else 0. */
static int
batch_phase5_and_cleanup(struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, struct batch_file *files,
    int n, int any_fail_in)
{
	u_int status;
	int i, k, any_fail = any_fail_in;

	debug_f("batch upload phase 5: collecting %d close replies", n);
	for (i = 0; i < n; i++) {
		/* An entry that never opened has no replies to collect. */
		if (files[i].handle == NULL)
			continue;
		/* Replies come back in send order, so the next ones must
		 * belong to entry i. get_status checks each id. The ones
		 * ahead of the CLOSE are best effort, as in sftp_upload. A
		 * failure is logged and the file's result stands. */
		for (k = 0; k < files[i].npre_close; k++) {
			status = get_status(conn, files[i].pre_close_ids[k]);
			if (status == SSH2_FX_CONNECTION_LOST)
				goto lost;
			if (status != SSH2_FX_OK)
				error("batch %s \"%s\": %s",
				    files[i].pre_close_what[k],
				    entries[i].remote_path, fx2txt(status));
		}
		status = get_status(conn, files[i].close_id);
		if (status == SSH2_FX_CONNECTION_LOST)
			goto lost;
		/* A failed close can mean the server could not flush the
		 * data, so the file is not trusted as complete. */
		if (status != SSH2_FX_OK) {
			error("batch close \"%s\": %s",
			    entries[i].remote_path, fx2txt(status));
			if (status == SSH2_FX_PERMISSION_DENIED)
				entries[i].perm_denied = 1;
			if (!files[i].failed) {
				files[i].failed = 1;
				entries[i].result = -1;
				any_fail = 1;
			}
		}
		/* This entry is settled. Its NULL handle tells
		 * batch_fail_all_remaining to leave it alone. */
		free(files[i].handle);
		files[i].handle = NULL;
	}
	goto cleanup;

 lost:
	/* get_status found the connection dead or broken, so no more
	 * replies are coming. */
	error_f("batch close: no usable reply while collecting (entry %d/%d)",
	    i, n);
	batch_fail_all_remaining(files, entries, n, &any_fail);

 cleanup:
	/* Close any local file phase 3 left open, and free the handle of any
	 * entry whose reply never came. */
	for (i = 0; i < n; i++) {
		if (files[i].local_fd >= 0)
			close(files[i].local_fd);
		free(files[i].handle);
	}
	free(files);

	return any_fail ? -1 : 0;
}

/* HPN: collect a sent batch's CLOSE replies and free it. The contract is
 * at the prototype in sftp-client.h. */
int
sftp_upload_batch_finish(struct sftp_conn *conn,
    struct sftp_upload_batch_pending *pending)
{
	int rc;

	/* send returns NULL when it sent no CLOSEs, so there is nothing to
	 * collect. */
	if (pending == NULL)
		return 0;
	rc = batch_phase5_and_cleanup(conn, pending->entries, pending->files,
	    pending->nentries, pending->any_fail);
	/* Phase 5 freed files. The entries belong to the caller. */
	free(pending);
	return rc;
}

/* HPN: send, without waiting, what a small batch file needs before its
 * CLOSE, in the order sftp_upload applies it: the in-place size, the -p
 * attrs, and the fsync. Each request is recorded so phase 5 can collect its
 * reply. The server handles requests on one handle in order, so these land
 * after the file's WRITE and before its CLOSE. */
static void
batch_send_pre_close(struct sftp_conn *conn, struct batch_file *file,
    int preserve_flag, int fsync_flag, int inplace_flag)
{
	struct sshbuf *msg = conn->msg;
	Attrib trunc_attrs;
	u_int id;
	int r;

	file->npre_close = 0;
	/* In place left any old tail of the file, so cut it to size. */
	if (inplace_flag) {
		attrib_clear(&trunc_attrs);
		trunc_attrs.flags = SSH2_FILEXFER_ATTR_SIZE;
		trunc_attrs.size = (uint64_t)file->sb.st_size;
		id = conn->msg_id++;
		send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT,
		    file->handle, file->handle_len, &trunc_attrs);
		file->pre_close_ids[file->npre_close] = id;
		file->pre_close_what[file->npre_close++] = "truncate";
	}
	if (preserve_flag) {
		id = conn->msg_id++;
		send_string_attrs_request(conn, id, SSH2_FXP_FSETSTAT,
		    file->handle, file->handle_len, &file->a);
		file->pre_close_ids[file->npre_close] = id;
		file->pre_close_what[file->npre_close++] = "setstat";
	}
	/* Like sftp_fsync, skip it when the server lacks the extension. */
	if (fsync_flag && (conn->exts & SFTP_EXT_FSYNC) != 0) {
		/* Reset for the same reason as send_string_request. */
		sshbuf_reset(msg);
		id = conn->msg_id++;
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_cstring(msg, "fsync@openssh.com")) != 0 ||
		    (r = sshbuf_put_string(msg, file->handle,
		    file->handle_len)) != 0)
			fatal_fr(r, "compose batch fsync");
		send_msg(conn, msg);
		file->pre_close_ids[file->npre_close] = id;
		file->pre_close_what[file->npre_close++] = "fsync";
	}
}

/* HPN: phases 1 to 4 of the batch upload, with the previous batch's phase
 * 5 in between. The contract is at the prototype in sftp-client.h. */
struct sftp_upload_batch_pending *
sftp_upload_batch_send(struct sftp_conn *conn,
    struct sftp_upload_batch_entry *entries, int n,
    int preserve_flag, int fsync_flag, int inplace_flag,
    struct sftp_upload_batch_pending *prev)
{
	struct sftp_upload_batch_pending *pending;
	struct batch_file *files;
	struct sshbuf *msg;
	u_int openmode = SSH2_FXF_WRITE | SSH2_FXF_CREAT;
	u_int status;
	int i, r, any_fail = 0;

	/* An empty batch sends nothing, but the previous batch still needs
	 * its replies collected. */
	if (n <= 0) {
		if (prev != NULL)
			(void)sftp_upload_batch_finish(conn, prev);
		return NULL;
	}
	/* In place keeps the existing file, as in sftp_upload, and phase 4
	 * sets its final size. */
	if (!inplace_flag)
		openmode |= SSH2_FXF_TRUNC;

	debug_f("batch upload: n=%d preserve=%d fsync=%d inplace=%d",
	    n, preserve_flag, fsync_flag, inplace_flag);

	files = xcalloc(n, sizeof(*files));
	for (i = 0; i < n; i++) {
		files[i].local_fd = -1;
		entries[i].result = 0;
		entries[i].perm_denied = 0;
	}

	/* Phase 1: open each local file and send its OPEN without waiting
	 * for the handle. All n go out in one burst. */
	debug_f("batch upload phase 1: sending %d SSH_FXP_OPEN requests", n);
	for (i = 0; i < n; i++) {
		if ((files[i].local_fd = open(entries[i].local_path,
		    O_RDONLY)) == -1) {
			error("batch open local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
			continue;
		}
		if (fstat(files[i].local_fd, &files[i].sb) == -1) {
			error("batch fstat local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			close(files[i].local_fd);
			files[i].local_fd = -1;
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
			continue;
		}
		/* The walk queues only regular files, but the path may have
		 * changed since. sftp_upload refuses the same. */
		if (!S_ISREG(files[i].sb.st_mode)) {
			error("batch local \"%s\" is not a regular file",
			    entries[i].local_path);
			close(files[i].local_fd);
			files[i].local_fd = -1;
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
			continue;
		}
		stat_to_attrib(&files[i].sb, &files[i].a);
		files[i].a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
		files[i].a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
		files[i].a.perm &= 0777;
		if (!preserve_flag)
			files[i].a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;

		files[i].open_id = conn->msg_id++;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_OPEN)) != 0 ||
		    (r = sshbuf_put_u32(msg, files[i].open_id)) != 0 ||
		    (r = sshbuf_put_cstring(msg, entries[i].remote_path)) != 0 ||
		    (r = sshbuf_put_u32(msg, openmode)) != 0 ||
		    (r = encode_attrib(msg, &files[i].a)) != 0)
			fatal_fr(r, "compose batch open");
		send_msg(conn, msg);
		sshbuf_free(msg);
	}

	/* Collect the previous batch's replies now, between this batch's
	 * OPENs and its handles. The server works on both at once, which
	 * saves about one round trip per batch. A failed drain fails the
	 * previous batch's open entries inside finish. This batch goes on,
	 * and fails on its own in phase 2 if the connection is gone. */
	if (prev != NULL) {
		(void)sftp_upload_batch_finish(conn, prev);
		prev = NULL;
	}

	/* Phase 2: collect the handles in the order the OPENs went out. One
	 * round trip covers all n. */
	debug_f("batch upload phase 2: collecting %d handles", n);
	for (i = 0; i < n; i++) {
		if (files[i].failed)
			continue; /* no open was sent for this entry */
		files[i].handle = get_handle(conn, files[i].open_id,
		    &files[i].handle_len,
		    "batch dest open \"%s\"", entries[i].remote_path);
		if (files[i].handle == NULL) {
			/* A failure that leaves the connection alive came
			 * from the server's own STATUS, so a denial is this
			 * entry's. */
			if (!sftp_conn_is_dead(conn) &&
			    conn->hpn->last_status == SSH2_FX_PERMISSION_DENIED)
				entries[i].perm_denied = 1;
			close(files[i].local_fd);
			files[i].local_fd = -1;
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
		}
	}

	/* Phase 3a: write each small file, one that fits in a single WRITE,
	 * without waiting for the replies, so n round trips become one. Large
	 * files wait for phase 3c. */
	debug_f("batch upload phase 3: transferring %d files", n);
	{
		u_char *data = xmalloc(conn->upload_buflen);

		for (i = 0; i < n; i++) {
			size_t len;

			if (files[i].failed || files[i].handle == NULL)
				continue;
			if (files[i].sb.st_size > (off_t)conn->upload_buflen)
				continue; /* a large file waits for phase 3c */
			if (files[i].sb.st_size == 0) {
				/* An empty file needs no WRITE. TRUNC emptied
				 * it, or phase 4 sets its size in place. */
				close(files[i].local_fd);
				files[i].local_fd = -1;
				continue;
			}
			/* Read the whole file. A short read means it changed
			 * since its fstat. */
			len = atomicio(read, files[i].local_fd, data,
			    (size_t)files[i].sb.st_size);
			close(files[i].local_fd);
			files[i].local_fd = -1;
			if (len != (size_t)files[i].sb.st_size) {
				error("read local \"%s\": %s",
				    entries[i].local_path, errno == EPIPE ?
				    "file shrank while being read" :
				    strerror(errno));
				files[i].failed = 1;
				entries[i].result = -1;
				any_fail = 1;
				continue;
			}
			/* The whole file is in the buffer, so hash it there
			 * for the verify phase. */
			entries[i].have_src_hash = sftp_hpn_src_hash_buf(conn->hpn,
			    data, len, &entries[i].src_hash) == 0;
			/* Phase 3b collects the reply. */
			files[i].write_id = conn->msg_id++;
			files[i].write_sent = 1;
			if ((msg = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			if ((r = sshbuf_put_u8(msg, SSH2_FXP_WRITE)) != 0 ||
			    (r = sshbuf_put_u32(msg, files[i].write_id)) != 0 ||
			    (r = sshbuf_put_string(msg, files[i].handle,
			    files[i].handle_len)) != 0 ||
			    (r = sshbuf_put_u64(msg, 0)) != 0 ||       /* offset=0 */
			    (r = sshbuf_put_string(msg, data, len)) != 0)
				fatal_fr(r, "compose batch write");
			send_msg(conn, msg);
			sftp_conn_bytes_wired_add(conn, (uint64_t)len);
			sshbuf_free(msg);
		}
		free(data);
	}

	/* Phase 3b: collect the small-file WRITE replies in send order. One
	 * round trip covers all n. A lost connection or a protocol error
	 * abandons the batch rather than calling fatal, which would take the
	 * other parallel workers down with it. */
	for (i = 0; i < n; i++) {
		if (!files[i].write_sent)
			continue; /* no write sent for this entry */
		status = get_status(conn, files[i].write_id);
		if (status == SSH2_FX_CONNECTION_LOST) {
			error_f("batch write: no usable reply while collecting "
			    "(entry %d/%d)", i, n);
			batch_fail_all_remaining(files, entries, n, &any_fail);
			goto send_failed;
		}
		if (status != SSH2_FX_OK) {
			error("write remote \"%s\": %s",
			    entries[i].remote_path, fx2txt(status));
			if (status == SSH2_FX_PERMISSION_DENIED)
				entries[i].perm_denied = 1;
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
		} else
			sftp_conn_live_account(conn,
			    files[i].sb.st_size); /* HPN */
	}

	/* Phase 3c: upload each large file in turn through do_upload_body,
	 * which applies its own in-place size, -p attrs and fsync. */
	for (i = 0; i < n; i++) {
		if (files[i].failed || files[i].handle == NULL)
			continue;
		if (files[i].sb.st_size <= (off_t)conn->upload_buflen)
			continue; /* a small file went in phase 3a */
		debug_f("batch upload large file %d/%d: %s -> %s (%lld bytes)",
		    i + 1, n, entries[i].local_path, entries[i].remote_path,
		    (long long)files[i].sb.st_size);
		/* Scope the connection's denial flag to this one file. */
		sftp_conn_clear_perm_denied(conn);
		r = do_upload_body(conn, files[i].local_fd, files[i].sb.st_size,
		    files[i].handle, files[i].handle_len, &files[i].a,
		    entries[i].local_path, entries[i].remote_path,
		    preserve_flag, fsync_flag, inplace_flag,
		    /*resume=*/0, /*resume_offset=*/0);
		/* Take the teed source hash for the verify phase. */
		entries[i].have_src_hash = sftp_hpn_src_take(conn->hpn,
		    (uint64_t)files[i].sb.st_size, &entries[i].src_hash) == 0;
		if (close(files[i].local_fd) == -1) {
			error("batch close local \"%s\": %s",
			    entries[i].local_path, strerror(errno));
			r = -1;
		}
		files[i].local_fd = -1;
		if (r != 0) {
			if (sftp_conn_saw_perm_denied(conn))
				entries[i].perm_denied = 1;
			files[i].failed = 1;
			entries[i].result = -1;
			any_fail = 1;
		}
	}

	/* Phase 4: send every CLOSE in one burst. Each small file that wrote
	 * cleanly gets its in-place size, -p attrs and fsync just ahead of its
	 * CLOSE, in the same burst. */
	debug_f("batch upload phase 4: sending %d SSH_FXP_CLOSE requests", n);
	for (i = 0; i < n; i++) {
		if (files[i].handle == NULL)
			continue;
		if (!files[i].failed &&
		    files[i].sb.st_size <= (off_t)conn->upload_buflen)
			batch_send_pre_close(conn, &files[i], preserve_flag,
			    fsync_flag, inplace_flag);
		files[i].close_id = conn->msg_id++;
		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new failed");
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_CLOSE)) != 0 ||
		    (r = sshbuf_put_u32(msg, files[i].close_id)) != 0 ||
		    (r = sshbuf_put_string(msg, files[i].handle,
		    files[i].handle_len)) != 0)
			fatal_fr(r, "compose batch close");
		send_msg(conn, msg);
		sshbuf_free(msg);
	}

	/* Phase 5 waits for sftp_upload_batch_finish, so the caller can send
	 * the next batch's OPENs first. */
	pending = xcalloc(1, sizeof(*pending));
	pending->entries  = entries;
	pending->files    = files;
	pending->nentries = n;
	pending->any_fail = any_fail;
	return pending;

 send_failed:
	/* Phase 3b failed before any CLOSE went out, so there is nothing for
	 * finish to collect. Free the batch and return NULL. */
	for (i = 0; i < n; i++) {
		if (files[i].local_fd >= 0)
			close(files[i].local_fd);
		free(files[i].handle);
	}
	free(files);
	return NULL;
}

/* HPN: accessors for the HPN modules, which cannot see struct sftp_conn.
 * sftp-client-internal.h declares them. */

/* HPN: the next outbound message id for conn. */
u_int
sftp_conn_alloc_msg_id(struct sftp_conn *conn)
{
	return conn->msg_id++;
}

/* HPN: the HPN state hung off conn, or NULL for a NULL conn. HPN modules
 * work on it directly, so no per-field accessor has to live in this file. */
struct sftp_hpn_conn *
sftp_conn_hpn(struct sftp_conn *conn)
{
	return conn == NULL ? NULL : conn->hpn;
}

/* HPN: the extensions the server advertised, or 0 for a NULL conn, so the
 * has_*() predicates can live in sftp-hpn-client.c. */
u_int
sftp_conn_exts(struct sftp_conn *conn)
{
	return conn == NULL ? 0 : conn->exts;
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
		if (get_msg(to, msg) != 0)	/* HPN: the connection is gone */
			goto lost;

		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0) {
			error_fr(r, "dest parse");	/* HPN */
			goto violation;
		}
		debug3("Received dest reply T:%u I:%u R:%u", type, id, *nreqsp);
		if (type != SSH2_FXP_STATUS) {
			error_f("Expected SSH2_FXP_STATUS(%d) packet, got %d - "
			    "possible protocol corruption", SSH2_FXP_STATUS, type);
			goto violation;
		}
		if ((r = sshbuf_get_u32(msg, &status)) != 0) {
			error_fr(r, "parse dest status");	/* HPN */
			goto violation;
		}
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
	return;

 violation:
	/* HPN: a malformed reply breaks this connection, not the process. */
	sftp_conn_set_protocol_violation(to);
 lost:
	/* HPN: the replies still outstanding stay counted in *nreqsp, so a
	 * caller must check *write_errorp, not *nreqsp == 0, to know every
	 * write was acked. */
	if (*write_errorp == 0)
		*write_errorp = SSH2_FX_CONNECTION_LOST;
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
		hpn_meter_start(hpn_meter_serial(), from, HPN_METER_FILE,
		    HPN_METER_DOM_TRANSFER,
		    progress_meter_path(from_path), size,
		    &progress_counter, 1);
	}
	while (num_req > 0 || max_req > 0) {
		u_char *data;
		size_t len;
		double t_data_start;

		/*
		 * Simulate EOF on interrupt: stop sending new requests and
		 * allow outstanding requests to drain gracefully
		 */
		if (interrupted || sftp_conn_is_dead(to)) { /* HPN */
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
		/* HPN: time the wait for a DATA reply, as sftp_download does.
		 * The signal goes to from, since a slow reply means the read
		 * side is wedged. */
		t_data_start = monotime_double();
		if (get_msg(from, msg) != 0)
			break;
		if (monotime_double() - t_data_start > RDAHEAD_BP_THRESHOLD_SEC)
			sftp_conn_rdahead_backpressure_signal(from);
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &id)) != 0) {
			/* HPN: a bad reply fails the connection, not the
			 * process. The drain after the loop fails the file. */
			error_fr(r, "parse");
			sftp_conn_set_protocol_violation(from);
			break;
		}
		debug3("Received origin reply T:%u I:%u R:%d",
		    type, id, max_req);

		/* Find the request in our queue */
		if ((req = request_find(&requests, id)) == NULL) {
			sftp_conn_die(from, "Unexpected reply %u", id);
			read_error = 1;
			max_req = 0;
			num_req = 0;
			break;
		}

		switch (type) {
		case SSH2_FXP_STATUS:
			if ((r = sshbuf_get_u32(msg, &status)) != 0) {
				error_fr(r, "parse status");
				sftp_conn_set_protocol_violation(from); /* HPN */
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			if (status != SSH2_FX_EOF)
				read_error = 1;
			max_req = 0;
			TAILQ_REMOVE(&requests, req, tq);
			free(req);
			num_req--;
			break;
		case SSH2_FXP_DATA:
			if ((r = sshbuf_get_string(msg, &data, &len)) != 0) {
				error_fr(r, "parse data");
				sftp_conn_set_protocol_violation(from); /* HPN */
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			debug3("Received data %llu -> %llu",
			    (unsigned long long)req->offset,
			    (unsigned long long)req->offset + len - 1);
			if (len > req->len) {
				sftp_conn_die(from,	/* HPN */
				    "Received more data than asked for "
				    "%zu > %zu", len, req->len);
				free(data);
				read_error = 1;
				max_req = 0;
				num_req = 0;
				break;
			}
			sftp_conn_bytes_wired_add(from, (uint64_t)len);
			if (len == 0) {
				/* HPN: allow one zero-length DATA reply, and
				 * treat a second as a broken server. That fails
				 * the connection, not the process. The drain
				 * after the loop sets read_error. */
				if (seen_zerolen) {
					sftp_conn_die(from,
					    "server sent zero data length");
					free(data);
					max_req = 0;
					num_req = 0;
					break;
				}
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
			sftp_conn_bytes_wired_add(to, (uint64_t)len);
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
					/* HPN: adaptive read-ahead window */
					max_req = sftp_conn_rdahead_window(from,
					    len);
				}
			}
			break;
		default:
			error_f("Expected SSH2_FXP_DATA(%u) packet, got %u - "
			    "possible protocol corruption", SSH2_FXP_DATA, type);
			sftp_conn_set_protocol_violation(from);
			read_error = 1;
			/* HPN: drain the queue here, so the loop ends at its
			 * next check. That saves a get_msg round trip on a
			 * connection already known to be broken. */
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
		hpn_meter_stop(hpn_meter_serial(), from);

	/* Drain replies from the server (blocking) */
	debug3_f("waiting for %u replies from destination", num_upload_req);
	handle_dest_replies(to, to_path, 1, &num_upload_req, &write_error);

	/* HPN: requests still queued here mean the loop stopped early on a
	 * broken read connection, since a clean exit leaves the queue empty.
	 * Drain it, mark from dead, and fail this file. handle_dest_replies
	 * above has already recorded the write side in write_error. */
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
		/* HPN: as in sftp_download, SSH2_FX_OK here means the origin
		 * connection died, which was logged where it failed, so there
		 * is no status to show. */
		if (status == SSH2_FX_OK)
			error("read origin \"%s\" failed", from_path);
		else
			error("read origin \"%s\": %s", from_path,
			    fx2txt(status));
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

/* HPN: the crossload sink's make_dir. It creates dst on the destination,
 * writable while the walk fills it, and defers its attrs to the end of the
 * transfer, as upstream's crossload walk applies them. */
static int
crossload_make_dir(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, const Attrib *attrs)
{
	struct crossload_sink	*ctx = (struct crossload_sink *)sink;
	Attrib		 curdir = *attrs;
	int		 created;

	if (ctx->print_flag && ctx->print_flag != SFTP_PROGRESS_ONLY)
		pm_mprintf("Retrieving %s\n", src);

	curdir.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	curdir.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	if ((curdir.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) == 0) {
		debug("Origin did not send permissions for directory \"%s\"",
		    dst);
		curdir.perm = S_IWUSR | S_IXUSR;
		curdir.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	}
	/* Keep only the mode bits. The helper forces the owner write and
	 * execute bits while the contents transfer, and the deferred setstat
	 * restores this mode. */
	curdir.perm &= 01777;
	if (sftp_hpn_ensure_remote_dir(ctx->to, dst, &curdir, &created) != 0)
		return -1;

	/* A directory this walk made needs its real mode back, and under -p
	 * any directory gets its attrs. */
	if (created || ctx->preserve_flag)
		sftp_hpn_dirattrs_defer_remote(ctx->dirs, dst, &curdir);
	return 0;
}

/* HPN: the crossload sink's xfer_file. It crossloads one file from the
 * origin to the destination. */
static int
crossload_xfer_file(struct sftp_tree_dl_sink *sink, const char *src,
    const char *dst, Attrib *attrs)
{
	struct crossload_sink	*ctx = (struct crossload_sink *)sink;

	if (sftp_crossload(ctx->from, ctx->to, src, dst, attrs,
	    ctx->preserve_flag) == -1) {
		error("crossload \"%s\" to \"%s\" failed", src, dst);
		return -1;
	}
	return 0;
}

/* HPN: the crossload sink's aborting. The walk stops on an interrupt, or
 * once either connection is dead, since every later file would fail on
 * it. */
static int
crossload_aborting(struct sftp_tree_dl_sink *sink)
{
	struct crossload_sink	*ctx = (struct crossload_sink *)sink;

	return interrupted || sftp_conn_is_dead(ctx->from) ||
	    sftp_conn_is_dead(ctx->to);
}

int
sftp_crossload_dir(struct sftp_conn *from, struct sftp_conn *to,
    const char *from_path, const char *to_path,
    Attrib *dirattrib, int preserve_flag, int print_flag, int follow_link_flag)
{
	char *from_path_canon;
	int ret;
	struct sftp_hpn_dirattr_list dirs = { NULL, 0, 0 };
	struct crossload_sink sink = {
		.base = {
			.make_dir = crossload_make_dir,
			.xfer_file = crossload_xfer_file,
			.aborting = crossload_aborting },
		.from = from,
		.to = to,
		.dirs = &dirs,
		.preserve_flag = preserve_flag,
		.print_flag = print_flag };

	if ((from_path_canon = sftp_realpath(from, from_path)) == NULL) {
		error("crossload \"%s\": path canonicalization failed",
		    from_path);
		return -1;
	}

	/* HPN: reuse the download drivers with conn set to from. Use the
	 * chunked tree walk when the origin supports it, else the recursive
	 * readdir fallback. The sink writes to the destination. */
	if (sftp_conn_has_tree_walk(from))
		ret = sftp_tree_download_consume(from, from_path_canon,
		    to_path, dirattrib, follow_link_flag, &sink.base);
	else
		ret = sftp_readdir_download_consume(from, from_path_canon,
		    to_path, 0, MAX_DIR_DEPTH, dirattrib, follow_link_flag,
		    &sink.base);

	/* HPN: apply the deferred directory setstats on the destination. */
	sftp_hpn_dirattrs_apply(to, &dirs);
	sftp_hpn_dirattrs_free(&dirs);

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
	int r, ret = -1;	/* HPN */

	*usernamesp = *groupnamesp = NULL;
	if (!sftp_can_get_users_groups_by_id(conn))
		return SSH_ERR_FEATURE_UNSUPPORTED;

	if ((uidbuf = sshbuf_new()) == NULL ||
	    (gidbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* HPN: reset for the same reason as send_string_request. */
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
	if (get_msg(conn, msg) != 0)
		goto out;	/* HPN */
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &id)) != 0) {
		error_fr(r, "parse");	/* HPN */
		goto violation;
	}
	if (id != expected_id) {
		error_f("ID mismatch (%u != %u) - possible protocol corruption",
		    id, expected_id);
		goto violation;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int status;
		char *errmsg;

		if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
		    (r = sshbuf_get_cstring(msg, &errmsg, NULL)) != 0) {
			error_fr(r, "parse status");	/* HPN */
			goto violation;
		}
		error("users-groups-by-id %s",
		    *errmsg == '\0' ? fx2txt(status) : errmsg);
		free(errmsg);
		goto out;	/* HPN */
	} else if (type != SSH2_FXP_EXTENDED_REPLY) {
		error_f("Expected SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u - "
		    "possible protocol corruption", SSH2_FXP_EXTENDED_REPLY, type);
		goto violation;
	}

	/* reuse */
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	uidbuf = gidbuf = NULL;
	if ((r = sshbuf_froms(msg, &uidbuf)) != 0 ||
	    (r = sshbuf_froms(msg, &gidbuf)) != 0) {
		error_fr(r, "parse response");	/* HPN */
		goto violation;
	}
	if (nuids > 0) {
		usernames = xcalloc(nuids, sizeof(*usernames));
		for (i = 0; i < nuids; i++) {
			if ((r = sshbuf_get_cstring(uidbuf, &name, NULL)) != 0) {
				error_fr(r, "parse user name");	/* HPN */
				goto violation;
			}
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
			if ((r = sshbuf_get_cstring(gidbuf, &name, NULL)) != 0) {
				error_fr(r, "parse group name");	/* HPN */
				goto violation;
			}
			/* Handle unresolved names */
			if (*name == '\0') {
				free(name);
				name = NULL;
			}
			groupnames[i] = name;
		}
	}
	if (sshbuf_len(uidbuf) != 0) {
		error_f("unexpected extra username data");	/* HPN */
		goto violation;
	}
	if (sshbuf_len(gidbuf) != 0) {
		error_f("unexpected extra groupname data");	/* HPN */
		goto violation;
	}
	/* success */
	*usernamesp = usernames;
	*groupnamesp = groupnames;
	ret = 0;
	goto out;

 violation:
	/* HPN: a malformed reply breaks this connection, not the process. */
	sftp_conn_set_protocol_violation(conn);
 out:
	sshbuf_free(uidbuf);
	sshbuf_free(gidbuf);
	if (ret != 0) {
		/* HPN: free the names read before the failure. */
		for (i = 0; usernames != NULL && i < nuids; i++)
			free(usernames[i]);
		for (i = 0; groupnames != NULL && i < ngids; i++)
			free(groupnames[i]);
		free(usernames);
		free(groupnames);
	}
	return ret;
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

