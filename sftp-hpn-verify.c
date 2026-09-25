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

/* sftp-hpn-verify.c - client-side verification and verified resume for
 * HPN-SSH: local XXH3 hashing (whole-file and per-range), the remote
 * hash extensions (hpn-check-file, sftp-hash-range) with their
 * heartbeat and progress stall detection, post-transfer verification
 * with auto-repair, and the chunked verified resume behind reput and
 * reget. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"
#include "ssherr.h"
#include "sshbuf.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-client.h"
#include "sftp-hpn-verify.h"
#include "sftp-hpn-verify-hash.h"	/* fsync+O_DIRECT on-disk read-back hashing */
#include "sftp-hpn-server.h"	/* heartbeat protocol + wire-name macros */
#include "hpn-meter.h"		/* the verify phase's progress meter */
#include "sftp-hpn-transferlog.h"

#define XXH_INLINE_ALL
#include "xxhash.h"

/* Read buffer for local hashing, and the bytes hashed between watchdog
 * refreshes and progress reports. */
#define HASH_RANGE_READ_BUF_LEN	65536
#define HASH_REFRESH_BYTES	((uint64_t)64 * 1024 * 1024)

/* Chunked resume tunables. CHUNK_SIZE is the re-transfer granularity: at
 * 64 MiB the per-chunk protocol cost, 16 bytes of request and 8 of reply,
 * is negligible next to a missed chunk's transfer. Below MIN_FILE_SIZE
 * the whole-file hash gate is cheaper than the chunked round trip, and
 * two chunks give an engaged run something to map. The request cap,
 * SFTP_HASH_RANGE_MAX_RANGES, is shared with the server through
 * sftp-hpn-server.h; a span with more chunks than that is hashed in
 * several requests. */
#define CHUNK_HASH_CHUNK_SIZE			((uint64_t)64 * 1024 * 1024)
#define CHUNK_HASH_MIN_FILE_SIZE		(2 * CHUNK_HASH_CHUNK_SIZE)

/* SIGINT flag, defined by both binaries that link this file, sftp.c and
 * scp.c, and set by their handlers. The auto-repair loop polls it so a
 * multi-attempt repair stops on Ctrl-C instead of grinding on. */
extern _Atomic sig_atomic_t interrupted;

/* Meter gate, also defined by both binaries. The verify phase gates its
 * progress meter on it like the transfer loops do. */
extern int showprogress;

/* One (offset, length) range of a batched hash query. The same struct
 * describes the request and, through a parallel hashes array, the reply. */
struct sftp_hash_range {
	uint64_t	off;
	uint64_t	len;
};

/* Hash [offset, offset + length) of an open fd with streaming XXH3. A
 * short read hashes what was read: a caller comparing against the peer's
 * hash of the full range then sees a mismatch, which is the right answer
 * for a truncated file. The watchdog is paused for the hash and the
 * pause refreshed every HASH_REFRESH_BYTES, along with a report of
 * progress_base plus the bytes hashed so far to the hash-work op, whose
 * leg base the caller sets. Returns 0 with the hash in *hash_out, or -1
 * on a seek, read or hash-state error. Leaves the fd positioned after
 * the last byte read. */
static int
sftp_hpn_xxhash_local_range(struct sftp_conn *conn, int fd, uint64_t offset,
    uint64_t length, uint64_t progress_base, uint64_t *hash_out)
{
	XXH3_state_t *state;
	u_char buf[HASH_RANGE_READ_BUF_LEN];
	uint64_t remaining = length;
	uint64_t since_refresh = 0;
	ssize_t nread;
	int rc = -1;

	/* error checking */
	if (hash_out == NULL || fd < 0) {
		errno = EINVAL;
		return -1;
	}
	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		return -1;
	}
	if (XXH3_64bits_reset(state) == XXH_ERROR) {
		error_f("XXH3_64bits_reset failed");
		goto out;
	}
	if (lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
		error_f("lseek to %llu: %s",
		    (unsigned long long)offset, strerror(errno));
		goto out;
	}

	/* Hashing a large file can be minutes of wire silence. Declare the
	 * pause here and refresh it as the bytes go by: a single window set
	 * before the call would expire mid-hash and the watchdog would kill
	 * a worker that is working. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);

	/* read the fd in BUF_LEN chunks */
	while (remaining > 0) {
		size_t toread = (size_t)MINIMUM((uint64_t)sizeof(buf),
		    remaining);

		nread = read(fd, buf, toread);
		if (nread == 0)
			break;	/* short read, hash what we got */
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			error_f("read at offset %llu: %s",
			    (unsigned long long)(offset + length - remaining),
			    strerror(errno));
			goto out;
		}
		if (XXH3_64bits_update(state, buf, (size_t)nread)
		    == XXH_ERROR) {
			error_f("XXH3_64bits_update failed");
			goto out;
		}
		remaining -= (uint64_t)nread;
		since_refresh += (uint64_t)nread;
		/* Renew the pause declared above and report progress. */
		if (since_refresh >= HASH_REFRESH_BYTES) {
			sftp_conn_watchdog_pause(conn,
			    HPN_HEARTBEAT_REFRESH_SEC);
			sftp_conn_hash_op_progress(conn,
			    progress_base + (length - remaining));
			since_refresh = 0;
		}
	}

	*hash_out = (uint64_t)XXH3_64bits_digest(state);
	rc = 0;
 out:
	XXH3_freeState(state);
	return rc;
}

/* Hash the first length bytes of an open local file, restoring the fd's
 * position on return. sftp_hpn_xxhash_local_range describes the watchdog
 * and progress behavior. Returns 0 with the hash in *hash_out, or -1 on
 * a seek, read or hash-state error. */
int
sftp_hpn_xxhash_local_fd(struct sftp_conn *conn, int fd, uint64_t length,
    uint64_t *hash_out)
{
	off_t pos_before;
	int rc;

	if ((pos_before = lseek(fd, 0, SEEK_CUR)) == (off_t)-1) {
		error_f("lseek failed: %s", strerror(errno));
		return -1;
	}
	rc = sftp_hpn_xxhash_local_range(conn, fd, 0, length, 0, hash_out);
	if (rc == 0)
		debug3_f("local hash of first %llu bytes: %016llx",
		    (unsigned long long)length, (unsigned long long)*hash_out);
	if (lseek(fd, pos_before, SEEK_SET) == (off_t)-1)
		error_f("lseek restore failed: %s", strerror(errno));
	return rc;
}

/* Wait for the reply to hash request id on a connection whose watchdog
 * the caller has paused. Heartbeats arrive first: EXTENDED_REPLY
 * messages whose first field, field_width bytes wide, is the sentinel,
 * followed by the server's bytes hashed so far. Returns 0 with the real
 * reply's first field in *field and msg positioned after it, 1 for a
 * STATUS reply with *status set and its text, if any, in *errmsg, which
 * the caller frees, or -1 with the connection dead: a transport failure
 * already logged, or a reply that does not fit the request, reported
 * here. name is the extension's short name for the messages. */
static int
hash_reply_wait(struct sftp_conn *conn, const char *name, const char *path,
    u_int id, int field_width, uint64_t sentinel, struct sshbuf *msg,
    uint64_t *field, u_int *status, char **errmsg)
{
	uint64_t hb_prog, hb_prog_last = 0;
	time_t hb_now, hb_advance_sec = monotime();
	u_int rid, field32;
	u_char type;
	int r;

	for (;;) {
		if (get_msg(conn, msg) != 0)
			return -1;
		/* A reply that does not fit the request leaves the connection
		 * desynchronized, so these mark it dead instead of falling
		 * back: the stray reply would surface in a later request. */
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			sftp_conn_die(conn, "%s \"%s\": parse reply header: "
			    "%s", name, path, ssh_err(r));
			return -1;
		}
		if (rid != id) {
			sftp_conn_die(conn, "%s \"%s\": reply id mismatch "
			    "(%u != %u)", name, path, rid, id);
			return -1;
		}
		if (type == SSH2_FXP_STATUS) {
			if ((r = sshbuf_get_u32(msg, status)) != 0) {
				sftp_conn_die(conn, "%s \"%s\": parse status: "
				    "%s", name, path, ssh_err(r));
				return -1;
			}
			(void)sshbuf_get_cstring(msg, errmsg, NULL);
			return 1;
		}
		if (type != SSH2_FXP_EXTENDED_REPLY) {
			sftp_conn_die(conn, "%s \"%s\": expected "
			    "SSH2_FXP_EXTENDED_REPLY(%u), got %u",
			    name, path, SSH2_FXP_EXTENDED_REPLY, type);
			return -1;
		}
		if (field_width == 4) {
			r = sshbuf_get_u32(msg, &field32);
			*field = field32;
		} else
			r = sshbuf_get_u64(msg, field);
		if (r != 0) {
			sftp_conn_die(conn, "%s \"%s\": parse reply: %s",
			    name, path, ssh_err(r));
			return -1;
		}
		if (*field != sentinel)
			return 0;

		/* A heartbeat. The figure after the sentinel feeds the
		 * hash-work op and renews the pause; a missing one counts as
		 * no advance. */
		hb_now = monotime();
		if (sshbuf_get_u64(msg, &hb_prog) != 0)
			hb_prog = hb_prog_last;
		debug3_f("%s \"%s\" id=%u heartbeat progress=%llu",
		    name, path, id, (unsigned long long)hb_prog);
		sftp_conn_hash_op_progress(conn, hb_prog);
		if (hb_prog > hb_prog_last) {
			hb_prog_last = hb_prog;
			hb_advance_sec = hb_now;
		} else if (hb_now - hb_advance_sec >=
		    (time_t)HPN_VERIFY_PROGRESS_STALL_SEC) {
			/* Liveness without progress is a stalled backend. The
			 * request cannot be abandoned on a live connection, a
			 * late reply would desync it, so the connection is
			 * failed instead. */
			sftp_conn_die(conn, "%s \"%s\": server hash made no "
			    "progress for %u seconds", name, path,
			    HPN_VERIFY_PROGRESS_STALL_SEC);
			return -1;
		}
		sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	}
}

/* Ask the server for the XXH3 hash of the first length bytes of path
 * through hpn-check-file. Returns 0 with the hash in *hash_out, or -1
 * for a server without the extension, a STATUS reply, which is reported
 * as an error, or a dead connection. The caller's hash-work op takes
 * the server's progress. */
int
sftp_hpn_hash_remote_file(struct sftp_conn *conn, const char *path,
    uint64_t length, uint64_t *hash_out)
{
	struct sshbuf *msg;
	char *errmsg = NULL;
	u_int id, status;
	int r, rc = -1;

	if (!sftp_conn_has_hpn_check_file(conn)) {
		debug_f("server does not support hpn-check-file extension");
		return -1;
	}
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = sftp_conn_alloc_msg_id(conn);
	/* construct and send the path for the file to be checked */
	debug3_f("sending hpn-check-file for \"%s\" length=%llu id=%u",
	    path, (unsigned long long)length, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_CHECK_FILE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u64(msg, length)) != 0)
		fatal_fr(r, "compose");
	if (send_msg(conn, msg) != 0)
		goto out;

	/* the hashing can take a long time so pause the watchdog */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	r = hash_reply_wait(conn, "hpn-check-file", path, id, 8,
	    HPN_HASH_CHECK_FILE_HEARTBEAT, msg, hash_out, &status, &errmsg);
	/* got a response restart the watchdog */
	sftp_conn_watchdog_resume(conn);
	if (r == 1)
		error("hpn-check-file \"%s\": %s", path,
		    (errmsg != NULL && *errmsg != '\0') ? errmsg :
		    fx2txt(status));
	if (r != 0)
		goto out;
	debug3_f("remote hash of \"%s\" first %llu bytes: %016llx",
	    path, (unsigned long long)length, (unsigned long long)*hash_out);
	rc = 0;
 out:
	free(errmsg);
	sshbuf_free(msg);
	return rc;
}

/* Ask the server for the XXH3 hash of each of the n ranges of path, at
 * most SFTP_HASH_RANGE_MAX_RANGES of them, through sftp-hash-range.
 * Returns 0 with the hashes in hashes_out in range order, or -1 for a
 * server without the extension, a STATUS reply or a dead connection. A
 * STATUS reply means the server could not hash its own copy, which the
 * user is told about since it points at that copy's storage even when
 * the whole-file fallback then succeeds; local_is_target says whether
 * that copy is the source or the destination. The caller's hash-work op
 * takes the server's progress. */
static int
sftp_hpn_hash_remote_ranges(struct sftp_conn *conn, const char *path,
    int local_is_target, const struct sftp_hash_range *ranges, u_int n,
    uint64_t *hashes_out)
{
	struct sshbuf *msg;
	char *errmsg = NULL;
	uint64_t num_hashes;
	u_int id, status, i;
	int r, rc = -1;

	/* The request cap is the caller's contract, not a server limit. */
	if (n == 0 || n > SFTP_HASH_RANGE_MAX_RANGES) {
		error_f("%u ranges for \"%s\"", n, path);
		return -1;
	}
	if (!sftp_conn_has_hash_range(conn)) {
		debug_f("server lacks sftp-hash-range; chunked path "
		    "unavailable");
		return -1;
	}
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	/* Compose and send: path, count, then each (offset, length). */
	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending sftp-hash-range \"%s\" num_ranges=%u id=%u",
	    path, n, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_HASH_RANGE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal_fr(r, "compose");
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_put_u64(msg, ranges[i].off)) != 0 ||
		    (r = sshbuf_put_u64(msg, ranges[i].len)) != 0)
			fatal_fr(r, "compose range %u", i);
	}
	if (send_msg(conn, msg) != 0)
		goto out;

	/* Wait through the heartbeats for the count, or a STATUS. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	r = hash_reply_wait(conn, "sftp-hash-range", path, id, 4,
	    HPN_NUM_HASHES_HEARTBEAT, msg, &num_hashes, &status, &errmsg);
	sftp_conn_watchdog_resume(conn);
	if (r == 1)
		logit("sftp-hash-range \"%s\": server reported %s; the %s "
		    "may have a storage or permission problem", path,
		    (errmsg != NULL && *errmsg != '\0') ? errmsg :
		    fx2txt(status),
		    local_is_target ? "source" : "destination");
	if (r != 0)
		goto out;

	/* One hash per range, in request order. */
	if (num_hashes != n) {
		sftp_conn_die(conn, "sftp-hash-range \"%s\": %llu hashes for "
		    "%u ranges", path, (unsigned long long)num_hashes, n);
		goto out;
	}
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_get_u64(msg, &hashes_out[i])) != 0) {
			sftp_conn_die(conn, "sftp-hash-range \"%s\": parse "
			    "hash %u: %s", path, i, ssh_err(r));
			goto out;
		}
	}
	debug3_f("sftp-hash-range \"%s\": received %u hashes", path, n);
	rc = 0;
 out:
	free(errmsg);
	sshbuf_free(msg);
	return rc;
}

/* Inline source hash. An upload reads the whole source to send it, so
 * rather than read it again at verify, the bytes are teed into a
 * streaming XXH3 as they go by. The state lives on the connection, one
 * file at a time: the upload's park takes the finished hash into the
 * verify entry, or leaves it for the parallel worker to take, before the
 * next file arms. Every entry point is a no-op when not armed or when
 * hpn is NULL, so the disabled hot path is untouched. */

/* Start hashing a new source; any earlier state is discarded. A hash
 * state that cannot be had leaves the tee disarmed and verify re-reads. */
void
sftp_hpn_src_arm(struct sftp_hpn_conn *hpn)
{
	XXH3_state_t *st;

	if (hpn == NULL)
		return;
	sftp_hpn_src_dispose(hpn);	/* clear any stale state first */
	if ((st = XXH3_createState()) == NULL ||
	    XXH3_64bits_reset(st) == XXH_ERROR) {
		if (st != NULL)
			XXH3_freeState(st);
		return;			/* leave disarmed; verify re-reads */
	}
	hpn->verify_src_state = st;
	hpn->verify_src_bytes = 0;
	hpn->verify_src_valid = 0;
	hpn->verify_src_failed = 0;
}

/* Add the bytes just read from the source. An update failure marks the
 * hash failed, which finish then discards. */
void
sftp_hpn_src_feed(struct sftp_hpn_conn *hpn, const u_char *buf, size_t len)
{
	if (hpn == NULL || hpn->verify_src_state == NULL || hpn->verify_src_failed)
		return;
	if (XXH3_64bits_update((XXH3_state_t *)hpn->verify_src_state,
	    buf, len) == XXH_ERROR) {
		hpn->verify_src_failed = 1;
		return;
	}
	hpn->verify_src_bytes += (uint64_t)len;
}

/* Digest after the last byte; the result is valid only when no update
 * failed. */
void
sftp_hpn_src_finish(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL || hpn->verify_src_state == NULL)
		return;
	if (!hpn->verify_src_failed) {
		hpn->verify_src_hash = (uint64_t)XXH3_64bits_digest(
		    (XXH3_state_t *)hpn->verify_src_state);
		hpn->verify_src_valid = 1;
	}
	XXH3_freeState((XXH3_state_t *)hpn->verify_src_state);
	hpn->verify_src_state = NULL;
}

/* Drop any state and result: a partial or aborted upload, a park that
 * did not take the hash, and connection teardown. */
void
sftp_hpn_src_dispose(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	if (hpn->verify_src_state != NULL) {
		XXH3_freeState((XXH3_state_t *)hpn->verify_src_state);
		hpn->verify_src_state = NULL;
	}
	hpn->verify_src_valid = 0;
	hpn->verify_src_failed = 0;
	hpn->verify_src_bytes = 0;
}

/* Consume the finished hash, once, if it covers expect_bytes. Returns 0
 * with the hash in *hash_out, or -1 when there is none or the byte count
 * differs, in which case the caller reads the source itself. */
int
sftp_hpn_src_take(struct sftp_hpn_conn *hpn, uint64_t expect_bytes,
    uint64_t *hash_out)
{
	if (hpn == NULL || !hpn->verify_src_valid)
		return -1;
	hpn->verify_src_valid = 0;		/* consume once */
	if (hpn->verify_src_bytes != expect_bytes)
		return -1;			/* did not cover the whole file */
	*hash_out = hpn->verify_src_hash;
	return 0;
}

/* One-shot form of the tee for a source read in a single buffer, the
 * pipelined small-file batch. Returns 0 with the hash in *hash_out, or -1
 * when verify is off or hpn is NULL, so the disabled path does no work. */
int
sftp_hpn_src_hash_buf(struct sftp_hpn_conn *hpn, const u_char *buf,
    size_t len, uint64_t *hash_out)
{
	if (hpn == NULL || !hpn->verify_transfer_enabled)
		return -1;
	*hash_out = (uint64_t)XXH3_64bits(buf, len);
	return 0;
}

/*
 * Verify ONE byte range [off, off+len) of a file: O_DIRECT read-back hash of the
 * local range vs the server's sftp-hash-range of the remote range, compared.
 * Direction-agnostic - the caller picks which path is local vs remote (upload:
 * local=source, remote=dest; download: local=dest, remote=source).  Used by the
 * range-granular parallel verify, where one large file's chunks are spread
 * across the worker pool.  Returns 0 = match, 1 = MISMATCH (corruption), -1 =
 * could not verify (local read error or server hash-range failure).
 */
/* Read-back progress shim: land the local leg's cumulative bytes on the
 * conn's hash-work op (sftp_hpn_readback_progress contract). */
static void
verify_readback_progress(void *arg, uint64_t bytes)
{
	sftp_conn_hash_op_progress((struct sftp_conn *)arg, bytes);
}

static int
sftp_hpn_verify_chunk(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t off, off_t len, int local_is_target,
    int have_local_hash, uint64_t local_hash,
    uint64_t *local_hash_out, uint64_t *remote_hash_out)
{
	uint64_t	 remote_hash = 0;
	struct sftp_hash_range range;

	if (conn == NULL || remote_path == NULL || len <= 0)
		return -1;
	if (!sftp_conn_has_hash_range(conn))
		return -1;	/* submit only chunks supported servers; defensive */

	/* Hash-work op: local + remote legs of this span (work-bytes).
	 * Ended by the unit-completion fold sites, not here. */
	sftp_conn_hash_op_begin(conn, 2 * (uint64_t)len);

	/*
	 * Local range hash.  When have_local_hash is set (an upload range whose
	 * source XXH3 was teed during the transfer) re-use it - no re-read
	 * (the leg's work was prepaid by the transfer tee; credit it whole).
	 * Otherwise read the local range back from disk (download dest, or an
	 * untee'd upload range), feeding the leg per read buffer.
	 */
	if (!have_local_hash) {
		if (local_path == NULL)
			return -1;
		sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
		/*
		 * O_DIRECT platter read-back only for the WRITTEN side (a
		 * download dest); an upload source is read buffered - its cache
		 * already reflects the on-disk content and the warm re-read is
		 * cheaper, matching the whole-file verify path.
		 */
		if (sftp_hpn_hash_range_ondisk(local_path, (uint64_t)off,
		    (uint64_t)len, /*ondisk=*/local_is_target, &local_hash,
		    verify_readback_progress, conn) != 0) {
			error_f("verify: local range hash failed at %llu+%llu "
			    "for \"%s\"", (unsigned long long)off,
			    (unsigned long long)len, local_path);
			sftp_conn_watchdog_resume(conn);
			return -1;
		}
		sftp_conn_watchdog_resume(conn);
	} else {
		debug_f("verify: teed source hash for \"%s\" [%llu+%llu)",
		    local_path, (unsigned long long)off,
		    (unsigned long long)len);
		sftp_conn_hash_op_progress(conn, (uint64_t)len);
	}

	range.off = (uint64_t)off;
	range.len = (uint64_t)len;
	sftp_conn_hash_op_leg(conn, (uint64_t)len);
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	if (sftp_hpn_hash_remote_ranges(conn, remote_path, local_is_target,
	    &range, 1, &remote_hash) != 0) {
		sftp_conn_watchdog_resume(conn);
		return -1;
	}
	sftp_conn_watchdog_resume(conn);

	if (local_hash_out != NULL)
		*local_hash_out = local_hash;
	if (remote_hash_out != NULL)
		*remote_hash_out = remote_hash;

	if (local_hash != remote_hash) {
		/* Low-level, direction-blind, and fires per chunk per repair
		 * attempt: keep it at debug.  The user-facing message (naming
		 * the local/remote dest) is emitted by the verify/repair callers
		 * that know the transfer direction. */
		debug_f("verify: range [%llu+%llu) of \"%s\" hash mismatch "
		    "(local vs remote)", (unsigned long long)off,
		    (unsigned long long)len, remote_path);
		return 1;
	}
	return 0;
}


/*
 * Chunked reconciliation of a span [span_off, span_off+span_len) of a file:
 * hash the span in 64 MiB chunks on both sides (local via the O_DIRECT-capable
 * range read, remote via sftp-hash-range), then splice each contiguous run of
 * mismatched chunks in place - sftp_upload_range (upload: local_is_target 0,
 * source -> remote dest) or sftp_download_range (download: local_is_target 1,
 * remote source -> local dest).  Only the mismatched chunks move, not the gaps
 * between them.
 *
 * This is the single splice engine behind BOTH verified resume (whole file,
 * span = [0, size)) and per-range auto-repair (an arbitrary sub-range).
 *
 * Returns 1 (every chunk already matched - nothing to do), 0 (one or more runs
 * spliced successfully), or -1 (declined: server lacks sftp-hash-range, span
 * below the chunk floor, or a local/remote hash or transfer error - the
 * caller falls back to a whole-span re-transmit).  A
 * partial failure mid-run leaves the destination indeterminate, hence -1 +
 * fallback.
 */
static int
chunked_reconcile_span(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path,
    off_t span_off, off_t span_len, off_t dest_size, int local_is_target)
{
	struct sftp_hash_range	*ranges = NULL;
	uint64_t		*local_hashes = NULL;
	uint64_t		*remote_hashes = NULL;
	uint64_t		 slen, soff, bytes_moved = 0, checked_bytes;
	uint64_t		 refetch_total = 0, remote_done = 0;
	volatile uint64_t	 live_ctr = 0;
	int			 meter_on = 0;
	const char		*ing = local_is_target ? "re-fetching"
				    : "re-transferring";
	const char		*ed = local_is_target ? "re-fetched"
				    : "re-transferred";
	u_int			 n_chunks, n_check, n_mismatched = 0;
	u_int			 i, j, batch;
	int			 rc = -1;

	if (conn == NULL || local_path == NULL || remote_path == NULL ||
	    local_fd < 0 || span_len <= 0)
		return -1;

	if (!sftp_conn_has_hash_range(conn)) {
		debug_f("server lacks sftp-hash-range; declining chunked path "
		    "for \"%s\"", local_path);
		return -1;
	}
	slen = (uint64_t)span_len;
	soff = (uint64_t)span_off;
	if (slen < CHUNK_HASH_MIN_FILE_SIZE) {
		debug_f("span %llu of \"%s\" below chunked threshold %llu; "
		    "declining", (unsigned long long)slen, local_path,
		    (unsigned long long)CHUNK_HASH_MIN_FILE_SIZE);
		return -1;
	}

	n_chunks = (u_int)((slen + CHUNK_HASH_CHUNK_SIZE - 1) /
	    CHUNK_HASH_CHUNK_SIZE);

	if ((ranges = calloc(n_chunks, sizeof(*ranges))) == NULL ||
	    (local_hashes = calloc(n_chunks, sizeof(*local_hashes))) == NULL ||
	    (remote_hashes = calloc(n_chunks, sizeof(*remote_hashes))) == NULL) {
		error_f("calloc for %u chunks failed", n_chunks);
		goto out;
	}

	/*
	 * Build the chunk layout over the span.  The last chunk clamps to the
	 * span end so the server's matching XXH3 (also clamped) lines up with
	 * the local hash.
	 */
	for (i = 0; i < n_chunks; i++) {
		uint64_t off = soff + (uint64_t)i * CHUNK_HASH_CHUNK_SIZE;
		uint64_t remain = (soff + slen) - off;
		ranges[i].off = off;
		ranges[i].len = remain < CHUNK_HASH_CHUNK_SIZE
		    ? remain : CHUNK_HASH_CHUNK_SIZE;
	}

	/*
	 * Destination-EOF clamp: a chunk that extends past the DESTINATION's
	 * current size cannot match - the dest side hashes only up to its
	 * EOF, so a straddling or wholly-absent chunk is a guaranteed
	 * mismatch.  Skip hashing those on BOTH sides (a 5 GB partial of a
	 * 20 GB file used to cost a 20 GB source hash) and send them straight
	 * to the refill list.  dest_size 0 = unknown/full: check everything
	 * (the repair path and equal-size resumes).  Chunks are ordered, so
	 * the checked set is the prefix [0, n_check).
	 */
	n_check = n_chunks;
	if (dest_size > 0) {
		for (i = 0; i < n_chunks; i++) {
			if (ranges[i].off + ranges[i].len >
			    (uint64_t)dest_size) {
				n_check = i;
				break;
			}
		}
		if (n_check < n_chunks)
			debug_f("dest-EOF clamp for \"%s\": checking %u/%u "
			    "chunks (dest size %llu); %u known-missing",
			    local_path, n_check, n_chunks,
			    (unsigned long long)dest_size,
			    n_chunks - n_check);
	}
	checked_bytes = 0;
	for (i = 0; i < n_check; i++)
		checked_bytes += ranges[i].len;

	/* Pause the orchestrator watchdog for the combined local+remote
	 * hash phase.  Auto-expires; explicit resume on every exit path.
	 * Also raise the hash-op marker NOW: the local hash phase below is
	 * byte-silent for tens of seconds on a big span, and the marker is
	 * what gates the watchdog's kill classifiers off a working hasher
	 * (the pause alone does not gate born-dead).  Refreshed per chunk. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	/* Hash-work op: both legs of the checked span (work-bytes). */
	sftp_conn_hash_op_begin(conn, 2 * checked_bytes);

	/* Leg notices: the local leg feeds no meter (only the remote
	 * heartbeats do), so without these the display sits still while
	 * work is happening.  logit self-gates under -q; worded neutrally
	 * because this engine also runs verify auto-repair.  Skipped when
	 * the dest-EOF clamp left nothing to hash. */
	if (n_check > 0)
		logit("hashing the local copy of \"%s\"", local_path);

	/* Local hashing. The helper refreshes the pause and reports progress
	 * as it goes; the per-chunk report here covers a short final chunk. */
	uint64_t local_done = 0;

	for (i = 0; i < n_check; i++) {
		if (sftp_hpn_xxhash_local_range(conn, local_fd, ranges[i].off,
		    ranges[i].len, local_done, &local_hashes[i]) != 0) {
			error_f("local hash failed at chunk %u offset %llu "
			    "for \"%s\"", i,
			    (unsigned long long)ranges[i].off, local_path);
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
		local_done += ranges[i].len;
		sftp_conn_hash_op_progress(conn, local_done);
	}

	/* Remote hashing of the checked prefix, in batches of at most
	 * SFTP_HASH_RANGE_MAX_RANGES, the per-request bound. Each batch is
	 * all-or-nothing and the helper emits the user-visible warning on a
	 * failure. This is the second leg of the work op. The server's
	 * heartbeats report progress from zero for each request, so the leg
	 * base moves up by the batches already done and the meter stays
	 * monotone. Skipped entirely when the clamp left nothing to compare. */
	if (n_check > 0)
		logit("hashing the remote copy of \"%s\"", remote_path);
	for (i = 0; i < n_check; i += batch) {
		batch = n_check - i;
		if (batch > SFTP_HASH_RANGE_MAX_RANGES)
			batch = SFTP_HASH_RANGE_MAX_RANGES;
		sftp_conn_hash_op_leg(conn, checked_bytes + remote_done);
		if (sftp_hpn_hash_remote_ranges(conn, remote_path, local_is_target,
		    &ranges[i], batch, &remote_hashes[i]) != 0) {
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
		for (j = i; j < i + batch; j++)
			remote_done += ranges[j].len;
	}
	sftp_conn_watchdog_resume(conn);

	/* Chunks past the dest EOF: force-mismatch so the splice loop below
	 * re-sends them (calloc left local == remote == 0). */
	for (i = n_check; i < n_chunks; i++)
		remote_hashes[i] = 1;

	for (i = 0; i < n_chunks; i++) {
		if (local_hashes[i] != remote_hashes[i])
			n_mismatched++;
	}

	if (n_mismatched == 0) {
		debug("chunked reconcile: all %u chunks of span match, "
		    "\"%s\" already current", n_chunks, local_path);
		rc = 1;
		goto out;
	}

	for (i = 0; i < n_chunks; i++) {
		if (local_hashes[i] != remote_hashes[i])
			refetch_total += ranges[i].len;
	}
	/*
	 * Hand the display from the resume-check meter to a transfer meter.
	 * The hash work is done, and leaving that meter up leaves its
	 * counter dead for the whole re-fetch: the user watches a stalled
	 * 98 percent while gigabytes move. The range legs feed the
	 * connection's live counter, so this meter ticks with received or
	 * sent bytes and completes when the re-fetch does.
	 */
	if (showprogress && refetch_total > 0) {
		const char *target = local_is_target ? local_path
		    : remote_path;
		const char *base = strrchr(target, '/');

		hpn_meter_stop(hpn_meter_serial(), conn);
		/* The live counter is a volatile uint64_t and the meter
		 * takes an off_t: same width, and byte counts stay far
		 * below the sign bit. */
		if (hpn_meter_start(hpn_meter_serial(), conn,
		    HPN_METER_FILE, HPN_METER_DOM_TRANSFER,
		    base != NULL ? base + 1 : target,
		    (off_t)refetch_total, (off_t *)&live_ctr, 1) == 0) {
			sftp_conn_set_live_counter(conn, &live_ctr);
			meter_on = 1;
		}
	}

	i = 0;
	while (i < n_chunks) {
		u_int run_start;
		uint64_t run_off, run_len;
		int r;

		if (local_hashes[i] == remote_hashes[i]) {
			i++;
			continue;
		}
		run_start = i;
		while (i < n_chunks && local_hashes[i] != remote_hashes[i])
			i++;
		run_off = ranges[run_start].off;
		run_len = (ranges[i - 1].off + ranges[i - 1].len) - run_off;

		debug3("resume: %s chunks [%u, %u) at offset %llu "
		    "length %llu for \"%s\"", ing, run_start, i,
		    (unsigned long long)run_off,
		    (unsigned long long)run_len, local_path);
		if (local_is_target)
			r = sftp_download_range(conn, remote_path, local_path,
			    (off_t)run_off, (off_t)run_len, NULL);
		else
			r = sftp_upload_range(conn, local_path, remote_path,
			    (off_t)run_off, (off_t)run_len, NULL, NULL, NULL);
		if (r != 0) {
			/* A dead connection (worker churn) is expected fallout
			 * - the caller's fallback retries; only a live-conn
			 * failure deserves the user's attention. */
			if (sftp_conn_is_dead(conn))
				debug_f("reconcile of chunks [%u, %u) failed "
				    "for \"%s\"; falling back", run_start, i,
				    local_path);
			else
				error_f("reconcile of chunks [%u, %u) failed "
				    "for \"%s\"; falling back", run_start, i,
				    local_path);
			goto out;
		}
		bytes_moved += run_len;
	}

	logit("verified resume \"%s\": %s %u/%u chunks "
	    "(%u hashed, %u known-missing past dest EOF; "
	    "%llu / %llu bytes, %.1f%% of span)",
	    local_path, ed, n_mismatched, n_chunks,
	    n_check, n_chunks - n_check,
	    (unsigned long long)bytes_moved, (unsigned long long)slen,
	    100.0 * (double)bytes_moved / (double)slen);
	rc = 0;
out:
	if (meter_on) {
		sftp_conn_set_live_counter(conn, NULL);
		hpn_meter_stop(hpn_meter_serial(), conn);
	}
	free(ranges);
	free(local_hashes);
	free(remote_hashes);
	return rc;
}

int
sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size)
{
	if (file_size <= 0)
		return -1;
	return chunked_reconcile_span(conn, local_fd, local_path, remote_path,
	    0, file_size, dest_size, /*local_is_target=*/0);
}

int
sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size)
{
	if (file_size <= 0)
		return -1;
	return chunked_reconcile_span(conn, local_fd, local_path, remote_path,
	    0, file_size, dest_size, /*local_is_target=*/1);
}

void
sftp_hpn_verify_repair_resolve(int no_verify_repair_cli, int *enabled_out,
    int *attempts_out)
{
	if (enabled_out != NULL)
		*enabled_out = !no_verify_repair_cli;
	if (attempts_out != NULL)
		*attempts_out = 3;	/* per-range re-transfer attempt cap */
}

/*
 * One repair pass over the span [span_off, span_off+span_len) of
 * `local_path`/`remote_path`.  Granularity mirrors the transfer: a span at or
 * above the chunk-hash floor re-hashes in 64 MiB chunks and splices only the
 * mismatched contiguous runs in place (no truncation, offset-addressed WRITE);
 * a smaller span (or one the chunked path declines) re-transmits the whole
 * span.  Returns 0 if a pass ran (caller re-verifies), -1 on a hard transfer
 * error.
 */
static int
verify_repair_one_pass(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t span_off,
    off_t span_len)
{
	int rc;

	if (span_len > 0 && (uint64_t)span_len >= CHUNK_HASH_MIN_FILE_SIZE) {
		int fd = open(local_path, O_RDONLY);

		if (fd == -1) {
			error_f("open local \"%s\": %s", local_path,
			    strerror(errno));
			return -1;
		}
		rc = chunked_reconcile_span(conn, fd, local_path, remote_path,
		    span_off, span_len, /*dest_size=*/0, local_is_target);
		close(fd);
		/*
		 * 1 = nothing mismatched at chunk granularity, 0 = spliced;
		 * either way a pass ran.  -1 = declined (server lacks
		 * sftp-hash-range, chunk-count cap, or local I/O error) - fall
		 * through to a whole-span re-transmit.
		 */
		if (rc >= 0)
			return 0;
	}

	/* Whole-span re-transmit: re-send / re-fetch [span_off, span_len). */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	if (local_is_target)
		rc = sftp_download_range(conn, remote_path, local_path,
		    span_off, span_len, NULL);
	else
		rc = sftp_upload_range(conn, local_path, remote_path,
		    span_off, span_len, NULL, NULL, NULL);
	sftp_conn_watchdog_resume(conn);
	return rc == 0 ? 0 : -1;
}

int
sftp_hpn_verify_repair(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t off, off_t len,
    int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out)
{
	struct stat sb;
	uint64_t lh = 0, rh = 0, dest_hash, prev_hash;
	const char *side, *dst;
	int r, attempt;

	if (repaired_out != NULL)
		*repaired_out = 0;

	/*
	 * Whole-file mode: callers pass len <= 0 to mean "the entire file" and
	 * the size is resolved here; range callers (the orchestrator's per-range
	 * verify) pass an explicit [off, len).
	 */
	if (len <= 0) {
		Attrib ra;
		off_t remote_size;

		if (stat(local_path, &sb) == -1) {
			error_f("stat \"%s\": %s", local_path, strerror(errno));
			return -1;
		}
		/*
		 * Whole-file verify must confirm the two files are the SAME
		 * SIZE, not merely that their common prefix matches.  len was
		 * derived from the local size alone and both ends hash [0,len),
		 * so a dest shorter than the source (a truncated download that
		 * completed on an early / adversarial EOF) or longer (a dest
		 * overwritten out of band) would pass because only
		 * min(local,remote) is ever hashed.  Stat the remote and require
		 * the sizes to agree; a divergence is a definitive mismatch.
		 * (A size mismatch is not the localized-corruption case the
		 * span repair below handles, so it is reported, not repaired.)
		 */
		if (sftp_stat(conn, remote_path, 1, &ra) != 0 ||
		    (ra.flags & SSH2_FILEXFER_ATTR_SIZE) == 0) {
			error_f("verify \"%s\": cannot determine remote size",
			    remote_path);
			return -1;	/* unverifiable: fail closed */
		}
		remote_size = (off_t)ra.size;
		if (sb.st_size != remote_size) {
			logit("verify: \"%s\" size mismatch "
			    "(local %lld, remote %lld)",
			    local_is_target ? local_path : remote_path,
			    (long long)sb.st_size, (long long)remote_size);
			return 1;	/* definitive mismatch */
		}
		if (sb.st_size == 0)
			return 0;	/* empty file: trivially matches */
		off = 0;
		len = sb.st_size;
	}

	side = local_is_target ? "local" : "remote";
	dst = local_is_target ? local_path : remote_path;

	/*
	 * Initial verify of the span via the one range-hash path (sftp-hash-
	 * range, O_DIRECT read-back of the WRITTEN side).  A teed source hash
	 * (uploads) lets the common no-repair case skip the local read.
	 */
	r = sftp_hpn_verify_chunk(conn, local_path, remote_path, off, len,
	    local_is_target, have_local_hash, local_hash, &lh, &rh);
	if (r != 1)
		return r;		/* 0 = good, -1 = unverifiable */
	if (!repair_enabled)
		return 1;		/* mismatch, repair disabled */

	if (max_attempts < 1)
		max_attempts = 1;
	dest_hash = local_is_target ? lh : rh;
	prev_hash = dest_hash;

	logit("Repairing %s file \"%s\" (verify mismatch)...", side, dst);

	for (attempt = 1; attempt <= max_attempts; attempt++) {
		/*
		 * Bail on Ctrl-C between attempts: a converging/capping repair
		 * of a large span would otherwise grind through every remaining
		 * attempt before the interrupt is noticed.  The span is left as
		 * the last attempt wrote it (still corrupt) and recorded as a
		 * verify failure by the caller.
		 */
		if (interrupted) {
			logit("repair of %s file \"%s\" interrupted", side, dst);
			return 1;
		}
		if (verify_repair_one_pass(conn, local_path, remote_path,
		    local_is_target, off, len) != 0) {
			error_f("repair re-transfer failed for \"%s\"", dst);
			return 1;
		}
		/* Re-verify off the platter; no tee on the rare repair path. */
		r = sftp_hpn_verify_chunk(conn, local_path, remote_path, off,
		    len, local_is_target, /*have_local_hash=*/0, 0, &lh, &rh);
		if (r == 0) {
			logit("repaired %s file \"%s\" (attempt %d)",
			    side, dst, attempt);
			if (repaired_out != NULL)
				*repaired_out = 1;
			return 0;
		}
		if (r < 0) {
			/*
			 * Could not re-verify this attempt (transient read or
			 * extension problem): keep trying to the cap, give up.
			 */
			if (attempt >= max_attempts)
				break;
			continue;
		}
		/*
		 * Still corrupt.  Convergence: the same dest hash twice in a
		 * row means a deterministic fault keeps re-writing the same bad
		 * bytes (bad media / a re-corrupting source) - no point
		 * retrying.
		 */
		dest_hash = local_is_target ? lh : rh;
		if (dest_hash == prev_hash) {
			error_f("%s file \"%s\": two identical failed hashes in "
			    "a row - deterministic fault, not retrying",
			    side, dst);
			return 1;
		}
		prev_hash = dest_hash;
	}
	error_f("%s file \"%s\": still corrupt after %d repair attempt(s) - "
	    "possible storage/media fault", side, dst, max_attempts);
	return 1;
}

/* ==========================================================================
 * Conn-side verify-state bridge wrappers (moved from sftp-client.c).
 *
 * Each reaches HPN per-connection verify state through sftp_conn_hpn(); the
 * bodies are behavior-identical to the originals.  Declared in
 * sftp-client-internal.h; call sites unchanged.  (sftp_conn_verify_run_phase
 * still lives in sftp-client.c - it drives the progress meter + transfer log.)
 * ========================================================================== */

/* Verify transfer state accessors.  Set from sftp.c once -V has been
 * parsed; read where verify is gated - arming the inline source-hash tee
 * and the classic post-transfer verify phase. */
void
sftp_conn_set_verify_transfer(struct sftp_conn *conn, int enabled)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->verify_transfer_enabled = enabled ? 1 : 0;
}

int
sftp_conn_verify_transfer_enabled(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	return h != NULL && h->verify_transfer_enabled;
}

void
sftp_conn_set_verify_repair(struct sftp_conn *conn, int enabled, int attempts)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	h->verify_repair_enabled = enabled ? 1 : 0;
	h->verify_repair_attempts = attempts < 1 ? 1 : attempts;
}

/* Park a just-transferred file for the classic post-transfer verify phase,
 * at the end of sftp_upload (local_is_target 0) and sftp_download (1).
 * No-op unless verify is enabled, and skipped on parallel worker conns,
 * whose fleet parks for itself (live_counter is the per-worker hook, NULL
 * on the main conn). Records the paths and, for an upload whose inline
 * source hash covered all size bytes, takes that hash so the phase can
 * skip the local read. The compare itself runs later in
 * sftp_conn_verify_run_phase, the upload-everything-then-verify model,
 * instead of stalling each file on a round trip. The hashed form below
 * is for the serial bundle flush, whose members' hashes come from the
 * bundle writer rather than the slot. */
static void
verify_park_entry(struct sftp_hpn_conn *h, const char *local_path,
    const char *remote_path, int local_is_target, int have_src_hash,
    uint64_t src_hash)
{
	struct sftp_verify_pending_entry *e;

	if (h->verify_pending_count >= h->verify_pending_cap) {
		int newcap = h->verify_pending_cap ?
		    h->verify_pending_cap * 2 : 64;
		h->verify_pending = xreallocarray(h->verify_pending, newcap,
		    sizeof(*h->verify_pending));
		h->verify_pending_cap = newcap;
	}
	e = &h->verify_pending[h->verify_pending_count++];
	e->local_path = xstrdup(local_path);
	e->remote_path = xstrdup(remote_path);
	e->local_is_target = local_is_target;
	e->have_src_hash = have_src_hash;
	e->src_hash = have_src_hash ? src_hash : 0;
}

void
sftp_conn_verify_park(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t size)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	uint64_t src_hash = 0;
	int have_src_hash;

	if (!sftp_conn_verify_transfer_enabled(conn))
		return;
	if (h->live_counter != NULL)
		return;
	have_src_hash = !local_is_target &&
	    sftp_hpn_src_take(h, (uint64_t)size, &src_hash) == 0;
	verify_park_entry(h, local_path, remote_path, local_is_target,
	    have_src_hash, src_hash);
}

void
sftp_conn_verify_park_hashed(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int have_src_hash, uint64_t src_hash)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (!sftp_conn_verify_transfer_enabled(conn))
		return;
	if (h->live_counter != NULL)
		return;
	verify_park_entry(h, local_path, remote_path, /*local_is_target=*/0,
	    have_src_hash, src_hash);
}

/* Files parked for the classic verify phase; lets the caller print a quiet-
 * gated "Verifying N file(s)..." line before sftp_conn_verify_run_phase. */
int
sftp_conn_verify_pending_count(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return 0;
	return h->verify_pending_count;
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
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	size_t n = 0;

	if (out_paths != NULL)
		*out_paths = NULL;
	if (out_used != NULL)
		*out_used = 0;
	if (h == NULL)
		return 0;
	n = h->verify_failed_count;
	if (out_paths != NULL)
		*out_paths = h->verify_failed_paths;
	if (out_used != NULL)
		*out_used = n;
	h->verify_failed_paths = NULL;
	h->verify_failed_count = 0;
	return n;
}

/* Classic post-transfer verify phase: verify every file parked during
 * the command's transfers, then clear the list. The single-conn analogue
 * of the -j orchestrator's verify phase, on the same verify and repair
 * engine. An upload's teed source hash rides in its entry, so only files
 * without one are read locally. Mismatches are recorded on the conn and
 * drained later to the run summary and SFTP_EX_VERIFY_FAILED; they do not
 * fail the transfer. No-op when nothing was parked (parallel mode, or
 * verify disabled). */
void
sftp_conn_verify_run_phase(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	int i;
	off_t total = 0, counter = 0;
	int meter_on = 0;
	struct stat sb;

	debug_f("verify phase: %d file(s) parked",
	    h == NULL ? 0 : h->verify_pending_count);
	if (h == NULL || h->verify_pending_count == 0)
		return;
	/* Size each parked file for the progress-meter total (stat is cheap;
	 * the per-file verify re-stats anyway).  The byte-based meter mirrors
	 * the transfer meter - bar, rate, ETA - so the user sees the verify
	 * phase is working, not hung.  Gated on showprogress, same as transfers
	 * (off under -q / batch / non-tty). */
	for (i = 0; i < h->verify_pending_count; i++) {
		if (stat(h->verify_pending[i].local_path, &sb) == 0)
			h->verify_pending[i].size = sb.st_size;
		/* WORK-bytes: both ends hash each byte, so the meter total
		 * is 2x (project_hash_work_meter_design). */
		total += 2 * h->verify_pending[i].size;
	}
	if (showprogress && total > 0) {
		/* WORK kind in the work-byte domain (2x the moved bytes,
		 * both ends hash): the core marks it not a file and raises
		 * the verify phase flag for the frame stream. */
		hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_WORK,
		    HPN_METER_DOM_WORK, "verify", total, &counter, 0);
		/* Bridge the hash engines' per-op progress into the meter
		 * counter so a single big file moves smoothly instead of
		 * jumping 0->100 at completion. */
		sftp_conn_set_hash_meter_ctr(conn, &counter);
		meter_on = 1;
	}
	for (i = 0; i < h->verify_pending_count; i++) {
		struct sftp_verify_pending_entry *e =
		    &h->verify_pending[i];
		/*
		 * SIGINT aborts the phase, like the transfer loops: stop
		 * verifying on interrupt but keep ripping through the rest of the
		 * list to free it (no network, fast), so nothing leaks and the
		 * interrupt unwinds promptly to the prompt / exit.
		 */
		if (!interrupted) {
			int repaired = 0;
			int r = sftp_hpn_verify_repair(conn, e->local_path,
			    e->remote_path, e->local_is_target,
			    /*off=*/0, /*len=*/e->size,
			    e->have_src_hash, e->src_hash,
			    h->verify_repair_enabled,
			    h->verify_repair_attempts, &repaired);
			/* TransferLog: the file's final status under -V (the
			 * serial transfer line deferred to here).  Unverifiable
			 * transferred fine - plain success. */
			if (transferlog_active()) {
				enum transferlog_status st;

				if (r == 1)
					st = TRANSFERLOG_FAILED;
				else if (r < 0)
					st = TRANSFERLOG_SUCCESS;
				else
					st = repaired ? TRANSFERLOG_REPAIRED :
					    TRANSFERLOG_VERIFIED;
				transferlog_file(st, (long long)e->size,
				    e->local_is_target ? e->local_path :
				    e->remote_path);
			}
			if (r == 1) {
				error("VERIFY FAILED: \"%s\" (post-transfer hash "
				    "mismatch - the transferred file does NOT "
				    "match the source)", e->remote_path);
				h->verify_failed_paths = xreallocarray(
				    h->verify_failed_paths,
				    h->verify_failed_count + 1,
				    sizeof(*h->verify_failed_paths));
				h->verify_failed_paths[
				    h->verify_failed_count++] =
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
		hpn_meter_stop(hpn_meter_serial(), conn);
	}
	h->verify_pending_count = 0;
}
