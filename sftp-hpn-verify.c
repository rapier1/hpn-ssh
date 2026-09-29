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
#include "sftp-hpn-verify-hash.h"	/* O_DIRECT read-back hashing */
#include "sftp-hpn-server.h"	/* heartbeat protocol + wire-name macros */
#include "hpn-meter.h"		/* the verify phase's progress meter */
#include "sftp-hpn-transferlog.h"

#define XXH_INLINE_ALL
#include "xxhash.h"

/* Chunked resume tunables. CHUNK_SIZE is the re-transfer granularity: at
 * 64 MiB the per-chunk protocol cost, 16 bytes of request and 8 of reply,
 * is negligible next to a missed chunk's transfer. Below MIN_FILE_SIZE
 * the whole-file hash gate is cheaper than the chunked round trip, and
 * two chunks give an engaged run something to map. The request cap,
 * SFTP_HASH_RANGE_MAX_RANGES, is shared with the server through
 * sftp-hpn-server.h; a span with more chunks than that is hashed in
 * several requests. */
#define CHUNK_HASH_CHUNK_SIZE		((uint64_t)64 * 1024 * 1024)
#define CHUNK_HASH_MIN_FILE_SIZE	(2 * CHUNK_HASH_CHUNK_SIZE)

/* Auto-repair attempts per mismatched range before sftp_hpn_verify_repair
 * gives up and reports the destination as still corrupt. */
#define VERIFY_REPAIR_ATTEMPTS		3

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

/* Progress for a local hash: each buffer the reader hashes renews the
 * watchdog pause and reports base plus the bytes so far to the hash-work
 * op, whose leg base the caller sets. */
struct local_hash_progress {
	struct sftp_conn	*conn;
	uint64_t		 base;
};

static void
local_hash_progress(void *arg, uint64_t done)
{
	struct local_hash_progress *p = arg;

	sftp_conn_watchdog_pause(p->conn, HPN_HEARTBEAT_REFRESH_SEC);
	sftp_conn_hash_op_progress(p->conn, p->base + done);
}

/* Hash [offset, offset + length) of an open fd, buffered, through the
 * shared hash reader. A short read hashes what was read: a caller
 * comparing against the peer's hash of the full range then sees a
 * mismatch, which is the right answer for a truncated file. Hashing a
 * large file can be minutes of wire silence, so the watchdog is paused
 * here and the pause renewed as the bytes go by; a single window set
 * before the call would expire mid-hash. progress_base plus the bytes
 * hashed so far goes to the hash-work op. Returns 0 with the hash in
 * *hash_out, or -1 on a seek, read or hash-state error. Leaves the fd
 * positioned after the last byte read. */
static int
sftp_hpn_xxhash_local_range(struct sftp_conn *conn, int fd, uint64_t offset,
    uint64_t length, uint64_t progress_base, uint64_t *hash_out)
{
	struct sftp_hpn_hash_reader *reader;
	struct local_hash_progress progress = { conn, progress_base };
	int rc;

	if ((reader = sftp_hpn_hash_reader_attach(fd, "local file")) == NULL) {
		error_f("hash reader: %s", strerror(errno));
		return -1;
	}
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	rc = sftp_hpn_hash_reader_range(reader, offset, length, hash_out,
	    local_hash_progress, &progress);
	sftp_hpn_hash_reader_close(reader);
	return rc;
}

/* Hash the first length bytes of an open local file, restoring the fd's
 * position on return. sftp_hpn_xxhash_local_range describes the watchdog
 * and progress behavior. Returns 0 with the hash in *hash_out, or -1 on
 * a seek, read or hash-state error. */
static int
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
static int
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

/* One hash-work op of two legs covers the pair; it stays up for the
 * caller's meter bridge and a worker retires it at unit end. The remote
 * leg goes first because a server without hpn-check-file fails it at
 * once, which spares the local hash. Each leg pauses the watchdog for
 * itself; the resume here ends the last one promptly. A failed leg has
 * already reported itself. */
int
sftp_hpn_prefix_match(struct sftp_conn *conn, int local_fd,
    const char *remote_path, uint64_t length)
{
	uint64_t local_hash, remote_hash;
	int rc = -1;

	sftp_conn_hash_op_begin(conn, 2 * length);
	if (sftp_hpn_hash_remote_file(conn, remote_path, length,
	    &remote_hash) != 0)
		goto out;
	sftp_conn_hash_op_leg(conn, length);
	if (sftp_hpn_xxhash_local_fd(conn, local_fd, length,
	    &local_hash) != 0)
		goto out;
	debug3_f("\"%s\" first %llu bytes: local %016llx remote %016llx",
	    remote_path, (unsigned long long)length,
	    (unsigned long long)local_hash, (unsigned long long)remote_hash);
	rc = local_hash == remote_hash;
out:
	sftp_conn_watchdog_resume(conn);
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
		/* leave the tee disarmed; verify reads the source itself */
		return;
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
	if (hpn == NULL || hpn->verify_src_state == NULL ||
	    hpn->verify_src_failed)
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
	/* the tee did not cover the whole file */
	if (hpn->verify_src_bytes != expect_bytes)
		return -1;
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

/* Progress callback for the read-back hash, in the form
 * sftp_hpn_readback_progress expects: the local leg's cumulative bytes
 * go to the connection's hash-work op. */
static void
verify_readback_progress(void *arg, uint64_t bytes)
{
	sftp_conn_hash_op_progress((struct sftp_conn *)arg, bytes);
}

/* Verify one range [off, off + len) of a file: the local side's hash
 * against the server's sftp-hash-range of the remote side. local_is_target
 * says which path is which: 0 for an upload (local source, remote
 * destination), 1 for a download (local destination, remote source).
 * The local hash is the caller's teed source hash when it has one,
 * otherwise an O_DIRECT read-back of a written destination or a
 * buffered read of a source. Every verify comes through here, the
 * whole-file phase with the whole file as its range and the repair per
 * chunk. Opens the connection's hash-work op for both legs. Returns 0
 * for a match, 1 for a mismatch, or -1 when the range could not be
 * verified, and fills *local_hash_out and *remote_hash_out when they
 * are non-NULL. */
static int
sftp_hpn_verify_chunk(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t off, off_t len, int local_is_target,
    int have_local_hash, uint64_t local_hash,
    uint64_t *local_hash_out, uint64_t *remote_hash_out)
{
	uint64_t remote_hash = 0;
	struct sftp_hash_range range;

	if (len <= 0)
		return -1;
	/* A server without sftp-hash-range cannot verify a range at all, so
	 * bail before the local work. */
	if (!sftp_conn_has_hash_range(conn))
		return -1;

	/* Hash-work op for both legs, in work bytes. The parallel worker ends
	 * it when the unit completes; the serial phase begins the next one
	 * over it. */
	sftp_conn_hash_op_begin(conn, 2 * (uint64_t)len);

	/* Local leg. A teed source hash was paid for by the transfer, so its
	 * leg is credited whole. Otherwise read the range back: O_DIRECT for
	 * a written destination, so the hash reflects the device, buffered
	 * for a source, whose cache already matches the disk and is cheaper
	 * to re-read. */
	if (!have_local_hash) {
		/* pause the watchdog so a long hash doesn't trip it */
		sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
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

	/* Remote leg. */
	range.off = (uint64_t)off;
	range.len = (uint64_t)len;
	sftp_conn_hash_op_leg(conn, (uint64_t)len);
	/* again, pause the watchdog */
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
		/* Direction-blind and fired per chunk per attempt, so debug
		 * only; the callers that know the direction tell the user. */
		debug_f("verify: range [%llu+%llu) of \"%s\" hash mismatch "
		    "(local vs remote)", (unsigned long long)off,
		    (unsigned long long)len, remote_path);
		return 1;
	}
	return 0;
}

/* Reconcile the span [span_off, span_off + span_len) of a file between
 * its two copies: hash it in 64 MiB chunks on both sides, the local
 * copy through local_fd and the remote copy through sftp-hash-range,
 * then move each contiguous run of mismatched chunks in place, with
 * sftp_upload_range when local_is_target is 0 and sftp_download_range
 * when it is 1. The gaps between runs never move. This is the one
 * splice engine behind verified resume, whose span is the whole file,
 * and verify auto-repair, whose span is the mismatched range; label
 * names which for the completion notice. dest_size is the
 * destination's current size: chunks past it cannot match, so they
 * skip both hashes and go straight to the move list. Runs on the serial
 * path and inside a
 * parallel worker; the meter handoff is serial only, since the parallel
 * start zeroes showprogress. Returns 1 when every chunk matched, 0 when
 * every mismatched run moved, or -1 when it declined, for a server
 * without sftp-hash-range or a span under the two-chunk floor, or a
 * hash or transfer failed. A failure mid-run leaves the destination
 * indeterminate, so the caller re-sends the whole span. */
static int
chunked_reconcile_span(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path,
    off_t span_off, off_t span_len, off_t dest_size, int local_is_target,
    const char *label)
{
	struct sftp_hash_range *ranges = NULL;
	uint64_t *local_hashes = NULL;
	uint64_t *remote_hashes = NULL;
	u_char *differs = NULL;
	uint64_t slen, soff, checked_bytes = 0, local_done = 0;
	uint64_t remote_done = 0, refetch_total = 0, bytes_moved = 0;
	volatile uint64_t live_ctr = 0;
	const char *moving = local_is_target ? "re-fetching"
	    : "re-transferring";
	const char *moved = local_is_target ? "re-fetched" : "re-transferred";
	u_int n_chunks, n_check, n_mismatched = 0;
	u_int i, j, batch;
	int meter_on = 0;
	int rc = -1;

	if (local_fd < 0 || span_len <= 0)
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
	ranges = calloc(n_chunks, sizeof(*ranges));
	local_hashes = calloc(n_chunks, sizeof(*local_hashes));
	remote_hashes = calloc(n_chunks, sizeof(*remote_hashes));
	differs = calloc(n_chunks, sizeof(*differs));
	if (ranges == NULL || local_hashes == NULL || remote_hashes == NULL ||
	    differs == NULL) {
		error_f("calloc for %u chunks failed", n_chunks);
		goto out;
	}

	/* Lay the chunks over the span. The last one clamps to the span end,
	 * as the server clamps its hash, so the two line up. */
	for (i = 0; i < n_chunks; i++) {
		uint64_t off = soff + (uint64_t)i * CHUNK_HASH_CHUNK_SIZE;
		uint64_t remain = (soff + slen) - off;

		ranges[i].off = off;
		ranges[i].len = remain < CHUNK_HASH_CHUNK_SIZE
		    ? remain : CHUNK_HASH_CHUNK_SIZE;
	}

	/* Destination EOF clamp. The destination hashes only up to its EOF,
	 * so a chunk that straddles or lies past it cannot match: skip its
	 * hash on both sides and send it straight to the move list. The
	 * chunks are ordered, so the checked set is the prefix [0, n_check)
	 * and its byte count sizes the hash-work op. */
	n_check = n_chunks;
	for (i = 0; i < n_chunks; i++) {
		if (ranges[i].off + ranges[i].len > (uint64_t)dest_size) {
			n_check = i;
			break;
		}
	}
	if (n_check < n_chunks)
		debug_f("dest-EOF clamp for \"%s\": checking %u/%u "
		    "chunks (dest size %llu); %u known-missing",
		    local_path, n_check, n_chunks,
		    (unsigned long long)dest_size, n_chunks - n_check);
	for (i = 0; i < n_check; i++)
		checked_bytes += ranges[i].len;

	/* Pause the watchdog for both hash legs; every exit below resumes
	 * it. The hash-work op goes up now as well: the local leg is
	 * byte-silent for as long as it runs, and the op's marker is what
	 * holds off the watchdog's throughput streaks, which never consult
	 * the pause, and covers the tail after the resume. The local helper
	 * and the remote heartbeats refresh both as they go. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	sftp_conn_hash_op_begin(conn, 2 * checked_bytes);

	/* Local leg. The notices say which copy is being hashed; both are
	 * worded for resume and repair alike and skipped when the clamp
	 * left nothing to hash. The helper reports its own progress; the
	 * report here covers a chunk too short to trigger one. */
	if (n_check > 0)
		logit("hashing the local copy of \"%s\"", local_path);
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

	/* Remote leg, in batches of at most SFTP_HASH_RANGE_MAX_RANGES, the
	 * per-request bound. Each batch is all or nothing and the helper
	 * warns the user on a failure. The server's heartbeats count from
	 * zero for each request, so the leg base moves up by the batches
	 * already done and the op stays monotone. */
	if (n_check > 0)
		logit("hashing the remote copy of \"%s\"", remote_path);
	for (i = 0; i < n_check; i += batch) {
		batch = n_check - i;
		if (batch > SFTP_HASH_RANGE_MAX_RANGES)
			batch = SFTP_HASH_RANGE_MAX_RANGES;
		sftp_conn_hash_op_leg(conn, checked_bytes + remote_done);
		if (sftp_hpn_hash_remote_ranges(conn, remote_path,
		    local_is_target, &ranges[i], batch,
		    &remote_hashes[i]) != 0) {
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
		for (j = i; j < i + batch; j++)
			remote_done += ranges[j].len;
	}
	sftp_conn_watchdog_resume(conn);

	/* A chunk moves when its hashes differ, or when it lies past the
	 * checked prefix and was never hashed. */
	for (i = 0; i < n_chunks; i++) {
		differs[i] = i >= n_check ||
		    local_hashes[i] != remote_hashes[i];
		if (differs[i]) {
			n_mismatched++;
			refetch_total += ranges[i].len;
		}
	}
	if (n_mismatched == 0) {
		debug_f("all %u chunks of span match, \"%s\" already current",
		    n_chunks, local_path);
		rc = 1;
		goto out;
	}

	/* Hand the display from the resume-check meter to a transfer meter.
	 * The hash work is done, and left up that meter would sit at its
	 * final figure for the whole move while gigabytes pass. The range
	 * transfers bump the connection's live counter, so this meter
	 * ticks with the bytes moved and completes with them. The live
	 * counter is a volatile uint64_t and the meter takes an off_t, the
	 * same width, and byte counts stay far below the sign bit. */
	if (showprogress) {
		const char *target = local_is_target ? local_path : remote_path;
		const char *base = strrchr(target, '/');

		hpn_meter_stop(hpn_meter_serial(), conn);
		if (hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_FILE,
		    HPN_METER_DOM_TRANSFER, base != NULL ? base + 1 : target,
		    (off_t)refetch_total, (off_t *)&live_ctr, 1) == 0) {
			sftp_conn_set_live_counter(conn, &live_ctr);
			meter_on = 1;
		}
	}

	/* Move the mismatched chunks, one range transfer per contiguous run.
	 * Each run is written at its offset, so the copy keeps its size and
	 * the matched chunks stay untouched. The first failed run ends the
	 * pass, and the caller re-sends the whole span. */
	i = 0;
	while (i < n_chunks) {
		u_int run_start;
		uint64_t run_off, run_len;
		int r;

		if (!differs[i]) {
			i++;
			continue;
		}
		run_start = i;
		while (i < n_chunks && differs[i])
			i++;
		run_off = ranges[run_start].off;
		run_len = (ranges[i - 1].off + ranges[i - 1].len) - run_off;

		debug3_f("%s chunks [%u, %u) at offset %llu length %llu for "
		    "\"%s\"", moving, run_start, i, (unsigned long long)run_off,
		    (unsigned long long)run_len, local_path);
		if (local_is_target)
			r = sftp_download_range(conn, remote_path, local_path,
			    (off_t)run_off, (off_t)run_len, NULL);
		else
			r = sftp_upload_range(conn, local_path, remote_path,
			    (off_t)run_off, (off_t)run_len, NULL, NULL, NULL);
		if (r != 0) {
			/* A dead connection is worker churn that the caller's
			 * fallback retries; only a failure on a live one needs
			 * the user's attention. */
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

	logit("%s \"%s\": %s %u/%u chunks (%u hashed, %u known-missing past "
	    "dest EOF; %llu / %llu bytes, %.1f%% of span)", label, local_path,
	    moved, n_mismatched, n_chunks, n_check, n_chunks - n_check,
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
	free(differs);
	return rc;
}

/* Verified resume of an upload: the local file is the source and the
 * remote one the destination. The header states the contract. */
int
sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size)
{
	return chunked_reconcile_span(conn, local_fd, local_path, remote_path,
	    0, file_size, dest_size, /*local_is_target=*/0, "verified resume");
}

/* Verified resume of a download: the remote file is the source and the
 * local one the destination. The header states the contract. */
int
sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size)
{
	return chunked_reconcile_span(conn, local_fd, local_path, remote_path,
	    0, file_size, dest_size, /*local_is_target=*/1, "verified resume");
}

/* Repair is on unless the token turned it off, and the attempt cap is
 * the fixed VERIFY_REPAIR_ATTEMPTS. */
void
sftp_hpn_verify_repair_resolve(int no_verify_repair_cli, int *enabled_out,
    int *attempts_out)
{
	*enabled_out = !no_verify_repair_cli;
	*attempts_out = VERIFY_REPAIR_ATTEMPTS;
}

/* One repair pass over the span [span_off, span_off + span_len). A span
 * at or above the two-chunk floor goes through the chunked engine, which
 * moves only the runs that differ; a smaller span, or one the engine
 * declined or failed, moves whole. Either way the bytes land at their
 * offsets and nothing is truncated. Returns 0 when a pass ran, so the
 * caller re-verifies, or -1 on a transfer error. */
static int
verify_repair_one_pass(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t span_off,
    off_t span_len)
{
	int rc;

	/* The floor check here saves opening the file for a span the engine
	 * would decline anyway. */
	if (span_len >= (off_t)CHUNK_HASH_MIN_FILE_SIZE) {
		int fd = open(local_path, O_RDONLY);

		if (fd == -1) {
			error_f("open local \"%s\": %s", local_path,
			    strerror(errno));
			return -1;
		}
		/* the whole-file check found equal sizes, so the destination
		 * holds at least the span */
		rc = chunked_reconcile_span(conn, fd, local_path, remote_path,
		    span_off, span_len, /*dest_size=*/span_off + span_len,
		    local_is_target, "verify repair");
		close(fd);
		/* 1 or 0 means a pass ran; -1 means the engine declined or
		 * failed and the whole span moves instead. */
		if (rc >= 0)
			return 0;
	}

	/* Whole-span move. */
	if (local_is_target)
		rc = sftp_download_range(conn, remote_path, local_path,
		    span_off, span_len, NULL);
	else
		rc = sftp_upload_range(conn, local_path, remote_path,
		    span_off, span_len, NULL, NULL, NULL);
	return rc;
}

/* Verify, then repair and re-verify up to max_attempts times. The first
 * verify may use the caller's teed source hash; every re-verify reads
 * the destination back from disk. Two identical failed destination
 * hashes in a row mean the repair keeps writing the same bad bytes, so
 * the loop stops early; so does a SIGINT between attempts, leaving the
 * range as the last attempt wrote it. */
int
sftp_hpn_verify_repair_range(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t off, off_t len,
    int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out)
{
	uint64_t local_now = 0, remote_now = 0, dest_hash, prev_hash;
	const char *side, *dst;
	int r, attempt;

	/* nothing repaired yet */
	if (repaired_out != NULL)
		*repaired_out = 0;

	/* text used in notifications */
	side = local_is_target ? "local" : "remote";
	/* where the target lives */
	dst = local_is_target ? local_path : remote_path;

	/* first verify, with the teed source hash when the caller has one */
	r = sftp_hpn_verify_chunk(conn, local_path, remote_path, off, len,
	    local_is_target, have_local_hash, local_hash, &local_now,
	    &remote_now);
	/* 0 is verified, -1 is unverifiable */
	if (r != 1)
		return r;
	/* a mismatch with repair off */
	if (!repair_enabled)
		return 1;

	/* the destination's hash before repair, for the convergence check */
	dest_hash = local_is_target ? local_now : remote_now;
	prev_hash = dest_hash;
	logit("Repairing %s file \"%s\" (verify mismatch)...", side, dst);

	/* repair, re-verify, repeat up to the cap */
	for (attempt = 1; attempt <= max_attempts; attempt++) {
		/* stop on Ctrl-C between attempts */
		if (interrupted) {
			logit("repair of %s file \"%s\" interrupted",
			    side, dst);
			return 1;
		}
		/* re-send the span, chunked or whole */
		if (verify_repair_one_pass(conn, local_path, remote_path,
		    local_is_target, off, len) != 0) {
			error_f("repair re-transfer failed for \"%s\"", dst);
			return 1;
		}
		/* re-verify from disk, no teed hash on this path */
		r = sftp_hpn_verify_chunk(conn, local_path, remote_path, off,
		    len, local_is_target, /*have_local_hash=*/0, 0,
		    &local_now, &remote_now);
		/* repaired */
		if (r == 0) {
			logit("repaired %s file \"%s\" (attempt %d)",
			    side, dst, attempt);
			if (repaired_out != NULL)
				*repaired_out = 1;
			return 0;
		}
		/* An attempt that could not be re-verified, a transient read
		 * or extension problem, just uses up an attempt. */
		if (r < 0)
			continue;
		/* the same bad bytes as last time: a deterministic fault */
		dest_hash = local_is_target ? local_now : remote_now;
		if (dest_hash == prev_hash) {
			error_f("%s file \"%s\": two identical failed hashes "
			    "in a row, a deterministic fault, not retrying",
			    side, dst);
			return 1;
		}
		prev_hash = dest_hash;
	}
	/* out of attempts */
	if (r < 0)
		error_f("%s file \"%s\": could not re-verify after %d repair "
		    "attempt(s)", side, dst, max_attempts);
	else
		error_f("%s file \"%s\": still corrupt after %d repair "
		    "attempt(s), possible storage or media fault",
		    side, dst, max_attempts);
	return 1;
}

/* Stat both ends and compare the sizes before any hashing: each side
 * would hash [0, len) from one size, so a shorter or longer destination
 * would otherwise pass. An empty pair matches without hashing. Otherwise
 * the whole file goes to the range form. */
int
sftp_hpn_verify_repair_file(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, int have_local_hash,
    uint64_t local_hash, int repair_enabled, int max_attempts,
    int *repaired_out)
{
	struct stat sb;
	Attrib ra;
	off_t remote_size;

	if (repaired_out != NULL)
		*repaired_out = 0;
	/* local size */
	if (stat(local_path, &sb) == -1) {
		error_f("stat \"%s\": %s", local_path, strerror(errno));
		return -1;
	}
	/* remote size; without it nothing can be verified */
	if (sftp_stat(conn, remote_path, 1, &ra) != 0 ||
	    (ra.flags & SSH2_FILEXFER_ATTR_SIZE) == 0) {
		error_f("verify \"%s\": cannot determine remote size",
		    remote_path);
		return -1;
	}
	remote_size = (off_t)ra.size;
	/* sizes don't match, we can't repair in place */
	if (sb.st_size != remote_size) {
		logit("verify: \"%s\" size mismatch (local %lld, remote %lld)",
		    local_is_target ? local_path : remote_path,
		    (long long)sb.st_size, (long long)remote_size);
		return 1;
	}
	/* empty file on both ends */
	if (sb.st_size == 0)
		return 0;
	return sftp_hpn_verify_repair_range(conn, local_path, remote_path,
	    local_is_target, 0, sb.st_size, have_local_hash, local_hash,
	    repair_enabled, max_attempts, repaired_out);
}

/* Per-connection verify state, declared in sftp-client-internal.h. The
 * upstream files and the parallel code reach it only through these. Each
 * no-ops on a NULL connection, like every accessor in sftp-hpn-client.c. */

/* Set whether the post-transfer verify phase runs: at startup from -V in
 * both clients, per command by the interactive toggle in sftp.c, and on
 * each respawned worker connection, which the fleet must tell itself. */
void
sftp_conn_set_verify_transfer(struct sftp_conn *conn, int enabled)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->verify_transfer_enabled = enabled ? 1 : 0;
}

/* Whether the post-transfer verify phase runs. Gates the inline source
 * hash tee and the parking of transferred files for the phase. */
int
sftp_conn_verify_transfer_enabled(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->verify_transfer_enabled;
}

/* Set the auto-repair settings for the single-connection verify phase,
 * as sftp_hpn_verify_repair_resolve produced them; the fleet keeps its
 * own copy. The attempt cap is held at one or more. */
void
sftp_conn_set_verify_repair(struct sftp_conn *conn, int enabled, int attempts)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->verify_repair_enabled = enabled ? 1 : 0;
	hpn->verify_repair_attempts = attempts < 1 ? 1 : attempts;
}

/* Grow the pending list as needed and append one entry. The list is the
 * price of verifying after every transfer instead of stalling each file
 * on a round trip; sftp_conn_verify_run_phase drains it. */
static void
verify_park_entry(struct sftp_hpn_conn *hpn, const char *local_path,
    const char *remote_path, int local_is_target, int have_src_hash,
    uint64_t src_hash)
{
	struct sftp_verify_pending_entry *entry;

	if (hpn->verify_pending_count >= hpn->verify_pending_cap) {
		int newcap = hpn->verify_pending_cap ?
		    hpn->verify_pending_cap * 2 : 64;
		hpn->verify_pending = xreallocarray(hpn->verify_pending, newcap,
		    sizeof(*hpn->verify_pending));
		hpn->verify_pending_cap = newcap;
	}
	entry = &hpn->verify_pending[hpn->verify_pending_count++];
	entry->local_path = xstrdup(local_path);
	entry->remote_path = xstrdup(remote_path);
	entry->local_is_target = local_is_target;
	entry->have_src_hash = have_src_hash;
	entry->src_hash = have_src_hash ? src_hash : 0;
}

/* Park a just-transferred file for the post-transfer verify phase, at
 * the end of sftp_upload and sftp_download and per member of a serial
 * bundle download. No-op unless verify is on, and on a worker
 * connection, whose fleet verifies for itself; the registered live
 * counter marks those. An upload whose inline source hash covered all
 * size bytes takes that hash along so the phase can skip the local
 * read. */
void
sftp_conn_verify_park(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int local_is_target, off_t size)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t src_hash = 0;
	int have_src_hash;

	if (hpn == NULL || !hpn->verify_transfer_enabled ||
	    hpn->live_counter != NULL)
		return;
	/* only an upload has a teed source hash to take */
	have_src_hash = !local_is_target &&
	    sftp_hpn_src_take(hpn, (uint64_t)size, &src_hash) == 0;
	verify_park_entry(hpn, local_path, remote_path, local_is_target,
	    have_src_hash, src_hash);
}

/* The serial bundle upload's form, per member: the source hash comes
 * from the bundle writer rather than the connection's tee slot. */
void
sftp_conn_verify_park_hashed(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, int have_src_hash, uint64_t src_hash)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL || !hpn->verify_transfer_enabled ||
	    hpn->live_counter != NULL)
		return;
	verify_park_entry(hpn, local_path, remote_path, /*local_is_target=*/0,
	    have_src_hash, src_hash);
}

/* Files parked for the post-transfer verify phase, so the caller can
 * announce "Verifying N file(s)" before sftp_conn_verify_run_phase. */
int
sftp_conn_verify_pending_count(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return hpn->verify_pending_count;
}

/* Hand the verify phase's failed paths to the caller, who owns the array
 * and its strings from then on, and empty the connection's list. The
 * parallel path has sftp_parallel_drain_verify_failures in the same
 * shape, so sftp.c and scp.c fold both into one summary and exit code.
 * Returns the count. */
int
sftp_conn_drain_verify_failures(struct sftp_conn *conn, char ***out_paths,
    int *out_used)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL) {
		*out_paths = NULL;
		*out_used = 0;
		return 0;
	}
	*out_paths = hpn->verify_failed_paths;
	*out_used = hpn->verify_failed_count;
	hpn->verify_failed_paths = NULL;
	hpn->verify_failed_count = 0;
	return *out_used;
}

/* The post-transfer verify phase of a single connection: verify every
 * file parked during the command, repairing as configured, then clear
 * the list. The fleet has its own phase on the same engine. An upload's
 * teed source hash rides in its entry, so only files without one are
 * read locally. Each file's outcome goes to the transfer log, and a
 * mismatch is recorded on the connection for the run summary and the
 * SFTP_EX_VERIFY_FAILED exit; it does not fail the transfer. A SIGINT
 * stops the verifying but not the walk, so the list is freed either
 * way. No-op when nothing was parked. */
void
sftp_conn_verify_run_phase(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	off_t total = 0, counter = 0;
	int i, meter_on = 0;
	struct stat sb;

	debug_f("verify phase: %d file(s) parked",
	    hpn == NULL ? 0 : hpn->verify_pending_count);
	if (hpn == NULL || hpn->verify_pending_count == 0)
		return;

	/* size each file for the meter; both ends hash every byte, so the
	 * meter counts work bytes, twice the file */
	for (i = 0; i < hpn->verify_pending_count; i++) {
		hpn->verify_pending[i].size =
		    stat(hpn->verify_pending[i].local_path, &sb) == 0 ?
		    sb.st_size : 0;
		total += 2 * hpn->verify_pending[i].size;
	}
	/* a work meter in the work-byte domain: the meter core does not
	 * count it as a file and raises the verify phase flag */
	if (showprogress && total > 0) {
		hpn_meter_start(hpn_meter_serial(), conn, HPN_METER_WORK,
		    HPN_METER_DOM_WORK, "verify", total, &counter, 0);
		/* the engines' per-op progress lands on the meter counter, so
		 * one big file moves smoothly instead of jumping at the end */
		sftp_conn_set_hash_meter_ctr(conn, &counter);
		meter_on = 1;
	}

	for (i = 0; i < hpn->verify_pending_count; i++) {
		struct sftp_verify_pending_entry *entry =
		    &hpn->verify_pending[i];

		if (!interrupted) {
			int repaired = 0;
			/* the whole-file form compares the sizes first */
			int rc = sftp_hpn_verify_repair_file(conn,
			    entry->local_path, entry->remote_path,
			    entry->local_is_target, entry->have_src_hash,
			    entry->src_hash, hpn->verify_repair_enabled,
			    hpn->verify_repair_attempts, &repaired);

			/* the transfer log line was held back for this final
			 * status; unverifiable still transferred fine */
			if (transferlog_active()) {
				enum transferlog_status st;

				if (rc == 1)
					st = TRANSFERLOG_FAILED;
				else if (rc < 0)
					st = TRANSFERLOG_SUCCESS;
				else
					st = repaired ? TRANSFERLOG_REPAIRED :
					    TRANSFERLOG_VERIFIED;
				transferlog_file(st, (long long)entry->size,
				    entry->local_is_target ? entry->local_path :
				    entry->remote_path);
			}
			/* a mismatch is recorded for the drain at exit */
			if (rc == 1) {
				error("VERIFY FAILED: \"%s\" (post-transfer "
				    "hash mismatch - the transferred file does "
				    "NOT match the source)",
				    entry->remote_path);
				hpn->verify_failed_paths = xreallocarray(
				    hpn->verify_failed_paths,
				    hpn->verify_failed_count + 1,
				    sizeof(*hpn->verify_failed_paths));
				hpn->verify_failed_paths[
				    hpn->verify_failed_count++] =
				    xstrdup(entry->remote_path);
			} else if (rc < 0) {
				logit("VERIFY SKIPPED: \"%s\": could not "
				    "verify (no hpn-check-file@hpnssh.org on "
				    "the server, or a read error)",
				    entry->remote_path);
			}
			/* fold this file's work into the meter base so the
			 * next file's progress continues from it */
			sftp_conn_hash_meter_base_add(conn,
			    2 * (uint64_t)entry->size);
		}
		free(entry->local_path);
		free(entry->remote_path);
	}
	if (meter_on) {
		sftp_conn_set_hash_meter_ctr(conn, NULL);
		hpn_meter_stop(hpn_meter_serial(), conn);
	}
	hpn->verify_pending_count = 0;
}
