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
 * sftp-hpn-verify.c - client-side verification and verified resume for
 * HPN-SSH: local XXH3 hashing (whole-file and per-range), the remote
 * hash extensions (hpn-check-file, sftp-hash-range) with their
 * heartbeat/progress stall detection, post-transfer verification, and
 * the chunked verified-resume orchestration for reput/reget.
 *
 * This file is the landing zone for future verify work: parallel hole
 * refill (feed missing-chunk runs to the range machinery), chunk-
 * parallel server hashing, and streaming verify.  See the project
 * notes for the cost taxonomy (avoid / parallelize / overlap).
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
#define XXH_INLINE_ALL
#include "xxhash.h"

/*
 * SIGINT flag, defined in sftp.c (hpnsftp) and scp.c (hpnscp) - both binaries
 * that link this object provide it, and both set it from their SIGINT handler
 * in either the classic or the parallel context.  The auto-repair loop polls
 * it so a multi-attempt repair bails promptly on Ctrl-C instead of grinding
 * through the remaining attempts.
 */
extern _Atomic sig_atomic_t interrupted;

/* ── BEGIN sftp-hash-range: client-side helpers ───────────────────────────
 *
 * Helpers for chunked resume.  See sftp-hpn-client.h for the public API
 * and the design rationale at project_chunked_resume_plan.md in memory.
 *
 * sftp_hpn_xxhash_local_range - local XXH3 over an open fd's range
 * sftp_hpn_hash_remote_ranges  - wire-level sftp-hash-range@hpnssh.org query
 */

#define HASH_RANGE_READ_BUF_LEN	65536U

#include "sftp.h"
#include "sftp-client-internal.h"

/*
 * Tunables for chunked resume.  Defaults chosen per the locked design
 * (project_chunked_resume_plan.md memory):
 *
 *  CHUNK_HASH_CHUNK_SIZE       - granularity of re-transfer.  64 MiB makes
 *                                per-chunk protocol overhead (16 B request,
 *                                8 B response) negligible vs. typical
 *                                missed-chunk transfer cost.
 *  CHUNK_HASH_MIN_FILE_SIZE    - below this, skip the chunked path; the
 *                                full-file hash gate is cheaper than the
 *                                chunked-request round trip on small files.
 *                                Chosen as 2 * CHUNK_SIZE so any engaged
 *                                run has at least two chunks to map.
 *  CHUNK_HASH_MAX_RANGES_PER_REQUEST
 *                              - must match server-side cap in
 *                                sftp-hpn-server.c (SFTP_HASH_RANGE_MAX_RANGES).
 *                                Bounds server-side allocation against an
 *                                unbounded request; the server allocates
 *                                N range + N hash entries up front.  At
 *                                64 MiB chunks this also caps single-file
 *                                chunked-resume at 4 TiB; bigger files
 *                                decline and fall through to the existing
 *                                full-file gate.
 */
#define CHUNK_HASH_CHUNK_SIZE			((u_int64_t)(64ULL * 1024ULL * 1024ULL))
#define CHUNK_HASH_MIN_FILE_SIZE		((u_int64_t)(2ULL * CHUNK_HASH_CHUNK_SIZE))
#define CHUNK_HASH_MAX_RANGES_PER_REQUEST	65536U

int
sftp_hpn_xxhash_local_range(int fd, u_int64_t offset, u_int64_t length,
    u_int64_t *hash_out)
{
	XXH3_state_t	*state;
	u_char		 buf[HASH_RANGE_READ_BUF_LEN];
	u_int64_t	 remaining;
	ssize_t		 nread;

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
		XXH3_freeState(state);
		return -1;
	}

	if (length > 0 && lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
		error_f("lseek to %llu: %s",
		    (unsigned long long)offset, strerror(errno));
		XXH3_freeState(state);
		return -1;
	}

	remaining = length;
	while (remaining > 0) {
		size_t toread = (size_t)MINIMUM(
		    (u_int64_t)sizeof(buf), remaining);
		nread = read(fd, buf, toread);
		if (nread == 0)
			break;	/* short read - caller may treat as
				 * truncated; we hash what we got */
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			error_f("read at offset %llu: %s",
			    (unsigned long long)offset, strerror(errno));
			XXH3_freeState(state);
			return -1;
		}
		if (XXH3_64bits_update(state, buf, (size_t)nread)
		    == XXH_ERROR) {
			error_f("XXH3_64bits_update failed");
			XXH3_freeState(state);
			return -1;
		}
		remaining -= (u_int64_t)nread;
	}

	*hash_out = (u_int64_t)XXH3_64bits_digest(state);
	XXH3_freeState(state);
	return 0;
}

/*
 * Hash the first 'length' bytes of an already-open local file using
 * XXH3_64bits (streaming API).  Seeks to offset 0 before reading.
 * Returns 0 and writes the hash to *hash_out on success, -1 on error.
 */
int
sftp_hpn_xxhash_local_fd(struct sftp_conn *conn, int fd, uint64_t length,
    uint64_t *hash_out)
{
	XXH3_state_t *state;
	XXH64_hash_t hash;
	u_char buf[65536];
	uint64_t remaining = length;
	ssize_t nread;
	off_t pos_before;

	pos_before = lseek(fd, 0, SEEK_CUR);
	debug3_f("local fd=%d length=%llu fd_pos_before=%lld",
	    fd, (unsigned long long)length, (long long)pos_before);

	if (lseek(fd, 0, SEEK_SET) == -1) {
		error_f("lseek failed: %s", strerror(errno));
		return -1;
	}

	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		return -1;
	}
	if (XXH3_64bits_reset(state) == XXH_ERROR) {
		error_f("XXH3_64bits_reset failed");
		XXH3_freeState(state);
		return -1;
	}

	uint64_t since_refresh = 0;

	while (remaining > 0) {
		size_t toread = (size_t)MINIMUM((uint64_t)sizeof(buf), remaining);

		/* Hashing a large file is minutes of byte-silence; a single
		 * pause window before the call expires mid-hash and the
		 * watchdog/endgame reaper kills a worker that is working.
		 * Refresh every 64 MiB hashed (the helper is cheap). */
		since_refresh += toread;
		if (conn != NULL && since_refresh >= (64ULL << 20)) {
			sftp_conn_watchdog_pause(conn,
			    HPN_HEARTBEAT_REFRESH_SEC);
			since_refresh = 0;
		}
		nread = read(fd, buf, toread);
		if (nread == 0)
			break; /* EOF before length bytes */
		if (nread < 0) {
			error_f("read failed: %s", strerror(errno));
			XXH3_freeState(state);
			(void)lseek(fd, pos_before, SEEK_SET);
			return -1;
		}
		if (XXH3_64bits_update(state, buf, (size_t)nread) == XXH_ERROR) {
			error_f("XXH3_64bits_update failed");
			XXH3_freeState(state);
			(void)lseek(fd, pos_before, SEEK_SET);
			return -1;
		}
		remaining -= (uint64_t)nread;
	}
	hash = XXH3_64bits_digest(state);
	XXH3_freeState(state);
	*hash_out = (uint64_t)hash;
	debug3_f("local hash of first %llu bytes: %016llx",
	    (unsigned long long)length, (unsigned long long)*hash_out);
	if (lseek(fd, pos_before, SEEK_SET) == -1)
		error_f("lseek restore failed: %s", strerror(errno));
	return 0;
}

/*
 * Request that the sender's sftp-server compute a XXH3_64bits hash of the
 * first 'length' bytes of 'path' using the hpn-check-file@hpnssh.org
 * extension.  Returns 0 and writes the hash value to *hash_out on success,
 * or -1 if the extension is unavailable or an error occurred.
 */
int
sftp_hpn_hash_remote_file(struct sftp_conn *conn, const char *path,
    uint64_t length, uint64_t *hash_out)
{
	struct sshbuf *msg;
	u_int id, rid;
	u_char type;
	int r;

	/* Check the extension before allocating msg, so the unsupported-server
	 * path does not leak an sshbuf (this is called per file). */
	if (!sftp_conn_has_hpn_check_file(conn)) {
		debug_f("server does not support hpn-check-file extension");
		return -1;
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending hpn-check-file for \"%s\" length=%llu id=%u",
	    path, (unsigned long long)length, id);
	sshbuf_reset(msg);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "hpn-check-file@hpnssh.org")) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u64(msg, length)) != 0)
		fatal_fr(r, "compose");
	send_msg(conn, msg);

	/*
	 * Initial watchdog grace covers worker time spent here before the
	 * first server heartbeat lands.  Each heartbeat received below
	 * refreshes the pause for another HPN_HEARTBEAT_REFRESH_SEC, so the
	 * orchestrator never kills us while the server is making forward
	 * progress.  See sftp-hpn-server.h for the protocol.
	 */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	/* Resume-check UX: mark the hash op so the reporter/meter can show
	 * "hashing N bytes"; heartbeats below refresh the stamp. */
	sftp_conn_hash_op_mark(conn, length);

	/* Heartbeats renew the lease (liveness) but carry a progress
	 * figure precisely because liveness is not enough: a stalled
	 * backend can heartbeat forever.  No advance for the threshold
	 * means the connection is treated as failed. */
	uint64_t hb_prog_last = 0;
	time_t hb_advance_sec = monotime();

	for (;;) {
		if (get_msg(conn, msg) != 0) {
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			/* A malformed reply must not abort the client - fatal
			 * here crashes the whole orchestrator when this is one
			 * of N parallel workers.  Mark the conn dead and return
			 * -1, matching the ID-mismatch / wrong-type cases below. */
			sftp_conn_die(conn, "hpn-check-file \"%s\": parse reply "
			    "header: %s", path, ssh_err(r));
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		}
		debug3_f("got response type=%u rid=%u (expected id=%u)",
		    type, rid, id);
		if (rid != id) {
			/* Was fatal("ID mismatch (%u != %u)", rid, id); -
			 * would crash the entire orchestrator if this
			 * worker is one of N in a parallel-streams
			 * transfer.  Mark the connection dead and let the
			 * caller's resume / verify path observe -1. */
			sftp_conn_die(conn,
			    "hpn-check-file ID mismatch (%u != %u)",
			    rid, id);
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		}

		if (type == SSH2_FXP_STATUS) {
			u_int status;
			char *errmsg = NULL;

			if ((r = sshbuf_get_u32(msg, &status)) != 0) {
				sftp_conn_die(conn, "hpn-check-file \"%s\": "
				    "parse status: %s", path, ssh_err(r));
				sftp_conn_watchdog_resume(conn);
				sshbuf_free(msg);
			return -1;
			}
			/* consume error-message and language-tag to leave
			 * msg clean */
			(void)sshbuf_get_cstring(msg, &errmsg, NULL);
			(void)sshbuf_get_cstring(msg, NULL, NULL);
			error("hpn-check-file \"%s\": %s", path,
			    (errmsg != NULL && *errmsg != '\0')
			    ? errmsg : fx2txt(status));
			debug3_f("server returned status %u for \"%s\"",
			    status, path);
			free(errmsg);
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		} else if (type != SSH2_FXP_EXTENDED_REPLY) {
			/* Was fatal("Expected SSH2_FXP_EXTENDED_REPLY ...");
			 * - would crash the entire orchestrator if this
			 * worker is one of N in a parallel-streams
			 * transfer.  Mark the connection dead and let the
			 * caller's resume / verify path observe -1. */
			sftp_conn_die(conn,
			    "hpn-check-file: expected "
			    "SSH2_FXP_EXTENDED_REPLY(%u) packet, got %u",
			    SSH2_FXP_EXTENDED_REPLY, type);
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		}

		if ((r = sshbuf_get_u64(msg, hash_out)) != 0) {
			sftp_conn_die(conn, "hpn-check-file \"%s\": parse hash: "
			    "%s", path, ssh_err(r));
			sftp_conn_watchdog_resume(conn);
			sshbuf_free(msg);
		return -1;
		}

		/*
		 * Heartbeat reply: refresh the watchdog pause and wait for
		 * the next message.  Real hash values never collide with
		 * the sentinel (probability 1/2^64).
		 */
		if (*hash_out == HPN_HASH_CHECK_FILE_HEARTBEAT) {
			uint64_t hb_prog = 0;
			time_t hb_now = monotime();

			if ((r = sshbuf_get_u64(msg, &hb_prog)) != 0)
				hb_prog = hb_prog_last; /* treat as no advance */
			debug3_f("hpn-check-file heartbeat for \"%s\" id=%u "
			    "progress=%llu", path, id,
			    (unsigned long long)hb_prog);
			/* Feed the verify progress meter: server bytes hashed. */
			sftp_conn_verify_inflight_set(conn, hb_prog);
			/* Refresh the hash-op marker + serial meter feed. */
			sftp_conn_hash_op_mark(conn, length);
			sftp_conn_hash_meter_feed(conn, hb_prog);
			if (hb_prog > hb_prog_last) {
				hb_prog_last = hb_prog;
				hb_advance_sec = hb_now;
			} else if (hb_now - hb_advance_sec >=
			    (time_t)HPN_VERIFY_PROGRESS_STALL_SEC) {
				sftp_conn_die(conn, "hpn-check-file \"%s\": "
				    "server hash made no progress for %d "
				    "seconds (stalled backend); treating "
				    "connection as failed",
				    path, (int)HPN_VERIFY_PROGRESS_STALL_SEC);
				sftp_conn_watchdog_resume(conn);
				sshbuf_free(msg);
		return -1;
			}
			sftp_conn_watchdog_pause(conn,
			    HPN_HEARTBEAT_REFRESH_SEC);
			continue;
		}

		debug3_f("remote hash of \"%s\" first %llu bytes: %016llx",
		    path, (unsigned long long)length,
		    (unsigned long long)*hash_out);
		sftp_conn_watchdog_resume(conn);
		sshbuf_free(msg);
		return 0;
	}
}

/*
 * ── Inline source-hash accumulator (HPNVerifyTransfer 1b) ────────────────
 * The upload reads the whole source to send it; rather than re-read the
 * source a second time at verify, we tee those bytes into a streaming XXH3
 * as they are read.  State lives on conn->hpn so it survives from the upload
 * call to the separate post-transfer verify call.  All entry points are
 * no-ops when not armed or hpn==NULL, so the disabled hot path is untouched.
 */
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

/*
 * Verify ONE byte range [off, off+len) of a file: O_DIRECT read-back hash of the
 * local range vs the server's sftp-hash-range of the remote range, compared.
 * Direction-agnostic - the caller picks which path is local vs remote (upload:
 * local=source, remote=dest; download: local=dest, remote=source).  Used by the
 * range-granular parallel verify, where one large file's chunks are spread
 * across the worker pool.  Returns 0 = match, 1 = MISMATCH (corruption), -1 =
 * could not verify (local read error or server hash-range failure).
 */
int
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

	/*
	 * Local range hash.  When have_local_hash is set (an upload range whose
	 * source XXH3 was teed during the transfer) re-use it - no re-read.
	 * Otherwise read the local range back from disk (download dest, or an
	 * untee'd upload range).
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
		    NULL, NULL) != 0) {
			error_f("verify: local range hash failed at %llu+%llu "
			    "for \"%s\"", (unsigned long long)off,
			    (unsigned long long)len, local_path);
			sftp_conn_watchdog_resume(conn);
			return -1;
		}
		sftp_conn_watchdog_resume(conn);
	}

	range.off = (uint64_t)off;
	range.len = (uint64_t)len;
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	if (sftp_hpn_hash_remote_ranges(conn, remote_path, &range, 1,
	    &remote_hash) != 0) {
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

int
sftp_hpn_hash_remote_ranges(struct sftp_conn *conn, const char *path,
    const struct sftp_hash_range *ranges, u_int n, u_int64_t *hashes_out)
{
	struct sshbuf	*msg = NULL;
	u_int		 id, rid, num_hashes, i;
	u_char		 type;
	int		 r;
	int		 rc = -1;

	if (conn == NULL || path == NULL || ranges == NULL ||
	    hashes_out == NULL || n == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!sftp_conn_has_hash_range(conn)) {
		/*
		 * Expected condition when talking to a pre-19.0 server;
		 * the caller will fall through to hpn-check-file whole-file
		 * hashing.  Keep at debug level so it doesn't spam users.
		 */
		debug_f("server lacks sftp-hash-range; chunked path "
		    "unavailable");
		return -1;
	}

	if ((msg = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		return -1;
	}

	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending sftp-hash-range \"%s\" num_ranges=%u id=%u",
	    path, n, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_HASH_RANGE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal_fr(r, "compose request header");
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_put_u64(msg, ranges[i].off)) != 0 ||
		    (r = sshbuf_put_u64(msg, ranges[i].len)) != 0)
			fatal_fr(r, "compose range %u", i);
	}
	if (send_msg(conn, msg) != 0) {
		/* Connection died (worker churn) - the fallback handles it and
		 * the death already produced its own heartbeat; debug only. */
		debug_f("sftp-hash-range \"%s\": transport send failed; "
		    "falling back to whole-file hash", path);
		goto out;
	}

	/*
	 * Initial watchdog grace covers the worker time until the first
	 * server heartbeat lands.  Each heartbeat refreshes the pause for
	 * another HPN_HEARTBEAT_REFRESH_SEC so the orchestrator never kills
	 * us while the server is making forward progress.  See
	 * sftp-hpn-server.h for the protocol.
	 */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
	/* Resume-check UX: mark the hash op with the summed range bytes so
	 * the reporter/meter can show it; heartbeats refresh the stamp. */
	u_int64_t hash_total = 0;

	for (i = 0; i < n; i++)
		hash_total += ranges[i].len;
	sftp_conn_hash_op_mark(conn, hash_total);

	/* Heartbeats renew the lease (liveness) but carry a progress
	 * figure precisely because liveness is not enough: a stalled
	 * backend can heartbeat forever.  No advance for the threshold
	 * means the connection is treated as failed. */
	u_int64_t hb_prog_last = 0;
	time_t hb_advance_sec = monotime();

	for (;;) {
		sshbuf_reset(msg);

		if (get_msg(conn, msg) != 0) {
			/* Same as the send-side: handled fallback, debug only. */
			debug_f("sftp-hash-range \"%s\": transport receive "
			    "failed; falling back to whole-file hash", path);
			break;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			logit_f("sftp-hash-range \"%s\": parse reply header: "
			    "%s; falling back to whole-file hash",
			    path, ssh_err(r));
			break;
		}
		if (rid != id) {
			logit_f("sftp-hash-range \"%s\": reply id mismatch "
			    "(got %u expected %u); falling back to "
			    "whole-file hash", path, rid, id);
			break;
		}

		if (type == SSH2_FXP_STATUS) {
			u_int	 status = SSH2_FX_FAILURE;
			char	*errmsg = NULL;

			(void)sshbuf_get_u32(msg, &status);
			(void)sshbuf_get_cstring(msg, &errmsg, NULL);
			/*
			 * User-visible warning per the chunked-resume design:
			 * server failure to hash a range indicates a problem
			 * on the destination (FS corruption, concurrent
			 * modification, permission change, etc.) and the user
			 * should know even if the fallback transfer succeeds.
			 */
			logit_f("sftp-hash-range \"%s\": server reported "
			    "error (%s); the destination may have storage / "
			    "FS / permission issues - falling back to "
			    "whole-file hash",
			    path,
			    (errmsg != NULL && *errmsg != '\0')
			        ? errmsg : fx2txt(status));
			free(errmsg);
			break;
		}
		if (type != SSH2_FXP_EXTENDED_REPLY) {
			logit_f("sftp-hash-range \"%s\": unexpected reply "
			    "type %u; falling back to whole-file hash",
			    path, type);
			break;
		}
		if ((r = sshbuf_get_u32(msg, &num_hashes)) != 0) {
			logit_f("sftp-hash-range \"%s\": parse num_hashes: "
			    "%s; falling back to whole-file hash",
			    path, ssh_err(r));
			break;
		}

		/*
		 * Heartbeat reply: refresh the watchdog pause and wait for
		 * the next message.  Real num_hashes is bounded by the
		 * SFTP_HASH_RANGE_MAX_RANGES cap (65536), well below the
		 * sentinel.
		 */
		if (num_hashes == HPN_NUM_HASHES_HEARTBEAT) {
			u_int64_t hb_prog = 0;
			time_t hb_now = monotime();

			if ((r = sshbuf_get_u64(msg, &hb_prog)) != 0)
				hb_prog = hb_prog_last; /* treat as no advance */
			debug3_f("sftp-hash-range \"%s\" id=%u heartbeat "
			    "progress=%llu", path, id,
			    (unsigned long long)hb_prog);
			/* Feed the verify progress meter: server bytes hashed. */
			sftp_conn_verify_inflight_set(conn, hb_prog);
			/* Refresh the hash-op marker + serial meter feed. */
			sftp_conn_hash_op_mark(conn, hash_total);
			sftp_conn_hash_meter_feed(conn, hb_prog);
			if (hb_prog > hb_prog_last) {
				hb_prog_last = hb_prog;
				hb_advance_sec = hb_now;
			} else if (hb_now - hb_advance_sec >=
			    (time_t)HPN_VERIFY_PROGRESS_STALL_SEC) {
				sftp_conn_die(conn, "sftp-hash-range "
				    "\"%s\": server hash made no progress "
				    "for %d seconds (stalled backend); "
				    "treating connection as failed",
				    path, (int)HPN_VERIFY_PROGRESS_STALL_SEC);
				break;
			}
			sftp_conn_watchdog_pause(conn,
			    HPN_HEARTBEAT_REFRESH_SEC);
			continue;
		}

		if (num_hashes != n) {
			logit_f("sftp-hash-range \"%s\": server returned %u "
			    "hashes for %u ranges; falling back to "
			    "whole-file hash", path, num_hashes, n);
			break;
		}
		for (i = 0; i < n; i++) {
			if ((r = sshbuf_get_u64(msg, &hashes_out[i])) != 0) {
				logit_f("sftp-hash-range \"%s\": parse hash "
				    "%u: %s; falling back to whole-file "
				    "hash", path, i, ssh_err(r));
				rc = -1;
				goto loop_done;
			}
		}

		debug3_f("sftp-hash-range \"%s\": received %u hashes", path, n);
		rc = 0;
		break;
	}

loop_done:
	sftp_conn_watchdog_resume(conn);
out:
	sshbuf_free(msg);
	return rc;
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
 * below the chunk floor, chunk count over the cap, or a local/remote hash or
 * transfer error - the caller falls back to a whole-span re-transmit).  A
 * partial failure mid-run leaves the destination indeterminate, hence -1 +
 * fallback.
 */
static int
chunked_reconcile_span(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path,
    off_t span_off, off_t span_len, off_t dest_size, int local_is_target)
{
	struct sftp_hash_range	*ranges = NULL;
	u_int64_t		*local_hashes = NULL;
	u_int64_t		*remote_hashes = NULL;
	u_int64_t		 slen, soff, bytes_moved = 0, checked_bytes;
	const char		*ing = local_is_target ? "re-fetching"
				    : "re-transferring";
	const char		*ed = local_is_target ? "re-fetched"
				    : "re-transferred";
	u_int			 n_chunks, n_check, n_mismatched = 0;
	u_int			 i;
	int			 rc = -1;

	if (conn == NULL || local_path == NULL || remote_path == NULL ||
	    local_fd < 0 || span_len <= 0)
		return -1;

	if (!sftp_conn_has_hash_range(conn)) {
		debug_f("server lacks sftp-hash-range; declining chunked path "
		    "for \"%s\"", local_path);
		return -1;
	}
	slen = (u_int64_t)span_len;
	soff = (u_int64_t)span_off;
	if (slen < CHUNK_HASH_MIN_FILE_SIZE) {
		debug_f("span %llu of \"%s\" below chunked threshold %llu; "
		    "declining", (unsigned long long)slen, local_path,
		    (unsigned long long)CHUNK_HASH_MIN_FILE_SIZE);
		return -1;
	}

	n_chunks = (u_int)((slen + CHUNK_HASH_CHUNK_SIZE - 1) /
	    CHUNK_HASH_CHUNK_SIZE);
	if (n_chunks > CHUNK_HASH_MAX_RANGES_PER_REQUEST) {
		debug_f("span of \"%s\" would need %u chunks > cap %u; "
		    "declining", local_path, n_chunks,
		    CHUNK_HASH_MAX_RANGES_PER_REQUEST);
		return -1;
	}

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
		u_int64_t off = soff + (u_int64_t)i * CHUNK_HASH_CHUNK_SIZE;
		u_int64_t remain = (soff + slen) - off;
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
			    (u_int64_t)dest_size) {
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
	sftp_conn_hash_op_mark(conn, checked_bytes);

	/* Local hashing.  Refresh the pause EVERY chunk: hashing a large span
	 * locally takes minutes of byte-silence, far past one pause window,
	 * and the watchdog/endgame reaper would otherwise kill a worker that
	 * is working hard - then the requeued unit re-hashes from scratch
	 * (churn, or a livelock for a single-file reputv). */
	for (i = 0; i < n_check; i++) {
		sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);
		sftp_conn_hash_op_mark(conn, checked_bytes);
		if (sftp_hpn_xxhash_local_range(local_fd, ranges[i].off,
		    ranges[i].len, &local_hashes[i]) != 0) {
			error_f("local hash failed at chunk %u offset %llu "
			    "for \"%s\"", i,
			    (unsigned long long)ranges[i].off, local_path);
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
	}

	/* Remote hashing: all-or-nothing over the CHECKED prefix.  Helper
	 * emits the user-visible warning on failure.  Skipped entirely when
	 * the clamp left nothing to compare. */
	if (n_check > 0 &&
	    sftp_hpn_hash_remote_ranges(conn, remote_path, ranges, n_check,
	    remote_hashes) != 0) {
		sftp_conn_watchdog_resume(conn);
		goto out;
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

	i = 0;
	while (i < n_chunks) {
		u_int run_start;
		u_int64_t run_off, run_len;
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

	if (span_len > 0 && (u_int64_t)span_len >= CHUNK_HASH_MIN_FILE_SIZE) {
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
    int repair_enabled, int max_attempts)
{
	struct stat sb;
	uint64_t lh = 0, rh = 0, dest_hash, prev_hash;
	const char *side, *dst;
	int r, attempt;

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
