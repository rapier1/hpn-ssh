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

/* sftp-client-internal.h - the HPN client's internal API, kept out of
 * upstream's sftp-client.h.
 *
 * It holds two things. The first is the narrow bridge out of sftp-client.c:
 * send_msg, get_msg, and get_handle with their static qualifiers removed,
 * plus three accessors (sftp_conn_hpn, sftp_conn_exts, and
 * sftp_conn_alloc_msg_id). That bridge is all sftp-client.c gains, so the
 * diff against upstream stays small on every merge. The second is the
 * per-connection HPN accessors, defined in sftp-hpn-client.c,
 * sftp-hpn-verify.c, and sftp-lustre-client.c. They reach the HPN state
 * through sftp_conn_hpn(). The HPN client modules use the header, as do
 * the thin HPN call sites in sftp.c, scp.c, and sftp-client.c. Nothing
 * here is needed by upstream code. */

#ifndef _SFTP_CLIENT_INTERNAL_H
#define _SFTP_CLIENT_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

struct sftp_conn;
struct sftp_hpn_conn;
struct sshbuf;
struct bwlimit;

/* The bridge from the opaque upstream struct sftp_conn to the HPN state
 * hung off it. HPN files call this and then work on struct sftp_hpn_conn
 * directly, so no per-field accessor has to live in sftp-client.c. */
struct sftp_hpn_conn *sftp_conn_hpn(struct sftp_conn *);

/* The bitmask of extensions the server advertised, so the HPN has_*()
 * predicates can live outside sftp-client.c. */
u_int sftp_conn_exts(struct sftp_conn *);

/* Send one SFTP message and empty the buffer. Returns 0, or -1 if the
 * connection is dead or the send fails, which marks it dead. */
int  send_msg(struct sftp_conn *, struct sshbuf *);

/* Receive one SFTP message into the buffer. Returns 0, or -1 if the
 * connection is dead or the read fails, which marks it dead. */
int  get_msg(struct sftp_conn *, struct sshbuf *);

/* Read the SSH_FXP_HANDLE reply to the request with the given id. Returns
 * a handle the caller frees, with its length stored through the pointer,
 * or NULL on failure. The printf-style format and arguments that follow
 * describe the request in the error logged on failure. */
u_char *get_handle(struct sftp_conn *, u_int, size_t *, const char *, ...)
    __attribute__((format(printf, 4, 5)));

/* The next outbound message id for this connection: conn->msg_id++
 * without the caller needing struct sftp_conn's layout. */
u_int sftp_conn_alloc_msg_id(struct sftp_conn *);

/* Mark the connection dead after an I/O failure it cannot recover from.
 * Later send_msg and get_msg calls fail at once. sftp-client.c sets the
 * flag directly, and the HPN modules use this. */
void sftp_conn_set_dead(struct sftp_conn *);

/* Latch a protocol violation, a reply with the wrong request id or a
 * packet type the request does not allow, and mark the connection dead.
 * sftp_conn_is_protocol_violation() in sftp-client.h reads it back. */
void sftp_conn_set_protocol_violation(struct sftp_conn *);

/* The watchdog-pause deadline, in monotonic milliseconds, or 0 when no
 * pause is active. The orchestrator's watchdog reads it from its own
 * thread to decide whether to hold off its inactivity checks. Safe from
 * any thread. Returns 0 if conn or conn->hpn is NULL. */
uint64_t sftp_conn_watchdog_pause_until_ms(struct sftp_conn *);

/* Watchdog pause. Tell the orchestrator's watchdog that this worker is
 * about to spend up to the given number of seconds on legitimate work that
 * moves no bytes. That is usually hashing for verify, but any code that
 * knows it will be quiet on the wire can use it. The watchdog holds off
 * every inactivity-based kill until the deadline passes or
 * sftp_conn_watchdog_resume() ends the pause. It still reaps a worker
 * whose ssh child has exited, since a pause cannot save that.
 *
 * A later call extends the pause to the later of the two deadlines, so a
 * shorter pause never cuts a longer one short. The pause expires on its
 * own, so a missing resume costs at most the declared time. Only the
 * connection's own thread may pause and resume it, because the extend is
 * a plain load and store. No-op when conn or its HPN state is NULL.
 *
 * Pass HPN_HEARTBEAT_REFRESH_SEC (sftp-hpn-server.h) as the first grace
 * window when entering a hash extension call. The server sends heartbeats
 * during a long hash, and each one refreshes the pause for another
 * HPN_HEARTBEAT_REFRESH_SEC. The watchdog then follows the server's real
 * progress instead of a prediction from the file size, which failed under
 * disk contention between workers. */
void sftp_conn_watchdog_pause(struct sftp_conn *, unsigned int);
void sftp_conn_watchdog_resume(struct sftp_conn *);

/* Adaptive read-ahead controller. init seeds it with the connection's
 * num_requests, the -R cap. account feeds it the bytes of each completed
 * request and resizes the in-flight depth at window boundaries. cap
 * returns the current depth, which the upload sites use to bound their
 * outstanding requests. window is account followed by cap, for the
 * download ramp sites. All are no-ops or return the floor when conn or
 * its HPN state is NULL. */
void     sftp_conn_rdahead_init(struct sftp_conn *, uint32_t);
void     sftp_conn_rdahead_account(struct sftp_conn *, size_t);
uint32_t sftp_conn_rdahead_cap(struct sftp_conn *);
uint32_t sftp_conn_rdahead_window(struct sftp_conn *, size_t);

/* Backpressure: the caller saw a STATUS read block for longer than
 * RDAHEAD_BP_THRESHOLD_SEC (sftp-hpn-client.h) and took the pipeline to be
 * wedged. Halve the depth, no lower than the floor, and let account()
 * adjust again. Signals that keep arriving at the floor mark the
 * connection dead once they pass RDAHEAD_REAP_BP_COUNT or
 * RDAHEAD_REAP_FLOOR_SEC, so the orchestrator respawns the worker on a
 * fresh TCP session. No-op when conn or its HPN state is NULL. */
void sftp_conn_rdahead_backpressure_signal(struct sftp_conn *);

/* Adaptive upload pacing (see the pace member of struct sftp_hpn_conn).
 * set_enabled is the -X Pacing= master switch, on by default. ack feeds
 * one WRITE status's payload bytes, with the request depth, to the rate
 * estimator. bwlimit returns the token bucket the outbound path applies:
 * the tighter of the adaptive ceiling and the user's -l bucket and rate,
 * or NULL for no limit. */
void sftp_hpn_pace_set_enabled(int);
void sftp_conn_pace_ack(struct sftp_conn *, size_t, u_int);
struct bwlimit *sftp_conn_pace_bwlimit(struct sftp_conn *, struct bwlimit *,
    uint64_t);

/* Add bytes to the worker's live-byte counter, which feeds the parallel
 * watchdog's liveness checks. No-op when no counter is registered. The
 * transfer loops in sftp-client.c and the bundle client call it. */
void sftp_conn_live_account(struct sftp_conn *, size_t);

/* Register the orchestrator's per-worker live-byte counter and its
 * cooperative-yield flag on a worker connection, or NULL to unregister.
 * See the field comments in sftp-hpn-client.h. */
void sftp_conn_set_live_counter(struct sftp_conn *, volatile uint64_t *);
void sftp_conn_set_yield_flag(struct sftp_conn *, volatile int *);

/* Set and query whether verify transfer (-V) is on for a connection.
 * sftp.c and scp.c set it from -V, and the parallel respawn path sets it
 * on each worker. It gates the inline source-hash tee and the verify
 * phase after the transfer. Safe when conn or conn->hpn is NULL, and the
 * query then returns 0. */
void sftp_conn_set_verify_transfer(struct sftp_conn *, int);
int  sftp_conn_verify_transfer_enabled(struct sftp_conn *);

/* Whether a connection can honor -V. The verify engine compares range
 * hashes from both ends, so the server must advertise sftp-hash-range.
 * Callers refuse -V with VERIFY_INCOMPAT_MSG when it cannot. */
int  sftp_conn_verify_transfer_supported(struct sftp_conn *);
#define VERIFY_INCOMPAT_MSG \
	"The remote cannot verify transfers. Please upgrade the remote " \
	"to at least HPN-SSH 19.0.0"

/* Set a single connection's verify auto-repair. attempts is at least 1.
 * sftp.c and scp.c resolve both from -X VerifyRepair, with the cap fixed
 * at 3. It is the per-connection form of fleet->verify_repair_enabled and
 * fleet->verify_repair_attempts, read by sftp_conn_verify_run_phase. Safe
 * when conn or conn->hpn is NULL. */
void sftp_conn_set_verify_repair(struct sftp_conn *, int enabled,
    int attempts);

/* Park a transferred file for the verify phase that runs after the
 * transfer. local_is_target is 0 from sftp_upload and 1 from
 * sftp_download. size is what an upload's inline source hash must cover
 * to be taken along. A no-op unless verify transfer is on, and skipped on
 * worker connections. The compare runs later in
 * sftp_conn_verify_run_phase. */
void sftp_conn_verify_park(struct sftp_conn *, const char *local_path,
    const char *remote_path, int local_is_target, off_t size);

/* The serial bundle flush's form, for an uploaded member whose source hash
 * comes from the bundle writer rather than the tee. */
void sftp_conn_verify_park_hashed(struct sftp_conn *, const char *local_path,
    const char *remote_path, int have_src_hash, uint64_t src_hash);

/* Set and query HPNLustreStripeCount, resolved from ssh_config: -1 for
 * auto, which follows -j, 0 for off, or an explicit count. Safe when conn
 * or conn->hpn is NULL, and the query then returns 0. */
void sftp_conn_set_lustre_stripe_count(struct sftp_conn *, int);
int  sftp_conn_lustre_stripe_count(struct sftp_conn *);

/* The SFTP payload bytes that actually crossed the wire on this
 * connection: WRITE data sent on uploads and DATA received on downloads,
 * without SSH framing or cipher overhead. The worker's completed-bytes
 * counter differs, because it counts a whole file even when a chunked
 * resume found it already matched and sent nothing. The orchestrator
 * reads both, so the summary can show what was resolved and what was
 * sent. add is fed by the transfer loops in sftp-client.c and by the
 * bundle path. Both are atomic, safe from any thread, and safe when conn
 * or conn->hpn is NULL. */
uint64_t sftp_conn_bytes_wired(struct sftp_conn *);
void     sftp_conn_bytes_wired_add(struct sftp_conn *, uint64_t);

/* Report one transfer's outcome from sftp_download or sftp_upload. rc is
 * -1 for a failure, 0 for success, 1 for a skip because the target is
 * identical, or 2 for a skip because it is larger. It prints the skip
 * notice for src and writes dst's TransferLog line, leaving a success to
 * the verify phase under -V. Returns -1 when rc is -1, and 0 otherwise. */
int sftp_hpn_report_transfer(struct sftp_conn *, int rc, const char *src,
    const char *dst, off_t size);

/* Hash-work accounting, shared by every hash phase. Work is counted in
 * work-bytes, two for each byte compared, one per leg.
 *
 * A hash engine drives one operation. op_begin sets its total_work,
 * op_leg starts each leg at base, the work already done, and op_progress
 * reports the leg_bytes hashed so far. op_end clears the operation, so a
 * unit-completion site that folds the work in reads hash_work_done_get()
 * first. The reporter reads the done and total pair with hash_work_live(),
 * which gives zeros once the operation has been quiet for
 * HASH_WORK_STALE_MS. The watchdog reads the total with op_live_total.
 *
 * set_hash_meter_ctr registers a serial meter's counter, and
 * hash_meter_base_add adds finished work under it, so the meter keeps
 * moving while the thread is blocked inside a hash engine. */
void     sftp_conn_hash_op_begin(struct sftp_conn *, uint64_t total_work);
void     sftp_conn_hash_op_leg(struct sftp_conn *, uint64_t base);
void     sftp_conn_hash_op_progress(struct sftp_conn *, uint64_t leg_bytes);
void     sftp_conn_hash_op_end(struct sftp_conn *);
void     sftp_conn_hash_work_live(struct sftp_conn *, uint64_t *, uint64_t *);
uint64_t sftp_conn_hash_op_live_total(struct sftp_conn *);
uint64_t sftp_conn_hash_work_done_get(struct sftp_conn *);
void     sftp_conn_set_hash_meter_ctr(struct sftp_conn *, volatile off_t *);
void     sftp_conn_hash_meter_base_add(struct sftp_conn *, uint64_t);

#endif /* _SFTP_CLIENT_INTERNAL_H */
