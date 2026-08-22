/* sftp-client-internal.h - narrow internal API exposed by sftp-client.c
 * to HPN-only client files (sftp-hpn-client.c).
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * It exists so HPN extension code can implement new SFTP wire
 * transactions (hpn-bundle-fetch, etc.) without that code accreting
 * inside sftp-client.c, which would inflate the diff against upstream
 * on every merge.
 *
 * Upstream merge note: sftp-client.c gains only:
 *   - `static` qualifier removed from send_msg / get_msg / get_handle
 *   - three bridge accessors (sftp_conn_alloc_msg_id, sftp_conn_hpn,
 *     sftp_conn_exts); every other per-connection HPN accessor lives in the
 *     HPN modules and reaches state through sftp_conn_hpn().
 * Nothing in this header is needed by upstream code paths.
 */

#ifndef _SFTP_CLIENT_INTERNAL_H
#define _SFTP_CLIENT_INTERNAL_H

#include <sys/types.h>
#include <stdarg.h>

struct sftp_conn;
struct sftp_hpn_conn;
struct sshbuf;

/*
 * The single bridge from the opaque upstream struct sftp_conn to the HPN
 * per-connection state (struct sftp_hpn_conn) hung off it.  HPN files call
 * this and then operate on struct sftp_hpn_conn directly, so no per-field
 * accessor needs to be defined inside the upstream sftp-client.c.
 */
struct sftp_hpn_conn *sftp_conn_hpn(struct sftp_conn *conn);

/*
 * Read the server-advertised SFTP extension bitmask (conn->exts) through the
 * opaque struct sftp_conn, so the HPN has_*() predicates can live outside
 * sftp-client.c.
 */
u_int sftp_conn_exts(struct sftp_conn *conn);

/*
 * Send an SFTP message over the connection.  Returns 0 on success,
 * -1 if conn is dead.  Marks conn dead on transport failure.
 */
int  send_msg(struct sftp_conn *conn, struct sshbuf *m);

/*
 * Receive one SFTP message into the supplied buffer.  Returns 0 on
 * success, non-zero on protocol/transport error (also marks conn dead
 * via the HPN dead flag).
 */
int  get_msg(struct sftp_conn *conn, struct sshbuf *m);

/*
 * Issue one outbound request and read back the SSH_FXP_HANDLE reply.
 * Returns a newly-malloc'd handle buffer on success (caller frees), or
 * NULL on failure.  *len is set to the handle length on success.
 *
 * `errfmt` (printf-style) is used to format the per-failure error log
 * message.  expected_id must match the reply's id field.
 */
u_char *get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...) __attribute__((format(printf, 4, 5)));

/*
 * Allocate and return the next outbound SFTP message id for this
 * connection.  Equivalent to `conn->msg_id++` but doesn't require the
 * caller to know struct sftp_conn's layout.
 */
u_int sftp_conn_alloc_msg_id(struct sftp_conn *conn);

/*
 * Mark a connection as dead due to a non-recoverable I/O failure.
 * Subsequent send_msg / get_msg short-circuit.  Equivalent to the
 * direct `conn->hpn->dead = 1` assignment that internal sftp-client.c
 * code can do; HPN extension code uses this accessor instead.
 */
void sftp_conn_set_dead(struct sftp_conn *conn);

/*
 * Atomic-load and return the watchdog-pause deadline for this
 * connection (monotonic milliseconds), or 0 if no pause is active.
 * Used by the parallel orchestrator's watchdog to decide whether to
 * suppress its inactivity-based heuristics for this worker.  Safe to
 * call from any thread.  Returns 0 if conn or conn->hpn is NULL.
 */
uint64_t sftp_conn_watchdog_pause_until_ms(struct sftp_conn *conn);

/*
 * Conn-side wrappers around sftp_hpn_watchdog_pause/_resume.  Let HPN
 * extension code that works through the opaque struct sftp_conn * (the
 * chunked-resume helpers, the bundle path, etc.) pause/resume the
 * watchdog without needing to extract conn->hpn manually.  No-op when
 * conn or conn->hpn is NULL.
 */
void sftp_conn_watchdog_pause(struct sftp_conn *conn, unsigned int seconds);
void sftp_conn_watchdog_resume(struct sftp_conn *conn);

/*
 * Conn-side wrappers around sftp_hpn_rdahead_cap / _account.  Used by the
 * bundle path in sftp-hpn-client.c (which sees struct sftp_conn as opaque)
 * to bound outstanding bundle WRITEs by the adaptive controller's current
 * depth and to feed accurate per-ack byte counts back to the throughput
 * sampler.  Both return / no-op cleanly when conn or conn->hpn is NULL;
 * sftp_conn_rdahead_cap returns `fallback` in that case so callers see
 * their fixed ceiling instead of zero.
 */
uint32_t sftp_conn_rdahead_cap(struct sftp_conn *conn, uint32_t fallback);
void     sftp_conn_rdahead_account(struct sftp_conn *conn, size_t nbytes);

/*
 * Per-worker live-byte counter bump (no-op when conn/hpn/counter is NULL).
 * The bundle codec feeds the parallel watchdog's liveness classifiers
 * through this; the non-bundle transfer paths bump the counter inline.
 */
void     sftp_conn_live_account(struct sftp_conn *conn, size_t nbytes);

/*
 * Backpressure signal - caller observed a STATUS read that blocked longer
 * than the controller's wedge-detection threshold (RDAHEAD_BP_THRESHOLD_SEC
 * in sftp-hpn-client.c, currently 10 s).  Forwards to
 * sftp_hpn_rdahead_backpressure_signal, which halves the in-flight depth
 * and re-enters the probe phase.  No-op when conn / conn->hpn is NULL or
 * the controller is disabled.
 */
void sftp_conn_rdahead_backpressure_signal(struct sftp_conn *conn);

/*
 * Set / query the verify transfer enabled state on a connection.
 * Latched from -V in sftp.c and stashed on conn->hpn; gates the
 * inline source-hash tee and the post-transfer verify phase.  Safe with
 * conn / conn->hpn NULL; query returns 0 in that case.
 */
void sftp_conn_set_verify_transfer(struct sftp_conn *conn, int enabled);
int  sftp_conn_verify_transfer_enabled(struct sftp_conn *conn);

/*
 * Set the single-conn (classic) verify auto-repair settings on a connection,
 * resolved in sftp.c from the -X VerifyRepair token (attempt cap fixed at
 * 3).  The conn-side analogue of the orchestrator's
 * p->verify_repair_{enabled,attempts}; read by sftp_conn_verify_run_phase.
 * Safe with conn / conn->hpn NULL.
 */
void sftp_conn_set_verify_repair(struct sftp_conn *conn, int enabled,
	int attempts);

/*
 * Park a transferred file for the classic post-transfer verify phase, called
 * at the end of sftp_upload (local_is_target=0) and sftp_download
 * (local_is_target=1).  No-op unless verify_transfer_enabled and skipped on
 * worker conns; the compare runs later in sftp_conn_verify_run_phase.
 */
void sftp_conn_verify_park(struct sftp_conn *conn,
	const char *local_path, const char *remote_path, int local_is_target);

/*
 * Set / query the HPNLustreStripeCount resolved-from-ssh_config value
 * stashed on conn->hpn.  Values: -1 = auto (use -j N); 0 = feature off;
 * >0 = explicit override.  Safe with conn / conn->hpn NULL; query returns
 * 0 in that case.
 */
void sftp_conn_set_lustre_stripe_count(struct sftp_conn *conn, int value);
int  sftp_conn_lustre_stripe_count(struct sftp_conn *conn);

/*
 * Query the latched "hpn-file-layout was declined on this conn" flag.
 * Set by the client-side helper after the first non-success reply so
 * subsequent calls short-circuit.  Safe with conn / conn->hpn NULL.
 */
int  sftp_conn_layout_set_declined(struct sftp_conn *conn);
void sftp_conn_set_layout_set_declined(struct sftp_conn *conn, int v);

/*
 * Cumulative SFTP-payload bytes that actually crossed the wire on this
 * connection - SSH2_FXP_WRITE payload sent (uploads) + SSH2_FXP_DATA
 * payload received (downloads).  Excludes SSH framing / cipher overhead.
 * Distinct from the worker's "work-units completed in bytes" counter,
 * which counts the full file size even when chunked-resume verified the
 * file already matched and skipped the transfer.  Read by the parallel
 * orchestrator at session end so the reporter can show both "resolved"
 * and "wired" so operators see what actually flowed.  Returns 0 if
 * conn or conn->hpn is NULL.  Safe to call from any thread.
 */
uint64_t sftp_conn_bytes_wired(struct sftp_conn *conn);

/*
 * Add to the wire-payload counter from outside sftp-client.c (the bundle send
 * path, which bypasses the per-file write loops).  Safe with conn/conn->hpn
 * NULL; atomic, callable from any thread.
 */
void sftp_conn_bytes_wired_add(struct sftp_conn *conn, uint64_t n);

/*
 * Unified hash-work accounting (project_hash_work_meter_design): every
 * hash phase meters in work-bytes (1 byte of overlap = 2 work-bytes, one
 * per leg).  Engines drive begin/leg/progress; unit-completion sites call
 * end (capture done BEFORE end when folding); the reporter reads the
 * stamp-gated live pair; the watchdog gate reads live_total.  The meter
 * bridge lets a serial meter counter advance while the thread is blocked
 * inside an engine.
 */
void     sftp_conn_hash_op_begin(struct sftp_conn *conn, uint64_t total_work);
void     sftp_conn_hash_op_leg(struct sftp_conn *conn, uint64_t base);
void     sftp_conn_hash_op_progress(struct sftp_conn *conn,
             uint64_t leg_bytes);
void     sftp_conn_hash_op_end(struct sftp_conn *conn);
void     sftp_conn_hash_work_live(struct sftp_conn *conn, uint64_t *done_out,
             uint64_t *total_out);
uint64_t sftp_conn_hash_op_live_total(struct sftp_conn *conn);
uint64_t sftp_conn_hash_work_done_get(struct sftp_conn *conn);
void     sftp_conn_set_hash_meter_ctr(struct sftp_conn *conn,
             volatile off_t *ctr);
void     sftp_conn_hash_meter_base_add(struct sftp_conn *conn, uint64_t work);

#endif /* _SFTP_CLIENT_INTERNAL_H */
