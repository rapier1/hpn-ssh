/* sftp-client-internal.h — narrow internal API exposed by sftp-client.c
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
 *   - two trivial accessor functions at end of file
 *     (sftp_conn_alloc_msg_id, sftp_conn_has_hpn_bundle_fetch)
 * Nothing in this header is needed by upstream code paths.
 */

#ifndef _SFTP_CLIENT_INTERNAL_H
#define _SFTP_CLIENT_INTERNAL_H

#include <sys/types.h>
#include <stdarg.h>

struct sftp_conn;
struct sshbuf;

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
 * connection (monotonic nanoseconds), or 0 if no pause is active.
 * Used by the parallel orchestrator's watchdog to decide whether to
 * suppress its inactivity-based heuristics for this worker.  Safe to
 * call from any thread.  Returns 0 if conn or conn->hpn is NULL.
 */
uint64_t sftp_conn_watchdog_pause_until_ns(struct sftp_conn *conn);

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
 * Set / query the HPNVerifyTransfer enabled state on a connection.
 * Resolved from ssh_config in sftp.c and stashed on conn->hpn so the
 * resume-decision callers can pass HPN_CHECK_FILE_STRICT in the
 * hpn-check-file request when the user has asked for maximum
 * verification.  Safe with conn / conn->hpn NULL; query returns 0 in
 * that case.
 */
void sftp_conn_set_verify_transfer(struct sftp_conn *conn, int enabled);
int  sftp_conn_verify_transfer_enabled(struct sftp_conn *conn);

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
 * connection — SSH2_FXP_WRITE payload sent (uploads) + SSH2_FXP_DATA
 * payload received (downloads).  Excludes SSH framing / cipher overhead.
 * Distinct from the worker's "work-units completed in bytes" counter,
 * which counts the full file size even when chunked-resume verified the
 * file already matched and skipped the transfer.  Read by the parallel
 * orchestrator at session end so the reporter can show both "resolved"
 * and "wired" so operators see what actually flowed.  Returns 0 if
 * conn or conn->hpn is NULL.  Safe to call from any thread.
 */
uint64_t sftp_conn_bytes_wired(struct sftp_conn *conn);

#endif /* _SFTP_CLIENT_INTERNAL_H */
