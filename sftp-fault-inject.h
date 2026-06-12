/*
 * sftp-fault-inject.h - fault-injection test scaffolding (HPN).
 *
 * TEST/DEBUG ONLY.  Everything here is compile-gated behind
 * -DHPN_FAULT_INJECTION and is a no-op in normal builds.  All functions
 * are prefixed fault_inj_ and every hook site in regular code is tagged
 * with a FAULT-INJ comment so the entire mechanism can be located (and,
 * if ever desired, removed) with a single grep.
 *
 * Knobs (parsed once per process):
 *   ENV-VAR SFTP_FAULT_INJECT=<bytes>[:<max_kills>]
 *       a connection is marked dead (exactly like a real EPIPE - no fds
 *       are closed at this layer) after sending <bytes> wire bytes; at
 *       most <max_kills> connections die (default unlimited).
 *   ENV-VAR SFTP_FAULT_PROTOCOL=<bytes>[:<max_kills>]
 *       a connection reports a protocol violation after <bytes>.
 *   ENV-VAR SFTP_FAULT_THROTTLE=<bytes>:<delay_ms>[:<max_conns>]
 *       after <bytes> sent, every further send on the connection sleeps
 *       <delay_ms> - a manufactured STRAGGLER (degraded path / slow
 *       peer), not a death.  At most <max_conns> connections throttle
 *       (default 1).  Built for tuning the tail trend detector.
 *   ENV-VAR SFTP_FAULT_THROTTLE_RECV=<bytes>:<delay_ms>[:<max_conns>]
 *       download-side mirror of SFTP_FAULT_THROTTLE: after <bytes>
 *       RECEIVED, every further message receive on the connection
 *       sleeps <delay_ms>.  Delaying the read backpressures the local
 *       ssh child's pipe, which closes the SSH channel window, which
 *       stalls the server's stream - from every client instrument's
 *       view this is indistinguishable from a slow server, with no
 *       server-side scaffolding needed.  At most <max_conns>
 *       connections throttle (default 1).  Never kills.
 */

#ifndef SFTP_FAULT_INJECT_H
#define SFTP_FAULT_INJECT_H

struct sftp_hpn_conn;

#ifdef HPN_FAULT_INJECTION
/* Arm a new connection from the env knobs (called at conn setup). */
void	fault_inj_arm_conn(struct sftp_hpn_conn *);
/* Per-send hook: accounts wire bytes, fires armed faults.  Returns -1
 * when this send should fail (connection has been marked dead or a
 * protocol violation has been raised), 0 otherwise. */
int	fault_inj_check_send(struct sftp_hpn_conn *, size_t);
/* Per-receive hook: accounts received wire bytes, fires the armed
 * receive throttle.  Never fails the receive. */
void	fault_inj_check_recv(struct sftp_hpn_conn *, size_t);
#else
/* Normal builds: hooks compile to nothing. */
#define fault_inj_arm_conn(hpn)		do { } while (0)
#define fault_inj_check_send(hpn, n)	(0)
#define fault_inj_check_recv(hpn, n)	do { } while (0)
#endif

#endif /* SFTP_FAULT_INJECT_H */
