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
 *   ENV-VAR SFTP_FAULT_CORRUPT=<off1>[,<off2>...][:persist|:vary|:multi[:N]]
 *       flips byte(s) at absolute file offset(s) in the data SENT.  The on-disk
 *       source is left clean, so a verified transfer's source hash stays good
 *       and the target hash diverges - a manufactured transfer/write corruption
 *       for exercising the integrity verify (HPNVerifyTransfer) and auto-repair.
 *       Single offset, no suffix: flip once, then disarm (verify-detection /
 *       single-file repair-success - a repair re-transfer is clean).  :persist:
 *       re-flip to the SAME value on every write covering the offset (repair
 *       re-corrupts identically -> repair CONVERGENCE give-up).  :vary: re-flip
 *       to a different value each write (-> repair attempt-CAP give-up).
 *       :multi[:N] (or a bare comma-separated offset LIST): flip each listed
 *       offset while a global slot remains (default N = offset count).  Slots
 *       are consumed by the initial send; verify+repair is a post-transfer
 *       phase, so the repair re-sends find the slots gone and converge - this is
 *       the MULTIPLE-corruptions-repair-SUCCESS case (N files at one offset:
 *       <off>:multi:<filecount>; one file at N points: <off1>,<off2>,...).
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
/* Per-write-chunk hook: if SFTP_FAULT_CORRUPT=<offset> is set, flips one byte
 * in the outgoing data buffer at that absolute file offset, once.  Corrupts
 * the bytes sent while leaving the on-disk source clean, so a verified
 * transfer's source hash holds and the target diverges. */
void	fault_inj_corrupt(off_t chunk_off, u_char *buf, size_t len);
#else
/* Normal builds: hooks compile to nothing. */
#define fault_inj_arm_conn(hpn)		do { } while (0)
#define fault_inj_check_send(hpn, n)	(0)
#define fault_inj_check_recv(hpn, n)	do { } while (0)
#define fault_inj_corrupt(off, buf, len)	do { } while (0)
#endif

#endif /* SFTP_FAULT_INJECT_H */
