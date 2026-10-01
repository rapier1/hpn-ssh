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

/* hpn-fault-inject.h - fault-injection test scaffolding for HPN-SSH.
 *
 * TEST/DEBUG ONLY. Everything here is built only with -DHPN_FAULT_INJECTION.
 * In normal builds the hooks below compile to nothing. All functions are
 * prefixed fault_inj_. No hook sites live in the tree: a test campaign adds
 * the calls it needs and removes them afterward. Typically that means
 * fault_inj_arm_conn() at connection setup, fault_inj_check_send() and
 * fault_inj_check_recv() around the wire I/O, and fault_inj_corrupt() on
 * each outgoing data chunk.
 *
 * Each fault is read from its environment variable once per process. A
 * value that is set but malformed is fatal, so a test never runs with a
 * fault it did not ask for. Every fault announces itself in the log.
 *
 *   ENV-VAR HPN_FAULT_INJECT=<bytes>[:<max_kills>]
 *       After <bytes> sent, the connection is marked dead, just like a
 *       real EPIPE (no descriptors are closed here). At most <max_kills>
 *       connections die, all of them by default. Tests worker death
 *       and recovery: the respawn and the requeue of the unfinished work.
 *
 *   ENV-VAR HPN_FAULT_PROTOCOL=<bytes>[:<max_kills>]
 *       After <bytes> sent, the connection reports a protocol violation.
 *       Tests the escalation: the first violation in a session respawns
 *       the worker, and the second ends hpnsftp.
 *
 *   ENV-VAR HPN_FAULT_THROTTLE=<bytes>:<delay_ms>[:<max_conns>]
 *       After <bytes> sent, every further send on the connection sleeps
 *       <delay_ms>. The connection stays alive but slow, a straggler.
 *       At most <max_conns> connections throttle (default 1). Tests the
 *       watchdog's straggler handling and the tail redistribution on
 *       uploads.
 *
 *   ENV-VAR HPN_FAULT_THROTTLE_RECV=<bytes>:<delay_ms>[:<max_conns>]
 *       The download mirror: after <bytes> received, every further
 *       receive sleeps <delay_ms>. The delayed reads fill the ssh child's
 *       pipe and close the channel window, so the client sees what looks
 *       like a slow server, with nothing needed on the server side. At
 *       most <max_conns> connections throttle (default 1). Tests the same
 *       straggler handling on downloads.
 *
 *   ENV-VAR HPN_FAULT_CORRUPT=<off1>[,<off2>...][:persist|:vary|:multi[:N]]
 *       Flips a byte at each absolute file offset in the data sent. The
 *       source on disk stays clean, so a verified transfer's source hash
 *       holds and the target hash diverges. Tests verify (-V) and its
 *       repair, one mode per outcome:
 *         once     one offset, no suffix: flip once. Verify must catch it
 *                  and the repair must succeed.
 *         persist  flip the same way on every write, repairs included.
 *                  The target hash repeats, so the repair must give up
 *                  as not converging.
 *         vary     flip differently on every write. The target hash
 *                  changes each attempt, so the repair must give up at
 *                  its attempt cap.
 *         multi    a list of offsets, or :multi[:N]: flip each listed
 *                  offset while N slots last (default, one per offset).
 *                  The first send spends the slots, so the repairs run
 *                  clean and must all succeed. Use one offset with N set
 *                  to the file count for many files, or a list for many
 *                  points in one file. */

#ifndef HPN_FAULT_INJECT_H
#define HPN_FAULT_INJECT_H

struct sftp_hpn_conn;

#ifdef HPN_FAULT_INJECTION
/* Arm a new connection with the faults that are set. Call it at
 * connection setup. */
void	fault_inj_arm_conn(struct sftp_hpn_conn *);
/* Send hook: count the bytes and fire any fault they cross. Returns -1
 * when the send should fail because the connection is now dead or has
 * a protocol violation, and 0 otherwise. */
int	fault_inj_check_send(struct sftp_hpn_conn *, size_t);
/* Receive hook: count the bytes and apply the receive throttle. Never
 * fails the receive. */
void	fault_inj_check_recv(struct sftp_hpn_conn *, size_t);
/* Data hook: given an outgoing chunk and its file offset, corrupt it in
 * place as HPN_FAULT_CORRUPT asks. */
void	fault_inj_corrupt(off_t, u_char *, size_t);
#else
/* Normal builds: hooks compile to nothing. */
#define fault_inj_arm_conn(hpn)		do { } while (0)
#define fault_inj_check_send(hpn, n)	(0)
#define fault_inj_check_recv(hpn, n)	do { } while (0)
#define fault_inj_corrupt(off, buf, len)	do { } while (0)
#endif

#endif /* HPN_FAULT_INJECT_H */
