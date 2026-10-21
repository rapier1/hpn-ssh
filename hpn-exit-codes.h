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

/* hpn-exit-codes.h - the exit codes a parallel worker uses to report why
 * its transport ended itself.
 *
 * A worker's congestion monitor ends the transport when it judges the
 * connection wedged. On the client side the worker's hpnssh exits with one
 * of these codes. On the server side the monitor sends the code as an
 * exit-status, and the client keeps it over the later status the session
 * teardown sends (clientloop.c). The orchestrator reaps the worker, and
 * classify_worker_death labels and counts the death by its code. The code
 * is a label only. The worker is respawned either way, and the detail goes
 * to the worker's stderr (one file per worker with hpnsftp -W).
 *
 * The codes take the reserved block 80-89, clear of values already in use:
 *   0        success
 *   1        general error (sftp.c)
 *   57       SFTP_EX_VERIFY_FAILED (sftp-client.h)
 *   58       HPN_EXIT_STRICT_ARGS (hpn-launch-args.h)
 *   64-78    BSD sysexits (EX_*)
 *   127      exec failure in spawn_worker_ssh
 *   255      ssh transport error (cleanup_exit)
 *
 * Delivery is best effort. A hard wedge may block the connection that
 * would carry the code. When no code arrives, classify_worker_death falls
 * back on the wait status and its own kill bookkeeping. */

#ifndef HPN_EXIT_CODES_H
#define HPN_EXIT_CODES_H

#define HPN_EXIT_TCP_BASE		80

/* cwnd collapse or an RTO stall. The worker has data, and the network has
 * stopped moving it. */
#define HPN_EXIT_TCP_WEDGE		80

/* Sustained loss or elevated RTT short of a wedge. Reserved: the monitor
 * reports PATH_DEGRADED but does not exit on it yet. */
#define HPN_EXIT_TCP_PATH_DEGRADED	81

/* The peer has kept its receive window shut past the emergency brake
 * horizon (hpn-congestion-monitor.c). The far end is not draining, which
 * points at the server or its disk. */
#define HPN_EXIT_TCP_PEER_STALL		82

#define HPN_EXIT_TCP_MAX		89

/* True if code is one of the reserved transport self-termination codes. */
#define HPN_EXIT_IS_TCP(code) \
	((code) >= HPN_EXIT_TCP_BASE && (code) <= HPN_EXIT_TCP_MAX)

#endif /* HPN_EXIT_CODES_H */
