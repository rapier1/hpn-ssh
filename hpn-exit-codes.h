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

#ifndef HPN_EXIT_CODES_H
#define HPN_EXIT_CODES_H

/*
 * HPN process exit codes for transport self-termination.
 *
 * When a parallel-streams worker (an hpnssh child) self-diagnoses a fatal
 * transport condition, it exits with one of these codes.  The orchestrator
 * reaps the worker, reads WEXITSTATUS, and uses the code to label the death
 * and pick a respawn policy.  Exactly one byte of signal -- a policy hint,
 * not a diagnostics channel (richer detail goes to the worker stderr log).
 *
 * Reserved block: 80-89.  Chosen to avoid values already in use:
 *   0        success
 *   1        general error (sftp.c)
 *   57       SFTP_EX_VERIFY_FAILED (sftp-client.h)
 *   64-78    BSD sysexits (EX_*)
 *   127      execvp-failed sentinel (spawn_worker_ssh)
 *   255      ssh transport-level error (cleanup_exit)
 *
 * Delivery is best-effort: a hard wedge may block the connection that would
 * carry the code (or the report).  When a code does not arrive, the
 * orchestrator falls back to inferring the death mode from the wait status
 * and its own kill bookkeeping -- see the reap-side classifier.
 */
#define HPN_EXIT_TCP_BASE		80

#define HPN_EXIT_TCP_WEDGE		80	/* cwnd collapse / RTO stall:
						 * we have data, the network has
						 * stopped moving it.  Respawn
						 * (fresh connection may help). */
#define HPN_EXIT_TCP_PATH_DEGRADED	81	/* sustained loss / elevated RTT,
						 * not a full wedge.  Respawn on
						 * a tight budget. */
#define HPN_EXIT_TCP_PEER_STALL		82	/* peer receive window pinned
						 * shut: the far end isn't
						 * draining (server/disk bound).
						 * Respawn unlikely to help;
						 * back off. */

#define HPN_EXIT_TCP_MAX		89

/* True if `code` is one of the reserved HPN transport self-termination codes. */
#define HPN_EXIT_IS_TCP(code) \
	((code) >= HPN_EXIT_TCP_BASE && (code) <= HPN_EXIT_TCP_MAX)

#endif /* HPN_EXIT_CODES_H */
