/*
 * sftp-client-hpn.c — HPN-SSH extensions to the SFTP client connection.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Isolating HPN-specific logic here keeps sftp-client.c's diff against
 * upstream small and mechanical.
 *
 * Contents:
 *   - sftp_hpn_conn_init / sftp_hpn_conn_free
 *   - sftp_conn_is_dead      (public API declared in sftp-client.h)
 *   - sftp_set_live_counter  (public API declared in sftp-client.h)
 *   - Fault injection (TEST/DEBUG only): fi_state, fi_state_init,
 *     sftp_hpn_check_fault
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#include "includes.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "sftp-client-hpn.h"

/* =========================================================
 * TEST/DEBUG ONLY — remove before production release.
 *
 * fi_state holds the process-wide fault injection parameters parsed once
 * from SFTP_FAULT_INJECT=<bytes>[:<max_kills>] at first worker connection.
 *
 * All locations that must be removed together:
 *   - fi_state struct (here)
 *   - fi_state_init() (here)
 *   - sftp_hpn_check_fault() (here)
 *   - fault_after_bytes / fault_bytes_sent in struct sftp_hpn_conn (sftp-client-hpn.h)
 *   - sftp_hpn_check_fault() call in send_msg (sftp-client.c)
 *   - sftp_set_live_counter fault block (here)
 * ========================================================= */
static struct {
	uint64_t       threshold;  /* byte threshold; 0 = disabled */
	int            kills_left; /* remaining kill slots; INT_MAX = unlimited */
	pthread_once_t once;
} fi_state = { 0, 0, PTHREAD_ONCE_INIT };

/*
 * Parsed once from SFTP_FAULT_INJECT=<bytes>[:<max_kills>].
 *   bytes     — worker connection dies after sending this many bytes.
 *   max_kills — optional; at most this many workers are killed (default: all).
 * Example: SFTP_FAULT_INJECT=150000:2  kills at most 2 out of N workers.
 */
static void
fi_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_INJECT");
	if (ev == NULL)
		return;
	char *ep;
	uint64_t bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fi_state.threshold  = bytes;
	fi_state.kills_left = (*ep == ':') ? (int)strtol(ep + 1, NULL, 10)
	                                   : INT_MAX;
}
/* END TEST/DEBUG */

struct sftp_hpn_conn *
sftp_hpn_conn_init(void)
{
	return xcalloc(1, sizeof(struct sftp_hpn_conn));
}

void
sftp_hpn_conn_free(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	freezero(hpn, sizeof(*hpn));
}

/*
 * Internal helper called by sftp_conn_is_dead() in sftp-client.c.
 * Operates on struct sftp_hpn_conn directly to avoid a dependency on
 * the opaque struct sftp_conn definition.
 */
int
sftp_hpn_is_dead(struct sftp_hpn_conn *hpn)
{
	return hpn != NULL && hpn->dead;
}

int
sftp_hpn_is_protocol_violation(struct sftp_hpn_conn *hpn)
{
	return hpn != NULL && hpn->protocol_violation;
}

void
sftp_hpn_set_protocol_violation(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	hpn->dead = 1;
	hpn->protocol_violation = 1;
}

/*
 * Internal helper called by sftp_set_live_counter() in sftp-client.c.
 * Registers the parallel orchestrator's live-bytes counter and arms the
 * fault injection threshold if SFTP_FAULT_INJECT is set (TEST/DEBUG).
 */
void
sftp_hpn_set_live_counter(struct sftp_hpn_conn *hpn, volatile uint64_t *counter)
{
	if (hpn == NULL)
		return;
	hpn->live_counter = counter;

	/* TEST/DEBUG ONLY — remove before production release */
	pthread_once(&fi_state.once, fi_state_init);
	if (fi_state.threshold > 0) {
		hpn->fault_after_bytes = fi_state.threshold;
		error("sftp: fault injection enabled: "
		    "connection will die after %llu bytes sent",
		    (unsigned long long)fi_state.threshold);
	}
	/* END TEST/DEBUG */
}

/*
 * TEST/DEBUG ONLY — remove before production release.
 *
 * Called by send_msg after each successful write.  Accumulates bytes sent
 * and triggers a simulated connection death when the threshold is reached.
 * Uses a shared atomic kill-slot counter so that at most fi_state.kills_left
 * workers actually die; the rest continue and pick up re-queued work.
 *
 * Returns 0 normally.
 * Returns -1 and sets hpn->dead when a fault fires; the caller must close
 * the connection file descriptors.
 */
int
sftp_hpn_check_fault(struct sftp_hpn_conn *hpn, size_t bytes)
{
	if (hpn == NULL || hpn->fault_after_bytes == 0)
		return 0;

	hpn->fault_bytes_sent += bytes;
	if (hpn->fault_bytes_sent < hpn->fault_after_bytes)
		return 0;

	/* Atomically claim a kill slot. */
	int prev = __atomic_fetch_sub(&fi_state.kills_left, 1,
	    __ATOMIC_SEQ_CST);
	if (prev > 0) {
		error("sftp: fault injection: simulating connection death "
		    "after %llu bytes sent",
		    (unsigned long long)hpn->fault_bytes_sent);
		hpn->dead = 1;
		return -1;
	}

	/* No kill slot available — restore counter, disable for this conn. */
	__atomic_fetch_add(&fi_state.kills_left, 1, __ATOMIC_SEQ_CST);
	hpn->fault_after_bytes = 0;
	return 0;
}
/* END TEST/DEBUG */
