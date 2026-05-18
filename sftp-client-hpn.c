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
 *   - Fault injection (TEST/DEBUG only): fi_state, fi_pv_state,
 *     fi_state_init, fi_pv_state_init, sftp_hpn_check_fault
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

#include <stdarg.h>
#include <stdio.h>

#include "xmalloc.h"
#include "log.h"
#include "sftp-client-hpn.h"

#ifdef HPN_FAULT_INJECTION
static struct {
	uint64_t       threshold;  /* byte threshold; 0 = disabled */
	int            kills_left; /* remaining kill slots; INT_MAX = unlimited */
	pthread_once_t once;
} fi_state = { 0, 0, PTHREAD_ONCE_INIT };

/* Parallel struct for SFTP_FAULT_PROTOCOL — triggers protocol violation. */
static struct {
	uint64_t       threshold;
	int            kills_left;
	pthread_once_t once;
} fi_pv_state = { 0, 0, PTHREAD_ONCE_INIT };

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

/*
 * Parsed once from SFTP_FAULT_PROTOCOL=<bytes>[:<max_kills>].
 *   bytes     — worker fires a protocol violation after sending this many bytes.
 *   max_kills — optional; at most this many workers trigger the fault.
 * Example: SFTP_FAULT_PROTOCOL=150000:1  triggers one protocol violation.
 */
static void
fi_pv_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_PROTOCOL");
	if (ev == NULL)
		return;
	char *ep;
	uint64_t bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fi_pv_state.threshold  = bytes;
	fi_pv_state.kills_left = (*ep == ':') ? (int)strtol(ep + 1, NULL, 10)
	                                      : INT_MAX;
}
#endif /* HPN_FAULT_INJECTION */

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
 * Mark a connection as dead with prominent diagnostic logging, without
 * terminating the process. See header comment for full semantics.
 *
 * Implementation detail: format the message into a stack buffer (avoid
 * heap allocation in error paths), call error() at the standard ERROR
 * log level, then set hpn->dead so subsequent RPC calls bail.
 */
void
sftp_hpn_conn_die(struct sftp_hpn_conn *hpn, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	/* Distinctive prefix so these are easy to grep out of logs:
	 * "sftp: connection died: <reason>" */
	error("sftp: connection died: %s", buf);

	if (hpn != NULL)
		hpn->dead = 1;
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

#ifdef HPN_FAULT_INJECTION
	pthread_once(&fi_state.once, fi_state_init);
	if (fi_state.threshold > 0) {
		hpn->fault_after_bytes = fi_state.threshold;
		error("sftp: fault injection enabled: "
		    "connection will die after %llu bytes sent",
		    (unsigned long long)fi_state.threshold);
	}
	pthread_once(&fi_pv_state.once, fi_pv_state_init);
	if (fi_pv_state.threshold > 0) {
		hpn->fault_pv_after_bytes = fi_pv_state.threshold;
		error("sftp: protocol-violation fault injection enabled: "
		    "connection will report protocol violation after %llu bytes sent",
		    (unsigned long long)fi_pv_state.threshold);
	}
#endif /* HPN_FAULT_INJECTION */
}

#ifdef HPN_FAULT_INJECTION
/*
 * Called by send_msg after each successful write.  Accumulates bytes sent
 * and fires the first armed fault trigger whose threshold is reached.
 * Protocol-violation fault (SFTP_FAULT_PROTOCOL) is checked first; connection-
 * death fault (SFTP_FAULT_INJECT) is checked second.  Each uses an independent
 * atomic kill-slot counter so exactly max_kills workers trigger the fault.
 *
 * Returns 0 normally.
 * Returns -1 and sets hpn->dead (and hpn->protocol_violation if applicable)
 * when a fault fires; the caller must close the connection file descriptors.
 */
int
sftp_hpn_check_fault(struct sftp_hpn_conn *hpn, size_t bytes)
{
	if (hpn == NULL)
		return 0;

	/* Only accumulate if at least one fault type is armed. */
	if (hpn->fault_after_bytes == 0 && hpn->fault_pv_after_bytes == 0)
		return 0;

	hpn->fault_bytes_sent += bytes;

	/* Check protocol-violation fault first (higher priority signal). */
	if (hpn->fault_pv_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_pv_after_bytes) {
		int prev = __atomic_fetch_sub(&fi_pv_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating protocol "
			    "violation after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			sftp_hpn_set_protocol_violation(hpn);
			return -1;
		}
		/* No slot — restore and disarm for this connection. */
		__atomic_fetch_add(&fi_pv_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		hpn->fault_pv_after_bytes = 0;
	}

	/* Check connection-death fault. */
	if (hpn->fault_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_after_bytes) {
		int prev = __atomic_fetch_sub(&fi_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating connection "
			    "death after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			hpn->dead = 1;
			return -1;
		}
		/* No slot — restore and disarm for this connection. */
		__atomic_fetch_add(&fi_state.kills_left, 1, __ATOMIC_SEQ_CST);
		hpn->fault_after_bytes = 0;
	}

	return 0;
}
#endif /* HPN_FAULT_INJECTION */
