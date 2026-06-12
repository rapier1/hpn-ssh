/*
 * sftp-fault-inject.c - fault-injection test scaffolding (HPN).
 * See sftp-fault-inject.h for the knobs and the removal contract.
 * TEST/DEBUG ONLY: empty translation unit in normal builds.
 */

#include "includes.h"

#ifdef HPN_FAULT_INJECTION

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>

#include "log.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-client.h"
#include "sftp-fault-inject.h"

static struct {
	uint64_t       threshold;  /* byte threshold; 0 = disabled */
	int            kills_left; /* remaining kill slots; INT_MAX = unlimited */
	pthread_once_t once;
} fault_inj_state = { 0, 0, PTHREAD_ONCE_INIT };

/* Parallel state for SFTP_FAULT_PROTOCOL - protocol violations. */
static struct {
	uint64_t       threshold;
	int            kills_left;
	pthread_once_t once;
} fault_inj_pv_state = { 0, 0, PTHREAD_ONCE_INIT };

static void
fault_inj_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_INJECT");
	char *ep;
	uint64_t bytes;

	if (ev == NULL)
		return;
	bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fault_inj_state.threshold  = bytes;
	fault_inj_state.kills_left = (*ep == ':') ?
	    (int)strtol(ep + 1, NULL, 10) : INT_MAX;
}

static void
fault_inj_pv_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_PROTOCOL");
	char *ep;
	uint64_t bytes;

	if (ev == NULL)
		return;
	bytes = strtoull(ev, &ep, 10);
	if (bytes == 0)
		return;
	fault_inj_pv_state.threshold  = bytes;
	fault_inj_pv_state.kills_left = (*ep == ':') ?
	    (int)strtol(ep + 1, NULL, 10) : INT_MAX;
}

void
fault_inj_arm_conn(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	pthread_once(&fault_inj_state.once, fault_inj_state_init);
	if (fault_inj_state.threshold > 0) {
		hpn->fault_after_bytes = fault_inj_state.threshold;
		error("sftp: fault injection enabled: "
		    "connection will die after %llu bytes sent",
		    (unsigned long long)fault_inj_state.threshold);
	}
	pthread_once(&fault_inj_pv_state.once, fault_inj_pv_state_init);
	if (fault_inj_pv_state.threshold > 0) {
		hpn->fault_pv_after_bytes = fault_inj_pv_state.threshold;
		error("sftp: protocol-violation fault injection enabled: "
		    "connection will report protocol violation after %llu "
		    "bytes sent",
		    (unsigned long long)fault_inj_pv_state.threshold);
	}
}

int
fault_inj_check_send(struct sftp_hpn_conn *hpn, size_t bytes)
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
		int prev = __atomic_fetch_sub(&fault_inj_pv_state.kills_left,
		    1, __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating protocol "
			    "violation after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			sftp_hpn_set_protocol_violation(hpn);
			return -1;
		}
		/* No slot - restore and disarm for this connection. */
		__atomic_fetch_add(&fault_inj_pv_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		hpn->fault_pv_after_bytes = 0;
	}

	/* Check connection-death fault. */
	if (hpn->fault_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_after_bytes) {
		int prev = __atomic_fetch_sub(&fault_inj_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			error("sftp: fault injection: simulating connection "
			    "death after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			/* Mark dead exactly like a real EPIPE - never close
			 * fds at this layer (the 2026-06-12 fd-recycling
			 * lesson: an early close here freed numbers the
			 * kernel reused for other workers' files, and the
			 * reaper's later by-number close killed them). */
			hpn->dead = 1;
			return -1;
		}
		__atomic_fetch_add(&fault_inj_state.kills_left, 1,
		    __ATOMIC_SEQ_CST);
		hpn->fault_after_bytes = 0;
	}

	return 0;
}

#else /* !HPN_FAULT_INJECTION */
/* Keep the translation unit non-empty for pedantic compilers. */
typedef int sftp_fault_inject_not_built;
#endif /* HPN_FAULT_INJECTION */
