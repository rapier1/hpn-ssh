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
 * sftp-fault-inject.c - fault-injection test scaffolding (HPN).
 * See sftp-fault-inject.h for the knobs and the removal contract.
 * TEST/DEBUG ONLY: empty translation unit in normal builds.
 */

#include "includes.h"

#ifdef HPN_FAULT_INJECTION

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* Throttle state for SFTP_FAULT_THROTTLE - manufactured stragglers. */
static struct {
	uint64_t       threshold;   /* start throttling after N sent bytes */
	uint64_t       delay_ms;    /* sleep per send once throttled */
	int            slots_left;  /* connections allowed to throttle */
	pthread_once_t once;
} fault_inj_throttle_state = { 0, 0, 0, PTHREAD_ONCE_INIT };

/* Throttle state for SFTP_FAULT_THROTTLE_RECV - manufactured download
 * stragglers (slow stream as observed by every client instrument). */
static struct {
	uint64_t       threshold;   /* start throttling after N recvd bytes */
	uint64_t       delay_ms;    /* sleep per receive once throttled */
	int            slots_left;  /* connections allowed to throttle */
	pthread_once_t once;
} fault_inj_rthrottle_state = { 0, 0, 0, PTHREAD_ONCE_INIT };

/* Parallel state for SFTP_FAULT_PROTOCOL - protocol violations. */
static struct {
	uint64_t       threshold;
	int            kills_left;
	pthread_once_t once;
} fault_inj_pv_state = { 0, 0, PTHREAD_ONCE_INIT };

/*
 * Corruption state for SFTP_FAULT_CORRUPT=<off1>[,<off2>...][:persist|:vary|:multi[:N]].
 * mode 0 (no suffix, single offset): flip one sent byte, once (original).
 * mode 1 (:persist):  re-flip to the SAME value on EVERY write covering the
 *                     offset (incl. repair re-transfers) -> the dest hash
 *                     repeats -> exercises the repair CONVERGENCE give-up.
 * mode 2 (:vary):     re-flip to a DIFFERENT value each write -> the dest hash
 *                     changes every attempt -> exercises the repair attempt-CAP.
 * mode 3 (:multi[:N], or a bare comma-separated offset list): flip each listed
 *                     offset while a global SLOT remains (default N = number of
 *                     offsets).  No per-write re-flip; slots are consumed by the
 *                     initial transmission of each covered offset.  Because
 *                     verify+repair is a POST-TRANSFER phase, the slots are gone
 *                     by the time the repair re-sends run, so every corruption
 *                     converges -> exercises repair SUCCESS across multiple files
 *                     (one offset, N = file count) AND multiple points in one
 *                     file (N offsets, one file).
 */
#define FAULT_CORRUPT_MAX_OFFSETS 16
static struct {
	uint64_t       offset;     /* mode 0/1/2: single absolute file offset */
	uint64_t       offsets[FAULT_CORRUPT_MAX_OFFSETS]; /* mode 3: offset list */
	int            n_offsets;  /* mode 3: count of offsets parsed */
	int            slots;      /* mode 3: corruptions left (atomic) */
	int            armed;      /* env knob was set */
	int            done;       /* mode 0: fired (atomic, single flip) */
	int            mode;       /* 0=once, 1=persist, 2=vary, 3=multi */
	uint64_t       seq;        /* mode 2: per-corruption counter (atomic) */
	pthread_once_t once;
} fault_inj_corrupt_state = { .once = PTHREAD_ONCE_INIT };

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

static void
fault_inj_throttle_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_THROTTLE");
	char *ep;
	uint64_t bytes, delay;

	if (ev == NULL)
		return;
	bytes = strtoull(ev, &ep, 10);
	if (bytes == 0 || *ep != ':')
		return;
	delay = strtoull(ep + 1, &ep, 10);
	if (delay == 0)
		return;
	fault_inj_throttle_state.threshold  = bytes;
	fault_inj_throttle_state.delay_ms   = delay;
	fault_inj_throttle_state.slots_left = (*ep == ':') ?
	    (int)strtol(ep + 1, NULL, 10) : 1;
}

static void
fault_inj_rthrottle_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_THROTTLE_RECV");
	char *ep;
	uint64_t bytes, delay;

	if (ev == NULL)
		return;
	bytes = strtoull(ev, &ep, 10);
	if (bytes == 0 || *ep != ':')
		return;
	delay = strtoull(ep + 1, &ep, 10);
	if (delay == 0)
		return;
	fault_inj_rthrottle_state.threshold  = bytes;
	fault_inj_rthrottle_state.delay_ms   = delay;
	fault_inj_rthrottle_state.slots_left = (*ep == ':') ?
	    (int)strtol(ep + 1, NULL, 10) : 1;
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
	pthread_once(&fault_inj_throttle_state.once,
	    fault_inj_throttle_state_init);
	if (fault_inj_throttle_state.threshold > 0) {
		hpn->fault_throttle_after_bytes =
		    fault_inj_throttle_state.threshold;
		error("sftp: throttle fault injection enabled: connection "
		    "will slow to %llums/send after %llu bytes sent",
		    (unsigned long long)fault_inj_throttle_state.delay_ms,
		    (unsigned long long)fault_inj_throttle_state.threshold);
	}
	pthread_once(&fault_inj_rthrottle_state.once,
	    fault_inj_rthrottle_state_init);
	if (fault_inj_rthrottle_state.threshold > 0) {
		hpn->fault_recv_throttle_after_bytes =
		    fault_inj_rthrottle_state.threshold;
		error("sftp: recv-throttle fault injection enabled: connection "
		    "will slow to %llums/recv after %llu bytes received",
		    (unsigned long long)fault_inj_rthrottle_state.delay_ms,
		    (unsigned long long)fault_inj_rthrottle_state.threshold);
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
	if (hpn->fault_after_bytes == 0 && hpn->fault_pv_after_bytes == 0 &&
	    hpn->fault_throttle_after_bytes == 0)
		return 0;

	hpn->fault_bytes_sent += bytes;

	/* Throttle: once over the threshold (and holding a slot), sleep per
	 * send - a live, progressing, SLOW connection.  Never kills. */
	if (hpn->fault_throttle_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_throttle_after_bytes) {
		if (!hpn->fault_throttling) {
			int prev = __atomic_fetch_sub(
			    &fault_inj_throttle_state.slots_left, 1,
			    __ATOMIC_SEQ_CST);
			if (prev > 0) {
				hpn->fault_throttling = 1;
				error("sftp: fault injection: throttling "
				    "connection (%llums/send) after %llu "
				    "bytes sent",
				    (unsigned long long)
				    fault_inj_throttle_state.delay_ms,
				    (unsigned long long)
				    hpn->fault_bytes_sent);
			} else {
				__atomic_fetch_add(
				    &fault_inj_throttle_state.slots_left, 1,
				    __ATOMIC_SEQ_CST);
				hpn->fault_throttle_after_bytes = 0;
			}
		}
		if (hpn->fault_throttling) {
			struct timespec ts = {
			    (time_t)(fault_inj_throttle_state.delay_ms / 1000),
			    (long)(fault_inj_throttle_state.delay_ms % 1000) *
			    1000000L };
			nanosleep(&ts, NULL);
		}
	}

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

void
fault_inj_check_recv(struct sftp_hpn_conn *hpn, size_t bytes)
{
	if (hpn == NULL || hpn->fault_recv_throttle_after_bytes == 0)
		return;

	hpn->fault_bytes_recvd += bytes;
	if (hpn->fault_bytes_recvd < hpn->fault_recv_throttle_after_bytes)
		return;

	/* Same slot discipline as the send throttle: claim once, or disarm
	 * this connection if the slots are taken.  Never kills - a live,
	 * progressing, SLOW stream. */
	if (!hpn->fault_recv_throttling) {
		int prev = __atomic_fetch_sub(
		    &fault_inj_rthrottle_state.slots_left, 1,
		    __ATOMIC_SEQ_CST);
		if (prev > 0) {
			hpn->fault_recv_throttling = 1;
			error("sftp: fault injection: recv-throttling "
			    "connection (%llums/recv) after %llu "
			    "bytes received",
			    (unsigned long long)
			    fault_inj_rthrottle_state.delay_ms,
			    (unsigned long long)hpn->fault_bytes_recvd);
		} else {
			__atomic_fetch_add(
			    &fault_inj_rthrottle_state.slots_left, 1,
			    __ATOMIC_SEQ_CST);
			hpn->fault_recv_throttle_after_bytes = 0;
		}
	}
	if (hpn->fault_recv_throttling) {
		struct timespec ts = {
		    (time_t)(fault_inj_rthrottle_state.delay_ms / 1000),
		    (long)(fault_inj_rthrottle_state.delay_ms % 1000) *
		    1000000L };
		nanosleep(&ts, NULL);
	}
}

static void
fault_inj_corrupt_state_init(void)
{
	const char *ev = getenv("SFTP_FAULT_CORRUPT");
	char *ep = NULL;
	int n = 0;

	if (ev == NULL)
		return;
	fault_inj_corrupt_state.armed = 1;

	/* Parse one or more comma-separated absolute file offsets. */
	fault_inj_corrupt_state.offsets[n++] = strtoull(ev, &ep, 10);
	while (ep != NULL && *ep == ',' && n < FAULT_CORRUPT_MAX_OFFSETS)
		fault_inj_corrupt_state.offsets[n++] =
		    strtoull(ep + 1, &ep, 10);
	fault_inj_corrupt_state.n_offsets = n;
	fault_inj_corrupt_state.offset = fault_inj_corrupt_state.offsets[0];

	/* Optional mode suffix.  Default (single offset, no suffix) = one-shot.
	 * :persist/:vary keep the single-offset give-up modes; :multi[:N] (or a
	 * bare offset LIST with no suffix) selects the slot-capped multi mode
	 * that lets the repair converge. */
	if (ep != NULL && *ep == ':') {
		if (strcmp(ep + 1, "persist") == 0)
			fault_inj_corrupt_state.mode = 1;
		else if (strcmp(ep + 1, "vary") == 0)
			fault_inj_corrupt_state.mode = 2;
		else if (strncmp(ep + 1, "multi", 5) == 0) {
			fault_inj_corrupt_state.mode = 3;
			ep += 1 + 5;	/* step past ":multi" */
			fault_inj_corrupt_state.slots = (*ep == ':') ?
			    (int)strtol(ep + 1, NULL, 10) : n;
		}
	} else if (n > 1) {
		fault_inj_corrupt_state.mode = 3;
		fault_inj_corrupt_state.slots = n;
	}
}

void
fault_inj_corrupt(off_t chunk_off, u_char *buf, size_t len)
{
	uint64_t target;

	pthread_once(&fault_inj_corrupt_state.once,
	    fault_inj_corrupt_state_init);
	if (!fault_inj_corrupt_state.armed || buf == NULL || len == 0)
		return;

	/* Mode 3 (multi): flip each listed offset that falls in this write,
	 * while a global slot remains.  Slots are consumed by the initial
	 * transmission; since verify+repair runs as a post-transfer phase the
	 * slots are exhausted before any repair re-send, so each corruption
	 * converges (repair SUCCESS over multiple files and/or multiple points
	 * in one file). */
	if (fault_inj_corrupt_state.mode == 3) {
		int i;

		for (i = 0; i < fault_inj_corrupt_state.n_offsets; i++) {
			uint64_t off = fault_inj_corrupt_state.offsets[i];
			int prev;

			if (off < (uint64_t)chunk_off ||
			    off >= (uint64_t)chunk_off + (uint64_t)len)
				continue;
			prev = __atomic_fetch_sub(&fault_inj_corrupt_state.slots,
			    1, __ATOMIC_SEQ_CST);
			if (prev <= 0) {
				/* Exhausted (this is the repair phase or past
				 * the requested count): restore, leave clean. */
				__atomic_fetch_add(
				    &fault_inj_corrupt_state.slots, 1,
				    __ATOMIC_SEQ_CST);
				continue;
			}
			buf[off - (uint64_t)chunk_off] ^= 0xFFU;
			error("sftp: fault injection: corrupted byte at file "
			    "offset %llu (multi, %d slot(s) left)",
			    (unsigned long long)off, prev - 1);
		}
		return;
	}

	target = fault_inj_corrupt_state.offset;
	if (target < (uint64_t)chunk_off ||
	    target >= (uint64_t)chunk_off + (uint64_t)len)
		return;

	if (fault_inj_corrupt_state.mode == 0) {
		/* One-shot: claim the single flip; lose the race -> another
		 * send already did it. */
		if (__atomic_load_n(&fault_inj_corrupt_state.done,
		    __ATOMIC_SEQ_CST))
			return;
		if (__atomic_exchange_n(&fault_inj_corrupt_state.done, 1,
		    __ATOMIC_SEQ_CST) != 0)
			return;
		buf[target - (uint64_t)chunk_off] ^= 0xFFU;
		error("sftp: fault injection: corrupted byte at file offset "
		    "%llu (once)", (unsigned long long)target);
		return;
	}

	/* Persistent: corrupt on EVERY write covering the offset (so the repair
	 * re-transfer re-corrupts).  mode 1 XORs a CONSTANT mask -> the dest hash
	 * repeats -> repair convergence.  mode 2 XORs a per-corruption counter ->
	 * the dest hash changes each attempt -> repair attempt-cap. */
	if (fault_inj_corrupt_state.mode == 2) {
		uint64_t s = __atomic_add_fetch(&fault_inj_corrupt_state.seq, 1,
		    __ATOMIC_SEQ_CST);
		u_char mask = (u_char)s;

		if (mask == 0)		/* keep it a real corruption */
			mask = 0x5AU;
		buf[target - (uint64_t)chunk_off] ^= mask;
		error("sftp: fault injection: corrupted byte at file offset "
		    "%llu (vary mask=0x%02x)", (unsigned long long)target,
		    (unsigned)mask);
	} else {
		buf[target - (uint64_t)chunk_off] ^= 0xFFU;
		error("sftp: fault injection: corrupted byte at file offset "
		    "%llu (persist)", (unsigned long long)target);
	}
}

#else /* !HPN_FAULT_INJECTION */
/* Keep the translation unit non-empty for pedantic compilers. */
typedef int sftp_fault_inject_not_built;
#endif /* HPN_FAULT_INJECTION */
