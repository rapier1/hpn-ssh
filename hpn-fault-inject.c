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
 * hpn-fault-inject.c - fault-injection test scaffolding for HPN-SSH.
 * TEST/DEBUG ONLY: built only with -DHPN_FAULT_INJECTION, and compiled out
 * otherwise. The environment variables and the API are documented in
 * hpn-fault-inject.h. No hook sites live in the tree: each test campaign
 * adds the fault_inj_ calls it needs and removes them afterward.
 */

#include "includes.h"

#ifdef HPN_FAULT_INJECTION

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "sftp-hpn-client.h"
#include "hpn-fault-inject.h"

#define FAULT_CORRUPT_MAX_OFFSETS 16

/* What HPN_FAULT_CORRUPT does once it has fired. */
enum fault_corrupt_mode {
	CORRUPT_ONCE,		/* flip one byte, once */
	CORRUPT_PERSIST,	/* flip it the same way on every write */
	CORRUPT_VARY,		/* flip it differently on every write */
	CORRUPT_MULTI,		/* flip each listed offset while slots last */
};

/* Mode names for the log, in enum order. */
static const char *corrupt_mode_names[] = {
	[CORRUPT_ONCE] = "once",
	[CORRUPT_PERSIST] = "persist",
	[CORRUPT_VARY] = "vary",
	[CORRUPT_MULTI] = "multi",
};

/* A fault that ends connections: HPN_FAULT_INJECT marks them dead and
 * HPN_FAULT_PROTOCOL reports a protocol violation. */
struct fault_inj_kill {
	uint64_t       threshold;  /* bytes before it fires; 0 = disabled */
	int            kills_left; /* connections left to hit; INT_MAX = no cap */
	pthread_once_t once;
};

/* A fault that slows connections: HPN_FAULT_THROTTLE delays sends and
 * HPN_FAULT_THROTTLE_RECV delays receives, making stragglers. */
struct fault_inj_throttle {
	uint64_t       threshold;  /* bytes before throttling starts */
	uint64_t       delay_ms;   /* sleep per message once throttled */
	int            slots_left; /* connections left to throttle */
	pthread_once_t once;
};

/* note: PTHREAD_ONCE_INIT is used to ensure that the structure is
 * initialized once and only once. This is important to prevent
 * worker threads from resetting state. kills left and slots left
 * are a shared budget across multiple threads so resetting those
 * across multiple inits would break that budget. */
static struct fault_inj_kill fault_inj_state = {
	.once = PTHREAD_ONCE_INIT,
};
static struct fault_inj_kill fault_inj_pv_state = {
	.once = PTHREAD_ONCE_INIT,
};
static struct fault_inj_throttle fault_inj_throttle_state = {
	.once = PTHREAD_ONCE_INIT,
};
static struct fault_inj_throttle fault_inj_rthrottle_state = {
	.once = PTHREAD_ONCE_INIT,
};

/* Corruption state for HPN_FAULT_CORRUPT. The mode decides which fields
 * apply; hpn-fault-inject.h describes the modes and what each one tests. */
static struct {
	uint64_t       offset;     /* ONCE, PERSIST, VARY: the offset */
	uint64_t       offsets[FAULT_CORRUPT_MAX_OFFSETS]; /* MULTI: offset list */
	int            n_offsets;  /* MULTI: count of offsets parsed */
	int            slots;      /* MULTI: corruptions left (atomic) */
	int            armed;      /* env knob was set */
	int            done;       /* ONCE: fired (atomic, single flip) */
	enum fault_corrupt_mode mode;
	uint64_t       seq;        /* VARY: per-corruption counter (atomic) */
	pthread_once_t once;
} fault_inj_corrupt_state = {
	.once = PTHREAD_ONCE_INIT,
};

/* Parse a decimal number from str for the variable name, or exit: a fault
 * that is set but cannot be read would make the test meaningless. */
static uint64_t
fault_inj_number(const char *name, const char *str, char **end)
{
	uint64_t value;

	errno = 0;
	value = strtoull(str, end, 10);
	if (*end == str || errno != 0)
		fatal("hpn fault injection: %s: bad number at \"%s\"",
		    name, str);
	return value;
}

/* Parse a connection or slot cap that must end the value. */
static int
fault_inj_cap(const char *name, const char *str)
{
	char *end;
	uint64_t value = fault_inj_number(name, str, &end);

	if (*end != '\0' || value > INT_MAX)
		fatal("hpn fault injection: %s: bad cap \"%s\"", name, str);
	return (int)value;
}

/* Parse <bytes>[:<max_kills>] from env into a kill fault and announce
 * it once. Unset, or a zero byte count, leaves it disabled; no cap means
 * every connection. what says what the fault does, e.g. "die". */
static void
fault_inj_kill_parse(struct fault_inj_kill *kill, const char *name,
    const char *what)
{
	const char *env = getenv(name);
	char *end;
	uint64_t bytes;

	if (env == NULL)
		return;
	bytes = fault_inj_number(name, env, &end);
	if (bytes == 0)
		return;		/* 0 turns the fault off */
	if (*end == ':')
		kill->kills_left = fault_inj_cap(name, end + 1);
	else if (*end == '\0')
		kill->kills_left = INT_MAX;
	else
		fatal("hpn fault injection: %s: junk after the byte count "
		    "in \"%s\"", name, env);
	kill->threshold = bytes;
	if (kill->kills_left == INT_MAX)
		error("hpn fault injection: every connection will %s after "
		    "%llu bytes sent", what, (unsigned long long)bytes);
	else
		error("hpn fault injection: %d connection%s will %s after "
		    "%llu bytes sent", kill->kills_left,
		    kill->kills_left == 1 ? "" : "s", what,
		    (unsigned long long)bytes);
}

/* Parse <bytes>:<delay_ms>[:<max_conns>] from env into a throttle fault
 * and announce it once. Unset, or a zero byte count or delay, leaves it
 * disabled; no cap means one connection. dir is "send" or "recv". */
static void
fault_inj_throttle_parse(struct fault_inj_throttle *throttle,
    const char *name, const char *dir)
{
	const char *env = getenv(name);
	char *end;
	uint64_t bytes, delay;

	if (env == NULL)
		return;
	bytes = fault_inj_number(name, env, &end);
	if (bytes == 0)
		return;		/* 0 turns the fault off */
	if (*end != ':')
		fatal("hpn fault injection: %s: expected "
		    "<bytes>:<delay_ms> in \"%s\"", name, env);
	delay = fault_inj_number(name, end + 1, &end);
	if (delay == 0)
		return;		/* 0 turns the fault off */
	if (*end == ':')
		throttle->slots_left = fault_inj_cap(name, end + 1);
	else if (*end == '\0')
		throttle->slots_left = 1;
	else
		fatal("hpn fault injection: %s: junk after the delay in "
		    "\"%s\"", name, env);
	throttle->threshold = bytes;
	throttle->delay_ms = delay;
	error("hpn fault injection: %d connection%s will slow to %llums/%s "
	    "after %llu bytes", throttle->slots_left,
	    throttle->slots_left == 1 ? "" : "s",
	    (unsigned long long)delay, dir, (unsigned long long)bytes);
}

/* pthread_once() entry points, one per environment variable */
static void
fault_inj_state_init(void)
{
	fault_inj_kill_parse(&fault_inj_state, "HPN_FAULT_INJECT", "die");
}

static void
fault_inj_pv_state_init(void)
{
	fault_inj_kill_parse(&fault_inj_pv_state, "HPN_FAULT_PROTOCOL",
	    "report a protocol violation");
}

static void
fault_inj_throttle_state_init(void)
{
	fault_inj_throttle_parse(&fault_inj_throttle_state,
	    "HPN_FAULT_THROTTLE", "send");
}

static void
fault_inj_rthrottle_state_init(void)
{
	fault_inj_throttle_parse(&fault_inj_rthrottle_state,
	    "HPN_FAULT_THROTTLE_RECV", "recv");
}

/* Take one unit of a budget shared across threads. Returns 1 if one was
 * left, or 0 if the budget is spent, which leaves it unchanged. */
static int
fault_inj_take_slot(int *budget)
{
	if (__atomic_fetch_sub(budget, 1, __ATOMIC_SEQ_CST) > 0)
		return 1;
	__atomic_fetch_add(budget, 1, __ATOMIC_SEQ_CST);
	return 0;
}

/* Sleep for a throttle's delay. */
static void
fault_inj_sleep_ms(uint64_t ms)
{
	struct timespec ts = {
		.tv_sec = (time_t)(ms / 1000),
		.tv_nsec = (long)(ms % 1000) * 1000000L,
	};

	nanosleep(&ts, NULL);
}

/* Arm a new connection with whichever kill and throttle faults are set.
 * Each connection gets the thresholds; the shared budgets decide which
 * of them actually fault. */
void
fault_inj_arm_conn(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	pthread_once(&fault_inj_state.once, fault_inj_state_init);
	hpn->fault_after_bytes = fault_inj_state.threshold;
	pthread_once(&fault_inj_throttle_state.once,
	    fault_inj_throttle_state_init);
	hpn->fault_throttle_after_bytes = fault_inj_throttle_state.threshold;
	pthread_once(&fault_inj_rthrottle_state.once,
	    fault_inj_rthrottle_state_init);
	hpn->fault_recv_throttle_after_bytes =
	    fault_inj_rthrottle_state.threshold;
	pthread_once(&fault_inj_pv_state.once, fault_inj_pv_state_init);
	hpn->fault_pv_after_bytes = fault_inj_pv_state.threshold;
}

/* Count bytes sent on a connection and fire whichever faults it has
 * crossed. Throttling sleeps and continues; a protocol violation or a
 * death marks the connection and returns -1, as a failed send would.
 * Returns 0 otherwise. */
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

	/* Throttle: once over the threshold and holding a slot, sleep before
	 * each send. The connection stays alive and progressing, only slow. */
	if (hpn->fault_throttle_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_throttle_after_bytes) {
		if (!hpn->fault_throttling) {
			if (fault_inj_take_slot(
			    &fault_inj_throttle_state.slots_left)) {
				hpn->fault_throttling = 1;
				error("hpn fault injection: throttling "
				    "connection (%llums/send) after %llu "
				    "bytes sent",
				    (unsigned long long)
				    fault_inj_throttle_state.delay_ms,
				    (unsigned long long)
				    hpn->fault_bytes_sent);
			} else {
				hpn->fault_throttle_after_bytes = 0;
			}
		}
		if (hpn->fault_throttling)
			fault_inj_sleep_ms(fault_inj_throttle_state.delay_ms);
	}

	/* Check protocol-violation fault first (higher priority signal). */
	if (hpn->fault_pv_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_pv_after_bytes) {
		if (fault_inj_take_slot(&fault_inj_pv_state.kills_left)) {
			error("hpn fault injection: simulating protocol "
			    "violation after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			/* Only the HPN state is in hand here, so latch both
			 * flags directly, the way
			 * sftp_conn_set_protocol_violation does. */
			hpn->dead = 1;
			hpn->protocol_violation = 1;
			return -1;
		}
		/* no slot left: disarm this connection */
		hpn->fault_pv_after_bytes = 0;
	}

	/* Check connection-death fault. */
	if (hpn->fault_after_bytes > 0 &&
	    hpn->fault_bytes_sent >= hpn->fault_after_bytes) {
		if (fault_inj_take_slot(&fault_inj_state.kills_left)) {
			error("hpn fault injection: simulating connection "
			    "death after %llu bytes sent",
			    (unsigned long long)hpn->fault_bytes_sent);
			/* Mark the connection dead as a real EPIPE would, and
			 * never close descriptors here. An early close once
			 * freed numbers the kernel reused for other workers'
			 * files, and the reaper's later close by number
			 * killed them. */
			hpn->dead = 1;
			return -1;
		}
		hpn->fault_after_bytes = 0;
	}

	return 0;
}

/* Count bytes received on a connection and, once it crosses the receive
 * throttle and holds a slot, sleep before each further receive. Never
 * fails the connection. */
void
fault_inj_check_recv(struct sftp_hpn_conn *hpn, size_t bytes)
{
	if (hpn == NULL || hpn->fault_recv_throttle_after_bytes == 0)
		return;

	hpn->fault_bytes_recvd += bytes;
	if (hpn->fault_bytes_recvd < hpn->fault_recv_throttle_after_bytes)
		return;

	/* Same slot rule as the send throttle: claim a slot once, or disarm
	 * this connection if none is left. The stream stays alive, only
	 * slow. */
	if (!hpn->fault_recv_throttling) {
		if (fault_inj_take_slot(&fault_inj_rthrottle_state.slots_left)) {
			hpn->fault_recv_throttling = 1;
			error("hpn fault injection: recv-throttling "
			    "connection (%llums/recv) after %llu "
			    "bytes received",
			    (unsigned long long)
			    fault_inj_rthrottle_state.delay_ms,
			    (unsigned long long)hpn->fault_bytes_recvd);
		} else {
			hpn->fault_recv_throttle_after_bytes = 0;
		}
	}
	if (hpn->fault_recv_throttling)
		fault_inj_sleep_ms(fault_inj_rthrottle_state.delay_ms);
}

/* pthread_once() entry point: parse HPN_FAULT_CORRUPT into the offsets to
 * flip and the mode. A bare list of more than one offset means MULTI. */
static void
fault_inj_corrupt_state_init(void)
{
	const char *name = "HPN_FAULT_CORRUPT";
	const char *env = getenv(name);
	char *end;
	int count = 0;

	if (env == NULL)
		return;

	/* Parse one or more comma-separated absolute file offsets. */
	fault_inj_corrupt_state.offsets[count++] =
	    fault_inj_number(name, env, &end);
	while (*end == ',') {
		if (count == FAULT_CORRUPT_MAX_OFFSETS)
			fatal("hpn fault injection: %s: more than %d offsets",
			    name, FAULT_CORRUPT_MAX_OFFSETS);
		fault_inj_corrupt_state.offsets[count++] =
		    fault_inj_number(name, end + 1, &end);
	}
	fault_inj_corrupt_state.n_offsets = count;
	fault_inj_corrupt_state.offset = fault_inj_corrupt_state.offsets[0];

	/* Optional mode suffix. A single offset with no suffix is ONCE;
	 * :persist and :vary take one offset; :multi[:N], or a bare list of
	 * offsets, is MULTI. */
	if (*end == ':') {
		if (strcmp(end + 1, "persist") == 0)
			fault_inj_corrupt_state.mode = CORRUPT_PERSIST;
		else if (strcmp(end + 1, "vary") == 0)
			fault_inj_corrupt_state.mode = CORRUPT_VARY;
		else if (strncmp(end + 1, "multi", 5) == 0) {
			fault_inj_corrupt_state.mode = CORRUPT_MULTI;
			end += 1 + 5;	/* step past ":multi" */
			if (*end == ':')
				fault_inj_corrupt_state.slots =
				    fault_inj_cap(name, end + 1);
			else if (*end == '\0')
				fault_inj_corrupt_state.slots = count;
			else
				fatal("hpn fault injection: %s: unknown mode "
				    "in \"%s\"", name, env);
		} else
			fatal("hpn fault injection: %s: unknown mode \"%s\"",
			    name, end + 1);
		if (count > 1 && fault_inj_corrupt_state.mode != CORRUPT_MULTI)
			fatal("hpn fault injection: %s: %s takes one offset",
			    name, corrupt_mode_names[
			    fault_inj_corrupt_state.mode]);
	} else if (*end != '\0') {
		fatal("hpn fault injection: %s: junk after the offsets in "
		    "\"%s\"", name, env);
	} else if (count > 1) {
		fault_inj_corrupt_state.mode = CORRUPT_MULTI;
		fault_inj_corrupt_state.slots = count;
	}
	fault_inj_corrupt_state.armed = 1;
	if (fault_inj_corrupt_state.mode == CORRUPT_MULTI)
		error("hpn fault injection: corrupting %d offset%s in multi "
		    "mode, %d time%s at most", count, count == 1 ? "" : "s",
		    fault_inj_corrupt_state.slots,
		    fault_inj_corrupt_state.slots == 1 ? "" : "s");
	else
		error("hpn fault injection: corrupting %d offset%s in %s mode",
		    count, count == 1 ? "" : "s",
		    corrupt_mode_names[fault_inj_corrupt_state.mode]);
}

/* Corrupt the outgoing write of len bytes at file offset chunk_off, in
 * place, if it covers an armed offset. The source file is never touched;
 * only the bytes on their way out change. */
void
fault_inj_corrupt(off_t chunk_off, u_char *buf, size_t len)
{
	uint64_t target;

	pthread_once(&fault_inj_corrupt_state.once,
	    fault_inj_corrupt_state_init);
	if (!fault_inj_corrupt_state.armed || buf == NULL || len == 0)
		return;

	/* MULTI: flip each listed offset in this write while a slot remains.
	 * The first transmission spends the slots, and verify and repair run
	 * after the transfer, so the repair re-sends go out clean. */
	if (fault_inj_corrupt_state.mode == CORRUPT_MULTI) {
		int i;

		for (i = 0; i < fault_inj_corrupt_state.n_offsets; i++) {
			uint64_t off = fault_inj_corrupt_state.offsets[i];

			if (off < (uint64_t)chunk_off ||
			    off >= (uint64_t)chunk_off + (uint64_t)len)
				continue;
			/* Exhausted (this is the repair phase or past the
			 * requested count): leave the byte clean. */
			if (!fault_inj_take_slot(&fault_inj_corrupt_state.slots))
				continue;
			buf[off - (uint64_t)chunk_off] ^= 0xFFU;
			error("hpn fault injection: corrupted byte at file "
			    "offset %llu (multi, %d slot(s) left)",
			    (unsigned long long)off,
			    __atomic_load_n(&fault_inj_corrupt_state.slots,
			    __ATOMIC_SEQ_CST));
		}
		return;
	}

	target = fault_inj_corrupt_state.offset;
	if (target < (uint64_t)chunk_off ||
	    target >= (uint64_t)chunk_off + (uint64_t)len)
		return;

	if (fault_inj_corrupt_state.mode == CORRUPT_ONCE) {
		/* ONCE: claim the single flip. Losing the race means another
		 * send already made it. */
		if (__atomic_load_n(&fault_inj_corrupt_state.done,
		    __ATOMIC_SEQ_CST))
			return;
		if (__atomic_exchange_n(&fault_inj_corrupt_state.done, 1,
		    __ATOMIC_SEQ_CST) != 0)
			return;
		buf[target - (uint64_t)chunk_off] ^= 0xFFU;
		error("hpn fault injection: corrupted byte at file offset "
		    "%llu (once)", (unsigned long long)target);
		return;
	}

	/* PERSIST and VARY corrupt every write that covers the offset, repairs
	 * included. PERSIST uses a fixed mask, so the target hash repeats; VARY
	 * uses a counter, so the hash changes on every attempt. */
	if (fault_inj_corrupt_state.mode == CORRUPT_VARY) {
		uint64_t seq = __atomic_add_fetch(&fault_inj_corrupt_state.seq, 1,
		    __ATOMIC_SEQ_CST);
		u_char mask = (u_char)seq;

		if (mask == 0)		/* keep it a real corruption */
			mask = 0x5AU;
		buf[target - (uint64_t)chunk_off] ^= mask;
		error("hpn fault injection: corrupted byte at file offset "
		    "%llu (vary mask=0x%02x)", (unsigned long long)target,
		    (unsigned)mask);
	} else {
		buf[target - (uint64_t)chunk_off] ^= 0xFFU;
		error("hpn fault injection: corrupted byte at file offset "
		    "%llu (persist)", (unsigned long long)target);
	}
}

#else /* !HPN_FAULT_INJECTION */
/* Keep the translation unit non-empty for pedantic compilers. */
typedef int hpn_fault_inject_not_built;
#endif /* HPN_FAULT_INJECTION */
