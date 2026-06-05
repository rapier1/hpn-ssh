/*
 * sftp-hpn-client.c - HPN-SSH extensions to the SFTP client connection.
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
#include <time.h>

#include <stdarg.h>
#include <stdio.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"		/* monotime_double, MINIMUM, MAXIMUM */

/* Needed by the hash-range / check-file / file-layout RPC code that
 * remained in this file after the bundle extraction (2026-05-31).
 * The bundle module owns its own copies of these includes. */
#include "sftp-common.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-client.h"
#include "sftp-hpn-bundle.h"	/* HPN_EXT_HASH_RANGE etc. wire names */

#ifdef HPN_FAULT_INJECTION
static struct {
	uint64_t       threshold;  /* byte threshold; 0 = disabled */
	int            kills_left; /* remaining kill slots; INT_MAX = unlimited */
	pthread_once_t once;
} fi_state = { 0, 0, PTHREAD_ONCE_INIT };

/* Parallel struct for SFTP_FAULT_PROTOCOL - triggers protocol violation. */
static struct {
	uint64_t       threshold;
	int            kills_left;
	pthread_once_t once;
} fi_pv_state = { 0, 0, PTHREAD_ONCE_INIT };

/*
 * ENV-VAR SFTP_FAULT_INJECT - compile-gated (HPN_FAULT_INJECTION):
 * fault-injection knob.  Parsed once from
 * SFTP_FAULT_INJECT=<bytes>[:<max_kills>] :
 *   bytes     - worker connection dies after sending this many bytes.
 *   max_kills - optional; at most this many workers are killed (default: all).
 * Example: SFTP_FAULT_INJECT=150000:2  kills at most 2 out of N workers.
 * See benchmark/env-vars-reference.md.
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
 * ENV-VAR SFTP_FAULT_PROTOCOL - compile-gated (HPN_FAULT_INJECTION):
 * fault-injection knob.  Parsed once from
 * SFTP_FAULT_PROTOCOL=<bytes>[:<max_kills>] :
 *   bytes     - worker fires a protocol violation after sending this many bytes.
 *   max_kills - optional; at most this many workers trigger the fault.
 * Example: SFTP_FAULT_PROTOCOL=150000:1  triggers one protocol violation.
 * See benchmark/env-vars-reference.md.
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

/* ──────────────────────────────────────────────────────────────────────────
 * Watchdog pause primitive (HPN).  Lets a worker tell the parallel
 * orchestrator's watchdog that it's about to be busy with legitimate
 * non-byte-transfer work (verify-hash phase, fsync after large write,
 * bundle accumulate/extract, etc.) for up to N seconds.  Watchdog
 * suppresses its inactivity-based heuristics for this worker until the
 * deadline expires; the SSH-child-gone check still fires regardless.
 * See sftp-hpn-client.h for full semantics.
 *
 * Used now by the verify-hash path in sftp_upload / sftp_download / the
 * chunked-resume helpers / sftp_verify_transfer.  Designed to be reusable
 * for any future operation that legitimately pauses byte flow on the SFTP
 * wire for an extended interval.
 * ────────────────────────────────────────────────────────────────────────── */

void
sftp_hpn_watchdog_pause(struct sftp_hpn_conn *hpn, unsigned int seconds)
{
	uint64_t deadline_ns;
	uint64_t cur;

	if (hpn == NULL)
		return;

	deadline_ns = monotime_ns() +
	    (uint64_t)seconds * 1000000000ULL;

	/*
	 * Extend, never shrink.  A shorter pause arriving while a longer
	 * pause is in flight must not undo the longer one (think: two
	 * different code paths each declaring their grace; whichever needs
	 * more time should win).
	 */
	cur = __atomic_load_n(&hpn->watchdog_pause_until_ns,
	    __ATOMIC_RELAXED);
	if (deadline_ns > cur) {
		__atomic_store_n(&hpn->watchdog_pause_until_ns,
		    deadline_ns, __ATOMIC_RELAXED);
	}
}

void
sftp_hpn_watchdog_resume(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->watchdog_pause_until_ns, 0,
	    __ATOMIC_RELAXED);
}

/*
 * sftp_hpn_grace_for_hash() was retired in favour of the heartbeat
 * protocol (see sftp-hpn-server.h: HPN_HEARTBEAT_*).  The watchdog pause
 * is now refreshed by each heartbeat the server emits during a long
 * hash, so the initial pause window is a fixed
 * HPN_HEARTBEAT_REFRESH_SEC at every callsite - independent of file
 * size or assumed disk speed.  The old grace formula's 1 GB/s assumption
 * broke under parallel-worker disk contention; heartbeats observe actual
 * progress instead of predicting it.
 */

/* ──────────────────────────────────────────────────────────────────────────
 * Adaptive read-ahead controller (HPN).  See sftp-hpn-client.h for rationale.
 * ────────────────────────────────────────────────────────────────────────── */

#define RDAHEAD_FLOOR        64u    /* smallest depth we ever probe */
#define RDAHEAD_GROW_PCT     0.15   /* >15% throughput gain => keep doubling */
#define RDAHEAD_EWMA_ALPHA   0.6    /* weight of the newest window's rate */
#define RDAHEAD_MIN_WIN_SEC  0.02   /* ignore windows shorter than this (noise) */

/*
 * Time-based recovery-probe interval (seconds).  When the controller has
 * been shrunk to floor by Part B's backpressure signal, it would
 * normally wait for a full window of `cur` acks before doubling - at
 * floor=64 on a slow path that can take tens of seconds and was the
 * dominant component of the ~100 s wedge-recovery tails observed in the
 * 2026-05-30 br008 mixed-tree Phase 2b run (iter15, iter16).
 *
 * If we've been at floor with `settled=0` for this long without filling
 * a window, force a doubling without waiting for full-window evidence.
 * This is a probe - if path conditions are still bad, Part B will fire
 * again and shrink us back to floor.  Oscillation cost is bounded:
 * one probe-and-shrink cycle every ~15 s (5 s probe interval + ~10 s
 * Part B detection), which is far better than indefinite floor-stuck
 * behaviour.  Restricted to cur==floor so we never accelerate growth
 * above the BDP knee on healthy paths.
 *
 * Half of Part B's threshold (10 s) is the chosen value: faster than
 * Part B's reaction means we bias toward higher depth, which is the
 * right direction when recovering from a transient wedge.
 */
#define RDAHEAD_PROBE_INTERVAL_SEC  5.0

/* SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC lives in sftp-hpn-client.h so the
 * STATUS-read sites in sftp-client.c share the same constant. */

/*
 * Seed the controller for a new connection: cap = num_requests (the -R
 * ceiling), floor = RDAHEAD_FLOOR clamped to cap, start probing at the floor.
 * HPN_RDAHEAD=fixed disables adaptation (legacy flat num_requests pipeline).
 */
void
sftp_hpn_rdahead_init(struct sftp_hpn_conn *hpn, uint32_t cap)
{
	const char *e;

	if (hpn == NULL)
		return;
	memset(&hpn->rd, 0, sizeof(hpn->rd));
	hpn->rd.cap = cap ? cap : 1;
	hpn->rd.floor = MINIMUM(RDAHEAD_FLOOR, hpn->rd.cap);
	hpn->rd.cur = hpn->rd.floor;
	hpn->rd.last_rising = hpn->rd.floor;
	hpn->rd.win_start = monotime_double();
	hpn->rd.enabled = 1;
	/* ENV-VAR HPN_RDAHEAD - developer-only: kill switch for the
	 * adaptive read-ahead controller.  Setting HPN_RDAHEAD=fixed
	 * reverts to the legacy flat num_requests pipeline (a fixed
	 * in-flight window equal to the -R ceiling).  Any other value or
	 * the unset case keeps the controller adaptive.  See
	 * benchmark/env-vars-reference.md. */
	if ((e = getenv("HPN_RDAHEAD")) != NULL && strcmp(e, "fixed") == 0)
		hpn->rd.enabled = 0;
}

/*
 * Current target in-flight depth, or 0 when adaptation is disabled - callers
 * treat 0 as "keep the fixed num_requests pipeline".
 */
uint32_t
sftp_hpn_rdahead_depth(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL || !hpn->rd.enabled)
		return 0;	/* 0 => caller keeps its fixed num_requests depth */
	return hpn->rd.cur;
}

/*
 * Feed one completed request's bytes to the controller.  Once per window (one
 * depth's worth of requests, and at least RDAHEAD_MIN_WIN_SEC) it measures
 * app-layer throughput and resizes the depth: EWMA-smooth the rate, grow x2
 * while the gain exceeds RDAHEAD_GROW_PCT, otherwise settle at the last depth
 * that was still rising (the BDP knee) and stop probing.  No-op once settled
 * or when disabled.
 */
void
sftp_hpn_rdahead_account(struct sftp_hpn_conn *hpn, size_t nbytes)
{
	struct sftp_rdahead *rd;
	double now, elapsed, rate, gain;

	if (hpn == NULL || !hpn->rd.enabled || hpn->rd.settled)
		return;
	rd = &hpn->rd;
	rd->win_bytes += nbytes;
	rd->win_reqs++;

	/*
	 * Time-based recovery probe: when Part B's backpressure signal
	 * shrunk us to floor with settled=0, the next window would
	 * normally need `cur` acks to complete before doubling.  At
	 * floor=64 on a slow path that takes tens of seconds (the dominant
	 * component of the ~100 s wedge-recovery tails observed in the
	 * 2026-05-30 br008 mixed-tree Phase 2b iter15/iter16 runs).
	 * Force a doubling after RDAHEAD_PROBE_INTERVAL_SEC even without
	 * a full window's worth of evidence.  If the path is still bad,
	 * Part B will fire again and shrink us back to floor - bounded
	 * oscillation cycle of ~15 s, far better than indefinite floor-
	 * stuck behaviour.  Restricted to cur==floor so probes never
	 * accelerate growth above the BDP knee on healthy paths.
	 */
	if (rd->cur == rd->floor && rd->cur < rd->cap) {
		double probe_elapsed = monotime_double() - rd->win_start;
		if (probe_elapsed > RDAHEAD_PROBE_INTERVAL_SEC) {
			uint32_t before = rd->cur;
			rd->last_rising = rd->cur;
			rd->cur = MINIMUM(rd->cur * 2, rd->cap);
			rd->win_bytes = 0;
			rd->win_reqs = 0;
			rd->win_start = monotime_double();
			/* Part D: cur is leaving floor, clear the
			 * persistent-degradation counters so a future bad
			 * patch starts a fresh accounting run rather than
			 * inheriting history from before recovery. */
			rd->consecutive_bp_at_floor = 0;
			rd->time_first_at_floor = 0.0;
			debug2_f("rdahead: time-probe → depth %u -> %u "
			    "(forced after %.1fs at floor)",
			    before, rd->cur, probe_elapsed);
			return;
		}
	}

	if (rd->win_reqs < rd->cur)
		return;				/* window = one depth's worth */
	now = monotime_double();
	elapsed = now - rd->win_start;
	if (elapsed < RDAHEAD_MIN_WIN_SEC)
		return;				/* too short to measure; keep filling */

	rate = (double)rd->win_bytes / elapsed;
	if (rd->last_rate <= 0.0) {
		/* First window: establish a baseline, then start climbing. */
		rd->last_rate = rate;
		rd->last_rising = rd->cur;
		if (rd->cur < rd->cap)
			rd->cur = MINIMUM(rd->cur * 2, rd->cap);
		else
			rd->settled = 1;
	} else {
		/* Smooth so one jittery window can't flip a decision. */
		rate = RDAHEAD_EWMA_ALPHA * rate +
		    (1.0 - RDAHEAD_EWMA_ALPHA) * rd->last_rate;
		gain = (rate - rd->last_rate) / rd->last_rate;
		if (gain > RDAHEAD_GROW_PCT) {
			/* Still benefiting from a deeper pipe. */
			rd->last_rising = rd->cur;
			if (rd->cur < rd->cap)
				rd->cur = MINIMUM(rd->cur * 2, rd->cap);
			else
				rd->settled = 1;	/* at the -R ceiling */
		} else {
			/* Plateau or overshoot: settle at the smallest depth
			 * that reached the throughput knee. */
			rd->cur = MAXIMUM(rd->last_rising, rd->floor);
			rd->settled = 1;
		}
		rd->last_rate = rate;
	}
	rd->win_bytes = 0;
	rd->win_reqs = 0;
	rd->win_start = now;
	/* Part D: any successful window that lands cur above floor counts
	 * as recovery - clear the persistent-degradation counters so a
	 * future bad patch starts a fresh accounting run. */
	if (rd->cur > rd->floor) {
		rd->consecutive_bp_at_floor = 0;
		rd->time_first_at_floor = 0.0;
	}
	debug2_f("rdahead: depth=%u cap=%u rate=%.1f MiB/s%s",
	    rd->cur, rd->cap, rate / (1024.0 * 1024.0),
	    rd->settled ? " (settled)" : "");
}

/*
 * Backpressure signal: caller observed a STATUS read that blocked longer
 * than RDAHEAD_BP_THRESHOLD_SEC and concluded the pipeline is wedged.
 * Multiplicatively decrease the in-flight depth (clamped to RDAHEAD_FLOOR),
 * clear `settled` so the controller re-probes from the new lower depth,
 * and discard the throughput baseline so the next window's rate isn't
 * compared against the now-invalid pre-wedge measurement.  No-op when the
 * controller is disabled (HPN_RDAHEAD=fixed) - in that mode the caller
 * is on a fixed pipeline and has nothing for us to adjust.
 *
 * Analogue: TCP's RTO-triggered multiplicative decrease.  See the
 * RDAHEAD_BP_THRESHOLD_SEC comment for the design rationale.
 */
void
sftp_hpn_rdahead_backpressure_signal(struct sftp_hpn_conn *hpn)
{
	struct sftp_rdahead *rd;
	uint32_t before;
	double now;

	if (hpn == NULL || !hpn->rd.enabled)
		return;
	rd = &hpn->rd;
	before = rd->cur;
	now = monotime_double();
	rd->cur = MAXIMUM(rd->cur / 2, rd->floor);
	rd->settled = 0;
	rd->last_rate = 0.0;
	rd->last_rising = rd->cur;
	rd->win_bytes = 0;
	rd->win_reqs = 0;
	rd->win_start = now;

	/*
	 * Part D - persistent-degradation tracking.  Each backpressure event
	 * that lands us at floor adds to the count and, on first arrival,
	 * stamps the time.  If either reap threshold is crossed, mark the
	 * connection dead so the orchestrator's existing watchdog reaps and
	 * respawns the worker on a fresh TCP session.  A fresh connection
	 * gets fresh kernel TCP state (cwnd, RTO, retransmits) which is the
	 * cure for TCP-wedge-class failures; path-wide degradation will
	 * re-trigger on the new connection, the session-wide respawn
	 * cooldown machinery (sftp-parallel.c) bounds the resulting churn.
	 */
	if (rd->cur == rd->floor) {
		if (rd->time_first_at_floor <= 0.0)
			rd->time_first_at_floor = now;
		rd->consecutive_bp_at_floor++;

		if (rd->consecutive_bp_at_floor >=
		    SFTP_HPN_RDAHEAD_REAP_BP_COUNT ||
		    (now - rd->time_first_at_floor) >
		    SFTP_HPN_RDAHEAD_REAP_TIME_AT_FLOOR_SEC) {
			debug_f("rdahead: connection persistently degraded "
			    "(bp_at_floor=%u floor_for=%.1fs); marking dead "
			    "for orchestrator respawn",
			    rd->consecutive_bp_at_floor,
			    now - rd->time_first_at_floor);
			hpn->dead = 1;
			/* Reset Part D state for hygiene - this hpn is
			 * about to be torn down anyway, but a clean state
			 * means a fresh respawn doesn't inherit anything. */
			rd->consecutive_bp_at_floor = 0;
			rd->time_first_at_floor = 0.0;
		}
	}

	debug2_f("rdahead: backpressure → depth %u -> %u (re-probing)",
	    before, rd->cur);
}

/*
 * Effective in-flight request cap for the UPLOAD-style sites (do_upload_body,
 * sftp_upload_range): the controller's current depth, or `fallback`
 * (num_requests) when adaptation is disabled.
 */
uint32_t
sftp_hpn_rdahead_cap(struct sftp_hpn_conn *hpn, uint32_t fallback)
{
	uint32_t d = sftp_hpn_rdahead_depth(hpn);

	return d != 0 ? d : fallback;
}

/*
 * Next read-ahead window for the DOWNLOAD-style ramp sites (sftp_download,
 * sftp_download_range, sftp_crossload): feed `nbytes` to the controller, then
 * return the new window - the adaptive depth, or the legacy +1 ramp
 * (cur -> cur+1, capped at `cap`) when adaptation is disabled.
 */
uint32_t
sftp_hpn_rdahead_window(struct sftp_hpn_conn *hpn, size_t nbytes,
    uint32_t cur, uint32_t cap)
{
	uint32_t d;

	sftp_hpn_rdahead_account(hpn, nbytes);
	d = sftp_hpn_rdahead_depth(hpn);
	if (d != 0)
		return d;			/* adaptive depth */
	return (cur < cap) ? cur + 1 : cur;	/* legacy +1 ramp (disabled) */
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
		/* No slot - restore and disarm for this connection. */
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
		/* No slot - restore and disarm for this connection. */
		__atomic_fetch_add(&fi_state.kills_left, 1, __ATOMIC_SEQ_CST);
		hpn->fault_after_bytes = 0;
	}

	return 0;
}
#endif /* HPN_FAULT_INJECTION */



/* ── BEGIN sftp-hash-range: client-side helpers ───────────────────────────
 *
 * Helpers for chunked resume.  See sftp-hpn-client.h for the public API
 * and the design rationale at project_chunked_resume_plan.md in memory.
 *
 * sftp_hpn_xxhash_local_range - local XXH3 over an open fd's range
 * sftp_hpn_hash_remote_ranges  - wire-level sftp-hash-range@hpnssh.org query
 */

#define HASH_RANGE_READ_BUF_LEN	65536U

#include "sftp.h"
#include "sftp-client-internal.h"
#include "sftp-hpn-server.h"	/* HPN_EXT_HASH_RANGE wire-name macro */
#define XXH_INLINE_ALL
#include "xxhash.h"

int
sftp_hpn_xxhash_local_range(int fd, u_int64_t offset, u_int64_t length,
    u_int64_t *hash_out)
{
	XXH3_state_t	*state;
	u_char		 buf[HASH_RANGE_READ_BUF_LEN];
	u_int64_t	 remaining;
	ssize_t		 nread;

	if (hash_out == NULL || fd < 0) {
		errno = EINVAL;
		return -1;
	}

	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		return -1;
	}
	if (XXH3_64bits_reset(state) == XXH_ERROR) {
		error_f("XXH3_64bits_reset failed");
		XXH3_freeState(state);
		return -1;
	}

	if (length > 0 && lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
		error_f("lseek to %llu: %s",
		    (unsigned long long)offset, strerror(errno));
		XXH3_freeState(state);
		return -1;
	}

	remaining = length;
	while (remaining > 0) {
		size_t toread = (size_t)MINIMUM(
		    (u_int64_t)sizeof(buf), remaining);
		nread = read(fd, buf, toread);
		if (nread == 0)
			break;	/* short read - caller may treat as
				 * truncated; we hash what we got */
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			error_f("read at offset %llu: %s",
			    (unsigned long long)offset, strerror(errno));
			XXH3_freeState(state);
			return -1;
		}
		if (XXH3_64bits_update(state, buf, (size_t)nread)
		    == XXH_ERROR) {
			error_f("XXH3_64bits_update failed");
			XXH3_freeState(state);
			return -1;
		}
		remaining -= (u_int64_t)nread;
	}

	*hash_out = (u_int64_t)XXH3_64bits_digest(state);
	XXH3_freeState(state);
	return 0;
}

int
sftp_hpn_hash_remote_ranges(struct sftp_conn *conn, const char *path,
    const struct sftp_hash_range *ranges, u_int n, u_int64_t *hashes_out)
{
	struct sshbuf	*msg = NULL;
	u_int		 id, rid, num_hashes, i;
	u_char		 type;
	int		 r;
	int		 rc = -1;

	if (conn == NULL || path == NULL || ranges == NULL ||
	    hashes_out == NULL || n == 0) {
		errno = EINVAL;
		return -1;
	}

	if (!sftp_conn_has_hash_range(conn)) {
		/*
		 * Expected condition when talking to a pre-19.0 server;
		 * the caller will fall through to hpn-check-file whole-file
		 * hashing.  Keep at debug level so it doesn't spam users.
		 */
		debug_f("server lacks sftp-hash-range; chunked path "
		    "unavailable");
		return -1;
	}

	if ((msg = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		return -1;
	}

	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending sftp-hash-range \"%s\" num_ranges=%u id=%u",
	    path, n, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_HASH_RANGE)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal_fr(r, "compose request header");
	for (i = 0; i < n; i++) {
		if ((r = sshbuf_put_u64(msg, ranges[i].off)) != 0 ||
		    (r = sshbuf_put_u64(msg, ranges[i].len)) != 0)
			fatal_fr(r, "compose range %u", i);
	}
	if (send_msg(conn, msg) != 0) {
		logit_f("sftp-hash-range \"%s\": transport send failed; "
		    "falling back to whole-file hash", path);
		goto out;
	}

	/*
	 * Initial watchdog grace covers the worker time until the first
	 * server heartbeat lands.  Each heartbeat refreshes the pause for
	 * another HPN_HEARTBEAT_REFRESH_SEC so the orchestrator never kills
	 * us while the server is making forward progress.  See
	 * sftp-hpn-server.h for the protocol.
	 */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);

	for (;;) {
		sshbuf_reset(msg);

		if (get_msg(conn, msg) != 0) {
			logit_f("sftp-hash-range \"%s\": transport receive "
			    "failed; falling back to whole-file hash", path);
			break;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			logit_f("sftp-hash-range \"%s\": parse reply header: "
			    "%s; falling back to whole-file hash",
			    path, ssh_err(r));
			break;
		}
		if (rid != id) {
			logit_f("sftp-hash-range \"%s\": reply id mismatch "
			    "(got %u expected %u); falling back to "
			    "whole-file hash", path, rid, id);
			break;
		}

		if (type == SSH2_FXP_STATUS) {
			u_int	 status = SSH2_FX_FAILURE;
			char	*errmsg = NULL;

			(void)sshbuf_get_u32(msg, &status);
			(void)sshbuf_get_cstring(msg, &errmsg, NULL);
			/*
			 * User-visible warning per the chunked-resume design:
			 * server failure to hash a range indicates a problem
			 * on the destination (FS corruption, concurrent
			 * modification, permission change, etc.) and the user
			 * should know even if the fallback transfer succeeds.
			 */
			logit_f("sftp-hash-range \"%s\": server reported "
			    "error (%s); the destination may have storage / "
			    "FS / permission issues - falling back to "
			    "whole-file hash",
			    path,
			    (errmsg != NULL && *errmsg != '\0')
			        ? errmsg : fx2txt(status));
			free(errmsg);
			break;
		}
		if (type != SSH2_FXP_EXTENDED_REPLY) {
			logit_f("sftp-hash-range \"%s\": unexpected reply "
			    "type %u; falling back to whole-file hash",
			    path, type);
			break;
		}
		if ((r = sshbuf_get_u32(msg, &num_hashes)) != 0) {
			logit_f("sftp-hash-range \"%s\": parse num_hashes: "
			    "%s; falling back to whole-file hash",
			    path, ssh_err(r));
			break;
		}

		/*
		 * Heartbeat reply: refresh the watchdog pause and wait for
		 * the next message.  Real num_hashes is bounded by the
		 * SFTP_HASH_RANGE_MAX_RANGES cap (65536), well below the
		 * sentinel.
		 */
		if (num_hashes == HPN_NUM_HASHES_HEARTBEAT) {
			debug3_f("sftp-hash-range \"%s\" id=%u heartbeat",
			    path, id);
			sftp_conn_watchdog_pause(conn,
			    HPN_HEARTBEAT_REFRESH_SEC);
			continue;
		}

		if (num_hashes != n) {
			logit_f("sftp-hash-range \"%s\": server returned %u "
			    "hashes for %u ranges; falling back to "
			    "whole-file hash", path, num_hashes, n);
			break;
		}
		for (i = 0; i < n; i++) {
			if ((r = sshbuf_get_u64(msg, &hashes_out[i])) != 0) {
				logit_f("sftp-hash-range \"%s\": parse hash "
				    "%u: %s; falling back to whole-file "
				    "hash", path, i, ssh_err(r));
				rc = -1;
				goto loop_done;
			}
		}

		debug3_f("sftp-hash-range \"%s\": received %u hashes", path, n);
		rc = 0;
		break;
	}

loop_done:
	sftp_conn_watchdog_resume(conn);
out:
	sshbuf_free(msg);
	return rc;
}

/*
 * Tunables for chunked resume.  Defaults chosen per the locked design
 * (project_chunked_resume_plan.md memory):
 *
 *  CHUNK_HASH_CHUNK_SIZE       - granularity of re-transfer.  64 MiB makes
 *                                per-chunk protocol overhead (16 B request,
 *                                8 B response) negligible vs. typical
 *                                missed-chunk transfer cost.
 *  CHUNK_HASH_MIN_FILE_SIZE    - below this, skip the chunked path; the
 *                                full-file hash gate is cheaper than the
 *                                chunked-request round trip on small files.
 *                                Chosen as 2 * CHUNK_SIZE so any engaged
 *                                run has at least two chunks to map.
 *  CHUNK_HASH_MAX_RANGES_PER_REQUEST
 *                              - must match server-side cap in
 *                                sftp-hpn-server.c (SFTP_HASH_RANGE_MAX_RANGES).
 *                                Bounds server-side allocation against an
 *                                unbounded request; the server allocates
 *                                N range + N hash entries up front.  At
 *                                64 MiB chunks this also caps single-file
 *                                chunked-resume at 4 TiB; bigger files
 *                                decline and fall through to the existing
 *                                full-file gate.
 */
#define CHUNK_HASH_CHUNK_SIZE			((u_int64_t)(64ULL * 1024ULL * 1024ULL))
#define CHUNK_HASH_MIN_FILE_SIZE		((u_int64_t)(2ULL * CHUNK_HASH_CHUNK_SIZE))
#define CHUNK_HASH_MAX_RANGES_PER_REQUEST	65536U

int
sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size)
{
	struct sftp_hash_range	*ranges = NULL;
	u_int64_t		*local_hashes = NULL;
	u_int64_t		*remote_hashes = NULL;
	u_int64_t		 fsize;
	u_int64_t		 bytes_retransferred = 0;
	u_int			 n_chunks, n_mismatched = 0;
	u_int			 i;
	int			 rc = -1;

	if (conn == NULL || local_path == NULL || remote_path == NULL ||
	    local_fd < 0 || file_size <= 0)
		return -1;

	if (!sftp_conn_has_hash_range(conn)) {
		debug_f("server lacks sftp-hash-range; declining chunked path "
		    "for \"%s\"", local_path);
		return -1;
	}
	fsize = (u_int64_t)file_size;
	if (fsize < CHUNK_HASH_MIN_FILE_SIZE) {
		debug_f("file \"%s\" size %llu below chunked threshold %llu; "
		    "declining", local_path, (unsigned long long)fsize,
		    (unsigned long long)CHUNK_HASH_MIN_FILE_SIZE);
		return -1;
	}

	n_chunks = (u_int)((fsize + CHUNK_HASH_CHUNK_SIZE - 1) /
	    CHUNK_HASH_CHUNK_SIZE);
	if (n_chunks > CHUNK_HASH_MAX_RANGES_PER_REQUEST) {
		debug_f("file \"%s\" would need %u chunks > cap %u; declining",
		    local_path, n_chunks, CHUNK_HASH_MAX_RANGES_PER_REQUEST);
		return -1;
	}

	if ((ranges = calloc(n_chunks, sizeof(*ranges))) == NULL ||
	    (local_hashes = calloc(n_chunks, sizeof(*local_hashes))) == NULL ||
	    (remote_hashes = calloc(n_chunks, sizeof(*remote_hashes))) == NULL) {
		error_f("calloc for %u chunks failed", n_chunks);
		goto out;
	}

	/*
	 * Build the chunk layout.  Last chunk's length is clamped to
	 * end-of-file so the server's matching XXH3 (also clamped) lines up
	 * with the local hash.
	 */
	for (i = 0; i < n_chunks; i++) {
		u_int64_t off = (u_int64_t)i * CHUNK_HASH_CHUNK_SIZE;
		u_int64_t remain = fsize - off;
		ranges[i].off = off;
		ranges[i].len = remain < CHUNK_HASH_CHUNK_SIZE
		    ? remain : CHUNK_HASH_CHUNK_SIZE;
	}

	/* Pause the orchestrator watchdog for the combined local+remote
	 * hash phase.  Auto-expires; explicit resume on every exit path
	 * below for promptness. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);

	/* Local hashing: any I/O error here is a real local-file problem;
	 * fall through to existing whole-file path (which will rediscover
	 * the same error and report it to the user). */
	for (i = 0; i < n_chunks; i++) {
		if (sftp_hpn_xxhash_local_range(local_fd, ranges[i].off,
		    ranges[i].len, &local_hashes[i]) != 0) {
			error_f("local hash failed at chunk %u offset %llu "
			    "for \"%s\"", i,
			    (unsigned long long)ranges[i].off, local_path);
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
	}

	/* Remote hashing: all-or-nothing.  Helper emits the user-visible
	 * warning on failure. */
	if (sftp_hpn_hash_remote_ranges(conn, remote_path, ranges, n_chunks,
	    remote_hashes) != 0) {
		sftp_conn_watchdog_resume(conn);
		goto out;
	}
	sftp_conn_watchdog_resume(conn);

	for (i = 0; i < n_chunks; i++) {
		if (local_hashes[i] != remote_hashes[i])
			n_mismatched++;
	}

	if (n_mismatched == 0) {
		debug("chunked verified transfer: all %u chunks match, "
		    "\"%s\" already complete", n_chunks, local_path);
		rc = 1;
		goto out;
	}

	/*
	 * Walk the chunk list and re-transfer each contiguous run of
	 * mismatches as a single sftp_upload_range call.  This minimises the
	 * number of open/close round trips relative to one call per chunk
	 * while keeping the byte-transfer footprint minimal (we still only
	 * send the mismatched chunks, not the gaps between them).
	 *
	 * Partial failure within a run leaves the destination in an
	 * indeterminate state, so we return -1 and let the caller's fallback
	 * path (full-file hash gate -> TRUNC + fresh upload) restore a sane
	 * destination.  No partial-progress accounting here.
	 */
	i = 0;
	while (i < n_chunks) {
		u_int run_start;
		u_int64_t run_off, run_len;

		if (local_hashes[i] == remote_hashes[i]) {
			i++;
			continue;
		}
		run_start = i;
		while (i < n_chunks && local_hashes[i] != remote_hashes[i])
			i++;
		run_off = ranges[run_start].off;
		run_len = (ranges[i - 1].off + ranges[i - 1].len) - run_off;

		debug3("chunked resume: re-transferring chunks [%u, %u) "
		    "at offset %llu length %llu for \"%s\"",
		    run_start, i,
		    (unsigned long long)run_off,
		    (unsigned long long)run_len, local_path);
		if (sftp_upload_range(conn, local_path, remote_path,
		    (off_t)run_off, (off_t)run_len) != 0) {
			error_f("re-transfer of chunks [%u, %u) failed for "
			    "\"%s\"; falling back to full-file path",
			    run_start, i, local_path);
			goto out;
		}
		bytes_retransferred += run_len;
	}

	logit("chunked verified resume \"%s\": re-transferred %u/%u chunks "
	    "(%llu / %llu bytes, %.1f%% of file)",
	    local_path, n_mismatched, n_chunks,
	    (unsigned long long)bytes_retransferred,
	    (unsigned long long)fsize,
	    100.0 * (double)bytes_retransferred / (double)fsize);
	rc = 0;
out:
	free(ranges);
	free(local_hashes);
	free(remote_hashes);
	return rc;
}

int
sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size)
{
	struct sftp_hash_range	*ranges = NULL;
	u_int64_t		*local_hashes = NULL;
	u_int64_t		*remote_hashes = NULL;
	u_int64_t		 fsize;
	u_int64_t		 bytes_refetched = 0;
	u_int			 n_chunks, n_mismatched = 0;
	u_int			 i;
	int			 rc = -1;

	if (conn == NULL || local_path == NULL || remote_path == NULL ||
	    local_fd < 0 || file_size <= 0)
		return -1;

	if (!sftp_conn_has_hash_range(conn)) {
		debug_f("server lacks sftp-hash-range; declining chunked path "
		    "for \"%s\"", local_path);
		return -1;
	}
	fsize = (u_int64_t)file_size;
	if (fsize < CHUNK_HASH_MIN_FILE_SIZE) {
		debug_f("file \"%s\" size %llu below chunked threshold %llu; "
		    "declining", local_path, (unsigned long long)fsize,
		    (unsigned long long)CHUNK_HASH_MIN_FILE_SIZE);
		return -1;
	}

	n_chunks = (u_int)((fsize + CHUNK_HASH_CHUNK_SIZE - 1) /
	    CHUNK_HASH_CHUNK_SIZE);
	if (n_chunks > CHUNK_HASH_MAX_RANGES_PER_REQUEST) {
		debug_f("file \"%s\" would need %u chunks > cap %u; declining",
		    local_path, n_chunks, CHUNK_HASH_MAX_RANGES_PER_REQUEST);
		return -1;
	}

	if ((ranges = calloc(n_chunks, sizeof(*ranges))) == NULL ||
	    (local_hashes = calloc(n_chunks, sizeof(*local_hashes))) == NULL ||
	    (remote_hashes = calloc(n_chunks, sizeof(*remote_hashes))) == NULL) {
		error_f("calloc for %u chunks failed", n_chunks);
		goto out;
	}

	/* Chunk layout identical to the upload sibling - the last chunk
	 * clamps to EOF and the server's matching XXH3 (also clamped) lines
	 * up with the local hash. */
	for (i = 0; i < n_chunks; i++) {
		u_int64_t off = (u_int64_t)i * CHUNK_HASH_CHUNK_SIZE;
		u_int64_t remain = fsize - off;
		ranges[i].off = off;
		ranges[i].len = remain < CHUNK_HASH_CHUNK_SIZE
		    ? remain : CHUNK_HASH_CHUNK_SIZE;
	}

	/* Pause the orchestrator watchdog for the combined local+remote
	 * hash phase.  Auto-expires; explicit resume on every exit path. */
	sftp_conn_watchdog_pause(conn, HPN_HEARTBEAT_REFRESH_SEC);

	/* Local hashing: the destination's current state (partial / sparse). */
	for (i = 0; i < n_chunks; i++) {
		if (sftp_hpn_xxhash_local_range(local_fd, ranges[i].off,
		    ranges[i].len, &local_hashes[i]) != 0) {
			error_f("local hash failed at chunk %u offset %llu "
			    "for \"%s\"", i,
			    (unsigned long long)ranges[i].off, local_path);
			sftp_conn_watchdog_resume(conn);
			goto out;
		}
	}

	/* Remote hashing: the source-of-truth.  All-or-nothing semantics;
	 * helper emits the user-visible warning on failure. */
	if (sftp_hpn_hash_remote_ranges(conn, remote_path, ranges, n_chunks,
	    remote_hashes) != 0) {
		sftp_conn_watchdog_resume(conn);
		goto out;
	}
	sftp_conn_watchdog_resume(conn);

	for (i = 0; i < n_chunks; i++) {
		if (local_hashes[i] != remote_hashes[i])
			n_mismatched++;
	}

	if (n_mismatched == 0) {
		debug("chunked verified transfer: all %u chunks match, "
		    "\"%s\" already complete", n_chunks, local_path);
		rc = 1;
		goto out;
	}

	/*
	 * Walk the chunk list and re-fetch each contiguous run of mismatches
	 * as a single sftp_download_range call.  Partial failure mid-run
	 * leaves the local destination in an indeterminate state, so we
	 * return -1 and let the caller's fallback (full-file hash gate ->
	 * truncate + fresh download) restore a sane destination.
	 */
	i = 0;
	while (i < n_chunks) {
		u_int run_start;
		u_int64_t run_off, run_len;

		if (local_hashes[i] == remote_hashes[i]) {
			i++;
			continue;
		}
		run_start = i;
		while (i < n_chunks && local_hashes[i] != remote_hashes[i])
			i++;
		run_off = ranges[run_start].off;
		run_len = (ranges[i - 1].off + ranges[i - 1].len) - run_off;

		debug3("chunked resume: re-fetching chunks [%u, %u) at "
		    "offset %llu length %llu for \"%s\"",
		    run_start, i,
		    (unsigned long long)run_off,
		    (unsigned long long)run_len, local_path);
		if (sftp_download_range(conn, remote_path, local_path,
		    (off_t)run_off, (off_t)run_len) != 0) {
			error_f("re-fetch of chunks [%u, %u) failed for "
			    "\"%s\"; falling back to full-file path",
			    run_start, i, local_path);
			goto out;
		}
		bytes_refetched += run_len;
	}

	logit("chunked verified resume \"%s\": re-fetched %u/%u chunks "
	    "(%llu / %llu bytes, %.1f%% of file)",
	    local_path, n_mismatched, n_chunks,
	    (unsigned long long)bytes_refetched,
	    (unsigned long long)fsize,
	    100.0 * (double)bytes_refetched / (double)fsize);
	rc = 0;
out:
	free(ranges);
	free(local_hashes);
	free(remote_hashes);
	return rc;
}

/* ── END sftp-hash-range ──────────────────────────────────────────────── */

/* ── BEGIN hpn-file-layout: Lustre auto-stripe (EXPERIMENTAL) ────────────
 *
 * Client side of the hpn-file-layout@hpnssh.org extension.  The caller
 * pre-decides whether to invoke this (Lustre destination + parallel mode
 * + HPNLustreStripeCount != 0); this function just runs the wire
 * transaction and translates the reply status.
 *
 * Wire format and status codes are defined in sftp-hpn-server.h.
 */
int
sftp_hpn_set_file_layout(struct sftp_conn *conn, const char *path,
    u_int32_t stripe_count, u_int32_t dom_size, u_int32_t *applied_out,
    u_int32_t *layout_kind_out)
{
	struct sshbuf	*msg = NULL;
	u_int		 id, rid;
	u_int32_t	 status = HPN_FILE_LAYOUT_FAIL;
	u_int32_t	 applied = 0;
	u_int32_t	 layout_kind = 0;
	u_char		 type;
	int		 r;
	int		 rc = HPN_FILE_LAYOUT_FAIL;

	if (applied_out != NULL)
		*applied_out = 0;
	if (layout_kind_out != NULL)
		*layout_kind_out = 0;

	if (conn == NULL || path == NULL) {
		errno = EINVAL;
		return HPN_FILE_LAYOUT_FAIL;
	}

	if (!sftp_conn_has_file_layout(conn)) {
		debug_f("server lacks hpn-file-layout; skipping");
		return HPN_FILE_LAYOUT_NOT_FS;
	}

	if ((msg = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		return HPN_FILE_LAYOUT_FAIL;
	}

	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending hpn-file-layout \"%s\" stripe_count=%u dom_size=%u id=%u",
	    path, stripe_count, dom_size, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_FILE_LAYOUT)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, stripe_count)) != 0 ||
	    (r = sshbuf_put_u32(msg, dom_size)) != 0)
		fatal_fr(r, "compose hpn-file-layout request");
	if (send_msg(conn, msg) != 0) {
		logit_f("hpn-file-layout \"%s\": transport send failed", path);
		goto out;
	}
	sshbuf_reset(msg);

	if (get_msg(conn, msg) != 0) {
		logit_f("hpn-file-layout \"%s\": transport receive failed",
		    path);
		goto out;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &rid)) != 0) {
		logit_f("hpn-file-layout \"%s\": parse reply header: %s",
		    path, ssh_err(r));
		goto out;
	}
	if (rid != id) {
		sftp_conn_die(conn,
		    "hpn-file-layout reply id mismatch (got %u expected %u)",
		    rid, id);
		goto out;
	}
	if (type == SSH2_FXP_STATUS) {
		u_int	 fx_status = SSH2_FX_FAILURE;
		(void)sshbuf_get_u32(msg, &fx_status);
		logit_f("hpn-file-layout \"%s\": server STATUS reply %s",
		    path, fx2txt(fx_status));
		goto out;
	}
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		sftp_conn_die(conn,
		    "hpn-file-layout: expected SSH2_FXP_EXTENDED_REPLY(%u), "
		    "got %u", SSH2_FXP_EXTENDED_REPLY, type);
		goto out;
	}

	if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
	    (r = sshbuf_get_u32(msg, &applied)) != 0) {
		logit_f("hpn-file-layout \"%s\": parse reply body: %s",
		    path, ssh_err(r));
		goto out;
	}
	/* rev-2 layout_kind (0=plain, 1=DoM); absent from a rev-1 server. */
	if (sshbuf_get_u32(msg, &layout_kind) != 0)
		layout_kind = 0;

	debug3_f("hpn-file-layout \"%s\" status=%u applied=%u kind=%u",
	    path, status, applied, layout_kind);
	if (applied_out != NULL)
		*applied_out = applied;
	if (layout_kind_out != NULL)
		*layout_kind_out = layout_kind;
	rc = (int)status;

out:
	sshbuf_free(msg);
	return rc;
}

/* ── END hpn-file-layout ──────────────────────────────────────────────── */
