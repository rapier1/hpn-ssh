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
#include "sftp-hpn-server.h"	/* hpn-file-layout wire format + status codes */
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
    u_int32_t stripe_count, u_int32_t small_threshold, u_int32_t *applied_out,
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
	debug3_f("sending hpn-file-layout \"%s\" stripe_count=%u small_threshold=%u id=%u",
	    path, stripe_count, small_threshold, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_FILE_LAYOUT)) != 0 ||
	    (r = sshbuf_put_cstring(msg, path)) != 0 ||
	    (r = sshbuf_put_u32(msg, stripe_count)) != 0 ||
	    (r = sshbuf_put_u32(msg, small_threshold)) != 0)
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
