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
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
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
#include "sftp-hpn-transferlog.h"	/* per-member TransferLog entries */
#include "utf8.h"		/* mprintf */

/* Adaptive upload pacing master switch (-X Pacing=), applied to each new
 * connection at init.  Read-only after option parsing, so parallel workers
 * may consult it without locking. */
static int sftp_hpn_pace_default = 1;	/* ON by default: wins where the
					 * duty-cycle pathology lives (j1/j2),
					 * measured neutral at j4/j8 and on
					 * fast sinks; -X Pacing=no disables */
static uint64_t sftp_hpn_pace_mean(struct sftp_hpn_conn *);

struct sftp_hpn_conn *
sftp_hpn_conn_init(void)
{
	struct sftp_hpn_conn *hpn;

	hpn = xcalloc(1, sizeof(struct sftp_hpn_conn));
	hpn->pace.enabled = sftp_hpn_pace_default;
	hpn->bundle_cfg.use = 1;	/* HPNUseBundle default: yes */
	hpn->bundle_cfg.writer_pool = 1;	/* HPNWriterPool default: yes */
	return hpn;
}

void
sftp_hpn_conn_free(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	sftp_hpn_src_dispose(hpn);	/* free any in-flight inline-hash state */
	/* Safety net: pending is normally drained by the verify phase and
	 * failures handed to sftp.c, both before teardown. */
	for (size_t i = 0; i < hpn->verify_pending_count; i++) {
		free(hpn->verify_pending[i].local_path);
		free(hpn->verify_pending[i].remote_path);
	}
	free(hpn->verify_pending);
	for (size_t i = 0; i < hpn->verify_failed_count; i++)
		free(hpn->verify_failed_paths[i]);
	free(hpn->verify_failed_paths);
	free(hpn->pace.bw);
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
 * Registers the parallel orchestrator's live-bytes counter for this
 * connection.
 */
void
sftp_hpn_set_live_counter(struct sftp_hpn_conn *hpn, volatile uint64_t *counter)
{
	if (hpn == NULL)
		return;
	hpn->live_counter = counter;
}

/*
 * Internal helper called by sftp_set_yield_flag() in sftp-client.c.
 * Registers the parallel orchestrator's cooperative-yield flag for this
 * connection (tail redistribution, phase C); see the field comment in
 * sftp-hpn-client.h.
 */
void
sftp_hpn_set_yield_flag(struct sftp_hpn_conn *hpn, volatile int *flag)
{
	if (hpn == NULL)
		return;
	hpn->yield_flag = flag;
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
	uint64_t deadline_ms;
	uint64_t cur;

	if (hpn == NULL)
		return;

	deadline_ms = monotime_ms() + (uint64_t)seconds * 1000ULL;

	/*
	 * Extend, never shrink.  A shorter pause arriving while a longer
	 * pause is in flight must not undo the longer one (think: two
	 * different code paths each declaring their grace; whichever needs
	 * more time should win).
	 */
	cur = __atomic_load_n(&hpn->watchdog_pause_until_ms,
	    __ATOMIC_RELAXED);
	if (deadline_ms > cur) {
		__atomic_store_n(&hpn->watchdog_pause_until_ms,
		    deadline_ms, __ATOMIC_RELAXED);
	}
}

void
sftp_hpn_watchdog_resume(struct sftp_hpn_conn *hpn)
{
	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->watchdog_pause_until_ms, 0,
	    __ATOMIC_RELAXED);
}

/* Conn-side wrappers around the watchdog primitives, reaching HPN state
 * through the opaque struct sftp_conn * via sftp_conn_hpn().  Declared in
 * sftp-client-internal.h; moved here from sftp-client.c so the upstream file
 * carries no per-field HPN accessor. */
uint64_t
sftp_conn_watchdog_pause_until_ms(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return __atomic_load_n(&hpn->watchdog_pause_until_ms, __ATOMIC_RELAXED);
}

void
sftp_conn_watchdog_pause(struct sftp_conn *conn, unsigned int seconds)
{
	sftp_hpn_watchdog_pause(sftp_conn_hpn(conn), seconds);
}

void
sftp_conn_watchdog_resume(struct sftp_conn *conn)
{
	sftp_hpn_watchdog_resume(sftp_conn_hpn(conn));
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
	if (hpn == NULL)
		return;
	memset(&hpn->rd, 0, sizeof(hpn->rd));
	hpn->rd.cap = cap ? cap : 1;
	hpn->rd.floor = MINIMUM(RDAHEAD_FLOOR, hpn->rd.cap);
	hpn->rd.cur = hpn->rd.floor;
	hpn->rd.last_rising = hpn->rd.floor;
	hpn->rd.win_start = monotime_double();
	hpn->rd.enabled = 1;
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

/* ==========================================================================
 * Conn-side bridge wrappers (moved out of sftp-client.c).
 *
 * Each takes the opaque struct sftp_conn * and reaches HPN per-connection
 * state through sftp_conn_hpn().  The bodies are behavior-identical to the
 * originals: sftp_conn_hpn(conn) is NULL exactly when conn was NULL or
 * conn->hpn was NULL, so the same guards hold.  Moved here so the upstream
 * sftp-client.c carries no per-field HPN accessor.  All are declared in
 * sftp-client-internal.h; call sites are unchanged.
 * ========================================================================== */

int
sftp_conn_is_dead(struct sftp_conn *conn)
{
	return conn != NULL && sftp_hpn_is_dead(sftp_conn_hpn(conn));
}

int
sftp_conn_is_protocol_violation(struct sftp_conn *conn)
{
	return conn != NULL &&
	    sftp_hpn_is_protocol_violation(sftp_conn_hpn(conn));
}

void
sftp_conn_die(struct sftp_conn *conn, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	sftp_hpn_conn_die(sftp_conn_hpn(conn), "%s", buf);
}

/* Mark `conn` as dead due to a non-recoverable I/O failure - same effect as
 * the direct conn->hpn->dead = 1 that in-file code can do. */
void
sftp_conn_set_dead(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->dead = 1;
}

/* Adaptive read-ahead controller wrappers.  The bundle path works through
 * the opaque struct sftp_conn * and feeds the controller / reads its cap
 * through these; all forward to the sftp_hpn_rdahead_* primitives. */
uint32_t
sftp_conn_rdahead_cap(struct sftp_conn *conn, uint32_t fallback)
{
	if (conn == NULL)
		return fallback;
	return sftp_hpn_rdahead_cap(sftp_conn_hpn(conn), fallback);
}

void
sftp_conn_rdahead_account(struct sftp_conn *conn, size_t nbytes)
{
	if (conn != NULL)
		sftp_hpn_rdahead_account(sftp_conn_hpn(conn), nbytes);
}

void
sftp_conn_rdahead_backpressure_signal(struct sftp_conn *conn)
{
	if (conn != NULL)
		sftp_hpn_rdahead_backpressure_signal(sftp_conn_hpn(conn));
}

/* Live-byte accounting wrapper.  The per-worker live counter (armed via
 * sftp_set_live_counter) is what the parallel watchdog's liveness classifiers
 * read; the bundle codec bumps it through this wrapper - without it a worker
 * mid-bundle reads as 0 bytes moved and is killed as born-dead/wedged on any
 * bundle slower than the detection window. */
void
sftp_conn_live_account(struct sftp_conn *conn, size_t nbytes)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL && h->live_counter != NULL)
		__atomic_fetch_add(h->live_counter, nbytes, __ATOMIC_RELAXED);
}

uint64_t
sftp_conn_bytes_wired(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return 0;
	return __atomic_load_n(&h->bytes_wired_payload, __ATOMIC_RELAXED);
}

/* Conn-level bridge so the bundle module can count wire payload the per-file
 * write loops already count via sftp_hpn_bytes_wired_add - without it,
 * bundle-moved bytes never register as "wired" and the run summary mislabels
 * them as "skipped via resume". */
void
sftp_conn_bytes_wired_add(struct sftp_conn *conn, uint64_t n)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		sftp_hpn_bytes_wired_add(h, n);
}

/* Unified hash-work accounting (see sftp-hpn-client.h for the model).
 * Engines call begin/leg/progress; unit-completion sites call end; the
 * reporter and watchdog read the stamp-gated live values. */
void
sftp_conn_hash_op_begin(struct sftp_conn *conn, uint64_t total_work)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	__atomic_store_n(&h->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_total, total_work, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
}

/* Entering a leg: subsequent progress reports are offset by `base`
 * (0 for the first leg, the span for the second). */
void
sftp_conn_hash_op_leg(struct sftp_conn *conn, uint64_t base)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	__atomic_store_n(&h->hash_work_leg_base, base, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
}

/* Cumulative progress within the current leg (heartbeat figures, local
 * read loops).  Publishes done = leg_base + leg_bytes (clamped to the op
 * total), refreshes the liveness stamp, and lands the value on the serial
 * meter bridge when one is registered. */
void
sftp_conn_hash_op_progress(struct sftp_conn *conn, uint64_t leg_bytes)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	uint64_t done, total;

	if (h == NULL)
		return;
	done = __atomic_load_n(&h->hash_work_leg_base, __ATOMIC_RELAXED) +
	    leg_bytes;
	total = __atomic_load_n(&h->hash_work_total, __ATOMIC_RELAXED);
	if (total > 0 && done > total)
		done = total;
	__atomic_store_n(&h->hash_work_done, done, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
	if (h->hash_meter_ctr != NULL)
		*h->hash_meter_ctr = (off_t)(h->hash_meter_base + done);
}

/* Unit completion: retire the op.  Callers that fold the op's work into a
 * phase accumulator must capture hash_work_done BEFORE this (the same
 * clear-before-fold discipline as the old inflight handoff). */
void
sftp_conn_hash_op_end(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	__atomic_store_n(&h->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_total, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&h->hash_work_stamp_ms, 0, __ATOMIC_RELAXED);
	if (h->hash_meter_ctr != NULL)
		*h->hash_meter_ctr = (off_t)h->hash_meter_base;
}

/* Stamp-gated live pair for the reporter: zeros unless refreshed within
 * the last 3 seconds (an engine gone on any path self-clears). */
void
sftp_conn_hash_work_live(struct sftp_conn *conn, uint64_t *done_out,
    uint64_t *total_out)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	uint64_t stamp;

	*done_out = 0;
	*total_out = 0;
	if (h == NULL)
		return;
	stamp = __atomic_load_n(&h->hash_work_stamp_ms, __ATOMIC_RELAXED);
	if (stamp == 0 || (uint64_t)monotime_ms() - stamp > 3000)
		return;
	*done_out = __atomic_load_n(&h->hash_work_done, __ATOMIC_RELAXED);
	*total_out = __atomic_load_n(&h->hash_work_total, __ATOMIC_RELAXED);
}

/* Live total only - the watchdog's "provably hashing" gate. */
uint64_t
sftp_conn_hash_op_live_total(struct sftp_conn *conn)
{
	uint64_t done, total;

	sftp_conn_hash_work_live(conn, &done, &total);
	return total;
}

/* Capture the current op's done figure (for completion folds). */
uint64_t
sftp_conn_hash_work_done_get(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return 0;
	return __atomic_load_n(&h->hash_work_done, __ATOMIC_RELAXED);
}

/* Serial meter bridge registration; resets the completed-work base. */
void
sftp_conn_set_hash_meter_ctr(struct sftp_conn *conn, volatile off_t *ctr)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	h->hash_meter_ctr = ctr;
	h->hash_meter_base = 0;
}

/* Serial multi-op meters (verify phase): fold a completed op's work into
 * the bridge base so the next op's progress continues from it. */
void
sftp_conn_hash_meter_base_add(struct sftp_conn *conn, uint64_t work)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return;
	h->hash_meter_base += work;
	if (h->hash_meter_ctr != NULL)
		*h->hash_meter_ctr = (off_t)h->hash_meter_base;
}

/* HPN permanent/policy-denied signal accessors, moved from sftp-client.c.
 * The backing flags now live on struct sftp_hpn_conn (migrated out of the
 * upstream struct sftp_conn); these reach them through sftp_conn_hpn().
 * Declared in sftp-client.h; call sites unchanged. */
int
sftp_conn_saw_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	return h != NULL && h->saw_perm_denied;
}

/* Latch the sticky permission-denied flag (called at the internal set-sites
 * that previously assigned conn->saw_perm_denied = 1 directly). */
void
sftp_conn_set_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->saw_perm_denied = 1;
}

void
sftp_conn_clear_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->saw_perm_denied = 0;
}

int
sftp_conn_saw_policy_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	return h != NULL && h->saw_policy_denied;
}

void
sftp_conn_clear_policy_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->saw_policy_denied = 0;
}

/*
 * Called right after a PERMISSION_DENIED status code is read, with `msg`
 * positioned at the status reply's error-message string.  If that message
 * carries HPN_POLICY_DENIED_TAG the refusal came from the server's -P/-p
 * request policy (not a filesystem error), so latch saw_policy_denied.
 * Consumes the message string from `msg`; harmless on a buffer that has none.
 */
void
sftp_conn_check_policy_tag(struct sftp_conn *conn, struct sshbuf *msg)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);
	char *errmsg = NULL;

	if (h == NULL || msg == NULL)
		return;
	if (sshbuf_get_cstring(msg, &errmsg, NULL) == 0 && errmsg != NULL &&
	    strstr(errmsg, HPN_POLICY_DENIED_TAG) != NULL)
		h->saw_policy_denied = 1;
	free(errmsg);
}

/* HPN SFTP-extension predicates (server-advertised bits), moved from
 * sftp-client.c.  They read the upstream conn->exts bitmask through the
 * sftp_conn_exts() bridge; the SFTP_EXT_HPN_* bits live in sftp-hpn-client.h.
 * Declared in sftp-client.h; call sites unchanged. */
int
sftp_conn_has_hpn_bundle(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HPN_BUNDLE) != 0;
}

int
sftp_conn_has_hpn_bundle_fetch(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HPN_BUNDLE_FETCH) != 0;
}

int
sftp_conn_has_hpn_check_file(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HPN_CHECK_FILE) != 0;
}

int
sftp_conn_has_hash_range(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HASH_RANGE) != 0;
}

int
sftp_conn_has_file_layout(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HPN_FILE_LAYOUT) != 0;
}

/*
 * HPN: the operator's per-user parallel-worker cap as advertised by the
 * server (hpn-max-workers@hpnssh.org).  Returns -1 when the server did not
 * advertise it (a stock / non-HPN server), 0 when advertised with no cap,
 * or the positive cap otherwise.  The orchestrator uses this to clamp -j.
 * Moved from sftp-client.c; declared in sftp-client.h.
 */
int
sftp_hpn_max_workers_cap(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	return h != NULL ? h->hpn_max_workers_cap : -1;
}

/* ---- Adaptive upload pacing ---------------------------------------------
 *
 * Problem: a single-stream upload at real RTT into a destination whose
 * filesystem sustains less than the path rate collapses into a duty cycle.
 * Unpaced ingest overfills the receiver's page cache to the dirty-page
 * cliff; the sink then hard-blocks for seconds, window credit famines, the
 * sender's TCP decays, and every cycle pays an RTT-scaled recovery.
 * Measured on both Lustre and ext4/NVMe sinks; reducing offered load below
 * the destination's sustained flush rate raised throughput 37% and removed
 * every multi-second stall (2026-07 investigation).
 *
 * Signal: WRITE status returns.  Their arrival rate IS the receiver's
 * sustained consumption rate, delayed ~1 RTT.  The page cache can lie to
 * the receiver's own flow control (writes complete at memcpy speed until
 * the cliff), but it cannot lie about the long-run ack rate.
 *
 * Control law (continuous; no modes):
 *
 *     ceiling = max(HEADROOM x mean(recent per-second rates), FLOOR)
 *     applied = min(ceiling, explicit -l if set)
 *
 * The estimator is the MEAN over a sliding window of per-second delivered
 * rates, with the first seconds after the first ack excised so TCP's
 * slow-start ramp never enters the estimate.  The mean - not a max - is
 * deliberate: famine/stall seconds enter the average, so if the sink does
 * hit its writeback cliff the estimate converges toward the sink's true
 * sustained rate (implicit learn-from-stall), whereas a max filter latches
 * the page-cache absorb rate and un-protects the transfer (measured:
 * 718 MB/s latched on a ~350 MB/s sink).  A fast sink acks at the send
 * rate, so the ceiling floats HEADROOM above actual throughput and never
 * binds; HEADROOM doubles as the upward probe when the sink speeds up.
 * The actuator is the same token bucket -l uses, re-armed on a fixed time
 * cadence from within the ack path - the design is deliberately blind to
 * file boundaries, so its behaviour is identical for one huge file or
 * hundreds of small files per second.
 */

/* Rate-sample bucket: one ring slot per second of delivered bytes. */
#define SFTP_HPN_PACE_BUCKET_MS		1000
/* Ring length = the estimator's memory, seconds (array size in .h). */
#define SFTP_HPN_PACE_RING		10
/* Ceiling = 5/4 x best recent rate: the overshoot bound and the probe. */
#define SFTP_HPN_PACE_HEADROOM_NUM	5
#define SFTP_HPN_PACE_HEADROOM_DEN	4
/* Startup grace: no pacing until a full request pipeline has been acked
 * AND this much wall time has passed - short transfers never pace. */
#define SFTP_HPN_PACE_GRACE_MS		1000
/* Slow-start excision: samples from the first SKIP_MS after the first ack
 * are discarded entirely - TCP's ramp would otherwise contaminate the
 * mean with rates that reflect the ramp, not the path or the sink.
 * 3s covers slow-start at RTTs up to ~200ms; at higher RTTs the ramp may
 * leak into the estimate slightly low, which is the safe direction. */
#define SFTP_HPN_PACE_SKIP_MS		3000
/* Re-arm cadence: the actuator is reprogrammed at most this often.  Also
 * the recovery clock: after an over-correction the ceiling climbs one
 * HEADROOM step per interval, so convergence is seconds-scale regardless
 * of file layout.  Mid-flow bandwidth_limit_init() at correctly-scaled
 * rates is safe; the earlier "multi-second sleeps" that motivated
 * boundary-only arming were an artifact of the x1024 rate
 * under-programming bug, not of re-initialisation itself. */
#define SFTP_HPN_PACE_ARM_MS		2000
/* Hard floor, 32 MiB/s: comfortably below any sink worth protecting and
 * ABOVE the duty-cycle rates the pathology itself produces, so pacing can
 * never do worse than the disease.  A sink slower than this simply gets
 * mild overshoot - i.e., today's behaviour. */
#define SFTP_HPN_PACE_FLOOR_BYTES	(32ULL * 1024 * 1024)

void
sftp_hpn_pace_set_enabled(int on)
{
	sftp_hpn_pace_default = on;
}

/* Feed one WRITE ack of len payload bytes into the controller: roll the
 * per-second rate bucket into the ring, manage startup grace, and re-arm
 * the actuator on the ARM_MS cadence.  Called from the upload ack-reap
 * path beside the read-ahead controller's hook. */
void
sftp_hpn_pace_ack(struct sftp_hpn_conn *hpn, size_t len, u_int num_requests)
{
	uint64_t now_ms, dt_ms, rate, best, target_bytes, rate_bits;
	uint64_t prev_bytes;

	if (hpn == NULL || !hpn->pace.enabled)
		return;
	now_ms = monotime_ms();
	if (hpn->pace.acks == 0) {
		hpn->pace.first_ack_ms = now_ms;
		hpn->pace.bucket_start_ms = now_ms;
	}
	hpn->pace.acks++;
	hpn->pace.bucket_bytes += len;

	dt_ms = now_ms - hpn->pace.bucket_start_ms;
	if (dt_ms < SFTP_HPN_PACE_BUCKET_MS)
		return;
	/* Slow-start excision: throw the bucket away (roll the window but
	 * record nothing) until SKIP_MS past the first ack. */
	if (now_ms - hpn->pace.first_ack_ms < SFTP_HPN_PACE_SKIP_MS) {
		hpn->pace.bucket_bytes = 0;
		hpn->pace.bucket_start_ms = now_ms;
		return;
	}
	rate = hpn->pace.bucket_bytes * 1000 / dt_ms;	/* bytes/sec */
	hpn->pace.rate_ring[hpn->pace.ring_idx++ % SFTP_HPN_PACE_RING] = rate;
	hpn->pace.bucket_bytes = 0;
	hpn->pace.bucket_start_ms = now_ms;

	if (!hpn->pace.active) {
		if (hpn->pace.acks < num_requests ||
		    now_ms - hpn->pace.first_ack_ms <
		    SFTP_HPN_PACE_SKIP_MS + SFTP_HPN_PACE_GRACE_MS)
			return;
		hpn->pace.active = 1;
		debug2_f("engaged: mean recent rate %llu bytes/s",
		    (unsigned long long)sftp_hpn_pace_mean(hpn));
	}

	/* Time-based re-arm, at most once per ARM interval. */
	if (now_ms - hpn->pace.last_arm_ms < SFTP_HPN_PACE_ARM_MS)
		return;
	best = sftp_hpn_pace_mean(hpn);
	if (best == 0)
		return;
	target_bytes = best *
	    SFTP_HPN_PACE_HEADROOM_NUM / SFTP_HPN_PACE_HEADROOM_DEN;
	/* Down-step clamp: one re-arm may cut the ceiling by at most half
	 * (no clamp on the first arm; bw_rate_bits holds bytes x 8).  The
	 * increase side is inherently bounded (~x5/4 per re-arm, since the
	 * mean can only grow as fast as the current ceiling admits); an
	 * unbounded decrease lets one transient famine window crater a
	 * healthy ceiling and the x5/4 climb-back takes tens of seconds.
	 * Halving per re-arm still tracks a genuine sustained slowdown
	 * within a few ARM intervals. */
	prev_bytes = hpn->pace.bw_rate_bits / 8;
	if (prev_bytes > 0 && target_bytes < prev_bytes / 2)
		target_bytes = prev_bytes / 2;
	if (target_bytes < SFTP_HPN_PACE_FLOOR_BYTES)
		target_bytes = SFTP_HPN_PACE_FLOOR_BYTES;
	/* Post-famine fast reclaim: if the last bucket consumed >=90%
	 * of the (famine-cut) ceiling, the sink has recovered - jump
	 * straight to 80% of the last rising-armed ceiling (= the last
	 * proven mean rate, since 0.8 x 5/4 = 1) instead of compounding
	 * x5/4 up from the floor.  The ring is flushed with the jump:
	 * its famine samples are already banked in the cut reclaim
	 * level, and restarting the estimator from post-jump buckets
	 * keeps the mean tracking delivery instead of dragging ~10s
	 * behind it.  A stale reclaim self-corrects: overshoot
	 * re-famines and each retry targets 20% lower, geometrically
	 * convergent on the sink's true rate. */
	if (prev_bytes > 0 && rate * 10 >= prev_bytes * 9 &&
	    target_bytes < hpn->pace.reclaim_bytes * 4 / 5) {
		target_bytes = hpn->pace.reclaim_bytes * 4 / 5;
		memset(hpn->pace.rate_ring, 0,
		    sizeof(hpn->pace.rate_ring));
		hpn->pace.ring_idx = 0;
		debug2_f("reclaim to %llu bytes/s",
		    (unsigned long long)target_bytes);
	}
	/* Rising/holding re-arms mark proven ground for the next
	 * reclaim; falling ones leave it frozen at the pre-descent
	 * peak. */
	if (prev_bytes == 0 || target_bytes >= prev_bytes)
		hpn->pace.reclaim_bytes = target_bytes;
	/* bandwidth_limit_init()'s rate field is bits/sec in practice: the
	 * -l path stores (kbit/s value) x 1024 there (verified live via gdb
	 * against misc.c's math).  bytes x 8 = bits/s lands ~2.4% below the
	 * exact -l scaling (1000/1024) - i.e. slightly conservative, well
	 * inside HEADROOM, and needs no division.  len (this ack's request
	 * size) is the natural chunk-size hint. */
	rate_bits = target_bytes * 8;
	if (hpn->pace.bw == NULL)
		hpn->pace.bw = xcalloc(1, sizeof(struct bwlimit));
	bandwidth_limit_init(hpn->pace.bw, rate_bits, len);
	hpn->pace.bw_rate_bits = rate_bits;
	hpn->pace.last_arm_ms = now_ms;
	debug2_f("ceiling %llu bytes/s (mean %llu)",
	    (unsigned long long)target_bytes, (unsigned long long)best);
}

/* Mean of the filled ring slots (bytes/sec); 0 when the ring is empty.
 * The MEAN - not the max - is the estimator: famine buckets enter the
 * average, so after a dirty-cliff stall the estimate converges toward the
 * sink's true sustained rate (implicit learn-from-first-stall).  A max
 * filter was tried and latched the page-cache absorb rate (718 MB/s on a
 * ~350 MB/s sink), un-protecting the transfer. */
static uint64_t
sftp_hpn_pace_mean(struct sftp_hpn_conn *hpn)
{
	uint64_t sum = 0;
	u_int i, n = 0;

	for (i = 0; i < SFTP_HPN_PACE_RING; i++) {
		if (hpn->pace.rate_ring[i] == 0)
			continue;
		sum += hpn->pace.rate_ring[i];
		n++;
	}
	return n > 0 ? sum / n : 0;
}

/* Select the token bucket the outbound path should apply: the TIGHTER of
 * the adaptive ceiling and the user's explicit -l (min composition).
 * Returns NULL when no limit applies.  Request traffic outside uploads is
 * far below the floor, so the ceiling never binds there. */
struct bwlimit *
sftp_hpn_pace_bwlimit(struct sftp_hpn_conn *hpn, struct bwlimit *user_bw,
    uint64_t user_rate)
{
	/* user_rate is conn->limit_kbps, which -l parsing already scaled to
	 * the same bits/sec-order units the bucket stores (kbit x 1024), so
	 * comparing it against bw_rate_bits (bytes x 8) is consistent to
	 * within the same 2.4% noted at the arming site in
	 * sftp_hpn_pace_ack. */
	if (hpn == NULL || !hpn->pace.active || hpn->pace.bw == NULL)
		return user_bw;
	if (user_bw != NULL && user_rate > 0 &&
	    user_rate <= hpn->pace.bw_rate_bits)
		return user_bw;
	return hpn->pace.bw;
}

void
sftp_conn_set_bundle_config(struct sftp_conn *conn, int use_bundle,
    uint64_t bundle_size, int writer_pool)
{
	struct sftp_hpn_conn *hpn = conn ? sftp_conn_hpn(conn) : NULL;

	if (hpn == NULL)
		return;
	hpn->bundle_cfg.use = use_bundle;
	hpn->bundle_cfg.size = bundle_size;
	hpn->bundle_cfg.writer_pool = writer_pool;
}

/*
 * HPN serial-path bundling: the recursive upload walk accumulates
 * bundle-eligible small files and ships each batch as one hpn-bundle
 * stream on the session connection, amortising the per-file OPEN/CLOSE
 * round trips that dominate small-file transfers at WAN RTTs.  The
 * eligibility policy is shared with the parallel planner
 * (sftp-hpn-bundle.h) so both modes make identical decisions.
 */

void
sftp_hpn_bundle_acc_init(struct sftp_hpn_bundle_acc *acc, struct sftp_conn *conn,
    int resume)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t target;

	memset(acc, 0, sizeof(*acc));
	if (hpn == NULL || !hpn->bundle_cfg.use ||
	    hpn->bundle_cfg.server_cant || resume ||
	    !sftp_conn_has_hpn_bundle(conn))
		return;
	target = hpn->bundle_cfg.size > 0 ?
	    hpn->bundle_cfg.size : HPN_BUNDLE_SIZE_DEFAULT;
	acc->target = target;
	acc->enabled = 1;
}

/* True iff the accumulator is live and this file may join a bundle -
 * the shared policy test, one source of truth with the parallel
 * producer's gate. */
int
sftp_hpn_bundle_acc_eligible(struct sftp_hpn_bundle_acc *acc, uint64_t size)
{
	return acc->enabled &&
	    hpn_bundle_file_eligible(size, acc->target);
}

/* Returns 1 when the accumulator must flush (shared policy: framed
 * bytes reach the target, or the member ceiling).  Frame accounting
 * matches the parallel producer: header + path + payload per member. */
int
sftp_hpn_bundle_acc_add(struct sftp_hpn_bundle_acc *acc, const char *src,
    const char *dst, long long size)
{
	if (acc->n == acc->cap) {
		acc->cap = acc->cap ? acc->cap * 2 : 64;
		acc->entries = xreallocarray(acc->entries, acc->cap,
		    sizeof(*acc->entries));
		acc->sizes = xreallocarray(acc->sizes, acc->cap,
		    sizeof(*acc->sizes));
	}
	acc->entries[acc->n].local_path = xstrdup(src);
	acc->entries[acc->n].remote_path = xstrdup(dst);
	acc->entries[acc->n].result = 0;
	acc->sizes[acc->n] = size;
	acc->n++;
	acc->bytes += BUNDLE_REC_FRAME_BYTES(strlen(dst), (uint64_t)size);
	return hpn_bundle_should_flush(acc->bytes, acc->n, acc->target);
}

static void
sftp_hpn_bundle_acc_reset(struct sftp_hpn_bundle_acc *acc)
{
	int i;

	for (i = 0; i < acc->n; i++) {
		free((void *)acc->entries[i].local_path);
		free((void *)acc->entries[i].remote_path);
	}
	acc->n = 0;
	acc->bytes = 0;
}

void
sftp_hpn_bundle_acc_free(struct sftp_hpn_bundle_acc *acc)
{
	sftp_hpn_bundle_acc_reset(acc);
	free(acc->entries);
	free(acc->sizes);
	acc->entries = NULL;
	acc->sizes = NULL;
	acc->cap = 0;
	acc->enabled = 0;
}

/*
 * Flush the accumulated members as one bundle and consume the
 * accumulator.  Returns 0 when the walk may continue cleanly, 1 when
 * one or more members failed but the walk may continue (caller marks
 * the transfer failed), and -1 on abort conditions: POLICY_DENIED (the
 * bundle API contract forbids falling back) or the session connection
 * dying mid-bundle.
 */
int
sftp_hpn_bundle_acc_flush(struct sftp_conn *conn, struct sftp_hpn_bundle_acc *acc,
    int preserve_flag, int print_flag, int verify, int fsync_flag,
    int inplace_flag)
{
	int i, rc, failures = 0;

	if (!acc->enabled || acc->n == 0)
		return 0;

	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Uploading bundle: %d files, %llu bytes\n",
		    acc->n, (unsigned long long)acc->bytes);
	rc = sftp_hpn_bundle_upload(conn, "", acc->entries, acc->n,
	    preserve_flag, fsync_flag, sftp_conn_hpn(conn)->bundle_cfg.writer_pool,
	    acc->target);
	switch (rc) {
	case SFTP_HPN_BUNDLE_OK:
		for (i = 0; i < acc->n; i++) {
			/* Mirror the per-file path: park for the classic
			 * verify phase (no-op unless verify is enabled);
			 * success is logged now only when verify will not
			 * log it after checking. */
			sftp_conn_verify_park(conn, acc->entries[i].local_path,
			    acc->entries[i].remote_path,
			    /*local_is_target=*/0);
			if (!sftp_conn_verify_transfer_enabled(conn))
				transferlog_file(TRANSFERLOG_SUCCESS,
				    acc->sizes[i],
				    acc->entries[i].remote_path);
		}
		break;
	case SFTP_HPN_BUNDLE_SERVER_CANT:
		/* Permanent, connection-agnostic refusal: stop bundling
		 * for this session and drive these members per-file. */
		debug_f("server refused bundle; per-file fallback");
		sftp_conn_hpn(conn)->bundle_cfg.server_cant = 1;
		acc->enabled = 0;
		for (i = 0; i < acc->n; i++) {
			int ur = sftp_upload(conn, acc->entries[i].local_path,
			    acc->entries[i].remote_path, preserve_flag,
			    /*resume*/0, verify, fsync_flag,
			    inplace_flag);
			if (ur == -1) {
				error("upload \"%s\" to \"%s\" failed",
				    acc->entries[i].local_path,
				    acc->entries[i].remote_path);
				transferlog_file(TRANSFERLOG_FAILED,
				    acc->sizes[i],
				    acc->entries[i].remote_path);
				failures++;
			} else if (!sftp_conn_verify_transfer_enabled(conn)) {
				transferlog_file(TRANSFERLOG_SUCCESS,
				    acc->sizes[i],
				    acc->entries[i].remote_path);
			}
		}
		break;
	case SFTP_HPN_BUNDLE_POLICY_DENIED:
		error("bundle upload denied by remote policy; aborting");
		sftp_hpn_bundle_acc_reset(acc);
		return -1;
	case SFTP_HPN_BUNDLE_TRANSPORT_FAILED:
	default:
		error("bundle upload failed: connection error");
		sftp_hpn_bundle_acc_reset(acc);
		return -1;
	}
	sftp_hpn_bundle_acc_reset(acc);
	return failures > 0 ? 1 : 0;
}
