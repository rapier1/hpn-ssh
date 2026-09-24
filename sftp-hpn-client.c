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

/* sftp-hpn-client.c - HPN-SSH extensions to the SFTP client connection,
 * kept out of sftp-client.c so its diff against upstream stays small.
 *
 * Per-connection HPN state, struct sftp_hpn_conn: the dead and
 * protocol-violation flags, the live counter and yield flag the
 * parallel watchdog reads, the adaptive read-ahead controller, the
 * adaptive upload pacer, the hash-operation meter accounting, the
 * permission and request-policy denial flags, the server's worker cap
 * and the extension capabilities it advertised. Most of it is reached
 * through the sftp_conn_* accessors declared in sftp-client.h.
 *
 * Transfer helpers: the serial walks' bundle accumulator for upload
 * and download, deferred directory attribute application, the
 * hpn-file-layout Lustre stripe request, the chunked tree walk, and the
 * three walk consumers that feed downloads and uploads. */

#include "includes.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h" /* monotime_double, MINIMUM, MAXIMUM */
#include "sftp-common.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sftp.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "progressmeter.h"  /* pm_mprintf */
/* hpn-file-layout wire format and status codes */
#include "sftp-hpn-server.h"
#include "sftp-hpn-client.h"
#include "sftp-hpn-tree.h"	/* tree walk and record codec */
#include "hpn-meter.h"	/* progress meter core */
#include "sftp-hpn-bundle.h"  /* bundle flags and eligibility policy */
#include "sftp-hpn-transferlog.h" /* per-member TransferLog entries */
#include "utf8.h"		/* fmprintf */

extern int showprogress;	/* progress gate, defined by sftp.c and scp.c */

/* Adaptive upload pacing master switch (-X Pacing=), applied to each new
 * connection at init. On by default: it wins where the duty-cycle
 * pathology lives, at -j1 and -j2, and measured neutral at -j4, -j8 and
 * on fast sinks. -X Pacing=no disables it. Read-only after option
 * parsing, so parallel workers may consult it without locking. */
static int sftp_hpn_pace_default = 1;

/* Adaptive read-ahead controller. See sftp-hpn-client.h for the
 * rationale. RDAHEAD_BP_THRESHOLD_SEC lives there too, so the
 * STATUS-read sites in sftp-client.c share the same constant. */
#define RDAHEAD_FLOOR		64u	/* smallest depth we ever probe */
#define RDAHEAD_GROW_PCT	0.15	/* >15% gain keeps doubling */
#define RDAHEAD_EWMA_ALPHA	0.6	/* weight of the newest window's rate */
#define RDAHEAD_MIN_WIN_SEC	0.02	/* ignore shorter windows as noise */
/* At the floor the controller would otherwise wait for a full window of
 * acks before doubling, tens of seconds on a slow path and the bulk of
 * the 100 s recovery tails seen after a wedge. After this long at the
 * floor it doubles once as a probe. If the path is still bad the
 * backpressure signal shrinks it back, one cycle every 15 s or so. Half
 * the backpressure threshold, so recovery biases toward depth. */
#define RDAHEAD_PROBE_INTERVAL_SEC	5.0

/* Adaptive upload pacing. Rate-sample bucket, one ring slot per second
 * of delivered bytes. */
#define PACE_BUCKET_MS		1000
/* Startup grace: no pacing until a full request pipeline has been acked
 * and this much wall time has passed, so short transfers never pace. */
#define PACE_GRACE_MS		1000
/* Slow-start excision: samples from the first SKIP_MS after the first
 * ack are discarded, or TCP's ramp would contaminate the mean with rates
 * that reflect the ramp, not the path or the sink. 3 s covers slow-start
 * at RTTs up to about 200 ms. At higher RTTs the ramp may leak into the
 * estimate slightly low, which is the safe direction. */
#define PACE_SKIP_MS		3000
/* Re-arm cadence: the actuator is reprogrammed at most this often. Also
 * the recovery clock, since after an over-correction the ceiling climbs
 * 25% per interval, so convergence is seconds-scale
 * regardless of file layout. */
#define PACE_ARM_MS		2000
/* Hard floor, 32 MiB/s: comfortably below any sink worth protecting and
 * above the duty-cycle rates the pathology itself produces, so pacing
 * can never do worse than the disease. A slower sink gets mild
 * overshoot, which is the unpaced behaviour. */
#define PACE_FLOOR_RATE		(32ULL * 1024 * 1024)

/* A hash op whose liveness stamp is older than this is treated as gone by
 * the reporter and the watchdog, so engines need no exit-point discipline. */
#define HASH_WORK_STALE_MS	3000

/* One entry's position and depth, for sorting the deferred attrs without
 * disturbing the list itself. */
struct dirattr_order {
	int idx;	/* position in the list's entries[] */
	int depth;	/* separator count of the entry's path */
};

/* A path pair plus attributes collected during a tree walk. Downloads
 * queue regular files in it, uploads queue subdirectories. src and dst
 * follow the transfer direction and are owned by the entry. attrs are
 * the peer's on download and the normalised local stat on upload. */
struct walk_entry {
	char	*src;
	char	*dst;
	Attrib	 attrs;
};

/* State threaded through the download consumer, one per tree walk. */
struct tree_dl_ctx {
	/* The walk's roots, borrowed from the caller. Each record's relpath
	 * is appended to both. */
	const char			*src;
	const char			*dst;
	/* Serial, parallel or crossload sink. */
	struct sftp_tree_dl_sink	*sink;
	/* Regular files queued during a read and transferred once it ends.
	 * Stays empty for a streaming sink. */
	struct walk_entry		*files;
	size_t				 nfiles;
	size_t				 files_alloc;
	/* Meter totals, tallied as each regular file record arrives, but
	 * only for a sink that takes them (set_total). total_overflow marks
	 * a byte tally past INT64_MAX, after which the meter runs
	 * rate-only. */
	off_t				 total_bytes;
	size_t				 total_files;
	int				 total_overflow;
	/* Set once the abort notice has been shown, so an interrupt that
	 * lands mid-batch reports itself once. */
	int				 abort_noticed;
	/* -1 after any per-entry failure. */
	int				 ret;
};

/* Allocate the per-connection HPN state for a new sftp_conn. Everything
 * starts zeroed except the three option defaults set here. Dies if
 * xcalloc fails. */
struct sftp_hpn_conn *
sftp_hpn_conn_init(void)
{
	struct sftp_hpn_conn *hpn;

	hpn = xcalloc(1, sizeof(*hpn));
	hpn->pace.enabled = sftp_hpn_pace_default;	/* -X Pacing= switch */
	hpn->bundle_cfg.use = 1;	/* HPNUseBundle default: yes */
	hpn->bundle_cfg.writer_pool = 1;	/* HPNWriterPool default: yes */
	return hpn;
}

/* Release a connection's HPN state. Frees what the struct owns: the
 * inline-hash state, the verify queues and the pacing actuator. The
 * live counter, yield flag and hash meter pointers are borrowed and
 * left alone. Safe to call with NULL. */
void
sftp_hpn_conn_free(struct sftp_hpn_conn *hpn)
{
	int i;

	if (hpn == NULL)
		return;
	sftp_hpn_src_dispose(hpn);	/* free any in-flight inline-hash state */
	/* Safety net: verify_pending is normally drained by the verify phase
	 * and verify_failed_paths handed to sftp.c, both before teardown. */
	for (i = 0; i < hpn->verify_pending_count; i++) {
		free(hpn->verify_pending[i].local_path);
		free(hpn->verify_pending[i].remote_path);
	}
	free(hpn->verify_pending);
	for (i = 0; i < hpn->verify_failed_count; i++)
		free(hpn->verify_failed_paths[i]);
	free(hpn->verify_failed_paths);
	free(hpn->pace.bw);
	freezero(hpn, sizeof(*hpn));
}

/* Latch a protocol violation. The connection is also marked dead so
 * every later RPC on it bails. Both flags are sticky. */
void
sftp_conn_set_protocol_violation(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->dead = 1;
	hpn->protocol_violation = 1;
}

/* Register a live-bytes counter for this connection. The transfer loops
 * bump it per chunk; the parallel watchdog and the serial verify meter
 * read it. NULL unregisters. */
void
sftp_conn_set_live_counter(struct sftp_conn *conn, volatile uint64_t *counter)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->live_counter = counter;
}

/* Register the parallel orchestrator's cooperative-yield flag for this
 * connection (tail redistribution). See the field comment in
 * sftp-hpn-client.h. NULL unregisters. */
void
sftp_conn_set_yield_flag(struct sftp_conn *conn, volatile int *flag)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->yield_flag = flag;
}

/* --------------------------------------------------------------------------
 * Watchdog pause primitive. Lets a worker tell the parallel
 * orchestrator's watchdog that it's about to be busy with legitimate
 * non-byte-transfer work (verify-hash phase, fsync after large write,
 * bundle accumulate/extract, etc.) for up to N seconds. Watchdog
 * suppresses its inactivity-based heuristics for this worker until the
 * deadline expires; the SSH-child-gone check still fires regardless.
 * Callers pause for HPN_HEARTBEAT_REFRESH_SEC and the server's heartbeats
 * during a long hash refresh it, so the window tracks real progress.
 * See sftp-client-internal.h for full semantics.
 * -------------------------------------------------------------------------- */

/* Declare up to seconds of legitimate quiet on this connection. The
 * deadline only ever moves later; resume or expiry clears it. */
void
sftp_conn_watchdog_pause(struct sftp_conn *conn, unsigned int seconds)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t deadline_ms;
	uint64_t current_ms;

	if (hpn == NULL)
		return;

	deadline_ms = monotime_ms() + (uint64_t)seconds * 1000ULL;

	/* Extend, never shrink: a shorter pause arriving while a longer one
	 * is in flight must not undo it. Only the worker's own thread writes
	 * this, so a plain load and store suffice. */
	current_ms = __atomic_load_n(&hpn->watchdog_pause_until_ms,
	    __ATOMIC_RELAXED);
	if (deadline_ms > current_ms) {
		__atomic_store_n(&hpn->watchdog_pause_until_ms,
		    deadline_ms, __ATOMIC_RELAXED);
	}
}

/* End the pause early so the watchdog's heuristics apply again. */
void
sftp_conn_watchdog_resume(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->watchdog_pause_until_ms, 0,
	    __ATOMIC_RELAXED);
}

/* Deadline of the current watchdog pause in monotonic ms, 0 when none.
 * Read by the parallel watchdog's classifiers. */
uint64_t
sftp_conn_watchdog_pause_until_ms(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return __atomic_load_n(&hpn->watchdog_pause_until_ms, __ATOMIC_RELAXED);
}

/* --------------------------------------------------------------------------
 * Adaptive read-ahead controller. Probes for the smallest in-flight
 * depth that saturates the path, doubling while throughput rises and
 * settling at the knee; -R stays the ceiling. Backpressure halves the
 * depth and a persistent floor marks the connection dead for respawn.
 * Rationale in sftp-hpn-client.h at struct sftp_rdahead.
 * -------------------------------------------------------------------------- */

/* Seed the controller for a new connection: cap is num_requests, the -R
 * ceiling, the floor is RDAHEAD_FLOOR clamped to it, and probing starts
 * at the floor. Re-seeding a live controller resets it. */
void
sftp_conn_rdahead_init(struct sftp_conn *conn, uint32_t cap)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	/* Likely not necessary as the caller xcallocs the struct so
	 * everything is already zero. Only here in case we end up
	 * reiniting an exist struct at some point */
	memset(&hpn->rd, 0, sizeof(hpn->rd));

	/* the only caller sets cap to 1024 *but* again for safety */
	hpn->rd.cap = cap ? cap : 1;

	hpn->rd.floor = MINIMUM(RDAHEAD_FLOOR, hpn->rd.cap);
	hpn->rd.cur = hpn->rd.floor;
	hpn->rd.last_rising = hpn->rd.floor;
	hpn->rd.win_start = monotime_double();
}

/* Open a fresh measurement window at now. */
static void
rdahead_window_reset(struct sftp_rdahead *rd, double now)
{
	rd->win_bytes = 0;
	rd->win_reqs = 0;
	rd->win_start = now;
}

/* The depth has left the floor: forget the degradation run so a future
 * bad patch starts a fresh count. */
static void
rdahead_clear_degradation(struct sftp_rdahead *rd)
{
	rd->consecutive_bp_at_floor = 0;
	rd->time_first_at_floor = 0.0;
}

/* Feed one completed request's bytes to the controller. Once per window,
 * one depth's worth of requests and at least RDAHEAD_MIN_WIN_SEC, it
 * measures app-layer throughput and resizes the depth: EWMA-smooth the
 * rate, double while the gain exceeds RDAHEAD_GROW_PCT, otherwise settle
 * at the last depth that was still rising, the BDP knee. A connection
 * parked at the floor gets a time-based probe instead. No-op once
 * settled. */
void
sftp_conn_rdahead_account(struct sftp_conn *conn, size_t nbytes)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	struct sftp_rdahead *rd;
	double now, elapsed, rate, gain;

	if (hpn == NULL || hpn->rd.settled)
		return;
	rd = &hpn->rd;
	rd->win_bytes += nbytes;
	rd->win_reqs++;
	now = monotime_double();

	/* Floor probe. After RDAHEAD_PROBE_INTERVAL_SEC at the floor, double
	 * once without waiting for a full window of acks; the backpressure
	 * signal shrinks it back if the path is still bad. See the define.
	 * Restricted to the floor so it never accelerates a healthy climb. */
	if (rd->cur == rd->floor && rd->cur < rd->cap) {
		double probe_elapsed = now - rd->win_start;
		if (probe_elapsed > RDAHEAD_PROBE_INTERVAL_SEC) {
			uint32_t before = rd->cur;
			rd->last_rising = rd->cur;
			rd->cur = MINIMUM(rd->cur * 2, rd->cap);
			rdahead_window_reset(rd, now);
			rdahead_clear_degradation(rd);
			debug2_f("rdahead: time-probe, depth %u -> %u "
			    "(forced after %.1fs at floor)",
			    before, rd->cur, probe_elapsed);
			return;
		}
	}

	if (rd->win_reqs < rd->cur)
		return;	 /* window = one depth's worth */
	elapsed = now - rd->win_start;
	if (elapsed < RDAHEAD_MIN_WIN_SEC)
		return;	 /* too short to measure; keep filling */

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
	rdahead_window_reset(rd, now);
	/* Any successful window that lands cur above the floor counts as
	 * recovery. */
	if (rd->cur > rd->floor)
		rdahead_clear_degradation(rd);
	debug2_f("rdahead: depth=%u cap=%u rate=%.1f MiB/s%s",
	    rd->cur, rd->cap, rate / (1024.0 * 1024.0),
	    rd->settled ? " (settled)" : "");
}

/* Backpressure signal: the caller saw a STATUS read block longer than
 * RDAHEAD_BP_THRESHOLD_SEC and concluded the pipeline is wedged. Halve
 * the in-flight depth, clamped to the floor, clear settled so the
 * controller re-probes from there, and discard the throughput baseline
 * so the next window is not judged against the pre-wedge rate. TCP's
 * multiplicative decrease on RTO is the analogue. Repeated signals at
 * the floor mark the connection dead so the orchestrator respawns it. */
void
sftp_conn_rdahead_backpressure_signal(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	struct sftp_rdahead *rd;
	uint32_t before;
	double now;

	if (hpn == NULL)
		return;
	rd = &hpn->rd;
	before = rd->cur;
	now = monotime_double();
	rd->cur = MAXIMUM(rd->cur / 2, rd->floor);
	rd->settled = 0;
	rd->last_rate = 0.0;
	rd->last_rising = rd->cur;
	rdahead_window_reset(rd, now);

	/* Persistent silence. Each signal that lands at the floor counts
	 * and, on first arrival, stamps the time. Past either reap threshold
	 * the connection is marked dead so the orchestrator's watchdog
	 * respawns the worker on a fresh TCP session, which is the cure for
	 * a wedged one. See the thresholds in sftp-hpn-client.h. Any
	 * completed request at the floor clears the run through the
	 * probe in account(). A connection that crawls is left to the
	 * watchdog's monitoring. */
	if (rd->cur == rd->floor) {
		if (rd->time_first_at_floor <= 0.0)
			rd->time_first_at_floor = now;
		rd->consecutive_bp_at_floor++;

		if (rd->consecutive_bp_at_floor >= RDAHEAD_REAP_BP_COUNT ||
		    (now - rd->time_first_at_floor) > RDAHEAD_REAP_FLOOR_SEC) {
			debug_f("rdahead: connection persistently degraded "
			    "(bp_at_floor=%u floor_for=%.1fs); marking dead "
			    "for orchestrator respawn",
			    rd->consecutive_bp_at_floor,
			    now - rd->time_first_at_floor);
			hpn->dead = 1;
			/* This state is about to be torn down; clear it so a
			 * respawn never inherits the run. */
			rdahead_clear_degradation(rd);
		}
	}

	debug2_f("rdahead: backpressure, depth %u -> %u (re-probing)",
	    before, rd->cur);
}

/* The controller's current depth, the in-flight cap for the upload sites
 * (do_upload_body, sftp_upload_range) and the bundle paths. A conn with
 * no HPN state gets the floor. */
uint32_t
sftp_conn_rdahead_cap(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return RDAHEAD_FLOOR;
	return hpn->rd.cur;
}

/* Next read-ahead window for the download sites (sftp_download,
 * sftp_download_range, sftp_crossload): feed nbytes to the controller and
 * return its depth. */
uint32_t
sftp_conn_rdahead_window(struct sftp_conn *conn, size_t nbytes)
{
	sftp_conn_rdahead_account(conn, nbytes);
	return sftp_conn_rdahead_cap(conn);
}

/* Client side of the hpn-file-layout@hpnssh.org extension: one round trip
 * asking the server to set a layout on the directory at path, stripe_count
 * wide with files below small_threshold kept on one stripe. Returns the
 * reply status, HPN_FILE_LAYOUT_OK, _NOT_FS, _PERM or _FAIL, and reports
 * what the server applied through applied_out and layout_kind_out. The
 * caller in sftp-lustre-client.c decides whether and what to ask. Wire
 * format and status codes are in sftp-hpn-server.h. This is projected
 * to be a somewhat generic function for other parallel file systems. */
int
sftp_hpn_set_file_layout(struct sftp_conn *conn, const char *path,
    uint32_t stripe_count, uint32_t small_threshold, uint32_t *applied_out,
    uint32_t *layout_kind_out)
{
	struct sshbuf	*msg = NULL;
	u_int		 id, rid;
	uint32_t	 status = HPN_FILE_LAYOUT_FAIL;
	uint32_t	 applied = 0;
	uint32_t	 layout_kind = 0;
	u_char		 type;
	int		 r;
	int		 rc = HPN_FILE_LAYOUT_FAIL;

	if (applied_out != NULL)
		*applied_out = 0;
	if (layout_kind_out != NULL)
		*layout_kind_out = 0;

	if (conn == NULL || path == NULL)
		return HPN_FILE_LAYOUT_FAIL;

	if (!sftp_conn_has_file_layout(conn)) {
		debug_f("server lacks hpn-file-layout; skipping");
		return HPN_FILE_LAYOUT_NOT_FS;
	}

	if ((msg = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		return HPN_FILE_LAYOUT_FAIL;
	}

	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending hpn-file-layout \"%s\" stripe_count=%u "
	    "small_threshold=%u id=%u",
	    path, stripe_count, small_threshold, id);
	/* compose and send the request */
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

	/* get the reply */
	if (get_msg(conn, msg) != 0) {
		logit_f("hpn-file-layout \"%s\": transport receive failed",
		    path);
		goto out;
	}
	/* check the header */
	if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
	    (r = sshbuf_get_u32(msg, &rid)) != 0) {
		logit_f("hpn-file-layout \"%s\": parse reply header: %s",
		    path, ssh_err(r));
		goto out;
	}
	/* We got another request's reply */
	if (rid != id) {
		sftp_conn_die(conn,
		    "hpn-file-layout reply id mismatch (got %u expected %u)",
		    rid, id);
		sftp_conn_set_protocol_violation(conn);
		goto out;
	}
	/* not the response we want */
	if (type == SSH2_FXP_STATUS) {
		u_int	 fx_status = SSH2_FX_FAILURE;
		(void)sshbuf_get_u32(msg, &fx_status);
		logit_f("hpn-file-layout \"%s\": server STATUS reply %s",
		    path, fx2txt(fx_status));
		goto out;
	}
	/* anything else is a protocol problem */
	if (type != SSH2_FXP_EXTENDED_REPLY) {
		sftp_conn_die(conn,
		    "hpn-file-layout: expected SSH2_FXP_EXTENDED_REPLY(%u), "
		    "got %u", SSH2_FXP_EXTENDED_REPLY, type);
		sftp_conn_set_protocol_violation(conn);
		goto out;
	}

	/* parse the reply body */
	if ((r = sshbuf_get_u32(msg, &status)) != 0 ||
	    (r = sshbuf_get_u32(msg, &applied)) != 0 ||
	    (r = sshbuf_get_u32(msg, &layout_kind)) != 0) {
		logit_f("hpn-file-layout \"%s\": parse reply body: %s",
		    path, ssh_err(r));
		goto out;
	}

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

/* ==========================================================================
 * Per-connection state accessors. Each takes the opaque struct sftp_conn
 * and reaches the HPN state through sftp_conn_hpn(), so the upstream
 * sftp-client.c carries no per-field HPN accessor. Groups, in order:
 * liveness flags and death, wire and live byte accounting, hash-work
 * accounting for the meter, permission and policy latches, server
 * extension predicates, and the advertised worker cap. The liveness,
 * latch, predicate and cap functions are public in sftp-client.h; the
 * accounting ones are in sftp-client-internal.h.
 * ========================================================================== */

/* True once the connection is unusable. Set by sftp_conn_die,
 * sftp_conn_set_dead, a protocol violation and the read-ahead reap.
 * Sticky. */
int
sftp_conn_is_dead(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->dead;
}

/* A protocol violation is a reply that breaks the SFTP protocol: a
 * request id other than the one outstanding, or a packet type the
 * request does not permit. sftp-client.c flags it wherever it decodes
 * a reply. It points at a MITM or a corrupt server rather than a
 * dropped connection, so callers abort instead of retrying. */
int
sftp_conn_is_protocol_violation(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->protocol_violation;
}

/* Log a connection failure and latch dead, without terminating the
 * process. The RPC layer calls this in place of fatal() on paths that
 * may run inside a parallel worker, where fatal() would take down the
 * orchestrator. Later RPCs on the connection bail on the dead flag. */
void
sftp_conn_die(struct sftp_conn *conn, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	/* Fixed prefix so these are easy to grep out of logs. */
	error("sftp: connection died: %s", buf);
	sftp_conn_hpn(conn)->dead = 1;
}

/* Mark the connection dead after a transport failure the caller has
 * already reported. sftp-client.c sets the flag directly, the HPN
 * modules use this. No NULL guard on purpose: a connection always has
 * HPN state, and a condemned connection left alive is worse than a
 * crash here. */
void
sftp_conn_set_dead(struct sftp_conn *conn)
{
	sftp_conn_hpn(conn)->dead = 1;
}

/* Credit nbytes to the live counter, if one is registered. The bundle
 * codec feeds the watchdog's liveness classifiers through this; the
 * per-file loops in sftp-client.c bump the counter inline. Without it a
 * worker mid-bundle reads as zero bytes moved and is killed as born-dead
 * on any bundle slower than the detection window. */
void
sftp_conn_live_account(struct sftp_conn *conn, size_t nbytes)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL && hpn->live_counter != NULL)
		__atomic_fetch_add(hpn->live_counter, nbytes, __ATOMIC_RELAXED);
}

/* Payload bytes that have crossed the wire on this connection so far.
 * The orchestrator reads it at session end for the resolved versus
 * wired summary. Written by sftp_conn_bytes_wired_add. */
uint64_t
sftp_conn_bytes_wired(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return __atomic_load_n(&hpn->bytes_wired_payload, __ATOMIC_RELAXED);
}

/* Account nbytes of payload that crossed the wire on this connection,
 * WRITE payload sent or DATA payload received. Atomic, safe from any
 * thread. Read back through sftp_conn_bytes_wired. */
void
sftp_conn_bytes_wired_add(struct sftp_conn *conn, uint64_t nbytes)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL || nbytes == 0)
		return;
	__atomic_fetch_add(&hpn->bytes_wired_payload, nbytes, __ATOMIC_RELAXED);
}

/* Unified hash-work accounting (see sftp-hpn-client.h for the model).
 * Engines call begin/leg/progress; unit-completion sites call end; the
 * reporter and watchdog read the stamp-gated live values. The two
 * meter functions mirror done onto a serial meter counter for the
 * non-parallel paths. */
void
sftp_conn_hash_op_begin(struct sftp_conn *conn, uint64_t total_work)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_total, total_work, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
}

/* Entering a leg: subsequent progress reports are offset by `base`
 * (0 for the first leg, the span for the second). */
void
sftp_conn_hash_op_leg(struct sftp_conn *conn, uint64_t base)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->hash_work_leg_base, base, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
}

/* Cumulative progress within the current leg (heartbeat figures, local
 * read loops). Publishes done = leg_base + leg_bytes (clamped to the op
 * total), refreshes the liveness stamp, and lands the value on the serial
 * meter bridge when one is registered. */
void
sftp_conn_hash_op_progress(struct sftp_conn *conn, uint64_t leg_bytes)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t done, total;

	if (hpn == NULL)
		return;
	done = __atomic_load_n(&hpn->hash_work_leg_base, __ATOMIC_RELAXED) +
	    leg_bytes;
	total = __atomic_load_n(&hpn->hash_work_total, __ATOMIC_RELAXED);
	if (total > 0 && done > total)
		done = total;
	__atomic_store_n(&hpn->hash_work_done, done, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_stamp_ms, (uint64_t)monotime_ms(),
	    __ATOMIC_RELAXED);
	if (hpn->hash_meter_ctr != NULL)
		*hpn->hash_meter_ctr = (off_t)(hpn->hash_meter_base + done);
}

/* Unit completion: retire the op. Callers that fold the op's work into a
 * phase accumulator must read hash_work_done before this clears it. */
void
sftp_conn_hash_op_end(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	__atomic_store_n(&hpn->hash_work_done, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_leg_base, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_total, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&hpn->hash_work_stamp_ms, 0, __ATOMIC_RELAXED);
	if (hpn->hash_meter_ctr != NULL)
		*hpn->hash_meter_ctr = (off_t)hpn->hash_meter_base;
}

/* Stamp-gated live pair for the reporter: zeros unless refreshed within
 * HASH_WORK_STALE_MS (an engine gone on any path self-clears). */
void
sftp_conn_hash_work_live(struct sftp_conn *conn, uint64_t *done_out,
    uint64_t *total_out)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t stamp;

	*done_out = 0;
	*total_out = 0;
	if (hpn == NULL)
		return;
	stamp = __atomic_load_n(&hpn->hash_work_stamp_ms, __ATOMIC_RELAXED);
	if (stamp == 0 || (uint64_t)monotime_ms() - stamp > HASH_WORK_STALE_MS)
		return;
	*done_out = __atomic_load_n(&hpn->hash_work_done, __ATOMIC_RELAXED);
	*total_out = __atomic_load_n(&hpn->hash_work_total, __ATOMIC_RELAXED);
}

/* Live total only. This is the watchdog's "provably hashing" gate. */
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
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return __atomic_load_n(&hpn->hash_work_done, __ATOMIC_RELAXED);
}

/* Serial meter bridge registration; NULL unregisters. Resets the
 * completed-work base. */
void
sftp_conn_set_hash_meter_ctr(struct sftp_conn *conn, volatile off_t *ctr)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->hash_meter_ctr = ctr;
	hpn->hash_meter_base = 0;
}

/* Serial multi-op meters (verify phase): fold a completed op's work into
 * the bridge base so the next op's progress continues from it. */
void
sftp_conn_hash_meter_base_add(struct sftp_conn *conn, uint64_t work)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->hash_meter_base += work;
	if (hpn->hash_meter_ctr != NULL)
		*hpn->hash_meter_ctr = (off_t)hpn->hash_meter_base;
}

/* Two sticky refusal flags. saw_perm_denied: the server answered
 * PERMISSION_DENIED, so the parallel worker marks the unit no-retry
 * rather than respawn into the same refusal. It survives the
 * post-failure CLOSE and is cleared at each unit boundary. */
int
sftp_conn_saw_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->saw_perm_denied;
}

/* Latch permission-denied. Called by the STATUS and HANDLE decoders in
 * sftp-client.c. */
void
sftp_conn_set_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->saw_perm_denied = 1;
}

/* Clear it at a unit boundary so the next unit judges its own replies. */
void
sftp_conn_clear_perm_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->saw_perm_denied = 0;
}

/* saw_policy_denied: the refusal carried the server's request-policy tag,
 * a -P/-p class denial rather than a filesystem error, so the bundle
 * path aborts the whole transfer. Cleared at each bundle attempt. */
int
sftp_conn_saw_policy_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->saw_policy_denied;
}

/* Clear it before a bundle attempt. */
void
sftp_conn_clear_policy_denied(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->saw_policy_denied = 0;
}

/* Called right after a PERMISSION_DENIED status code is read, with msg
 * positioned at the status reply's error-message string. If that message
 * carries HPN_POLICY_DENIED_TAG the refusal came from the server's -P/-p
 * request policy, not a filesystem error, so latch saw_policy_denied.
 * Consumes the message string from msg; harmless on a buffer that has
 * none. */
void
sftp_conn_check_policy_tag(struct sftp_conn *conn, struct sshbuf *msg)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	char *errmsg = NULL;

	if (hpn == NULL || msg == NULL)
		return;
	if (sshbuf_get_cstring(msg, &errmsg, NULL) == 0 && errmsg != NULL &&
	    strstr(errmsg, HPN_POLICY_DENIED_TAG) != NULL)
		hpn->saw_policy_denied = 1;
	free(errmsg);
}

/* Server-advertised extension predicates: which HPN SFTP extensions the
 * peer announced in its VERSION reply. Read through the sftp_conn_exts()
 * bridge; the SFTP_EXT_HPN_* bits are in sftp-hpn-client.h. */
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

/* True when the server advertised both halves of the chunked tree walk,
 * hpn-dtree-open and hpn-dtree-read. The download walks pick it over the
 * readdir fallback. */
int
sftp_conn_has_tree_walk(struct sftp_conn *conn)
{
	u_int both = SFTP_EXT_HPN_DTREE_OPEN | SFTP_EXT_HPN_DTREE_READ;

	return (sftp_conn_exts(conn) & both) == both;
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

int
sftp_conn_has_fs_info(struct sftp_conn *conn)
{
	return (sftp_conn_exts(conn) & SFTP_EXT_HPN_FS_INFO) != 0;
}

/* The operator's per-user parallel-worker cap as advertised by the server
 * (hpn-max-workers@hpnssh.org): -1 when not advertised, a stock server,
 * 0 when advertised with no cap, otherwise the cap. The orchestrator
 * clamps -j to it. */
int
sftp_conn_max_workers_cap(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL ? hpn->hpn_max_workers_cap : -1;
}

/* --------------------------------------------------------------------------
 * Adaptive upload pacing. WRITE acks arrive at the receiver's true
 * sustained drain rate, so their rate is the signal: the ceiling is
 * 125% of the mean of recent per-second rates, floored, and armed
 * on the same token bucket -l uses. Holding offered load just under the
 * sink's flush rate keeps its page cache off the dirty-page cliff that
 * otherwise collapses a single-stream high-RTT upload into a stall and
 * recover duty cycle. Measured on Lustre and ext4/NVMe: 37% higher
 * throughput and no multi-second stalls.
 *
 * The mean, not a max, is the deliberate choice: stall seconds enter the
 * average and pull the estimate toward the sink's real sustained rate,
 * where a max filter would latch the page cache's absorb rate and stop
 * protecting the transfer. Arming runs on a time cadence from the ack
 * path and never looks at file boundaries, so one huge file and hundreds
 * of small ones behave the same. Rationale in sftp-hpn-client.h at the
 * pace member.
 * -------------------------------------------------------------------------- */

/* -X Pacing= master switch, applied to every connection created after
 * it. Parsed once at startup, before any connection exists. */
void
sftp_hpn_pace_set_enabled(int on)
{
	sftp_hpn_pace_default = on;
}

/* Mean of the nonzero ring slots in bytes/sec, 0 when there are none.
 * Empty slots and buckets that truncated to zero are skipped alike. The
 * section banner explains why the estimator is a mean. */
static uint64_t
sftp_hpn_pace_mean(struct sftp_hpn_conn *hpn)
{
	uint64_t sum = 0;
	u_int i, filled = 0;

	for (i = 0; i < PACE_RING; i++) {
		if (hpn->pace.rate_ring[i] == 0)
			continue;
		sum += hpn->pace.rate_ring[i];
		filled++;
	}
	if (filled > 0)
		return sum / filled;
	return 0;
}

/* Feed one WRITE ack of len payload bytes into the controller: roll the
 * per-second rate bucket into the ring, hold off until a full pipeline
 * of num_requests has been acked and the grace period has passed, and
 * re-arm the actuator on the ARM_MS cadence. Called from the upload
 * ack-reap paths in sftp-client.c. There are extensive comments in this
 * because it's not necessarily transparent what we are doing or why. */
void
sftp_conn_pace_ack(struct sftp_conn *conn, size_t len, u_int num_requests)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);
	uint64_t now_ms, elapsed_ms, bucket_rate, mean_rate, target_rate;
	uint64_t prev_rate, rate_bits;

	if (hpn == NULL || !hpn->pace.enabled)
		return;
	now_ms = monotime_ms();
	if (hpn->pace.acks == 0) {
		hpn->pace.first_ack_ms = now_ms;
		hpn->pace.bucket_start_ms = now_ms;
	}
	hpn->pace.acks++;
	hpn->pace.bucket_bytes += len;

	elapsed_ms = now_ms - hpn->pace.bucket_start_ms;
	if (elapsed_ms < PACE_BUCKET_MS)
		return;
	/* Slow-start excision: throw the bucket away (roll the window but
	 * record nothing) until SKIP_MS past the first ack. */
	if (now_ms - hpn->pace.first_ack_ms < PACE_SKIP_MS) {
		hpn->pace.bucket_bytes = 0;
		hpn->pace.bucket_start_ms = now_ms;
		return;
	}
	bucket_rate = hpn->pace.bucket_bytes * 1000 / elapsed_ms;
	hpn->pace.rate_ring[hpn->pace.ring_idx++ % PACE_RING] = bucket_rate;
	hpn->pace.bucket_bytes = 0;
	hpn->pace.bucket_start_ms = now_ms;

	if (!hpn->pace.active) {
		if (hpn->pace.acks < num_requests ||
		    now_ms - hpn->pace.first_ack_ms <
		    PACE_SKIP_MS + PACE_GRACE_MS)
			return;
		hpn->pace.active = 1;
		debug2_f("engaged: mean recent rate %llu bytes/s",
		    (unsigned long long)sftp_hpn_pace_mean(hpn));
	}

	/* Time-based re-arm, at most once per ARM interval. */
	if (now_ms - hpn->pace.last_arm_ms < PACE_ARM_MS)
		return;
	mean_rate = sftp_hpn_pace_mean(hpn);
	/* Every closed bucket truncated to zero, a trickle of tiny writes
	 * on a slow path. Keep the current ceiling rather than arm on no
	 * evidence. */
	if (mean_rate == 0)
		return;
	/* Ceiling at 125% of the mean. The headroom is both the overshoot
	 * bound, ingest runs at most 25% above what the sink drains, and
	 * the upward probe, the ceiling can rise 25% per re-arm when the
	 * sink speeds up. 125% trades probe speed against overshoot. */
	target_rate = mean_rate * 5 / 4;
	/* Down-step clamp: one re-arm may cut the ceiling by at most half
	 * (no clamp on the first arm; bw_rate_bits holds bytes x 8). The
	 * increase side is inherently bounded (about 25% per re-arm, since the
	 * mean can only grow as fast as the current ceiling admits); an
	 * unbounded decrease lets one transient famine window crater a
	 * healthy ceiling and the 25% climb-back takes tens of seconds.
	 * Halving per re-arm still tracks a genuine sustained slowdown
	 * within a few ARM intervals. */
	prev_rate = hpn->pace.bw_rate_bits / 8;
	if (prev_rate > 0 && target_rate < prev_rate / 2)
		target_rate = prev_rate / 2;
	if (target_rate < PACE_FLOOR_RATE)
		target_rate = PACE_FLOOR_RATE;
	/* Post-famine fast reclaim. After a famine the down-step clamp can
	 * leave the ceiling at the floor, and climbing back 25% per re-arm
	 * takes tens of seconds. Two tests together say the sink has recovered.
	 * First, the last bucket delivered at least 90% of the current ceiling,
	 * so the ceiling is binding (90% is a somewhat arbitrary value);
	 * healthy running delivers about 80% of it, the inverse of the 125%
	 * headroom. Second, the target is below 80% of reclaim_bytes, the
	 * proven ceiling from before the descent. The jump goes to that 80%,
	 * roughly the delivery rate that earned the proven ceiling. The ring is
	 * flushed with the jump, or its famine samples would pull the next arm
	 * back down and undo the reclaim. If the sink cannot hold the new level
	 * it famines again and the next jump lands 20% lower, converging on its
	 * true rate. */
	if (prev_rate > 0 && bucket_rate * 10 >= prev_rate * 9 &&
	    target_rate < hpn->pace.reclaim_bytes * 4 / 5) {
		target_rate = hpn->pace.reclaim_bytes * 4 / 5;
		memset(hpn->pace.rate_ring, 0,
		    sizeof(hpn->pace.rate_ring));
		hpn->pace.ring_idx = 0;
		debug2_f("reclaim to %llu bytes/s",
		    (unsigned long long)target_rate);
	}
	/* reclaim_bytes follows the ceiling on any re-arm that holds or
	 * rises and freezes on one that falls, so it keeps the level from
	 * before the last descent. */
	if (prev_rate == 0 || target_rate >= prev_rate)
		hpn->pace.reclaim_bytes = target_rate;
	/* The token bucket's rate is bits/s, whatever misc.c's parameter
	 * name says, so bytes x 8 is exact. len, this ack's request size,
	 * is the natural chunk-size hint. */
	rate_bits = target_rate * 8;
	if (hpn->pace.bw == NULL)
		hpn->pace.bw = xcalloc(1, sizeof(*hpn->pace.bw));
	bandwidth_limit_init(hpn->pace.bw, rate_bits, len);
	hpn->pace.bw_rate_bits = rate_bits;
	hpn->pace.last_arm_ms = now_ms;
	debug2_f("ceiling %llu bytes/s (mean %llu)",
	    (unsigned long long)target_rate, (unsigned long long)mean_rate);
}

/* The token bucket the outbound path should apply: the tighter of the
 * adaptive ceiling and the user's explicit -l, or NULL when neither
 * applies. Until pacing engages this is just the -l bucket. send_msg
 * applies the result to every outbound message, not only upload WRITEs,
 * and pacing stays engaged for the life of the connection once it
 * starts. That is harmless: READs, stats and other requests are tiny
 * next to PACE_FLOOR_RATE, so the ceiling only ever binds on upload
 * data. */
struct bwlimit *
sftp_conn_pace_bwlimit(struct sftp_conn *conn, struct bwlimit *user_bw,
    uint64_t user_rate)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL || !hpn->pace.active || hpn->pace.bw == NULL)
		return user_bw;
	/* user_rate is conn->limit_kbps, which -l parsing already scaled to
	 * bits/s (kbit x 1024), the unit bw_rate_bits holds, so the two
	 * compare directly. */
	if (user_bw != NULL && user_rate > 0 &&
	    user_rate <= hpn->pace.bw_rate_bits)
		return user_bw;
	return hpn->pace.bw;
}

/* Install the bundling knobs resolved from ssh_config, HPNUseBundle,
 * HPNBundleSize and HPNWriterPool, for the serial-path walks. Without
 * this call the connection keeps the defaults set at init. */
void
sftp_conn_set_bundle_config(struct sftp_conn *conn, int use_bundle,
    uint64_t bundle_size, int writer_pool)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	hpn->bundle_cfg.use = use_bundle;
	hpn->bundle_cfg.size = bundle_size;
	hpn->bundle_cfg.writer_pool = writer_pool;
}

/* --------------------------------------------------------------------------
 * Serial-path bundling. The recursive walks in sftp-client.c
 * collect bundle-eligible small files here, across directories, and ship
 * each batch as one hpn-bundle upload or hpn-bundle-fetch download on the
 * session connection. The grouping policy is shared with the parallel
 * producer through sftp-hpn-bundle.h, so both modes bundle identically.
 * -------------------------------------------------------------------------- */

/* Open an accumulator for one recursive walk. It stays disabled, so every
 * file transfers individually, when bundling is off, the server refused a
 * bundle earlier this session, the walk is a resume, or the server lacks
 * the extension for this direction. */
void
sftp_hpn_bundle_acc_init(struct sftp_hpn_bundle_acc *acc,
    struct sftp_conn *conn, int resume, int is_download)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	memset(acc, 0, sizeof(*acc));
	if (hpn == NULL || !hpn->bundle_cfg.use ||
	    hpn->bundle_cfg.server_cant || resume)
		return;
	if (is_download && !sftp_conn_has_hpn_bundle_fetch(conn))
		return;
	if (!is_download && !sftp_conn_has_hpn_bundle(conn))
		return;
	acc->target = hpn->bundle_cfg.size;
	if (acc->target == 0)
		acc->target = HPN_BUNDLE_SIZE_DEFAULT;
	acc->is_download = is_download;
	acc->enabled = 1;
}

/* True when the accumulator is live and a file of this size may join a
 * bundle under the policy shared with the parallel producer: smaller than
 * a quarter of the bundle target. */
int
sftp_hpn_bundle_acc_eligible(const struct sftp_hpn_bundle_acc *acc,
    uint64_t size)
{
	return acc->enabled &&
	    hpn_bundle_file_eligible(size, acc->target);
}

/* Append one member and return 1 when the accumulator must flush: its
 * framed bytes reached the target, it holds BUNDLE_BATCH_MAX_FILES
 * members, or, for a download, the fetch request's path list would
 * outgrow one SFTP message. src and dst are in transfer order, local then
 * remote for an upload and remote then local for a download. Frame
 * accounting matches the parallel producer. */
int
sftp_hpn_bundle_acc_add(struct sftp_hpn_bundle_acc *acc, const char *src,
    const char *dst, off_t size)
{
	if (acc->nmembers == acc->members_alloc) {
		if (acc->members_alloc == 0)
			acc->members_alloc = 64;
		else
			acc->members_alloc *= 2;
		acc->src_paths = xreallocarray(acc->src_paths,
		    acc->members_alloc, sizeof(*acc->src_paths));
		acc->dst_paths = xreallocarray(acc->dst_paths,
		    acc->members_alloc, sizeof(*acc->dst_paths));
		acc->sizes = xreallocarray(acc->sizes, acc->members_alloc,
		    sizeof(*acc->sizes));
	}
	acc->src_paths[acc->nmembers] = xstrdup(src);
	acc->dst_paths[acc->nmembers] = xstrdup(dst);
	acc->sizes[acc->nmembers] = size;
	acc->nmembers++;
	if (acc->is_download) {
		/* Downloads frame by the remote path, which the fetch request
		 * also carries as a length-prefixed string. */
		acc->bytes += BUNDLE_REC_FRAME_BYTES(strlen(src),
		    (uint64_t)size);
		acc->path_bytes += 4 + strlen(src);
		return hpn_bundle_dl_should_flush(acc->bytes, acc->nmembers,
		    acc->target, acc->path_bytes, BUNDLE_DL_FETCH_REQ_MAX);
	}
	acc->bytes += BUNDLE_REC_FRAME_BYTES(strlen(dst), (uint64_t)size);
	return hpn_bundle_should_flush(acc->bytes, acc->nmembers, acc->target);
}

/* Drop the members after a flush and keep the arrays for the next batch. */
static void
sftp_hpn_bundle_acc_reset(struct sftp_hpn_bundle_acc *acc)
{
	int i;

	for (i = 0; i < acc->nmembers; i++) {
		free(acc->src_paths[i]);
		free(acc->dst_paths[i]);
	}
	acc->nmembers = 0;
	acc->bytes = 0;
	acc->path_bytes = 0;
}

/* Release everything the accumulator holds and disable it. */
void
sftp_hpn_bundle_acc_free(struct sftp_hpn_bundle_acc *acc)
{
	sftp_hpn_bundle_acc_reset(acc);
	free(acc->src_paths);
	free(acc->dst_paths);
	free(acc->sizes);
	acc->src_paths = NULL;
	acc->dst_paths = NULL;
	acc->sizes = NULL;
	acc->members_alloc = 0;
	acc->enabled = 0;
}

/* Report one file transfer's outcome from sftp_download or sftp_upload:
 * rc -1 failed, 0 transferred, 1 skipped as identical, 2 skipped because
 * the target is larger. Prints the skip notice and writes the TransferLog
 * line. A success is left for the verify phase to log when -V is on.
 * Returns -1 when the transfer failed, else 0. */
int
sftp_hpn_report_transfer(struct sftp_conn *conn, int rc, const char *src,
    const char *dst, off_t size)
{
	/* In frame mode stdout carries the progress frames, so text goes to
	 * stderr instead. */
	FILE *out = hpn_pm_active() ? stderr : stdout;

	switch (rc) {
	case -1:
		transferlog_file(TRANSFERLOG_FAILED, size, dst);
		return -1;
	case 1:
		fmprintf(out, "File skipped: %s: Identical.\n", src);
		transferlog_file(TRANSFERLOG_SKIPPED, size, dst);
		break;
	case 2:
		fmprintf(out, "File skipped: %s: Target is larger than "
		    "source.\n", src);
		transferlog_file(TRANSFERLOG_SKIPPED, size, dst);
		break;
	default:
		if (!sftp_conn_verify_transfer_enabled(conn))
			transferlog_file(TRANSFERLOG_SUCCESS, size, dst);
		break;
	}
	return 0;
}

/* Transfer one bundle member on its own, the fallback when the bundle
 * could not carry it, and report the outcome. Returns -1 when the
 * transfer failed, else 0. */
static int
bundle_member_xfer(struct sftp_conn *conn, struct sftp_hpn_bundle_acc *acc,
    int i, int preserve_flag, int verify, int fsync_flag, int inplace_flag)
{
	const char *src = acc->src_paths[i];
	const char *dst = acc->dst_paths[i];
	int rc;

	if (acc->is_download) {
		rc = sftp_download(conn, src, dst, NULL, preserve_flag,
		    /*resume*/0, fsync_flag, inplace_flag, verify);
		if (rc == -1)
			error("download \"%s\" to \"%s\" failed", src, dst);
	} else {
		rc = sftp_upload(conn, src, dst, preserve_flag,
		    /*resume*/0, verify, fsync_flag, inplace_flag);
		if (rc == -1)
			error("upload \"%s\" to \"%s\" failed", src, dst);
	}
	return sftp_hpn_report_transfer(conn, rc, src, dst, acc->sizes[i]);
}

/* Upload half of sftp_hpn_bundle_acc_flush: send the batch as one
 * hpn-bundle stream. Upload gets no per-member status back, so the
 * bundle succeeds or fails as a whole. A server that cannot bundle gets
 * the members one file at a time instead, and bundling stays off for the
 * rest of the session. A policy denial or a lost connection aborts the
 * walk. */
static int
bundle_acc_flush_upload(struct sftp_conn *conn,
    struct sftp_hpn_bundle_acc *acc, int preserve_flag,
    int verify, int fsync_flag, int inplace_flag)
{
	struct sftp_hpn_bundle_upload_entry *entries;
	struct sftp_bundle_opts opts;
	int i, rc, failures = 0;

	entries = xcalloc(acc->nmembers, sizeof(*entries));
	for (i = 0; i < acc->nmembers; i++) {
		entries[i].local_path = acc->src_paths[i];
		entries[i].remote_path = acc->dst_paths[i];
	}
	memset(&opts, 0, sizeof(opts));
	opts.preserve = preserve_flag;
	opts.fsync = fsync_flag;
	opts.writer_pool = sftp_conn_hpn(conn)->bundle_cfg.writer_pool;
	/* entries carry full remote paths */
	rc = sftp_hpn_bundle_upload(conn, "", entries, acc->nmembers, &opts);
	switch (rc) {
	case SFTP_HPN_BUNDLE_OK:
		for (i = 0; i < acc->nmembers; i++) {
			/* Mirror the per-file path: park for the classic
			 * verify phase, a no-op unless verify is on, then
			 * report the success. */
			sftp_conn_verify_park(conn, acc->src_paths[i],
			    acc->dst_paths[i], /*local_is_target=*/0);
			(void)sftp_hpn_report_transfer(conn, 0,
			    acc->src_paths[i], acc->dst_paths[i],
			    acc->sizes[i]);
		}
		break;
	case SFTP_HPN_BUNDLE_SERVER_CANT:
		/* Permanent, connection-agnostic refusal: stop bundling
		 * for this session and drive these members per-file. */
		debug_f("server refused bundle; per-file fallback");
		sftp_conn_hpn(conn)->bundle_cfg.server_cant = 1;
		acc->enabled = 0;
		for (i = 0; i < acc->nmembers; i++)
			if (bundle_member_xfer(conn, acc, i, preserve_flag,
			    verify, fsync_flag, inplace_flag) == -1)
				failures++;
		break;
	case SFTP_HPN_BUNDLE_POLICY_DENIED:
		error("bundle upload denied by remote policy; aborting");
		free(entries);
		return -1;
	case SFTP_HPN_BUNDLE_TRANSPORT_FAILED:
	default:
		error("bundle upload failed: connection error");
		free(entries);
		return -1;
	}
	free(entries);
	return failures > 0 ? 1 : 0;
}

/* Download half of sftp_hpn_bundle_acc_flush: fetch the batch as one
 * hpn-bundle-fetch transaction. The server returns a result per file, so
 * members that failed inside a good transaction are retried one file at
 * a time. A server that cannot bundle gets every member one file at a
 * time instead, and bundling stays off for the rest of the session. A
 * policy denial or a lost connection aborts the walk. */
static int
bundle_acc_flush_download(struct sftp_conn *conn,
    struct sftp_hpn_bundle_acc *acc, int preserve_flag,
    int verify, int fsync_flag, int inplace_flag)
{
	struct sftp_hpn_bundle_download_entry *entries;
	struct sftp_bundle_opts opts;
	int i, rc, failures = 0;
	off_t meter_ctr = 0, meter_total = 0;
	char meter_label[32];
	int meter_on;

	entries = xcalloc(acc->nmembers, sizeof(*entries));
	for (i = 0; i < acc->nmembers; i++) {
		entries[i].remote_path = acc->src_paths[i];
		entries[i].local_path = acc->dst_paths[i];
		meter_total += acc->sizes[i];
	}
	/* Meter the bundle as one BUNDLE-kind unit carrying acc->nmembers
	 * files. Bundled files never reach sftp_download, so without it a
	 * serial bundle shows no meter at all. Declaring every member at the
	 * start lets the frame stream count them, and a bundle of only empty
	 * files meters too, since the kind renders a zero total as complete.
	 * Parallel workers call sftp_hpn_bundle_download directly, so this
	 * never touches the parallel aggregate meter. */
	meter_on = showprogress;
	if (meter_on) {
		snprintf(meter_label, sizeof(meter_label), "%d files",
		    acc->nmembers);
		hpn_meter_start(hpn_meter_serial(), acc, HPN_METER_BUNDLE,
		    HPN_METER_DOM_TRANSFER, meter_label, meter_total,
		    &meter_ctr, (u_int)acc->nmembers);
	}
	memset(&opts, 0, sizeof(opts));
	opts.preserve = preserve_flag;
	opts.fsync = fsync_flag;
	opts.writer_pool = sftp_conn_hpn(conn)->bundle_cfg.writer_pool;
	rc = sftp_hpn_bundle_download(conn, entries, acc->nmembers, &opts,
	    meter_on ? &meter_ctr : NULL);
	if (meter_on)
		hpn_meter_stop(hpn_meter_serial(), acc);
	switch (rc) {
	case SFTP_HPN_BUNDLE_OK:
		for (i = 0; i < acc->nmembers; i++) {
			if (entries[i].result == 0) {
				sftp_conn_verify_park(conn,
				    acc->dst_paths[i], acc->src_paths[i],
				    /*local_is_target=*/1);
				(void)sftp_hpn_report_transfer(conn, 0,
				    acc->src_paths[i], acc->dst_paths[i],
				    acc->sizes[i]);
				continue;
			}
			/* Per-entry failure: re-drive individually (the
			 * per-file path parks for verify internally). */
			if (bundle_member_xfer(conn, acc, i, preserve_flag,
			    verify, fsync_flag, inplace_flag) == -1)
				failures++;
		}
		break;
	case SFTP_HPN_BUNDLE_SERVER_CANT:
		debug_f("server refused bundle-fetch; per-file fallback");
		sftp_conn_hpn(conn)->bundle_cfg.server_cant = 1;
		acc->enabled = 0;
		for (i = 0; i < acc->nmembers; i++)
			if (bundle_member_xfer(conn, acc, i, preserve_flag,
			    verify, fsync_flag, inplace_flag) == -1)
				failures++;
		break;
	case SFTP_HPN_BUNDLE_POLICY_DENIED:
		error("bundle download denied by remote policy; aborting");
		free(entries);
		return -1;
	case SFTP_HPN_BUNDLE_TRANSPORT_FAILED:
	default:
		error("bundle download failed: connection error");
		free(entries);
		return -1;
	}
	free(entries);
	return failures > 0 ? 1 : 0;
}

/* Flush the accumulator: send the batch collected since the last flush as
 * one bundle, hpn-bundle for an upload or hpn-bundle-fetch for a
 * download, then empty it. Called when sftp_hpn_bundle_acc_add reports
 * the batch full and once more at the end of an uninterrupted walk.
 * Returns 0 on success, 1 when members failed but the walk can go on,
 * and -1 to abort on a policy denial or a dead connection. */
int
sftp_hpn_bundle_acc_flush(struct sftp_conn *conn,
    struct sftp_hpn_bundle_acc *acc, int preserve_flag, int print_flag,
    int verify, int fsync_flag, int inplace_flag)
{
	int i, r;
	off_t file_bytes = 0;

	/* Nothing to send. bundle_acc_flush_upload and _download also rely
	 * on this: they allocate one entry per member, and xcalloc fatals on
	 * zero. */
	if (!acc->enabled || acc->nmembers == 0)
		return 0;

	if (print_flag && print_flag != SFTP_PROGRESS_ONLY) {
		/* loop to get sum of file sizes. Before we were 
		 * reporting on the bundle size which included the
		 * the framing and path byte */
		for (i = 0; i < acc->nmembers; i++)
			file_bytes += acc->sizes[i];
		pm_mprintf("%s bundle: %d files, %lld bytes\n",
		    acc->is_download ? "Fetching" : "Uploading",
		    acc->nmembers, (long long)file_bytes);
	}
	if (acc->is_download)
		r = bundle_acc_flush_download(conn, acc, preserve_flag,
		    verify, fsync_flag, inplace_flag);
	else
		r = bundle_acc_flush_upload(conn, acc, preserve_flag,
		    verify, fsync_flag, inplace_flag);
	sftp_hpn_bundle_acc_reset(acc);
	return r;
}

/* --------------------------------------------------------------------------
 * Shared directory handling, one implementation for the serial walks
 * in sftp-client.c and the parallel producer in sftp-parallel-walk.c.
 * Directories are created with the owner write and execute bits forced
 * on, and their final attributes are deferred to the end of the transfer,
 * then applied deepest first. Bundles write files after the walk has left
 * their directory, so a restrictive mode applied inline could block them.
 * The header comment in sftp-hpn-client.h has the tradeoffs.
 * -------------------------------------------------------------------------- */

/* Normalise a local stat into the attrs a directory is created with. Size
 * and owner are dropped, since neither means anything for a directory we
 * create. The mode keeps the permission and sticky bits, as stock sftp
 * does, and the timestamps are kept only under -p. Four walks share this,
 * so a change to what a directory's creation attrs mean is one edit. */
void
sftp_hpn_dir_attrs_from_stat(const struct stat *sb, int preserve_flag,
    Attrib *out)
{
	stat_to_attrib(sb, out);
	out->flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	out->flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	out->perm &= 01777;
	if (!preserve_flag)
		out->flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
}

/* Create the remote destination directory with the owner write and
 * execute bits forced on, as stock sftp's upload walk does. The deferred
 * attrs restore the real mode later. An existing directory is fine.
 * Sets *created to whether this call made it. Returns -1 when it cannot
 * be created and nothing usable is there. */
int
sftp_hpn_ensure_remote_dir(struct sftp_conn *conn, const char *dst,
    const Attrib *attrs, int *created)
{
	Attrib mkdir_attrs = *attrs;
	Attrib dirattrib;

	*created = 0;
	mkdir_attrs.perm |= (S_IWUSR|S_IXUSR);
	if (sftp_mkdir(conn, dst, &mkdir_attrs, 0) == 0) {
		*created = 1;
		return 0;
	}
	/* SFTP has no portable EEXIST, so on a mkdir failure check whether
	 * the path already exists as a directory. */
	if (sftp_stat(conn, dst, 0, &dirattrib) != 0)
		return -1;
	if (!S_ISDIR(dirattrib.perm)) {
		error("\"%s\" exists but is not a directory", dst);
		return -1;
	}
	return 0;
}

/* Local counterpart for downloads: create the directory with the remote
 * mode, or 0777 when the server sent none, plus the owner write and
 * execute bits. An existing directory is fine, as in stock sftp. Reports
 * the final and the forced mode so the caller can defer the chmod when
 * they differ. */
int
sftp_hpn_ensure_local_dir(const char *dst, const Attrib *dirattrib,
    mode_t *mode_out, mode_t *tmpmode_out)
{
	mode_t mode = 0777, tmpmode;

	if (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		mode = dirattrib->perm & 01777;
	else
		debug_f("local \"%s\": server did not send permissions",
		    dst);
	tmpmode = mode | (S_IWUSR|S_IXUSR);
	if (mkdir(dst, tmpmode) == -1) {
		struct stat sb;

		if (errno != EEXIST) {
			error("mkdir %s: %s", dst, strerror(errno));
			return -1;
		}
		if (stat(dst, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
			error("\"%s\" exists but is not a directory", dst);
			return -1;
		}
	}
	*mode_out = mode;
	*tmpmode_out = tmpmode;
	return 0;
}

/* Return the next free slot in the deferred-attribute list, zeroed,
 * doubling the list as needed. */
static struct sftp_hpn_dirattr *
dirattrs_grow(struct sftp_hpn_dirattr_list *dl)
{
	struct sftp_hpn_dirattr *d;

	if (dl->nentries == dl->entries_alloc) {
		if (dl->entries_alloc == 0)
			dl->entries_alloc = 32;
		else
			dl->entries_alloc *= 2;
		dl->entries = xreallocarray(dl->entries, dl->entries_alloc,
		    sizeof(*dl->entries));
	}
	d = &dl->entries[dl->nentries++];
	memset(d, 0, sizeof(*d));
	return d;
}

/* Queue a remote directory's final attrs for a setstat after the
 * transfer. */
void
sftp_hpn_dirattrs_defer_remote(struct sftp_hpn_dirattr_list *dl,
    const char *path, const Attrib *attrs)
{
	struct sftp_hpn_dirattr *d = dirattrs_grow(dl);

	d->path = xstrdup(path);
	d->attrs = *attrs;
	d->is_local = 0;
}

/* Queue a local directory's final mode and times, to be applied after
 * the whole transfer finishes. They cannot be applied when the directory
 * is created, for two reasons. A read-only mode would stop the files
 * that belong in the directory from being written. And writing each of
 * those files updates the directory's modification time, overwriting
 * any time set earlier. Because bundles can deliver a directory's files
 * after the walk has moved past it, the end of the transfer is the first
 * point at which every directory is known to be complete.
 *
 * The mode is stored only when it differs from the mode the directory
 * was created with. (mode_t)-1 means no chmod is needed. */
void
sftp_hpn_dirattrs_defer_local(struct sftp_hpn_dirattr_list *dl,
    const char *path, mode_t mode, mode_t tmpmode, const Attrib *dirattrib)
{
	struct sftp_hpn_dirattr *d = dirattrs_grow(dl);

	d->path = xstrdup(path);
	d->is_local = 1;
	d->mode = (mode_t)-1;
	if (mode != tmpmode)
		d->mode = mode;
	if (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		d->set_times = 1;
		d->atime = dirattrib->atime;
		d->mtime = dirattrib->mtime;
	}
}

/* Depth of a path, counted in separators, for ordering the deferred attrs. */
static int
dirattr_path_depth(const char *path)
{
	int depth = 0;

	for (; *path != '\0'; path++)
		if (*path == '/')
			depth++;
	return depth;
}

/* Deeper paths first; original position breaks ties so the order is
 * deterministic for a given list. */
static int
dirattr_deepest_first(const void *va, const void *vb)
{
	const struct dirattr_order *a = va;
	const struct dirattr_order *b = vb;

	if (a->depth != b->depth)
		return b->depth - a->depth;
	return a->idx - b->idx;
}

/* Apply every deferred directory attribute, deepest path first. It serves both
 * directions: uploads defer remote setstats and downloads defer local mode and
 * time changes. The order matters. Directories were created with the owner
 * write and execute bits forced on, and these attrs put the real mode back. If
 * a parent went first, its real mode could remove the execute bit its children
 * still need, and every chmod and utimes below it would then fail with EACCES,
 * leaving the children with the widened mode. The list cannot supply the order
 * itself: the upload walk defers children first, but the download and
 * crossload walks, and the tree walk, defer parents first. Remote
 * setstats go through sftp_setstat_pipeline, one window of outstanding requests
 * rather than a round trip per directory, and it keeps the order given. Local
 * attrs are plain syscalls, applied inline. */
void
sftp_hpn_dirattrs_apply(struct sftp_conn *conn,
    struct sftp_hpn_dirattr_list *dl)
{
	struct dirattr_order *order;
	char **paths;
	Attrib *attrs;
	int i, nremote = 0;

	/* Nothing deferred, for example a download without -p whose
	 * directories needed no widening. xcalloc(0) would fatal. */
	if (dl->nentries == 0)
		return;

	paths = xcalloc(dl->nentries, sizeof(*paths));
	attrs = xcalloc(dl->nentries, sizeof(*attrs));
	order = xcalloc(dl->nentries, sizeof(*order));

	/* Sort the index of path entries in deepest first order */
	for (i = 0; i < dl->nentries; i++) {
		order[i].idx = i;
		order[i].depth = dirattr_path_depth(dl->entries[i].path);
	}
	qsort(order, (size_t)dl->nentries, sizeof(*order),
	    dirattr_deepest_first);

	/* Step through the sorted list */
	for (i = 0; i < dl->nentries; i++) {
		struct sftp_hpn_dirattr *d = &dl->entries[order[i].idx];

		/* Don't apply remote entries. Collect it for the
		 * pipelined batch after the loop. */
		if (!d->is_local) {
			/* borrowed; the list outlives this call */
			paths[nremote] = d->path;
			attrs[nremote] = d->attrs;
			nremote++;
			continue;
		}
		/* Set time */
		if (d->set_times) {
			struct timeval tv[2];

			tv[0].tv_sec = d->atime;
			tv[1].tv_sec = d->mtime;
			tv[0].tv_usec = tv[1].tv_usec = 0;
			if (utimes(d->path, tv) == -1)
				error("local set times on \"%s\": %s",
				    d->path, strerror(errno));
		}
		/* Set mode */
		if (d->mode != (mode_t)-1 &&
		    chmod(d->path, d->mode) == -1)
			error("local chmod directory \"%s\": %s",
			    d->path, strerror(errno));
	}

	/* Send the collected remote setstats (see above) as one batch
	   rather than one round trip per directory. Downloads collect none. */
	if (nremote > 0)
		(void)sftp_setstat_pipeline(conn, paths, attrs, nremote);

	free(paths);
	free(attrs);
	free(order);
}

void
sftp_hpn_dirattrs_free(struct sftp_hpn_dirattr_list *dl)
{
	int i;

	for (i = 0; i < dl->nentries; i++)
		free(dl->entries[i].path);
	free(dl->entries);
	dl->entries = NULL;
	dl->nentries = dl->entries_alloc = 0;
}

/* --------------------------------------------------------------------------
 * Recursive walk drivers shared by the serial walks in sftp-client.c
 * and the parallel walk in sftp-parallel-walk.c. Each supplies its
 * own sink. The download driver walks a remote subtree in batches through
 * sftp_tree_walk_open, _read and _close and replays the records through the
 * sink, with a readdir walk as the fallback when the server lacks the
 * extension. The upload driver walks the local tree.
 * -------------------------------------------------------------------------- */

/* Send hpn-dtree-open for root and keep the handle in *walk. A STATUS
 * reply, which is how the server reports a missing, unreadable or
 * non-directory root, is logged by get_handle with the server's reason. */
int
sftp_tree_walk_open(struct sftp_conn *conn, const char *root, uint32_t flags,
    struct sftp_tree_walk *walk)
{
	struct sshbuf	*msg;
	u_int		 id;
	int		 r;

	memset(walk, 0, sizeof(*walk));
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending hpn-dtree-open \"%s\" flags=0x%x id=%u", root, flags,
	    id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_DTREE_OPEN)) != 0 ||
	    (r = sshbuf_put_cstring(msg, root)) != 0 ||
	    (r = sshbuf_put_u32(msg, flags)) != 0)
		fatal_fr(r, "compose hpn-dtree-open request");
	r = send_msg(conn, msg);
	sshbuf_free(msg);
	if (r != 0) {
		logit_f("hpn-dtree-open \"%s\": transport send failed", root);
		return -1;
	}
	walk->handle = get_handle(conn, id, &walk->handle_len,
	    "remote tree open \"%s\"", root);
	if (walk->handle == NULL)
		return -1;
	return 0;
}

/* Send one hpn-dtree-read and hand each record of the reply to cb. The
 * reply is a run of DATA messages ended by BATCH_END, or by END when the
 * walk is complete, and every message is read before returning, so the
 * connection is ours until then. See reply_stream_active.
 *
 * A message we cannot decode leaves the batch desynced, and the server
 * keeps sending the rest of it regardless. Leaving the connection alive
 * would let those messages surface as an id mismatch on the next command,
 * which would then fail carrying the wrong path. Every bail-out below dies
 * for the same reason, and latches a protocol violation where the peer is
 * at fault. */
int
sftp_tree_walk_read(struct sftp_conn *conn, struct sftp_tree_walk *walk,
    uint32_t max_records, sftp_tree_record_cb cb, void *ctx, int *done)
{
	struct sshbuf	*msg;
	u_int		 id, rid;
	u_char		 type, version, kind;
	uint32_t	 count, i;
	uint64_t	 nrecords = 0;
	int		 r, rc = -1, finished = 0, skip = 0;

	*done = 0;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	id = sftp_conn_alloc_msg_id(conn);
	debug3_f("sending hpn-dtree-read max=%u id=%u", max_records, id);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, HPN_EXT_DTREE_READ)) != 0 ||
	    (r = sshbuf_put_string(msg, walk->handle, walk->handle_len)) != 0 ||
	    (r = sshbuf_put_u32(msg, max_records)) != 0)
		fatal_fr(r, "compose hpn-dtree-read request");
	if (send_msg(conn, msg) != 0) {
		logit_f("hpn-dtree-read: transport send failed");
		goto out;
	}
	sftp_conn_hpn(conn)->reply_stream_active = 1;

	while (!finished) {
		sshbuf_reset(msg);
		if (get_msg(conn, msg) != 0) {
			logit_f("hpn-dtree-read: transport receive failed");
			goto out;
		}
		if ((r = sshbuf_get_u8(msg, &type)) != 0 ||
		    (r = sshbuf_get_u32(msg, &rid)) != 0) {
			sftp_conn_die(conn, "hpn-dtree-read: parse reply "
			    "header: %s", ssh_err(r));
			goto out;
		}
		if (rid != id) {
			sftp_conn_die(conn, "hpn-dtree-read reply id mismatch "
			    "(got %u expected %u)", rid, id);
			sftp_conn_set_protocol_violation(conn);
			goto out;
		}
		/* The server refused the request, a bad handle, before sending
		 * anything, so the exchange is over and the connection is
		 * still in sync. */
		if (type == SSH2_FXP_STATUS) {
			u_int fx_status = SSH2_FX_FAILURE;

			(void)sshbuf_get_u32(msg, &fx_status);
			logit_f("hpn-dtree-read: server STATUS %s",
			    fx2txt(fx_status));
			goto out;
		}
		if (type != SSH2_FXP_EXTENDED_REPLY) {
			sftp_conn_die(conn, "hpn-dtree-read: expected "
			    "EXTENDED_REPLY(%u), got %u",
			    SSH2_FXP_EXTENDED_REPLY, type);
			sftp_conn_set_protocol_violation(conn);
			goto out;
		}
		if ((r = sshbuf_get_u8(msg, &version)) != 0 ||
		    (r = sshbuf_get_u8(msg, &kind)) != 0 ||
		    (r = sshbuf_get_u32(msg, &count)) != 0) {
			sftp_conn_die(conn, "hpn-dtree-read: parse message "
			    "header: %s", ssh_err(r));
			goto out;
		}
		if (version != HPN_DTREE_VERSION) {
			sftp_conn_die(conn, "hpn-dtree-read: unsupported codec "
			    "version %u", version);
			goto out;
		}
		/* A DATA message always carries records and a marker never
		 * does. Refusing an empty DATA message keeps a peer from
		 * parking us in this loop with messages that never reach the
		 * callback, and bounds a request to max_records messages. */
		switch (kind) {
		case HPN_DTREE_CHUNK_DATA:
			if (count == 0) {
				sftp_conn_die(conn, "hpn-dtree-read: DATA "
				    "message carries no records");
				sftp_conn_set_protocol_violation(conn);
				goto out;
			}
			break;
		case HPN_DTREE_CHUNK_BATCH_END:
		case HPN_DTREE_CHUNK_END:
			if (count != 0) {
				sftp_conn_die(conn, "hpn-dtree-read: end marker "
				    "carries %u records", count);
				sftp_conn_set_protocol_violation(conn);
				goto out;
			}
			finished = 1;
			break;
		default:
			sftp_conn_die(conn, "hpn-dtree-read: unknown message "
			    "kind %u", kind);
			sftp_conn_set_protocol_violation(conn);
			goto out;
		}
		/* More records than were asked for is the peer's fault. */
		nrecords += count;
		if (nrecords > max_records) {
			sftp_conn_die(conn, "hpn-dtree-read: %llu records for a "
			    "request of %u", (unsigned long long)nrecords,
			    max_records);
			sftp_conn_set_protocol_violation(conn);
			goto out;
		}
		/* Once the callback (cb) has bowed out, usually an interrupt,
		 * stop decoding: nothing would be done with the records. Keep
		 * reading to the marker so the exchange finishes in sync and
		 * the connection stays usable, but discard each message
		 * whole rather than parsing records that are being thrown
		 * away. */
		for (i = 0; !skip && i < count; i++) {
			struct sftp_tree_ent ent;

			memset(&ent, 0, sizeof(ent));
			if ((r = sftp_tree_get_record(msg, &ent.relpath,
			    &ent.rectype, &ent.a, &ent.status)) != 0) {
				free(ent.relpath);
				sftp_conn_die(conn, "hpn-dtree-read: parse "
				    "record: %s", ssh_err(r));
				goto out;
			}
			skip = cb(ctx, &ent) != 0;
			free(ent.relpath);
		}
		if (kind == HPN_DTREE_CHUNK_END)
			*done = 1;
	}
	rc = 0;
 out:
	/* Clear on every exit, including the error gotos: an abandoned batch
	 * leaves the connection unusable anyway, but a stuck flag would turn
	 * that into a confusing fatal on the next unrelated request. */
	sftp_conn_hpn(conn)->reply_stream_active = 0;
	sshbuf_free(msg);
	return rc;
}

/* Close the walk's handle and free it. A dead connection gets no CLOSE,
 * since nothing can be sent on it. */
int
sftp_tree_walk_close(struct sftp_conn *conn, struct sftp_tree_walk *walk)
{
	int rc = 0;

	if (walk->handle == NULL)
		return 0;
	if (!sftp_conn_is_dead(conn))
		rc = sftp_close(conn, walk->handle, (u_int)walk->handle_len);
	free(walk->handle);
	walk->handle = NULL;
	walk->handle_len = 0;
	return rc;
}

/* Add a peer-reported file size to *total for the meter. A size past off_t,
 * or a sum that would pass it, would wrap the signed total negative and the
 * meter would render nonsense. In that case return -1 and leave *total
 * alone, so the caller can report an unknown total and let the meter run
 * rate-only. An entry without a size adds nothing. */
static int
tree_total_add(off_t *total, const Attrib *attrs)
{
	uint64_t size = attrs->size;

	if ((attrs->flags & SSH2_FILEXFER_ATTR_SIZE) == 0)
		return 0;
	if (size > (uint64_t)INT64_MAX ||
	    (uint64_t)*total > (uint64_t)INT64_MAX - size)
		return -1;
	*total += (off_t)size;
	return 0;
}

/* Per-record callback (see sftp_tree_record_cb). Directories are created
 * inline: the wire contract emits a parent before its children, so a dir's
 * parent already exists on disk when its record arrives. Regular files go
 * one of two ways. A streaming sink (the parallel fleet) takes each file as
 * it arrives, so transfer overlaps discovery. Otherwise the file is queued
 * and transferred once the batch ends, because a transfer issued while the
 * dtree-read reply is still arriving would collide with it on the control
 * connection. On abort the callback returns nonzero so the read stops
 * decoding. */
static int
tree_dl_consume_record(void *vctx, struct sftp_tree_ent *ent)
{
	struct tree_dl_ctx	*ctx = vctx;
	Attrib			*attrs = &ent->a;
	char			*new_src, *new_dst;

	/* On abort, tell the read to stop decoding. It still reads the batch
	 * to its marker and discards it, so the connection stays in sync.
	 * Say so once, since the user sees a pause before the prompt. */
	if (ctx->sink->aborting(ctx->sink)) {
		if (!ctx->abort_noticed && ctx->sink->notice != NULL)
			ctx->sink->notice(ctx->sink,
			    "Interrupt: draining file list. Please wait.");
		ctx->abort_noticed = 1;
		return -1;
	}
	/* A failure of the walk root itself arrives with an empty relpath,
	 * since there is no component below the root to name. Handle it
	 * before the validator. The validator rightly rejects "" for every
	 * record that builds a path from it, but here that would report a
	 * suspect path and hide the real cause, an unreadable root. */
	if (ent->rectype == HPN_DTREE_REC_ERROR &&
	    (ent->relpath == NULL || *ent->relpath == '\0')) {
		error("remote \"%s\": %s", ctx->src, fx2txt(ent->status));
		ctx->sink->fail(ctx->sink, ctx->src, "remote error");
		ctx->ret = -1;
		return 0;
	}
	if (!sftp_tree_relpath_ok(ent->relpath)) {
		error("tree walk: suspect path \"%s\" under \"%s\"",
		    ent->relpath == NULL ? "(null)" : ent->relpath, ctx->src);
		ctx->sink->fail(ctx->sink, ctx->src, "suspect path");
		ctx->ret = -1;
		return 0;
	}
	new_src = sftp_path_append(ctx->src, ent->relpath);
	new_dst = sftp_path_append(ctx->dst, ent->relpath);

	switch (ent->rectype) {
	case HPN_DTREE_REC_DIR:
		if (ctx->sink->make_dir(ctx->sink, new_src, new_dst, attrs) != 0)
			ctx->ret = -1;
		free(new_src);
		free(new_dst);
		break;
	case HPN_DTREE_REC_REG:
		/* Tally the meter totals only for a sink that takes them. */
		if (ctx->sink->set_total != NULL) {
			if (!ctx->total_overflow &&
			    tree_total_add(&ctx->total_bytes, attrs) != 0) {
				debug_f("tree walk \"%s\": file sizes "
				    "exceed off_t; meter falls back to "
				    "rate-only", ctx->src);
				ctx->total_overflow = 1;
				ctx->total_bytes = 0;
			}
			ctx->total_files++;
		}
		if (ctx->sink->streams_files) {
			/* Hand it over now instead of queueing it, so transfer
			 * overlaps discovery. files[] stays empty and the
			 * fleet holds only its bounded window of pending work
			 * (sftp_parallel_await_capacity). This is legal only
			 * because this sink just enqueues work for the fleet.
			 * reply_stream_active catches it at once if that ever
			 * stops being true. */
			if (ctx->sink->xfer_file(ctx->sink, new_src, new_dst,
			    attrs) != 0)
				ctx->ret = -1;
			free(new_src);
			free(new_dst);
			break;
		}
		if (ctx->nfiles == ctx->files_alloc) {
			if (ctx->files_alloc == 0)
				ctx->files_alloc = 256;
			else
				ctx->files_alloc *= 2;
			ctx->files = xreallocarray(ctx->files,
			    ctx->files_alloc, sizeof(*ctx->files));
		}
		ctx->files[ctx->nfiles].src = new_src;
		ctx->files[ctx->nfiles].dst = new_dst;
		ctx->files[ctx->nfiles].attrs = *attrs;
		ctx->nfiles++;
		/* new_src and new_dst are now owned by the queue. */
		break;
	case HPN_DTREE_REC_ERROR:
		error("remote \"%s\": %s", new_src, fx2txt(ent->status));
		ctx->sink->fail(ctx->sink, new_src, "remote error");
		ctx->ret = -1;
		free(new_src);
		free(new_dst);
		break;
	default:
		/* symlink (skipped, OpenSSH parity) or non-regular */
		logit("download \"%s\": not a regular file", new_src);
		free(new_src);
		free(new_dst);
		break;
	}
	return 0;
}

/* Resolve the attrs of a remote download root and check that it is a
 * directory. Shared by the tree and readdir consumers. dirattrib is the
 * caller's attrs, or NULL to stat src into *statbuf. Returns the attrs to
 * use, or NULL after reporting the failure to the sink. */
static Attrib *
dl_root_attrs(struct sftp_conn *conn, const char *src, Attrib *dirattrib,
    Attrib *statbuf, struct sftp_tree_dl_sink *sink)
{
	/* The caller may not have the root's attrs (top-level calls never
	 * do), so stat it here. Fail only if that stat fails. */
	if (dirattrib == NULL) {
		if (sftp_stat(conn, src, 1, statbuf) != 0) {
			error("stat remote \"%s\" directory failed", src);
			sink->fail(sink, src, "remote stat failed");
			return NULL;
		}
		dirattrib = statbuf;
	}
	/* it's not actually a directory so this doesn't apply */
	if (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		sink->fail(sink, src, "not a directory");
		return NULL;
	}
	return dirattrib;
}

/* Free the paths of the files queued so far and empty the queue. The
 * array itself is kept for the next chunk. */
static void
tree_dl_files_clear(struct tree_dl_ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->nfiles; i++) {
		free(ctx->files[i].src);
		free(ctx->files[i].dst);
	}
	ctx->nfiles = 0;
}

/* Records to ask for per hpn-dtree-read. */
static uint32_t
tree_chunk_records(void)
{
	const char	*env;
	const char	*errstr;
	long long	 records;

	/* ENV-VAR HPN_DTREE_CHUNK: test-only override of the records requested
	 * per hpn-dtree-read, so regress can cross chunk boundaries with a
	 * small tree. Remove this block to remove the variable. */
	if ((env = getenv("HPN_DTREE_CHUNK")) != NULL) {
		records = strtonum(env, 1, HPN_DTREE_MAX_BATCH, &errstr);
		if (errstr == NULL)
			return (uint32_t)records;
		debug_f("HPN_DTREE_CHUNK \"%s\" is %s, using the default", env,
		    errstr);
	}
	return HPN_DTREE_MAX_BATCH;
}

/* Shared download driver: walk src through the chunked tree walk and
 * replay each record through the sink. Serial, parallel and crossload each
 * supply their own sink, and the classification, path building and
 * iteration live here once. Each chunk is read in full, then its queued
 * files are transferred, then the next chunk is requested, so memory holds
 * one chunk of the tree and data starts moving after the first. A
 * streaming sink takes each file during the read instead, so its queue is
 * always empty when the transfer loop runs. See sftp-hpn-client.h. */
int
sftp_tree_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, Attrib *dirattrib, int follow_link_flag,
    struct sftp_tree_dl_sink *sink)
{
	struct tree_dl_ctx	ctx;
	struct sftp_tree_walk	walk;
	Attrib			ldirattrib;
	uint32_t		flags = 0, chunk;
	size_t			i;
	int			done = 0;

	/* Check that the root is a directory before starting a walk. */
	dirattrib = dl_root_attrs(conn, src, dirattrib, &ldirattrib, sink);
	if (dirattrib == NULL)
		return -1;
	/* Create the local root. The sink defers its attrs, and the serial
	 * and crossload sinks print the "Retrieving" line. */
	if (sink->make_dir(sink, src, dst, dirattrib) != 0)
		return -1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.src = src;
	ctx.dst = dst;
	ctx.sink = sink;

	if (follow_link_flag)
		flags = HPN_DTREE_FOLLOW_SYMLINKS;
	if (sftp_tree_walk_open(conn, src, flags, &walk) != 0) {
		sink->fail(sink, src, "remote tree open failed");
		return -1;
	}
	chunk = tree_chunk_records();

	/* One chunk per pass. Each record goes to tree_dl_consume_record,
	 * which creates directories inline and queues regular files, and the
	 * queue is transferred and emptied before the next read. Symlinks
	 * are followed only when the caller asks. */
	do {
		/* The transfer pauses while a batch is fetched. Tell the user
		 * why, on every batch including the first. */
		if (sink->notice != NULL)
			sink->notice(sink, "Retrieving file list from server.");
		if (sftp_tree_walk_read(conn, &walk, chunk,
		    tree_dl_consume_record, &ctx, &done) != 0) {
			error("remote tree walk \"%s\" failed", src);
			sink->fail(sink, src, "remote tree walk failed");
			ctx.ret = -1;
			break;
		}
		for (i = 0; i < ctx.nfiles && !sink->aborting(sink); i++) {
			if (sink->xfer_file(sink, ctx.files[i].src,
			    ctx.files[i].dst, &ctx.files[i].attrs) != 0)
				ctx.ret = -1;
		}
		tree_dl_files_clear(&ctx);
	} while (!done && !sink->aborting(sink));

	/* The totals are complete only once the walk reached END. A sink
	 * with an aggregate meter takes them then. */
	if (done && sink->set_total != NULL)
		sink->set_total(sink, ctx.total_bytes, ctx.total_files);

	sftp_tree_walk_close(conn, &walk);
	tree_dl_files_clear(&ctx);
	free(ctx.files);
	return ctx.ret;
}

/* Fallback recursive readdir download driver, used when the server lacks
 * the tree walk. Enumerate src a directory at a time, recursing into
 * subdirectories, and replay each entry through the same sink the tree
 * consumer uses. Files go to the sink as they are listed, so memory is one
 * listing per level of recursion. Directory attrs are deferred in pre-order
 * here. sftp_hpn_dirattrs_apply sorts them deepest first at the end of the
 * walk, so the recording order does not matter. See sftp-hpn-client.h. */
int
sftp_readdir_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, Attrib *dirattrib,
    int follow_link_flag, struct sftp_tree_dl_sink *sink)
{
	SFTP_DIRENT	**entries;
	char		 *new_src = NULL, *new_dst = NULL;
	Attrib		  ldirattrib, lsym;
	int		  ret = 0, i;

	/* Bounds recursion, including symlink loops when following links. */
	if (depth >= max_depth) {
		error("Maximum directory depth exceeded: %d levels", depth);
		sink->fail(sink, src, "max directory depth exceeded");
		return -1;
	}

	/* check to see if we should use this download_consume() */
	dirattrib = dl_root_attrs(conn, src, dirattrib, &ldirattrib, sink);
	if (dirattrib == NULL)
		return -1;
	/* Create dst. The sink's make_dir also prints progress, matches the
	 * Lustre layout where supported and defers the attrs. */
	if (sink->make_dir(sink, src, dst, dirattrib) != 0)
		return -1;
	/* Lists the whole directory before any entry is handled. */
	if (sftp_readdir(conn, src, &entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		sink->fail(sink, src, "remote readdir failed");
		return -1;
	}

	for (i = 0; entries[i] != NULL && !sink->aborting(sink); i++) {
		const char	*filename;
		Attrib		*attrs;

		/* Free the previous entry's paths here so continue needs no
		 * cleanup. */
		free(new_dst);
		free(new_src);
		filename = entries[i]->filename;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);
		attrs = &entries[i]->a;

		if (S_ISLNK(attrs->perm)) {
			if (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				continue;
			}
			/* scp follows symlinks (sftp does not). Resolve
			 * the target and treat the entry as whatever it
			 * points to. */
			if (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				error("remote stat \"%s\" failed", new_src);
				sink->fail(sink, new_src, "remote stat failed");
				ret = -1;
				continue;
			}
			attrs = &lsym;
		}
		if (S_ISDIR(attrs->perm)) {
			/* readdir lists the directory itself and its parent. */
			if (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			if (sftp_readdir_download_consume(conn, new_src,
			    new_dst, depth + 1, max_depth, attrs,
			    follow_link_flag, sink) != 0)
				ret = -1;
		} else if (S_ISREG(attrs->perm)) {
			if (sink->xfer_file(sink, new_src, new_dst, attrs) != 0)
				ret = -1;
		} else {
			logit("download \"%s\": not a regular file", new_src);
		}
	}
	free(new_dst);
	free(new_src);
	sftp_free_dirents(entries);
	return ret;
}

/* Shared upload driver for serial and parallel. Enumerate the local
 * directory src, hand each regular file to the sink and collect the
 * subdirectories. Create those in one sftp_mkdir_pipeline call on the
 * control connection, which drains fully, so each directory exists before
 * its files are written. Then recurse into each, passing whether this walk
 * created it. dst itself was created by the caller. See sftp-hpn-client.h. */
int
sftp_upload_walk_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, int created, int preserve_flag,
    int follow_link_flag, struct sftp_upload_sink *sink)
{
	DIR				*dirp;
	struct dirent			*dp;
	char				*new_src = NULL, *new_dst = NULL;
	struct stat			 sb;
	Attrib				 dir_attrs;
	struct walk_entry		*subdirs = NULL;
	int				 nsubdirs = 0, subdirs_alloc = 0;
	int				 i, ret = 0;

	/* Bounds recursion, including symlink loops when following links. */
	if (depth >= max_depth) {
		error("Maximum directory depth exceeded: %d levels", depth);
		sink->fail(sink, src, "max directory depth exceeded");
		return -1;
	}
	/* stat, not lstat, so a symlinked root is followed like stock. */
	if (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		sink->fail(sink, src, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		sink->fail(sink, src, "not a directory");
		return -1;
	}

	/* This directory's source-derived attrs; dst was created by the caller
	 * (the root by the entry point, deeper dirs by the parent's batch). */
	sftp_hpn_dir_attrs_from_stat(&sb, preserve_flag, &dir_attrs);

	/* Serial prints progress. Parallel marks the enumeration phase. */
	sink->enter_dir(sink, src, dst);

	if ((dirp = opendir(src)) == NULL) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		sink->fail(sink, src, strerror(errno));
		return -1;
	}
	while (((dp = readdir(dirp)) != NULL) && !sink->aborting(sink)) {
		const char *filename = dp->d_name;

		free(new_dst);
		free(new_src);
		new_dst = new_src = NULL;
		/* Skip empty directory slots (inode 0), as stock does. */
		if (dp->d_ino == 0)
			continue;
		if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			continue;
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		/* lstat first so symlinks can be told apart. */
		if (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", new_src, strerror(errno));
			sink->fail(sink, new_src, strerror(errno));
			ret = -1;
			continue;
		}
		if (S_ISLNK(sb.st_mode)) {
			if (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			/* scp follows symlinks (sftp does not). */
			if (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", new_src,
				    strerror(errno));
				sink->fail(sink, new_src, strerror(errno));
				ret = -1;
				continue;
			}
		}
		/* Hold subdirectories until the listing is done, so they can
		 * be created in one batch. */
		if (S_ISDIR(sb.st_mode)) {
			if (nsubdirs == subdirs_alloc) {
				if (subdirs_alloc == 0)
					subdirs_alloc = 64;
				else
					subdirs_alloc *= 2;
				subdirs = xreallocarray(subdirs, subdirs_alloc,
				    sizeof(*subdirs));
			}
			subdirs[nsubdirs].src = new_src;
			subdirs[nsubdirs].dst = new_dst;
			sftp_hpn_dir_attrs_from_stat(&sb, preserve_flag,
			    &subdirs[nsubdirs].attrs);
			nsubdirs++;
			new_src = new_dst = NULL;	/* owned by subdirs[] */
		} else if (S_ISREG(sb.st_mode)) {
			if (sink->xfer_file(sink, new_src, new_dst, &sb) != 0)
				ret = -1;
		} else {
			logit("%s: not a regular file", filename);
		}
	}
	free(new_dst);
	free(new_src);
	(void)closedir(dirp);

	/* Batch-create the collected subdirs, then recurse into each. */
	if (!sink->aborting(sink) && nsubdirs > 0) {
		char	**paths = xcalloc(nsubdirs, sizeof(*paths));
		Attrib	 *attrs = xcalloc(nsubdirs, sizeof(*attrs));
		u_char	 *created_flags = xcalloc(nsubdirs,
		    sizeof(*created_flags));
		u_char	 *failed_flags = xcalloc(nsubdirs,
		    sizeof(*failed_flags));

		for (i = 0; i < nsubdirs; i++) {
			paths[i] = subdirs[i].dst;
			attrs[i] = subdirs[i].attrs;
		}
		/* Parallel marks the mkdir phase here. Serial does nothing. */
		sink->before_mkdir(sink);
		/* One call. The pipeline windows the requests itself and
		 * drains fully before returning.
		 *
		 * A directory we could not create is a failed transfer.
		 * Discarding this count reported success for an upload that
		 * did not happen: an empty subdirectory transfers nothing, so
		 * nothing else notices the destination is missing. */
		if (sftp_mkdir_pipeline(conn, paths, attrs, nsubdirs,
		    created_flags, failed_flags) > 0)
			ret = -1;
		free(paths);
		free(attrs);
		for (i = 0; i < nsubdirs && !sink->aborting(sink); i++) {
			/* Do not descend into one that failed. There is
			 * nothing to write into, and deferring its attributes
			 * would setstat whatever does occupy the path. */
			if (failed_flags[i]) {
				sink->fail(sink, subdirs[i].dst,
				    "remote mkdir failed");
				continue;
			}
			if (sftp_upload_walk_consume(conn, subdirs[i].src,
			    subdirs[i].dst, depth + 1, max_depth,
			    (int)created_flags[i], preserve_flag,
			    follow_link_flag, sink) != 0)
				ret = -1;
		}
		free(created_flags);
		free(failed_flags);
	}
	for (i = 0; i < nsubdirs; i++) {
		free(subdirs[i].src);
		free(subdirs[i].dst);
	}
	free(subdirs);

	/* A directory needs its attrs fixed up after its contents land if we
	 * created it (it was made with restrictive bits) or if -p asked for
	 * the source's own. Gate it here so both sinks just record. */
	if (created || preserve_flag)
		sink->defer_dir(sink, dst, &dir_attrs);
	return ret;
}
