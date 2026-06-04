/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */

/*
 * sftp-hpn-congestion.c -- per-worker TCP-health self-monitor for the
 * parallel-streams transfer path.
 *
 * ============================================================
 *  Purpose, and how this relates to the worker watchdog
 * ============================================================
 *
 * The parallel-streams orchestrator already has a time-based worker
 * watchdog (sftp-parallel.c).  That watchdog is OBSERVATIONAL: it
 * watches application-layer outcomes -- bytes moved over time, time
 * since last completion, a worker's throughput EMA versus its peers --
 * and from those it infers whether a worker is HEALTHY, STALLED, or
 * DEAD.  It answers one question:
 *
 *      "Is work happening?"
 *
 * This module reads the kernel's TCP_INFO for the worker's transport
 * socket.  It is CAUSAL and looks one layer down, at the transport
 * itself -- congestion window, retransmits, RTO accumulation, round-trip
 * time, connection state.  It answers a different question:
 *
 *      "Is the network the reason work isn't happening?"
 *
 * The two are COMPLEMENTARY, not redundant.  This module is designed to
 * enrich the watchdog's verdict, never to act as a second independent
 * killer.  Three concrete roles it is meant to play once the decision
 * logic lands on top of this primitive:
 *
 *   1. Faster, surer escalation.  A socket can be retransmitting hard
 *      and cwnd-collapsed while still dribbling just enough bytes that
 *      the watchdog's progress timer never trips.  TCP_INFO sees the
 *      pathology immediately, so the watchdog can escalate without
 *      waiting out the full silence threshold.
 *
 *   2. The no-peer absolute signal.  The watchdog's throughput-outlier
 *      detection is COMPARATIVE -- it needs peers to measure a worker
 *      against.  With a single worker (-j 1), or when peers go idle,
 *      that comparison has no signal, and the intended absolute-floor
 *      fallback keys on a configured "healthy kbps" floor that is not
 *      currently wired up.  TCP_INFO gives a peer-independent verdict:
 *      this socket is objectively wedged, regardless of what anyone
 *      else is doing.  Closing this blind spot is the original
 *      motivation for the module.
 *
 *   3. Veto bad kills.  The watchdog cannot tell "slow because the
 *      network is wedged" from "slow because we are app-limited or
 *      disk-bound."  TCP_INFO can: a healthy cwnd with low retransmits
 *      and an app-limited delivery-rate sample means the network is
 *      fine and a respawn would accomplish nothing.  The monitor can
 *      veto an outlier kill in that case.
 *
 * What this module CANNOT see, and why the watchdog stays essential:
 * non-network stalls.  A hung server-side disk write, a deadlocked
 * worker thread, or an application that simply isn't draining the
 * socket all leave TCP looking perfectly healthy while no useful work
 * happens.  Only the watchdog's bytes-flat signal catches those.  The
 * watchdog is also the SOLE health signal on platforms without
 * TCP_INFO (see tcpi-portable.c): there this module reports
 * UNSUPPORTED and consumers fall back entirely to the watchdog.
 *
 * Mental model to keep while maintaining this code:
 *
 *      watchdog  : "is work happening?"        (necessary, always on)
 *      this file : "is the network at fault?"  (sharper, where available)
 *
 * ============================================================
 *  Layering
 * ============================================================
 *
 *      orchestrator decision logic   (sftp-parallel.c; consumes samples)
 *              |
 *      sftp-hpn-congestion.{c,h}     (this file: probe + poll + classify)
 *              |
 *      tcpi-portable.{c,h}           (portable getsockopt(TCP_INFO) view)
 *              |
 *      kernel TCP_INFO
 *
 * This file is the polling primitive and availability state machine
 * ONLY.  It takes no action and makes no kill/keep/scale decision -- it
 * just produces classified samples for the layer above.  The decision
 * logic is a later change.
 *
 * ============================================================
 *  Availability state machine
 * ============================================================
 *
 *   UNPROBED --init--> { UNSUPPORTED | PENDING | BASIC | EXTENDED }
 *
 *   PENDING  --poll, retries < limit--> PENDING
 *   PENDING  --poll, retries == limit--> UNSUPPORTED      (terminal)
 *   PENDING  --poll, live sample-------> BASIC or EXTENDED
 *   BASIC    --poll, no Tier-2---------> BASIC
 *   BASIC    --poll, Tier-2 present----> EXTENDED
 *   EXTENDED --poll--------------------> EXTENDED          (tier sticky)
 *   UNSUPPORTED --poll-----------------> UNSUPPORTED  (no syscall made)
 *
 * PENDING covers the window where getsockopt succeeds but the socket
 * has not produced usable numbers yet (not fully established, zeroed
 * struct).  We give it a bounded number of probes before concluding the
 * fd will never yield a usable TCP_INFO and settling to UNSUPPORTED.
 */

#include "includes.h"

#include <string.h>

#include "tcpi-portable.h"
#include "sftp-hpn-congestion.h"

/*
 * Number of consecutive probes that may return without a usable sample
 * before we give up on the fd and settle to UNSUPPORTED.  The caller
 * polls at roughly the watchdog tick (~1 s), so this is about a
 * ten-second grace period for the connection to start reporting.
 */
#define HEALTH_PROBE_RETRY_LIMIT	10

/*
 * A connected TCP socket always reports a non-zero send MSS; a
 * freshly-created or closed one reports zeros.  We use that as the
 * "this is a real, established connection" test -- the Tier-1 safe-region
 * fields are only meaningful once it holds.
 */
static int
tcpi_sample_is_live(const struct tcpi_portable *t)
{
	return t->snd_mss > 0;
}

/*
 * Tier-2 fields (min_rtt, delivery_rate, ...) only ever appear on Linux
 * >= 4.x.  Their presence is exactly what distinguishes EXTENDED from
 * BASIC; on the BSDs they are permanently absent, so those platforms
 * top out at BASIC by design.
 */
static int
tcpi_sample_has_tier2(const struct tcpi_portable *t)
{
	return (t->avail_flags &
	    (TCPI_AVAIL_MIN_RTT | TCPI_AVAIL_DELIVERY_RATE)) != 0;
}

/*
 * Take one sample, advance the availability state machine, and fill
 * *out.  Shared by init (eager probe, scratch output) and the public
 * poll entry point.
 */
static void
health_classify(struct sftp_hpn_tcp_health_ctx *ctx,
    struct sftp_hpn_tcp_health *out)
{
	memset(out, 0, sizeof(*out));

	/* Terminal: never issue another syscall once we've given up. */
	if (ctx->avail == TCP_HEALTH_UNSUPPORTED) {
		out->availability = TCP_HEALTH_UNSUPPORTED;
		return;
	}

	if (tcpi_portable_get(ctx->fd, &out->raw) != 0) {
		/*
		 * No usable TCP_INFO on this build is terminal.  A per-call
		 * getsockopt failure on a supported platform is treated as a
		 * still-pending probe until we run out of patience.
		 */
		if (!tcpi_portable_supported() ||
		    ++ctx->pending_retries >= HEALTH_PROBE_RETRY_LIMIT)
			ctx->avail = TCP_HEALTH_UNSUPPORTED;
		else
			ctx->avail = TCP_HEALTH_PENDING;
		out->availability = ctx->avail;
		return;
	}

	/* Already at the top tier: keep sampling, hold EXTENDED. */
	if (ctx->avail == TCP_HEALTH_EXTENDED) {
		out->availability = TCP_HEALTH_EXTENDED;
		return;
	}

	if (!tcpi_sample_is_live(&out->raw)) {
		/* Succeeded, but the connection isn't reporting yet. */
		if (++ctx->pending_retries >= HEALTH_PROBE_RETRY_LIMIT)
			ctx->avail = TCP_HEALTH_UNSUPPORTED;
		else
			ctx->avail = TCP_HEALTH_PENDING;
		out->availability = ctx->avail;
		return;
	}

	/* Live sample: BASIC, promoted to EXTENDED when Tier-2 is present. */
	ctx->pending_retries = 0;
	ctx->avail = tcpi_sample_has_tier2(&out->raw)
	    ? TCP_HEALTH_EXTENDED : TCP_HEALTH_BASIC;
	out->availability = ctx->avail;
}

void
sftp_hpn_tcp_health_ctx_init(struct sftp_hpn_tcp_health_ctx *ctx, int fd)
{
	struct sftp_hpn_tcp_health scratch;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = fd;
	ctx->avail = TCP_HEALTH_UNPROBED;

	/* Compile-time unsupported platforms settle immediately. */
	if (!tcpi_portable_supported()) {
		ctx->avail = TCP_HEALTH_UNSUPPORTED;
		return;
	}

	/* Eager probe: resolves avail to PENDING / BASIC / EXTENDED. */
	health_classify(ctx, &scratch);
}

int
sftp_hpn_tcp_health_poll(struct sftp_hpn_tcp_health_ctx *ctx,
    struct sftp_hpn_tcp_health *out)
{
	health_classify(ctx, out);
	return (ctx->avail == TCP_HEALTH_UNSUPPORTED) ? -1 : 0;
}

/*
 * Wedge classifier.  Thresholds are conservative first-cut values; all
 * named so they are easy to tune.  Signatures and the rationale behind
 * each field are documented in the file banner's watchdog-interplay
 * section.
 *
 * Key principle (confirmed against net/ipv4/{tcp,tcp_rate}.c): we judge a
 * connection by ACTIVE NETWORK DISTRESS, never by absence of throughput.
 * delivery_rate and the app_limited bit are recomputed only per delivered
 * ACK, so during a no-ACK stall they go STALE -- useless for detecting the
 * stall, and they can't tell a wedge from the app simply pausing (e.g. to
 * hash during verification).  The distress signals we use are computed at
 * read time and stay live: total_rto_time includes the in-progress RTO
 * episode, rwnd_limited includes the in-progress chrono interval, and
 * snd_cwnd / notsent_bytes / total_retrans are current-state.
 */
#define WEDGE_SUSTAIN_SECS	10	/* consecutive ~1s samples before acting */
#define WEDGE_CWND_COLLAPSED	4	/* snd_cwnd (segments) at/below = collapsed */
#define WEDGE_MIN_RTT_LAN_US	5000	/* skip paths under 5 ms (LAN) */
#define PEER_STALL_BRAKE_SECS	300	/* peer-stall emergency brake: a stall
					 * sustained this long (5 min) is wedged,
					 * not draining - reap it.  The PEER_STALL
					 * verdict (>= WEDGE_SUSTAIN_SECS, below
					 * this) is waited out instead. */

enum sftp_hpn_wedge_verdict
sftp_hpn_classify(struct sftp_hpn_tcp_health_ctx *ctx,
    const struct sftp_hpn_tcp_health *h)
{
	const struct tcpi_portable *t = &h->raw;
	u_int64_t	d_rto, d_retrans, d_rwnd;
	int		have_data, cwnd_collapsed, have_rto, wedge_now;

	/*
	 * Only EXTENDED carries the signals we act on.  Anything less:
	 * reset trend state and stay silent (the caller still logs the
	 * sample so BASIC data can be evaluated later).
	 */
	if (h->availability != TCP_HEALTH_EXTENDED) {
		ctx->trend_valid = 0;
		ctx->wedge_secs = ctx->peer_stall_secs =
		    ctx->path_degraded_secs = 0;
		ctx->wedge_retrans_seen = 0;
		return SFTP_HPN_WEDGE_NONE;
	}

	/* The delta signals need a previous sample to compare against. */
	if (!ctx->trend_valid) {
		ctx->prev_total_rto_time = t->total_rto_time;
		ctx->prev_total_retrans  = t->total_retrans;
		ctx->prev_rwnd_limited   = t->rwnd_limited;
		ctx->trend_valid = 1;
		return SFTP_HPN_WEDGE_NONE;
	}
	d_rto = (t->total_rto_time >= ctx->prev_total_rto_time) ?
	    (u_int64_t)(t->total_rto_time - ctx->prev_total_rto_time) : 0;
	d_retrans = (t->total_retrans >= ctx->prev_total_retrans) ?
	    (t->total_retrans - ctx->prev_total_retrans) : 0;
	d_rwnd = (t->rwnd_limited >= ctx->prev_rwnd_limited) ?
	    (t->rwnd_limited - ctx->prev_rwnd_limited) : 0;
	ctx->prev_total_rto_time = t->total_rto_time;
	ctx->prev_total_retrans  = t->total_retrans;
	ctx->prev_rwnd_limited   = t->rwnd_limited;

	/* LAN paths: signals are noisy and wedges don't manifest the same. */
	if (t->min_rtt < WEDGE_MIN_RTT_LAN_US) {
		ctx->wedge_secs = ctx->peer_stall_secs =
		    ctx->path_degraded_secs = 0;
		ctx->wedge_retrans_seen = 0;
		return SFTP_HPN_WEDGE_NONE;
	}

	/*
	 * notsent_bytes > 0 = we have data queued the network hasn't taken.
	 * A healthy path drains it fast even if the app pauses, so a value
	 * stuck above zero is itself a network signal -- and it scopes the
	 * client-side classifier to the sending side (uploads), since a
	 * download's notsent is ~0.
	 */
	have_data = (t->notsent_bytes > 0);
	cwnd_collapsed = (t->snd_cwnd <= WEDGE_CWND_COLLAPSED);
	have_rto = (t->avail_flags & TCPI_AVAIL_TOTAL_RTO) != 0;

	/*
	 * PEER_STALL: the peer's receive window is pinning us while the
	 * network (cwnd) is otherwise healthy -- the far end isn't draining.
	 * Checked first: a healthy cwnd distinguishes "peer won't accept"
	 * from "network has collapsed".  Needs the 4.10 rwnd_limited field.
	 */
	if ((t->avail_flags & TCPI_AVAIL_RWND_LIMITED) &&
	    have_data && d_rwnd > 0 && !cwnd_collapsed) {
		ctx->wedge_secs = ctx->path_degraded_secs = 0;
		ctx->wedge_retrans_seen = 0;
		/* peer_stall_secs keeps climbing while the stall persists.
		 * Brake first (sustained past the 5 min horizon = wedged, reap),
		 * otherwise the wait-it-out PEER_STALL verdict once past the
		 * sustain floor. */
		if (++ctx->peer_stall_secs >= PEER_STALL_BRAKE_SECS)
			return SFTP_HPN_WEDGE_PEER_STALL_BRAKE;
		if (ctx->peer_stall_secs >= WEDGE_SUSTAIN_SECS)
			return SFTP_HPN_WEDGE_PEER_STALL;
		return SFTP_HPN_WEDGE_NONE;
	}
	ctx->peer_stall_secs = 0;

	/*
	 * WEDGE.  Primary signal (kernel >= 6.7): RTO time actively
	 * accruing -- the connection is sitting in timeout recovery.
	 * Fallback (EXTENDED but < 6.7, no RTO accounting): a sustained
	 * collapsed cwnd, corroborated by retransmits seen during the
	 * window so a legitimately slow / small-cwnd link (small cwnd but
	 * no loss) is not mistaken for a wedge.
	 */
	wedge_now = have_rto ? (have_data && d_rto > 0)
			     : (have_data && cwnd_collapsed);
	if (wedge_now) {
		ctx->path_degraded_secs = 0;
		if (d_retrans > 0)
			ctx->wedge_retrans_seen = 1;
		if (ctx->wedge_secs < WEDGE_SUSTAIN_SECS)
			ctx->wedge_secs++;
		if (ctx->wedge_secs >= WEDGE_SUSTAIN_SECS &&
		    (have_rto || ctx->wedge_retrans_seen))
			return SFTP_HPN_WEDGE_TCP_WEDGE;
		return SFTP_HPN_WEDGE_NONE;
	}
	ctx->wedge_secs = 0;
	ctx->wedge_retrans_seen = 0;

	/*
	 * PATH_DEGRADED (monitor only): still moving, but losing packets
	 * steadily.  Reported once per episode; never triggers a kill yet.
	 */
	if (have_data && d_retrans > 0) {
		if (++ctx->path_degraded_secs == WEDGE_SUSTAIN_SECS)
			return SFTP_HPN_WEDGE_PATH_DEGRADED;
		return SFTP_HPN_WEDGE_NONE;
	}
	ctx->path_degraded_secs = 0;

	return SFTP_HPN_WEDGE_NONE;
}
