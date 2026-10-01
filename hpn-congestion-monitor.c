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

/* hpn-congestion-monitor.c - how the TCP health monitor samples and judges
 * a connection. What it is for, and how it relates to the watchdog, is in
 * hpn-congestion-monitor.h.
 *
 * Layering:
 *
 *      clientloop.c / serverloop.c   (poll on a timer, act on the verdict)
 *              |
 *      hpn-congestion-monitor.{c,h}  (this file: probe, poll, classify)
 *              |
 *      tcpi-portable.{c,h}           (portable getsockopt(TCP_INFO) view)
 *              |
 *      kernel TCP_INFO
 *
 * The callers poll from a timer rather than on traffic, so a wedged
 * connection with nothing moving is still sampled.
 *
 * Availability state machine:
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
 * PENDING covers the window where getsockopt succeeds but the socket has
 * not produced usable numbers yet (not fully established, zeroed struct).
 * It gets a bounded number of probes before the monitor concludes the fd
 * will never yield a usable TCP_INFO and settles to UNSUPPORTED.
 *
 * The classifier judges only EXTENDED samples, by active network distress
 * rather than by missing throughput. The reasoning is at
 * hpn_cong_classify(). */

#include "includes.h"

#include <string.h>

#include "tcpi-portable.h"
#include "hpn-congestion-monitor.h"

/* Number of consecutive probes that may return without a usable sample
 * before the monitor gives up on the fd and settles to UNSUPPORTED. The
 * callers poll about once a second, so this is roughly a ten-second grace
 * period for the connection to start reporting. */
#define HEALTH_PROBE_RETRY_LIMIT	10

/* Wedge classifier thresholds, conservative and named for tuning. */
#define WEDGE_SUSTAIN_SECS	10	/* consecutive ~1s samples before acting */
#define WEDGE_CWND_COLLAPSED	4	/* cwnd collapsed at or below, in segments */
#define WEDGE_MIN_RTT_LAN_US	5000	/* skip paths under 5 ms (LAN) */
/* Peer-stall emergency brake: a stall sustained this long (5 min) is
 * wedged, not draining, so it is reaped. A shorter one, at least
 * WEDGE_SUSTAIN_SECS, gets the PEER_STALL verdict and is waited out. */
#define PEER_STALL_BRAKE_SECS	300

/* A connected TCP socket always reports a non-zero send MSS, and a new or
 * closed one reports zeros. That is the test for a real, established
 * connection. The Tier-1 fields mean nothing until it holds. */
static int
tcpi_sample_is_live(const struct tcpi_portable *tcpi)
{
	return tcpi->snd_mss > 0;
}

/* The Tier-2 fields (min_rtt, delivery_rate, and others) only appear on
 * Linux 4.x and later. Their presence is what separates EXTENDED from
 * BASIC. The BSDs never have them, so those platforms top out at BASIC. */
static int
tcpi_sample_has_tier2(const struct tcpi_portable *tcpi)
{
	return (tcpi->avail_flags &
	    (TCPI_AVAIL_MIN_RTT | TCPI_AVAIL_DELIVERY_RATE)) != 0;
}

/* Take one sample, advance the availability state machine, and fill *out.
 * Used by init for its first probe and by the public poll. */
static void
cong_sample(struct hpn_cong_ctx *ctx, struct hpn_cong_sample *out)
{
	memset(out, 0, sizeof(*out));

	/* Terminal: never issue another syscall once we've given up. */
	if (ctx->avail == HPN_CONG_UNSUPPORTED) {
		out->availability = HPN_CONG_UNSUPPORTED;
		return;
	}

	/* No sample, or not live yet before EXTENDED was reached: still
	 * pending, until the probes run out. A sample at EXTENDED holds the
	 * tier. */
	if (tcpi_portable_get(ctx->fd, &out->raw) != 0 ||
	    (ctx->avail != HPN_CONG_EXTENDED &&
	    !tcpi_sample_is_live(&out->raw))) {
		if (++ctx->pending_retries >= HEALTH_PROBE_RETRY_LIMIT)
			ctx->avail = HPN_CONG_UNSUPPORTED;
		else
			ctx->avail = HPN_CONG_PENDING;
		out->availability = ctx->avail;
		return;
	}
	if (ctx->avail == HPN_CONG_EXTENDED) {
		out->availability = HPN_CONG_EXTENDED;
		return;
	}

	/* Live sample: BASIC, promoted to EXTENDED when Tier-2 is present. */
	ctx->pending_retries = 0;
	ctx->avail = HPN_CONG_BASIC;
	if (tcpi_sample_has_tier2(&out->raw))
		ctx->avail = HPN_CONG_EXTENDED;
	out->availability = ctx->avail;
}

/* Set up the monitor for fd and probe it once, so the caller learns right
 * away whether this platform and socket can be monitored at all. */
void
hpn_cong_init(struct hpn_cong_ctx *ctx, int fd)
{
	struct hpn_cong_sample scratch;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = fd;
	ctx->avail = HPN_CONG_UNPROBED;

	/* Compile-time unsupported platforms settle immediately. */
	if (!tcpi_portable_supported()) {
		ctx->avail = HPN_CONG_UNSUPPORTED;
		return;
	}

	/* Eager probe: resolves avail to PENDING / BASIC / EXTENDED. */
	cong_sample(ctx, &scratch);
}

/* Take one sample. Returns -1 once the monitor has settled to UNSUPPORTED,
 * so the caller can stop polling, and 0 otherwise. */
int
hpn_cong_poll(struct hpn_cong_ctx *ctx,
    struct hpn_cong_sample *out)
{
	cong_sample(ctx, out);
	if (ctx->avail == HPN_CONG_UNSUPPORTED)
		return -1;
	return 0;
}

/* Forget how long each signature has held. */
static void
cong_reset_counts(struct hpn_cong_ctx *ctx)
{
	ctx->wedge_secs = 0;
	ctx->peer_stall_secs = 0;
	ctx->path_degraded_secs = 0;
	ctx->wedge_retrans_seen = 0;
}

/* Keep this sample's cumulative counters for the next sample's deltas. */
static void
cong_save_counters(struct hpn_cong_ctx *ctx, const struct tcpi_portable *tcpi)
{
	ctx->prev_total_rto_time = tcpi->total_rto_time;
	ctx->prev_total_retrans = tcpi->total_retrans;
	ctx->prev_rwnd_limited = tcpi->rwnd_limited;
}

/* How far a cumulative counter moved since the last sample, or 0 if it
 * went backwards, as when the kernel resets it. */
static uint64_t
cong_delta(uint64_t now, uint64_t prev)
{
	if (now < prev)
		return 0;
	return now - prev;
}

/* Wedge classifier. It judges a connection by active network distress,
 * never by missing throughput (checked against net/ipv4/{tcp,tcp_rate}.c).
 * delivery_rate and the app_limited bit are recomputed only when an ACK
 * arrives, so during a stall with no ACKs they go stale. They cannot
 * detect the stall, and they cannot tell a wedge from the application
 * pausing, for example to hash during verify. The distress signals used
 * here stay current when read: total_rto_time includes the RTO episode in
 * progress, rwnd_limited includes the interval in progress, and snd_cwnd,
 * notsent_bytes, and total_retrans are current state. */
enum hpn_cong_verdict
hpn_cong_classify(struct hpn_cong_ctx *ctx,
    const struct hpn_cong_sample *sample)
{
	const struct tcpi_portable *tcpi = &sample->raw;
	uint64_t	d_rto, d_retrans, d_rwnd;
	int		have_data, cwnd_collapsed, have_rto, wedge_now;

	/* Only EXTENDED carries the signals this acts on. For anything less,
	 * reset the trend state and stay silent. The caller still logs the
	 * sample, so BASIC data can be evaluated later. */
	if (sample->availability != HPN_CONG_EXTENDED) {
		ctx->trend_valid = 0;
		cong_reset_counts(ctx);
		return HPN_WEDGE_NONE;
	}

	/* The delta signals need a previous sample to compare against. */
	if (!ctx->trend_valid) {
		cong_save_counters(ctx, tcpi);
		ctx->trend_valid = 1;
		return HPN_WEDGE_NONE;
	}
	d_rto = cong_delta(tcpi->total_rto_time, ctx->prev_total_rto_time);
	d_retrans = cong_delta(tcpi->total_retrans, ctx->prev_total_retrans);
	d_rwnd = cong_delta(tcpi->rwnd_limited, ctx->prev_rwnd_limited);
	cong_save_counters(ctx, tcpi);

	/* LAN paths: the signals are noisy and wedges look different. */
	if (tcpi->min_rtt < WEDGE_MIN_RTT_LAN_US) {
		cong_reset_counts(ctx);
		return HPN_WEDGE_NONE;
	}

	/* notsent_bytes > 0 means data is queued that the network has not
	 * taken. A healthy path drains it fast even when the application
	 * pauses, so a value stuck above zero is itself a network signal. It
	 * also limits the client-side classifier to uploads, since a
	 * download's notsent is about 0. */
	have_data = (tcpi->notsent_bytes > 0);
	cwnd_collapsed = (tcpi->snd_cwnd <= WEDGE_CWND_COLLAPSED);
	have_rto = (tcpi->avail_flags & TCPI_AVAIL_TOTAL_RTO) != 0;

	/* PEER_STALL: the peer's receive window is holding us back while the
	 * cwnd is healthy, so the far end is not draining. This is checked
	 * first, because a healthy cwnd is what tells "the peer will not
	 * accept" from "the network has collapsed". It needs the rwnd_limited
	 * field from Linux 4.10. */
	if ((tcpi->avail_flags & TCPI_AVAIL_RWND_LIMITED) &&
	    have_data && d_rwnd > 0 && !cwnd_collapsed) {
		ctx->wedge_secs = ctx->path_degraded_secs = 0;
		ctx->wedge_retrans_seen = 0;
		/* peer_stall_secs keeps climbing while the stall persists.
		 * Brake first (sustained past the 5 min horizon = wedged, reap),
		 * otherwise the wait-it-out PEER_STALL verdict once past the
		 * sustain floor. */
		if (++ctx->peer_stall_secs >= PEER_STALL_BRAKE_SECS)
			return HPN_WEDGE_PEER_STALL_BRAKE;
		if (ctx->peer_stall_secs >= WEDGE_SUSTAIN_SECS)
			return HPN_WEDGE_PEER_STALL;
		return HPN_WEDGE_NONE;
	}
	ctx->peer_stall_secs = 0;

	/* WEDGE. The primary signal, on kernels 6.7 and later, is RTO time
	 * still accruing: the connection is sitting in timeout recovery. The
	 * fallback, on EXTENDED kernels before 6.7 with no RTO accounting, is
	 * a sustained collapsed cwnd. Retransmits seen during the window must
	 * corroborate it, so a link that is slow with a small cwnd but no
	 * loss is not mistaken for a wedge. */
	wedge_now = have_data && cwnd_collapsed;
	if (have_rto)
		wedge_now = have_data && d_rto > 0;
	if (wedge_now) {
		ctx->path_degraded_secs = 0;
		if (d_retrans > 0)
			ctx->wedge_retrans_seen = 1;
		if (ctx->wedge_secs < WEDGE_SUSTAIN_SECS)
			ctx->wedge_secs++;
		if (ctx->wedge_secs >= WEDGE_SUSTAIN_SECS &&
		    (have_rto || ctx->wedge_retrans_seen))
			return HPN_WEDGE_TCP_WEDGE;
		return HPN_WEDGE_NONE;
	}
	ctx->wedge_secs = 0;
	ctx->wedge_retrans_seen = 0;

	/* PATH_DEGRADED, for monitoring only: still moving, but losing packets
	 * steadily. It is reported once per episode and never triggers a
	 * kill. */
	if (have_data && d_retrans > 0) {
		if (++ctx->path_degraded_secs == WEDGE_SUSTAIN_SECS)
			return HPN_WEDGE_PATH_DEGRADED;
		return HPN_WEDGE_NONE;
	}
	ctx->path_degraded_secs = 0;

	return HPN_WEDGE_NONE;
}
