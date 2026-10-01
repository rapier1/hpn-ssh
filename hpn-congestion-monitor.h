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

#ifndef HPN_CONGESTION_MONITOR_H
#define HPN_CONGESTION_MONITOR_H

#include "tcpi-portable.h"

/* hpn-congestion-monitor.h - TCP health monitor for parallel-worker
 * transports.
 *
 * A parallel hpnsftp worker's ssh connection watches its own socket
 * through TCP_INFO and ends itself when the network, not the work, has
 * stopped it. The client loop runs it on every worker connection, where
 * it judges uploads, since only a sender has data queued. The server loop
 * runs it on the far end when HPNWorkersDie allows, where it judges
 * downloads. A TCP_WEDGE or PEER_STALL_BRAKE verdict makes the transport
 * exit with an HPN_EXIT_TCP_* code, and the orchestrator reconnects the
 * worker.
 *
 * It complements the orchestrator's watchdog (sftp-parallel-watchdog.c)
 * rather than duplicating it. The watchdog asks "is work happening?" from
 * the bytes moved over time. This asks "is the network the reason it
 * isn't?" from the transport itself: the congestion window, retransmits,
 * time in RTO, and the peer's receive window. That catches what the
 * watchdog cannot: a connection that dribbles just enough bytes to keep
 * the watchdog's timer from tripping, and a single worker with no peers to
 * compare against. It also knows when not to kill. A peer that has stopped
 * draining, such as a busy Lustre backend, recovers on its own, and a
 * reconnect would only stall again, so PEER_STALL is waited out.
 *
 * It cannot see a stall above the network. A hung disk write, a
 * deadlocked thread, or an application that stops reading all leave TCP
 * looking healthy. Those remain the watchdog's job, as does everything on
 * a platform without TCP_INFO, where the monitor reports UNSUPPORTED and
 * its callers stop polling. */

/* How much of TCP_INFO this connection can give: none yet, none ever, the
 * portable fields, or the Linux extras the wedge classifier needs. */
enum hpn_cong_avail {
	HPN_CONG_UNPROBED,	/* ctx not yet initialised */
	HPN_CONG_PENDING,	/* supported, but no live sample yet */
	HPN_CONG_UNSUPPORTED,	/* no usable TCP_INFO here (terminal) */
	HPN_CONG_BASIC,		/* Tier-1 fields confirmed live */
	HPN_CONG_EXTENDED,	/* Tier-1 + Tier-2 confirmed (Linux) */
};

/* One connection's monitor: its socket, how much TCP_INFO it gives, and
 * the trend state the classifier carries from one sample to the next. */
struct hpn_cong_ctx {
	int		fd;		/* worker transport socket */
	enum hpn_cong_avail avail;
	int		pending_retries; /* probes spent waiting for a sample */

	/* Trend state for hpn_cong_classify(). prev_* hold the previous
	 * sample's cumulative counters, for the deltas. The *_secs counters
	 * count the consecutive samples, about one a second, that a
	 * signature has held. */
	int		trend_valid;		/* prev_* populated */
	uint32_t	prev_total_rto_time;
	uint64_t	prev_total_retrans;
	uint64_t	prev_rwnd_limited;
	int		wedge_secs;
	int		peer_stall_secs;
	int		path_degraded_secs;
	/* Loss seen during the wedge window. It corroborates the cwnd
	 * fallback on kernels before 6.7, which have no RTO accounting. */
	int		wedge_retrans_seen;
};

/* Verdict from the wedge classifier. TCP_WEDGE and PEER_STALL_BRAKE end
 * the transport, which exits with an HPN_EXIT_TCP_* code. PEER_STALL means
 * the peer has held our send window back for at least WEDGE_SUSTAIN_SECS,
 * but less than the brake horizon. The caller waits it out, because a
 * passing backend stall recovers on its own. PEER_STALL_BRAKE is the same
 * condition held past PEER_STALL_BRAKE_SECS. It is no longer draining
 * slowly but wedged, so the caller reaps it as an emergency brake.
 * PATH_DEGRADED is reported but does not trigger a kill yet. It is watched
 * to judge whether the signal is trustworthy enough to act on. */
enum hpn_cong_verdict {
	HPN_WEDGE_NONE,
	HPN_WEDGE_TCP_WEDGE,
	HPN_WEDGE_PEER_STALL,
	HPN_WEDGE_PEER_STALL_BRAKE,
	HPN_WEDGE_PATH_DEGRADED,
};

/* One sample: the TCP_INFO snapshot and the availability it was taken at. */
struct hpn_cong_sample {
	struct tcpi_portable	raw;		/* normalised TCP_INFO snapshot */
	enum hpn_cong_avail	availability;	/* mirror of ctx->avail */
};

/* Set up ctx for a socket and probe it once. Afterward ctx->avail is
 * UNSUPPORTED (terminal), PENDING, BASIC, or EXTENDED. */
void hpn_cong_init(struct hpn_cong_ctx *, int);

/* Take a fresh sample. Returns 0 whenever a sample could be taken, and the
 * caller then acts on its availability: PENDING, BASIC, or EXTENDED.
 * Returns -1 only once the monitor has settled to UNSUPPORTED. No syscall
 * is made, and the sample is zeroed. A -1 tells the caller to stop
 * polling for good and rely on the watchdog. */
int hpn_cong_poll(struct hpn_cong_ctx *, struct hpn_cong_sample *);

/* Feed one sample to the wedge classifier, advance the trend state in ctx,
 * and return a verdict. Only EXTENDED samples are judged, and BASIC and
 * PENDING always return NONE, so the caller logs BASIC samples itself.
 * Apart from the trend state in ctx it has no side effects, so it can be
 * unit-tested with made-up samples. */
enum hpn_cong_verdict
hpn_cong_classify(struct hpn_cong_ctx *, const struct hpn_cong_sample *);

#endif /* HPN_CONGESTION_MONITOR_H */
