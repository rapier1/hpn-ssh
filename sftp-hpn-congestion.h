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

#ifndef SFTP_HPN_CONGESTION_H
#define SFTP_HPN_CONGESTION_H

#include "tcpi-portable.h"

/*
 * Per-worker TCP-health self-monitor for the parallel-streams transfer
 * path.  The full rationale -- in particular how this relates to the
 * time-based worker watchdog -- is in sftp-hpn-congestion.c; read that
 * before changing this module.  In one line: the watchdog answers "is
 * work happening?" and this answers "is the network the reason it
 * isn't?".  They are complementary; this enriches the watchdog's
 * verdict, it does not replace it.
 *
 * This first cut is the polling primitive only: probe availability,
 * sample on demand (the caller drives cadence -- typically the ~1 s
 * watchdog tick), and classify into a coarse health tier.  The decision
 * logic that consumes the samples (wedge detection, outlier-kill veto,
 * no-peer absolute signal) lands on top of this in a later change.
 */

enum sftp_hpn_tcp_health_avail {
	TCP_HEALTH_UNPROBED = 0,	/* ctx not yet initialised */
	TCP_HEALTH_PENDING,		/* supported, but no live sample yet */
	TCP_HEALTH_UNSUPPORTED,		/* no usable TCP_INFO here (terminal) */
	TCP_HEALTH_BASIC,		/* Tier-1 fields confirmed live */
	TCP_HEALTH_EXTENDED,		/* Tier-1 + Tier-2 confirmed (Linux) */
};

struct sftp_hpn_tcp_health_ctx {
	int		fd;		/* worker transport socket */
	enum sftp_hpn_tcp_health_avail avail;
	u_int32_t	pending_retries; /* probes spent waiting for a sample */
	/*
	 * Room for trend state (RTT / cwnd / retrans history, last-poll
	 * time) once the wedge-detection logic lands.  Kept out of the
	 * first cut deliberately -- nothing reads it yet.
	 */
};

struct sftp_hpn_tcp_health {
	struct tcpi_portable		raw;	/* normalised TCP_INFO snapshot */
	enum sftp_hpn_tcp_health_avail	availability; /* mirror of ctx->avail */
};

/*
 * Initialise ctx for socket fd and eagerly probe availability.  After
 * this returns, ctx->avail is one of UNSUPPORTED (terminal), PENDING,
 * BASIC, or EXTENDED.
 */
void	sftp_hpn_tcp_health_ctx_init(struct sftp_hpn_tcp_health_ctx *ctx,
	    int fd);

/*
 * Take a fresh sample into *out.
 *
 * Returns 0 with *out populated whenever a sample could be taken -- the
 * caller then dispatches on out->availability (PENDING / BASIC /
 * EXTENDED).  Returns -1 only once ctx has settled to UNSUPPORTED: no
 * syscall is made, *out is zeroed, and out->availability is
 * UNSUPPORTED.  A -1 is the signal for a consumer to disarm its
 * TCP_INFO-driven path permanently and lean on the watchdog instead.
 */
int	sftp_hpn_tcp_health_poll(struct sftp_hpn_tcp_health_ctx *ctx,
	    struct sftp_hpn_tcp_health *out);

#endif /* SFTP_HPN_CONGESTION_H */
