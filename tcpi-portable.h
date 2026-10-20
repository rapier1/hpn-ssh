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

/* tcpi-portable.h - a portable view of the kernel's TCP connection state.
 *
 * Linux, FreeBSD, NetBSD and OpenBSD each have a struct tcp_info, and macOS
 * has struct tcp_connection_info, but the layouts are not compatible. The
 * window scales are 4-bit nibbles on Linux and FreeBSD and full bytes on
 * OpenBSD. FreeBSD carries an unused tcpi_snd_bwnd that shifts every later
 * field by 32 bits relative to OpenBSD. OpenBSD fills its extension region
 * only for privileged callers. The units differ as well. tcpi-portable.c
 * reads each kernel structure by field name against the header it was
 * built with, converts to the units here, and exposes only struct
 * tcpi_portable. The kernel structures stay private to it.
 *
 * This is separate from metrics.c, which writes the whole kernel structure
 * to CSV for offline diagnosis. This view feeds decisions during a
 * transfer. The two share only the kernel interface. */

#ifndef TCPI_PORTABLE_H
#define TCPI_PORTABLE_H

#include <stdint.h>

/* Availability bits for the fields after Tier 1 in struct tcpi_portable.
 * The Tier 1 fields are filled on every supported platform, and each later
 * field is valid only when its bit is set in avail_flags. */
#define TCPI_AVAIL_TOTAL_RETRANS	(1u << 0)
#define TCPI_AVAIL_SEGS_OUT		(1u << 1)
#define TCPI_AVAIL_MIN_RTT		(1u << 2)
#define TCPI_AVAIL_NOTSENT_BYTES	(1u << 3)
#define TCPI_AVAIL_DELIVERY_RATE	(1u << 4)
#define TCPI_AVAIL_BUSY_TIME		(1u << 5)
#define TCPI_AVAIL_RWND_LIMITED		(1u << 6)
#define TCPI_AVAIL_RCV_WND		(1u << 7)
#define TCPI_AVAIL_TOTAL_RTO		(1u << 8)
#define TCPI_AVAIL_BYTES_RECEIVED	(1u << 9)
#define TCPI_AVAIL_RCV_SSTHRESH		(1u << 10)

struct tcpi_portable {
	/* Tier 1, the kernel fields through tcpi_rcv_space, filled on every
	 * supported platform */
	uint8_t		state;		/* TCP state, such as TCP_ESTABLISHED */
	uint8_t		options;	/* negotiated TCP options bitmask */
	uint8_t		snd_wscale;	/* send window-scale shift */
	uint8_t		rcv_wscale;	/* recv window-scale shift */
	uint32_t	snd_mss;	/* send MSS, bytes */
	uint32_t	rtt;		/* smoothed RTT, microseconds */
	uint32_t	rttvar;		/* RTT variance, microseconds */
	uint32_t	snd_ssthresh;	/* slow-start threshold, segments */
	uint32_t	snd_cwnd;	/* send congestion window, segments */
	/* receive space, bytes: Linux's autotuning estimate, and the
	 * advertised window elsewhere */
	uint32_t	rcv_space;

	/* Tier 1.5 and Tier 2, each valid only when avail_flags says so */
	uint64_t	total_retrans;	/* cumulative sender retransmits */
	uint64_t	bytes_received;	/* cumulative bytes received */
	uint32_t	segs_out;	/* segments sent */
	uint32_t	min_rtt;	/* minimum observed RTT, microseconds */
	uint32_t	notsent_bytes;	/* bytes queued but not yet sent */
	uint64_t	delivery_rate;	/* delivery rate, bytes/sec */
	uint8_t		delivery_rate_app_limited; /* app-limited sample */
	uint64_t	busy_time;	/* usec the connection spent sending */
	uint64_t	rwnd_limited;	/* usec limited by the recv window */
	uint32_t	rcv_wnd;	/* advertised window, scaled, bytes */
	uint32_t	rcv_ssthresh;	/* receive-side slow-start threshold:
					 * the kernel's current allowance for
					 * the advertised window, bytes */
	uint16_t	total_rto;	/* cumulative RTO timeouts */
	uint16_t	total_rto_recoveries; /* cumulative RTO recoveries */
	uint32_t	total_rto_time;	/* total time in RTO recovery, ms */

	uint32_t	avail_flags;	/* OR of the TCPI_AVAIL_* bits */
};

/* Fill *out with the TCP state of socket fd. Returns 0 with the Tier 1
 * fields set, and each later field valid only when its TCPI_AVAIL_* bit
 * is set in out->avail_flags. Returns -1 with *out zeroed when getsockopt
 * fails, leaving its errno, or when this build cannot read the TCP state
 * at all, with errno ENOTSUP. */
int	tcpi_portable_get(int, struct tcpi_portable *);

/* Whether this build can read the TCP state at all. It is fixed when the
 * build is compiled and does not depend on any socket, so a caller can
 * check it once before arming a code path that needs it. */
int	tcpi_portable_supported(void);

#endif /* TCPI_PORTABLE_H */
