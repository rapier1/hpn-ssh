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

#ifndef TCPI_PORTABLE_H
#define TCPI_PORTABLE_H

#include <sys/types.h>

/*
 * Portable accessor for getsockopt(IPPROTO_TCP, TCP_INFO).
 *
 * Linux, FreeBSD, NetBSD, and OpenBSD all expose a "struct tcp_info",
 * but the layouts are NOT binary-compatible:
 *
 *   - window-scale is two packed 4-bit nibbles on Linux/FreeBSD but two
 *     full bytes on OpenBSD;
 *   - FreeBSD carries a dead tcpi_snd_bwnd field that shifts every later
 *     offset by one 32-bit word relative to OpenBSD;
 *   - OpenBSD only populates the extension region for privileged callers.
 *
 * (See repo-root openbsd_tcp_info.md for the full field-by-field diff.)
 *
 * We sidestep all of that by only ever reading the kernel struct through
 * its named fields against the locally compiled header -- never by
 * casting a raw byte buffer from one platform onto another -- and by
 * exposing only this normalised view to callers.  The raw "struct
 * tcp_info" stays private to tcpi-portable.c; consumers see nothing but
 * "struct tcpi_portable".
 *
 * This layer is deliberately separate from metrics.{c,h}: that module
 * serialises the full struct for offline CSV diagnostics, while this one
 * feeds live in-transfer decisions.  They share nothing but the kernel
 * API.
 */

/*
 * Availability bits for the extension-region / version-gated fields.
 * Tier-1 fields (above the comment in struct tcpi_portable) are always
 * populated on a supported platform; everything below it is valid only
 * when the matching bit is set in avail_flags.
 */
#define TCPI_AVAIL_TOTAL_RETRANS	(1u << 0)
#define TCPI_AVAIL_SEGS_OUT		(1u << 1)
#define TCPI_AVAIL_MIN_RTT		(1u << 2)
#define TCPI_AVAIL_NOTSENT_BYTES	(1u << 3)
#define TCPI_AVAIL_DELIVERY_RATE	(1u << 4)
#define TCPI_AVAIL_BUSY_TIME		(1u << 5)
#define TCPI_AVAIL_RWND_LIMITED		(1u << 6)
#define TCPI_AVAIL_RCV_WND		(1u << 7)	/* Linux 6.2+ */
#define TCPI_AVAIL_TOTAL_RTO		(1u << 8)	/* Linux 6.7+ (the trio) */
#define TCPI_AVAIL_BYTES_RECEIVED	(1u << 9)	/* Linux tcpi_bytes_received */

struct tcpi_portable {
	/*
	 * Tier 1 -- safe region (kernel fields up to and including
	 * tcpi_rcv_space).  Populated on every platform we support.
	 */
	u_int8_t	state;		/* TCP FSM state (TCP_ESTABLISHED, ...) */
	u_int8_t	options;	/* negotiated TCP options bitmask */
	u_int8_t	snd_wscale;	/* send window-scale shift */
	u_int8_t	rcv_wscale;	/* recv window-scale shift */
	u_int32_t	snd_mss;	/* send MSS, bytes */
	u_int32_t	rtt;		/* smoothed RTT, microseconds */
	u_int32_t	rttvar;		/* RTT variance, microseconds */
	u_int32_t	snd_ssthresh;	/* slow-start threshold, segments */
	u_int32_t	snd_cwnd;	/* send congestion window, segments */
	u_int32_t	rcv_space;	/* advertised recv window, bytes */

	/* Tier 1.5 + Tier 2 -- valid only where avail_flags says so. */
	u_int64_t	total_retrans;	/* cumulative retransmits (sender side) */
	u_int64_t	bytes_received;	/* cumulative bytes received (Linux only) */
	u_int32_t	segs_out;	/* segments sent */
	u_int32_t	min_rtt;	/* minimum observed RTT, microseconds */
	u_int32_t	notsent_bytes;	/* bytes queued but not yet sent */
	u_int64_t	delivery_rate;	/* delivery rate, bytes/sec */
	u_int8_t	delivery_rate_app_limited; /* rate sample was app-limited */
	u_int64_t	busy_time;	/* usec the connection spent sending */
	u_int64_t	rwnd_limited;	/* usec send was limited by recv window */
	u_int32_t	rcv_wnd;	/* scaled advertised recv window, bytes */
	u_int16_t	total_rto;	/* cumulative RTO timeouts */
	u_int16_t	total_rto_recoveries; /* cumulative RTO recoveries */
	u_int32_t	total_rto_time;	/* total time in RTO recovery, ms */

	u_int32_t	avail_flags;	/* OR of TCPI_AVAIL_* for gated fields */
};

/*
 * Fill *out from the socket's TCP_INFO.
 *
 * Returns 0 on success, with all Tier-1 fields populated and gated
 * fields valid only where their TCPI_AVAIL_* bit is set in
 * out->avail_flags.
 *
 * Returns -1 on failure -- either getsockopt() failed (errno set by the
 * syscall) or this build has no usable struct tcp_info (errno set to
 * ENOTSUP).  In both failure cases *out is fully zeroed.
 */
int	tcpi_portable_get(int fd, struct tcpi_portable *out);

/*
 * True (non-zero) if this build can read TCP_INFO at all.  This is a
 * compile-time property of the platform, independent of any particular
 * socket; callers can use it to decide whether to even arm a
 * TCP_INFO-driven code path.
 */
int	tcpi_portable_supported(void);

/*
 * Best-effort write op: clamp the advertised receive window on a connected
 * TCP socket to `bytes` (Linux: setsockopt(TCP_WINDOW_CLAMP)).  Returns 0
 * when the clamp was applied, and also when the platform has no such option
 * (a silent no-op -- e.g. the BSDs and macOS); returns -1 (errno set) only
 * if an attempt was made and the setsockopt failed.  This is the first write
 * member of the interface: tcpi-portable is the portable TCP-stack accessor,
 * reads and the few tuning writes HPN needs, not a read-only metrics view.
 */
int	tcpi_portable_clamp_rcvwnd(int fd, u_int32_t bytes);

#endif /* TCPI_PORTABLE_H */
