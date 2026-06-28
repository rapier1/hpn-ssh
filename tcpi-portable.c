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

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
# define _DARWIN_C_SOURCE 1	/* expose struct tcp_connection_info / TCP_CONNECTION_INFO; hidden under strict POSIX */
#endif

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>

/*
 * Pull in the kernel's "struct tcp_info" exactly the way metrics.h does:
 * <linux/tcp.h> on Linux (its field set is richer and version-gated by
 * the LINUX_VERSION_CODE macros that defines.h already provides via
 * <linux/version.h>), <netinet/tcp.h> on the BSDs.  We never include
 * both in one translation unit -- they each define a conflicting "struct
 * tcp_info".  OpenBSD's struct first appears in 7.7 (May 2025); the
 * autoconf member check gates it so pre-7.7 falls through to the
 * unsupported path below.
 */
#if defined(__linux__)
# include <linux/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#elif defined(__FreeBSD__) || defined(__NetBSD__)
# include <netinet/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#elif defined(__APPLE__)
# include <netinet/tcp.h>	/* struct tcp_connection_info, TCP_CONNECTION_INFO */
# define TCPI_PORTABLE_SUPPORTED 1
# define TCPI_PORTABLE_MACOS 1
#elif defined(__OpenBSD__) && defined(HAVE_STRUCT_TCP_INFO_TCPI_SND_CWND)
# include <netinet/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#endif

#include "tcpi-portable.h"

int
tcpi_portable_supported(void)
{
#ifdef TCPI_PORTABLE_SUPPORTED
	return 1;
#else
	return 0;
#endif
}

#ifdef TCPI_PORTABLE_SUPPORTED

#ifdef TCPI_PORTABLE_MACOS
/*
 * macOS has no Linux-style TCP_INFO; it exposes getsockopt(TCP_CONNECTION_INFO)
 * -> struct tcp_connection_info instead.  Read that and normalise into struct
 * tcpi_portable.  Conversions vs the Linux/BSD tcp_info layout:
 *   - RTT fields are MILLISECONDS on macOS; tcpi_portable wants microseconds
 *     -> x1000.  (srtt/rttcur are documented "in ms"; tcpi_rttvar has no unit
 *     comment in the SDK header but is assumed ms for consistency.)
 *   - snd_cwnd / snd_ssthresh are BYTES on macOS; tcpi_portable expresses them
 *     in SEGMENTS (Linux convention) -> divide by tcpi_maxseg (guard /0).
 *   - retransmits arrive as a sender-side packet counter (txretransmitpackets).
 * Fields macOS does not provide (min_rtt, notsent_bytes, delivery_rate,
 * busy_time, rwnd_limited, rcv_wnd[6.2], the RTO trio) are left unflagged in
 * avail_flags -- the same reduced set the BSDs present, which the classifier
 * already gates on and degrades against.  macOS ships a fixed struct, so no
 * TCPI_FIELD_IN length-gate is needed here.
 */
int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	struct tcp_connection_info tci;
	socklen_t tcilen = sizeof(tci);

	memset(out, 0, sizeof(*out));
	memset(&tci, 0, sizeof(tci));

	if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tci, &tcilen) != 0)
		return -1;

	/* Tier 1 -- always populated on a supported platform. */
	out->state = tci.tcpi_state;
	out->options = (u_int8_t)tci.tcpi_options;
	out->snd_wscale = tci.tcpi_snd_wscale;
	out->rcv_wscale = tci.tcpi_rcv_wscale;
	out->snd_mss = tci.tcpi_maxseg;
	out->rtt = tci.tcpi_srtt * 1000;	/* ms -> usec */
	out->rttvar = tci.tcpi_rttvar * 1000;	/* assumed ms -> usec (see note) */
	out->rcv_space = tci.tcpi_rcv_wnd;	/* advertised recv window, bytes */
	if (tci.tcpi_maxseg > 0) {
		/* macOS reports these in bytes; express in segments. */
		out->snd_cwnd = tci.tcpi_snd_cwnd / tci.tcpi_maxseg;
		out->snd_ssthresh = tci.tcpi_snd_ssthresh / tci.tcpi_maxseg;
	}

	/* Tier 1.5 -- cumulative retransmits (sender-side packets). */
	out->total_retrans = tci.tcpi_txretransmitpackets;
	out->avail_flags |= TCPI_AVAIL_TOTAL_RETRANS;

	out->segs_out = (u_int32_t)tci.tcpi_txpackets;
	out->avail_flags |= TCPI_AVAIL_SEGS_OUT;

	out->bytes_received = tci.tcpi_rxbytes;
	out->avail_flags |= TCPI_AVAIL_BYTES_RECEIVED;

	return 0;
}

#else  /* Linux / BSD via struct tcp_info */

/*
 * A field is genuinely present only if getsockopt wrote at least through
 * its last byte.  getsockopt returns min(our_buffer, kernel_struct) and
 * writes the real length back into the socklen_t (value-result).  This
 * runtime gate -- not the build-time LINUX_VERSION_CODE gate below -- is
 * what makes the accessor correct under binary distribution: a packaged
 * binary is built against one kernel's headers but runs on whatever
 * kernel the user has, which is usually older and almost never the same.
 * The compile-time #if only proves the field exists in the header we
 * built against; it says nothing about the running kernel.  We zero the
 * struct first, so an unwritten field reads as 0 -- without this check we
 * would mistake that 0 for a real value and wrongly set its avail bit.
 *
 * offsetof/sizeof do not work on bitfield members, so any group that
 * contains a bitfield gates on a normal sibling field from the same
 * kernel version instead.
 */
#define TCPI_FIELD_IN(len, field)					\
	((len) >= (socklen_t)(offsetof(struct tcp_info, field) +	\
	    sizeof(((const struct tcp_info *)0)->field)))

int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	struct tcp_info	ti;
	socklen_t	tilen = sizeof(ti);

	memset(out, 0, sizeof(*out));
	memset(&ti, 0, sizeof(ti));

	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tilen) != 0)
		return -1;

	/*
	 * Tier 1 -- safe region (through tcpi_rcv_space).  Every field is
	 * read by name against the locally compiled header, so the
	 * window-scale nibble-vs-byte difference and the tcpi_snd_bwnd
	 * offset shift between platforms are resolved by the compiler; we
	 * never reinterpret a foreign byte layout.
	 */
	out->state = ti.tcpi_state;
	out->options = ti.tcpi_options;
	out->snd_wscale = ti.tcpi_snd_wscale;
	out->rcv_wscale = ti.tcpi_rcv_wscale;
	out->snd_mss = ti.tcpi_snd_mss;
	out->rtt = ti.tcpi_rtt;
	out->rttvar = ti.tcpi_rttvar;
	out->snd_ssthresh = ti.tcpi_snd_ssthresh;
	out->snd_cwnd = ti.tcpi_snd_cwnd;
	out->rcv_space = ti.tcpi_rcv_space;

	/*
	 * Tier 1.5 -- cumulative retransmits.  Linux names it
	 * tcpi_total_retrans (part of the early base set); FreeBSD/NetBSD
	 * expose the equivalent tcpi_snd_rexmitpack.  OpenBSD also has
	 * tcpi_snd_rexmitpack but privilege-gates the extension region
	 * (unprivileged callers read 0), and hpnsftp runs unprivileged -- so
	 * we deliberately leave it unflagged on OpenBSD rather than advertise
	 * a value that is indistinguishable from "no retransmits".
	 */
#if defined(__linux__)
	if (TCPI_FIELD_IN(tilen, tcpi_total_retrans)) {
		out->total_retrans = ti.tcpi_total_retrans;
		out->avail_flags |= TCPI_AVAIL_TOTAL_RETRANS;
	}
#elif defined(__FreeBSD__) || defined(__NetBSD__)
	if (TCPI_FIELD_IN(tilen, tcpi_snd_rexmitpack)) {
		out->total_retrans = ti.tcpi_snd_rexmitpack;
		out->avail_flags |= TCPI_AVAIL_TOTAL_RETRANS;
	}
#endif

	/*
	 * Tier 2 -- Linux-only, kernel-version-gated.  The #if guards make
	 * each field name compile only where the build header declares it;
	 * the TCPI_FIELD_IN runtime gate then confirms the running kernel
	 * actually populated it.  These fields are permanently absent on the
	 * BSDs (not merely old-kernel), so they stay unflagged off Linux.
	 */
#if defined(__linux__)
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	if (TCPI_FIELD_IN(tilen, tcpi_bytes_received)) {
		out->bytes_received = ti.tcpi_bytes_received;
		out->avail_flags |= TCPI_AVAIL_BYTES_RECEIVED;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	if (TCPI_FIELD_IN(tilen, tcpi_segs_out)) {
		out->segs_out = ti.tcpi_segs_out;
		out->avail_flags |= TCPI_AVAIL_SEGS_OUT;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	if (TCPI_FIELD_IN(tilen, tcpi_min_rtt)) {
		out->min_rtt = ti.tcpi_min_rtt;
		out->avail_flags |= TCPI_AVAIL_MIN_RTT;
	}
	if (TCPI_FIELD_IN(tilen, tcpi_notsent_bytes)) {
		out->notsent_bytes = ti.tcpi_notsent_bytes;
		out->avail_flags |= TCPI_AVAIL_NOTSENT_BYTES;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	/* app_limited is a bitfield (no offsetof); gate on its u64 sibling. */
	if (TCPI_FIELD_IN(tilen, tcpi_delivery_rate)) {
		out->delivery_rate = ti.tcpi_delivery_rate;
		out->delivery_rate_app_limited =
		    ti.tcpi_delivery_rate_app_limited;
		out->avail_flags |= TCPI_AVAIL_DELIVERY_RATE;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (TCPI_FIELD_IN(tilen, tcpi_busy_time)) {
		out->busy_time = ti.tcpi_busy_time;
		out->avail_flags |= TCPI_AVAIL_BUSY_TIME;
	}
	if (TCPI_FIELD_IN(tilen, tcpi_rwnd_limited)) {
		out->rwnd_limited = ti.tcpi_rwnd_limited;
		out->avail_flags |= TCPI_AVAIL_RWND_LIMITED;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
	if (TCPI_FIELD_IN(tilen, tcpi_rcv_wnd)) {
		out->rcv_wnd = ti.tcpi_rcv_wnd;
		out->avail_flags |= TCPI_AVAIL_RCV_WND;
	}
# endif
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)
	/*
	 * The 6.7 RTO trio landed in one commit; gate on the last (highest
	 * offset) member so its presence implies all three are written.
	 */
	if (TCPI_FIELD_IN(tilen, tcpi_total_rto_time)) {
		out->total_rto = ti.tcpi_total_rto;
		out->total_rto_recoveries = ti.tcpi_total_rto_recoveries;
		out->total_rto_time = ti.tcpi_total_rto_time;
		out->avail_flags |= TCPI_AVAIL_TOTAL_RTO;
	}
# endif
#endif /* __linux__ */

	return 0;
}

#undef TCPI_FIELD_IN

#endif /* TCPI_PORTABLE_MACOS (else: Linux/BSD tcp_info path) */

#else /* !TCPI_PORTABLE_SUPPORTED */

int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	(void)fd;
	memset(out, 0, sizeof(*out));
	errno = ENOTSUP;
	return -1;
}

#endif /* TCPI_PORTABLE_SUPPORTED */

/*
 * Clamp the advertised receive window to `bytes`.  Compiled on every platform
 * (independent of the read path above): where TCP_WINDOW_CLAMP exists (Linux)
 * it applies the clamp; elsewhere it is a silent no-op.  Returns 0 on success
 * or no-op, -1 only if an attempted setsockopt failed.
 */
int
tcpi_portable_clamp_rcvwnd(int fd, u_int32_t bytes)
{
#ifdef TCP_WINDOW_CLAMP
	int clamp = (int)bytes;

	return setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP,
	    &clamp, sizeof(clamp));
#else
	(void)fd;
	(void)bytes;
	return 0;	/* no such option on this platform: silent no-op */
#endif
}
