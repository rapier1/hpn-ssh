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

/* tcpi-portable.c - the kernel's TCP connection state through one portable
 * view, struct tcpi_portable (see tcpi-portable.h). */

/* Defined before any system header, because macOS hides struct
 * tcp_connection_info and TCP_CONNECTION_INFO under strict POSIX. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
# define _DARWIN_C_SOURCE 1
#endif

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>

/* Include the header that defines this platform's TCP state structure.
 * Linux has struct tcp_info in <linux/tcp.h>, with fields gated below by
 * the LINUX_VERSION_CODE macros from defines.h. FreeBSD and NetBSD have it
 * in <netinet/tcp.h>. The two headers define conflicting versions, so only
 * one is ever included. macOS has struct tcp_connection_info instead.
 * OpenBSD has struct tcp_info from 7.7 on, and configure's check for its
 * tcpi_snd_cwnd member sends older releases to the unsupported path.
 * TCPI_PORTABLE_SUPPORTED marks a platform with such a structure, and
 * TCPI_PORTABLE_MACOS marks macOS, whose structure has its own reader. */
#if defined(__linux__)
# include <linux/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#elif defined(__FreeBSD__) || defined(__NetBSD__)
# include <netinet/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#elif defined(__APPLE__)
# include <netinet/tcp.h>	/* struct tcp_connection_info */
# define TCPI_PORTABLE_SUPPORTED 1
# define TCPI_PORTABLE_MACOS 1
#elif defined(__OpenBSD__) && defined(HAVE_STRUCT_TCP_INFO_TCPI_SND_CWND)
# include <netinet/tcp.h>
# define TCPI_PORTABLE_SUPPORTED 1
#endif

#include "tcpi-portable.h"

/* Whether this build can read the TCP state structure at all, fixed when
 * it was compiled. */
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
/* macOS has no TCP_INFO. It offers struct tcp_connection_info through
 * TCP_CONNECTION_INFO instead, read here into struct tcpi_portable. Its RTT
 * fields are in milliseconds and become microseconds. The SDK header gives
 * srtt and rttcur in milliseconds and rttvar no unit, so rttvar is assumed
 * to match. snd_cwnd and snd_ssthresh are in bytes and become segments,
 * the Linux unit. Retransmits come from the sender's packet counter. macOS
 * lacks min_rtt, notsent_bytes, delivery_rate, busy_time, rwnd_limited,
 * rcv_wnd and the RTO counters, so their bits stay clear. That is the same
 * reduced set the BSDs give, which the congestion classifier handles. The
 * structure has a fixed size, so no TCPI_FIELD_IN check is needed. */
int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	struct tcp_connection_info tci;
	socklen_t tcilen = sizeof(tci);

	memset(out, 0, sizeof(*out));
	memset(&tci, 0, sizeof(tci));

	if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tci,
	    &tcilen) != 0)
		return -1;

	/* Tier 1, filled on every supported platform */
	out->state = tci.tcpi_state;
	out->options = (uint8_t)tci.tcpi_options;
	out->snd_wscale = tci.tcpi_snd_wscale;
	out->rcv_wscale = tci.tcpi_rcv_wscale;
	out->snd_mss = tci.tcpi_maxseg;
	out->rtt = tci.tcpi_srtt * 1000;	/* ms -> usec */
	out->rttvar = tci.tcpi_rttvar * 1000;	/* assumed ms -> usec */
	out->rcv_space = tci.tcpi_rcv_wnd;	/* advertised window, bytes */
	if (tci.tcpi_maxseg > 0) {
		/* bytes on macOS, segments here */
		out->snd_cwnd = tci.tcpi_snd_cwnd / tci.tcpi_maxseg;
		out->snd_ssthresh = tci.tcpi_snd_ssthresh / tci.tcpi_maxseg;
	}

	/* Tier 1.5, the cumulative counters */
	out->total_retrans = tci.tcpi_txretransmitpackets;
	out->avail_flags |= TCPI_AVAIL_TOTAL_RETRANS;

	out->segs_out = (uint32_t)tci.tcpi_txpackets;
	out->avail_flags |= TCPI_AVAIL_SEGS_OUT;

	out->bytes_received = tci.tcpi_rxbytes;
	out->avail_flags |= TCPI_AVAIL_BYTES_RECEIVED;

	return 0;
}

#else  /* Linux / BSD via struct tcp_info */

/* True when getsockopt wrote field in full. getsockopt copies the shorter
 * of our struct and the kernel's, and stores the length it wrote in len.
 * This runtime check, not the build-time LINUX_VERSION_CODE gates below,
 * is what keeps the reader right in a packaged binary, which is built
 * against one kernel's headers and usually runs on an older kernel. The
 * #if only proves the field is in the header we built against. Because
 * the struct is zeroed first, an unwritten field reads as 0, and without
 * this check that 0 would pass for a real value and set its avail bit.
 * offsetof and sizeof do not work on bitfields, so a group that holds a
 * bitfield is gated on a plain field of the same kernel version. */
#define TCPI_FIELD_IN(len, field)					\
	((len) >= (socklen_t)(offsetof(struct tcp_info, field) +	\
	    sizeof(((const struct tcp_info *)0)->field)))

/* Linux and the BSDs: read struct tcp_info into struct tcpi_portable. */
int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	struct tcp_info	ti;
	socklen_t	tilen = sizeof(ti);

	memset(out, 0, sizeof(*out));
	memset(&ti, 0, sizeof(ti));

	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tilen) != 0)
		return -1;

	/* Tier 1, through tcpi_rcv_space. Each field is read by name from the
	 * header this was built against, so the compiler resolves the window
	 * scale's nibbles or bytes and FreeBSD's extra tcpi_snd_bwnd. No byte
	 * layout is ever reinterpreted. */
	out->state = ti.tcpi_state;
	out->options = ti.tcpi_options;
	out->snd_wscale = ti.tcpi_snd_wscale;
	out->rcv_wscale = ti.tcpi_rcv_wscale;
	out->snd_mss = ti.tcpi_snd_mss;
	out->rtt = ti.tcpi_rtt;
	out->rttvar = ti.tcpi_rttvar;
	/* Segments here. Linux reports both in segments and NetBSD reports
	 * cwnd in segments. The other BSD values are in bytes. */
#if defined(__linux__) || defined(__NetBSD__)
	out->snd_cwnd = ti.tcpi_snd_cwnd;
#else
	if (ti.tcpi_snd_mss > 0)
		out->snd_cwnd = ti.tcpi_snd_cwnd / ti.tcpi_snd_mss;
#endif
#if defined(__linux__)
	out->snd_ssthresh = ti.tcpi_snd_ssthresh;
#else
	if (ti.tcpi_snd_mss > 0)
		out->snd_ssthresh = ti.tcpi_snd_ssthresh / ti.tcpi_snd_mss;
#endif
	out->rcv_space = ti.tcpi_rcv_space;

	/* The receive-side slow-start threshold, the kernel's current allowance
	 * for the advertised window. Linux has it in its base set, ahead of
	 * tcpi_rcv_space. FreeBSD and NetBSD carry only a placeholder, so it is
	 * flagged on Linux alone. */
#if defined(__linux__)
	if (TCPI_FIELD_IN(tilen, tcpi_rcv_ssthresh)) {
		out->rcv_ssthresh = ti.tcpi_rcv_ssthresh;
		out->avail_flags |= TCPI_AVAIL_RCV_SSTHRESH;
	}
#endif

	/* Tier 1.5, cumulative retransmits. Linux has tcpi_total_retrans in its
	 * base set, and FreeBSD and NetBSD have tcpi_snd_rexmitpack. OpenBSD
	 * has tcpi_snd_rexmitpack too, but fills it only for a privileged
	 * caller, and HPN-SSH's clients are not. Its 0 would look like no
	 * retransmits, so OpenBSD leaves the field unflagged. */
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

	/* Tier 2, Linux only and gated by kernel version. Each #if compiles a
	 * field only where the build header declares it, and TCPI_FIELD_IN then
	 * confirms the running kernel filled it. The BSDs never have these
	 * fields, so they stay unflagged there. */
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
	/* app_limited is a bitfield, so delivery_rate, from the same kernel
	 * version, gates it */
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
	/* the three RTO counters arrived together in 6.7, so the last of them
	 * gates all three */
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

/* No TCP state structure on this platform: fail with ENOTSUP. */
int
tcpi_portable_get(int fd, struct tcpi_portable *out)
{
	(void)fd;
	memset(out, 0, sizeof(*out));
	errno = ENOTSUP;
	return -1;
}

#endif /* TCPI_PORTABLE_SUPPORTED */
