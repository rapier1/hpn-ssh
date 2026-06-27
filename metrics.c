/*
 * Copyright (c) 2022 The Board of Trustees of Carnegie Mellon University.
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

#include "includes.h"
#include "metrics.h"
#include "ssherr.h"
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>		/* offsetof for the TCPI_FIELD_IN length gate */
#include <sys/utsname.h>	/* uname for the runtime kernel version stamp */

/* kernel version macro moved to defines.h */

/*
 * A tcp_info field is genuinely present only if getsockopt wrote at least
 * through its last byte.  getsockopt returns min(our_buffer, kernel_struct)
 * and writes the real length back into the socklen_t (value-result).  This
 * runtime gate -- not the build-time LINUX_VERSION_CODE #if below -- is what
 * makes serialization correct under binary distribution: a packaged binary is
 * built against one kernel's headers but runs on whatever kernel the user has,
 * which is usually older and almost never the same.  The compile-time #if only
 * proves the field exists in the header we built against; it says nothing about
 * the running kernel.  Mirrors the gate in tcpi-portable.c.
 *
 * offsetof/sizeof do not work on bitfield members, so a group that contains a
 * bitfield gates on a normal sibling field from the same kernel version.
 */
#ifdef TCP_INFO
#define TCPI_FIELD_IN(len, field)					\
	((len) >= (socklen_t)(offsetof(struct tcp_info, field) +	\
	    sizeof(((const struct tcp_info *)0)->field)))
#endif

/*
 * The running kernel's version as a KERNEL_VERSION() code, parsed from the
 * uname(2) release string.  Replaces the old LINUX_VERSION_CODE stamp, which
 * recorded the BUILD kernel.  Returns 0 if the release does not parse; the
 * reader treats a missing/0 stamp harmlessly because read-back is keyed on
 * field presence, not on this value.
 */
static unsigned int
metrics_runtime_kernel_version(const char *release)
{
#ifdef __linux__
	int maj = 0, min = 0, patch = 0;

	if (sscanf(release, "%d.%d.%d", &maj, &min, &patch) < 2)
		return 0;
	if (patch > 255)		/* KERNEL_VERSION packs patch into 8 bits */
		patch = 255;
	return (unsigned int)KERNEL_VERSION(maj, min, patch);
#else
	(void)release;
	return 0;
#endif
}

/*
 * Read-back and the column header are driven purely by which keys a record
 * contains, not by any kernel-version comparison.  The writer only emits a
 * post-3.15 field when the producing kernel actually returned it, so key
 * presence is the authoritative gate -- and because binn is self-describing by
 * key name (independent of struct layout), a record produced by a remote host
 * on a different kernel still reads correctly.
 */
static int
metrics_has(void *binnobj, const char *key)
{
	binn value;

	return binn_object_get_value(binnobj, key, &value) ? 1 : 0;
}

/* add the information from the tcp_info struct to the
 * serialized binary object
 */
void
metrics_write_binn_object(struct tcp_info *data, socklen_t tilen,
			  struct binn_struct *binnobj) {
#if !defined TCP_INFO
	/*tcp info isn't supported on this system */
	return;
#else

/* the base set of tcpi_ measurements starting from kernel 3.7.0
 * these measurements existed in previous kernels but the oldest this
 * is going to support is 3.7.0. We do need to store the kernel version as well */

	/*
	 * Stamp the record with the RUNNING kernel, not the build kernel.
	 * uname(2) gives a human-readable release string and the version code
	 * we parse from it; tilen (the getsockopt value-result length) records
	 * exactly how many bytes this kernel returned.  These are diagnostic
	 * metadata -- read-back gates on key presence, not on the version.
	 */
	{
		struct utsname uts;

		if (uname(&uts) == 0) {
			binn_object_set_str(binnobj, "kernel_release",
					    uts.release);
			binn_object_set_uint32(binnobj, "kernel_version",
			    metrics_runtime_kernel_version(uts.release));
		} else {
			binn_object_set_uint32(binnobj, "kernel_version", 0);
		}
	}
	binn_object_set_uint32(binnobj, "tcpi_len", (unsigned int)tilen);

	/* the following are common under both linux and BSD */
	binn_object_set_uint8(binnobj, "tcpi_snd_wscale",
			      data->tcpi_snd_wscale);
	binn_object_set_uint8(binnobj, "tcpi_rcv_wscale",
			      data->tcpi_rcv_wscale);
	binn_object_set_uint8(binnobj, "tcpi_state",
			      data->tcpi_state);
	binn_object_set_uint8(binnobj, "tcpi_options",
			      data->tcpi_options);
	binn_object_set_uint32(binnobj, "tcpi_snd_ssthresh",
			       data->tcpi_snd_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_rtt",
			       data->tcpi_rtt);
	binn_object_set_uint32(binnobj, "tcpi_last_data_recv",
			       data->tcpi_last_data_recv);
	binn_object_set_uint32(binnobj, "tcpi_rttvar",
			       data->tcpi_rttvar);
	binn_object_set_uint32(binnobj, "tcpi_snd_cwnd",
			       data->tcpi_snd_cwnd);
	binn_object_set_uint32(binnobj, "tcpi_rcv_mss",
			       data->tcpi_rcv_mss);
	binn_object_set_uint32(binnobj, "tcpi_rto",
			       data->tcpi_rto);
	binn_object_set_uint32(binnobj, "tcpi_snd_mss",
			       data->tcpi_snd_mss);
	binn_object_set_uint32(binnobj, "tcpi_rcv_space",
			       data->tcpi_rcv_space);

/* the following exist under both but with different names */
#ifdef __linux__
	binn_object_set_uint8(binnobj, "tcpi_ca_state",
			      data->tcpi_ca_state);
	binn_object_set_uint8(binnobj, "tcpi_probes",
			      data->tcpi_probes);
	binn_object_set_uint8(binnobj, "tcpi_backoff",
			      data->tcpi_backoff);
	binn_object_set_uint8(binnobj, "tcpi_retransmits",
			      data->tcpi_retransmits);
	binn_object_set_uint32(binnobj, "tcpi_rcv_ssthresh",
			       data->tcpi_rcv_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_sacked",
			       data->tcpi_sacked);
	binn_object_set_uint32(binnobj, "tcpi_pmtu",
			       data->tcpi_pmtu);
	binn_object_set_uint32(binnobj, "tcpi_fackets",
			       data->tcpi_fackets);
	binn_object_set_uint32(binnobj, "tcpi_lost",
			       data->tcpi_lost);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_sent",
			       data->tcpi_last_ack_sent);
	binn_object_set_uint32(binnobj, "tcpi_unacked",
			       data->tcpi_unacked);
	binn_object_set_uint32(binnobj, "tcpi_last_data_sent",
			       data->tcpi_last_data_sent);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_recv",
			       data->tcpi_last_ack_recv);
	binn_object_set_uint32(binnobj, "tcpi_reordering",
			       data->tcpi_reordering);
	binn_object_set_uint32(binnobj, "tcpi_advmss",
			       data->tcpi_advmss);
	binn_object_set_uint32(binnobj, "tcpi_retrans",
			       data->tcpi_retrans);
	binn_object_set_uint32(binnobj, "tcpi_ato",
			       data->tcpi_ato);
	binn_object_set_uint32(binnobj, "tcpi_rcv_rtt",
			       data->tcpi_rcv_rtt);
#else
	binn_object_set_uint8(binnobj, "tcpi_backoff",
			      data->__tcpi_backoff);
	binn_object_set_uint8(binnobj, "tcpi_ca_state",
			      data->__tcpi_ca_state);
	binn_object_set_uint8(binnobj, "tcpi_probes",
			      data->__tcpi_probes);
	binn_object_set_uint8(binnobj, "tcpi_retransmits",
			      data->__tcpi_retransmits);
	binn_object_set_uint32(binnobj, "tcpi_rcv_ssthresh",
			       data->__tcpi_rcv_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_sacked",
			       data->__tcpi_sacked);
	binn_object_set_uint32(binnobj, "tcpi_pmtu",
			       data->__tcpi_pmtu);
	binn_object_set_uint32(binnobj, "tcpi_fackets",
			       data->__tcpi_fackets);
	binn_object_set_uint32(binnobj, "tcpi_lost",
			       data->__tcpi_lost);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_sent",
			       data->__tcpi_last_ack_sent);
	binn_object_set_uint32(binnobj, "tcpi_unacked",
			       data->__tcpi_unacked);
	binn_object_set_uint32(binnobj, "tcpi_last_data_sent",
			       data->__tcpi_last_data_sent);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_recv",
			       data->__tcpi_last_ack_recv);
	binn_object_set_uint32(binnobj, "tcpi_reordering",
			       data->__tcpi_reordering);
	binn_object_set_uint32(binnobj, "tcpi_advmss",
			       data->__tcpi_advmss);
	binn_object_set_uint32(binnobj, "tcpi_retrans",
			       data->__tcpi_retrans);
	binn_object_set_uint32(binnobj, "tcpi_ato",
			       data->__tcpi_ato);
	binn_object_set_uint32(binnobj, "tcpi_rcv_rtt",
			       data->__tcpi_rcv_rtt);
#endif

/* Under BSD snd_rexmitpack is the same as linux total_retrans*/
#ifdef __linux__
	binn_object_set_uint32(binnobj, "tcpi_total_retrans",
			       data->tcpi_total_retrans);
#else
	binn_object_set_uint32(binnobj, "tcpi_total_retrans",
			       data->tcpi_snd_rexmitpack);
#endif

/*
 * Modern FreeBSD / OpenBSD tcp_info extensions.  BSD has no version macro, so
 * each field is gated by an autoconf member check (compile: does THIS
 * platform's struct define it -- FreeBSD and OpenBSD diverge) plus the runtime
 * TCPI_FIELD_IN length gate.  Wrapped #ifndef __linux__ because
 * delivered_ce/received_ce also exist on Linux, where the version groups below
 * already emit them.  On OpenBSD these extension fields read 0 for an
 * unprivileged caller (the kernel only fills them for privileged sockets).
 */
#ifndef __linux__
	/* FreeBSD AccECN + tail-loss-probe + SACK telemetry. */
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_DELIVERED_CE
	if (TCPI_FIELD_IN(tilen, tcpi_delivered_ce))
		binn_object_set_uint32(binnobj, "tcpi_delivered_ce",
				       data->tcpi_delivered_ce);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RECEIVED_CE
	if (TCPI_FIELD_IN(tilen, tcpi_received_ce))
		binn_object_set_uint32(binnobj, "tcpi_received_ce",
				       data->tcpi_received_ce);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_TOTAL_TLP
	if (TCPI_FIELD_IN(tilen, tcpi_total_tlp))
		binn_object_set_uint32(binnobj, "tcpi_total_tlp",
				       data->tcpi_total_tlp);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_TOTAL_TLP_BYTES
	if (TCPI_FIELD_IN(tilen, tcpi_total_tlp_bytes))
		binn_object_set_uint64(binnobj, "tcpi_total_tlp_bytes",
				       data->tcpi_total_tlp_bytes);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RCV_NUMSACKS
	if (TCPI_FIELD_IN(tilen, tcpi_rcv_numsacks))
		binn_object_set_uint32(binnobj, "tcpi_rcv_numsacks",
				       data->tcpi_rcv_numsacks);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_DUPACKS
	if (TCPI_FIELD_IN(tilen, tcpi_dupacks))
		binn_object_set_uint32(binnobj, "tcpi_dupacks",
				       data->tcpi_dupacks);
#endif
	/* OpenBSD extensions: peak send window, min RTT, peer advertised
	 * window, timestamp echo, receive-buffer autotune counters, and the
	 * socket-buffer occupancy/limit block. */
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_MAX_SNDWND
	if (TCPI_FIELD_IN(tilen, tcpi_max_sndwnd))
		binn_object_set_uint32(binnobj, "tcpi_max_sndwnd",
				       data->tcpi_max_sndwnd);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RTTMIN
	if (TCPI_FIELD_IN(tilen, tcpi_rttmin))
		binn_object_set_uint32(binnobj, "tcpi_rttmin",
				       data->tcpi_rttmin);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RCV_ADV
	if (TCPI_FIELD_IN(tilen, tcpi_rcv_adv))
		binn_object_set_uint32(binnobj, "tcpi_rcv_adv",
				       data->tcpi_rcv_adv);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_TS_RECENT
	if (TCPI_FIELD_IN(tilen, tcpi_ts_recent))
		binn_object_set_uint32(binnobj, "tcpi_ts_recent",
				       data->tcpi_ts_recent);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RFBUF_CNT
	if (TCPI_FIELD_IN(tilen, tcpi_rfbuf_cnt))
		binn_object_set_uint32(binnobj, "tcpi_rfbuf_cnt",
				       data->tcpi_rfbuf_cnt);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RFBUF_TS
	if (TCPI_FIELD_IN(tilen, tcpi_rfbuf_ts))
		binn_object_set_uint32(binnobj, "tcpi_rfbuf_ts",
				       data->tcpi_rfbuf_ts);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_RCV_SB_CC
	if (TCPI_FIELD_IN(tilen, tcpi_so_rcv_sb_cc))
		binn_object_set_uint32(binnobj, "tcpi_so_rcv_sb_cc",
				       data->tcpi_so_rcv_sb_cc);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_RCV_SB_HIWAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_rcv_sb_hiwat))
		binn_object_set_uint32(binnobj, "tcpi_so_rcv_sb_hiwat",
				       data->tcpi_so_rcv_sb_hiwat);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_RCV_SB_LOWAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_rcv_sb_lowat))
		binn_object_set_uint32(binnobj, "tcpi_so_rcv_sb_lowat",
				       data->tcpi_so_rcv_sb_lowat);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_RCV_SB_WAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_rcv_sb_wat))
		binn_object_set_uint32(binnobj, "tcpi_so_rcv_sb_wat",
				       data->tcpi_so_rcv_sb_wat);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_SND_SB_CC
	if (TCPI_FIELD_IN(tilen, tcpi_so_snd_sb_cc))
		binn_object_set_uint32(binnobj, "tcpi_so_snd_sb_cc",
				       data->tcpi_so_snd_sb_cc);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_SND_SB_HIWAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_snd_sb_hiwat))
		binn_object_set_uint32(binnobj, "tcpi_so_snd_sb_hiwat",
				       data->tcpi_so_snd_sb_hiwat);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_SND_SB_LOWAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_snd_sb_lowat))
		binn_object_set_uint32(binnobj, "tcpi_so_snd_sb_lowat",
				       data->tcpi_so_snd_sb_lowat);
#endif
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_SO_SND_SB_WAT
	if (TCPI_FIELD_IN(tilen, tcpi_so_snd_sb_wat))
		binn_object_set_uint32(binnobj, "tcpi_so_snd_sb_wat",
				       data->tcpi_so_snd_sb_wat);
#endif
#endif /* !__linux__ */

/* The last section are for kernel specific metrics in linux.  The outer #if
 * is the COMPILE gate (the member exists in the header we built against); the
 * inner TCPI_FIELD_IN is the RUNTIME gate (the running kernel actually returned
 * it).  Both are needed: the #if lets the code compile, the runtime gate keeps
 * us from serializing uninitialized struct tail as data on an older kernel. */
#ifdef __linux__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	if (TCPI_FIELD_IN(tilen, tcpi_pacing_rate)) {
		binn_object_set_uint64(binnobj, "tcpi_max_pacing_rate",
				       data->tcpi_max_pacing_rate);
		binn_object_set_uint64(binnobj, "tcpi_pacing_rate",
				       data->tcpi_pacing_rate);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	if (TCPI_FIELD_IN(tilen, tcpi_bytes_received)) {
		binn_object_set_uint64(binnobj, "tcpi_bytes_acked",
				       data->tcpi_bytes_acked);
		binn_object_set_uint64(binnobj, "tcpi_bytes_received",
				       data->tcpi_bytes_received);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	if (TCPI_FIELD_IN(tilen, tcpi_segs_out)) {
		binn_object_set_uint32(binnobj, "tcpi_segs_in",
				       data->tcpi_segs_in);
		binn_object_set_uint32(binnobj, "tcpi_segs_out",
				       data->tcpi_segs_out);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	if (TCPI_FIELD_IN(tilen, tcpi_data_segs_out)) {
		binn_object_set_uint32(binnobj, "tcpi_notsent_bytes",
				       data->tcpi_notsent_bytes);
		binn_object_set_uint32(binnobj, "tcpi_min_rtt",
				       data->tcpi_min_rtt);
		binn_object_set_uint32(binnobj, "tcpi_data_segs_in",
				       data->tcpi_data_segs_in);
		binn_object_set_uint32(binnobj, "tcpi_data_segs_out",
				       data->tcpi_data_segs_out);
	}
#endif

	/* delivery_rate_app_limited is a bitfield; gate on its u64 sibling. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	if (TCPI_FIELD_IN(tilen, tcpi_delivery_rate)) {
		binn_object_set_uint8(binnobj, "tcpi_delivery_rate_app_limited",
				      data->tcpi_delivery_rate_app_limited);
		binn_object_set_uint64(binnobj, "tcpi_delivery_rate",
				       data->tcpi_delivery_rate);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (TCPI_FIELD_IN(tilen, tcpi_rwnd_limited)) {
		binn_object_set_uint64(binnobj, "tcpi_busy_time",
				       data->tcpi_busy_time);
		binn_object_set_uint64(binnobj, "tcpi_sndbuf_limited",
				       data->tcpi_sndbuf_limited);
		binn_object_set_uint64(binnobj, "tcpi_rwnd_limited",
				       data->tcpi_rwnd_limited);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	if (TCPI_FIELD_IN(tilen, tcpi_delivered_ce)) {
		binn_object_set_uint32(binnobj, "tcpi_delivered",
				       data->tcpi_delivered);
		binn_object_set_uint32(binnobj, "tcpi_delivered_ce",
				       data->tcpi_delivered_ce);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
	if (TCPI_FIELD_IN(tilen, tcpi_reord_seen)) {
		binn_object_set_uint64(binnobj, "tcpi_bytes_sent",
				       data->tcpi_bytes_sent);
		binn_object_set_uint64(binnobj, "tcpi_bytes_retrans",
				       data->tcpi_bytes_retrans);
		binn_object_set_uint32(binnobj, "tcpi_dsack_dups",
				       data->tcpi_dsack_dups);
		binn_object_set_uint32(binnobj, "tcpi_reord_seen",
				       data->tcpi_reord_seen);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	if (TCPI_FIELD_IN(tilen, tcpi_rcv_ooopack)) {
		binn_object_set_uint32(binnobj, "tcpi_snd_wnd",
				       data->tcpi_snd_wnd);
		binn_object_set_uint32(binnobj, "tcpi_rcv_ooopack",
				       data->tcpi_rcv_ooopack);
	}
#endif

	/* fastopen_client_fail (5.5) is 2 bits packed into the SAME __u8 as
	 * delivery_rate_app_limited (4.9), so it grew the struct by 0 bytes and
	 * cannot be length-detected on its own; gate it on that 4.9 byte.  It
	 * reads 0 on 4.9-5.4 kernels (spare bits), meaningful on 5.5+. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
	if (TCPI_FIELD_IN(tilen, tcpi_delivery_rate)) {
		binn_object_set_uint8(binnobj, "tcpi_fastopen_client_fail",
				      data->tcpi_fastopen_client_fail);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
	if (TCPI_FIELD_IN(tilen, tcpi_rehash)) {
		binn_object_set_uint32(binnobj, "tcpi_rcv_wnd",
				       data->tcpi_rcv_wnd);
		binn_object_set_uint32(binnobj, "tcpi_rehash",
				       data->tcpi_rehash);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)
	if (TCPI_FIELD_IN(tilen, tcpi_total_rto_time)) {
		binn_object_set_uint16(binnobj, "tcpi_total_rto",
				       data->tcpi_total_rto);
		binn_object_set_uint16(binnobj, "tcpi_total_rto_recoveries",
				       data->tcpi_total_rto_recoveries);
		binn_object_set_uint32(binnobj, "tcpi_total_rto_time",
				       data->tcpi_total_rto_time);
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,18,0)
	/* accecn_fail_mode/accecn_opt_seen are bitfields (offsetof/sizeof are
	 * invalid on them), so gate on received_ce_bytes -- the last non-bitfield
	 * 6.18 member.  The bitfields ride the same struct version, so they are
	 * present whenever received_ce_bytes is. */
	if (TCPI_FIELD_IN(tilen, tcpi_received_ce_bytes)) {
		binn_object_set_uint32(binnobj, "tcpi_received_ce",
				       data->tcpi_received_ce);
		binn_object_set_uint32(binnobj, "tcpi_delivered_e1_bytes",
				       data->tcpi_delivered_e1_bytes);
		binn_object_set_uint32(binnobj, "tcpi_delivered_e0_bytes",
				       data->tcpi_delivered_e0_bytes);
		binn_object_set_uint32(binnobj, "tcpi_delivered_ce_bytes",
				       data->tcpi_delivered_ce_bytes);
		binn_object_set_uint32(binnobj, "tcpi_received_e1_bytes",
				       data->tcpi_received_e1_bytes);
		binn_object_set_uint32(binnobj, "tcpi_received_e0_bytes",
				       data->tcpi_received_e0_bytes);
		binn_object_set_uint32(binnobj, "tcpi_received_ce_bytes",
				       data->tcpi_received_ce_bytes);
		binn_object_set_uint16(binnobj, "tcpi_accecn_fail_mode",
				       data->tcpi_accecn_fail_mode);
		binn_object_set_uint16(binnobj, "tcpi_accecn_opt_seen",
				       data->tcpi_accecn_opt_seen);
	}
#endif
#endif /*endif for #ifdef __linux__ */
#endif /*endif for TCP_INFO */
}

/* this reads out the tcp_info binn object and formats it into a single line
 * the object will not necessarily have all of the elements. If it's empty it
 * current just spits out 0. This isn't optimal as 0 can also be a valid value */
void
metrics_read_binn_object (void *binnobj, char *output) {
	int len = 0;
	int buflen = 2047;	/* paired with the metricsstring malloc in the caller */
	if (binnobj == NULL) {
		fprintf(stderr, "Metric polling returned bad data.\n");
		return;
	}

	/* base set of metrics */
	len = snprintf(output, buflen, "%u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u",
		       binn_object_uint8(binnobj, "tcpi_state"),
		       binn_object_uint8(binnobj, "tcpi_ca_state"),
		       binn_object_uint8(binnobj, "tcpi_retransmits"),
		       binn_object_uint8(binnobj, "tcpi_probes"),
		       binn_object_uint8(binnobj, "tcpi_backoff"),
		       binn_object_uint8(binnobj, "tcpi_options"),
		       binn_object_uint8(binnobj, "tcpi_snd_wscale"),
		       binn_object_uint8(binnobj, "tcpi_rcv_wscale"),
		       binn_object_uint32(binnobj, "tcpi_rto"),
		       binn_object_uint32(binnobj, "tcpi_ato"),
		       binn_object_uint32(binnobj, "tcpi_snd_mss"),
		       binn_object_uint32(binnobj, "tcpi_rcv_mss"),
		       binn_object_uint32(binnobj, "tcpi_unacked"),
		       binn_object_uint32(binnobj, "tcpi_sacked"),
		       binn_object_uint32(binnobj, "tcpi_lost"),
		       binn_object_uint32(binnobj, "tcpi_retrans"),
		       binn_object_uint32(binnobj, "tcpi_fackets"),
		       binn_object_uint32(binnobj, "tcpi_last_data_sent"),
		       binn_object_uint32(binnobj, "tcpi_last_ack_sent"),
		       binn_object_uint32(binnobj, "tcpi_last_data_recv"),
		       binn_object_uint32(binnobj, "tcpi_last_ack_recv"),
		       binn_object_uint32(binnobj, "tcpi_pmtu"),
		       binn_object_uint32(binnobj, "tcpi_rcv_ssthresh"),
		       binn_object_uint32(binnobj, "tcpi_rtt"),
		       binn_object_uint32(binnobj, "tcpi_rttvar"),
		       binn_object_uint32(binnobj, "tcpi_snd_ssthresh"),
		       binn_object_uint32(binnobj, "tcpi_snd_cwnd"),
		       binn_object_uint32(binnobj, "tcpi_advmss"),
		       binn_object_uint32(binnobj, "tcpi_reordering"),
		       binn_object_uint32(binnobj, "tcpi_rcv_rtt"),
		       binn_object_uint32(binnobj, "tcpi_rcv_space"),
		       binn_object_uint32(binnobj, "tcpi_total_retrans")
		);

	/*
	 * Append the post-3.15 fields this record actually carries, keyed on
	 * which keys are present (see metrics_has).  No kernel-version compare:
	 * correct regardless of the local build kernel, and correct for a record
	 * produced by a remote host on a different kernel.  Column order MUST
	 * match metrics_print_header().
	 */
	if (metrics_has(binnobj, "tcpi_max_pacing_rate")) {
		len += snprintf(output+len, (buflen-len), ", %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_max_pacing_rate"),
				binn_object_uint64(binnobj, "tcpi_pacing_rate")
			);
	}

	if (metrics_has(binnobj, "tcpi_bytes_acked")) {
		len += snprintf(output+len, (buflen-len), ", %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_bytes_acked"),
				binn_object_uint64(binnobj, "tcpi_bytes_received")
			);
	}

	if (metrics_has(binnobj, "tcpi_segs_in")) {
		len += snprintf(output+len, (buflen-len), ", %u, %u",
				binn_object_uint32(binnobj, "tcpi_segs_in"),
				binn_object_uint32(binnobj, "tcpi_segs_out")
			);
	}

	if (metrics_has(binnobj, "tcpi_notsent_bytes")) {
		len += snprintf(output+len, (buflen-len), ", %u, %u, %u, %u",
				binn_object_uint32(binnobj, "tcpi_notsent_bytes"),
				binn_object_uint32(binnobj, "tcpi_min_rtt"),
				binn_object_uint32(binnobj, "tcpi_data_segs_in"),
				binn_object_uint32(binnobj, "tcpi_data_segs_out")
			);
	}

	if (metrics_has(binnobj, "tcpi_delivery_rate_app_limited")) {
		len += snprintf(output+len, (buflen-len), ", %u, %llu",
				binn_object_uint8(binnobj, "tcpi_delivery_rate_app_limited"),
				binn_object_uint64(binnobj, "tcpi_delivery_rate")
			);
	}

	if (metrics_has(binnobj, "tcpi_busy_time")) {
		len += snprintf(output+len, (buflen-len), ", %llu, %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_busy_time"),
				binn_object_uint64(binnobj, "tcpi_sndbuf_limited"),
				binn_object_uint64(binnobj, "tcpi_rwnd_limited")
			);
	}

	if (metrics_has(binnobj, "tcpi_delivered")) {
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_delivered")
			);
	}

	/* delivered_ce is per-key: Linux emits it with tcpi_delivered (4.18),
	 * FreeBSD emits it standalone -- same column either way. */
	if (metrics_has(binnobj, "tcpi_delivered_ce")) {
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_delivered_ce")
			);
	}

	if (metrics_has(binnobj, "tcpi_bytes_sent")) {
		len += snprintf(output+len, (buflen-len), ", %llu, %llu, %u, %u",
				binn_object_uint64(binnobj, "tcpi_bytes_sent"),
				binn_object_uint64(binnobj, "tcpi_bytes_retrans"),
				binn_object_uint32(binnobj, "tcpi_dsack_dups"),
				binn_object_uint32(binnobj, "tcpi_reord_seen")
			);
	}

	if (metrics_has(binnobj, "tcpi_snd_wnd")) {
		len += snprintf(output+len, (buflen-len), ", %u, %u",
				binn_object_uint32(binnobj, "tcpi_snd_wnd"),
				binn_object_uint32(binnobj, "tcpi_rcv_ooopack")
			);
	}

	if (metrics_has(binnobj, "tcpi_fastopen_client_fail")) {
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint8(binnobj, "tcpi_fastopen_client_fail")
			);
	}

	if (metrics_has(binnobj, "tcpi_rcv_wnd")) {
		len += snprintf(output+len, (buflen-len), ", %u, %u",
				binn_object_uint32(binnobj, "tcpi_rcv_wnd"),
				binn_object_uint32(binnobj, "tcpi_rehash")
			);
	}

	if (metrics_has(binnobj, "tcpi_total_rto")) {
		len += snprintf(output+len, (buflen-len), ", %u, %u, %u",
				binn_object_uint16(binnobj, "tcpi_total_rto"),
				binn_object_uint16(binnobj, "tcpi_total_rto_recoveries"),
				binn_object_uint32(binnobj, "tcpi_total_rto_time")
			);
	}

	/* received_ce is per-key: Linux emits it with the AccECN block (6.18),
	 * FreeBSD emits it standalone -- same column either way. */
	if (metrics_has(binnobj, "tcpi_received_ce")) {
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_received_ce")
			);
	}

	/* The rest of the Linux 6.18 AccECN block; gated on a 6.18-only key so
	 * it does not fire for a FreeBSD record that only carries received_ce. */
	if (metrics_has(binnobj, "tcpi_accecn_opt_seen")) {
		len += snprintf(output+len, (buflen-len),
				", %u, %u, %u, %u, %u, %u, %u, %u",
				binn_object_uint32(binnobj, "tcpi_delivered_e1_bytes"),
				binn_object_uint32(binnobj, "tcpi_delivered_e0_bytes"),
				binn_object_uint32(binnobj, "tcpi_delivered_ce_bytes"),
				binn_object_uint32(binnobj, "tcpi_received_e1_bytes"),
				binn_object_uint32(binnobj, "tcpi_received_e0_bytes"),
				binn_object_uint32(binnobj, "tcpi_received_ce_bytes"),
				binn_object_uint16(binnobj, "tcpi_accecn_fail_mode"),
				binn_object_uint16(binnobj, "tcpi_accecn_opt_seen")
			);
	}

	/*
	 * FreeBSD / OpenBSD tcp_info extensions (per-key; absent on Linux
	 * records, so these add no columns there).  Order MUST match
	 * metrics_print_header().
	 */
	if (metrics_has(binnobj, "tcpi_total_tlp"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_total_tlp"));
	if (metrics_has(binnobj, "tcpi_total_tlp_bytes"))
		len += snprintf(output+len, (buflen-len), ", %llu",
				binn_object_uint64(binnobj, "tcpi_total_tlp_bytes"));
	if (metrics_has(binnobj, "tcpi_rcv_numsacks"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_rcv_numsacks"));
	if (metrics_has(binnobj, "tcpi_dupacks"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_dupacks"));
	if (metrics_has(binnobj, "tcpi_max_sndwnd"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_max_sndwnd"));
	if (metrics_has(binnobj, "tcpi_rttmin"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_rttmin"));
	if (metrics_has(binnobj, "tcpi_rcv_adv"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_rcv_adv"));
	if (metrics_has(binnobj, "tcpi_ts_recent"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_ts_recent"));
	if (metrics_has(binnobj, "tcpi_rfbuf_cnt"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_rfbuf_cnt"));
	if (metrics_has(binnobj, "tcpi_rfbuf_ts"))
		len += snprintf(output+len, (buflen-len), ", %u",
				binn_object_uint32(binnobj, "tcpi_rfbuf_ts"));
	if (metrics_has(binnobj, "tcpi_so_rcv_sb_cc"))
		len += snprintf(output+len, (buflen-len), ", %u, %u, %u, %u",
				binn_object_uint32(binnobj, "tcpi_so_rcv_sb_cc"),
				binn_object_uint32(binnobj, "tcpi_so_rcv_sb_hiwat"),
				binn_object_uint32(binnobj, "tcpi_so_rcv_sb_lowat"),
				binn_object_uint32(binnobj, "tcpi_so_rcv_sb_wat"));
	if (metrics_has(binnobj, "tcpi_so_snd_sb_cc"))
		len += snprintf(output+len, (buflen-len), ", %u, %u, %u, %u",
				binn_object_uint32(binnobj, "tcpi_so_snd_sb_cc"),
				binn_object_uint32(binnobj, "tcpi_so_snd_sb_hiwat"),
				binn_object_uint32(binnobj, "tcpi_so_snd_sb_lowat"),
				binn_object_uint32(binnobj, "tcpi_so_snd_sb_wat"));
}

/* Print out the header to the file so that the column header matches the
 * data in the metrics object. The post-3.15 columns vary by what the
 * producing kernel returned, so we test the SAME key presence the reader uses
 * (metrics_read_binn_object) -- header and data row stay in lockstep with no
 * kernel-version compare.  NOTE: This doesn't put the values/headers in the
 * most useful order but the resulting file is probably going to get processed
 * by something */
void
metrics_print_header(FILE *fptr, char *extra_text, void *binnobj) {
	char *krel = binn_object_str(binnobj, "kernel_release");

	if (extra_text != NULL) {
		fprintf(fptr, "%s (kernel %s)\n", extra_text,
			krel != NULL ? krel : "unknown");
	}
	fprintf(fptr, "timestamp, state, ca_state, retransmits, probes, backoff, options, ");
	fprintf(fptr, "snd_wscale, rcv_wscale, rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, ");
	fprintf(fptr, "fackets, last_data_sent, last_ack_sent, last_data_recv, ");
	fprintf(fptr, "last_ack_recv, pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, ");
	fprintf(fptr, "snd_cwnd, advmss, reordering, rcv_rtt, rcv_space, total_retrans");

	/* Column names for the post-3.15 fields this record carries, keyed on
	 * presence so the header always matches the data row.  Order MUST match
	 * metrics_read_binn_object(). */
	if (metrics_has(binnobj, "tcpi_max_pacing_rate"))
		fprintf(fptr, ", max_pacing_rate, pacing_rate");
	if (metrics_has(binnobj, "tcpi_bytes_acked"))
		fprintf(fptr, ", bytes_acked, bytes_received");
	if (metrics_has(binnobj, "tcpi_segs_in"))
		fprintf(fptr, ", segs_in, segs_out");
	if (metrics_has(binnobj, "tcpi_notsent_bytes"))
		fprintf(fptr, ", notsent_bytes, min_rtt, data_segs_in, data_seg_out");
	if (metrics_has(binnobj, "tcpi_delivery_rate_app_limited"))
		fprintf(fptr, ", delivery_rate_app_limited, delivery_rate");
	if (metrics_has(binnobj, "tcpi_busy_time"))
		fprintf(fptr, ", busy_time, sndbuf_limited, rwnd_limited");
	if (metrics_has(binnobj, "tcpi_delivered"))
		fprintf(fptr, ", delivered");
	if (metrics_has(binnobj, "tcpi_delivered_ce"))
		fprintf(fptr, ", delivered_ce");
	if (metrics_has(binnobj, "tcpi_bytes_sent"))
		fprintf(fptr, ", bytes_sent, bytes_retrans, dsack_dups, reord_seen");
	if (metrics_has(binnobj, "tcpi_snd_wnd"))
		fprintf(fptr, ", snd_wnd, rcv_ooopack");
	if (metrics_has(binnobj, "tcpi_fastopen_client_fail"))
		fprintf(fptr, ", fastopen_client_fail");
	if (metrics_has(binnobj, "tcpi_rcv_wnd"))
		fprintf(fptr, ", rcv_wnd, rehash");
	if (metrics_has(binnobj, "tcpi_total_rto"))
		fprintf(fptr, ", total_rto, total_rto_recoveries, total_rto_time");
	if (metrics_has(binnobj, "tcpi_received_ce"))
		fprintf(fptr, ", received_ce");
	if (metrics_has(binnobj, "tcpi_accecn_opt_seen"))
		fprintf(fptr, ", delivered_e1_bytes, delivered_e0_bytes, "
			"delivered_ce_bytes, received_e1_bytes, received_e0_bytes, "
			"received_ce_bytes, accecn_fail_mode, accecn_opt_seen");

	/* FreeBSD / OpenBSD tcp_info extension columns (order MUST match
	 * metrics_read_binn_object). */
	if (metrics_has(binnobj, "tcpi_total_tlp"))
		fprintf(fptr, ", total_tlp");
	if (metrics_has(binnobj, "tcpi_total_tlp_bytes"))
		fprintf(fptr, ", total_tlp_bytes");
	if (metrics_has(binnobj, "tcpi_rcv_numsacks"))
		fprintf(fptr, ", rcv_numsacks");
	if (metrics_has(binnobj, "tcpi_dupacks"))
		fprintf(fptr, ", dupacks");
	if (metrics_has(binnobj, "tcpi_max_sndwnd"))
		fprintf(fptr, ", max_sndwnd");
	if (metrics_has(binnobj, "tcpi_rttmin"))
		fprintf(fptr, ", rttmin");
	if (metrics_has(binnobj, "tcpi_rcv_adv"))
		fprintf(fptr, ", rcv_adv");
	if (metrics_has(binnobj, "tcpi_ts_recent"))
		fprintf(fptr, ", ts_recent");
	if (metrics_has(binnobj, "tcpi_rfbuf_cnt"))
		fprintf(fptr, ", rfbuf_cnt");
	if (metrics_has(binnobj, "tcpi_rfbuf_ts"))
		fprintf(fptr, ", rfbuf_ts");
	if (metrics_has(binnobj, "tcpi_so_rcv_sb_cc"))
		fprintf(fptr, ", so_rcv_sb_cc, so_rcv_sb_hiwat, so_rcv_sb_lowat, "
			"so_rcv_sb_wat");
	if (metrics_has(binnobj, "tcpi_so_snd_sb_cc"))
		fprintf(fptr, ", so_snd_sb_cc, so_snd_sb_hiwat, so_snd_sb_lowat, "
			"so_snd_sb_wat");
	fprintf(fptr, "\n\n");
}
