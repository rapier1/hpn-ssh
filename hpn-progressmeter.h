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

/*
 * hpn-progressmeter.h - HPN progress/status-frame telemetry domain.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * The binary status-frame half of the progress subsystem, extracted from
 * progressmeter.c so the TTY meter (progressmeter.c) and the frame emitter
 * (hpn-progressmeter.c) are separate translation units.  See
 * hpn-status-relay-design.md for the frame protocol.
 *
 * The dependency runs one way, meter -> frames: progressmeter.c drives this
 * module through the three seams below, passing its freshly computed meter
 * state by value.  The frame domain never reaches back into the meter.
 */
#ifndef HPN_PROGRESSMETER_H
#define HPN_PROGRESSMETER_H

/*
 * Producer API (hpn_pm_*).  The transfer clients call these to arm frame
 * mode and push telemetry; progressmeter.h includes this header so a caller
 * needs only "progressmeter.h" to reach both the meter and the frame side.
 */
void	hpn_pm_frame_mode(u_int);
int	hpn_pm_active(void);
void	hpn_pm_set_workers(u_int, u_int);
void	hpn_pm_set_files(u_int, u_int);
void	hpn_pm_meter_not_a_file(void);
void	hpn_pm_meter_files(u_int);
void	hpn_pm_count_file(void);
void	hpn_pm_set_phase(u_int, int);
void	hpn_pm_filefail(u_int, const char *, size_t);
void	hpn_pm_filedone(u_int, long long, const char *, size_t);
void	hpn_pm_end(int, u_int);

/*
 * Per-meter render currency (Stage 2).  One meter's freshly computed
 * numbers, filled by whichever producer is live - the local rate math or
 * the relay's frame ingest - and consumed by the sinks: the TTY renderer
 * paints a line from it, and the frame sink projects it to the wire
 * (overlaying the cross-file aggregate + dropping the label).  PER-METER,
 * never aggregated: the frame sink adds the running total itself, so this
 * struct stays free of frame-domain state and the wire's "no label"
 * invariant is preserved at the projection.
 */
struct meter_view {
	const char	*label;		/* TTY paints it; the wire drops it */
	off_t		 cur;		/* this meter's position */
	off_t		 total;		/* this meter's target (0 = unknown) */
	long long	 rate;		/* smoothed bytes/sec */
	long long	 inst;		/* instantaneous; each filler picks its
					 * own peak scheme and writes it here */
	off_t		 delta;		/* raw bytes since last sample - the
					 * frame sink derives its per-second
					 * rate_inst = delta/elapsed, distinct
					 * from the display inst above */
	double		 elapsed;	/* raw seconds since last sample */
	uint32_t	 eta_sec;	/* HPNS_ETA_UNKNOWN if not derivable */
	int		 stalled;	/* no progress for STALL_TIME */
	int		 done;		/* transfer complete */
	int		 percent;	/* 0..100, filler-computed: an unknown
					 * (0) total reads 100% for a local
					 * meter but 0% on the relay, so the
					 * policy lives in the fill, not the
					 * shared renderer */
	long		 elapsed_sec;	/* wall-clock, for the DONE line */
};

/*
 * Meter -> frame seams (called only from progressmeter.c):
 *   hpn_pm_emit_view   - build and emit one PROGRESS frame from a filled
 *                        meter_view (rate limited unless forced).  Reads the
 *                        view's cur/total/rate + raw delta/elapsed (for the
 *                        per-second instantaneous rate) and overlays the
 *                        cross-file aggregate + phase flags itself.
 *   hpn_pm_meter_start - a new per-file meter is starting: mark it a file
 *                        and clear the phase flags.
 *   hpn_pm_meter_done  - a meter finished: emit a boundary frame and fold
 *                        its bytes/file into the running totals.
 */
void	hpn_pm_emit_view(const struct meter_view *, int);
void	hpn_pm_meter_start(void);
void	hpn_pm_meter_done(off_t, off_t, long long);

#endif /* HPN_PROGRESSMETER_H */
