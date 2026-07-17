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
void	hpn_pm_count_file(void);
void	hpn_pm_set_phase(u_int, int);
void	hpn_pm_filefail(u_int, const char *, size_t);
void	hpn_pm_filedone(u_int, long long, const char *, size_t);
void	hpn_pm_end(int, u_int);

/*
 * Meter -> frame seams (called only from progressmeter.c).  Everything the
 * frame emitter needs from the live meter arrives here by value:
 *   hpn_pm_emit             - build and emit one PROGRESS frame from
 *                                   the meter's current position and rate
 *                                   (rate limited unless forced).
 *   hpn_pm_meter_start - a new per-file meter is starting: mark
 *                                   it a file and clear the phase flags.
 *   hpn_pm_meter_done  - a meter finished: emit a boundary frame
 *                                   and fold its bytes/file into the running
 *                                   totals.
 * Args carry cur_pos, end_pos (off_t) and bytes_per_second + rate_inst
 * (long long) - the meter statics the emitter used to read directly.
 */
void	hpn_pm_emit(off_t, off_t, long long, long long, int);
void	hpn_pm_meter_start(void);
void	hpn_pm_meter_done(off_t, off_t, long long);

#endif /* HPN_PROGRESSMETER_H */
