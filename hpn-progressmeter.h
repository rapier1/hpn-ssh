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

/* hpn-progressmeter.h - the status-frame emitter's interface.
 *
 * The transfer clients arm frame mode and push telemetry through the
 * hpn_pm_* calls, and the meter hands each view and meter boundary to the
 * emitter through the calls at the end of this file. The dependency runs
 * one way, from the meter to the frames, and the emitter never calls back
 * into the meter. hpn-status-frame.h defines the frame format. */
#ifndef HPN_PROGRESSMETER_H
#define HPN_PROGRESSMETER_H

#include <sys/types.h>

struct meter_view;

/* The producer side. The transfer clients and the parallel reporter call
 * these to arm frame mode, push telemetry, and report failed and finished
 * files. progressmeter.h includes this header, so its callers reach both
 * the meter and the frame side through it. */
void	hpn_pm_frame_mode(u_int);
int	hpn_pm_active(void);
void	hpn_pm_set_workers(u_int, u_int);
void	hpn_pm_set_files(u_int, u_int);
void	hpn_pm_count_file(void);
void	hpn_pm_set_phase(u_int, int);
void	hpn_pm_filefail(u_int, const char *, size_t);
void	hpn_pm_filedone(u_int, off_t, const char *, size_t);
void	hpn_pm_end(int, u_int);

/* The meter's calls into the emitter, made only by the meter in
 * progressmeter.c and hpn-meter.c. They hand over each view, and say when
 * a meter starts and finishes and how many files it represents. */
void	hpn_pm_emit_view(const struct meter_view *, int);
void	hpn_pm_meter_start(void);
void	hpn_pm_meter_not_a_file(void);
void	hpn_pm_meter_files(u_int);
void	hpn_pm_meter_done(off_t, off_t, long long);

#endif /* HPN_PROGRESSMETER_H */
