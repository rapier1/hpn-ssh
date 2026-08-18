/* $OpenBSD: progressmeter.h,v 1.5 2019/01/24 16:52:17 dtucker Exp $ */
/*
 * Copyright (c) 2002 Nils Nordman.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "hpn-status-frame.h"
/*
 * The binary status-frame API (hpn_pm_*) lives in hpn-progressmeter.c; its
 * declarations are in hpn-progressmeter.h, included here so existing
 * "progressmeter.h" call sites still see them.
 */
#include "hpn-progressmeter.h"

void	start_progress_meter(const char *, off_t, off_t *);
void	refresh_progress_meter(int);
void	stop_progress_meter(void);

/* Sink dispatch and display session mechanics, exported for the hpn-meter
 * core (hpn-meter.c): the core owns meter state and the fill, this file
 * owns the alarm, the TTY, the log guard, and the sinks. */
void	pm_dispatch_view(const struct meter_view *, int);
void	pm_display_begin(void);
void	pm_display_end(off_t, off_t, off_t, double);

/* Display session for the relay source in hpn-meter.c, which renders
 * remote telemetry only (no local rate/ETA derivation - frame arrival
 * timing aliases). */
void	pm_display_begin_relay(void);
void	pm_display_end_relay(void);
