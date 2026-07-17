/* $OpenBSD: progressmeter.c,v 1.57 2026/03/29 01:08:13 djm Exp $ */
/*
 * Copyright (c) 2003 Nils Nordman.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "progressmeter.h"
#include "atomicio.h"
#include "hpn-status-frame.h"
#include "hpn-progressmeter.h"
#include "log.h"
#include "misc.h"
#include "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* determines whether we can output to the terminal */
static int can_output(void);

/* window resizing */
static void sig_winch(int);
static void setscreensize(void);

/* signal handler for updating the progress meter */
static void sig_alarm(int);

static double start;		/* start progress */
static double last_update;	/* last progress update */
static const char *file;	/* name of the file being transferred */
static off_t start_pos;		/* initial position of transfer */
static off_t end_pos;		/* ending position of transfer */
static off_t cur_pos;		/* transfer position as of last refresh */
static off_t last_pos;
/* HPN log/meter interleave guard state (see meter_log_enter below). */
static pthread_mutex_t meter_mu = PTHREAD_MUTEX_INITIALIZER;
static int meter_active;
static off_t max_delta_pos = 0;
static volatile off_t *counter;	/* progress counter */
static long stalled;		/* how long we have been stalled */
static long long bytes_per_second; /* current speed in bytes per second */
static int win_size;		/* terminal window size */
static volatile sig_atomic_t win_resized; /* for window resizing */
static volatile sig_atomic_t alarm_fired;

/*
 * HPN status relay, consumer side: render remote telemetry verbatim.
 * Everything painted comes from the last PROGRESS frame - no rate, delta,
 * or ETA is ever derived locally, because the counter would advance only
 * when a ~1 Hz frame lands and sampling that against the local clock
 * aliases (alternating 0 and 2x-link-speed readings).  Opt-in: only the
 * frame consumers (scp -R, hpn3scp) enter this mode; local meters never
 * touch it and their math path is unchanged.
 */
static int relay_mode;
static struct {
	uint64_t bytes_done;
	uint64_t bytes_total;
	uint64_t rate;		/* source-smoothed */
	uint64_t rate_inst;	/* source last-interval */
	uint64_t rate_inst_max;	/* peak inst within the current phase */
	uint64_t rate_inst_peak_xfer;	/* transfer-phase peak, latched at the
					 * verify transition: the completion
					 * line summarizes the TRANSFER, and a
					 * verify-phase hash peak (legitimately
					 * above link speed) would read as an
					 * impossible network rate there */
	uint32_t eta_sec;
	int	 verifying;	/* HPNS_F_VERIFY seen: label the phase */
	int	 resuming;	/* HPNS_F_RESUME live: label the phase */
	int	 done;		/* END received: paint the 100% line */
	double	 last_frame;	/* monotime of the last sample (stall aging) */
	double	 started;
} relay;
static off_t relay_ctr;		/* placeholder counter for the meter core */

/* units for format_size */
static const char unit[] = " KMGT";

static int
can_output(void)
{
	return (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/* size needed to format integer type v, using (nbits(v) * log2(10) / 10) */
#define STRING_SIZE(v) (((sizeof(v) * 8 * 4) / 10) + 1)

static const char *
format_rate(off_t bytes)
{
	int i;
	static char buf[STRING_SIZE(bytes) * 2 + 16];

	bytes *= 100;
	for (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	if (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	snprintf(buf, sizeof(buf), "%3lld.%1lld%cB",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
	return buf;
}

static const char *
format_size(off_t bytes)
{
	int i;
	static char buf[STRING_SIZE(bytes) + 16];

	for (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(buf, sizeof(buf), "%4lld%c%s",
	    (long long) bytes,
	    unit[i],
	    i ? "B" : " ");
	return buf;
}

/* tail of the meter line, after the two rate columns */
enum meter_tail {
	METER_TAIL_STALLED,	/* "- stalled -" */
	METER_TAIL_UNKNOWN,	/* "  --:-- ETA" */
	METER_TAIL_ETA,		/* time remaining + " ETA" */
	METER_TAIL_DONE		/* time elapsed, no suffix */
};

/*
 * Compose and paint one meter line: label, percent, transferred amount,
 * smoothed rate, instantaneous rate, then the tail.  Pure output - the
 * caller supplies every value, so the local math path and the relay
 * (remote telemetry) path render through one code path and cannot drift
 * apart visually.  Extracted verbatim from the original refresh paint.
 */
static void
render_meter_line(const char *label, int percent, off_t bytes_shown,
    long long rate, off_t inst_rate, enum meter_tail tail, long tail_seconds)
{
	char *buf = NULL, *obuf = NULL;
	int hours, minutes, seconds;
	int file_len, cols;

	/* Don't bother if we can't even display the completion percentage */
	if (win_size < 4)
		return;

	/* filename / label */
	file_len = cols = win_size - 45;
	if (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, label);
		/* If we used fewer columns than expected then pad */
		if (cols < file_len)
			xextendf(&buf, NULL, "%*s", file_len - cols, "");
	}

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, NULL, " %3d%% %s %s/s ", percent,
	    format_size(bytes_shown), format_rate((off_t)rate));

	/* instantaneous rate */
	xextendf(&buf, NULL, "%s/s", format_rate(inst_rate));

	switch (tail) {
	case METER_TAIL_STALLED:
		xextendf(&buf, NULL, "- stalled -");
		break;
	case METER_TAIL_UNKNOWN:
		xextendf(&buf, NULL, "  --:-- ETA");
		break;
	case METER_TAIL_ETA:
	case METER_TAIL_DONE:
		seconds = (int)tail_seconds;
		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;
		if (hours != 0) {
			xextendf(&buf, NULL, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} else
			xextendf(&buf, NULL, "  %02d:%02d", minutes, seconds);
		xextendf(&buf, NULL,
		    tail == METER_TAIL_ETA ? " ETA" : "    ");
		break;
	}

	/* Finally, truncate string at window width */
	cols = win_size - 1;
	asmprintf(&obuf, INT_MAX, &cols, " %s", buf);
	if (obuf != NULL) {
		*obuf = '\r'; /* must insert as asmprintf() would escape it */
		/* HPN: serialise against log output (meter_log_enter) so a
		 * redraw never interleaves with a log line mid-write. */
		pthread_mutex_lock(&meter_mu);
		atomicio(vwrite, STDOUT_FILENO, obuf, strlen(obuf));
		pthread_mutex_unlock(&meter_mu);
	}
	free(buf);
	free(obuf);
}

/*
 * Relay-mode paint: everything shown comes from the stored frame
 * telemetry.  The only local inputs are wall-clock ages: total elapsed
 * for the completion line and the last-frame age for stall detection
 * (a dead source must not keep displaying its final healthy rate).
 */
static void
relay_render(void)
{
	char vlabel[512];
	const char *label = file;
	double now = monotime_double();
	enum meter_tail tail;
	long tsec = 0;
	off_t inst;
	int percent;

	if (relay.done || (relay.bytes_total > 0 &&
	    relay.bytes_done >= relay.bytes_total))
		percent = 100;
	else if (relay.bytes_total > 0)
		percent = (int)(relay.bytes_done * 100 / relay.bytes_total);
	else
		percent = 0;

	if (relay.done) {
		tail = METER_TAIL_DONE;
		tsec = (long)(now - relay.started);
		/* peak, like local - the TRANSFER peak when a verify phase
		 * followed (its hash peak is not a network rate) */
		inst = (off_t)(relay.rate_inst_peak_xfer > 0 ?
		    relay.rate_inst_peak_xfer : relay.rate_inst_max);
	} else if (now - relay.last_frame >= STALL_TIME) {
		tail = METER_TAIL_STALLED;
		inst = 0;
	} else if (relay.rate == 0 || relay.eta_sec == HPNS_ETA_UNKNOWN) {
		tail = METER_TAIL_UNKNOWN;
		inst = (off_t)relay.rate_inst;
	} else {
		tail = METER_TAIL_ETA;
		tsec = (long)relay.eta_sec;
		inst = (off_t)relay.rate_inst;
	}

	/* PREFIX the phase tag: the label field truncates at the right edge
	 * (win_size - 45), so a suffix vanishes on narrow terminals.  The
	 * resume check precedes transfer; verify follows it - mutually
	 * exclusive in practice, resume checked first. */
	if (relay.resuming && label != NULL) {
		snprintf(vlabel, sizeof(vlabel), "resume check: %s", label);
		label = vlabel;
	} else if (relay.verifying && label != NULL) {
		snprintf(vlabel, sizeof(vlabel), "verify: %s", label);
		label = vlabel;
	}
	render_meter_line(label, percent, (off_t)relay.bytes_done,
	    tail == METER_TAIL_STALLED ? 0 : (long long)relay.rate,
	    inst, tail, tsec);
}

void
refresh_progress_meter(int force_update)
{
	off_t transferred;
	double elapsed, now;
	int percent;
	off_t bytes_left;
	long long cur_speed;
	long tail_seconds;
	enum meter_tail tail;
	off_t delta_pos;

	if (file == NULL || (!force_update && !alarm_fired && !win_resized) ||
	    (!hpn_pm_active() && !can_output()))
		return;
	alarm_fired = 0;

	if (win_resized) {
		if (!hpn_pm_active())
			setscreensize();
		win_resized = 0;
	}

	/* HPN status relay consumer: paint the stored remote telemetry and
	 * skip every local derivation (see relay_render). */
	if (relay_mode) {
		relay_render();
		return;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	/* HPN: the parallel aggregate can step BACKWARD - a worker dying
	 * mid-unit takes its in-progress bytes out of the aggregate until
	 * the requeued unit re-transfers them.  A negative step poisons the
	 * rate math (the EMA explodes through format_rate's cast - 81.3TB/s -
	 * or prints negative garbage).  Clamp: the meter pauses through the
	 * dip instead of exploding. */
	if (transferred < 0)
		transferred = 0;
	cur_pos = *counter;
	now = monotime_double();
	bytes_left = end_pos - cur_pos;

	delta_pos = cur_pos - last_pos;
	if (delta_pos < 0)
		delta_pos = 0;
	if (delta_pos > max_delta_pos)
		max_delta_pos = delta_pos;

	if (bytes_left > 0)
		elapsed = now - last_update;
	else {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed.  HPN: require a measurable window - back-to-back
	 * refreshes (alarm + forced update) give elapsed ~1 microsecond,
	 * which passes a !=0 test and explodes the division by 10^6 (the
	 * 984.6TB/s artifact); the poisoned EMA then decays for many ticks.
	 * Under 1ms there is nothing meaningful to measure: hold the EMA. */
	if (elapsed >= 0.001)
		cur_speed = (transferred / elapsed);
	else
		cur_speed = bytes_per_second;

#define AGE_FACTOR 0.9
	if (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} else
		bytes_per_second = cur_speed;

	last_update = now;

	/* HPN status relay: frame mode replaces the ANSI paint entirely -
	 * emit a binary PROGRESS frame from the freshly computed state and
	 * skip all terminal work below.  The instantaneous rate rides in
	 * the frame because a consumer cannot derive it from arrival times
	 * (see relay_render). */
	if (hpn_pm_active()) {
		long long rate_inst;

		if (bytes_left > 0 && elapsed >= 0.001)
			rate_inst = (long long)(delta_pos / elapsed);
		else
			rate_inst = 0;
		hpn_pm_emit(cur_pos, end_pos, bytes_per_second,
		    rate_inst, force_update);
		last_pos = cur_pos;
		return;
	}

	/* percent of transfer done.  Clamp at 100: the resume-check stretch
	 * can shrink the total (a hash-op marker going stale) under a
	 * ratcheted counter, and >100% must never render. */
	if (end_pos == 0 || cur_pos >= end_pos)
		percent = 100;
	else
		percent = ((float)cur_pos / end_pos) * 100;

	/* ETA tail: same decision order as the historic inline paint */
	if (!transferred)
		stalled += elapsed;
	else
		stalled = 0;

	if (stalled >= STALL_TIME) {
		tail = METER_TAIL_STALLED;
		tail_seconds = 0;
	} else if (bytes_per_second == 0 && bytes_left) {
		tail = METER_TAIL_UNKNOWN;
		tail_seconds = 0;
	} else if (bytes_left > 0) {
		tail = METER_TAIL_ETA;
		tail_seconds = (long)(bytes_left / bytes_per_second);
	} else {
		tail = METER_TAIL_DONE;
		tail_seconds = (long)elapsed;
	}

	render_meter_line(file, percent, cur_pos, bytes_per_second,
	    bytes_left > 0 ? delta_pos : max_delta_pos, tail, tail_seconds);
	last_pos = cur_pos;
}

/*
 * HPN log/meter interleave guard.  Registered with log.c whenever a
 * meter is running: before a log line is written, take the lock and
 * clear the meter's line so the message lands whole at column 0; the
 * meter repaints on its next refresh.  Redraws are never driven from
 * signal context (sig_alarm only sets a flag), so a plain mutex is
 * safe here.
 */
static void
meter_log_enter(void)
{
	pthread_mutex_lock(&meter_mu);
	if (meter_active)
		atomicio(vwrite, STDOUT_FILENO, "\r\033[K", 4);
}

static void
meter_log_exit(void)
{
	pthread_mutex_unlock(&meter_mu);
}

static void
sig_alarm(int ignore)
{
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

/*
 * TTY-side arming shared by the local and relay meter starts: log/meter
 * interleave guard, window sizing, and the WINCH handler.  Frame mode
 * never calls this - stdout is its binary channel, and the guard's
 * "\r\033[K" or a screen-size ioctl make no sense on a pipe.
 */
static void
meter_tty_arm(void)
{
	pthread_mutex_lock(&meter_mu);
	meter_active = 1;
	pthread_mutex_unlock(&meter_mu);
	log_set_output_guard(meter_log_enter, meter_log_exit);
	setscreensize();
	ssh_signal(SIGWINCH, sig_winch);
}

void
start_progress_meter(const char *f, off_t filesize, off_t *ctr)
{
	start = last_update = monotime_double();
	file = f;
	hpn_pm_meter_start();
	relay_mode = 0;			/* local meter unless the relay APIs
					 * re-arm it (pm_relay_*) */
	max_delta_pos = 0;		/* peak-inst is per meter; carrying it
					 * across meters leaked the previous
					 * transfer's peak into this one */
	start_pos = *ctr;
	end_pos = filesize;
	cur_pos = 0;
	/* Seed last_pos at the starting position: a resumed transfer's
	 * counter begins at the resume offset, and a zero last_pos would
	 * paint that whole offset as the first instantaneous rate (then
	 * latch it as the run's peak via max_delta_pos). */
	last_pos = *ctr;
	counter = ctr;
	stalled = 0;
	bytes_per_second = 0;

	/*
	 * Frame mode skips the TTY arming (stdout is its binary channel)
	 * AND the initial forced paint: phase callers set their flag
	 * (set_phase) only AFTER this returns (the reset above would clear
	 * it), so a frame emitted here would carry cleared flags and the
	 * wrong byte base - one mislabeled frame at every phase boundary.
	 * The alarm / reporter tick emits a correctly-flagged frame within
	 * a second; nothing is lost.
	 */
	if (!hpn_pm_active()) {
		meter_tty_arm();
		refresh_progress_meter(1);
	}

	ssh_signal(SIGALRM, sig_alarm);
	alarm(UPDATE_INTERVAL);
}

void
stop_progress_meter(void)
{
	alarm(0);

	pthread_mutex_lock(&meter_mu);
	meter_active = 0;
	pthread_mutex_unlock(&meter_mu);

	/*
	 * Frame mode: fold the finished meter into the aggregate so the
	 * next meter's frames continue the running totals (serial scp runs
	 * one meter per file).  A boundary frame is emitted through the
	 * regular limiter - if it is dropped, the next 1 Hz tick or the
	 * final END frame carries the totals.
	 */
	if (hpn_pm_active()) {
		if (file != NULL) {
			if (counter != NULL)
				cur_pos = *counter;
			hpn_pm_meter_done(cur_pos, end_pos,
			    bytes_per_second);
			cur_pos = 0;
		}
		file = NULL;
		return;
	}

	/* Relay meter: the completion line was painted by relay_end();
	 * just drop out of relay mode and finish with the newline. */
	relay_mode = 0;

	if (!can_output())
		return;

	/* Ensure we complete the progress */
	if (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = NULL;
}

/*
 * Relay mode (consumer side): begin a meter whose every displayed value
 * comes from remote PROGRESS frames.  Reuses the meter core for the
 * alarm, window sizing, and log interleave, but relay_render() bypasses
 * all local rate/delta/ETA math - see the relay struct above for why.
 */
void
pm_relay_start(const char *label)
{
	/*
	 * Own initialization instead of borrowing start_progress_meter():
	 * its local path would paint a bogus "100% 0.0KB/s" line before
	 * the first frame arrives.  cur_pos == end_pos == 0 also keeps the
	 * final local repaint in stop_progress_meter() skipped - relay_end
	 * paints the completion line itself.
	 */
	relay_ctr = 0;
	file = label;
	counter = &relay_ctr;
	start_pos = end_pos = cur_pos = last_pos = 0;
	stalled = 0;
	bytes_per_second = 0;
	meter_tty_arm();
	memset(&relay, 0, sizeof(relay));
	relay.started = relay.last_frame = monotime_double();
	relay_mode = 1;
	ssh_signal(SIGALRM, sig_alarm);
	alarm(UPDATE_INTERVAL);
}

/* Store one PROGRESS frame's telemetry and repaint (alarm-gated). */
void
pm_relay_sample(const struct hpns_progress *p)
{
	if (!relay_mode)
		return;
	if ((p->flags & HPNS_F_RESUME) && !relay.resuming)
		relay.resuming = 1;
	else if (relay.resuming && !(p->flags & HPNS_F_RESUME)) {
		/* resume check over, transfer begins: drop the hash peaks
		 * so the completion line reflects transfer rates only */
		relay.resuming = 0;
		relay.rate_inst_max = 0;
	}
	if ((p->flags & HPNS_F_VERIFY) && !relay.verifying) {
		relay.verifying = 1;
		/* latch the transfer peak for the completion line, then
		 * track the verify phase's own peak separately */
		relay.rate_inst_peak_xfer = relay.rate_inst_max;
		relay.rate_inst_max = 0;
	}
	relay.bytes_done = p->bytes_done;
	if (p->bytes_total > 0)
		relay.bytes_total = p->bytes_total;
	relay.rate = p->rate_bps;
	relay.rate_inst = p->rate_inst_bps;
	if (p->rate_inst_bps > relay.rate_inst_max)
		relay.rate_inst_max = p->rate_inst_bps;
	relay.eta_sec = p->eta_sec;
	relay.last_frame = monotime_double();
	refresh_progress_meter(0);
}

/*
 * END received: force the completion line (100%, total elapsed, peak
 * instantaneous rate).  The caller still calls stop_progress_meter()
 * for the trailing newline.
 */
void
pm_relay_end(u_int64_t bytes_done)
{
	double dur;

	if (!relay_mode)
		return;
	relay.bytes_done = bytes_done;
	if (bytes_done > relay.bytes_total)
		relay.bytes_total = bytes_done;
	relay.done = 1;
	/* Phases are over at END: the completion line summarizes the
	 * transfer and must not carry a "verify:"/"resume check:" prefix. */
	relay.verifying = 0;
	relay.resuming = 0;
	/* Whole-run average for the completion line, matching the local
	 * meter.  Computed over the full local duration, so per-tick frame
	 * quantization cannot alias it. */
	dur = monotime_double() - relay.started;
	relay.rate = dur >= 0.001 ? (uint64_t)(bytes_done / dur) : 0;
	relay.rate_inst = 0;
	relay.last_frame = monotime_double();
	refresh_progress_meter(1);
}

/*
 * Adjust a running meter's target size.  Used by the parallel reporter
 * (source side) when a live meter's denominator legitimately changes:
 * it tracks the aggregate hash-work total during the resume-check
 * stretch, then restores the transfer total when the stretch ends.
 */
void
pm_set_total(off_t total)
{
	end_pos = total;
}

static void
sig_winch(int sig)
{
	win_resized = 1;
}

static void
setscreensize(void)
{
	struct winsize winsize;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		if (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		else
			win_size = winsize.ws_col;
	} else
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
