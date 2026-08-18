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
#include "hpn-meter.h"
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

/* render one meter line from a filled per-meter view (Stage 2) */
static void render_from_view(const struct meter_view *);

/* HPN log/meter interleave guard state (see meter_log_enter below). */
static pthread_mutex_t meter_mu = PTHREAD_MUTEX_INITIALIZER;
static int meter_active;
static int win_size;		/* terminal window size */
static volatile sig_atomic_t win_resized; /* for window resizing */
static volatile sig_atomic_t alarm_fired;


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
 * Paint one meter line from a filled view: the shared render derivation -
 * percent, then the stall/unknown/ETA/done tail, then render_meter_line.
 * The local meter feeds this; the relay consumer will too (Stage 2).  The
 * decision order matches the historic inline paint exactly.
 */
static void
render_from_view(const struct meter_view *v)
{
	enum meter_tail tail;
	long tsec = 0;

	/*
	 * Tail selector shared by the local meter and the relay consumer.
	 * It is a pure selector: each filler has already baked in its
	 * source-specific choices (the relay blanks rate/inst when its
	 * source goes silent; both supply their own peak inst, eta_sec, and
	 * done flag), so no per-source logic lives here.
	 */
	if (v->stalled)
		tail = METER_TAIL_STALLED;
	else if (v->done) {
		tail = METER_TAIL_DONE;
		tsec = v->elapsed_sec;
	} else if (v->rate == 0 || v->eta_sec == HPNS_ETA_UNKNOWN)
		tail = METER_TAIL_UNKNOWN;
	else {
		tail = METER_TAIL_ETA;
		tsec = (long)v->eta_sec;
	}

	render_meter_line(v->label, v->percent, v->cur, v->rate, v->inst,
	    tail, tsec);
}

/*
 * ENV-VAR HPN_PM_DEBUG - developer-only: capture the meter's computed values
 * without a terminal.  Set to a file path to append samples there, or to "1"
 * or "-" for stderr.  When set, the meter runs and writes one text line per
 * refresh regardless of TTY (see the non-TTY showprogress guards in scp.c and
 * sftp.c), for reviewing meter behavior non-interactively.  Not user-facing.
 */
static FILE	*pm_debug_fp;
static int	 pm_debug_checked;

static void
pm_debug_init(void)
{
	const char *e;

	if (pm_debug_checked)
		return;
	pm_debug_checked = 1;
	if ((e = getenv("HPN_PM_DEBUG")) == NULL || *e == '\0')
		return;
	if (strcmp(e, "1") == 0 || strcmp(e, "-") == 0)
		pm_debug_fp = stderr;
	else if ((pm_debug_fp = fopen(e, "a")) == NULL)
		pm_debug_fp = stderr;	/* a bad path stays visible */
}

static void
pm_debug_view(const struct meter_view *v)
{
	if (pm_debug_fp == NULL)
		return;
	fprintf(pm_debug_fp,
	    "pm label=%s cur=%llu total=%llu pct=%d rate=%lld inst=%llu "
	    "stalled=%d eta=%u elapsed=%ld\n",
	    v->label != NULL ? v->label : "",
	    (unsigned long long)v->cur, (unsigned long long)v->total,
	    v->percent, (long long)v->rate, (unsigned long long)v->inst,
	    v->stalled ? 1 : 0, v->eta_sec, v->elapsed_sec);
	fflush(pm_debug_fp);
}

void
refresh_progress_meter(int force_update)
{
	if (!hpn_meter_display_active() ||
	    !hpn_meter_display_thread_ok() ||
	    (!force_update &&
	    !__atomic_load_n(&alarm_fired, __ATOMIC_RELAXED) &&
	    !win_resized) ||
	    (!hpn_pm_active() && !can_output() && pm_debug_fp == NULL))
		return;
	__atomic_store_n(&alarm_fired, 0, __ATOMIC_RELAXED);

	if (win_resized) {
		if (!hpn_pm_active())
			setscreensize();
		win_resized = 0;
	}

	/* The meter core owns all sample state and the fills; this function
	 * supplies the shared cadence gates above (the alarm flag, forced
	 * updates, and window resizes) and nothing else. */
	hpn_meter_refresh_current(force_update);
}

/*
 * Route one filled view to the active sinks: the frame emitter when frame
 * mode is armed, else the TTY renderer when output is possible, and the
 * HPN_PM_DEBUG capture always. The single dispatch definition, shared by
 * the legacy fill above and the hpn-meter core's fills.
 */
void
pm_dispatch_view(const struct meter_view *v, int force_update)
{
	if (hpn_pm_active())
		hpn_pm_emit_view(v, force_update);
	else if (can_output())
		render_from_view(v);
	pm_debug_view(v);
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
	int save_errno = errno;

	/* Relaxed atomic store: the flag is read and cleared by whichever
	 * thread drives refresh, not only the one this signal landed on.
	 * alarm() can clobber errno, so restore it; a handler that spoils
	 * errno corrupts whatever syscall it interrupted. */
	__atomic_store_n(&alarm_fired, 1, __ATOMIC_RELAXED);
	alarm(UPDATE_INTERVAL);
	errno = save_errno;
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

/*
 * Compatibility wrappers with the stock signatures. Every in-tree caller
 * uses the meter core directly; these exist so upstream code arriving in
 * a rebase that still calls the historic API gets a working FILE meter
 * instead of a link error. The owner token is this file's own.
 */
static const char pm_wrapper_owner;

void
start_progress_meter(const char *f, off_t filesize, off_t *ctr)
{
	(void)hpn_meter_start(hpn_meter_serial(), &pm_wrapper_owner,
	    HPN_METER_FILE, HPN_METER_DOM_TRANSFER, f, filesize, ctr, 1);
}

void
stop_progress_meter(void)
{
	hpn_meter_stop(hpn_meter_serial(), &pm_wrapper_owner);
}

/*
 * Display session mechanics for a meter owned by the hpn-meter core:
 * everything start_progress_meter does around the meter state itself. The
 * initial forced paint routes back to the core's fill through the hook in
 * refresh_progress_meter, so the core must be current before this is
 * called. Frame mode skips the TTY arming and the initial paint for the
 * same reasons start_progress_meter does: stdout is the frame channel, and
 * phase flags are set only after start returns.
 */
/*
 * Display session for the relay source (hpn-meter.c): TTY arming and the
 * alarm, with two deliberate differences from pm_display_begin. No initial
 * forced paint, because nothing has arrived to paint until the first frame,
 * and the TTY arms unconditionally, matching the historic relay start.
 */
void
pm_display_begin_relay(void)
{
	pm_debug_init();
	meter_tty_arm();
	ssh_signal(SIGALRM, sig_alarm);
	alarm(UPDATE_INTERVAL);
}

/*
 * Close the relay's display session: the completion line was painted by
 * the relay end, so only the alarm, the log guard, and the trailing
 * newline remain. The newline is skipped when output is impossible, as
 * the legacy relay branch of stop_progress_meter skipped it.
 */
void
pm_display_end_relay(void)
{
	alarm(0);

	pthread_mutex_lock(&meter_mu);
	meter_active = 0;
	pthread_mutex_unlock(&meter_mu);

	if (!can_output())
		return;

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
}

void
pm_display_begin(void)
{
	pm_debug_init();
	if (!hpn_pm_active()) {
		/* Arm on "stdout is a terminal", not "foreground right
		 * now": a transfer started in the background never armed,
		 * so win_size stayed 0 and no paint ever happened after
		 * fg, with no self-heal because the resize handler that
		 * sets win_resized was never installed (review finding
		 * #27). Painting stays gated on being foreground below. */
		if (isatty(STDOUT_FILENO))
			meter_tty_arm();
		if (can_output() || pm_debug_fp != NULL)
			refresh_progress_meter(1);
	}
	ssh_signal(SIGALRM, sig_alarm);
	alarm(UPDATE_INTERVAL);
}

/*
 * Close the display session for a core-owned meter, mirroring
 * stop_progress_meter. painted is the last position a refresh actually
 * showed and decides whether a final repaint is owed; cur is the fresh
 * counter value and total and rate feed the completion frame, exactly as
 * the legacy stop reads them.
 */
void
pm_display_end(off_t painted, off_t cur, off_t total, double rate)
{
	alarm(0);

	pthread_mutex_lock(&meter_mu);
	meter_active = 0;
	pthread_mutex_unlock(&meter_mu);

	if (hpn_pm_active()) {
		hpn_pm_meter_done(cur, total, rate);
		return;
	}

	if (!can_output())
		return;

	if (painted != total)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
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
