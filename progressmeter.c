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
 * HPN status relay (hpn-status-relay-design.md): when frame mode is
 * armed the meter machinery runs as usual but refresh() emits binary
 * status frames on stdout instead of ANSI meter text.  Serial transfers
 * run one meter per file, so completed meters fold into an aggregate
 * accumulator here; the parallel path runs a single aggregate meter and
 * pushes fleet telemetry in via the setters below.  Emission is rate
 * limited so per-file meter start/stop churn from many small files
 * cannot flood the channel - the 1 Hz alarm cadence carries the truth.
 */
#define FRAME_MIN_INTERVAL	0.2	/* seconds between PROGRESS frames */
static int frame_mode;			/* emit frames instead of text */
static double frame_last_emit;		/* rate limiter timestamp */
static off_t frames_acc_bytes;		/* bytes from completed meters */
static u_int32_t frames_files_done;	/* completed meters (serial) */
static u_int32_t frames_files_total;	/* external, 0 = unknown */
static int frames_files_ext;		/* setter overrides meter counts */
static int frame_meter_is_file = 1;	/* current meter counts as a file; the
					 * verify meter clears it (not a file) */
static u_int32_t frames_streams = 1;	/* effective -j for HELLO */
static u_int16_t frames_workers_active;
static u_int16_t frames_workers_stalled;
static u_int16_t frames_flags;

/* units for format_size */
static const char unit[] = " KMGT";

static int
can_output(void)
{
	return (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

/*
 * Emit one PROGRESS frame from the current meter state (frame mode
 * only).  Called from refresh_progress_meter() after the shared
 * rate/EMA math, and from stop_progress_meter() at meter boundaries.
 * Rate limited unless forced; the periodic 1 Hz alarm tick always
 * carries current totals, so dropped boundary frames lose nothing.
 */
static void
frames_emit_progress(int force)
{
	struct hpns_progress pr;
	u_char fbuf[HPNS_HDR_LEN + HPNS_PROGRESS_LEN];
	off_t bytes_left;
	double now;

	now = monotime_double();
	if (!force && now - frame_last_emit < FRAME_MIN_INTERVAL)
		return;
	frame_last_emit = now;

	memset(&pr, 0, sizeof(pr));
	pr.bytes_done = (uint64_t)(frames_acc_bytes + cur_pos);
	pr.bytes_total = end_pos > 0 ?
	    (uint64_t)(frames_acc_bytes + end_pos) : 0;
	pr.rate_bps = bytes_per_second > 0 ?
	    (uint64_t)bytes_per_second : 0;
	bytes_left = end_pos - cur_pos;
	if (bytes_left > 0 && bytes_per_second > 0)
		pr.eta_sec = (uint32_t)(bytes_left / bytes_per_second);
	else
		pr.eta_sec = HPNS_ETA_UNKNOWN;
	pr.files_done = frames_files_done;
	pr.files_total = frames_files_total;
	pr.workers_active = frames_workers_active;
	pr.workers_stalled = frames_workers_stalled;
	pr.flags = frames_flags;

	atomicio(vwrite, STDOUT_FILENO, fbuf,
	    hpns_encode_progress(fbuf, &pr));
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

void
refresh_progress_meter(int force_update)
{
	char *buf = NULL, *obuf = NULL;
	off_t transferred;
	double elapsed, now;
	int percent;
	off_t bytes_left;
	long long cur_speed;
	int hours, minutes, seconds;
	int file_len, cols;
	off_t delta_pos;

	if (file == NULL || (!force_update && !alarm_fired && !win_resized) ||
	    (!frame_mode && !can_output()))
		return;
	alarm_fired = 0;

	if (win_resized) {
		if (!frame_mode)
			setscreensize();
		win_resized = 0;
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
	 * skip all terminal work below. */
	if (frame_mode) {
		frames_emit_progress(force_update);
		last_pos = cur_pos;
		return;
	}

	/* Don't bother if we can't even display the completion percentage */
	if (win_size < 4)
		return;

	/* filename */
	file_len = cols = win_size - 45;
	if (file_len > 0) {
		asmprintf(&buf, INT_MAX, &cols, "%-*s", file_len, file);
		/* If we used fewer columns than expected then pad */
		if (cols < file_len)
			xextendf(&buf, NULL, "%*s", file_len - cols, "");
	}
	/* percent of transfer done */
	if (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	else
		percent = ((float)cur_pos / end_pos) * 100;

	/* percent / amount transferred / bandwidth usage */
	xextendf(&buf, NULL, " %3d%% %s %s/s ", percent, format_size(cur_pos),
	    format_rate((off_t)bytes_per_second));

	/* instantaneous rate */
	if (bytes_left > 0)
		xextendf(&buf, NULL, "%s/s", format_rate((off_t)delta_pos));
	else
		xextendf(&buf, NULL, "%s/s", format_rate((off_t)max_delta_pos));

	/* ETA */
	if (!transferred)
		stalled += elapsed;
	else
		stalled = 0;

	if (stalled >= STALL_TIME)
		xextendf(&buf, NULL, "- stalled -");
	else if (bytes_per_second == 0 && bytes_left)
		xextendf(&buf, NULL, "  --:-- ETA");
	else {
		if (bytes_left > 0)
			seconds = bytes_left / bytes_per_second;
		else
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		if (hours != 0) {
			xextendf(&buf, NULL, "%d:%02d:%02d",
			    hours, minutes, seconds);
		} else
			xextendf(&buf, NULL, "  %02d:%02d", minutes, seconds);

		if (bytes_left > 0)
			xextendf(&buf, NULL, " ETA");
		else
			xextendf(&buf, NULL, "    ");
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

void
start_progress_meter(const char *f, off_t filesize, off_t *ctr)
{
	start = last_update = monotime_double();
	file = f;
	frame_meter_is_file = 1;	/* each meter is a file unless cleared */
	frames_flags &= ~HPNS_F_VERIFY;	/* verify meters re-arm this per meter */
	start_pos = *ctr;
	end_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	bytes_per_second = 0;

	/*
	 * Frame mode never paints the terminal, so skip the TTY-only setup:
	 * the log/meter interleave guard writes "\r\033[K" to stdout, which
	 * would corrupt the frame stream, and the screen-size ioctl is
	 * meaningless on a pipe.
	 */
	if (!frame_mode) {
		pthread_mutex_lock(&meter_mu);
		meter_active = 1;
		pthread_mutex_unlock(&meter_mu);
		log_set_output_guard(meter_log_enter, meter_log_exit);

		setscreensize();
	}
	refresh_progress_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	if (!frame_mode)
		ssh_signal(SIGWINCH, sig_winch);
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
	if (frame_mode) {
		if (file != NULL) {
			if (counter != NULL)
				cur_pos = *counter;
			frames_emit_progress(0);
			frames_acc_bytes += cur_pos;
			if (!frames_files_ext && frame_meter_is_file)
				frames_files_done++;
			cur_pos = 0;
		}
		file = NULL;
		return;
	}

	if (!can_output())
		return;

	/* Ensure we complete the progress */
	if (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = NULL;
}

/*
 * Arm HPN status-relay frame mode (A side; see hpn-status-relay-design.md).
 * Called once at startup when HPN_ENABLE_REMOTE_PROGRESS is set and stdout
 * is not a TTY.  Emits the HELLO frame (version + capability advertisement;
 * totals mostly unknown this early) so the consumer can distinguish "peer
 * speaks frames" from an old peer's silence.
 */
void
progressmeter_frame_mode(u_int streams)
{
	struct hpns_hello h;
	u_char fbuf[HPNS_HDR_LEN + HPNS_HELLO_LEN];

	frame_mode = 1;
	frames_streams = streams > 0 ? (u_int32_t)streams : 1;

	memset(&h, 0, sizeof(h));
	h.proto_ver = HPNS_VERSION;
	h.caps = 0;			/* no pull support in v1 */
	h.total_bytes = 0;
	h.total_files = 0;
	h.streams = frames_streams;
	atomicio(vwrite, STDOUT_FILENO, fbuf, hpns_encode_hello(fbuf, &h));
}

/*
 * Fleet telemetry for PROGRESS frames, pushed by the parallel reporter
 * tick.  No-op storage unless frame mode is armed (the reporter calls
 * unconditionally).
 */
void
progressmeter_frames_set_workers(u_int active, u_int stalled)
{
	frames_workers_active = (u_int16_t)(active > 0xffff ? 0xffff : active);
	frames_workers_stalled =
	    (u_int16_t)(stalled > 0xffff ? 0xffff : stalled);
}

/*
 * Mark the current meter as NOT a file transfer (e.g. the post-transfer
 * verify meter), so stopping it does not bump the serial per-file count.
 * The next start_progress_meter resets it back to "is a file".
 */
void
progressmeter_frames_meter_not_a_file(void)
{
	frame_meter_is_file = 0;
}

/*
 * Mark the current meter as the verification phase, so PROGRESS frames carry
 * HPNS_F_VERIFY and a front-end can label the phase "verifying".  Cleared by
 * the next start_progress_meter; both the serial and parallel verify meters
 * set it right after starting.
 */
void
progressmeter_frames_set_verifying(int on)
{
	if (on)
		frames_flags |= HPNS_F_VERIFY;
	else
		frames_flags &= ~HPNS_F_VERIFY;
}

/*
 * External file counts (parallel path), overriding the serial
 * one-meter-per-file accounting.
 */
void
progressmeter_frames_set_files(u_int done, u_int total)
{
	frames_files_ext = 1;
	frames_files_done = (u_int32_t)done;
	frames_files_total = (u_int32_t)total;
}

/*
 * Emit a FILEFAIL frame (A side): one per failed file, sent before the END
 * frame.  kind is HPNS_FF_TRANSFER or HPNS_FF_VERIFY; path is copied verbatim
 * as opaque bytes, clamped to the payload cap with HPNS_FF_TRUNCATED flagged
 * (the consumer neutralizes it before any display).  No-op unless frame mode
 * is armed.
 */
void
progressmeter_frames_filefail(u_int kind, const char *path, size_t path_len)
{
	struct hpns_filefail ff;
	u_char fbuf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];

	if (!frame_mode)
		return;
	memset(&ff, 0, sizeof(ff));
	ff.kind = (u_char)(kind & HPNS_FF_KINDMASK);
	if (path_len > HPNS_FILEFAIL_MAXPATH) {
		path_len = HPNS_FILEFAIL_MAXPATH;
		ff.kind |= HPNS_FF_TRUNCATED;
	}
	ff.path = (const u_char *)path;
	ff.path_len = (uint16_t)path_len;
	atomicio(vwrite, STDOUT_FILENO, fbuf, hpns_encode_filefail(fbuf, &ff));
}

/*
 * Emit the final END frame (A side, once, on the way out of main).
 * Advisory only: the consumer takes success/failure from the transport
 * exit status.  No-op unless frame mode is armed.
 */
void
progressmeter_frames_end(int ok, u_int files_failed)
{
	struct hpns_end e;
	u_char fbuf[HPNS_HDR_LEN + HPNS_END_LEN];

	if (!frame_mode)
		return;
	memset(&e, 0, sizeof(e));
	e.bytes_done = (uint64_t)frames_acc_bytes;
	e.files_done = frames_files_done;
	e.files_failed = (u_int32_t)files_failed;
	e.ok = ok ? 1 : 0;
	atomicio(vwrite, STDOUT_FILENO, fbuf, hpns_encode_end(fbuf, &e));
}

/*
 * Adjust a running meter's target size (B side: the relay consumer
 * learns/grows the remote total from PROGRESS frames after the meter
 * has started).
 */
void
progress_meter_set_total(off_t total)
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
