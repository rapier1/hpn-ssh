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
 * hpn-progressmeter.c - HPN status-relay frame emitter.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * The binary frame half of the progress subsystem, split out of
 * progressmeter.c: progressmeter.c owns the ANSI TTY meter, this file owns
 * the status-frame telemetry stream.  The two share nothing but the three
 * meter -> frame seams (hpn_pm_*); the frame domain never reaches
 * back into the meter.  See hpn-status-relay-design.md for the protocol.
 */

#include "includes.h"

#include <sys/types.h>

#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "hpn-status-frame.h"
#include "hpn-progressmeter.h"
#include "misc.h"

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
static u_int32_t frames_meter_files = 1; /* how many files the current meter
					 * represents: 1 per-file, N for a
					 * bundle, 0 for a non-file meter
					 * (verify, resume check) */
static u_int32_t frames_streams = 1;	/* effective -j for HELLO */
static u_int16_t frames_workers_active;
static u_int16_t frames_workers_stalled;
static u_int16_t frames_flags;	/* HPNS_F_* - written by BOTH the main
					 * thread and the reporter (set_phase,
					 * meter starts), so every access is
					 * atomic: a lost-update RMW would
					 * misfile hash bytes into the
					 * transfer accumulator */
static long long frames_rate_inst;	/* last-interval rate for PROGRESS */

/*
 * All binary frame writes route through here.  A failed write (EPIPE -
 * the relay consumer is gone) latches the channel dead so we stop
 * writing instead of spamming a broken pipe.  Output hygiene ONLY: the
 * meter displays data, it does not carry control.  Cancellation of an
 * orphaned transfer is a transport concern, handled by the parallel
 * reporter's session-liveness poll on stdout+stderr.
 *
 * Frame integrity rests on pipe-write atomicity: the largest frame is
 * HPNS_HDR_LEN + HPNS_MAX_PAYLOAD (520) bytes, within PIPE_BUF on every
 * supported platform (4096 on Linux and the BSDs; only the POSIX 512
 * floor would be marginal), so each frame lands in one write() that the
 * kernel never splits and atomicio never has to resume.  That is what
 * keeps the reporter thread's periodic ticks and the main thread's
 * meter-boundary frames from interleaving mid-frame on shared stdout.
 */
static int frames_channel_dead;

static void
frames_write(u_char *buf, size_t len)
{
	if (frames_channel_dead)
		return;
	if (atomicio(vwrite, STDOUT_FILENO, buf, len) != len)
		frames_channel_dead = 1;
}

/*
 * Build and emit one PROGRESS frame from the passed meter state (frame
 * mode only).  Rate limited unless forced.  Meter boundaries force the
 * emit: the consumer preserves one painted row per completed file and
 * derives per-file byte spans from the boundary frames, so a dropped
 * boundary would leave it a stale tick short.  Reads the retained
 * frames_rate_inst - hpn_pm_emit sets it just before a refresh-driven
 * emit, and a boundary emit reuses the last value.
 */
static void
emit_progress(off_t cur_pos, off_t end_pos, long long bytes_per_second,
    int force)
{
	struct hpns_progress pr;
	u_char fbuf[HPNS_HDR_LEN + HPNS_PROGRESS_LEN];
	off_t bytes_left, acc;
	double now;

	now = monotime_double();
	if (!force && now - frame_last_emit < FRAME_MIN_INTERVAL)
		return;
	frame_last_emit = now;

	memset(&pr, 0, sizeof(pr));
	/*
	 * frames_acc_bytes is the transfer total (completed per-file meters).
	 * The verify and resume-check phases reuse the meter machinery but
	 * their bytes are hash-domain quantities; adding the transfer total
	 * to those meters would double-count.  Each is a single 0..total
	 * meter with nothing to accumulate, so use a zero base and let its
	 * own counter stand.
	 */
	u_int16_t fl = __atomic_load_n(&frames_flags, __ATOMIC_RELAXED);

	acc = (fl & (HPNS_F_VERIFY | HPNS_F_RESUME)) ? 0 : frames_acc_bytes;
	pr.bytes_done = (uint64_t)(acc + cur_pos);
	pr.bytes_total = end_pos > 0 ?
	    (uint64_t)(acc + end_pos) : 0;
	pr.rate_bps = bytes_per_second > 0 ?
	    (uint64_t)bytes_per_second : 0;
	pr.rate_inst_bps = frames_rate_inst > 0 ?
	    (uint64_t)frames_rate_inst : 0;
	bytes_left = end_pos - cur_pos;
	if (bytes_left > 0 && bytes_per_second > 0)
		pr.eta_sec = (uint32_t)(bytes_left / bytes_per_second);
	else
		pr.eta_sec = HPNS_ETA_UNKNOWN;
	pr.files_done = frames_files_done;
	pr.files_total = frames_files_total;
	pr.workers_active = frames_workers_active;
	pr.workers_stalled = frames_workers_stalled;
	pr.flags = fl;

	frames_write(fbuf, hpns_encode_progress(fbuf, &pr));
}

/*
 * Emit a PROGRESS frame from a filled meter_view (frame mode).  Called from
 * refresh_progress_meter() after the shared rate/EMA math.  Derives the
 * instantaneous rate from the view's raw delta/elapsed - a true per-second
 * rate, distinct from the display inst - and retains it so a later
 * meter-boundary emit (hpn_pm_meter_done) reuses it.  emit_progress overlays
 * the cross-file aggregate + phase flags and computes the ETA.
 */
void
hpn_pm_emit_view(const struct meter_view *v, int force)
{
	off_t bytes_left = v->total - v->cur;

	frames_rate_inst = (bytes_left > 0 && v->elapsed >= 0.001) ?
	    (long long)(v->delta / v->elapsed) : 0;
	emit_progress(v->cur, v->total, v->rate, force);
}

/*
 * A new per-file meter is starting.  Mark it a file (the verify meter
 * clears this again) and clear the phase flags; phase meters re-arm them
 * per meter right after starting.  No-op-safe when frame mode is off -
 * the state is simply never read.
 */
void
hpn_pm_meter_start(void)
{
	frames_meter_files = 1;		/* each meter is one file unless the
					 * kind says otherwise (see
					 * hpn_pm_meter_files / _not_a_file) */
	__atomic_fetch_and(&frames_flags,
	    (u_int16_t)~(HPNS_F_VERIFY | HPNS_F_RESUME), __ATOMIC_RELAXED);
					/* phase meters re-arm these per meter */
}

/*
 * A meter finished (frame mode): count the file, emit a forced boundary
 * frame, then fold the meter into the aggregate so the next meter's
 * frames continue the running totals (serial scp runs one meter per
 * file).  The count comes first so the boundary frame itself announces
 * the completion: the consumer preserves a painted row when files_done
 * rises, and that frame must carry the file's exact end state, not the
 * next 1 Hz tick's mid-file position.  Forced for the same reason - a
 * rate-limited boundary emit would drop whenever a tick landed just
 * before the completion.
 */
void
hpn_pm_meter_done(off_t cur_pos, off_t end_pos,
    long long bytes_per_second)
{
	if (!frames_files_ext)
		frames_files_done += frames_meter_files;
	emit_progress(cur_pos, end_pos, bytes_per_second, 1);
	/* Only transfer meters feed the running total; verify and
	 * resume-check bytes are hash-domain quantities (see emit_progress)
	 * and must not inflate it or the END frame. */
	if (!(__atomic_load_n(&frames_flags, __ATOMIC_RELAXED) &
	    (HPNS_F_VERIFY | HPNS_F_RESUME)))
		frames_acc_bytes += cur_pos;
}

/*
 * Arm HPN status-relay frame mode (A side; see hpn-status-relay-design.md).
 * Called once at startup when HPN_ENABLE_REMOTE_PROGRESS is set and stdout
 * is not a TTY.  Emits the HELLO frame (version + capability advertisement;
 * totals mostly unknown this early) so the consumer can distinguish "peer
 * speaks frames" from an old peer's silence.
 */
void
hpn_pm_frame_mode(u_int streams)
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
	frames_write(fbuf, hpns_encode_hello(fbuf, &h));
}

/*
 * Is binary frame emission armed?  When it is, stdout is the frame channel,
 * so callers must not write human text (mprintf/printf) to it - that would
 * corrupt the stream.  Gate any such phase message on !this.
 */
int
hpn_pm_active(void)
{
	return frame_mode;
}

/*
 * Fleet telemetry for PROGRESS frames, pushed by the parallel reporter
 * tick.  No-op storage unless frame mode is armed (the reporter calls
 * unconditionally).
 */
void
hpn_pm_set_workers(u_int active, u_int stalled)
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
hpn_pm_meter_not_a_file(void)
{
	frames_meter_files = 0;
}

/*
 * Declare how many files the current meter represents. A serial bundle is
 * one meter carrying N files; counting it as one meter, one file is review
 * finding #16. Called by the meter core from the BUNDLE kind.
 */
void
hpn_pm_meter_files(u_int n)
{
	frames_meter_files = (u_int32_t)n;
}

/*
 * Count a file the resume gate resolved without a transfer meter:
 * skipped as identical/diverged, or refilled by the (unmetered) chunked
 * path.  Keeps serial frame counts consistent with the parallel walker
 * tally, which counts every submitted file.  If the refill leg ever
 * gains a file meter, the refilled case must stop being counted here.
 * No-op when the parallel reporter owns the counts.
 */
void
hpn_pm_count_file(void)
{
	if (!frame_mode || frames_files_ext)
		return;
	frames_files_done++;
}

/*
 * Set or clear a phase flag (HPNS_F_VERIFY / HPNS_F_RESUME) so PROGRESS
 * frames carry it and a front-end can label the phase.  Cleared by the
 * next start_progress_meter; phase meters set it right after starting.
 *
 * Only sets the flag - it does NOT emit a frame.  In the parallel path the
 * reporter thread is the sole frame writer; emitting from this (main) thread
 * too would interleave two atomicio writes to stdout and corrupt a frame.
 * The reporter's next tick (and the serial meter's alarm) carry the flag out.
 */
void
hpn_pm_set_phase(u_int flag, int on)
{
	if (on)
		__atomic_fetch_or(&frames_flags, (u_int16_t)flag,
		    __ATOMIC_RELAXED);
	else
		__atomic_fetch_and(&frames_flags, (u_int16_t)~flag,
		    __ATOMIC_RELAXED);
}

/*
 * External file counts (parallel path), overriding the serial
 * one-meter-per-file accounting.
 */
void
hpn_pm_set_files(u_int done, u_int total)
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
hpn_pm_filefail(u_int kind, const char *path, size_t path_len)
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
	frames_write(fbuf, hpns_encode_filefail(fbuf, &ff));
}

/*
 * Emit a FILEDONE frame (A side): one per file with its final
 * transfer-log status, sent only when the consumer armed the relay with
 * the "log" value (the transferlog module gates the call).  Same clamp
 * and opaque-path discipline as FILEFAIL.  No-op unless frame mode is
 * armed.
 */
void
hpn_pm_filedone(u_int status, long long size, const char *path,
    size_t path_len)
{
	struct hpns_filedone fd;
	u_char fbuf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];

	if (!frame_mode)
		return;
	memset(&fd, 0, sizeof(fd));
	fd.status = (u_char)(status & HPNS_FD_STATUSMASK);
	fd.size = size > 0 ? (uint64_t)size : 0;
	if (path_len > HPNS_FILEDONE_MAXPATH) {
		path_len = HPNS_FILEDONE_MAXPATH;
		fd.status |= HPNS_FD_TRUNCATED;
	}
	fd.path = (const u_char *)path;
	fd.path_len = (uint16_t)path_len;
	frames_write(fbuf, hpns_encode_filedone(fbuf, &fd));
}

/*
 * Emit the final END frame (A side, once, on the way out of main).
 * Advisory only: the consumer takes success/failure from the transport
 * exit status.  No-op unless frame mode is armed.
 */
void
hpn_pm_end(int ok, u_int files_failed)
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
	frames_write(fbuf, hpns_encode_end(fbuf, &e));
}
