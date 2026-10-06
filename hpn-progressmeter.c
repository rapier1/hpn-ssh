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

/* hpn-progressmeter.c - the status-frame emitter.
 *
 * The binary half of the progress subsystem. progressmeter.c owns the ANSI
 * TTY meter, and this file owns the status-frame stream that a relay
 * consumer reads in its place. The meter side reaches this file only
 * through the hpn_pm_* calls, and nothing here calls back into the meter.
 * hpn-status-frame.h defines the frame format. */

#include "includes.h"

#include <sys/types.h>

#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "hpn-meter.h"
#include "hpn-status-frame.h"
#include "hpn-progressmeter.h"
#include "misc.h"

/* The frame emitter's state. When frame mode is armed, the meter runs as
 * usual but its views go out as binary status frames on stdout instead of
 * ANSI meter text. A serial transfer runs one meter per file, so completed
 * meters fold into the accumulator here. The parallel path runs a single
 * aggregate meter and pushes fleet telemetry in through the setters below.
 * PROGRESS frames are rate limited, so the start and stop churn of many
 * small files cannot flood the channel. The once-a-second alarm still
 * delivers a frame per tick. */
#define FRAME_MIN_INTERVAL	0.2	/* seconds between PROGRESS frames */
static int frame_mode;			/* emit frames instead of text */
/* Guards every static below. The reporter thread and the main thread both
 * read and write them, and a frame is built and written under one hold, so
 * frames go out in the order their state was read. frame_mode above is
 * set once at startup, before the reporter exists. */
static pthread_mutex_t frames_mu = PTHREAD_MUTEX_INITIALIZER;
static double frame_last_emit;		/* rate limiter timestamp */
static off_t frames_acc_bytes;		/* bytes from completed meters */
static uint32_t frames_files_done;	/* from meters, or set externally */
static uint32_t frames_files_total;	/* external, 0 = unknown */
static int frames_files_ext;		/* setter overrides meter counts */
/* How many files the current meter represents: 1 for a file, N for a
 * bundle, and 0 for a meter that is not a file (verify, resume check). */
static uint32_t frames_meter_files = 1;
static uint16_t frames_workers_active;	/* fleet workers neither stalled nor dead */
static uint16_t frames_workers_stalled;	/* fleet workers judged stalled */
/* HPNS_F_* phase flags, carried on every PROGRESS frame. A verify or
 * resume flag also keeps hash bytes out of the transfer accumulator. */
static uint16_t frames_flags;
static long long frames_rate_inst;	/* last-interval rate for PROGRESS */
/* Set once a frame write fails, after which no frame is written. */
static int frames_channel_dead;

/* Every binary frame goes out through here. A failed write, usually EPIPE
 * because the relay consumer is gone, marks the channel dead so nothing
 * more is written to a broken pipe. This is output hygiene only, because
 * the meter displays data and carries no control. Cancelling an orphaned
 * transfer is a transport concern, handled by the parallel reporter's
 * session-liveness poll on stdout and stderr.
 *
 * The caller holds frames_mu. Two threads write frames, the reporter on its
 * ticks and the main thread at meter boundaries, and the mutex keeps one
 * frame from interleaving with another on the shared stdout, whatever the
 * pipe's atomic write size and whether stdout is a pipe at all. */
static void
frames_write_locked(u_char *buf, size_t len)
{
	if (!frames_channel_dead &&
	    atomicio(vwrite, STDOUT_FILENO, buf, len) != len)
		frames_channel_dead = 1;
}

/* Write a frame built from no shared state. A frame that reads the
 * emitter's state is built and written under one hold of frames_mu, so the
 * reporter and main thread never build from state the other is changing.
 * That prevents torn 64-bit counts, double-counted final bytes, and stale
 * frames following newer ones. */
static void
frames_write(u_char *buf, size_t len)
{
	pthread_mutex_lock(&frames_mu);
	frames_write_locked(buf, len);
	pthread_mutex_unlock(&frames_mu);
}

/* Build and emit one PROGRESS frame from the given meter state, in frame
 * mode only. It is rate limited unless forced. Meter boundaries force the
 * emit, because the consumer keeps one painted row per completed file and
 * derives each file's byte span from the boundary frames, so a dropped
 * boundary would leave it a tick short. It reads the retained
 * frames_rate_inst, which hpn_pm_emit_view sets just before a
 * refresh-driven emit and a boundary emit reuses. The caller holds
 * frames_mu. */
static void
emit_progress(off_t cur_pos, off_t end_pos, long long bytes_per_second,
    int force, uint16_t extra_flags)
{
	struct hpns_progress progress;
	u_char fbuf[HPNS_HDR_LEN + HPNS_PROGRESS_LEN];
	off_t bytes_left, acc;
	double now;
	uint16_t flags;

	now = monotime_double();
	if (!force && now - frame_last_emit < FRAME_MIN_INTERVAL)
		return;
	frame_last_emit = now;

	memset(&progress, 0, sizeof(progress));
	/* frames_acc_bytes is the transfer total from completed per-file
	 * meters. The verify and resume-check phases reuse the meter, but
	 * their bytes are hash bytes, and adding the transfer total to them
	 * would double-count. Each is a single 0..total meter with nothing to
	 * accumulate, so it uses a zero base and its own counter stands. */
	flags = frames_flags;
	acc = frames_acc_bytes;
	if (flags & (HPNS_F_VERIFY | HPNS_F_RESUME))
		acc = 0;
	progress.bytes_done = (uint64_t)(acc + cur_pos);
	if (end_pos > 0)
		progress.bytes_total = (uint64_t)(acc + end_pos);
	if (bytes_per_second > 0)
		progress.rate_bps = (uint64_t)bytes_per_second;
	if (frames_rate_inst > 0)
		progress.rate_inst_bps = (uint64_t)frames_rate_inst;
	/* an ETA too large for the frame's u32 reads as unknown */
	bytes_left = end_pos - cur_pos;
	progress.eta_sec = HPNS_ETA_UNKNOWN;
	if (bytes_left > 0 && bytes_per_second > 0 &&
	    bytes_left / bytes_per_second < HPNS_ETA_UNKNOWN)
		progress.eta_sec = (uint32_t)(bytes_left / bytes_per_second);
	progress.files_done = frames_files_done;
	progress.files_total = frames_files_total;
	progress.workers_active = frames_workers_active;
	progress.workers_stalled = frames_workers_stalled;
	progress.flags = flags | extra_flags;

	frames_write_locked(fbuf, hpns_encode_progress(fbuf, &progress));
}

/* Emit a PROGRESS frame from a filled meter view, in frame mode. The view
 * dispatch in progressmeter.c calls it after the meter core's rate math. It
 * derives a true per-second rate from the view's raw delta and elapsed,
 * which differs from the display's per-sample inst, and keeps it for a
 * later boundary emit in hpn_pm_meter_done to reuse. emit_progress adds
 * the cross-file aggregate and phase flags and computes the ETA. */
void
hpn_pm_emit_view(const struct meter_view *view, int force)
{
	pthread_mutex_lock(&frames_mu);
	/* A completed view's elapsed spans the whole transfer, not the last
	 * interval, and a microsecond window divides into nonsense. Neither
	 * gives a per-second rate. */
	frames_rate_inst = 0;
	if (!view->done && view->elapsed >= 0.001)
		frames_rate_inst = (long long)(view->delta / view->elapsed);
	emit_progress(view->cur, view->total, view->rate, force, 0);
	pthread_mutex_unlock(&frames_mu);
}

/* A new meter is starting. It counts as one file and carries no phase
 * flag until the meter core says otherwise, right after this call. The
 * state is harmless when frame mode is off, because nothing reads it. */
void
hpn_pm_meter_start(void)
{
	pthread_mutex_lock(&frames_mu);
	/* hpn_pm_meter_files and hpn_pm_meter_not_a_file override the count */
	frames_meter_files = 1;
	/* a phase meter re-arms its flag with hpn_pm_set_phase */
	frames_flags &= (uint16_t)~(HPNS_F_VERIFY | HPNS_F_RESUME);
	pthread_mutex_unlock(&frames_mu);
}

/* A meter finished, in frame mode. Count the file, emit a forced boundary
 * frame, and fold the meter into the running total, so the next meter's
 * frames carry on from it. A serial transfer runs one meter per file. The
 * count comes first so the boundary frame itself announces the completion.
 * The consumer keeps a painted row when files_done rises, and that frame
 * must carry the file's exact end state, not a later tick's mid-file
 * position. The emit is forced for the same reason, because a rate-limited
 * one would drop whenever a tick landed just before the completion. */
void
hpn_pm_meter_done(off_t cur_pos, off_t end_pos, long long bytes_per_second)
{
	uint16_t boundary = 0;

	pthread_mutex_lock(&frames_mu);
	/* Only a meter counting its own files marks a file boundary. The
	 * fleet counts externally, and the verify and resume-check meters are
	 * not files, so the consumer keeps rows only for true serial file
	 * boundaries. */
	if (!frames_files_ext) {
		frames_files_done += frames_meter_files;
		if (frames_meter_files > 0)
			boundary = HPNS_F_BOUNDARY;
	}
	emit_progress(cur_pos, end_pos, bytes_per_second, 1, boundary);
	/* Only transfer meters feed the running total. Verify and resume-check
	 * bytes are hash bytes and must not inflate it or the END frame. */
	if (!(frames_flags & (HPNS_F_VERIFY | HPNS_F_RESUME)))
		frames_acc_bytes += cur_pos;
	pthread_mutex_unlock(&frames_mu);
}

/* Arm status-relay frame mode on the source side. scp calls it once at
 * startup when HPN_ENABLE_REMOTE_PROGRESS is set and stdout is not a TTY.
 * It emits the HELLO frame, carrying the version and capabilities with the
 * totals still unknown, so the consumer can tell a peer that speaks frames
 * from an old peer's silence. */
void
hpn_pm_frame_mode(u_int streams)
{
	struct hpns_hello hello;
	u_char fbuf[HPNS_HDR_LEN + HPNS_HELLO_LEN];

	frame_mode = 1;

	memset(&hello, 0, sizeof(hello));
	hello.proto_ver = HPNS_VERSION;
	hello.caps = 0;			/* no pull support in v1 */
	hello.total_bytes = 0;
	hello.total_files = 0;
	/* the effective -j, where a serial transfer is one stream */
	hello.streams = 1;
	if (streams > 0)
		hello.streams = (uint32_t)streams;
	frames_write(fbuf, hpns_encode_hello(fbuf, &hello));
}

/* Report whether frame mode is armed. When it is, stdout is the frame
 * channel, and human text written there by mprintf or printf would corrupt
 * the stream. Gate any such message on this returning 0. */
int
hpn_pm_active(void)
{
	return frame_mode;
}

/* Store the fleet's worker counts for PROGRESS frames. The parallel
 * reporter pushes them every tick, whether or not frame mode is armed, and
 * they are read only when it is. */
void
hpn_pm_set_workers(u_int active, u_int stalled)
{
	/* the frame carries each count in 16 bits */
	if (active > UINT16_MAX)
		active = UINT16_MAX;
	if (stalled > UINT16_MAX)
		stalled = UINT16_MAX;
	pthread_mutex_lock(&frames_mu);
	frames_workers_active = (uint16_t)active;
	frames_workers_stalled = (uint16_t)stalled;
	pthread_mutex_unlock(&frames_mu);
}

/* Mark the current meter as not a file, so stopping it does not raise the
 * serial file count. The meter core calls it for WORK and AGGREGATE
 * meters, and the next hpn_pm_meter_start makes the meter a file again. */
void
hpn_pm_meter_not_a_file(void)
{
	pthread_mutex_lock(&frames_mu);
	frames_meter_files = 0;
	pthread_mutex_unlock(&frames_mu);
}

/* Declare how many files the current meter represents. A serial bundle is
 * one meter carrying many files, so stopping it must count all of them.
 * The meter core calls it for BUNDLE meters. */
void
hpn_pm_meter_files(u_int nfiles)
{
	pthread_mutex_lock(&frames_mu);
	frames_meter_files = (uint32_t)nfiles;
	pthread_mutex_unlock(&frames_mu);
}

/* Count a file the resume gate resolved without a transfer meter, either
 * skipped as identical or diverged, or refilled by the unmetered chunked
 * path. This keeps the serial frame counts consistent with the parallel
 * walker's tally, which counts every submitted file. If the refill leg
 * ever gains a file meter, the refilled case must stop being counted here.
 * It does nothing when the parallel reporter owns the counts. */
void
hpn_pm_count_file(void)
{
	if (!frame_mode)
		return;
	pthread_mutex_lock(&frames_mu);
	if (!frames_files_ext)
		frames_files_done++;
	pthread_mutex_unlock(&frames_mu);
}

/* Set or clear a phase flag, HPNS_F_VERIFY or HPNS_F_RESUME, so PROGRESS
 * frames carry it and a front end can label the phase. A phase meter sets
 * it right after starting, as does the parallel reporter's resume-check
 * stretch, and the next hpn_pm_meter_start clears it. This only sets the
 * flag and does not emit a frame. The reporter's next tick, or the serial
 * meter's alarm, carries it out. */
void
hpn_pm_set_phase(u_int flag, int on)
{
	pthread_mutex_lock(&frames_mu);
	if (on)
		frames_flags |= (uint16_t)flag;
	else
		frames_flags &= (uint16_t)~flag;
	pthread_mutex_unlock(&frames_mu);
}

/* Store external file counts, which override the serial count of one
 * file per meter. The parallel reporter pushes them every tick, and scp
 * pushes the final tally once more before the END frame. */
void
hpn_pm_set_files(u_int done, u_int total)
{
	pthread_mutex_lock(&frames_mu);
	frames_files_ext = 1;
	frames_files_done = (uint32_t)done;
	frames_files_total = (uint32_t)total;
	pthread_mutex_unlock(&frames_mu);
}

/* Emit a FILEFAIL frame on the source side, one per failed file, before
 * the END frame. kind is HPNS_FF_TRANSFER or HPNS_FF_VERIFY. The path goes
 * out verbatim as opaque bytes, clipped to the payload cap with
 * HPNS_FF_TRUNCATED set, and the consumer neutralizes it before any
 * display. It does nothing unless frame mode is armed. */
void
hpn_pm_filefail(u_int kind, const char *path, size_t path_len)
{
	struct hpns_filefail filefail;
	u_char fbuf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];

	if (!frame_mode)
		return;
	memset(&filefail, 0, sizeof(filefail));
	filefail.kind = (u_char)(kind & HPNS_FF_KINDMASK);
	if (path_len > HPNS_FILEFAIL_MAXPATH) {
		path_len = HPNS_FILEFAIL_MAXPATH;
		filefail.kind |= HPNS_FF_TRUNCATED;
	}
	filefail.path = (const u_char *)path;
	filefail.path_len = (uint16_t)path_len;
	frames_write(fbuf, hpns_encode_filefail(fbuf, &filefail));
}

/* Emit a FILEDONE frame on the source side, one per file with its final
 * transfer-log status. The transferlog module sends it only when the
 * consumer armed the relay with the "log" value. The path is clipped and
 * sent as opaque bytes, as in FILEFAIL. It does nothing unless frame mode
 * is armed. */
void
hpn_pm_filedone(u_int status, off_t size, const char *path, size_t path_len)
{
	struct hpns_filedone filedone;
	u_char fbuf[HPNS_HDR_LEN + HPNS_MAX_PAYLOAD];

	if (!frame_mode)
		return;
	memset(&filedone, 0, sizeof(filedone));
	filedone.status = (u_char)(status & HPNS_FD_STATUSMASK);
	if (size > 0)
		filedone.size = (uint64_t)size;
	if (path_len > HPNS_FILEDONE_MAXPATH) {
		path_len = HPNS_FILEDONE_MAXPATH;
		filedone.status |= HPNS_FD_TRUNCATED;
	}
	filedone.path = (const u_char *)path;
	filedone.path_len = (uint16_t)path_len;
	frames_write(fbuf, hpns_encode_filedone(fbuf, &filedone));
}

/* Emit the final END frame on the source side, once, on the way out of
 * main. It is advisory, because the consumer takes success or failure from
 * the transport's exit status. It does nothing unless frame mode is
 * armed. */
void
hpn_pm_end(int ok, u_int files_failed)
{
	struct hpns_end end;
	u_char fbuf[HPNS_HDR_LEN + HPNS_END_LEN];

	if (!frame_mode)
		return;
	memset(&end, 0, sizeof(end));
	end.files_failed = (uint32_t)files_failed;
	if (ok)
		end.ok = 1;
	pthread_mutex_lock(&frames_mu);
	end.bytes_done = (uint64_t)frames_acc_bytes;
	end.files_done = frames_files_done;
	frames_write_locked(fbuf, hpns_encode_end(fbuf, &end));
	pthread_mutex_unlock(&frames_mu);
}
