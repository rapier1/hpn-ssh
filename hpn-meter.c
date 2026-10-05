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

/* hpn-meter.c - the progress meter core. hpn-meter.h describes the model.
 *
 * This file owns the meter object and its two fills. The builtin fill
 * samples a counter and derives the rate and stall state for every local
 * meter, from one file to the parallel aggregate. It leaves out two pieces
 * of upstream's refresh_progress_meter math on purpose. First, a counter
 * source is monotonic by contract, so there is no negative delta to clamp.
 * Second, the meter's kind says whether a zero total means an empty
 * transfer or a total not known yet, so only an AGGREGATE meter runs
 * rate-only. The relay fill builds the view from the progress frames a
 * remote source sends, for the launcher of an scp -R or hpn3scp transfer. */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "hpn-status-frame.h"
#include "hpn-progressmeter.h"
#include "hpn-meter.h"

/* Stall threshold in seconds. Matches STALL_TIME in progressmeter.c. */
#define HPN_METER_STALL_SEC	5

/* The meter currently driving the display. One meter is current at a time,
 * whether serial, aggregate, or relay, because the display session (alarm,
 * TTY, log guard) is a singleton in progressmeter.c. */
static struct hpn_meter *current_meter;

/* Core-owned storage for the serial meter; see hpn-meter.h. */
static struct hpn_meter serial_meter;

/* The relay consumer's state, filled from the remote source's PROGRESS
 * frames. The rate, delta, and ETA shown are the source's own and are never
 * derived locally. First, a counter that advances only when a frame lands,
 * about once a second, aliases against the local clock into alternating
 * zero and double-speed readings. Second, only the frame consumers (scp -R
 * and hpn3scp) use this state, so local meters are unaffected. */
static struct {
	uint64_t bytes_done;	/* cumulative, from the last frame */
	uint64_t bytes_total;	/* 0 until the source knows it */
	uint64_t rate;		/* source-smoothed */
	uint64_t rate_inst;	/* source last-interval */
	uint64_t rate_inst_max;	/* peak inst within the current phase */
	/* Transfer-phase peak, latched when verify starts. The completion
	 * line summarizes the transfer, and a verify-phase hash peak can
	 * legitimately exceed link speed, which would read there as an
	 * impossible network rate. */
	uint64_t rate_inst_peak_xfer;
	uint32_t eta_sec;	/* source's ETA, or HPNS_ETA_UNKNOWN */
	int	 verifying;	/* HPNS_F_VERIFY seen: label the phase */
	int	 resuming;	/* HPNS_F_RESUME live: label the phase */
	int	 done;		/* END received: paint the 100% line */
	double	 last_break;	/* monotime of the last row break, one per second */
	double	 last_frame;	/* monotime of the last sample (stall aging) */
	double	 started;	/* monotime the relay started */

	/* Per-file state. Frames carry cumulative bytes (the running total
	 * plus the current meter), while their rate and ETA are already per
	 * file. So subtracting the cumulative base recorded at the last
	 * boundary recovers the source's own per-file meter exactly. The
	 * live line is relative to file_base, and each boundary preserves a
	 * completed-file row built from the row_* snapshot. */
	uint64_t file_base;	/* cumulative bytes at the last preserved row */
	uint64_t file_inst_max;	/* peak frame inst since the last row */
	double	 file_start;	/* monotime of the last preserved row */
	int	 row_pending;	/* fill paints one completed-file row */
	uint64_t row_bytes;	/* the completed file's bytes */
	uint64_t row_avg;	/* its average rate */
	uint64_t row_peak;	/* its peak inst rate */
	long	 row_elapsed;	/* its elapsed seconds */
} relay;

/* The core requires a counter, but the relay fill never reads it. */
static off_t relay_ctr;
static struct hpn_meter relay_meter;	/* core-owned, like serial_meter */

/* The serial meter's storage, owned here so it can never dangle into a
 * caller's stack frame. See hpn-meter.h. */
struct hpn_meter *
hpn_meter_serial(void)
{
	return &serial_meter;
}

/* Whether a meter is current. refresh_progress_meter does nothing without
 * one. */
int
hpn_meter_display_active(void)
{
	return current_meter != NULL;
}

/* True when the calling thread may run the current meter's fill: there is
 * no meter, the meter is not bound to a thread, or this is the thread it is
 * bound to. refresh_progress_meter checks this before it consumes the alarm
 * flag. Otherwise a bound meter's tick could be eaten by whichever worker's
 * receive path called refresh first, and that worker would then return
 * without painting. */
int
hpn_meter_display_thread_ok(void)
{
	struct hpn_meter *meter = current_meter;

	return meter == NULL || !meter->display_bound ||
	    pthread_equal(pthread_self(), meter->display_tid);
}

/* Start a meter and make it current. The kind, domain, and file count are
 * fixed for the meter's whole life. The label is copied, not borrowed, and
 * defaults to "transfer". Returns -1 and starts nothing if meter or ctr is
 * NULL or a meter is already current, which no legal caller sequence
 * produces today. */
static int
meter_init(struct hpn_meter *meter, const void *owner,
    enum hpn_meter_kind kind, enum hpn_meter_domain domain,
    const char *label, off_t total, off_t *ctr, u_int nfiles)
{
	if (meter == NULL || ctr == NULL) {
		error_f("meter started without %s", meter == NULL ? "a meter" :
		    "a counter");
		return -1;
	}
	if (current_meter != NULL) {
		error_f("meter \"%s\" already active", current_meter->label);
		return -1;
	}

	/* create the meter and set to supplied values */
	memset(meter, 0, sizeof(*meter));
	strlcpy(meter->label, label != NULL ? label : "transfer",
	    sizeof(meter->label));
	meter->kind = kind;
	meter->domain = domain;
	meter->owner = owner;
	meter->total = total;
	meter->ctr = ctr;
	meter->nfiles = nfiles;
	meter->start_t = meter->last_t = monotime_double();
	/* Seed the positions at the counter's starting value. A resumed
	 * transfer's counter begins at the resume offset, and a zero seed
	 * would paint that whole offset as the first instantaneous rate.
	 * cur_pos stays 0 as the first-sample sentinel the fill tests. */
	meter->start_pos = meter->last_pos = *ctr;
	meter->cur_pos = 0;
	meter->active = 1;
	current_meter = meter;

	/* Same order as start_progress_meter: tell the frame emitter a
	 * meter began, then run the display session mechanics, which end
	 * with the initial forced paint routed back to this meter. */
	hpn_pm_meter_start();
	/* The kind and domain set what the frame emitter reports for this
	 * meter. First, a WORK or AGGREGATE meter is not one file, and a
	 * BUNDLE meter is nfiles files. Second, a WORK meter's domain names
	 * the phase a frame consumer labels: hash bytes are the resume check,
	 * and work bytes are the verify pass. The phase flag stays set past
	 * stop on purpose, because the next meter's start clears it. */
	if (kind == HPN_METER_WORK || kind == HPN_METER_AGGREGATE)
		hpn_pm_meter_not_a_file();
	if (kind == HPN_METER_BUNDLE)
		hpn_pm_meter_files(nfiles);
	if (kind == HPN_METER_WORK) {
		if (domain == HPN_METER_DOM_HASH)
			hpn_pm_set_phase(HPNS_F_RESUME, 1);
		else if (domain == HPN_METER_DOM_WORK)
			hpn_pm_set_phase(HPNS_F_VERIFY, 1);
	}
	return 0;
}

/* Start a meter and its display session. Returns 0, or -1 with the cause
 * logged and nothing started. */
int
hpn_meter_start(struct hpn_meter *meter, const void *owner,
    enum hpn_meter_kind kind, enum hpn_meter_domain domain,
    const char *label, off_t total, off_t *ctr, u_int nfiles)
{
	if (meter_init(meter, owner, kind, domain, label, total, ctr,
	    nfiles) != 0)
		return -1;
	/* after init, so the session's first forced paint finds this meter
	 * current */
	pm_display_begin();
	return 0;
}

/* The owner check shared by stop and the update functions. The meter must
 * be current and active, and the caller must be the owner that started it.
 * A meter that is no longer current is refused quietly, since a late update
 * or a second stop is harmless. A caller that is not the owner holds a
 * stale handle, so that refusal is logged rather than folded into the
 * wrong meter. The update functions are display-thread only, which for the
 * fleet meter means the reporter. */
static int
meter_owned(struct hpn_meter *meter, const void *owner, const char *what)
{
	if (meter == NULL || !meter->active || meter != current_meter)
		return 0;
	if (owner != meter->owner) {
		error_f("%s for \"%s\" from a non-owner ignored",
		    what, meter->label);
		return 0;
	}
	return 1;
}

/* Grow the total and file count. It adds rather than replaces on purpose.
 * A later enumeration grows a live denominator, so a second command can
 * never shrink the total under the bytes already counted and freeze the
 * meter at 100 percent. */
void
hpn_meter_add_total(struct hpn_meter *meter, const void *owner,
    off_t add_bytes, u_int add_files)
{
	if (!meter_owned(meter, owner, "total update"))
		return;
	if (add_bytes > 0)
		meter->total += add_bytes;
	meter->nfiles += add_files;
}

/* Replace the total outright. This is for the reporter's resume-check
 * stretch, which temporarily runs the meter in the hash-byte domain and
 * restores the transfer total afterwards. Ordinary growth uses
 * hpn_meter_add_total. */
void
hpn_meter_retotal(struct hpn_meter *meter, const void *owner, off_t total)
{
	if (!meter_owned(meter, owner, "retotal"))
		return;
	meter->total = total;
}

/* Restrict the fill to one thread. Every thread that drives refresh
 * reaches the fill, and for the fleet meter that includes the workers, on
 * each message they receive, and the walker on the control connection.
 * Their fills would race the reporter's updates, as ThreadSanitizer showed.
 * Binding makes their refresh calls no-ops for this meter, so the
 * reporter's alarm-gated tick is the only sampler. */
void
hpn_meter_bind_display(struct hpn_meter *meter, const void *owner, pthread_t tid)
{
	if (!meter_owned(meter, owner, "display bind"))
		return;
	meter->display_tid = tid;
	meter->display_bound = 1;
}

/* Replace the label. The meter owns the copy, as at start. */
void
hpn_meter_relabel(struct hpn_meter *meter, const void *owner, const char *label)
{
	if (!meter_owned(meter, owner, "relabel") || label == NULL)
		return;
	strlcpy(meter->label, label, sizeof(meter->label));
}

/* Stop a meter. Only the owner that started it may stop it. */
void
hpn_meter_stop(struct hpn_meter *meter, const void *owner)
{
	if (!meter_owned(meter, owner, "stop"))
		return;
	/* The display session needs two positions. First, the last painted
	 * one decides whether a final repaint is owed, since a completed
	 * transfer's last alarm paint is usually short of 100%. Second, the
	 * fresh counter gives the completion frame's byte totals. */
	pm_display_end(meter->cur_pos, *meter->ctr, meter->total, meter->rate_ema);
	/* only now, because that final repaint goes through refresh, which
	 * paints only the current meter */
	current_meter = NULL;
	meter->active = 0;
}

/* The builtin fill: sample the counter, derive the rate and stall state,
 * fill a view, and hand it to the sinks. refresh_progress_meter calls it
 * after the shared cadence gates (the alarm flag, a forced update, a window
 * resize), so this math runs at most a few times a second however often
 * the transfer loop drives refresh. */
void
hpn_meter_refresh_current(int force_update)
{
	struct hpn_meter *meter = current_meter;
	struct meter_view view;
	off_t transferred, bytes_left, delta_pos, base;
	double now, elapsed, cur_speed;
	int total_unknown;

	if (meter == NULL || !hpn_meter_display_thread_ok())
		return;

	/* A source with its own fill (the relay) supplies the whole view.
	 * The counter math below is the builtin fill. */
	if (meter->fill != NULL) {
		meter->fill(meter, &view);
		pm_dispatch_view(&view, force_update);
		return;
	}

	/* cur_pos is 0 until the first sample, which measures from the
	 * starting position instead */
	if (meter->cur_pos != 0)
		base = meter->cur_pos;
	else
		base = meter->start_pos;
	transferred = *meter->ctr - base;
	meter->cur_pos = *meter->ctr;
	now = monotime_double();
	bytes_left = meter->total - meter->cur_pos;

	/* Bytes moved since the last sample. The live line shows this as its
	 * instantaneous figure, and the largest one is the peak the completion
	 * line shows. It is per sample, not per second, so a late sample can
	 * read high. */
	delta_pos = meter->cur_pos - meter->last_pos;
	if (delta_pos > meter->max_delta)
		meter->max_delta = delta_pos;

	/* An AGGREGATE meter with no total yet is a rate-only meter, not a
	 * completed one, because its denominator arrives mid-flight when the
	 * enumeration drains. Every other kind reads a zero total as an
	 * empty transfer, complete on its first sample. */
	total_unknown = (meter->kind == HPN_METER_AGGREGATE && meter->total == 0);
	if (bytes_left > 0 || total_unknown)
		elapsed = now - meter->last_t;
	else {
		/* Complete: report the true whole-transfer average. A FILE
		 * meter with total 0 is an empty file and lands here on its
		 * first sample, complete by definition. */
		elapsed = now - meter->start_t;
		transferred = meter->total - meter->start_pos;
		meter->rate_ema = 0;
	}

	/* Require a measurable window. Back-to-back refreshes (the alarm plus
	 * a forced update) give microsecond windows whose division poisons
	 * the EMA for many ticks, so hold the previous rate instead. */
	if (elapsed >= 0.001)
		cur_speed = transferred / elapsed;
	else
		cur_speed = meter->rate_ema;

	/* Smooth the rate, 90 percent history to 10 percent this sample. The
	 * first sample, and the completion reset above, seed it directly. */
	if (meter->rate_ema != 0)
		meter->rate_ema = meter->rate_ema * 0.9 + cur_speed * 0.1;
	else
		meter->rate_ema = cur_speed;
	meter->last_t = now;

	/* time without progress accumulates, and any progress resets it */
	if (transferred == 0)
		meter->stalled += elapsed;
	else
		meter->stalled = 0;

	view.label = meter->label;
	view.cur = meter->cur_pos;
	view.total = meter->total;
	if (total_unknown)
		view.percent = 0;
	/* if meter->total is 0 then we risk a div by 0 and it's also a
	 * valid potential reading */
	else if (meter->total == 0 || meter->cur_pos >= meter->total)
		view.percent = 100;
	else
		view.percent = (int)((float)meter->cur_pos / meter->total * 100);
	view.rate = (long long)meter->rate_ema;
	if (bytes_left > 0 || total_unknown)
		view.inst = delta_pos;
	else
		view.inst = meter->max_delta;	/* complete: show the peak */
	view.delta = delta_pos;
	view.elapsed = elapsed;
	/* An ETA too large for the frame's u32 reads as unknown. Converting
	 * an out-of-range double to an integer is undefined. */
	view.eta_sec = HPNS_ETA_UNKNOWN;
	if (bytes_left > 0 && meter->rate_ema > 0 &&
	    bytes_left / meter->rate_ema < HPNS_ETA_UNKNOWN)
		view.eta_sec = (uint32_t)(bytes_left / meter->rate_ema);
	view.stalled = meter->stalled >= HPN_METER_STALL_SEC;
	view.done = !total_unknown && bytes_left <= 0;
	view.elapsed_sec = (long)elapsed;

	pm_dispatch_view(&view, force_update);
	/* the next sample's delta starts here */
	meter->last_pos = meter->cur_pos;
}

/* ---- relay source ----------------------------------------------------- */

/* The relay fill. Everything shown comes from the stored frame telemetry.
 * The only local inputs are wall-clock ages: the total elapsed time for
 * the completion line, and the last frame's age for stall detection, so a
 * dead source does not keep showing its final healthy rate. */
static void
relay_fill(struct hpn_meter *meter, struct meter_view *view)
{
	/* static: the view carries this label back to the caller, past this
	 * frame. The relay is a singleton filled on one thread. */
	static char vlabel[HPN_METER_LABEL_MAX + 16];
	double now = monotime_double();
	uint64_t base, cur, total;
	int silent = now - relay.last_frame >= HPN_METER_STALL_SEC;

	memset(view, 0, sizeof(*view));

	/* Prefix the phase tag, because the label field is cut at the right
	 * edge (win_size - 45) and a suffix would vanish on a narrow terminal.
	 * The resume check comes before the transfer and verify after it, so
	 * the two do not overlap. */
	view->label = meter->label;
	if (relay.resuming) {
		snprintf(vlabel, sizeof(vlabel), "resume check: %s",
		    meter->label);
		view->label = vlabel;
	} else if (relay.verifying) {
		snprintf(vlabel, sizeof(vlabel), "verify: %s", meter->label);
		view->label = vlabel;
	}

	/* A completed-file row: one preserved line per source-side file
	 * boundary, shown as a done row with the file's bytes, its average
	 * and peak rates, and its elapsed time. The average is derived here,
	 * but from the exact byte span between two boundary frames over the
	 * wall time between them. That whole-file quotient cannot alias
	 * against the frame cadence the way a per-sample rate would. */
	if (relay.row_pending) {
		relay.row_pending = 0;
		view->cur = view->total = (off_t)relay.row_bytes;
		view->rate = (long long)relay.row_avg;
		view->inst = (off_t)relay.row_peak;
		view->done = 1;
		view->percent = 100;
		view->elapsed_sec = relay.row_elapsed;
		return;
	}

	/* The live line and the END line. While the transfer runs, show the
	 * source's per-file meter. The frame's cumulative bytes and total,
	 * minus the base recorded at the last boundary, are the current
	 * file's position and size, and the frame's rate and ETA are already
	 * per file. The END line summarizes the whole run, so it goes back
	 * to the cumulative figures. */
	base = relay.file_base;
	if (relay.done)
		base = 0;
	cur = 0;
	if (relay.bytes_done > base)
		cur = relay.bytes_done - base;
	total = 0;
	if (relay.bytes_total > base)
		total = relay.bytes_total - base;
	view->cur = (off_t)cur;
	view->total = (off_t)total;
	/* an unknown (0) total reads 0%, so the relay never claims 100%
	 * before the source has reported a size */
	if (relay.done || (total > 0 && cur >= total))
		view->percent = 100;
	else if (total > 0)
		view->percent = (int)(cur * 100 / total);
	else
		view->percent = 0;
	view->eta_sec = relay.eta_sec;
	view->done = relay.done;
	view->stalled = !relay.done && silent;
	view->elapsed_sec = (long)(now - relay.started);

	/* The rate and inst choices are the relay's own, so they live here
	 * and not in the shared renderer. First, a silent source shows no
	 * rate, because its last value is stale. Second, completion shows
	 * the transfer-phase peak, because a verify-phase hash peak is not a
	 * network rate. The relay never derives a rate or ETA locally. */
	if (relay.done && relay.rate_inst_peak_xfer > 0)
		view->inst = (off_t)relay.rate_inst_peak_xfer;
	else if (relay.done)
		view->inst = (off_t)relay.rate_inst_max;
	else if (silent)
		view->inst = 0;
	else
		view->inst = (off_t)relay.rate_inst;
	if (silent && !relay.done)
		view->rate = 0;
	else
		view->rate = (long long)relay.rate;
}

/* Start the relay meter. It differs from the counter sources on purpose.
 * First, there is no initial paint, because nothing has arrived to paint
 * until the first frame. Second, its counter is a placeholder that exists
 * only because the core requires one. */
void
hpn_meter_relay_start(const char *label)
{
	relay_ctr = 0;
	/* AGGREGATE, because the relay stands for the whole remote run rather
	 * than one file, and its total is unknown until a frame reports it */
	if (meter_init(&relay_meter, &relay_meter, HPN_METER_AGGREGATE,
	    HPN_METER_DOM_TRANSFER, label, 0, &relay_ctr, 0) != 0)
		return;
	/* after init, which clears the whole meter */
	relay_meter.fill = relay_fill;
	memset(&relay, 0, sizeof(relay));
	relay.started = relay.last_frame = monotime_double();
	relay.file_start = relay.started;
	pm_display_begin_relay();
}

/* Restart the per-file tracking at a phase change. The frames' cumulative
 * bytes change domain with the phase, and the new phase's peaks are its
 * own. */
static void
relay_phase_reset(double now)
{
	relay.rate_inst_max = 0;
	relay.file_base = 0;
	relay.file_inst_max = 0;
	relay.file_start = now;
}

/* Take one PROGRESS frame from the remote source. The frame consumers
 * (scp -R and hpn3scp) call this for every frame, and it does nothing
 * unless the relay meter is current. First, it follows the source's phase
 * flags, restarting the per-file tracking when the resume check ends or
 * verify begins. Second, it stores the frame's telemetry for the fill.
 * Third, at a file boundary it paints and keeps a completed-file row.
 * It then asks for an ordinary repaint, which the alarm gates. */
void
hpn_meter_relay_sample(const struct hpns_progress *frame)
{
	double now, span;

	if (current_meter != &relay_meter)
		return;
	now = monotime_double();

	if ((frame->flags & HPNS_F_RESUME) && !relay.resuming)
		relay.resuming = 1;
	else if (relay.resuming && !(frame->flags & HPNS_F_RESUME)) {
		/* the resume check is over and the transfer begins, so the
		 * completion line reflects transfer rates only */
		relay.resuming = 0;
		relay_phase_reset(now);
	}
	if ((frame->flags & HPNS_F_VERIFY) && !relay.verifying) {
		relay.verifying = 1;
		/* latch the transfer peak for the completion line, then
		 * track the verify phase's own peak separately */
		relay.rate_inst_peak_xfer = relay.rate_inst_max;
		relay_phase_reset(now);
	}
	relay.bytes_done = frame->bytes_done;
	if (frame->bytes_total > 0)
		relay.bytes_total = frame->bytes_total;
	relay.rate = frame->rate_bps;
	relay.rate_inst = frame->rate_inst_bps;
	if (frame->rate_inst_bps > relay.rate_inst_max)
		relay.rate_inst_max = frame->rate_inst_bps;
	if (frame->rate_inst_bps > relay.file_inst_max)
		relay.file_inst_max = frame->rate_inst_bps;
	relay.eta_sec = frame->eta_sec;
	relay.last_frame = now;

	/* HPNS_F_BOUNDARY marks a frame the source emitted at a serial file
	 * boundary, carrying that file's exact end state (see
	 * hpn_pm_meter_done). Preserve a completed-file row. Its bytes are the
	 * span since the last boundary, its average is that span over the
	 * wall time, and its peak is the largest frame inst seen within it.
	 * A rise in files_done is not a boundary, because a fleet source's
	 * external counts rise on ordinary ticks and would paint spurious
	 * rows. Rows are limited to one per second, so a source streaming
	 * many small files cannot flood the history. A skipped boundary folds
	 * into the next row, which then covers every file since the last
	 * one. */
	if ((frame->flags & HPNS_F_BOUNDARY) && now - relay.last_break >= 1.0) {
		span = now - relay.file_start;
		relay.last_break = now;
		relay.row_bytes = frame->bytes_done - relay.file_base;
		relay.row_avg = 0;
		if (span >= 0.001)
			relay.row_avg = (uint64_t)(relay.row_bytes / span);
		relay.row_peak = relay.file_inst_max;
		relay.row_elapsed = (long)span;
		relay.row_pending = 1;
		refresh_progress_meter(1);
		/* clear it in case the refresh did not reach the fill */
		relay.row_pending = 0;
		pm_meter_line_break();
		relay.file_base = frame->bytes_done;
		relay.file_start = now;
		relay.file_inst_max = 0;
	}
	refresh_progress_meter(0);
}

/* END received: force the completion line, with 100%, the total elapsed
 * time, and the peak instantaneous rate. The caller still closes the meter
 * for the trailing newline. */
void
hpn_meter_relay_end(uint64_t bytes_done)
{
	double now, dur;

	if (current_meter != &relay_meter)
		return;
	relay.bytes_done = bytes_done;
	if (bytes_done > relay.bytes_total)
		relay.bytes_total = bytes_done;
	relay.done = 1;
	/* The phases are over at END, so the completion line summarizes the
	 * transfer without a "verify:" or "resume check:" prefix. */
	relay.verifying = 0;
	relay.resuming = 0;
	/* The whole-run average for the completion line, matching the local
	 * meter. It is computed over the full local duration, so the frames'
	 * per-tick steps cannot alias it. */
	now = monotime_double();
	dur = now - relay.started;
	relay.rate = 0;
	if (dur >= 0.001)
		relay.rate = (uint64_t)(bytes_done / dur);
	relay.rate_inst = 0;
	relay.last_frame = now;
	refresh_progress_meter(1);
}

/* Close the relay meter. Any completion line was painted by
 * hpn_meter_relay_end. A close without an end, from a garbled stream,
 * paints nothing, so a broken source never shows a fake completion. */
void
hpn_meter_relay_stop(void)
{
	if (current_meter != &relay_meter)
		return;
	pm_display_end_relay();
	current_meter = NULL;
	relay_meter.active = 0;
}
