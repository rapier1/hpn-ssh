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
 * hpn-meter.c - progress meter core. See hpn-meter.h for the model and
 * hpn-progressmeter-rework-design.md for the design it implements.
 *
 * This file owns the meter object and the counter-source fill. The fill is
 * the serial per-file sample math, ported from refresh_progress_meter with
 * the parallel-only handling left out on purpose: a counter source is
 * monotonic by contract, so the negative-delta clamp has nothing to clamp,
 * and the kind disambiguates a zero total, so the rate-only fallback for an
 * unknown denominator does not apply to a FILE meter.
 */

#include "includes.h"

#include <sys/types.h>

#include <string.h>

#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "hpn-meter.h"

/* Stall threshold in seconds. Matches STALL_TIME in progressmeter.c. */
#define HPN_METER_STALL_SEC	5

/*
 * The meter currently driving the display. One at a time: every serial
 * caller runs meters sequentially, and the display session (alarm, TTY,
 * log guard) is itself a singleton in progressmeter.c.
 */
static struct hpn_meter *current_meter;

/* Core-owned storage for the serial meter; see hpn-meter.h. */
static struct hpn_meter serial_meter;

struct hpn_meter *
hpn_meter_serial(void)
{
	return &serial_meter;
}

int
hpn_meter_display_active(void)
{
	return current_meter != NULL;
}

/*
 * True when the calling thread may run the current meter's fill. Checked
 * by refresh_progress_meter BEFORE it consumes the alarm flag: a bound
 * meter's tick must be left for the owning thread, not eaten by whichever
 * worker's receive path called refresh first and then returned without
 * painting.
 */
int
hpn_meter_display_thread_ok(void)
{
	struct hpn_meter *m = current_meter;

	return m == NULL || !m->display_bound ||
	    pthread_equal(pthread_self(), m->display_tid);
}

/*
 * Start a meter. The kind, domain, and file count are fixed here for the
 * meter's whole life. The label is copied, not borrowed. Returns -1 and
 * starts nothing if a meter is already current, which no legal caller
 * sequence produces today.
 */
static int
meter_init(struct hpn_meter *m, const void *owner,
    enum hpn_meter_kind kind, enum hpn_meter_domain domain,
    const char *label, off_t total, off_t *ctr, u_int nfiles)
{
	if (m == NULL || ctr == NULL)
		return -1;
	if (current_meter != NULL) {
		error_f("meter \"%s\" already active", current_meter->label);
		return -1;
	}

	memset(m, 0, sizeof(*m));
	strlcpy(m->label, label != NULL ? label : "transfer",
	    sizeof(m->label));
	m->kind = kind;
	m->domain = domain;
	m->owner = owner;
	m->total = total;
	m->ctr = ctr;
	m->nfiles = nfiles;
	m->start_t = m->last_t = monotime_double();
	/*
	 * Seed the positions at the counter's starting value: a resumed
	 * transfer's counter begins at the resume offset, and a zero seed
	 * would paint that whole offset as the first instantaneous rate.
	 * cur_pos stays 0 as the first-sample sentinel the fill tests.
	 */
	m->start_pos = m->last_pos = *ctr;
	m->cur_pos = 0;
	m->active = 1;
	current_meter = m;

	/* Same order as start_progress_meter: tell the frame emitter a
	 * meter began, then run the display session mechanics, which end
	 * with the initial forced paint routed back to this meter. */
	hpn_pm_meter_start();
	/*
	 * The kind and domain drive the frame-side declarations the old API
	 * left to each caller after start, which is how the bundle meter
	 * came to be counted as one file. A WORK meter is not a file, and
	 * its domain names the phase a frame consumer labels: hash bytes
	 * are the resume check, and work-bytes are the verify pass. The
	 * flag persists past stop on purpose; the next meter start clears
	 * it, which is the existing frame timing.
	 */
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

int
hpn_meter_start(struct hpn_meter *m, const void *owner,
    enum hpn_meter_kind kind, enum hpn_meter_domain domain,
    const char *label, off_t total, off_t *ctr, u_int nfiles)
{
	if (meter_init(m, owner, kind, domain, label, total, ctr,
	    nfiles) != 0)
		return -1;
	pm_display_begin();
	return 0;
}

/*
 * Owner gate shared by stop and the update entry points: the meter must be
 * current and active, and the caller must be the owner that started it.
 * Anything else is a caller holding a stale handle and is refused loudly
 * rather than folded into the wrong meter (review findings #9 and #28 were
 * exactly such updates landing on a meter their caller did not own). The
 * update entry points below are display-thread only: for the fleet meter
 * that is the reporter, and nothing else may call them.
 */
static int
meter_owned(struct hpn_meter *m, const void *owner, const char *what)
{
	if (m == NULL || !m->active || m != current_meter)
		return 0;
	if (owner != m->owner) {
		error_f("%s for \"%s\" from a non-owner ignored",
		    what, m->label);
		return 0;
	}
	return 1;
}

/*
 * Grow the total and file count. Additive on purpose: a later enumeration
 * grows a live denominator instead of replacing it, so the meter can never
 * read a frozen 100 percent because a second command shrank the total
 * under the bytes already counted (review finding #9).
 */
void
hpn_meter_add_total(struct hpn_meter *m, const void *owner,
    off_t add_bytes, u_int add_files)
{
	if (!meter_owned(m, owner, "total update"))
		return;
	if (add_bytes > 0)
		m->total += add_bytes;
	m->nfiles += add_files;
}

/*
 * Replace the total outright. For the reporter's resume-check stretch,
 * which temporarily runs the meter in the hash-byte domain and restores
 * the transfer total afterwards; ordinary growth uses hpn_meter_add_total.
 */
void
hpn_meter_retotal(struct hpn_meter *m, const void *owner, off_t total)
{
	if (!meter_owned(m, owner, "retotal"))
		return;
	m->total = total;
}

/*
 * Restrict the fill to one thread. Every thread that drives refresh
 * reaches the fill, and for the fleet meter that includes workers on each
 * received message and the walker on the control connection; their fills
 * would race the reporter's updates, which ThreadSanitizer confirmed.
 * Binding makes their refresh calls no-ops for this meter, so the
 * reporter's alarm-gated tick is the only sampler.
 */
void
hpn_meter_bind_display(struct hpn_meter *m, const void *owner, pthread_t tid)
{
	if (!meter_owned(m, owner, "display bind"))
		return;
	m->display_tid = tid;
	m->display_bound = 1;
}

/* Replace the label. The meter owns the copy, as at start. */
void
hpn_meter_relabel(struct hpn_meter *m, const void *owner, const char *label)
{
	if (!meter_owned(m, owner, "relabel") || label == NULL)
		return;
	strlcpy(m->label, label, sizeof(m->label));
}

/*
 * Stop a meter. Only the owner that started it may stop it.
 */
void
hpn_meter_stop(struct hpn_meter *m, const void *owner)
{
	if (!meter_owned(m, owner, "stop"))
		return;
	/*
	 * The display session needs two positions: the last painted one to
	 * decide whether a final repaint is owed (a completed transfer's
	 * last alarm paint is usually short of 100%), and the fresh counter
	 * for the completion frame's byte totals.
	 */
	pm_display_end(m->cur_pos, *m->ctr, m->total, m->rate_ema);
	current_meter = NULL;
	m->active = 0;
}

/*
 * Counter-source fill: sample the counter, derive rate and stall state,
 * fill a view, and hand it to the sinks. Called from
 * refresh_progress_meter after the shared cadence gates (alarm flag,
 * forced update, window resize), so the math here runs at most a few
 * times a second however often the transfer loop drives refresh.
 */
void
hpn_meter_refresh_current(int force_update)
{
	struct hpn_meter *m = current_meter;
	struct meter_view v;
	off_t transferred, bytes_left, delta_pos;
	double now, elapsed, cur_speed;
	int total_unknown;

	if (m == NULL)
		return;
	if (m->display_bound &&
	    !pthread_equal(pthread_self(), m->display_tid))
		return;

	/* A source with its own fill (the relay) supplies the whole view;
	 * the counter math below is the builtin fill. */
	if (m->fill != NULL) {
		struct meter_view v;

		m->fill(m, &v);
		pm_dispatch_view(&v, force_update);
		return;
	}

	transferred = *m->ctr - (m->cur_pos ? m->cur_pos : m->start_pos);
	m->cur_pos = *m->ctr;
	now = monotime_double();
	bytes_left = m->total - m->cur_pos;

	delta_pos = m->cur_pos - m->last_pos;
	if (delta_pos > m->max_delta)
		m->max_delta = delta_pos;

	/* An AGGREGATE meter with no total yet is a rate-only meter, not a
	 * completed one: its denominator arrives mid-flight when the
	 * enumeration drains. Every other kind reads a zero total as an
	 * empty transfer, complete on its first sample. */
	total_unknown = (m->kind == HPN_METER_AGGREGATE && m->total == 0);
	if (bytes_left > 0 || total_unknown)
		elapsed = now - m->last_t;
	else {
		/* Complete: report the true whole-transfer average. A FILE
		 * meter with total 0 is an empty file and lands here on its
		 * first sample, complete by definition. */
		elapsed = now - m->start_t;
		transferred = m->total - m->start_pos;
		m->rate_ema = 0;
	}

	/* Require a measurable window: back-to-back refreshes (alarm plus a
	 * forced update) give microsecond windows whose division poisons
	 * the EMA for many ticks. Hold the previous rate instead. */
	if (elapsed >= 0.001)
		cur_speed = transferred / elapsed;
	else
		cur_speed = m->rate_ema;

	if (m->rate_ema != 0)
		m->rate_ema = m->rate_ema * 0.9 + cur_speed * 0.1;
	else
		m->rate_ema = cur_speed;
	m->last_t = now;

	if (transferred == 0)
		m->stalled += elapsed;
	else
		m->stalled = 0;

	v.label = m->label;
	v.cur = m->cur_pos;
	v.total = m->total;
	if (total_unknown)
		v.percent = 0;
	else if (m->total == 0 || m->cur_pos >= m->total)
		v.percent = 100;
	else
		v.percent = (int)((float)m->cur_pos / m->total * 100);
	v.rate = (long long)m->rate_ema;
	v.inst = (bytes_left > 0 || total_unknown) ? delta_pos : m->max_delta;
	v.delta = delta_pos;
	v.elapsed = elapsed;
	v.eta_sec = (bytes_left > 0 && m->rate_ema > 0) ?
	    (uint32_t)(bytes_left / m->rate_ema) : HPNS_ETA_UNKNOWN;
	v.stalled = m->stalled >= HPN_METER_STALL_SEC;
	v.done = !total_unknown && bytes_left <= 0;
	v.elapsed_sec = (long)elapsed;

	pm_dispatch_view(&v, force_update);
	m->last_pos = m->cur_pos;
}

/* ---- relay source ----------------------------------------------------- */

/*
 * HPN status relay, consumer side: render remote telemetry verbatim.
 * Everything painted comes from the last PROGRESS frame - no rate, delta,
 * or ETA is ever derived locally, because the counter would advance only
 * when a ~1 Hz frame lands and sampling that against the local clock
 * aliases (alternating 0 and 2x-link-speed readings).  Opt-in: only the
 * frame consumers (scp -R, hpn3scp) enter this mode; local meters never
 * touch it and their math path is unchanged.
 */
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
static off_t relay_ctr;		/* the core requires a counter; the
				 * relay fill never reads it */
static struct hpn_meter relay_meter;	/* core-owned, like serial_meter */

/*
 * Fill a view from the stored remote telemetry. Ported from the old
 * relay_render; the only changes are the label coming from the meter's
 * owned copy instead of the borrowed file global, and the view being
 * returned for the shared dispatch instead of rendered directly, which
 * also puts relay views into the HPN_PM_DEBUG capture for the first time.
 */
/*
 * Relay-mode paint: everything shown comes from the stored frame
 * telemetry.  The only local inputs are wall-clock ages: total elapsed
 * for the completion line and the last-frame age for stall detection
 * (a dead source must not keep displaying its final healthy rate).
 */
static void
relay_fill(struct hpn_meter *m, struct meter_view *view)
{
	char vlabel[512];
	const char *label = m->label;
	double now = monotime_double();
	struct meter_view v;
	int silent = now - relay.last_frame >= HPN_METER_STALL_SEC;

	memset(&v, 0, sizeof(v));

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

	v.label = label;
	v.cur = (off_t)relay.bytes_done;
	v.total = (off_t)relay.bytes_total;
	v.eta_sec = relay.eta_sec;
	v.done = relay.done;
	v.stalled = !relay.done && silent;
	v.elapsed_sec = (long)(now - relay.started);
	/* Relay policy: an unknown (0) total reads 0% - do not claim 100%
	 * before the source has reported a size. */
	if (relay.done || (relay.bytes_total > 0 &&
	    relay.bytes_done >= relay.bytes_total))
		v.percent = 100;
	else if (relay.bytes_total > 0)
		v.percent = (int)(relay.bytes_done * 100 / relay.bytes_total);
	else
		v.percent = 0;

	/*
	 * Source-specific display choices live in the fill, not the shared
	 * renderer.  A silent source: blank the rate/inst - its last value is
	 * stale (a dead source must not keep showing a healthy rate).  On
	 * completion: show the TRANSFER-phase peak inst (a verify-phase hash
	 * peak is not a network rate).  The relay never derives rate/eta
	 * locally; both ride in the frame (see the relay struct comment).
	 */
	if (relay.done)
		v.inst = (off_t)(relay.rate_inst_peak_xfer > 0 ?
		    relay.rate_inst_peak_xfer : relay.rate_inst_max);
	else if (silent)
		v.inst = 0;
	else
		v.inst = (off_t)relay.rate_inst;
	v.rate = (silent && !relay.done) ? 0 : (long long)relay.rate;

	*view = v;
}


/*
 * Start the relay meter. Differs from the counter sources on purpose: no
 * initial paint (nothing has arrived to paint until the first frame) and
 * the placeholder counter exists only to satisfy the core.
 */
void
hpn_meter_relay_start(const char *label)
{
	relay_ctr = 0;
	if (meter_init(&relay_meter, &relay_meter, HPN_METER_AGGREGATE,
	    HPN_METER_DOM_TRANSFER, label, 0, &relay_ctr, 0) != 0)
		return;
	relay_meter.fill = relay_fill;
	memset(&relay, 0, sizeof(relay));
	relay.started = relay.last_frame = monotime_double();
	pm_display_begin_relay();
}

/* Store one PROGRESS frame's telemetry and repaint (alarm-gated). */
void
hpn_meter_relay_sample(const struct hpns_progress *p)
{
	if (current_meter != &relay_meter)
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
 * instantaneous rate).  The caller still closes the meter
 * for the trailing newline.
 */
void
hpn_meter_relay_end(u_int64_t bytes_done)
{
	double dur;

	if (current_meter != &relay_meter)
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
 * Close the relay meter. The completion line, if any, was painted by
 * hpn_meter_relay_end; a close without an end (a garbled stream) paints
 * nothing, so a broken source never shows a fake completion.
 */
void
hpn_meter_relay_stop(void)
{
	if (current_meter != &relay_meter)
		return;
	pm_display_end_relay();
	current_meter = NULL;
	relay_meter.active = 0;
}
