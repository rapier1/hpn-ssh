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
 * Start a meter. The kind, domain, and file count are fixed here for the
 * meter's whole life. The label is copied, not borrowed. Returns -1 and
 * starts nothing if a meter is already current, which no legal caller
 * sequence produces today.
 */
int
hpn_meter_start(struct hpn_meter *m, const void *owner,
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
	if (kind == HPN_METER_WORK) {
		if (domain == HPN_METER_DOM_HASH)
			hpn_pm_set_phase(HPNS_F_RESUME, 1);
		else if (domain == HPN_METER_DOM_WORK)
			hpn_pm_set_phase(HPNS_F_VERIFY, 1);
	}
	pm_display_begin();
	return 0;
}

/*
 * Stop a meter. Only the owner that started it may stop it; anything else
 * is a caller holding a stale handle and is refused loudly rather than
 * folded into the wrong meter's completion.
 */
void
hpn_meter_stop(struct hpn_meter *m, const void *owner)
{
	if (m == NULL || !m->active || m != current_meter)
		return;
	if (owner != m->owner) {
		error_f("stop for \"%s\" from a non-owner ignored", m->label);
		return;
	}
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

	if (m == NULL)
		return;

	transferred = *m->ctr - (m->cur_pos ? m->cur_pos : m->start_pos);
	m->cur_pos = *m->ctr;
	now = monotime_double();
	bytes_left = m->total - m->cur_pos;

	delta_pos = m->cur_pos - m->last_pos;
	if (delta_pos > m->max_delta)
		m->max_delta = delta_pos;

	if (bytes_left > 0)
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
	if (m->total == 0 || m->cur_pos >= m->total)
		v.percent = 100;
	else
		v.percent = (int)((float)m->cur_pos / m->total * 100);
	v.rate = (long long)m->rate_ema;
	v.inst = bytes_left > 0 ? delta_pos : m->max_delta;
	v.delta = delta_pos;
	v.elapsed = elapsed;
	v.eta_sec = (bytes_left > 0 && m->rate_ema > 0) ?
	    (uint32_t)(bytes_left / m->rate_ema) : HPNS_ETA_UNKNOWN;
	v.stalled = m->stalled >= HPN_METER_STALL_SEC;
	v.done = bytes_left <= 0;
	v.elapsed_sec = (long)elapsed;

	pm_dispatch_view(&v, force_update);
	m->last_pos = m->cur_pos;
}
