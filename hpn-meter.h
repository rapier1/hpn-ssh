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

/* hpn-meter.h - the progress meter core.
 *
 * A meter is a named view over one progress source. It owns its label,
 * declares what it measures when it starts (kind and byte domain), and is
 * updated only by the owner that started it. Sources produce samples, the
 * fill turns a sample into a struct meter_view, and the sinks (TTY render,
 * status frames, and the HPN_PM_DEBUG capture) consume the view. A meter
 * bound to a display thread is filled only on that thread, which for the
 * fleet's meter is the reporter.
 *
 * progressmeter.c keeps the display session mechanics (alarm, TTY arming,
 * the log interleave guard, and the sink dispatch) and the stock formatting
 * primitives. This unit holds no knowledge of the transfer code: callers
 * hand it a label, a total, and a counter to watch. */

#ifndef HPN_METER_H
#define HPN_METER_H

#include <sys/types.h>
#include <stdint.h>

#include <pthread.h>

struct meter_view;
struct hpns_progress;

/* What a meter measures, declared at start and fixed for its life. The
 * kind also disambiguates a zero total. A FILE meter with total 0 is a
 * genuinely empty file and renders complete, while an AGGREGATE meter with
 * total 0 has an unknown denominator and renders rate-only. */
enum hpn_meter_kind {
	HPN_METER_FILE,		/* one file; counts 1 toward file totals */
	HPN_METER_BUNDLE,	/* one meter carrying nfiles files */
	HPN_METER_WORK,		/* hash or verify work; not a file */
	HPN_METER_AGGREGATE,	/* fleet-wide; file counts arrive externally */
};

/* The byte domain a WORK meter's total and counter live in, declared at
 * start. It names the phase a frame consumer labels: hash bytes are the
 * resume check, and work bytes are the verify pass, which counts twice the
 * moved bytes because both ends hash every byte. */
enum hpn_meter_domain {
	HPN_METER_DOM_TRANSFER,		/* bytes moved */
	HPN_METER_DOM_HASH,		/* bytes hashed once (resume check) */
	HPN_METER_DOM_WORK,		/* work-bytes, 2x moved (verify) */
};

/* The longest label a meter keeps, including the NUL. */
#define HPN_METER_LABEL_MAX	128

/* One meter: what it measures, the counter it samples, and the sample
 * state its fill keeps between start and stop. */
struct hpn_meter {
	char	label[HPN_METER_LABEL_MAX];	/* owned copy, never borrowed */
	enum hpn_meter_kind	kind;
	off_t	total;		/* denominator; 0 reads per the kind */
	/* Borrowed, so it must outlive the meter. It is written by the thread
	 * that drives the meter. For the fleet's meter that is the reporter,
	 * plus one final snap by the thread that stops it. */
	volatile off_t *ctr;
	u_int	nfiles;		/* how many files this meter represents */
	const void *owner;	/* opaque token; updates and stop must match */

	/* Source-specific view fill. NULL runs the builtin counter fill. A
	 * source whose view does not come from a local counter (the relay)
	 * sets it inside the meter unit. */
	void	(*fill)(struct hpn_meter *, struct meter_view *);

	/* When bound, only this thread may run the fill. Every thread that
	 * drives refresh samples the fleet's meter (the workers on each
	 * message they receive, the walker on the control connection), and an
	 * unbound fill from any of them would race the reporter's updates to
	 * this struct. Serial meters stay unbound, because their fill runs on
	 * the one thread that owns the transfer. */
	int	display_bound;
	pthread_t display_tid;

	/* Sample state, written by the fill between start and stop. */
	off_t	start_pos, cur_pos, last_pos, max_delta;
	double	start_t, last_t;
	double	rate_ema;
	double	stalled;	/* seconds without progress */
	int	active;		/* set by start, cleared by stop */
};

/* The serial meter object, owned by this unit so its storage can never
 * dangle into a caller's dead stack frame. One serial meter runs at a
 * time, which is the existing behaviour of every serial caller. */
struct hpn_meter *hpn_meter_serial(void);

/* Start a meter with its display session, or stop it. Start returns 0, or
 * -1 with the cause logged and nothing started. Only the owner that
 * started a meter may stop it. */
int	hpn_meter_start(struct hpn_meter *, const void *, enum hpn_meter_kind,
	    enum hpn_meter_domain, const char *, off_t, off_t *, u_int);
void	hpn_meter_stop(struct hpn_meter *, const void *);

/* Owner-checked updates, display-thread only (the reporter for the fleet
 * meter): grow the total additively, replace it (resume-check stretch),
 * or replace the owned label. */
void	hpn_meter_add_total(struct hpn_meter *, const void *, off_t, u_int);
void	hpn_meter_retotal(struct hpn_meter *, const void *, off_t);
void	hpn_meter_relabel(struct hpn_meter *, const void *, const char *);
/* Restrict the fill to one thread (the reporter, for the fleet meter). */
void	hpn_meter_bind_display(struct hpn_meter *, const void *, pthread_t);

/* The relay source: a meter over hpns_progress frames from a remote
 * transfer, which scp -R and hpn3scp consume. No local counter exists. The
 * rate and ETA ride in the frames, because deriving them from frames that
 * arrive about once a second aliases against the local clock. Start arms
 * the display without an initial paint, since nothing has arrived to paint.
 * End paints the completion line, and stop closes the display session. */
void	hpn_meter_relay_start(const char *);
void	hpn_meter_relay_sample(const struct hpns_progress *);
void	hpn_meter_relay_end(uint64_t);
void	hpn_meter_relay_stop(void);

/* Display routing used by progressmeter.c: whether a meter is current,
 * whether this thread may fill it, and the fill-and-dispatch on the shared
 * refresh cadence. */
int	hpn_meter_display_active(void);
int	hpn_meter_display_thread_ok(void);
void	hpn_meter_refresh_current(int);

#endif /* HPN_METER_H */
