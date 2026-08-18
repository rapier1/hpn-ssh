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
 * hpn-meter - progress meter core.
 *
 * A meter is a named view over one progress source. It owns its label,
 * declares what it measures when it starts (kind and byte domain), and is
 * updated only by the owner that started it. Sources produce samples, the
 * fill turns a sample into a struct meter_view, and the sinks (TTY render,
 * status frames, and the HPN_PM_DEBUG capture) consume the view. The
 * design, the per-caller requirements, and the threading rule live in
 * hpn-progressmeter-rework-design.md.
 *
 * progressmeter.c keeps the display session mechanics (alarm, TTY arming,
 * the log interleave guard, and the sink dispatch) and the stock formatting
 * primitives. This unit holds no knowledge of the transfer code: callers
 * hand it a label, a total, and a counter to watch.
 */

#ifndef HPN_METER_H
#define HPN_METER_H

#include <sys/types.h>

#include <pthread.h>

struct meter_view;
struct hpns_progress;

/*
 * What a meter measures. Declared at start, never after: the old API let a
 * caller mark a running meter "not a file" once it was already live, and
 * the callers that never did (the bundle path) were miscounted. The kind
 * also disambiguates a zero total: a FILE meter with total 0 is a genuinely
 * empty file and renders complete, where an AGGREGATE meter with total 0 is
 * an unknown denominator and renders rate-only.
 */
enum hpn_meter_kind {
	HPN_METER_FILE = 0,	/* one file; counts 1 toward file totals */
	HPN_METER_BUNDLE,	/* one meter carrying nfiles files */
	HPN_METER_WORK,		/* hash or verify work; not a file */
	HPN_METER_AGGREGATE,	/* fleet-wide; file counts arrive externally */
};

/*
 * The byte domain the total and counter live in. Carried so a consumer,
 * and especially stop, knows what the numbers mean: verify counts
 * work-bytes at twice the moved bytes because both ends hash every byte,
 * and snapping a transfer-byte display to a work-byte total is how the old
 * code needed a side flag to avoid lying at completion.
 */
enum hpn_meter_domain {
	HPN_METER_DOM_TRANSFER = 0,	/* bytes moved */
	HPN_METER_DOM_HASH,		/* bytes hashed once (resume check) */
	HPN_METER_DOM_WORK,		/* work-bytes, 2x moved (verify) */
};

#define HPN_METER_LABEL_MAX	128

struct hpn_meter {
	char	label[HPN_METER_LABEL_MAX];	/* owned copy, never borrowed */
	enum hpn_meter_kind	kind;
	enum hpn_meter_domain	domain;
	off_t	total;		/* denominator; 0 reads per the kind */
	volatile off_t *ctr;	/* borrowed; must outlive the meter, and only
				 * the meter's own thread may write it except
				 * for the fleet source (see the design doc's
				 * threading section) */
	u_int	nfiles;		/* how many files this meter represents */
	const void *owner;	/* opaque token; updates and stop must match */

	/*
	 * Source-specific view fill; NULL runs the builtin counter fill.
	 * Set inside the meter unit by sources whose view does not derive
	 * from a local counter (the relay).
	 */
	void	(*fill)(struct hpn_meter *m, struct meter_view *v);

	/*
	 * When bound, only this thread may run the fill: the fleet meter is
	 * sampled by every thread that drives refresh (workers per received
	 * message, the walker on the control connection, the alarm), and an
	 * unbound fill from any of them would race the reporter's updates on
	 * this struct. Serial meters stay unbound; their fill runs on the
	 * one thread that owns the transfer.
	 */
	int	display_bound;
	pthread_t display_tid;

	/* Sample state, written by the fill between start and stop. */
	off_t	start_pos, cur_pos, last_pos, max_delta;
	double	start_t, last_t;
	double	rate_ema;
	double	stalled;
	int	active;
};

/*
 * The serial meter object, owned by this unit so its storage can never
 * dangle into a caller's dead stack frame. One serial meter runs at a
 * time, which is the existing behaviour of every serial caller.
 */
struct hpn_meter *hpn_meter_serial(void);

int	hpn_meter_start(struct hpn_meter *m, const void *owner,
	    enum hpn_meter_kind kind, enum hpn_meter_domain domain,
	    const char *label, off_t total, off_t *ctr, u_int nfiles);
void	hpn_meter_stop(struct hpn_meter *m, const void *owner);

/* Owner-checked updates, display-thread only (the reporter for the fleet
 * meter): grow the total additively, replace it (resume-check stretch),
 * or replace the owned label. */
void	hpn_meter_add_total(struct hpn_meter *m, const void *owner,
	    off_t add_bytes, u_int add_files);
void	hpn_meter_retotal(struct hpn_meter *m, const void *owner, off_t total);
void	hpn_meter_relabel(struct hpn_meter *m, const void *owner,
	    const char *label);
/* Restrict the fill to one thread (the reporter, for the fleet meter). */
void	hpn_meter_bind_display(struct hpn_meter *m, const void *owner,
	    pthread_t tid);

/*
 * Relay source: a meter over hpns_progress frames from a remote transfer
 * (scp -R and hpn3scp consume these). No local counter exists; rate and
 * ETA ride in the frames because deriving them from ~1 Hz frame arrival
 * against the local clock aliases. Start arms the display without an
 * initial paint (nothing has arrived to paint), end paints the completion
 * line, and stop closes the display session.
 */
void	hpn_meter_relay_start(const char *label);
void	hpn_meter_relay_sample(const struct hpns_progress *p);
void	hpn_meter_relay_end(u_int64_t bytes_done);
void	hpn_meter_relay_stop(void);

/* Display routing used by progressmeter.c: is a core meter current, and
 * fill-and-dispatch it on the shared refresh cadence. */
int	hpn_meter_display_active(void);
int	hpn_meter_display_thread_ok(void);
void	hpn_meter_refresh_current(int force_update);

#endif /* HPN_METER_H */
