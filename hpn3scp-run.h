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
 * hpn3scp-run.h - shared status-relay transfer runner.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Extracted from scp.c's -R status path so hpnscp (local ANSI meter) and
 * hpn3scp (structured event stream) share one launch+parse loop.  See
 * hpn-status-relay-design.md and hpn-launcher-design.md.
 *
 * hpn_run_status() forks a command with a piped stdout, parses HPNS status
 * frames from it, and dispatches decoded frames to the caller's hooks.  A
 * garbled stream degrades to verbatim passthrough (telemetry never control):
 * the caller decides where those raw bytes go via passthrough_fd - STDOUT
 * for hpnscp, a discard (-1) for hpn3scp so raw remote bytes never touch its
 * control protocol.  Return value comes from the child's exit status, the
 * same contract as scp's do_local_cmd().
 */

#ifndef HPN3SCP_RUN_H
#define HPN3SCP_RUN_H

#include <sys/types.h>

#include "hpn-status-frame.h"

struct arglist;

/*
 * Per-transfer hooks.  Any hook may be NULL.  Decoded-frame hooks receive
 * the validated struct; on_tick fires roughly once a second (poll timeout /
 * signal wake) so a live local meter can repaint during quiet spells;
 * on_degrade fires once when the frame stream is abandoned for passthrough.
 * ctx is passed to every hook.
 */
struct hpn_run_hooks {
	void (*on_hello)(const struct hpns_hello *, void *ctx);
	void (*on_progress)(const struct hpns_progress *, void *ctx);
	void (*on_end)(const struct hpns_end *, void *ctx);
	void (*on_tick)(void *ctx);
	void (*on_degrade)(void *ctx);
	int  passthrough_fd;	/* raw bytes after degrade go here; <0 = discard */
	void *ctx;
};

/*
 * Fork+exec a->list[0] with a piped stdout, dispatch its HPNS frames to
 * `h`.  If pidp != NULL it receives the child pid after fork and -1 after
 * reap, so the caller's own signal handler can kill the child.  Returns 0
 * if the child exited 0, -1 otherwise.
 */
int	hpn_run_status(struct arglist *a, pid_t *pidp,
	    const struct hpn_run_hooks *h);

#endif /* HPN3SCP_RUN_H */
