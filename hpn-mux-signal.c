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

/* hpn-mux-signal.c - the master side of hpnssh -O signal (see
 * hpn-mux-signal.h). mux.c carries the call sites: the hello extension,
 * the info request, and the client's -O command. */

#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "ssherr.h"
#include "packet.h"
#include "channels.h"
#include "hpn-mux-signal.h"

/* the signal sent, INT, as a terminal's ^C sends */
#define HPN_MUX_SIGNAL_NAME	"INT"

/* Send the signal request on c when it is an open session that a mux
 * client opened, and count it. Stdio forwards and the master's own
 * channels are left alone. No reply is asked for, because a server that
 * refuses the request, as sshd does for a forced command, has nothing
 * the client could act on. */
static void
signal_session(struct ssh *ssh, Channel *c, void *ctx)
{
	u_int *count = ctx;
	int r;

	if (c->ctl_chan == -1 || c->type != SSH_CHANNEL_OPEN ||
	    c->ctype == NULL || strcmp(c->ctype, "session") != 0)
		return;
	channel_request_start(ssh, c->self, "signal", 0);
	if ((r = sshpkt_put_cstring(ssh, HPN_MUX_SIGNAL_NAME)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "channel %d: send signal request", c->self);
	(*count)++;
}

/* Send INT to every mux session and report how many got it. */
char *
hpn_mux_signal_sessions(struct ssh *ssh)
{
	char *msg;
	u_int count = 0;

	channel_foreach(ssh, signal_session, &count);
	debug_f("sent %s to %u session(s)", HPN_MUX_SIGNAL_NAME, count);
	xasprintf(&msg, "Sent %s to %u session(s)\r\n", HPN_MUX_SIGNAL_NAME,
	    count);
	return msg;
}
