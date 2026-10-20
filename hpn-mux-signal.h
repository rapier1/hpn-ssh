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

/* hpn-mux-signal.h - hpnssh -O signal: signal a ControlMaster's sessions.
 *
 * A master advertises HPN_MUX_SIGNAL_EXT in its mux hello. A client that
 * sees it sends an info request under the same name, and the master then
 * sends the "signal" channel request for INT on every session it carries
 * for its mux clients. The source's sshd signals the session's process
 * group. hpn3scp uses it to cancel a copy on a source too old for the
 * stdin lifeline. */

#ifndef HPN_MUX_SIGNAL_H
#define HPN_MUX_SIGNAL_H

struct ssh;

/* the mux extension, and the name of the info request that uses it */
#define HPN_MUX_SIGNAL_EXT	"hpn-signal@hpnssh.org"

/* Master side. Send INT to every session the master carries for its mux
 * clients. Returns the reply message for the client, which the caller
 * frees. */
char	*hpn_mux_signal_sessions(struct ssh *);

#endif /* HPN_MUX_SIGNAL_H */
