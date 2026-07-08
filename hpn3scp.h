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
 * hpn3scp.h - third-party transfer launcher (B side) engine state.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.  hpn3scp
 * is the B-side orchestrator for direct A->C ("third party") transfers: it
 * drives the shipped hpnscp -R transport, brokers the target host key, runs
 * an A->C auth preflight, and relays live status.  See hpn-launcher-design.md
 * for the full design (this is the Stage 0 skeleton: phase enum + session
 * state + the control protocol; the phase handlers land in later stages).
 */

#ifndef HPN3SCP_H
#define HPN3SCP_H

#include <sys/types.h>

struct arglist;			/* misc.h; only pointers needed here */

/* Phase state machine (hpn-launcher-design.md sec 7). */
enum launch_phase {
	LP_RESOLVE,		/* parse the endpoint specs */
	LP_REACH_SOURCE,	/* open the B->A control link */
	LP_FETCH_TARGET_KEY,	/* keyscan C from A */
	LP_CONFIRM_KEY,		/* present fingerprint; accept/verify */
	LP_PROVISION,		/* write transfer-scoped known_hosts on A */
	LP_AUTH_PREFLIGHT,	/* arrange + test the A->C credential */
	LP_LAUNCH,		/* spawn hpnscp -R via the shared runner */
	LP_MONITOR,		/* consume status frames -> progress events */
	LP_COMPLETE,		/* reap, clean up, report */
	LP_FAILED
};

/*
 * Host-key acceptance policy (Q3, fail-closed).  There is NO blind-accept
 * mode: acceptance requires SSHFP verification, an explicit human accept of
 * the shown fingerprint, or a user-pinned key - else the session fails.
 */
enum decision_policy {
	DP_PROMPT,		/* interactive: SSHFP-verify else prompt+accept */
	DP_VERIFY_OR_FAIL	/* non-interactive: SSHFP/pinned key or abort */
};

/* One transfer endpoint, parsed from an scp:// URI or host:path (Stage 1). */
struct endpoint {
	char	*user;		/* validated (okname) */
	char	*host;		/* validated (valid_domain) */
	int	 port;		/* -1 = default */
	char	*path;		/* home-relative vs absolute preserved */
};

struct launch_session {
	/* raw args (Stage 0); parsed into src/dst in Stage 1 */
	const char	*src_arg;	/* A */
	const char	*dst_arg;	/* C */
	struct endpoint	 src;
	struct endpoint	 dst;
	int		 streams;	/* -j */
	int		 forward_agent;	/* -A: opt-in agent forwarding */
	int		 verbosity;	/* -v count, propagated to ssh + hpnscp */
	int		 addr_family;	/* -4/-6: 4, 6, or 0 (default) - all hops */
	struct arglist	*hpnscp_extra;	/* -r/-o/-X/-Y forwarded to source hpnscp */
	enum decision_policy policy;
	char		*identity;	/* chosen A->C key, or NULL */
	/* runtime */
	enum launch_phase phase;
	pid_t		 child;		/* launch ssh pid, or -1 */
};

const char	*phase_name(enum launch_phase p);

/* build the ssh command that reaches the source A (defined in hpn3scp.c);
 * with_n adds -n, with_agent adds -A.  Shared with the host-key broker. */
void		 ssh_base_args(struct launch_session *s, struct arglist *a,
		    int with_n, int with_agent);

#endif /* HPN3SCP_H */
