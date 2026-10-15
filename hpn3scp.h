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

/* hpn3scp.h - session state for the third-party transfer launcher.
 *
 * hpn3scp runs on the launcher and copies files directly from a source
 * host to a target host. This header holds what one run carries through
 * its phases: the parsed endpoints, the options, and the pid of the ssh
 * that runs the copy. hpn3scp.c owns the session. The host-key broker
 * reads it, and hpn3scp-proto.c reports the endpoints. */

#ifndef HPN3SCP_H
#define HPN3SCP_H

#include <sys/types.h>	/* for pid_t */

/* Defined in misc.h. Only pointers are needed here. */
struct arglist;

/* The phases of one run, in the order hpn3scp.c emits them. The host-key
 * phases are skipped when the source host already trusts the target, and
 * the fetch repeats when port 2222 falls back to 22. Every run ends with
 * COMPLETE, a failed one too. */
enum run_phase {
	RUN_RESOLVE,		/* parse the endpoint specs */
	RUN_FETCH_TARGET_KEY,	/* the source host scans the target's keys */
	RUN_CONFIRM_KEY,	/* decide which keys the source may trust */
	RUN_PROVISION,		/* add them to the source's known_hosts */
	RUN_LAUNCH,		/* start hpnscp on the source host */
	RUN_MONITOR,		/* relay its status frames as progress events */
	RUN_COMPLETE		/* the run ended, and the done event follows */
};

/* One endpoint of the copy, parsed from an scp:// URI or [user@]host:path */
struct endpoint {
	char	*user;		/* checked by valid_user(), NULL if not given */
	char	*host;		/* checked by valid_host(), never NULL */
	int	 port;		/* -1 when not given */
	/* As given, so a relative path stays under the login home. NULL when
	 * an scp:// URI names no path. */
	char	*path;
};

/* Everything one run knows. main() fills in the operands and options, and
 * run_session() parses the endpoints and drives the phases. */
struct run_state {
	/* the two operands as given, parsed into src and dst */
	const char	*src_arg;
	const char	*dst_arg;
	struct endpoint	 src;
	struct endpoint	 dst;
	int		 streams;	/* -j, 1 when not given */
	int		 use_ambient;	/* -A: forward the ambient agent */
	int		 verbosity;	/* -v count, passed to ssh and hpnscp */
	int		 addr_family;	/* 4 or 6 for -4 or -6, else 0 */
	int		 verify_requested;	/* -V or -Z given */
	int		 verify_full;		/* -V given */
	/* -r, -V, -Z, -z, -o, the forwarded -X options, and the words of -Y,
	 * passed on to the source's hpnscp */
	struct arglist	*hpnscp_extra;
	/* runtime */
	pid_t		 child;		/* launch ssh pid, or -1 */
};

/* Build the ssh command that reaches the source host, up to and including
 * the host. The caller appends the remote command. with_n adds -n and
 * with_agent adds -A. Defined in hpn3scp.c and shared with the host-key
 * broker. */
void	ssh_base_args(const struct run_state *, struct arglist *, int with_n,
	    int with_agent);

/* Add -4 or -6 when the user chose an address family. Shared with the
 * host-key broker. */
void	add_addr_family_arg(const struct run_state *, struct arglist *);

#endif /* HPN3SCP_H */
