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
 * hpn3scp.c - third-party transfer launcher (B side), engine entry point.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.  Stage 0
 * skeleton: argument intake, session setup, the phase-name table, and a
 * dispatcher that walks the phase machine over the real control protocol.
 * Only RESOLVE is wired; the remaining phase handlers arrive in later stages
 * (see hpn-launcher-design.md).  Progress/decision output all flows through
 * hpn3scp-proto so the CLI and a future GUI share one engine.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "hpn3scp.h"
#include "hpn3scp-proto.h"

const char *
phase_name(enum launch_phase p)
{
	switch (p) {
	case LP_RESOLVE:		return "RESOLVE";
	case LP_REACH_SOURCE:		return "REACH_SOURCE";
	case LP_FETCH_TARGET_KEY:	return "FETCH_TARGET_KEY";
	case LP_CONFIRM_KEY:		return "CONFIRM_KEY";
	case LP_PROVISION:		return "PROVISION";
	case LP_AUTH_PREFLIGHT:		return "AUTH_PREFLIGHT";
	case LP_LAUNCH:			return "LAUNCH";
	case LP_MONITOR:		return "MONITOR";
	case LP_COMPLETE:		return "COMPLETE";
	case LP_FAILED:			return "FAILED";
	}
	return "UNKNOWN";
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: hpn3scp [-j streams] source target\n"
	    "       third-party (direct A->C) copy, orchestrated from here.\n");
	exit(1);
}

/*
 * Drive the phase machine.  Stage 0: emit the opening phases over the
 * protocol, then report that the trust-broker/launch phases are not yet
 * built.  Returns the process exit status.
 */
static int
run_session(struct launch_session *s)
{
	s->phase = LP_RESOLVE;
	proto_emit_phase(phase_name(s->phase));
	/* Stage 1 replaces this with real scp:// parsing + validation. */
	proto_emit_resolved(s->src_arg, s->dst_arg, s->streams);

	s->phase = LP_REACH_SOURCE;
	proto_emit_phase(phase_name(s->phase));
	proto_emit_error("stage0 skeleton: phases beyond RESOLVE are not yet "
	    "implemented");

	s->phase = LP_FAILED;
	proto_emit_done(0, 1);
	return 1;
}

int
main(int argc, char **argv)
{
	struct launch_session s;
	int ch;

	/* logs to stderr; stdout is reserved for the control protocol */
	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);

	memset(&s, 0, sizeof(s));
	s.streams = 1;
	s.policy = DP_PROMPT;
	s.child = -1;

	while ((ch = getopt(argc, argv, "j:v")) != -1) {
		switch (ch) {
		case 'j':
			s.streams = (int)strtol(optarg, NULL, 10);
			if (s.streams < 1)
				usage();
			break;
		case 'v':
			log_change_level(SYSLOG_LEVEL_DEBUG1);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();

	s.src_arg = argv[0];
	s.dst_arg = argv[1];

	proto_init(stdout);
	return run_session(&s);
}
