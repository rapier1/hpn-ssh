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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "hpn3scp.h"
#include "hpn3scp-hostkey.h"
#include "hpn3scp-proto.h"
#include "hpn3scp-run.h"

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
	    "usage: hpn3scp [-46Arv] [-j streams] [-o ssh_option] [-X sftp_option]\n"
	    "               [-Y \"hpnscp switches\"] source target\n");
	exit(1);
}

/*
 * Drive the phase machine.  Stage 0: emit the opening phases over the
 * protocol, then report that the trust-broker/launch phases are not yet
 * built.  Returns the process exit status.
 */
/*
 * Reject usernames carrying shell-hazard characters before they are embedded
 * in the remote command line - same intent as scp.c's okname(), written with
 * explicit ASCII tests so it is locale-independent like the rest of hpn3scp.
 */
static int
valid_user(const char *u)
{
	const u_char *p = (const u_char *)u;

	if (*p == '\0')
		return 0;
	for (; *p != '\0'; p++) {
		if (*p & 0x80)
			return 0;			/* no high-bit bytes */
		if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
		    (*p >= '0' && *p <= '9'))
			continue;			/* alphanumeric ok */
		switch (*p) {
		case '\'': case '"': case '`': case ' ': case '#':
			return 0;			/* shell hazards */
		default:
			break;				/* other punctuation ok */
		}
	}
	return 1;
}

/*
 * Parse one endpoint argument - an scp:// URI or a plain [user@]host:path -
 * into ep.  Returns 0 for a valid REMOTE endpoint; -1 otherwise with *why set
 * to a short reason.  The scp:// path rule (one slash after the port = home-
 * relative, two = absolute) is inherited from parse_uri().
 */
static int
resolve_endpoint(const char *arg, struct endpoint *ep, const char **why)
{
	char *user = NULL, *host = NULL, *path = NULL;
	int port = -1, r;

	memset(ep, 0, sizeof(*ep));
	ep->port = -1;

	r = parse_uri("scp", arg, &user, &host, &port, &path);
	if (r == -1) {
		*why = "invalid scp:// uri";
		return -1;
	}
	if (r == 1) {
		/* not a URI: [user@]host:path */
		if (parse_user_host_path(arg, &user, &host, &path) == -1) {
			*why = "not a valid [user@]host:path";
			return -1;
		}
		port = -1;
	}
	if (host == NULL) {
		*why = "endpoint has no host (a third-party copy needs two "
		    "remote hosts)";
		free(user);
		free(path);
		return -1;
	}
	if (user != NULL && !valid_user(user)) {
		*why = "invalid username";
		free(user);
		free(host);
		free(path);
		return -1;
	}
	ep->user = user;
	ep->host = host;
	ep->port = port;
	ep->path = path;
	return 0;
}

/* [user@]host[:port]:path for display only (never fed back to a shell) */
static void
endpoint_desc(const struct endpoint *ep, char *buf, size_t len)
{
	char portbuf[16] = "";

	if (ep->port != -1)
		snprintf(portbuf, sizeof(portbuf), ":%d", ep->port);
	snprintf(buf, len, "%s%s%s%s:%s",
	    ep->user != NULL ? ep->user : "", ep->user != NULL ? "@" : "",
	    ep->host, portbuf, ep->path != NULL ? ep->path : "");
}

/*
 * Build the ssh command used to reach the source A, up to and including the
 * host - the caller appends the remote command.  with_n adds -n (no stdin,
 * for the launch); with_agent adds -A (opt-in forwarding, section 0).
 */
void
ssh_base_args(struct launch_session *s, arglist *a, int with_n, int with_agent)
{
	int i;

	memset(a, 0, sizeof(*a));
	a->list = NULL;
	addargs(a, "%s", _PATH_SSH_PROGRAM);
	addargs(a, "-x");
	addargs(a, "-oClearAllForwardings=yes");
	if (with_n)
		addargs(a, "-n");
	if (with_agent)
		addargs(a, "-A");
	for (i = 0; i < s->verbosity; i++)	/* -v propagates to the launch ssh */
		addargs(a, "-v");
	if (s->addr_family == 4)		/* -4/-6 applies to every hop */
		addargs(a, "-4");
	else if (s->addr_family == 6)
		addargs(a, "-6");
	if (s->src.port != -1) {
		addargs(a, "-p");
		addargs(a, "%d", s->src.port);
	}
	if (s->src.user != NULL) {
		addargs(a, "-l");
		addargs(a, "%s", s->src.user);
	}
	addargs(a, "--");
	addargs(a, "%s", s->src.host);
}

/*
 * Discover the absolute path of hpnscp on the source and return it in out.
 * An explicit override wins (documented escape hatch); otherwise probe the
 * source's PATH with `command -v hpnscp` and require an absolute path -
 * never a bare name, so PATH shadowing on the source becomes an early,
 * legible failure instead of a mid-transfer surprise.
 */
static int
discover_remote_hpnscp(struct launch_session *s, char *out, size_t outlen)
{
	arglist a;
	char buf[1024];
	const char *env;
	int r;

	if ((env = getenv("HPN3SCP_REMOTE_HPNSCP")) != NULL && *env != '\0') {
		if (*env != '/') {
			proto_emit_error("HPN3SCP_REMOTE_HPNSCP must be an "
			    "absolute path");
			return -1;
		}
		strlcpy(out, env, outlen);
		return 0;
	}

	ssh_base_args(s, &a, 0, 0);
	addargs(&a, "command -v hpnscp");
	r = hpn_run_capture(&a, buf, sizeof(buf), 20000);
	freeargs(&a);
	if (r != 0) {
		proto_emit_error("could not probe the source for hpnscp "
		    "(is the source reachable? set HPN3SCP_REMOTE_HPNSCP to "
		    "override)");
		return -1;
	}
	buf[strcspn(buf, "\r\n")] = '\0';
	if (buf[0] != '/') {
		proto_emit_error("source has no hpnscp on PATH (set "
		    "HPN3SCP_REMOTE_HPNSCP to its absolute path)");
		return -1;
	}
	strlcpy(out, buf, outlen);
	return 0;
}

/* decoded frames -> protocol events (numbers only) */
static void
ev_progress(const struct hpns_progress *p, void *ctx)
{
	(void)ctx;
	proto_emit_progress(p->bytes_done, p->bytes_total, p->rate_bps,
	    p->eta_sec, p->files_done, p->files_total, p->workers_active,
	    p->workers_stalled);
}

static void
ev_end(const struct hpns_end *e, void *ctx)
{
	(void)ctx;
	proto_emit_progress(e->bytes_done, e->bytes_done, 0, 0, e->files_done,
	    e->files_done + e->files_failed, 0, 0);
}

static void
ev_degrade(void *ctx)
{
	(void)ctx;
	proto_emit_warning("source is not sending status; the transfer "
	    "continues without progress");
}

/*
 * Launch the source's hpnscp (by absolute path) to push directly to the
 * target, and relay its status frames as events.  Mirrors scp.c's proven -R
 * command build: env-armed frames, -j / -P forwarded into the source's
 * hpnscp, target as user@host:path.  Raw bytes from a source that does not
 * speak frames are discarded (passthrough_fd = -1), never written to our
 * protocol stdout.  Returns the child exit status.
 */
static int
do_launch(struct launch_session *s, const char *abs_hpnscp)
{
	arglist a;
	struct hpn_run_hooks h;
	char *cp;
	int r, i;

	ssh_base_args(s, &a, 1, s->forward_agent);
	addargs(&a, "env");
	addargs(&a, "HPN_ENABLE_REMOTE_PROGRESS=1");
	addargs(&a, "%s", abs_hpnscp);
	/* the target key is trusted by now (broker or pre-existing), so hold
	 * the workers to strict checking; a user -o after this can override */
	addargs(&a, "-o");
	addargs(&a, "StrictHostKeyChecking=yes");
	for (i = 0; i < s->verbosity; i++)	/* -v propagates to the source hpnscp */
		addargs(&a, "-v");
	if (s->addr_family == 4)		/* the A->C transfer hop */
		addargs(&a, "-4");
	else if (s->addr_family == 6)
		addargs(&a, "-6");
	for (i = 0; i < (int)s->hpnscp_extra->num; i++)	/* -o/-X/-Y/-r */
		addargs(&a, "%s", s->hpnscp_extra->list[i]);
	if (s->streams > 1) {
		addargs(&a, "-j");
		addargs(&a, "%d", s->streams);
	}
	if (s->dst.port != -1) {
		addargs(&a, "-P");
		addargs(&a, "%d", s->dst.port);
	}
	addargs(&a, "%s", s->src.path != NULL ? s->src.path : ".");
	addargs(&a, "%s%s%s:%s",
	    s->dst.user != NULL ? s->dst.user : "",
	    s->dst.user != NULL ? "@" : "",
	    s->dst.host, s->dst.path != NULL ? s->dst.path : "");

	cp = argv_assemble(a.num, a.list);
	debug("launch: %s", cp);		/* visible under -v */
	free(cp);

	memset(&h, 0, sizeof(h));
	h.on_progress = ev_progress;
	h.on_end = ev_end;
	h.on_degrade = ev_degrade;
	h.passthrough_fd = -1;
	h.ctx = s;

	r = hpn_run_status(&a, &s->child, &h);
	freeargs(&a);
	return r;
}

static int
run_session(struct launch_session *s)
{
	const char *why = NULL;
	char sd[512], dd[512], abs_hpnscp[1024];
	int r;

	s->phase = LP_RESOLVE;
	proto_emit_phase(phase_name(s->phase));
	if (resolve_endpoint(s->src_arg, &s->src, &why) != 0 ||
	    resolve_endpoint(s->dst_arg, &s->dst, &why) != 0) {
		proto_emit_error(why);
		proto_emit_done(0, 1);
		return 1;
	}
	endpoint_desc(&s->src, sd, sizeof(sd));
	endpoint_desc(&s->dst, dd, sizeof(dd));
	proto_emit_resolved(sd, dd, s->streams);

	/*
	 * Stage 2 - host-key trust broker.  If the source already trusts the
	 * target (target in its known_hosts) there is nothing to do; otherwise
	 * fetch the target key, verify it (SSHFP or an ssh-style prompt), and
	 * add it to the source's known_hosts before we launch with strict
	 * checking.  The A->C auth preflight (Stage 3) is still ahead.
	 */
	if (hpn3scp_source_knows_target(s) != 1) {
		struct target_keyset set;

		s->phase = LP_FETCH_TARGET_KEY;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_fetch_target_keys(s, &set) != 0) {
			proto_emit_error("could not retrieve the target host key "
			    "from the source");
			proto_emit_done(0, 1);
			return 1;
		}
		s->phase = LP_CONFIRM_KEY;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_confirm_target(s, &set) != 0) {
			hpn3scp_free_keyset(&set);
			proto_emit_done(0, 1);
			return 1;
		}
		s->phase = LP_PROVISION;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_provision_target(s, &set) != 0) {
			hpn3scp_free_keyset(&set);
			proto_emit_error("could not add the target host key to "
			    "the source's known_hosts");
			proto_emit_done(0, 1);
			return 1;
		}
		hpn3scp_free_keyset(&set);
	} else {
		debug("source already trusts %s; skipping host-key brokering",
		    s->dst.host);
	}

	s->phase = LP_LAUNCH;
	proto_emit_phase(phase_name(s->phase));
	if (discover_remote_hpnscp(s, abs_hpnscp, sizeof(abs_hpnscp)) != 0) {
		proto_emit_done(0, 1);
		return 1;
	}
	debug("source hpnscp: %s", abs_hpnscp);	/* visible under -v */

	s->phase = LP_MONITOR;
	proto_emit_phase(phase_name(s->phase));
	r = do_launch(s, abs_hpnscp);

	s->phase = LP_COMPLETE;
	proto_emit_phase(phase_name(s->phase));
	proto_emit_done(r == 0, r == 0 ? 0 : 1);
	return r == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
	struct launch_session s;
	arglist hpnscp_extra;
	char **av;
	int ch, ac, i;

	/* logs to stderr; stdout is reserved for the control protocol */
	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);
	signal(SIGPIPE, SIG_IGN);	/* we write to child stdins (provision) */

	memset(&s, 0, sizeof(s));
	s.streams = 1;
	s.policy = DP_PROMPT;
	s.child = -1;
	memset(&hpnscp_extra, 0, sizeof(hpnscp_extra));
	s.hpnscp_extra = &hpnscp_extra;

	/*
	 * -o / -X / -Y / -r all just accumulate flags for the source hpnscp:
	 * -o and -X forward one-for-one to hpnscp's own -o (ssh options) and
	 * -X (sftp options); -r forwards -r (recursive); -Y is the escape
	 * hatch for hpnscp's native switches - one quoted string, split with
	 * quote/escape handling so dashes travel intact.
	 */
	while ((ch = getopt(argc, argv, "j:Arvo:X:Y:46")) != -1) {
		switch (ch) {
		case 'j':
			s.streams = (int)strtol(optarg, NULL, 10);
			if (s.streams < 1)
				usage();
			break;
		case '4':
			s.addr_family = 4;
			break;
		case '6':
			s.addr_family = 6;
			break;
		case 'A':
			s.forward_agent = 1;
			break;
		case 'v':
			s.verbosity++;
			log_change_level(s.verbosity == 1 ? SYSLOG_LEVEL_DEBUG1 :
			    s.verbosity == 2 ? SYSLOG_LEVEL_DEBUG2 :
			    SYSLOG_LEVEL_DEBUG3);
			break;
		case 'r':
			addargs(&hpnscp_extra, "-r");
			break;
		case 'o':
			addargs(&hpnscp_extra, "-o");
			addargs(&hpnscp_extra, "%s", optarg);
			break;
		case 'X':
			addargs(&hpnscp_extra, "-X");
			addargs(&hpnscp_extra, "%s", optarg);
			break;
		case 'Y':
			if (argv_split(optarg, &ac, &av, 0) != 0) {
				fprintf(stderr, "hpn3scp: bad -Y value: %s\n",
				    optarg);
				exit(1);
			}
			for (i = 0; i < ac; i++)
				addargs(&hpnscp_extra, "%s", av[i]);
			argv_free(av, ac);
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
