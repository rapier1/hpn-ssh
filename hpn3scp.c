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

#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "progressmeter.h"
#include "xmalloc.h"
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
	    "usage: hpn3scp [-46AVZrv] [-j streams] [-o ssh_option] [-X sftp_option]\n"
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
	char buf[1024], *m;
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
		xasprintf(&m, "could not probe %s for hpnscp (is it "
		    "reachable? set HPN3SCP_REMOTE_HPNSCP to override)",
		    s->src.host);
		proto_emit_error(m);
		free(m);
		return -1;
	}
	buf[strcspn(buf, "\r\n")] = '\0';
	if (buf[0] != '/') {
		xasprintf(&m, "%s has no hpnscp on its PATH (set "
		    "HPN3SCP_REMOTE_HPNSCP to its absolute path)",
		    s->src.host);
		proto_emit_error(m);
		free(m);
		return -1;
	}
	strlcpy(out, buf, outlen);
	return 0;
}

/*
 * Decoded frames -> output.  Protocol mode relays them as EVENT lines;
 * human mode (stdout is a terminal) drives a local progress meter instead,
 * exactly as hpnscp's -R consumer does.
 */
static struct {
	char	 label[1100];	/* "srchost => dsthost", local argv data only */
	off_t	 ctr;		/* meter counter, fed from frames */
	off_t	 total;
	int	 on;
} meter;

/* per-transfer failure tally, for the completion summary */
static struct {
	unsigned int	verify;
	unsigned int	transfer;
} failtally;

/* the END frame's authoritative counts, for the completion summary */
static struct {
	uint32_t	files_done;
	int		got;
} endinfo;

static void
ev_hello(const struct hpns_hello *hl, void *ctx)
{
	(void)ctx;
	if (hl->total_bytes > 0)
		meter.total = (off_t)hl->total_bytes;
}

static void
ev_progress(const struct hpns_progress *p, void *ctx)
{
	(void)ctx;
	if (proto_human()) {
		meter.ctr = (off_t)p->bytes_done;
		if (p->bytes_total > 0)
			meter.total = (off_t)p->bytes_total;
		if (!meter.on) {
			start_progress_meter(meter.label, meter.total,
			    &meter.ctr);
			meter.on = 1;
		}
		progress_meter_set_total(meter.total);
		refresh_progress_meter(0);
		return;
	}
	proto_emit_progress(p->bytes_done, p->bytes_total, p->rate_bps,
	    p->eta_sec, p->files_done, p->files_total, p->workers_active,
	    p->workers_stalled);
}

static void
ev_end(const struct hpns_end *e, void *ctx)
{
	(void)ctx;
	endinfo.files_done = e->files_done;
	endinfo.got = 1;
	if (proto_human()) {
		meter.ctr = (off_t)e->bytes_done;
		return;
	}
	proto_emit_progress(e->bytes_done, e->bytes_done, 0, 0, e->files_done,
	    e->files_done + e->files_failed, 0, 0);
}

static void
ev_file_fail(const struct hpns_filefail *ff, void *ctx)
{
	(void)ctx;
	if ((ff->kind & HPNS_FF_KINDMASK) == HPNS_FF_VERIFY)
		failtally.verify++;
	else
		failtally.transfer++;
	/* structured emit; the borrowed path is consumed now (percent-encoded)
	 * and not retained.  Human mode is a no-op here - the source's stderr
	 * already carries the per-file detail. */
	proto_emit_file_fail(ff->kind, ff->path, ff->path_len);
}

static void
ev_tick(void *ctx)
{
	(void)ctx;
	if (meter.on)
		refresh_progress_meter(0);
}

static void
ev_degrade(void *ctx)
{
	(void)ctx;
	if (meter.on) {
		stop_progress_meter();
		meter.on = 0;
	}
	proto_emit_warning("source is not sending status; the transfer "
	    "continues without progress");
}

/*
 * Human-mode completion summary (walk-away confidence): only when -V/-Z was
 * requested.  A clean run confirms verification; a verify failure points at
 * the per-file detail the source already printed above.  No-op in protocol
 * mode - the front end builds its own summary from the file_fail + done events.
 */
static void
emit_completion_summary(struct launch_session *s)
{
	if (!proto_human() || !s->verify_requested)
		return;
	if (failtally.verify > 0)
		fprintf(stderr, "hpn3scp: WARNING: %u file%s failed "
		    "verification (see above)\n", failtally.verify,
		    failtally.verify == 1 ? "" : "s");
	else if (failtally.transfer == 0 && endinfo.got)
		fprintf(stderr, "hpn3scp: verified: %u file%s OK\n",
		    endinfo.files_done, endinfo.files_done == 1 ? "" : "s");
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

	/* source-key-only default: no agent is forwarded and the source
	 * authenticates to the target with its own key.  -A opts into
	 * forwarding the user's ambient agent instead. */
	ssh_base_args(s, &a, 1, s->use_ambient);
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

	snprintf(meter.label, sizeof(meter.label), "%s => %s",
	    s->src.host, s->dst.host);

	memset(&h, 0, sizeof(h));
	h.on_hello = ev_hello;
	h.on_progress = ev_progress;
	h.on_end = ev_end;
	h.on_file_fail = ev_file_fail;
	h.on_tick = ev_tick;
	h.on_degrade = ev_degrade;
	h.passthrough_fd = -1;
	h.ctx = s;

	r = hpn_run_status(&a, &s->child, &h);
	freeargs(&a);
	if (meter.on) {
		refresh_progress_meter(1);
		stop_progress_meter();
		meter.on = 0;
	}
	return r;
}

/*
 * -A path: confirm the user's ambient agent is present and non-empty (we
 * cannot see per-key constraints, only presence/count).  0 ok, -1 with a
 * specific error emitted.
 */
static int
check_ambient_agent(void)
{
	struct ssh_identitylist *idl = NULL;
	int fd, r, nkeys = 0;

	if (getenv("SSH_AUTH_SOCK") == NULL) {
		proto_emit_error("-A given but no ssh-agent is running "
		    "(SSH_AUTH_SOCK unset); start one (hpnssh-agent) and load "
		    "your key (hpnssh-add)");
		return -1;
	}
	if (ssh_get_authentication_socket(&fd) != 0) {
		proto_emit_error("-A given but the agent at SSH_AUTH_SOCK is "
		    "unreachable (stale socket?)");
		return -1;
	}
	r = ssh_fetch_identitylist(fd, &idl);
	ssh_close_authentication_socket(fd);
	if (r == 0 && idl != NULL)
		nkeys = (int)idl->nkeys;
	if (idl != NULL)
		ssh_free_identitylist(idl);
	if (nkeys == 0) {
		proto_emit_error("-A given but your agent holds no keys; "
		    "hpnssh-add the key that opens the target");
		return -1;
	}
	return 0;
}

/*
 * Preflight the A->C hop before any workers spawn: run
 * `ssh [-A] A "ssh -o BatchMode=yes ... C true"`.  Default (source-key-only)
 * omits -A so the test is whether the source can reach the target with its
 * OWN key; with -A the user's ambient agent is forwarded and tested instead.
 * 0 if the source can authenticate; -1 with a classified error emitted
 * (auth / host key / unreachable), naming the hosts and the fix.
 */
static int
auth_preflight(struct launch_session *s)
{
	arglist a;
	char buf[8192], target[600], *m;
	int rc;

	/* 2>&1 brings the inner ssh's diagnostics back on stdout so we can
	 * classify the failure */
	ssh_base_args(s, &a, 0, s->use_ambient);
	addargs(&a, "ssh");
	addargs(&a, "-o");
	addargs(&a, "BatchMode=yes");
	addargs(&a, "-o");
	addargs(&a, "ConnectTimeout=10");
	addargs(&a, "-o");
	addargs(&a, "StrictHostKeyChecking=yes");
	if (s->addr_family == 4)
		addargs(&a, "-4");
	else if (s->addr_family == 6)
		addargs(&a, "-6");
	if (s->dst.port != -1) {
		addargs(&a, "-p");
		addargs(&a, "%d", s->dst.port);
	}
	snprintf(target, sizeof(target), "%s%s%s",
	    s->dst.user != NULL ? s->dst.user : "",
	    s->dst.user != NULL ? "@" : "", s->dst.host);
	addargs(&a, "%s", target);
	addargs(&a, "true");
	addargs(&a, "2>&1");
	rc = hpn_run_capture(&a, buf, sizeof(buf), 30000);
	freeargs(&a);

	if (rc == 0)
		return 0;			/* A can authenticate to C */

	if (strstr(buf, "Permission denied") != NULL ||
	    strstr(buf, "Too many authentication") != NULL) {
		if (s->use_ambient) {
			xasprintf(&m, "%s cannot authenticate to %s: your "
			    "forwarded agent holds no key %s accepts - "
			    "hpnssh-add the right key", s->src.host,
			    s->dst.host, s->dst.host);
		} else {
			char portopt[16] = "";

			/* a copy-pasteable fix: ssh-copy-id run on the source */
			if (s->dst.port != -1)
				snprintf(portopt, sizeof(portopt), "-p %d ",
				    s->dst.port);
			xasprintf(&m, "%s cannot authenticate to %s with its "
			    "own key - run \"ssh-copy-id %s%s%s%s\" on %s, or "
			    "re-run with -A to forward your agent",
			    s->src.host, s->dst.host, portopt,
			    s->dst.user != NULL ? s->dst.user : "",
			    s->dst.user != NULL ? "@" : "", s->dst.host,
			    s->src.host);
		}
	} else if (strstr(buf, "Host key verification failed") != NULL) {
		xasprintf(&m, "%s could not verify %s's host key during "
		    "preflight", s->src.host, s->dst.host);
	} else {
		xasprintf(&m, "%s could not reach %s for a preflight check "
		    "(unreachable or timed out)", s->src.host, s->dst.host);
	}
	proto_emit_error(m);
	free(m);
	return -1;
}

static int
run_session(struct launch_session *s)
{
	const char *why = NULL;
	char sd[512], dd[512], abs_hpnscp[1024], *m;
	struct target_keyset set;
	int r, ret = 1, knows;

	memset(&set, 0, sizeof(set));

	s->phase = LP_RESOLVE;
	proto_emit_phase(phase_name(s->phase));
	if (resolve_endpoint(s->src_arg, &s->src, &why) != 0 ||
	    resolve_endpoint(s->dst_arg, &s->dst, &why) != 0) {
		proto_emit_error(why);
		goto fail;
	}
	endpoint_desc(&s->src, sd, sizeof(sd));
	endpoint_desc(&s->dst, dd, sizeof(dd));
	proto_emit_resolved(sd, dd, s->streams);

	/*
	 * Stage 2 - host-key trust broker: only if the source does not already
	 * trust the target.  Fetch the target's keys via the source, verify
	 * (SSHFP or ssh-style prompt), and add them to the source's
	 * known_hosts for the strict launch.
	 */
	knows = hpn3scp_source_knows_target(s);
	if (knows != 1) {
		s->phase = LP_FETCH_TARGET_KEY;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_fetch_target_keys(s, &set) != 0) {
			xasprintf(&m, "could not retrieve %s's host key via "
			    "%s", s->dst.host, s->src.host);
			proto_emit_error(m);
			free(m);
			goto fail;
		}
		s->phase = LP_CONFIRM_KEY;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_confirm_target(s, &set) != 0)
			goto fail;
		s->phase = LP_PROVISION;
		proto_emit_phase(phase_name(s->phase));
		if (hpn3scp_provision_target(s, &set) != 0) {
			xasprintf(&m, "could not add %s's host key to %s's "
			    "known_hosts", s->dst.host, s->src.host);
			proto_emit_error(m);
			free(m);
			goto fail;
		}
	} else {
		debug("source already trusts %s; skipping host-key brokering",
		    s->dst.host);
	}

	/*
	 * Stage 3 - credential.  SOURCE-KEY-ONLY by default: the source
	 * authenticates to the target with its own key, so the user's key
	 * never leaves B and no agent is ever forwarded.  -A opts into
	 * forwarding the user's ambient agent (unconstrained - the agent
	 * design forbids an intermediate host signing with a forwarded
	 * constrained key; see hpn-launcher-design.md sec 15) for sources
	 * that have no key of their own on the target.
	 */
	if (s->use_ambient && check_ambient_agent() != 0)
		goto fail;

	/* preflight the A->C hop before any workers spawn */
	s->phase = LP_AUTH_PREFLIGHT;
	proto_emit_phase(phase_name(s->phase));
	if (auth_preflight(s) != 0)
		goto fail;			/* error emitted in preflight */

	s->phase = LP_LAUNCH;
	proto_emit_phase(phase_name(s->phase));
	if (discover_remote_hpnscp(s, abs_hpnscp, sizeof(abs_hpnscp)) != 0)
		goto fail;
	debug("source hpnscp: %s", abs_hpnscp);	/* visible under -v */

	s->phase = LP_MONITOR;
	proto_emit_phase(phase_name(s->phase));
	r = do_launch(s, abs_hpnscp);
	emit_completion_summary(s);

	s->phase = LP_COMPLETE;
	proto_emit_phase(phase_name(s->phase));
	proto_emit_done(r == 0, r == 0 ? 0 : 1);
	ret = (r == 0) ? 0 : 1;
	goto out;

 fail:
	proto_emit_done(0, 1);
	ret = 1;
 out:
	hpn3scp_free_keyset(&set);
	return ret;
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
	while ((ch = getopt(argc, argv, "j:Arvo:X:Y:46VZ")) != -1) {
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
			s.use_ambient = 1;
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
		case 'V':
			addargs(&hpnscp_extra, "-V");
			s.verify_requested = 1;
			break;
		case 'Z':
			addargs(&hpnscp_extra, "-Z");
			s.verify_requested = 1;	/* resume implies verification */
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
	/* a terminal gets the human rendering; a pipe gets the EVENT protocol */
	if (isatty(STDOUT_FILENO))
		proto_set_human(1);
	return run_session(&s);
}
