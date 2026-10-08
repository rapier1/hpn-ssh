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

/* hpn3scp.c - the third-party transfer launcher.
 *
 * hpn3scp runs on the launcher and copies files directly from a source
 * host to a target host, without the data passing through the launcher.
 * It works through a fixed sequence of phases. It resolves the endpoints,
 * brokers the target's host key into the source's known_hosts when the
 * source does not already trust it, checks that the source can
 * authenticate to the target, then launches hpnscp on the source and
 * relays its progress. All progress and decisions go through hpn3scp-proto,
 * so the command line and the GUI drive the same engine. */

#include "includes.h"

#include <sys/types.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "ssh.h"		/* SSH_MAX_* sizes readconf.h needs */
#include "readconf.h"	/* ssh_valid_ruser */
#include "progressmeter.h"
#include "hpn-meter.h"	/* relay meter source */
#include "xmalloc.h"
#include "hpn3scp.h"
#include "hpn3scp-hostkey.h"
#include "hpn3scp-proto.h"
#include "sftp-hpn-transferlog.h"
#include "hpn3scp-run.h"
#include "hpn-launch-args.h"

/* The local relay meter in human mode: its label and whether it has
 * started. */
static struct {
	char	 label[HPN_METER_LABEL_MAX];	/* "source => target" */
	int	 on;
} meter;

/* per-transfer failure tally, for the completion summary */
static struct {
	u_int	verify;
	u_int	transfer;
} failtally;

/* the END frame's authoritative counts, for the completion summary */
static struct {
	uint32_t	files_done;
	/* END's ok byte. 0 means the source reported failure, even when no
	 * FILEFAIL arrived, because serial transfer errors send none. */
	int		ok;
	int		got;	/* an END frame arrived */
} endinfo;

/* The name of a phase as the GUI sees it, the value of a PHASE event. */
static const char *
phase_name(enum launch_phase phase)
{
	switch (phase) {
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
	    "usage: hpn3scp [-46AVZrv] [-j streams] [-o ssh_option]\n"
	    "               [-X sftp_option] [-Y switches] [-z level]\n"
	    "               source target\n");
	exit(1);
}

/* Reject a username that is unsafe in the source's command line. Two
 * upstream rules apply. ssh_valid_ruser() rejects a leading '-', control
 * characters, and the shell operators. scp.c's okname() rule, written
 * here with explicit ASCII tests, rejects spaces, quotes, '#', and
 * high-bit bytes. */
static int
valid_user(const char *user)
{
	const u_char *cursor = (const u_char *)user;

	if (*cursor == '\0' || !ssh_valid_ruser(user))
		return 0;
	for (; *cursor != '\0'; cursor++) {
		if (*cursor & 0x80)
			return 0;			/* no high-bit bytes */
		if ((*cursor >= 'A' && *cursor <= 'Z') ||
		    (*cursor >= 'a' && *cursor <= 'z') ||
		    (*cursor >= '0' && *cursor <= '9'))
			continue;			/* alphanumeric ok */
		switch (*cursor) {
		case '\'':
		case '"':
		case '`':
		case ' ':
		case '#':
			return 0;			/* shell hazards */
		default:
			break;				/* other punctuation ok */
		}
	}
	return 1;
}

/* Accept a host that is safe to embed in the source's command line: a
 * domain name or IPv4 address, as upstream's valid_domain() checks, or an
 * IPv6 literal. Anything else, including a leading '-', control
 * characters, and shell metacharacters, is rejected. */
static int
valid_host(const char *host)
{
	struct in6_addr addr6;
	char *copy;
	int ok;

	/* valid_domain() may strip a trailing dot, so it checks a copy */
	copy = xstrdup(host);
	ok = valid_domain(copy, 0, NULL);
	free(copy);
	if (!ok && strchr(host, ':') != NULL)
		ok = inet_pton(AF_INET6, host, &addr6) == 1;
	return ok;
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
	if (!valid_host(host)) {
		*why = "invalid host name";
		free(user);
		free(host);
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

/* The decoded-frame callbacks. Protocol mode relays each frame as an EVENT
 * line. Human mode, when stdout is a terminal, drives a local meter
 * rendered entirely from the frames through hpn_meter_relay_*, as hpnscp's
 * -R consumer does, so no rate or ETA is re-derived from arrival times. */

static void
ev_hello(const struct hpns_hello *hl, void *ctx)
{
	(void)ctx;
	(void)hl;	/* totals arrive in PROGRESS frames */
}

static void
ev_progress(const struct hpns_progress *p, void *ctx)
{
	(void)ctx;
	if (proto_human()) {
		if (!meter.on) {
			hpn_meter_relay_start(meter.label);
			meter.on = 1;
		}
		hpn_meter_relay_sample(p);
		return;
	}
	proto_emit_progress(p);
}

static void
ev_end(const struct hpns_end *e, void *ctx)
{
	struct hpns_progress last;

	(void)ctx;
	endinfo.files_done = e->files_done;
	endinfo.ok = e->ok;
	endinfo.got = 1;
	if (proto_human()) {
		if (meter.on)
			hpn_meter_relay_end(e->bytes_done);
		return;
	}
	/* synthesize the final 100% snapshot; phases are over by END and
	 * rates are unknowable, so flags, rates, and eta stay zero */
	memset(&last, 0, sizeof(last));
	last.bytes_done = e->bytes_done;
	last.bytes_total = e->bytes_done;
	last.files_done = e->files_done;
	last.files_total = e->files_done + e->files_failed;
	proto_emit_progress(&last);
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
	proto_emit_file_fail(ff);
}

static void
ev_filedone(const struct hpns_filedone *fd, void *ctx)
{
	(void)ctx;
	/* Launcher-side transfer log: the path is opaque remote bytes; the
	 * module percent-encodes before it lands in the log.  Protocol mode
	 * additionally emits the EVENT (no-op for a human - the log and the
	 * meter cover that case). */
	transferlog_file_bytes(transferlog_status_from_wire(fd->status),
	    (off_t)fd->size, fd->path, fd->path_len);
	proto_emit_file_status(fd);
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
		hpn_meter_relay_stop();
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
	else if (endinfo.got && !endinfo.ok) {
		/* The source reported failure without per-file FILEFAIL
		 * detail (serial transfer errors emit none): never claim
		 * anything was verified OK. */
		fprintf(stderr, "hpn3scp: WARNING: the source reported the "
		    "transfer incomplete (see errors above)\n");
	} else if (endinfo.got) {
		/* OK = files sent minus those that failed to transfer */
		u_int ok = endinfo.files_done > failtally.transfer ?
		    endinfo.files_done - failtally.transfer : 0;

		if (s->verify_full)
			fprintf(stderr, "hpn3scp: verified: %u file%s OK\n",
			    ok, ok == 1 ? "" : "s");
		else
			fprintf(stderr, "hpn3scp: %u file%s OK\n",
			    ok, ok == 1 ? "" : "s");
	}
}

/* Build the source hpnscp's own arguments: everything after the word
 * hpnscp, ending in -- and the two operands. Both launch modes send the
 * same list, on stdin or on the command line. */
static void
launch_hpnscp_args(struct launch_session *s, arglist *args)
{
	int i;

	memset(args, 0, sizeof(*args));
	/* the target key is trusted by now (broker or pre-existing), so hold
	 * the workers to strict checking; a user -o after this can override */
	addargs(args, "-o");
	addargs(args, "StrictHostKeyChecking=yes");
	for (i = 0; i < s->verbosity; i++)	/* -v propagates to the source hpnscp */
		addargs(args, "-v");
	if (s->addr_family == 4)		/* the A->C transfer hop */
		addargs(args, "-4");
	else if (s->addr_family == 6)
		addargs(args, "-6");
	for (i = 0; i < (int)s->hpnscp_extra->num; i++)	/* -r/-V/-Z/-o/-X/-Y */
		addargs(args, "%s", s->hpnscp_extra->list[i]);
	if (s->streams > 1) {
		addargs(args, "-j");
		addargs(args, "%d", s->streams);
	}
	if (s->dst.port != -1) {
		addargs(args, "-P");
		addargs(args, "%d", s->dst.port);
	}
	/* -- so a source path starting with '-' is never read as an option */
	addargs(args, "--");
	addargs(args, "%s", s->src.path != NULL ? s->src.path : ".");
	addargs(args, "%s%s%s:%s",
	    s->dst.user != NULL ? s->dst.user : "",
	    s->dst.user != NULL ? "@" : "",
	    s->dst.host, s->dst.path != NULL ? s->dst.path : "");
}

/* Start the source's hpnscp (a bare word, resolved by the source's PATH
 * exactly as stock scp resolves its remote command) to push directly to
 * the target, and relay its status as events. hpn_launch_args_run() keeps
 * the arguments off the source's shell and handles a legacy source. Raw
 * bytes from a source that does not speak frames are discarded
 * (passthrough_fd = -1), never written to our protocol stdout. Returns 0,
 * HPN_EXIT_STRICT_ARGS for a refused legacy source, HPN_LAUNCH_REFUSED when
 * the copy was refused before it ran, or -1. */
static int
do_launch(struct launch_session *s)
{
	struct hpn_launch launch;
	struct hpn_run_hooks hooks;
	arglist args, ssh_stdin, ssh_legacy;
	int r;

	snprintf(meter.label, sizeof(meter.label), "%s => %s",
	    s->src.host, s->dst.host);

	launch_hpnscp_args(s, &args);
	/* Source-key-only default: no agent is forwarded and the source
	 * authenticates to the target with its own key. -A opts into
	 * forwarding the user's ambient agent instead. Stdin mode needs
	 * stdin, so only the legacy prefix has -n. */
	ssh_base_args(s, &ssh_stdin, 0, s->use_ambient);
	ssh_base_args(s, &ssh_legacy, 1, s->use_ambient);

	memset(&hooks, 0, sizeof(hooks));
	hooks.on_hello = ev_hello;
	hooks.on_progress = ev_progress;
	hooks.on_end = ev_end;
	hooks.on_file_fail = ev_file_fail;
	hooks.on_filedone = ev_filedone;
	hooks.on_tick = ev_tick;
	hooks.on_degrade = ev_degrade;
	hooks.passthrough_fd = -1;
	hooks.ctx = s;

	memset(&launch, 0, sizeof(launch));
	launch.ssh_stdin = &ssh_stdin;
	launch.ssh_legacy = &ssh_legacy;
	launch.program = "hpnscp";
	/* "log" additionally asks the source for per-file FILEDONE frames
	 * (the transfer log / GUI file list); old sources treat any value
	 * as plain arming and the log degrades to header + footer. */
	launch.relay = "HPN_ENABLE_REMOTE_PROGRESS=1";
	if (transferlog_active())
		launch.relay = "HPN_ENABLE_REMOTE_PROGRESS=log";
	/* hpn3scp always relays, so both modes use the same hooks */
	launch.legacy_relay = 1;
	launch.args = &args;
	launch.source_host = s->src.host;
	launch.hooks = &hooks;
	launch.plain_hooks = &hooks;
	launch.pidp = &s->child;
	launch.warn = proto_emit_warning;
	launch.fail = proto_emit_error;

	r = hpn_launch_args_run(&launch);
	if (meter.on) {
		refresh_progress_meter(1);
		hpn_meter_relay_stop();
		meter.on = 0;
	}
	freeargs(&args);
	freeargs(&ssh_stdin);
	freeargs(&ssh_legacy);
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
	/* -- so a target starting with '-' is never read as an option */
	addargs(&a, "--");
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
	char sd[512], dd[512], *m;
	struct target_keyset set;
	int r, ret = 1, knows, counts_known;

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

	s->phase = LP_MONITOR;
	proto_emit_phase(phase_name(s->phase));
	r = do_launch(s);
	emit_completion_summary(s);

	/* a refused legacy source keeps its own exit status */
	ret = 0;
	if (r == HPN_EXIT_STRICT_ARGS)
		ret = HPN_EXIT_STRICT_ARGS;
	else if (r != 0)
		ret = 1;
	/* The counts are known when the source sent its END frame, or when
	 * the launch was refused before anything ran and so moved nothing,
	 * as for a failure before the launch. */
	counts_known = endinfo.got || r == HPN_EXIT_STRICT_ARGS ||
	    r == HPN_LAUNCH_REFUSED;
	s->phase = LP_COMPLETE;
	proto_emit_phase(phase_name(s->phase));
	proto_emit_done(r == 0, ret, counts_known, endinfo.files_done,
	    failtally.verify, failtally.transfer);
	goto out;

 fail:
	/* nothing was launched, so the zero counts are known */
	proto_emit_done(0, 1, 1, 0, 0, 0);
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
	while ((ch = getopt(argc, argv, "j:Arvo:X:Y:46VZz:")) != -1) {
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
			s.verify_full = 1;
			break;
		case 'Z':
			addargs(&hpnscp_extra, "-Z");
			s.verify_requested = 1;	/* resume implies verification */
			break;
		case 'z':
			/* HPN: zstd on the source->target transfer; forward
			 * the level to the source hpnscp verbatim. */
			addargs(&hpnscp_extra, "-z");
			addargs(&hpnscp_extra, "%s", optarg);
			break;
		case 'o':
			addargs(&hpnscp_extra, "-o");
			addargs(&hpnscp_extra, "%s", optarg);
			break;
		case 'X':
			/* The transfer log is written on this host, so
			 * TransferLog is not forwarded to the source. */
			if (transferlog_option(optarg))
				break;
			/* StrictArgs governs this launch, not the source */
			if (hpn_launch_args_option(optarg))
				break;
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
	/* -X TransferLog: open the log before any connection. The open is
	 * the writability check. */
	transferlog_begin();
	i = run_session(&s);
	transferlog_close();
	return i;
}
