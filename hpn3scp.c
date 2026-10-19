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
 * source does not already trust it, then launches hpnscp on the source
 * and relays its progress. All progress goes through hpn3scp-proto, so the
 * command line and the GUI drive the same engine. */

#include "includes.h"

#include <sys/types.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
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
#include "ssherr.h"
#include "hpn-meter.h"	/* relay meter source */
#include "hpn-status-frame.h"	/* the frame structs and flags */
#include "hpn-compress.h"	/* HPN_ZSTD_LEVEL_MIN, HPN_ZSTD_LEVEL_MAX */
#include "sftp-parallel.h"	/* SFTP_PARALLEL_MAX_WORKERS */
#include "xmalloc.h"
#include "hpn3scp.h"
#include "hpn3scp-hostkey.h"
#include "hpn3scp-proto.h"
#include "sftp-hpn-transferlog.h"
#include "hpn3scp-run.h"
#include "hpn-launch-args.h"

/* The local relay meter's label in human mode, "source => target" */
static char meter_label[HPN_METER_LABEL_MAX];

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

/* Liveness after the source's PROGRESS frames stop decoding */
static struct {
	int	warned;		/* the mismatch warning went out */
	int	blind;		/* PROGRESS cannot be read right now */
	double	last_alive;	/* monotime of the last alive event */
} liveness;

/* An idle shared login outlives a killed hpn3scp by at most this long.
 * It must also outlast the user reading the host-key prompt, when no ssh
 * to the source is open. */
#define MUX_PERSIST_SEC		300
/* short, because a socket path is limited to about 104 bytes */
#define MUX_DIR_TEMPLATE	"/tmp/hpn3scp.XXXXXXXXXX"

/* The run's shared login to the source host. Every ssh to the source
 * joins this master through its socket, so a password or MFA user logs
 * in once. The fields are read by a signal handler. */
static struct {
	char	*dir;		/* private directory, or NULL when closed */
	char	 path[64];	/* the master's ControlPath socket */
	pid_t	 pid;		/* the master, or -1 when not known */
	int	 ready;		/* later runs join the master */
} mux = { NULL, "", -1, 0 };

/* The name of a phase as the GUI sees it, the value of a PHASE event. */
static const char *
phase_name(enum run_phase phase)
{
	switch (phase) {
	case RUN_RESOLVE:		return "RESOLVE";
	case RUN_FETCH_TARGET_KEY:	return "FETCH_TARGET_KEY";
	case RUN_CONFIRM_KEY:		return "CONFIRM_KEY";
	case RUN_PROVISION:		return "PROVISION";
	case RUN_LAUNCH:		return "LAUNCH";
	case RUN_MONITOR:		return "MONITOR";
	case RUN_COMPLETE:		return "COMPLETE";
	}
	return "UNKNOWN";
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: hpn3scp [-46ArVvZ] [-j streams] [-o ssh_option]\n"
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
			return 0;	/* shell hazards */
		default:
			break;		/* other punctuation ok */
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

/* Parse one endpoint argument, an scp:// URI or a plain [user@]host:path,
 * into endpoint. Returns 0 for a valid remote endpoint, or -1 with *why
 * set to a short reason. The host and user are checked here, because they
 * reach the source's command line in the keyscan, the host-key check, and
 * a legacy launch. The scp:// path rule, one slash after the port for a
 * home-relative path and two for an absolute one, comes from parse_uri(). */
static int
resolve_endpoint(const char *arg, struct endpoint *endpoint, const char **why)
{
	char *user = NULL, *host = NULL, *path = NULL;
	int port = -1, r;

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->port = -1;

	r = parse_uri("scp", arg, &user, &host, &port, &path);
	if (r == -1) {
		*why = "invalid scp:// uri";
		return -1;
	}
	/* not a URI, so it must be [user@]host:path */
	if (r == 1 && parse_user_host_path(arg, &user, &host, &path) == -1) {
		*why = "not a valid [user@]host:path";
		return -1;
	}
	if (host == NULL) {
		*why = "endpoint has no host (a third-party copy needs two "
		    "remote hosts)";
		goto fail;
	}
	if (!valid_host(host)) {
		*why = "invalid host name";
		goto fail;
	}
	if (user != NULL && !valid_user(user)) {
		*why = "invalid username";
		goto fail;
	}
	endpoint->user = user;
	endpoint->host = host;
	endpoint->port = port;
	endpoint->path = path;
	return 0;

 fail:
	free(user);
	free(host);
	free(path);
	return -1;
}

/* Add -4 or -6 when the user chose an address family. ssh, hpnscp, and
 * ssh-keyscan all take the same flag, so one helper serves every hop. */
void
add_addr_family_arg(const struct run_state *session, arglist *args)
{
	if (session->addr_family == 4)
		addargs(args, "-4");
	else if (session->addr_family == 6)
		addargs(args, "-6");
}

/* The options of every ssh to the source, without the -- and the host,
 * so the shared login's own runs can add theirs first. with_n adds -n
 * for the legacy launch, which sends nothing on stdin. with_agent adds -A
 * for the user's opt-in agent forwarding. */
static void
ssh_source_options(const struct run_state *session, arglist *args,
    int with_n, int with_agent)
{
	int i;

	memset(args, 0, sizeof(*args));
	args->list = NULL;
	addargs(args, "%s", _PATH_SSH_PROGRAM);
	/* no X11 or port forwarding reaches the source */
	addargs(args, "-x");
	addargs(args, "-oClearAllForwardings=yes");
	if (with_n)
		addargs(args, "-n");
	if (with_agent)
		addargs(args, "-A");
	/* the user's -v reaches the ssh to the source */
	for (i = 0; i < session->verbosity; i++)
		addargs(args, "-v");
	add_addr_family_arg(session, args);
	if (session->src.port != -1) {
		addargs(args, "-p");
		addargs(args, "%d", session->src.port);
	}
	if (session->src.user != NULL) {
		addargs(args, "-l");
		addargs(args, "%s", session->src.user);
	}
}

/* Build the ssh command that reaches the source, up to and including the
 * host, joining the run's shared login once it is open. The caller
 * appends the remote command. with_n and with_agent are as for
 * ssh_source_options(). */
void
ssh_base_args(const struct run_state *session, arglist *args,
    int with_n, int with_agent)
{
	ssh_source_options(session, args, with_n, with_agent);
	/* join the master, and never become one */
	if (mux.ready) {
		addargs(args, "-oControlPath=%s", mux.path);
		addargs(args, "-oControlMaster=no");
	}
	/* the host was checked by valid_host(), and -- keeps it an operand */
	addargs(args, "--");
	addargs(args, "%s", session->src.host);
}

/* Stop the master by pid and remove its socket and directory. Only
 * async-signal-safe calls are made, so the signal handler and
 * cleanup_exit() can use it. */
static void
mux_kill(void)
{
	if (mux.pid > 0)
		kill(mux.pid, SIGTERM);
	if (mux.dir != NULL) {
		unlink(mux.path);
		rmdir(mux.dir);
	}
}

/* SIGINT, SIGTERM, or SIGHUP: stop the shared login, then die of the
 * signal. A GUI cancel should instead set a flag that run_session()
 * checks between phases, and tear down through mux_close(). */
static void
mux_signal(int signo)
{
	mux_kill();
	ssh_signal(signo, SIG_DFL);
	kill(getpid(), signo);
}

/* fatal() ends here, so the shared login does not outlive us */
void
cleanup_exit(int i)
{
	mux_kill();
	_exit(i);
}

/* Close the run's shared login: ask the master to exit, then remove its
 * directory. A master that does not answer is stopped by pid. */
static void
mux_close(const struct run_state *session)
{
	arglist args;
	char output[1024];

	if (mux.dir == NULL)
		return;
	if (mux.ready) {
		ssh_source_options(session, &args, 0, 0);
		addargs(&args, "-oControlPath=%s", mux.path);
		addargs(&args, "-O");
		addargs(&args, "exit");
		addargs(&args, "--");
		addargs(&args, "%s", session->src.host);
		/* Capturing stderr keeps "Exit request sent." off the
		 * terminal. An answered exit drops the pid, since the system
		 * may reuse it. */
		if (hpn_run_capture(&args, output, sizeof(output), 5000, NULL,
		    1) == 0)
			mux.pid = -1;
		freeargs(&args);
	}
	mux_kill();
	ssh_signal(SIGINT, SIG_DFL);
	ssh_signal(SIGTERM, SIG_DFL);
	ssh_signal(SIGHUP, SIG_DFL);
	free(mux.dir);
	mux.dir = NULL;
	mux.ready = 0;
	mux.pid = -1;
}

/* Open the run's shared login to the source host: a background master
 * that every later ssh joins. The opener has no deadline, because a
 * person may be typing a password. The master's pid, from -O check, lets
 * a signal stop it. Returns 0, or -1 with an error emitted. */
static int
mux_open(const struct run_state *session)
{
	arglist args;
	char *dir, *msg, *cp, output[1024];
	const char *errstr;
	long long pid;
	int rc;

	dir = xstrdup(MUX_DIR_TEMPLATE);
	if (mkdtemp(dir) == NULL) {
		xasprintf(&msg, "could not create a directory for the login "
		    "to %s: %s", session->src.host, strerror(errno));
		proto_emit_error(msg);
		free(msg);
		free(dir);
		return -1;
	}
	mux.dir = dir;
	snprintf(mux.path, sizeof(mux.path), "%s/m", mux.dir);
	/* from here a signal removes the directory */
	ssh_signal(SIGINT, mux_signal);
	ssh_signal(SIGTERM, mux_signal);
	ssh_signal(SIGHUP, mux_signal);

	/* -f goes to the background once logged in, with its stdio on
	 * /dev/null, so it never holds our output open. The master forwards
	 * the agent for a joining session only when it forwards it itself,
	 * so -A goes on the master too. */
	ssh_source_options(session, &args, 0, session->use_ambient);
	addargs(&args, "-f");
	addargs(&args, "-N");
	addargs(&args, "-oControlMaster=yes");
	addargs(&args, "-oControlPath=%s", mux.path);
	addargs(&args, "-oControlPersist=%d", MUX_PERSIST_SEC);
	addargs(&args, "--");
	addargs(&args, "%s", session->src.host);
	/* an empty payload: run it and wait, however long the login takes */
	rc = hpn_run_feed(&args, "");
	freeargs(&args);
	if (rc != 0) {
		xasprintf(&msg, "could not log in to %s", session->src.host);
		proto_emit_error(msg);
		free(msg);
		mux_close(session);
		return -1;
	}
	mux.ready = 1;

	/* -O check reports "Master running (pid=N)" on stderr */
	ssh_source_options(session, &args, 0, 0);
	addargs(&args, "-oControlPath=%s", mux.path);
	addargs(&args, "-O");
	addargs(&args, "check");
	addargs(&args, "--");
	addargs(&args, "%s", session->src.host);
	rc = hpn_run_capture(&args, output, sizeof(output), 5000, NULL, 1);
	freeargs(&args);
	if (rc == 0 && (cp = strstr(output, "(pid=")) != NULL) {
		cp += strlen("(pid=");
		cp[strcspn(cp, ")")] = '\0';
		pid = strtonum(cp, 2, INT_MAX, &errstr);
		if (errstr == NULL)
			mux.pid = (pid_t)pid;
	}
	if (mux.pid == -1)
		debug("no pid for the login to %s, so a signal leaves it to "
		    "end after %d idle seconds", session->src.host,
		    MUX_PERSIST_SEC);
	return 0;
}

/* The decoded-frame callbacks. Protocol mode relays each frame as an EVENT
 * line. Human mode, when stdout is a terminal, drives a local meter
 * rendered entirely from the frames through hpn_meter_relay_*, as hpnscp's
 * -R consumer does, so no rate or ETA is re-derived from arrival times. */

/* Feed a PROGRESS frame to the local meter in human mode, starting the
 * meter on the first one, or emit it as a progress event. */
static void
ev_progress(const struct hpns_progress *progress, void *ctx)
{
	(void)ctx;
	/* a frame that decodes ends liveness mode */
	liveness.blind = 0;
	if (proto_human()) {
		hpn_meter_relay_sample(meter_label, progress);
		return;
	}
	proto_emit_progress(progress);
}

/* A frame arrived, readable or not. Human mode notes it for the local
 * meter. In protocol mode, while progress cannot be read, an alive event
 * goes out at most once a second, so the front end can show that the copy
 * is running. */
static void
ev_frame(void *ctx)
{
	double now;

	(void)ctx;
	if (proto_human()) {
		hpn_meter_relay_heard(NULL);
		return;
	}
	if (!liveness.blind)
		return;
	now = monotime_double();
	if (now - liveness.last_alive >= 1.0) {
		liveness.last_alive = now;
		proto_emit_alive();
	}
}

/* The source's PROGRESS frames cannot be decoded. Warn once, then show
 * only that the copy is running: the local meter in human mode, and alive
 * events for the front end otherwise. */
static void
ev_mismatch(void *ctx)
{
	struct run_state *session = ctx;
	char *msg;

	if (!liveness.warned) {
		liveness.warned = 1;
		xasprintf(&msg, "Progress data from %s can't be parsed. The "
		    "meter will only show that the copy is running.",
		    session->src.host);
		proto_emit_warning(msg);
		free(msg);
	}
	liveness.blind = 1;
	if (proto_human())
		hpn_meter_relay_blind(meter_label);
}

/* Keep the END frame's counts for the done event and the summary. Then
 * close the meter in human mode, or emit a final progress event. */
static void
ev_end(const struct hpns_end *end, void *ctx)
{
	struct hpns_progress last;

	(void)ctx;
	endinfo.files_done = end->files_done;
	endinfo.ok = end->ok;
	endinfo.got = 1;
	/* the run is over, so no alive event follows */
	liveness.blind = 0;
	if (proto_human()) {
		hpn_meter_relay_end(end->bytes_done);
		return;
	}
	/* A synthesized final snapshot at 100%. Both totals are known by END.
	 * The phases are over and the rates are unknown, so the phase flags,
	 * rates, and ETA stay 0. */
	memset(&last, 0, sizeof(last));
	last.bytes_done = end->bytes_done;
	last.bytes_total = end->bytes_done;
	last.files_done = end->files_done;
	last.files_total = end->files_done + end->files_failed;
	last.flags = HPNS_F_TOTAL_KNOWN | HPNS_F_FILES_KNOWN;
	proto_emit_progress(&last);
}

/* Count a FILEFAIL frame as a verify or a transfer failure and emit a
 * file_fail event. Human mode emits nothing, because the source's stderr
 * already shows the detail. */
static void
ev_file_fail(const struct hpns_filefail *filefail, void *ctx)
{
	(void)ctx;
	if ((filefail->kind & HPNS_FF_KINDMASK) == HPNS_FF_VERIFY)
		failtally.verify++;
	else
		failtally.transfer++;
	/* the path is borrowed from the frame, so it is encoded now */
	proto_emit_file_fail(filefail);
}

/* Write a FILEDONE frame to the launcher-side transfer log and emit a
 * file_status event. Human mode emits nothing, because the log and the
 * meter cover it. */
static void
ev_filedone(const struct hpns_filedone *filedone, void *ctx)
{
	(void)ctx;
	/* the path is opaque remote bytes, which the log percent-encodes */
	transferlog_file_bytes(transferlog_status_from_wire(filedone->status),
	    (off_t)filedone->size, filedone->path, filedone->path_len);
	proto_emit_file_status(filedone);
}

/* Drop the meter and warn when the source stops sending frames. The copy
 * itself carries on. */
static void
ev_degrade(void *ctx)
{
	(void)ctx;
	hpn_meter_relay_stop();
	proto_emit_warning("source is not sending status; the transfer "
	    "continues without progress");
}

/* Print the human-mode completion summary when -V or -Z was given, so the
 * user can walk away and trust the result. A clean run reports the files
 * that came through, and a verify failure points at the per-file detail
 * the source printed above. Protocol mode prints nothing, because the
 * front end builds its own summary from the file_fail and done events. */
static void
emit_completion_summary(const struct run_state *session)
{
	u_int files_ok;

	if (!proto_human() || !session->verify_requested)
		return;
	if (failtally.verify > 0)
		fprintf(stderr, "hpn3scp: WARNING: %u file%s failed "
		    "verification (see above)\n", failtally.verify,
		    failtally.verify == 1 ? "" : "s");
	else if (endinfo.got && !endinfo.ok) {
		/* The source reported failure without FILEFAIL detail, as a
		 * serial transfer error does, so claim no file as verified. */
		fprintf(stderr, "hpn3scp: WARNING: the source reported the "
		    "transfer incomplete (see errors above)\n");
	} else if (endinfo.got) {
		/* the files sent, less those that failed to transfer */
		files_ok = 0;
		if (endinfo.files_done > failtally.transfer)
			files_ok = endinfo.files_done - failtally.transfer;
		fprintf(stderr, "hpn3scp: %s%u file%s OK\n",
		    session->verify_full ? "verified: " : "",
		    files_ok, files_ok == 1 ? "" : "s");
	}
}

/* Build the source hpnscp's own arguments: everything after the word
 * hpnscp, ending in -- and the two operands. Both launch modes send the
 * same list, on stdin or on the command line. */
static void
launch_hpnscp_args(const struct run_state *session, arglist *args)
{
	const char *lbracket = "", *rbracket = "";
	int i;

	memset(args, 0, sizeof(*args));
	/* The target key is trusted by now, from the broker or from before,
	 * so the workers are held to strict checking. ssh keeps the first
	 * value of an option, so a user's -o after this cannot loosen it. */
	addargs(args, "-o");
	addargs(args, "StrictHostKeyChecking=yes");
	/* the user's -v reaches the source hpnscp */
	for (i = 0; i < session->verbosity; i++)
		addargs(args, "-v");
	/* the source to target transfer hop */
	add_addr_family_arg(session, args);
	/* the user's -r, -V, -Z, -z, -o, -X, and -Y */
	for (i = 0; i < (int)session->hpnscp_extra->num; i++)
		addargs(args, "%s", session->hpnscp_extra->list[i]);
	if (session->streams > 1) {
		addargs(args, "-j");
		addargs(args, "%d", session->streams);
	}
	if (session->dst.port != -1) {
		addargs(args, "-P");
		addargs(args, "%d", session->dst.port);
	}
	/* -- so a source path starting with '-' is never read as an option */
	addargs(args, "--");
	addargs(args, "%s",
	    session->src.path != NULL ? session->src.path : ".");
	/* Brackets keep an IPv6 target's colons apart from the path. Without
	 * them hpnscp reads ::1:path as a local file name. */
	if (strchr(session->dst.host, ':') != NULL) {
		lbracket = "[";
		rbracket = "]";
	}
	addargs(args, "%s%s%s%s%s:%s",
	    session->dst.user != NULL ? session->dst.user : "",
	    session->dst.user != NULL ? "@" : "",
	    lbracket, session->dst.host, rbracket,
	    session->dst.path != NULL ? session->dst.path : "");
}

/* Start the source's hpnscp to push directly to the target, and relay its
 * status as events. hpnscp is a bare word that the source's PATH resolves,
 * as stock scp resolves its remote command. hpn_launch_args_run() keeps
 * the arguments off the source's shell and handles a legacy source. Raw
 * bytes from a source that does not send frames are discarded, so they
 * never reach our protocol stdout. Returns 0, HPN_EXIT_STRICT_ARGS for a
 * refused legacy source, HPN_LAUNCH_REFUSED when the copy was refused
 * before it ran, or -1. */
static int
do_launch(struct run_state *session)
{
	struct hpn_launch launch;
	struct hpn_run_hooks hooks;
	arglist args, ssh_stdin, ssh_legacy;
	int r;

	/* the human-mode meter's label, from local arguments only */
	snprintf(meter_label, sizeof(meter_label), "%s => %s",
	    session->src.host, session->dst.host);

	/* the source hpnscp's own arguments, one list for both modes */
	launch_hpnscp_args(session, &args);
	/* Source-key-only default: no agent is forwarded and the source
	 * authenticates to the target with its own key. -A opts into
	 * forwarding the user's ambient agent instead. Stdin mode needs
	 * stdin, so only the legacy prefix has -n. */
	ssh_base_args(session, &ssh_stdin, 0, session->use_ambient);
	ssh_base_args(session, &ssh_legacy, 1, session->use_ambient);

	/* Each decoded frame becomes an event, or feeds the meter in human
	 * mode. */
	memset(&hooks, 0, sizeof(hooks));
	hooks.on_progress = ev_progress;
	hooks.on_end = ev_end;
	hooks.on_file_fail = ev_file_fail;
	hooks.on_filedone = ev_filedone;
	hooks.on_tick = hpn_meter_relay_tick;
	hooks.on_degrade = ev_degrade;
	hooks.on_frame = ev_frame;
	hooks.on_mismatch = ev_mismatch;
	/* discard raw bytes from a source that does not send frames */
	hooks.passthrough_fd = -1;
	hooks.ctx = session;

	/* Describe the launch for the shared policy. */
	memset(&launch, 0, sizeof(launch));
	launch.ssh_stdin = &ssh_stdin;
	launch.ssh_legacy = &ssh_legacy;
	launch.program = "hpnscp";
	/* hpn3scp always relays, so both modes use the same hooks */
	launch.legacy_relay = 1;
	launch.args = &args;
	launch.source_host = session->src.host;
	/* a legacy retry joins the shared login, so it asks for nothing */
	launch.shared_login = mux.ready;
	launch.hooks = &hooks;
	launch.plain_hooks = &hooks;
	launch.pidp = &session->child;
	/* warnings and refusals go out as events, or as text in human mode */
	launch.warn = proto_emit_warning;
	launch.fail = proto_emit_error;

	/* stdin mode first, and the legacy command line only for a source
	 * that cannot read the list */
	r = hpn_launch_args_run(&launch);
	hpn_meter_relay_finish();
	freeargs(&args);
	freeargs(&ssh_stdin);
	freeargs(&ssh_legacy);
	return r;
}

/* Check the ambient agent before -A forwards it. The ambient agent is the
 * ssh-agent already running in the user's login session, found through
 * SSH_AUTH_SOCK. hpn3scp neither starts nor manages it. Only whether it
 * answers and holds keys can be checked here, because a client cannot see
 * per-key constraints such as ssh-add -h destination rules. Returns 0, or
 * -1 with an error emitted. */
static int
check_ambient_agent(void)
{
	struct ssh_identitylist *identities = NULL;
	char *msg;
	int agent_sock, r;

	/* the agent is not present when SSH_AUTH_SOCK is unset or empty */
	r = ssh_get_authentication_socket(&agent_sock);
	if (r == SSH_ERR_AGENT_NOT_PRESENT) {
		proto_emit_error("-A given but no ssh-agent is running "
		    "(SSH_AUTH_SOCK unset); start one (hpnssh-agent) and load "
		    "your key (hpnssh-add)");
		return -1;
	}
	if (r != 0) {
		proto_emit_error("-A given but the agent at SSH_AUTH_SOCK is "
		    "unreachable (stale socket?)");
		return -1;
	}
	r = ssh_fetch_identitylist(agent_sock, &identities);
	ssh_close_authentication_socket(agent_sock);
	ssh_free_identitylist(identities);
	/* the agent reports an empty key list as an error code */
	if (r == SSH_ERR_AGENT_NO_IDENTITIES) {
		proto_emit_error("-A given but your agent holds no keys; "
		    "hpnssh-add the key that opens the target");
		return -1;
	}
	if (r != 0) {
		xasprintf(&msg, "-A given but the agent did not list its keys: "
		    "%s", ssh_err(r));
		proto_emit_error(msg);
		free(msg);
		return -1;
	}
	return 0;
}

/* Make sure the source trusts the target's host key on session->dst.port.
 * Either it already does, or the key is fetched, confirmed by SSHFP or the
 * user, and added to the source's known_hosts. Returns 0, 1 when nothing
 * on the port responded and may_fall_back allows another port, or -1 with
 * an error emitted. */
static int
trust_target_port(struct run_state *session,
    struct target_keyset *keyset, int may_fall_back)
{
	char *msg;
	int r;

	/* the source host already trusts the key, so nothing is needed */
	if (hpn3scp_source_knows_target(session) == 1) {
		debug("source already trusts %s port %d; skipping host-key "
		    "brokering", session->dst.host, session->dst.port);
		return 0;
	}
	/* fetch the target's keys through the source host */
	proto_emit_phase(phase_name(RUN_FETCH_TARGET_KEY));
	r = hpn3scp_fetch_target_keys(session, keyset);
	/* nothing responded, so the caller may try the other port */
	if (r == 1 && may_fall_back)
		return 1;
	if (r != 0) {
		xasprintf(&msg, "could not retrieve %s's host key via %s",
		    session->dst.host, session->src.host);
		proto_emit_error(msg);
		free(msg);
		return -1;
	}
	/* the user or SSHFP accepts the key, or the run stops here */
	proto_emit_phase(phase_name(RUN_CONFIRM_KEY));
	if (hpn3scp_confirm_target(session, keyset) != 0)
		return -1;
	/* write the accepted key into the source's known_hosts */
	proto_emit_phase(phase_name(RUN_PROVISION));
	if (hpn3scp_provision_target(session, keyset) != 0) {
		xasprintf(&msg, "could not add %s's host key to %s's "
		    "known_hosts", session->dst.host, session->src.host);
		proto_emit_error(msg);
		free(msg);
		return -1;
	}
	return 0;
}

/* Run one third-party copy from start to finish and report it as events:
 * resolve the two endpoints, make sure the source trusts the target's host
 * key, check the agent for -A, then launch the source's hpnscp and relay
 * its status. Every path ends with exactly one done event. Returns the
 * exit status for main(). */
static int
run_session(struct run_state *session)
{
	const char *why = NULL;
	char *msg;
	struct target_keyset keyset;
	int r, ret = 1, counts_known;

	memset(&keyset, 0, sizeof(keyset));

	/* parse and check both endpoints before anything connects */
	proto_emit_phase(phase_name(RUN_RESOLVE));
	if (resolve_endpoint(session->src_arg, &session->src, &why) != 0 ||
	    resolve_endpoint(session->dst_arg, &session->dst, &why) != 0) {
		proto_emit_error(why);
		goto fail;
	}
	proto_emit_resolved(&session->src, &session->dst, session->streams);

	/* One login to the source for the whole run, so a password or MFA
	 * user is asked once. Every later ssh to the source joins it. */
	if (mux_open(session) != 0)
		goto fail;

	/* Make sure the source trusts the target's host key on the port the
	 * copy will use. A port the user gave is the only one tried. Without
	 * one, HPN's port 2222 comes first, as hpnssh tries it, and 22 is the
	 * fallback when nothing responds there. The port chosen stays set, so
	 * the launch uses it too and the copy cannot pick another. */
	if (session->dst.port != -1) {
		if (trust_target_port(session, &keyset, 0) != 0)
			goto fail;
	} else {
		session->dst.port = HPNSSH_DEFAULT_PORT;
		r = trust_target_port(session, &keyset, 1);
		if (r == 1) {
			debug("No response on port %d, trying port %d",
			    HPNSSH_DEFAULT_PORT, SSH_DEFAULT_PORT);
			session->dst.port = SSH_DEFAULT_PORT;
			r = trust_target_port(session, &keyset, 0);
		}
		if (r != 0)
			goto fail;
	}

	/* The credential. By default the source authenticates to the target
	 * with its own key, so the user's key never leaves the launcher and
	 * no agent is forwarded. -A forwards the ambient agent instead, for a
	 * source with no key of its own on the target. The user can limit
	 * the forwarded key to that one hop by loading it with ssh-add -h
	 * SOURCE -h "SOURCE>TARGET", which OpenSSH 8.9 and later honour. */
	if (session->use_ambient && check_ambient_agent() != 0)
		goto fail;

	/* Start the copy on the source and relay its frames until it ends.
	 * LAUNCH and MONITOR are emitted together for now. LAUNCH is kept so
	 * a front end can later show the time from starting the source to
	 * its first frame, which covers the source's login to the target. */
	proto_emit_phase(phase_name(RUN_LAUNCH));

	proto_emit_phase(phase_name(RUN_MONITOR));
	r = do_launch(session);
	/* A run that ended without the source's END frame failed before it
	 * reported a result, for example when the source could not log in to
	 * the target. The source's own messages are on stderr, so the event
	 * names only where it failed. A refused launch has reported already. */
	if (r != 0 && !endinfo.got && r != HPN_EXIT_STRICT_ARGS &&
	    r != HPN_LAUNCH_REFUSED) {
		xasprintf(&msg, "the copy on %s failed before it reported a "
		    "result (see its messages on stderr)", session->src.host);
		proto_emit_error(msg);
		free(msg);
	}
	/* A source that reported failure without a FILEFAIL frame, as a
	 * serial transfer error does, leaves the front end no file_fail
	 * event, so the failure gets an error event here. */
	if (endinfo.got && !endinfo.ok &&
	    failtally.verify == 0 && failtally.transfer == 0) {
		xasprintf(&msg, "the copy on %s reported a failure without "
		    "naming a file (see its messages on stderr)",
		    session->src.host);
		proto_emit_error(msg);
		free(msg);
	}
	emit_completion_summary(session);

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
	proto_emit_phase(phase_name(RUN_COMPLETE));
	proto_emit_done(r == 0, ret, counts_known, endinfo.files_done,
	    failtally.verify, failtally.transfer);
	goto out;

 fail:
	/* a failed run still ends with COMPLETE before its done event */
	proto_emit_phase(phase_name(RUN_COMPLETE));
	/* nothing was launched, so the zero counts are known */
	proto_emit_done(0, 1, 1, 0, 0, 0);
	ret = 1;
 out:
	mux_close(session);
	hpn3scp_free_keyset(&keyset);
	return ret;
}

/* Parse the options and the two endpoints, choose the human or protocol
 * rendering, and run the copy. Options the source's hpnscp needs are
 * collected into hpnscp_extra and forwarded unchanged. */
int
main(int argc, char **argv)
{
	struct run_state session;
	arglist hpnscp_extra;
	const char *errstr = NULL;
	char **split_argv;
	int ch, split_argc, i, ret;

	/* logs go to stderr, because stdout carries the control protocol */
	log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);
	/* we write to child stdins, so a child that exits must not kill us */
	signal(SIGPIPE, SIG_IGN);

	memset(&session, 0, sizeof(session));
	session.streams = 1;
	session.child = -1;
	memset(&hpnscp_extra, 0, sizeof(hpnscp_extra));
	session.hpnscp_extra = &hpnscp_extra;

	/* Most options are forwarded to the source's hpnscp. -o, -X, -r, -V,
	 * -Z, and -z become the same hpnscp options. -Y is the escape hatch
	 * for any other hpnscp switch: one quoted string, split with quote
	 * and escape handling so the dashes travel intact. */
	while ((ch = getopt(argc, argv, "j:Arvo:X:Y:46VZz:")) != -1) {
		switch (ch) {
		case 'j':
			/* the same limit the source's hpnscp enforces */
			session.streams = (int)strtonum(optarg, 1,
			    SFTP_PARALLEL_MAX_WORKERS, &errstr);
			if (errstr != NULL)
				fatal("Number of parallel streams %s: %s",
				    optarg, errstr);
			break;
		case '4':
			session.addr_family = 4;
			break;
		case '6':
			session.addr_family = 6;
			break;
		case 'A':
			session.use_ambient = 1;
			break;
		case 'v':
			/* each -v raises our own log level, up to DEBUG3 */
			session.verbosity++;
			if (session.verbosity == 1)
				log_change_level(SYSLOG_LEVEL_DEBUG1);
			else if (session.verbosity == 2)
				log_change_level(SYSLOG_LEVEL_DEBUG2);
			else
				log_change_level(SYSLOG_LEVEL_DEBUG3);
			break;
		case 'r':
			addargs(&hpnscp_extra, "-r");
			break;
		case 'V':
			addargs(&hpnscp_extra, "-V");
			session.verify_requested = 1;
			session.verify_full = 1;
			break;
		case 'Z':
			addargs(&hpnscp_extra, "-Z");
			/* resume implies verification */
			session.verify_requested = 1;
			break;
		case 'z':
			/* zstd on the source to target transfer. The level is
			 * checked here, so a bad one fails before connecting,
			 * and forwarded to the source's hpnscp. */
			(void)strtonum(optarg, HPN_ZSTD_LEVEL_MIN,
			    HPN_ZSTD_LEVEL_MAX, &errstr);
			if (errstr != NULL)
				fatal("Invalid -z zstd level \"%s\": %s "
				    "(range %d-%d)", optarg, errstr,
				    HPN_ZSTD_LEVEL_MIN, HPN_ZSTD_LEVEL_MAX);
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
			if (argv_split(optarg, &split_argc, &split_argv,
			    0) != 0) {
				fprintf(stderr, "hpn3scp: bad -Y value: %s\n",
				    optarg);
				exit(1);
			}
			for (i = 0; i < split_argc; i++)
				addargs(&hpnscp_extra, "%s", split_argv[i]);
			argv_free(split_argv, split_argc);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();

	session.src_arg = argv[0];
	session.dst_arg = argv[1];

	proto_init(stdout);
	/* A terminal gets the human rendering, and a pipe gets the EVENT
	 * protocol. */
	if (isatty(STDOUT_FILENO))
		proto_set_human(1);
	/* -X TransferLog: open the log before any connection. The open is
	 * the writability check. */
	transferlog_begin();
	ret = run_session(&session);
	transferlog_close();
	return ret;
}
