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

/* hpn-launch-args.c - running hpnscp on a third-party source without its
 * shell parsing the arguments.
 *
 * The file has three parts. First, the source side: hpnscp reads its
 * argument list from stdin and expands its local operands itself, standing
 * in for the shell. Second, the launcher side that hpn3scp and hpnscp -R
 * share: it packs the list, tries stdin mode, and falls back to the legacy
 * command line, loudly and narrowed, for a source that cannot read it.
 * Third, the scp -R glue that builds that launch from scp's options and
 * draws its relayed meter. hpn-launch-args.h describes the stdin format. */

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "log.h"
#include "misc.h"
#include "progressmeter.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "xmalloc.h"
#include "hpn-meter.h"
#include "hpn-progressmeter.h"
#include "hpn3scp-run.h"
#include "sftp-hpn-transferlog.h"
#include "hpn-launch-args.h"

/* ENV-VAR HPN_ARGS_STDIN: a third-party launcher (hpn3scp, hpnscp -R) puts
 * HPN_ARGS_STDIN=1 in the env prefix of the source's command. hpnscp then
 * reads its arguments from stdin instead of its command line. */
#define HPN_ARGS_STDIN_ENV	"HPN_ARGS_STDIN"

/* the characters a shell acts on as commands, refused on a legacy
 * source's command line */
#define LAUNCH_ARGS_SHELL_UNSAFE	";&|`$()<>'\"\\\n\r"

/* How a source host took a launch's argument list. */
enum launch_args_mode {
	LAUNCH_ARGS_UNKNOWN,	/* not tried yet */
	LAUNCH_ARGS_STDIN,	/* it read the list and sent HELLO */
	LAUNCH_ARGS_LEGACY	/* it exited 1 without HELLO */
};

/* The relayed meter of one scp -R launch. */
struct scp_remote_meter {
	/* built from local argv only, never remote bytes */
	const char	*label;
	int		 show;		/* scp would show a meter */
};

/* set once the argument list came from stdin, so the operands are
 * expanded here because no shell expanded them */
static int launch_args_from_stdin;

/* set by -X StrictArgs: refuse a source that cannot read the list */
static int launch_args_strict;

/* What the last launch learned about a source host, so the operands after
 * the first one to the same host skip the probe and the warning. */
static char *launch_args_known_host;
static enum launch_args_mode launch_args_known_mode;

/* Read stdin to EOF into buf, the way upstream's sshbuf_load_fd() reads a
 * file, but held to HPN_LAUNCH_ARGS_MAX by the buffer's own size limit.
 * Returns 0, or -1 with the cause logged. */
static int
launch_args_slurp(struct sshbuf *buf)
{
	u_char chunk[4096];
	size_t len;
	int r;

	if ((r = sshbuf_set_max_size(buf, HPN_LAUNCH_ARGS_MAX)) != 0) {
		error_fr(r, "set argument list limit");
		return -1;
	}
	for (;;) {
		/* atomicio() returns 0 with errno EPIPE at EOF */
		if ((len = atomicio(read, STDIN_FILENO, chunk,
		    sizeof(chunk))) == 0) {
			if (errno == EPIPE)
				return 0;
			error_f("read argument list: %s", strerror(errno));
			return -1;
		}
		/* the size limit turns an oversized list into a put error */
		if ((r = sshbuf_put(buf, chunk, len)) != 0) {
			if (r == SSH_ERR_NO_BUFFER_SPACE)
				error_f("argument list exceeds %d bytes",
				    HPN_LAUNCH_ARGS_MAX);
			else
				error_fr(r, "store argument list");
			return -1;
		}
	}
}

/* Replace argc and argv with the list on stdin when the launcher armed
 * stdin mode, keeping argv[0]. A bad or oversized list is fatal, because
 * hpnscp must never run a partial or guessed command. It also unsets
 * HPN_ARGS_STDIN, and arms the relay, so HELLO goes out on stdout. The
 * list only fills an empty command line. An hpnscp started with arguments
 * ignores the variable and keeps them. */
void
hpn_launch_args_stdin(int *argcp, char ***argvp)
{
	struct sshbuf *buf;
	const char *armed;
	char **argv;
	uint32_t count;
	u_int i;
	int r;

	armed = getenv(HPN_ARGS_STDIN_ENV);
	if (armed == NULL || strcmp(armed, "1") != 0)
		return;
	/* consumed here, so nothing this process starts inherits it */
	unsetenv(HPN_ARGS_STDIN_ENV);
	/* Our launchers start a bare hpnscp. Arguments mean a wrapper, a
	 * forced command, or a user who exported the variable, and those
	 * arguments stand, so the variable can never override a command an
	 * administrator fixed or break an ordinary run. */
	if (*argcp != 1) {
		debug_f("%s ignored: hpnscp was given arguments",
		    HPN_ARGS_STDIN_ENV);
		return;
	}
	/* Only a launcher sets this, and it pipes both ends. A terminal on
	 * either means a user set it by hand, and reading the list would
	 * wait on the keyboard and write a binary frame to the screen. */
	if (isatty(STDIN_FILENO) || isatty(STDOUT_FILENO))
		fatal_f("%s is set but stdin or stdout is a terminal",
		    HPN_ARGS_STDIN_ENV);

	if ((buf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (launch_args_slurp(buf) != 0)
		fatal_f("cannot read the argument list from stdin");
	if ((r = sshbuf_get_u32(buf, &count)) != 0)
		fatal_fr(r, "argument count");
	/* every argument takes at least its 4-byte length, so a count larger
	 * than that is a corrupt list, caught before the allocation */
	if (count > sshbuf_len(buf) / 4)
		fatal_f("argument count %u exceeds the list", count);

	/* argv[0] stays, the list follows, and a NULL ends it */
	argv = xcalloc((size_t)count + 2, sizeof(*argv));
	argv[0] = (*argvp)[0];
	for (i = 0; i < count; i++) {
		/* sshbuf_get_cstring() rejects an embedded NUL */
		if ((r = sshbuf_get_cstring(buf, &argv[i + 1], NULL)) != 0)
			fatal_fr(r, "argument %u", i);
	}
	if (sshbuf_len(buf) != 0)
		fatal_f("%zu bytes of trailing data after the argument list",
		    sshbuf_len(buf));
	sshbuf_free(buf);

	*argcp = (int)count + 1;
	*argvp = argv;
	launch_args_from_stdin = 1;

	/* Arm the relay and send HELLO now, before option parsing can fail,
	 * so the launcher can tell this hpnscp read the list. The number of
	 * streams is not known yet. */
	hpn_pm_frame_mode(0);
}

/* Expand the local source operands with glob(3) when the arguments came
 * from stdin, standing in for the shell that never saw them. Tildes and
 * braces expand as they would in a shell, and a pattern that matches
 * nothing is kept as typed, as sftp does. The last operand, the target,
 * and any remote operand stay as they are. argc and argv here are the
 * operands left after option parsing. */
void
hpn_launch_args_glob(int *argcp, char ***argvp)
{
	glob_t matches;
	char **argv, **expanded = NULL;
	size_t nexpanded = 0, k;
	int i, r;

	if (!launch_args_from_stdin || *argcp < 2)
		return;
	argv = *argvp;
	for (i = 0; i < *argcp - 1; i++) {
		/* a remote operand is globbed by its own side, over SFTP */
		if (colon(argv[i]) != NULL) {
			expanded = xrecallocarray(expanded, nexpanded,
			    nexpanded + 1, sizeof(*expanded));
			expanded[nexpanded++] = argv[i];
			continue;
		}
		memset(&matches, 0, sizeof(matches));
		r = glob(argv[i], GLOB_NOCHECK | GLOB_TILDE | GLOB_BRACE,
		    NULL, &matches);
		if (r != 0)
			fatal_f("cannot expand \"%s\": glob error %d",
			    argv[i], r);
		expanded = xrecallocarray(expanded, nexpanded,
		    nexpanded + matches.gl_pathc, sizeof(*expanded));
		for (k = 0; k < matches.gl_pathc; k++)
			expanded[nexpanded++] = xstrdup(matches.gl_pathv[k]);
		globfree(&matches);
	}
	/* the target goes last, and a NULL ends the list */
	expanded = xrecallocarray(expanded, nexpanded, nexpanded + 2,
	    sizeof(*expanded));
	expanded[nexpanded++] = argv[*argcp - 1];
	expanded[nexpanded] = NULL;

	*argcp = (int)nexpanded;
	*argvp = expanded;
}

/* Pack args in the stdin format: a u32 count, then one sshbuf string per
 * argument, held to HPN_LAUNCH_ARGS_MAX. Returns 0, or an ssherr code,
 * SSH_ERR_NO_BUFFER_SPACE for a list over the cap. */
static int
launch_args_pack(const struct arglist *args, struct sshbuf *buf)
{
	u_int i;
	int r;

	/* the reader's cap, enforced as the list is built */
	if ((r = sshbuf_set_max_size(buf, HPN_LAUNCH_ARGS_MAX)) != 0)
		return r;
	/* the count first, so the reader can check it against the list */
	if ((r = sshbuf_put_u32(buf, args->num)) != 0)
		return r;
	/* then each argument as a length and its bytes, never a NUL */
	for (i = 0; i < args->num; i++) {
		if ((r = sshbuf_put_cstring(buf, args->list[i])) != 0)
			return r;
	}
	return 0;
}

/* Report whether arg is safe on a legacy source's command line: it holds
 * no character the shell would act on as a command. Glob characters pass,
 * because a glob cannot run a command. */
static int
launch_args_shell_safe(const char *arg)
{
	return strpbrk(arg, LAUNCH_ARGS_SHELL_UNSAFE) == NULL;
}

/* Consume -X StrictArgs. Returns 1 when opt was StrictArgs and 0
 * otherwise, so the caller goes on to its other -X options. */
int
hpn_launch_args_option(const char *opt)
{
	if (strcasecmp(opt, "StrictArgs") != 0)
		return 0;
	launch_args_strict = 1;
	return 1;
}

/* The mode last learned for host, or LAUNCH_ARGS_UNKNOWN. */
static enum launch_args_mode
launch_args_mode_of(const char *host)
{
	if (launch_args_known_host == NULL ||
	    strcmp(launch_args_known_host, host) != 0)
		return LAUNCH_ARGS_UNKNOWN;
	return launch_args_known_mode;
}

/* Remember what a launch learned about host. */
static void
launch_args_learn(const char *host, enum launch_args_mode mode)
{
	free(launch_args_known_host);
	launch_args_known_host = xstrdup(host);
	launch_args_known_mode = mode;
}

/* Copy every argument of from onto the end of to. */
static void
launch_args_append(arglist *to, const struct arglist *from)
{
	u_int i;

	for (i = 0; i < from->num; i++)
		addargs(to, "%s", from->list[i]);
}

/* Log the command a launch runs, visible under -v. */
static void
launch_args_debug(const char *label, arglist *cmd)
{
	char *cmdline;

	cmdline = argv_assemble(cmd->num, cmd->list);
	debug("launch (%s): %s", label, cmdline);
	free(cmdline);
}

/* The variable that arms the source's status frames. The "log" value also
 * asks the source for per-file FILEDONE frames, for the launcher's transfer
 * log. An old source treats any value as plain arming and sends frames
 * without the per-file stream, so the log degrades to header, failures,
 * and footer. */
static const char *
launch_args_relay(void)
{
	if (transferlog_active())
		return "HPN_ENABLE_REMOTE_PROGRESS=log";
	return "HPN_ENABLE_REMOTE_PROGRESS=1";
}

/* Try stdin mode: only fixed text on the source's command line, and the
 * packed list on the session's stdin. Returns the run's status and fills
 * res, or returns HPN_LAUNCH_REFUSED when the list cannot be packed, in
 * which case nothing connects. */
static int
launch_args_try_stdin(const struct hpn_launch *launch,
    struct hpn_run_result *res)
{
	struct hpn_run_hooks hooks;
	struct sshbuf *list;
	arglist cmd;
	int r;

	/* A refusal returns before any run, and res must then say that
	 * nothing was seen, so the caller does not mistake it for a
	 * legacy source. */
	memset(res, 0, sizeof(*res));
	if ((list = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = launch_args_pack(launch->args, list)) != 0) {
		error_fr(r, "pack the argument list");
		if (r == SSH_ERR_NO_BUFFER_SPACE)
			launch->fail("the argument list is too long");
		else
			launch->fail("cannot pack the argument list");
		sshbuf_free(list);
		return HPN_LAUNCH_REFUSED;
	}

	/* The command line is fixed text: env arms the relay and stdin mode,
	 * and the program word follows with no arguments, because the source
	 * reads the list only into an empty command line. */
	memset(&cmd, 0, sizeof(cmd));
	launch_args_append(&cmd, launch->ssh_stdin);
	addargs(&cmd, "env");
	addargs(&cmd, "%s", launch_args_relay());
	addargs(&cmd, "%s=1", HPN_ARGS_STDIN_ENV);
	addargs(&cmd, "%s", launch->program);
	launch_args_debug("stdin", &cmd);

	/* The caller's hooks stay as given. This run adds the list as the
	 * session's stdin. */
	hooks = *launch->hooks;
	hooks.stdin_data = sshbuf_ptr(list);
	hooks.stdin_len = sshbuf_len(list);
	r = hpn_run_status(&cmd, launch->pidp, &hooks, res);
	freeargs(&cmd);
	sshbuf_free(list);
	return r;
}

/* Run the legacy command line, after refusing it under -X StrictArgs or
 * for an argument the shell would act on, and after the warning. warn is
 * set only the first time a host turns out to be legacy. Returns the run's
 * status, HPN_EXIT_STRICT_ARGS under -X StrictArgs, or HPN_LAUNCH_REFUSED
 * for an unsafe argument. Neither refusal connects to the source. */
static int
launch_args_legacy(const struct hpn_launch *launch, int warn)
{
	const struct hpn_run_hooks *hooks;
	arglist cmd;
	char *msg;
	u_int i;
	int r;

	/* both refusals come before the source is contacted again */
	if (launch_args_strict) {
		xasprintf(&msg, "%s cannot read the argument list safely and "
		    "-X StrictArgs refuses the unsafe mode",
		    launch->source_host);
		launch->fail(msg);
		free(msg);
		return HPN_EXIT_STRICT_ARGS;
	}
	/* The source's shell will parse every argument, so refuse any that
	 * could make it run a command. */
	for (i = 0; i < launch->args->num; i++) {
		if (!launch_args_shell_safe(launch->args->list[i])) {
			xasprintf(&msg, "%s needs the unsafe mode, which "
			    "refuses the argument \"%s\"",
			    launch->source_host, launch->args->list[i]);
			launch->fail(msg);
			free(msg);
			return HPN_LAUNCH_REFUSED;
		}
	}
	if (warn) {
		/* The retry is a second connection, so a password or MFA
		 * user is prompted again. Say so before they are. */
		xasprintf(&msg, "%s does not support safe argument passing. "
		    "This is a potential security hazard. Upgrade it to "
		    "HPN-SSH 19 or later to resolve. Continuing in unsafe "
		    "mode. You may be asked to log in to %s again.",
		    launch->source_host, launch->source_host);
		launch->warn(msg);
		free(msg);
	}

	/* The arguments ride the command line, where the source's shell
	 * parses them. */
	memset(&cmd, 0, sizeof(cmd));
	launch_args_append(&cmd, launch->ssh_legacy);
	if (launch->legacy_relay) {
		addargs(&cmd, "env");
		addargs(&cmd, "%s", launch_args_relay());
	}
	addargs(&cmd, "%s", launch->program);
	launch_args_append(&cmd, launch->args);
	launch_args_debug("legacy", &cmd);
	/* without the relay the source sends no frames, so its output just
	 * passes through */
	hooks = launch->plain_hooks;
	if (launch->legacy_relay)
		hooks = launch->hooks;
	r = hpn_run_status(&cmd, launch->pidp, hooks, NULL);
	freeargs(&cmd);
	return r;
}

/* Launch the program on the source. A host already known to be legacy
 * goes straight to the legacy command line. Otherwise stdin mode is tried,
 * and only an exit of 1 without a HELLO, an older hpnscp printing its
 * usage, falls back. */
int
hpn_launch_args_run(const struct hpn_launch *launch)
{
	struct hpn_run_result res;
	enum launch_args_mode mode;
	int r;

	mode = launch_args_mode_of(launch->source_host);
	/* A host already found legacy skips the probe. Its warning was
	 * given the first time. */
	if (mode == LAUNCH_ARGS_LEGACY)
		return launch_args_legacy(launch, 0);

	r = launch_args_try_stdin(launch, &res);
	if (res.got_hello)
		launch_args_learn(launch->source_host, LAUNCH_ARGS_STDIN);
	/* A HELLO, a signal, or any status but 1 is this run's answer. Only
	 * exit 1 without a HELLO is an older hpnscp that printed its usage. */
	if (res.got_hello || !res.exited || res.exit_status != 1)
		return r;
	launch_args_learn(launch->source_host, LAUNCH_ARGS_LEGACY);
	return launch_args_legacy(launch, 1);
}

/* The scp -R side of the HPN status relay. scp draws a local progress
 * meter rendered entirely from the frames the runner decodes: every value
 * shown comes from the source's own measurements, never re-derived from
 * frame arrival times. The meter starts on the first PROGRESS, and only
 * when scp would show one. */

/* Feed every PROGRESS frame to the meter when scp would show one. The
 * first frame starts it. */
static void
scp_remote_progress(const struct hpns_progress *progress, void *ctx)
{
	struct scp_remote_meter *meter = ctx;

	if (meter->show)
		hpn_meter_relay_sample(meter->label, progress);
}

/* Close the meter on the source's final byte count. */
static void
scp_remote_end(const struct hpns_end *end, void *ctx)
{
	(void)ctx;
	hpn_meter_relay_end(end->bytes_done);
}

/* Drop the meter when the frame stream is abandoned. */
static void
scp_remote_degrade(void *ctx)
{
	(void)ctx;
	hpn_meter_relay_stop();
	error("source is not sending status; the transfer continues without "
	    "progress");
}

/* -R with -X TransferLog: the source mirrors each file's final status as a
 * FILEDONE frame, and this writes it to the launcher-side log. The path
 * is opaque remote bytes, which the log module percent-encodes before they
 * reach the log. */
static void
scp_remote_filedone(const struct hpns_filedone *filedone, void *ctx)
{
	transferlog_file_bytes(transferlog_status_from_wire(filedone->status),
	    (off_t)filedone->size, filedone->path, filedone->path_len);
}

/* Report a launch warning on stderr. */
static void
scp_remote_warn(const char *msg)
{
	error("warning: %s", msg);
}

/* Report a launch failure on stderr. */
static void
scp_remote_fail(const char *msg)
{
	error("%s", msg);
}

/* Build the ssh prefix that reaches the source host. with_n adds -n,
 * which stdin mode leaves out because the argument list rides stdin. */
static void
scp_remote_ssh(const struct hpn_scp_remote *remote, arglist *prefix,
    int with_n)
{
	memset(prefix, 0, sizeof(*prefix));
	addargs(prefix, "%s", remote->ssh_program);
	/* as upstream scp -R: the hop only launches a copy, so no X11 and no
	 * forwarding */
	addargs(prefix, "-x");
	addargs(prefix, "-oClearAllForwardings=yes");
	if (with_n)
		addargs(prefix, "-n");
	launch_args_append(prefix, remote->ssh_args);
	if (remote->port != -1) {
		addargs(prefix, "-p");
		addargs(prefix, "%d", remote->port);
	}
	if (remote->user != NULL) {
		addargs(prefix, "-l");
		addargs(prefix, "%s", remote->user);
	}
	addargs(prefix, "--");
	addargs(prefix, "%s", remote->host);
}

/* Build the source scp's own arguments, ending in -- and the two
 * operands. */
static void
scp_remote_args(const struct hpn_scp_remote *remote, arglist *args)
{
	memset(args, 0, sizeof(*args));
	if (remote->verbose)
		addargs(args, "-v");
	if (remote->recursive)
		addargs(args, "-r");
	if (remote->preserve)
		addargs(args, "-p");
	if (remote->target_is_dir)
		addargs(args, "-d");
	/* A parallel, direct source->target transfer: -j and a non-default
	 * target port go to the source's scp. The source connects to the
	 * target, so its -P is the target port. */
	if (remote->streams > 1) {
		addargs(args, "-j");
		addargs(args, "%d", remote->streams);
	}
	if (remote->target_port != -1) {
		addargs(args, "-P");
		addargs(args, "%d", remote->target_port);
	}
	/* The source runs the source->target transfer, so its address family,
	 * compression, and verify and resume requests travel with it.
	 * ssh_args only decorates the hop to the source. */
	if (remote->family != 0)
		addargs(args, "-%d", remote->family);
	if (remote->compress)
		addargs(args, "-C");
	if (remote->zstd_level > 0)
		addargs(args, "-z%d", remote->zstd_level);
	if (remote->verify)
		addargs(args, "-V");
	if (remote->resume)
		addargs(args, "-Z");
	/* -- so a source path starting with '-' is never read as an option */
	addargs(args, "--");
	addargs(args, "%s", remote->src);
	if (remote->target_user != NULL)
		addargs(args, "%s@%s:%s", remote->target_user,
		    remote->target_host, remote->target_path);
	else
		addargs(args, "%s:%s", remote->target_host,
		    remote->target_path);
}

/* Run one scp -R source operand: build the hop to the source and the
 * source scp's arguments, wire the relayed meter and the transfer log to
 * the runner, and hand the launch to hpn_launch_args_run(). */
int
hpn_launch_args_scp_remote(const struct hpn_scp_remote *remote)
{
	struct scp_remote_meter meter;
	struct hpn_run_hooks hooks, plain_hooks;
	struct hpn_launch launch;
	arglist ssh_stdin, ssh_legacy, args;
	char *label;
	int r;

	/* Two prefixes for the same hop. Stdin mode needs the session's
	 * stdin open, and the legacy run closes it with -n. */
	scp_remote_ssh(remote, &ssh_stdin, 0);
	scp_remote_ssh(remote, &ssh_legacy, 1);
	/* the source scp's options and operands, one list for both modes */
	scp_remote_args(remote, &args);

	/* label is local argv data only, never remote-supplied strings */
	xasprintf(&label, "%s => %s", remote->host, remote->target_host);
	/* the meter starts unseen and shows only when scp would show one */
	memset(&meter, 0, sizeof(meter));
	meter.label = label;
	meter.show = remote->show_meter;
	/* A relayed run drives the meter and the transfer log from the
	 * source's frames. Anything else it prints goes to our stdout. */
	/* no HELLO hook: the totals arrive in PROGRESS frames */
	memset(&hooks, 0, sizeof(hooks));
	hooks.on_progress = scp_remote_progress;
	hooks.on_end = scp_remote_end;
	hooks.on_filedone = scp_remote_filedone;
	hooks.on_tick = hpn_meter_relay_tick;
	hooks.on_degrade = scp_remote_degrade;
	hooks.passthrough_fd = STDOUT_FILENO;
	hooks.ctx = &meter;
	/* a legacy run without the relay just passes its output through */
	memset(&plain_hooks, 0, sizeof(plain_hooks));
	plain_hooks.passthrough_fd = STDOUT_FILENO;

	/* Describe the launch for the shared policy. */
	memset(&launch, 0, sizeof(launch));
	launch.ssh_stdin = &ssh_stdin;
	launch.ssh_legacy = &ssh_legacy;
	/* Our own hpnssh rewrites the scp word behind the env prefix to
	 * hpnscp (clientloop.c). */
	launch.program = "scp";
	/* A legacy source keeps the relay only when this side wants a meter
	 * or a log. Stdin mode always arms it, because its HELLO tells a new
	 * source from a legacy one. env(1), not a VAR=val prefix, so
	 * csh-family login shells work. */
	launch.legacy_relay = remote->show_meter || transferlog_active();
	launch.args = &args;
	launch.source_host = remote->host;
	launch.hooks = &hooks;
	launch.plain_hooks = &plain_hooks;
	launch.pidp = remote->pidp;
	/* problems go to stderr, like scp's own errors */
	launch.warn = scp_remote_warn;
	launch.fail = scp_remote_fail;

	/* stdin mode first, and the legacy line only for a source that
	 * cannot read the list */
	r = hpn_launch_args_run(&launch);
	/* close the meter so the next operand's meter starts clean */
	hpn_meter_relay_finish();
	free(label);
	freeargs(&ssh_stdin);
	freeargs(&ssh_legacy);
	freeargs(&args);
	return r;
}
