/* $OpenBSD: scp.c,v 1.275 2026/06/28 23:47:16 djm Exp $ */
/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
 * Copyright (c) 2021 Chris Rapier. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Parts from:
 *
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <glob.h>
#include <libgen.h>
#include <locale.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <util.h>
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "hpn-status-frame.h"
#include "hpn3scp-run.h"
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"
#include "sftp.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_set_verify_transfer */
#include "sftp-hpn-verify.h"		/* sftp_hpn_verify_repair_resolve */
#include "sftp-hpn-transferlog.h"
#include "hpn-compress.h"		/* HPN: -z zstd level bounds */
#include "sftp-parallel.h"
#include "hpn-exit-codes.h"

extern char *__progname;

#define COPY_BUFLEN	16384

int do_cmd(char *, char *, char *, int, int, char *, int *, int *, pid_t *);
int do_cmd2(char *, char *, int, char *, int, int);

/* Struct for addargs */
arglist args;
arglist remote_remote_args;

/* Bandwidth limit */
long long limit_kbps = 0;
struct bwlimit bwlimit;

/* Name of current file being transferred. */
char *curfile;

/* This is set to non-zero to enable verbose mode. */
int verbose_mode = 0;
LogLevel log_level = SYSLOG_LEVEL_INFO;

/* This is set to zero if the progressmeter is not desired. */
int showprogress = 1;

/*
 * This is set to non-zero if remote-remote copy should be piped
 * through this process.
 */
int throughlocal = 1;

/* Non-standard port to use for the ssh connection or -1. */
int sshport = -1;

/* This is the program to execute for the secure connection. ("ssh" or -S) */
char *ssh_program = _PATH_SSH_PROGRAM;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;
pid_t do_cmd_pid2 = -1;

/* SFTP copy parameters */
size_t sftp_copy_buflen;
size_t sftp_nrequests;
int sftp_no_verify_repair;	/* -X VerifyRepair=no -> 1 (auto-repair off) */

/* Needed for sftp */
volatile sig_atomic_t interrupted = 0;

int sftp_glob(struct sftp_conn *, const char *, int,
    int (*)(const char *, int), glob_t *); /* proto for sftp-glob.c */

/* Flag to indicate that this is a file resume */
int resume_flag = 0; /* 0 is off, 1 is on */

/* we want the host name for debugging purposes */
char hostname[HOST_NAME_MAX + 1];

/*
 * HPN parallel-streams (-j): orchestrator handle plus the worker-spawn
 * parameters captured from the command line.  parallel_num_streams defaults to
 * 1 (single-stream, identical to traditional scp); -j N opts into the parallel
 * orchestrator and the post-transfer verify phase, mirroring hpnsftp.  The
 * orchestrator spawns its own worker SSH connections, so it needs the same
 * identity (-i), config file (-F) and -o options scp passes to its control
 * connection; host/user/port are captured at connect time.
 */
static int parallel_num_streams = 1;
static struct sftp_parallel *parallel_orch = NULL;
static const char *parallel_identity = NULL;	/* -i */
static const char *parallel_config_file = NULL;	/* -F */
static char **parallel_extra_o = NULL;		/* -o KEY=VALUE list, NULL-term */
static size_t parallel_extra_o_count = 0;
static size_t parallel_extra_o_cap = 0;
static int hpn_verify_transfer = 0;		/* HPNVerifyTransfer resolved */
static int verify_flag = 0;			/* -V: force HPNVerifyTransfer on */
static int family_flag = 0;			/* -4/-6: forward to -R source scp */
static int compress_flag = 0;			/* -C: forward to -R source scp */
static int zstd_level = 0;			/* -z: zstd@hpnssh.org level */
static int hpn_verify_failed = 0;		/* a transfer failed verify -> exit 57 */
static int range_split_min_mb_user = 0;		/* -M: range-split min file size, MiB */
static int writers_cap_user = 0;		/* -w: max range-writers per inode */
/*
 * showprogress as it stood before sftp_parallel_start() zeroed the global (it
 * suppresses each worker's own per-file meter so only the aggregate meter
 * draws).  The aggregate-meter gates use THIS, not the now-zero global - the
 * same reason sftp.c gates its progress_start on !quiet rather than showprogress.
 */
static int parallel_want_progress = 0;

/*
 * Append one -o KEY=VALUE option to the parallel worker-spawn list, kept
 * NULL-terminated so the orchestrator config (cfg->extra_argv) can consume it
 * directly.  optarg points into argv (stable for the process), but xstrdup
 * keeps ownership simple and matches sftp.c.
 */
static void
parallel_extra_o_add(const char *opt)
{
	if (parallel_extra_o_count + 2 > parallel_extra_o_cap) {
		parallel_extra_o_cap = parallel_extra_o_cap ?
		    parallel_extra_o_cap * 2 : 8;
		parallel_extra_o = xreallocarray(parallel_extra_o,
		    parallel_extra_o_cap, sizeof(*parallel_extra_o));
	}
	parallel_extra_o[parallel_extra_o_count++] = xstrdup(opt);
	parallel_extra_o[parallel_extra_o_count] = NULL;
}

static void
killchild(int signo)
{
	if (do_cmd_pid > 1) {
		kill(do_cmd_pid, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid, NULL, 0);
	}
	if (do_cmd_pid2 > 1) {
		kill(do_cmd_pid2, signo ? signo : SIGTERM);
		(void)waitpid(do_cmd_pid2, NULL, 0);
	}

	if (signo)
		_exit(1);
	exit(1);
}

static void
suspone(int pid, int signo)
{
	int status;

	if (pid > 1) {
		kill(pid, signo);
		while (waitpid(pid, &status, WUNTRACED) == -1 &&
		    errno == EINTR)
			;
	}
}

static void
suspchild(int signo)
{
	int save_errno = errno;
	suspone(do_cmd_pid, signo);
	suspone(do_cmd_pid2, signo);
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static int
do_local_cmd(arglist *a)
{
	char *cp;
	int status;
	pid_t pid;

#ifdef DEBUG
	fprintf(stderr, "In do_local_cmd\n");
#endif
	if (a->num == 0)
		fatal("do_local_cmd: no arguments");

	if (verbose_mode) {
		cp = argv_assemble(a->num, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		free(cp);
	}
	if ((pid = fork()) == -1)
		fatal("do_local_cmd: fork: %s", strerror(errno));

	if (pid == 0) {
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}

	do_cmd_pid = pid;
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_local_cmd: waitpid: %s", strerror(errno));

	do_cmd_pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);

	return (0);
}

/*
 * HPN status relay, consumer side (hpn-status-relay-design.md).  scp drives
 * a local ANSI progress meter rendered entirely from the frames the shared
 * runner decodes (pm_relay_*): every displayed value comes from
 * the source's own measurements, never re-derived from frame arrival times.
 * The meter starts on the first PROGRESS (only if showprogress).
 */
struct scp_meter {
	const char *label;	/* built from local argv only, never remote bytes */
	int meter_on;
};

static void
scp_meter_hello(const struct hpns_hello *h, void *ctx)
{
	/* totals arrive in PROGRESS frames; nothing to seed yet */
}

static void
scp_meter_progress(const struct hpns_progress *p, void *ctx)
{
	struct scp_meter *m = ctx;

	if (!m->meter_on && showprogress) {
		pm_relay_start(m->label);
		m->meter_on = 1;
	}
	if (m->meter_on)
		pm_relay_sample(p);
}

static void
scp_meter_end(const struct hpns_end *e, void *ctx)
{
	struct scp_meter *m = ctx;

	if (m->meter_on)
		pm_relay_end(e->bytes_done);
}

static void
scp_meter_tick(void *ctx)
{
	struct scp_meter *m = ctx;

	if (m->meter_on)
		refresh_progress_meter(0);
}

static void
scp_meter_degrade(void *ctx)
{
	struct scp_meter *m = ctx;

	if (m->meter_on) {
		stop_progress_meter();
		m->meter_on = 0;
	}
	error("remote status stream garbled; continuing without progress "
	    "display");
}

/* -R + -oTransferLog: the source mirrors each file's final status as a
 * FILEDONE frame; write it to the launcher-side log.  The path is opaque
 * remote bytes - the module percent-encodes before it hits the log. */
static void
scp_meter_filedone(const struct hpns_filedone *fd, void *ctx)
{
	transferlog_file_bytes(transferlog_status_from_wire(fd->status),
	    (long long)fd->size, fd->path, fd->path_len);
}

/*
 * Variant of do_local_cmd() for -R transfers with the status relay armed:
 * launch the ssh with a piped stdout via the shared runner, which parses
 * HPNS frames and drives the meter through the hooks above; raw output from
 * a source that does not speak frames passes through to our stdout.  Return
 * value is the child exit status, exactly as do_local_cmd().
 */
static int
do_local_cmd_status(arglist *a, const char *label)
{
	struct scp_meter m;
	struct hpn_run_hooks h;
	char *cp;
	int r;

	if (a->num == 0)
		fatal("do_local_cmd_status: no arguments");

	if (verbose_mode) {
		cp = argv_assemble(a->num, a->list);
		fmprintf(stderr, "Executing: %s\n", cp);
		free(cp);
	}

	/* the runner sets/clears do_cmd_pid; our killchild handler reads it */
	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);

	memset(&m, 0, sizeof(m));
	m.label = label;
	memset(&h, 0, sizeof(h));
	h.on_hello = scp_meter_hello;
	h.on_progress = scp_meter_progress;
	h.on_end = scp_meter_end;
	h.on_filedone = scp_meter_filedone;
	h.on_tick = scp_meter_tick;
	h.on_degrade = scp_meter_degrade;
	h.passthrough_fd = STDOUT_FILENO;
	h.ctx = &m;

	r = hpn_run_status(a, &do_cmd_pid, &h);

	if (m.meter_on) {
		refresh_progress_meter(1);
		stop_progress_meter();
	}
	return (r);
}

/*
 * This function executes the given command as the specified user on the
 * given host.  This returns < 0 if execution fails, and >= 0 otherwise. This
 * assigns the input and output file descriptors on success.
 */

int
do_cmd(char *program, char *host, char *remuser, int port, int subsystem,
    char *cmd, int *fdin, int *fdout, pid_t *pid)
{
#ifdef USE_PIPES
	int pin[2], pout[2];
#else
	int sv[2];
#endif

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: program %s host %s, user %s, command %s\n",
		    program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	if (port == -1)
		port = sshport;

#ifdef USE_PIPES
	if (pipe(pin) == -1 || pipe(pout) == -1)
		fatal("pipe: %s", strerror(errno));
#else
	/* Create a socket pair for communicating with ssh. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		fatal("socketpair: %s", strerror(errno));
#endif

	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);

	/* Fork a child to execute the command on the remote host using ssh. */
	*pid = fork();
	switch (*pid) {
	case -1:
		fatal("fork: %s", strerror(errno));
	case 0:
		/* Child. */
#ifdef USE_PIPES
		if (dup2(pin[0], STDIN_FILENO) == -1 ||
		    dup2(pout[1], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(pin[0]);
		close(pin[1]);
		close(pout[0]);
		close(pout[1]);
#else
		if (dup2(sv[0], STDIN_FILENO) == -1 ||
		    dup2(sv[0], STDOUT_FILENO) == -1) {
			error("dup2: %s", strerror(errno));
			_exit(1);
		}
		close(sv[0]);
		close(sv[1]);
#endif
		replacearg(&args, 0, "%s", program);
		if (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		if (subsystem)
			addargs(&args, "-s");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(program, args.list);
		perror(program);
		_exit(1);
	default:
		/* Parent.  Close the other side, and return the local side. */
#ifdef USE_PIPES
		close(pin[0]);
		close(pout[1]);
		*fdout = pin[1];
		*fdin = pout[0];
#else
		close(sv[0]);
		*fdin = sv[1];
		*fdout = sv[1];
#endif
		ssh_signal(SIGTERM, killchild);
		ssh_signal(SIGINT, killchild);
		ssh_signal(SIGHUP, killchild);
		return 0;
	}
}

/*
 * This function executes a command similar to do_cmd(), but expects the
 * input and output descriptors to be setup by a previous call to do_cmd().
 * This way the input and output of two commands can be connected.
 */
int
do_cmd2(char *host, char *remuser, int port, char *cmd,
    int fdin, int fdout)
{
	int status;
	pid_t pid;

	if (verbose_mode)
		fmprintf(stderr,
		    "Executing: 2nd program %s host %s, user %s, command %s\n",
		    ssh_program, host,
		    remuser ? remuser : "(unspecified)", cmd);

	if (port == -1)
		port = sshport;

	/* Fork a child to execute the command on the remote host using ssh. */
	pid = fork();
	if (pid == 0) {
		if (dup2(fdin, 0) == -1)
			perror("dup2");
		if (dup2(fdout, 1) == -1)
			perror("dup2");

		replacearg(&args, 0, "%s", ssh_program);
		if (port != -1) {
			addargs(&args, "-p");
			addargs(&args, "%d", port);
		}
		if (remuser != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", remuser);
		}
		addargs(&args, "-oBatchMode=yes");
		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", cmd);

		execvp(ssh_program, args.list);
		perror(ssh_program);
		exit(1);
	} else if (pid == -1) {
		fatal("fork: %s", strerror(errno));
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("do_cmd2: waitpid: %s", strerror(errno));
	return 0;
}

typedef struct {
	size_t cnt;
	char *buf;
} BUF;

BUF *allocbuf(BUF *, int, int);
void lostconn(int);
int okname(char *);
void run_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int note_err(const char *,...)
    __attribute__((__format__ (printf, 1, 2)));
void verifydir(char *);

struct passwd *pwd;
uid_t userid;
int errs, remin, remout, remin2, remout2;
int Tflag, pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

enum scp_mode_e {
	MODE_SCP,
	MODE_SFTP
};

int response(void);
void rsource(char *, struct stat *);
void sink(int, char *[], const char *);
void source(int, char *[]);
void tolocal(int, char *[], enum scp_mode_e, char *sftp_direct);
void toremote(int, char *[], enum scp_mode_e, char *sftp_direct);
void usage(void);

void source_sftp(int, char *, char *, struct sftp_conn *);
void sink_sftp(int, char *, const char *, struct sftp_conn *);
void throughlocal_sftp(struct sftp_conn *, struct sftp_conn *,
    char *, char *);

int
main(int argc, char **argv)
{
	int ch, fflag, tflag, status, r, n;
	char **newargv, *argv0;
	const char *errstr;
	extern char *optarg;
	extern int optind;
	enum scp_mode_e mode = MODE_SFTP;
	char *sftp_direct = NULL;
	long long llv;

	/* we use this to prepend the debugging statements
	 * so we know which side is saying what */
	gethostname(hostname, HOST_NAME_MAX + 1);

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	msetlocale();

	/* Copy argv, because we modify it */
	argv0 = argv[0];
	newargv = xcalloc(MAXIMUM(argc + 1, 1), sizeof(*newargv));
	for (n = 0; n < argc; n++)
		newargv[n] = xstrdup(argv[n]);
	argv = newargv;

	__progname = ssh_get_progname(argv[0]);

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	memset(&args, '\0', sizeof(args));
	memset(&remote_remote_args, '\0', sizeof(remote_remote_args));
	args.list = remote_remote_args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-x");
	addargs(&args, "-oPermitLocalCommand=no");
	addargs(&args, "-oClearAllForwardings=yes");
	addargs(&args, "-oRemoteCommand=none");
	addargs(&args, "-oRequestTTY=no");
	addargs(&args, "-oControlMaster=no");

	fflag = Tflag = tflag = 0;
	while ((ch = getopt(argc, argv,
	    "12346ABCTVdfOpqRrstvZz:D:F:J:M:P:S:c:i:j:l:o:w:X:")) != -1) {
		switch (ch) {
		/* User-visible flags. */
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* Ignored */
			break;
		/*
		 * Connection-shaping flags.  Also propagate to parallel-streams
		 * (-j) workers via their -o equivalents (the worker SSH argv is
		 * rebuilt from pcfg, not from these arglists).  -A (agent
		 * forwarding) is deliberately not forwarded to data workers.
		 */
		case 'A':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			break;
		case '4':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			parallel_extra_o_add("AddressFamily=inet");
			family_flag = 4;
			break;
		case '6':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			parallel_extra_o_add("AddressFamily=inet6");
			family_flag = 6;
			break;
		case 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			parallel_extra_o_add("Compression=yes");
			compress_flag = 1;
			break;
		case 'z': {
			/* HPN: zstd@hpnssh.org at this level.  Set it on the
			 * control/serial ssh AND forward ZstdLevel to the
			 * workers (which are their own hpnssh sessions). */
			const char *zerr = NULL;

			zstd_level = (int)strtonum(optarg, HPN_ZSTD_LEVEL_MIN,
			    HPN_ZSTD_LEVEL_MAX, &zerr);
			if (zerr != NULL)
				fatal("Invalid -z zstd level \"%s\": %s "
				    "(range %d-%d)", optarg, zerr,
				    HPN_ZSTD_LEVEL_MIN, HPN_ZSTD_LEVEL_MAX);
			addargs(&args, "-oZstdLevel=%d", zstd_level);
			{
				char zo[32];
				snprintf(zo, sizeof(zo), "ZstdLevel=%d",
				    zstd_level);
				parallel_extra_o_add(zo);
			}
			break;
		}
		case 'D':
			sftp_direct = optarg;
			break;
		case '3':
			throughlocal = 1;
			break;
		case 'R':
			throughlocal = 0;
			break;
		case 'o':
			if (transferlog_option(optarg))
				break;
			/* FALLTHROUGH */
		case 'c':
		case 'i':
		case 'F':
		case 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			/*
			 * Capture the worker-spawn-relevant options so the
			 * parallel orchestrator (-j) builds matching worker SSH
			 * connections.  -c (cipher) and -J (ProxyJump) have no
			 * structured pcfg field, so forward them as their -o
			 * equivalents (Ciphers= / ProxyJump=).
			 */
			if (ch == 'i')
				parallel_identity = optarg;
			else if (ch == 'F')
				parallel_config_file = optarg;
			else if (ch == 'o')
				parallel_extra_o_add(optarg);
			else if (ch == 'c') {
				char *o;
				xasprintf(&o, "Ciphers=%s", optarg);
				parallel_extra_o_add(o);
				free(o);
			} else if (ch == 'J') {
				char *o;
				xasprintf(&o, "ProxyJump=%s", optarg);
				parallel_extra_o_add(o);
				free(o);
			}
			break;
		case 'O':
			mode = MODE_SCP;
			break;
		case 's':
			mode = MODE_SFTP;
			break;
		case 'P':
			sshport = a2port(optarg);
			if (sshport <= 0)
				fatal("bad port \"%s\"\n", optarg);
			break;
		case 'B':
			addargs(&remote_remote_args, "-oBatchmode=yes");
			addargs(&args, "-oBatchmode=yes");
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			if (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			bandwidth_limit_init(&bwlimit, limit_kbps, COPY_BUFLEN);
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			iamrecursive = 1;
			break;
		case 'S':
			ssh_program = xstrdup(optarg);
			break;
		case 'v':
			addargs(&args, "-v");
			addargs(&remote_remote_args, "-v");
			if (verbose_mode == 0)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			verbose_mode = 1;
			break;
		case 'q':
			addargs(&args, "-q");
			addargs(&remote_remote_args, "-q");
			showprogress = 0;
			break;
		case 'Z':
			resume_flag = 1;
			break;
		case 'V':
			/*
			 * Force HPNVerifyTransfer on for this transfer - the
			 * dedicated switch for what -o HPNVerifyTransfer=yes
			 * does via ssh_config.  Transfer-layer verify deserves a
			 * first-class flag rather than only an ssh-wide -o option
			 * (which plain hpnssh also parses but ignores).
			 */
			verify_flag = 1;
			break;
		case 'j':
			parallel_num_streams = (int)strtonum(optarg, 1,
			    SFTP_PARALLEL_MAX_WORKERS, &errstr);
			if (errstr != NULL)
				fatal("Number of parallel streams %s: %s",
				    optarg, errstr);
			break;
		case 'M':
			/*
			 * Minimum file size (MiB) at which a single file is
			 * split across parallel workers by byte range.  Bounded
			 * [64, 10240] like sftp.c -M so neither degenerate value
			 * (over-chunking / no parallelism for huge files) can
			 * occur.  Only meaningful with -j > 1.
			 */
			range_split_min_mb_user = (int)strtonum(optarg, 64,
			    10240, &errstr);
			if (errstr != NULL)
				fatal("Range-split minimum (-M) must be between "
				    "64 and 10240 MiB: \"%s\": %s",
				    optarg, errstr);
			break;
		case 'w':
			/* Max concurrent range-writers per inode (mirror
			 * sftp.c -w).  Caps how many range-split workers write
			 * one file at once; buffered multi-writer into a single
			 * inode serialises on the per-inode lock (4 is the
			 * measured throughput knee).  Effective cap is
			 * min(this, -j); only meaningful with -j > 1. */
			writers_cap_user = (int)strtonum(optarg,
			    HPN_RANGE_WRITERS_CAP_FLOOR,
			    HPN_RANGE_WRITERS_CAP_MAX, &errstr);
			if (errstr != NULL)
				fatal("Concurrent range-writers per inode (-w) "
				    "must be between %d and %d: \"%s\": %s",
				    HPN_RANGE_WRITERS_CAP_FLOOR,
				    HPN_RANGE_WRITERS_CAP_MAX, optarg, errstr);
			break;
		case 'X':
			/* Please keep in sync with sftp.c -X */
			if (strncasecmp(optarg, "buffer=", 7) == 0) {
                                r = scan_scaled(optarg + 7, &llv);
                                /* don't ask for a buffer larger than the maximum
                                 * size that SFTP can handle */
                                if (r == 0 && (llv <= 0 || llv > (SFTP_MAX_MSG_LENGTH - 1024))) {
                                        r = -1;
                                        errno = EINVAL;
                                }
                                if (r == -1) {
                                        fatal("Invalid buffer size. Must be between 1B and 255KB."
                                              "\"%s\": %s", optarg + 7, strerror(errno));
                                }
                                sftp_copy_buflen = (size_t)llv;
                        } else if (strncasecmp(optarg, "nrequests=", 10) == 0) {
                                /* more than 10k to 15k requests starts stalling the connection
                                 * 8192 * default buffer size is 256MB of outstanding data.
                                 * if users need more then they need to up the buffer size */
                                llv = strtonum(optarg + 10, 1, 8 * 1024,
                                               &errstr);
                                if (errstr != NULL) {
                                        fatal("Invalid number of requests. Must be between 1 and 8192. "
                                              "\"%s\": %s", optarg + 10, errstr);
                                }
                                sftp_nrequests = (size_t)llv;
                        } else if (strncasecmp(optarg, "VerifyRepair=", 13) == 0) {
                                /* Auto-repair toggle (default yes); no value */
                                const char *v = optarg + 13;
                                if (strcasecmp(v, "no") == 0)
                                        sftp_no_verify_repair = 1;
                                else if (strcasecmp(v, "yes") == 0)
                                        sftp_no_verify_repair = 0;
                                else
                                        fatal("Invalid VerifyRepair value "
                                              "\"%s\": use yes or no", v);
                        } else if (strncasecmp(optarg, "Pacing=", 7) == 0) {
                                /* Adaptive upload pacing toggle (default
                                 * yes); see sftp_hpn_pace_ack. */
                                const char *v = optarg + 7;
                                if (strcasecmp(v, "no") == 0)
                                        sftp_hpn_pace_set_enabled(0);
                                else if (strcasecmp(v, "yes") == 0)
                                        sftp_hpn_pace_set_enabled(1);
                                else
                                        fatal("Invalid Pacing value "
                                              "\"%s\": use yes or no", v);
                        } else {
                                fatal("Invalid -X option");
                        }
                        break;

			/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			break;
		case 'T':
			Tflag = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2);

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent=no");

	if (iamremote)
		mode = MODE_SCP;

	/*
	 * Verified resume (-Z) needs the SFTP protocol's random-access range
	 * hashing, which the legacy scp protocol (-O) cannot provide.  Refuse
	 * the combination loudly rather than silently degrade to an unverified
	 * transfer.  (-Z is SFTP-only; the old MODE_SCP rcp-protocol resume is
	 * removed.)
	 */
	if (resume_flag && mode == MODE_SCP)
		fatal("-Z (verified resume) requires SFTP mode and cannot be "
		    "used with -O");

	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	if (!isatty(STDOUT_FILENO)) {
		/*
		 * ENV-VAR HPN_ENABLE_REMOTE_PROGRESS: status-relay arming
		 * (hpn-status-relay-design.md).  A launching hpnscp (-R third
		 * party transfers) - or any frame consumer - sets this in our
		 * environment to subscribe to binary progress frames on
		 * stdout.  When armed, the meter machinery keeps running but
		 * emits frames instead of ANSI text; unset gives the historic
		 * behavior (no meter on pipes).  An env var, not a flag, so
		 * old/stock binaries ignore the request instead of failing.
		 */
		const char *rprog = getenv("HPN_ENABLE_REMOTE_PROGRESS");

		if (rprog != NULL) {
			hpn_pm_frame_mode((u_int)parallel_num_streams);
			/* "log" value: the consumer also wants per-file
			 * FILEDONE frames for its transfer log / GUI. */
			if (strcmp(rprog, "log") == 0)
				transferlog_frames(1);
		} else if (getenv("HPN_PM_DEBUG") == NULL)
			showprogress = 0;
	}

	/* -oTransferLog: open (and thereby writability-check) the log NOW,
	 * before any connection is established - a bad path must fail the
	 * run before work starts. */
	transferlog_begin();

	if (pflag) {
		/* Cannot pledge: -p allows setuid/setgid files... */
	} else {
		if (pledge("stdio rpath wpath cpath fattr tty proc exec",
		    NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	remin = STDIN_FILENO;
	remout = STDOUT_FILENO;

	if (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	if (tflag) {
		/* Receive data. */
		sink(argc, argv, NULL);
		exit(errs != 0);
	}
	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	/* In the event of an hpn to hpn connection the scp
	 * command is rewritten to hpnscp. This happens in
	 * clientloop.c -cjr 12/12/2022 */

	(void) snprintf(cmd, sizeof cmd, "%s%s%s%s%s",
			"scp",
			verbose_mode ? " -v" : "",
			iamrecursive ? " -r" : "",
			pflag ? " -p" : "",
			targetshouldbedirectory ? " -d" : "");
#ifdef DEBUG
		fprintf(stderr, "%s: Sending cmd %s\n", hostname, cmd);
#endif
	(void) ssh_signal(SIGPIPE, lostconn);

	if (colon(argv[argc - 1]))	/* Dest is remote host. */
		toremote(argc, argv, mode, sftp_direct);
	else {
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
		tolocal(argc, argv, mode, sftp_direct);	/* Dest is local host. */
	}

	/*
	 * Finally check the exit status of the ssh process, if one was forked
	 * and no error has occurred yet
	 */
	if (do_cmd_pid != -1 && (mode == MODE_SFTP || errs == 0)) {
		if (remin != -1)
		    (void) close(remin);
		if (remout != -1)
		    (void) close(remout);
		if (waitpid(do_cmd_pid, &status, 0) == -1)
			errs = 1;
		else {
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				errs = 1;
		}
	}
	/* HPN status relay: final END frame (advisory; no-op unless armed).
	 * The consumer takes the authoritative result from our exit status. */
	hpn_pm_end(errs == 0 && !hpn_verify_failed,
	    (u_int)(errs > 0 ? errs : 0));
	transferlog_close();

	if (hpn_verify_failed)
		exit(SFTP_EX_VERIFY_FAILED);
	exit(errs != 0);
}

/* Callback from atomicio6 to update progress meter and limit bandwidth */
static int
scpio(void *_cnt, size_t s)
{
	off_t *cnt = (off_t *)_cnt;

	*cnt += s;
	refresh_progress_meter(0);
	if (limit_kbps > 0)
		bandwidth_limit(&bwlimit, s);
	return 0;
}

static int
do_times(int fd, int verb, const struct stat *sb)
{
	/* strlen(2^64) == 20; strlen(10^6) == 7 */
	char buf[(20 + 7 + 2) * 2 + 2];

	(void)snprintf(buf, sizeof(buf), "T%llu 0 %llu 0\n",
	    (unsigned long long) (sb->st_mtime < 0 ? 0 : sb->st_mtime),
	    (unsigned long long) (sb->st_atime < 0 ? 0 : sb->st_atime));
	if (verb) {
		fprintf(stderr, "File mtime %lld atime %lld\n",
		    (long long)sb->st_mtime, (long long)sb->st_atime);
		fprintf(stderr, "Sending file timestamps: %s", buf);
	}
	(void) atomicio(vwrite, fd, buf, strlen(buf));
	return (response());
}

static int
parse_scp_uri(const char *uri, char **userp, char **hostp, int *portp,
    char **pathp)
{
	int r;

	r = parse_uri("scp", uri, userp, hostp, portp, pathp);
	if (r == 0 && *pathp == NULL)
		*pathp = xstrdup(".");
	return r;
}

/* Appends a string to an array; returns 0 on success, -1 on alloc failure */
static int
append(char *cp, char ***ap, size_t *np)
{
	char **tmp;

	if ((tmp = reallocarray(*ap, *np + 1, sizeof(*tmp))) == NULL)
		return -1;
	tmp[(*np)] = cp;
	(*np)++;
	*ap = tmp;
	return 0;
}

/*
 * Finds the start and end of the first brace pair in the pattern.
 * returns 0 on success or -1 for invalid patterns.
 */
static int
find_brace(const char *pattern, int *startp, int *endp)
{
	int i;
	int in_bracket, brace_level;

	*startp = *endp = -1;
	in_bracket = brace_level = 0;
	for (i = 0; i < INT_MAX && *endp < 0 && pattern[i] != '\0'; i++) {
		switch (pattern[i]) {
		case '\\':
			/* skip next character */
			if (pattern[i + 1] != '\0')
				i++;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '{':
			if (in_bracket)
				break;
			if (pattern[i + 1] == '}') {
				/* Protect a single {}, for find(1), like csh */
				i++; /* skip */
				break;
			}
			if (*startp == -1)
				*startp = i;
			brace_level++;
			break;
		case '}':
			if (in_bracket)
				break;
			if (*startp < 0) {
				/* Unbalanced brace */
				return -1;
			}
			if (--brace_level <= 0)
				*endp = i;
			break;
		}
	}
	/* unbalanced brackets/braces */
	if (*endp < 0 && (*startp >= 0 || in_bracket))
		return -1;
	return 0;
}

/*
 * Assembles and records a successfully-expanded pattern, returns -1 on
 * alloc failure.
 */
static int
emit_expansion(const char *pattern, int brace_start, int brace_end,
    int sel_start, int sel_end, char ***patternsp, size_t *npatternsp)
{
	char *cp;
	size_t pattern_len;
	int o = 0, tail_len;

	if ((pattern_len = strlen(pattern)) == 0 || pattern_len >= INT_MAX)
		return -1;

	tail_len = strlen(pattern + brace_end + 1);
	if ((cp = malloc(brace_start + (sel_end - sel_start) +
	    tail_len + 1)) == NULL)
		return -1;

	/* Pattern before initial brace */
	if (brace_start > 0) {
		memcpy(cp, pattern, brace_start);
		o = brace_start;
	}
	/* Current braced selection */
	if (sel_end - sel_start > 0) {
		memcpy(cp + o, pattern + sel_start,
		    sel_end - sel_start);
		o += sel_end - sel_start;
	}
	/* Remainder of pattern after closing brace */
	if (tail_len > 0) {
		memcpy(cp + o, pattern + brace_end + 1, tail_len);
		o += tail_len;
	}
	cp[o] = '\0';
	if (append(cp, patternsp, npatternsp) != 0) {
		free(cp);
		return -1;
	}
	return 0;
}

/*
 * Expand the first encountered brace in pattern, appending the expanded
 * patterns it yielded to the *patternsp array.
 *
 * Returns 0 on success or -1 on allocation failure.
 *
 * Signals whether expansion was performed via *expanded and whether
 * pattern was invalid via *invalid.
 */
static int
brace_expand_one(const char *pattern, char ***patternsp, size_t *npatternsp,
    int *expanded, int *invalid)
{
	int i;
	int in_bracket, brace_start, brace_end, brace_level;
	int sel_start, sel_end;

	*invalid = *expanded = 0;

	if (find_brace(pattern, &brace_start, &brace_end) != 0) {
		*invalid = 1;
		return 0;
	} else if (brace_start == -1)
		return 0;

	in_bracket = brace_level = 0;
	for (i = sel_start = brace_start + 1; i < brace_end; i++) {
		switch (pattern[i]) {
		case '{':
			if (in_bracket)
				break;
			brace_level++;
			break;
		case '}':
			if (in_bracket)
				break;
			brace_level--;
			break;
		case '[':
			in_bracket = 1;
			break;
		case ']':
			in_bracket = 0;
			break;
		case '\\':
			if (i < brace_end - 1)
				i++; /* skip */
			break;
		}
		if (pattern[i] == ',' || i == brace_end - 1) {
			if (in_bracket || brace_level > 0)
				continue;
			/* End of a selection, emit an expanded pattern */

			/* Adjust end index for last selection */
			sel_end = (i == brace_end - 1) ? brace_end : i;
			if (emit_expansion(pattern, brace_start, brace_end,
			    sel_start, sel_end, patternsp, npatternsp) != 0)
				return -1;
			/* move on to the next selection */
			sel_start = i + 1;
			continue;
		}
	}
	if (in_bracket || brace_level > 0) {
		*invalid = 1;
		return 0;
	}
	/* success */
	*expanded = 1;
	return 0;
}

/* Expand braces from pattern. Returns 0 on success, -1 on failure */
static int
brace_expand(const char *pattern, char ***patternsp, size_t *npatternsp)
{
	char *cp, *cp2, **active = NULL, **done = NULL;
	size_t i, nactive = 0, ndone = 0;
	int ret = -1, invalid = 0, expanded = 0;

	*patternsp = NULL;
	*npatternsp = 0;

	/* Start the worklist with the original pattern */
	if ((cp = strdup(pattern)) == NULL)
		return -1;
	if (append(cp, &active, &nactive) != 0) {
		free(cp);
		return -1;
	}
	while (nactive > 0) {
		cp = active[nactive - 1];
		nactive--;
		if (brace_expand_one(cp, &active, &nactive,
		    &expanded, &invalid) == -1) {
			free(cp);
			goto fail;
		}
		if (invalid)
			fatal_f("invalid brace pattern \"%s\"", cp);
		if (expanded) {
			/*
			 * Current entry expanded to new entries on the
			 * active list; discard the progenitor pattern.
			 */
			free(cp);
			continue;
		}
		/*
		 * Pattern did not expand; append the filename component to
		 * the completed list
		 */
		if ((cp2 = strrchr(cp, '/')) != NULL)
			*cp2++ = '\0';
		else
			cp2 = cp;
		if (append(xstrdup(cp2), &done, &ndone) != 0) {
			free(cp);
			goto fail;
		}
		free(cp);
	}
	/* success */
	*patternsp = done;
	*npatternsp = ndone;
	done = NULL;
	ndone = 0;
	ret = 0;
 fail:
	for (i = 0; i < nactive; i++)
		free(active[i]);
	free(active);
	for (i = 0; i < ndone; i++)
		free(done[i]);
	free(done);
	return ret;
}

static struct sftp_conn *
do_sftp_connect(char *host, char *user, int port, char *sftp_direct,
   int *reminp, int *remoutp, int *pidp)
{
	if (sftp_direct == NULL) {
		if (do_cmd(ssh_program, host, user, port, 1, "sftp",
		    reminp, remoutp, pidp) < 0)
			return NULL;

	} else {
		freeargs(&args);
		addargs(&args, "sftp-server");
		if (do_cmd(sftp_direct, host, NULL, -1, 0, "sftp",
		    reminp, remoutp, pidp) < 0)
			return NULL;
	}
	return sftp_init(*reminp, *remoutp,
	    sftp_copy_buflen, sftp_nrequests, limit_kbps);
}

/*
 * Launch the parallel-streams orchestrator for a transfer involving `host`.
 * Always resolves HPNVerifyTransfer and latches it on the control connection
 * (so the single-stream path verifies through that conn); only spins up worker
 * connections when -j N (N > 1) was requested.  On orchestrator start failure
 * it leaves parallel_orch NULL and reverts to single-stream.
 */
static void
scp_parallel_launch(struct sftp_conn *conn, const char *host,
    const char *user, int port)
{
	struct sftp_parallel_config pcfg;
	char portbuf[16] = "";
	int eff_streams = 0;	/* per-call effective stream count after the cap */

	/*
	 * Capture whether progress is wanted BEFORE sftp_parallel_start() zeroes
	 * the global showprogress; the aggregate-meter start gates read this.
	 */
	parallel_want_progress = showprogress;

	/*
	 * Integrity verify is requested by -V only (not ssh_config); latch it on
	 * the control conn so single-stream scp parks verify items inside
	 * sftp_upload/sftp_download, and force it into the orchestrator config
	 * below so parallel workers verify too.
	 */
	hpn_verify_transfer = verify_flag;
	sftp_conn_set_verify_transfer(conn, hpn_verify_transfer);

	/*
	 * Resolve and latch the verify auto-repair settings on the control
	 * conn so single-stream scp's classic verify phase repairs too - the
	 * parallel path gets them via pcfg.no_verify_repair below.  Mirrors the
	 * sftp.c wiring: -X VerifyRepair=no (sftp_no_verify_repair) or
	 * HPN_NO_VERIFY_REPAIR disables; attempts from HPN_VERIFY_REPAIR_ATTEMPTS.
	 * Contained in { } to narrow the scope for the temprary vars. 
	 */
	{
		int rep_enabled, rep_attempts;
		sftp_hpn_verify_repair_resolve(sftp_no_verify_repair,
		    &rep_enabled, &rep_attempts);
		sftp_conn_set_verify_repair(conn, rep_enabled, rep_attempts);
	}

	if (parallel_num_streams <= 1)
		return;			/* single-stream: no orchestrator */

	/*
	 * HPN: clamp the requested worker count to THIS connection's advertised
	 * per-user cap (hpn-max-workers@hpnssh.org, read at sftp_init).  Computed
	 * per call into a local; parallel_num_streams stays the immutable -j
	 * request so each source connection caps against the original request.
	 * Downloads relaunch this per source argument (each may be a different
	 * host), and 3rd-party/crossload transfers will too, so the cap must be
	 * per-connection rather than a sticky once-only global.
	 *   cap < 0  -> not advertised (stock / non-HPN server): apply the
	 *               conservative no-policy default.
	 *   cap == 0 -> HPN server with no admin cap: honour the request.
	 *   cap > 0  -> HPN server policy: clamp to it.
	 * (The hard SFTP_PARALLEL_MAX_WORKERS ceiling is enforced at parse.)
	 */
	{
		int cap = sftp_hpn_max_workers_cap(conn);
		int requested = parallel_num_streams;

		eff_streams = requested;
		if (cap < 0)
			eff_streams = MINIMUM(requested,
			    HPN_NO_POLICY_WORKER_DEFAULT);
		else if (cap > 0)
			eff_streams = MINIMUM(requested, cap);
		if (eff_streams < requested) {
			if (cap < 0)
				logit("Parallel streams limited to %d "
				    "(server advertises no policy; "
				    "requested %d)", eff_streams, requested);
			else
				logit("Parallel streams limited to %d "
				    "by server policy (requested %d)",
				    eff_streams, requested);
		}
	}
	if (eff_streams <= 1)
		return;			/* clamped down to single-stream */

	memset(&pcfg, 0, sizeof(pcfg));
	pcfg.num_streams   = eff_streams;
	pcfg.host          = host;
	pcfg.user          = user;
	if (port > 0) {
		snprintf(portbuf, sizeof(portbuf), "%d", port);
		pcfg.port = portbuf;
	}
	pcfg.ssh_binary    = ssh_program;
	pcfg.identity      = parallel_identity;
	pcfg.config_file   = parallel_config_file;
	pcfg.extra_argv    = parallel_extra_o;
	pcfg.transfer_buflen = (u_int)sftp_copy_buflen;
	pcfg.num_requests  = (u_int)sftp_nrequests;
	pcfg.no_verify_repair = sftp_no_verify_repair;
	pcfg.limit_kbps    = (uint64_t)limit_kbps;
	pcfg.writers_per_inode_cap = writers_cap_user ?
	    writers_cap_user : HPN_RANGE_WRITERS_CAP_DEFAULT;
	pcfg.range_split_min_mb = range_split_min_mb_user;
	pcfg.verbose_level = verbose_mode;
	pcfg.preserve_flag = pflag;
	pcfg.print_flag    = showprogress ? SFTP_PROGRESS_ONLY : SFTP_QUIET;
	/*
	 * Resolves HPNUseBundle, HPNMaxRetries, HPNBundleSize,
	 * HPNMaxAuthConcurrent and HPNVerifyTransfer into pcfg from
	 * ssh_config + the -o overrides; must run before sftp_parallel_start.
	 * (The per-user worker cap, HPNMaxConcurrentWorkers, is a server-side
	 * option delivered over the wire via hpn-max-workers@hpnssh.org and
	 * applied above, not resolved from client ssh_config.)
	 */
	(void)sftp_parallel_apply_ssh_config(&pcfg, host,
	    parallel_config_file, parallel_extra_o);
	if (verify_flag)		/* -V forces verify on regardless of config */
		pcfg.verify_transfer = 1;
	/* HPN: latch the resolved bundling knobs on the control connection
	 * for the serial recursive walks (no -j runs use only this conn). */
	sftp_conn_set_bundle_config(conn, pcfg.use_bundle,
	    pcfg.bundle_size, pcfg.writer_pool);
	/* Adaptive throughput-outlier stall detection: shared defaults +
	 * SFTP_TPUT_* overrides (was a copy-paste of sftp.c's values that
	 * silently dropped the env overrides). */
	sftp_parallel_set_stall_defaults(&pcfg);

	if (showprogress)
		logit("Parallel streams: -j %d", eff_streams);
	parallel_orch = sftp_parallel_start(&pcfg);
	if (parallel_orch == NULL) {
		logit("Parallel-streams setup failed; falling back to "
		    "single-stream mode.");
		return;
	}
	/*
	 * Ignore SIGPIPE once the orchestrator is live (mirrors sftp.c).
	 * scp's default handler, lostconn, exits the whole process - so a
	 * write to one dead worker's pipe killed the entire transfer before
	 * the requeue/respawn machinery could react.  Ignored, the write
	 * fails with EPIPE, the conn is marked dead, and the unit requeues
	 * onto a respawned worker as designed.
	 */
	(void)ssh_signal(SIGPIPE, SIG_IGN);
	/*
	 * No interrupt flag is registered with the orchestrator: scp tears down
	 * bluntly on SIGINT - killchild SIGTERMs the control connection and
	 * _exit()s, and the worker connections die as their pipes close.  That
	 * is the desired behaviour for a one-shot command, so the orchestrator's
	 * graceful-abort path is intentionally left unused.
	 */
}

/*
 * Finish a transfer: drain the orchestrator (which runs the post-transfer
 * verify phase) or, in single-stream mode, run the control conn's verify phase.
 * Failed deliveries bump errs; a verify mismatch latches hpn_verify_failed so
 * main exits SFTP_EX_VERIFY_FAILED.  No-op when neither parallel mode nor
 * verify is active.
 */
static void
scp_parallel_finish(struct sftp_conn *conn)
{
	char **paths = NULL;
	size_t i, used = 0;

	if (parallel_orch != NULL) {
		struct sftp_parallel_stats pstats;

		sftp_parallel_wait(parallel_orch);
		/* A canceled run (interrupt / control-session loss) must not
		 * exit 0: the destination is incomplete by design. */
		if (sftp_parallel_was_aborted(parallel_orch)) {
			fmprintf(stderr, "scp: transfer aborted\n");
			++errs;
		}
		/* Authoritative final file count for the END frame: the async
		 * reporter's last tick can lag a fast transfer, so publish the
		 * walker's tally directly before the meter (and END) are read. */
		hpn_pm_set_files(
		    sftp_parallel_files_submitted(parallel_orch),
		    sftp_parallel_files_total(parallel_orch));
		sftp_parallel_progress_stop(parallel_orch);
		sftp_parallel_get_stats(parallel_orch, &pstats);
		if (showprogress && pstats.bytes_wired_aggregate > 0) {
			logit("Parallel streams: %.2f MiB transferred in %.1fs",
			    (double)pstats.bytes_wired_aggregate /
			    (1024.0 * 1024.0), pstats.elapsed_ms / 1000.0);
		}
		if (sftp_parallel_drain_failed_paths(parallel_orch,
		    &paths, &used) > 0) {
			for (i = 0; i < used; i++) {
				fmprintf(stderr,
				    "scp: transfer incomplete: %s\n", paths[i]);
				hpn_pm_filefail(HPNS_FF_TRANSFER,
				    paths[i], strlen(paths[i]));
				free(paths[i]);
			}
			free(paths);
			++errs;
		}
		paths = NULL;
		used = 0;
		if (sftp_parallel_drain_verify_failures(parallel_orch,
		    &paths, &used) > 0) {
			for (i = 0; i < used; i++) {
				fmprintf(stderr,
				    "HPNVerifyTransfer: FAILED: %s\n", paths[i]);
				hpn_pm_filefail(HPNS_FF_VERIFY,
				    paths[i], strlen(paths[i]));
				free(paths[i]);
			}
			free(paths);
			hpn_verify_failed = 1;
		}
		sftp_parallel_stop(parallel_orch);
		parallel_orch = NULL;
	} else if (hpn_verify_transfer) {
		sftp_conn_verify_run_phase(conn);
		if (sftp_conn_drain_verify_failures(conn, &paths, &used) > 0) {
			for (i = 0; i < used; i++) {
				fmprintf(stderr,
				    "HPNVerifyTransfer: FAILED: %s\n", paths[i]);
				hpn_pm_filefail(HPNS_FF_VERIFY,
				    paths[i], strlen(paths[i]));
				free(paths[i]);
			}
			free(paths);
			hpn_verify_failed = 1;
		}
	}
}

void
toremote(int argc, char **argv, enum scp_mode_e mode, char *sftp_direct)
{
	char *suser = NULL, *host = NULL, *src = NULL;
	char *bp, *tuser, *thost, *targ, *mlabel;
	int sport = -1, tport = -1, relay;
	struct sftp_conn *conn = NULL, *conn2 = NULL;
	arglist alist;
	int i, r, status;
	struct stat sb;
	u_int j;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	/* Parse target */
	r = parse_scp_uri(argv[argc - 1], &tuser, &thost, &tport, &targ);
	if (r == -1) {
		fmprintf(stderr, "%s: invalid uri\n", argv[argc - 1]);
		++errs;
		goto out;
	}
	if (r != 0) {
		if (parse_user_host_path(argv[argc - 1], &tuser, &thost,
		    &targ) == -1) {
			fmprintf(stderr, "%s: invalid target\n", argv[argc - 1]);
			++errs;
			goto out;
		}
	}

	/* Parse source files */
	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		if (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		if (r != 0) {
			parse_user_host_path(argv[i], &suser, &host, &src);
		}
		if (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		if (host && throughlocal) {	/* extended remote to remote */
			if (mode == MODE_SFTP) {
				/*
				 * HPN options that do not apply to the
				 * through-local (crossload) data path.
				 * Refuse loudly rather than silently
				 * degrade: a user who asked for parallel
				 * streams, verification, or verified resume
				 * must not believe they got them.  The -R
				 * direct source-to-destination path
				 * supports all three.
				 */
				if (parallel_num_streams > 1)
					fatal("-j does not apply to a "
					    "through-local (crossload) "
					    "transfer; use -R for a direct "
					    "source-to-destination transfer");
				if (verify_flag)
					fatal("-V does not apply to a "
					    "through-local (crossload) "
					    "transfer; use -R for a direct "
					    "source-to-destination transfer");
				if (resume_flag)
					fatal("-Z does not apply to a "
					    "through-local (crossload) "
					    "transfer; use -R for a direct "
					    "source-to-destination transfer");
				if (remin == -1 || conn == NULL) {
					/* Connect to dest now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					if (conn == NULL) {
						fatal("Unable to open "
						    "destination connection");
					}
					debug3_f("origin in %d out %d pid %ld",
					    remin, remout, (long)do_cmd_pid);
				}
				/*
				 * XXX remember suser/host/sport and only
				 * reconnect if they change between arguments.
				 * would save reconnections for cases like
				 * scp -3 hosta:/foo hosta:/bar hostb:
				 */
				/* Connect to origin now */
				sftp_free(conn2);
				conn2 = do_sftp_connect(host, suser,
				    sport, sftp_direct,
				    &remin2, &remout2, &do_cmd_pid2);
				if (conn2 == NULL) {
					fatal("Unable to open "
					    "source connection");
				}
				debug3_f("destination in %d out %d pid %ld",
				    remin2, remout2, (long)do_cmd_pid2);
				throughlocal_sftp(conn2, conn, src, targ);
				(void) close(remin2);
				(void) close(remout2);
				remin2 = remout2 = -1;
				if (waitpid(do_cmd_pid2, &status, 0) == -1)
					++errs;
				else if (!WIFEXITED(status) ||
				    WEXITSTATUS(status) != 0)
					++errs;
				do_cmd_pid2 = -1;
				continue;
			} else {
				xasprintf(&bp, "%s -f %s%s", cmd,
				    *src == '-' ? "-- " : "", src);
				if (do_cmd(ssh_program, host, suser, sport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				free(bp);
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				if (do_cmd2(thost, tuser, tport, bp,
				    remin, remout) < 0)
					exit(1);
				free(bp);
				(void) close(remin);
				(void) close(remout);
				remin = remout = -1;
			}
		} else if (host) {	/* standard remote to remote */
			/*
			 * Second remote user is passed to first remote side
			 * via scp command-line. Ensure it contains no obvious
			 * shell characters.
			 */
			if (tuser != NULL && !okname(tuser)) {
				++errs;
				continue;
			}

			freeargs(&alist);
			addargs(&alist, "%s", ssh_program);
			addargs(&alist, "-x");
			addargs(&alist, "-oClearAllForwardings=yes");
			addargs(&alist, "-n");
			for (j = 0; j < remote_remote_args.num; j++) {
				addargs(&alist, "%s",
				    remote_remote_args.list[j]);
			}

			if (sport != -1) {
				addargs(&alist, "-p");
				addargs(&alist, "%d", sport);
			}
			if (suser) {
				addargs(&alist, "-l");
				addargs(&alist, "%s", suser);
			}
			addargs(&alist, "--");
			addargs(&alist, "%s", host);
			/*
			 * HPN status relay (hpn-status-relay-design.md): when
			 * this side would have shown a meter, subscribe to
			 * progress frames from the source by prefixing the
			 * remote command with an environment variable.  An
			 * env prefix (not a flag) so old/stock sources ignore
			 * the request instead of choking on an unknown
			 * option; env(1) rather than a VAR=val shell prefix
			 * so csh-family login shells work.  Our own hpnssh
			 * rewrites the scp token behind the prefix to hpnscp
			 * (clientloop.c).
			 */
			/* Arm the relay for the meter, for the transfer log,
			 * or both.  The "log" value additionally asks the
			 * source for per-file FILEDONE frames; old sources
			 * treat any value as plain arming (frames without
			 * the per-file stream - the log degrades to header
			 * + failures + footer). */
			relay = showprogress != 0 || transferlog_active();
			if (relay) {
				addargs(&alist, "env");
				addargs(&alist, transferlog_active() ?
				    "HPN_ENABLE_REMOTE_PROGRESS=log" :
				    "HPN_ENABLE_REMOTE_PROGRESS=1");
			}
			addargs(&alist, "%s", cmd);
			/*
			 * HPN: make -R a parallel, direct source->target transfer --
			 * forward -j (parallel streams) and a non-default target port
			 * into the source's scp.  The source connects to the target,
			 * so its -P is the target port (tport).
			 */
			if (parallel_num_streams > 1) {
				addargs(&alist, "-j");
				addargs(&alist, "%d", parallel_num_streams);
			}
			if (tport != -1 && tport != SSH_DEFAULT_PORT) {
				addargs(&alist, "-P");
				addargs(&alist, "%d", tport);
			}
			/*
			 * The source runs the actual source->target transfer,
			 * so its address family and verify/resume requests must
			 * travel with it: remote_remote_args above only
			 * decorates the ssh hop to the source, and cmd carries
			 * none of these flags.
			 */
			if (family_flag)
				addargs(&alist, "-%d", family_flag);
			if (compress_flag)
				addargs(&alist, "-C");
			if (zstd_level > 0)
				addargs(&alist, "-z%d", zstd_level);
			if (verify_flag)
				addargs(&alist, "-V");
			if (resume_flag)
				addargs(&alist, "-Z");
			addargs(&alist, "%s", src);
			addargs(&alist, "%s%s%s:%s",
			    tuser ? tuser : "", tuser ? "@" : "",
			    thost, targ);
			if (relay) {
				/* label is local argv data only, never
				 * remote-supplied strings */
				xasprintf(&mlabel, "%s => %s", host, thost);
				r = do_local_cmd_status(&alist, mlabel);
				free(mlabel);
				if (r != 0)
					errs = 1;
			} else if (do_local_cmd(&alist) != 0)
				errs = 1;
		} else {	/* local to remote */
			if (mode == MODE_SFTP) {
				/* no need to glob: already done by shell */
				if (stat(argv[i], &sb) != 0) {
					fatal("stat local \"%s\": %s", argv[i],
					    strerror(errno));
				}
				if (remin == -1) {
					/* Connect to remote now */
					sftp_free(conn);
					conn = do_sftp_connect(thost, tuser,
					    tport, sftp_direct,
					    &remin, &remout, &do_cmd_pid);
					if (conn == NULL) {
						fatal("Unable to open sftp "
						    "connection");
					}
					/*
					 * Launch the parallel orchestrator and
					 * resolve HPNVerifyTransfer once the
					 * control connection is up (-j N only;
					 * single-stream just latches verify).
					 */
					scp_parallel_launch(conn, thost, tuser,
					    tport > 0 ? tport : sshport);
					/*
					 * Start the aggregate transfer meter once,
					 * sized to the total bytes of every source
					 * argument (mirrors sftp.c process_put).
					 * The reporter thread drives it from the
					 * workers' byte counters.  Gated on the
					 * pre-launch showprogress (off under -q /
					 * non-tty); the orchestrator already zeroed
					 * the global.
					 */
					if (parallel_orch != NULL &&
					    parallel_want_progress) {
						char label[64];
						off_t total_bytes = 0;
						long total_files = 0, fc;
						int k;

						for (k = 0; k < argc - 1; k++) {
							fc = 0;
							total_bytes +=
							    sftp_parallel_scan_upload_total(
							    argv[k], &fc);
							total_files += fc;
						}
						snprintf(label, sizeof(label),
						    "Uploading %ld file%s in "
						    "parallel", total_files,
						    total_files == 1 ? "" : "s");
						sftp_parallel_progress_start(
						    parallel_orch, label,
						    total_bytes);
						sftp_parallel_set_file_total(
						    parallel_orch, total_files);
					}
				}

				/* The protocol */
				source_sftp(1, argv[i], targ, conn);
				continue;
			}
			/* SCP */
			if (remin == -1) {
				xasprintf(&bp, "%s -t %s%s", cmd,
				    *targ == '-' ? "-- " : "", targ);
				if (do_cmd(ssh_program, thost, tuser, tport, 0,
				    bp, &remin, &remout, &do_cmd_pid) < 0)
					exit(1);
				if (response() < 0)
					exit(1);
				free(bp);
			}
			source(1, argv + i);
		}
	}
	scp_parallel_finish(conn);
out:
	freeargs(&alist);
	free(tuser);
	free(thost);
	free(targ);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
	sftp_free(conn2);
}

void
tolocal(int argc, char **argv, enum scp_mode_e mode, char *sftp_direct)
{
	char *bp, *host = NULL, *src = NULL, *suser = NULL;
	arglist alist;
	struct sftp_conn *conn = NULL;
	int i, r, sport = -1;

	memset(&alist, '\0', sizeof(alist));
	alist.list = NULL;

	for (i = 0; i < argc - 1; i++) {
		free(suser);
		free(host);
		free(src);
		r = parse_scp_uri(argv[i], &suser, &host, &sport, &src);
		if (r == -1) {
			fmprintf(stderr, "%s: invalid uri\n", argv[i]);
			++errs;
			continue;
		}
		if (r != 0)
			parse_user_host_path(argv[i], &suser, &host, &src);
		if (suser != NULL && !okname(suser)) {
			++errs;
			continue;
		}
		if (!host) {	/* Local to local. */
			freeargs(&alist);
			addargs(&alist, "%s", _PATH_CP);
			if (iamrecursive)
				addargs(&alist, "-r");
			if (pflag)
				addargs(&alist, "-p");
			addargs(&alist, "--");
			addargs(&alist, "%s", argv[i]);
			addargs(&alist, "%s", argv[argc-1]);
			if (do_local_cmd(&alist))
				++errs;
			continue;
		}
		/* Remote to local. */
		if (mode == MODE_SFTP) {
			sftp_free(conn);
			conn = do_sftp_connect(host, suser, sport,
			    sftp_direct, &remin, &remout, &do_cmd_pid);
			if (conn == NULL) {
				error("sftp connection failed");
				++errs;
				continue;
			}
			/*
			 * Launch the parallel orchestrator (and resolve
			 * HPNVerifyTransfer) for this source's connection,
			 * finished just below.  Downloads relaunch per source
			 * argument because each may name a different remote
			 * host, so one orchestrator can't serve them all.
			 */
			scp_parallel_launch(conn, host, suser,
			    sport > 0 ? sport : sshport);
			/*
			 * Start the aggregate transfer meter for this source.
			 * total=0: the remote byte total is not summed upfront
			 * (mirrors sftp.c process_get), so the meter shows bytes
			 * moved + rate rather than a percentage/ETA.  Gated on
			 * the pre-launch showprogress (off under -q / non-tty);
			 * the orchestrator already zeroed the global.  For a
			 * single regular-file source the size is known, so size
			 * the meter to it for a real percentage/ETA; globs and
			 * directories fall back to a rate-only meter (total 0).
			 */
			if (parallel_orch != NULL && parallel_want_progress) {
				Attrib da;
				off_t dtotal = 0;

				if (sftp_stat(conn, src, 1, &da) == 0 &&
				    (da.flags & SSH2_FILEXFER_ATTR_SIZE) &&
				    !S_ISDIR(da.perm))
					dtotal = (off_t)da.size;
				sftp_parallel_progress_start(parallel_orch,
				    "Downloading in parallel", dtotal);
			}

			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			scp_parallel_finish(conn);

			(void) close(remin);
			(void) close(remout);
			remin = remout = -1;
			continue;
		}
		/* SCP */
		xasprintf(&bp, "%s -f %s%s",
		    cmd, *src == '-' ? "-- " : "", src);
		if (do_cmd(ssh_program, host, suser, sport, 0, bp,
		    &remin, &remout, &do_cmd_pid) < 0) {
			free(bp);
			++errs;
			continue;
		}
		free(bp);
		sink(1, argv + argc - 1, src);
		(void) close(remin);
		remin = remout = -1;
	}
	freeargs(&alist);
	free(suser);
	free(host);
	free(src);
	sftp_free(conn);
}

#define TYPE_OVERFLOW(type, val) \
	((sizeof(type) == 4 && (val) > INT32_MAX) || \
	 (sizeof(type) == 8 && (val) > INT64_MAX) || \
	 (sizeof(type) != 4 && sizeof(type) != 8))

/* Prepare remote path, handling ~ by assuming cwd is the homedir */
static char *
prepare_remote_path(struct sftp_conn *conn, const char *path)
{
	size_t nslash;

	/* Handle ~ prefixed paths */
	if (*path == '\0' || strcmp(path, "~") == 0)
		return xstrdup(".");
	if (*path != '~')
		return xstrdup(path);
	if (strncmp(path, "~/", 2) == 0) {
		if ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
			return xstrdup(".");
		return xstrdup(path + 2 + nslash);
	}
	if (sftp_can_expand_path(conn))
		return sftp_expand_path(conn, path);
	/* No protocol extension */
	error("server expand-path extension is required "
	    "for ~user paths in SFTP mode");
	return NULL;
}

void
source_sftp(int argc, char *src, char *targ, struct sftp_conn *conn)
{
	char *target = NULL, *filename = NULL, *abs_dst = NULL;
	int src_is_dir, target_is_dir;
	Attrib a;
	struct stat st;

	memset(&a, '\0', sizeof(a));
	if (stat(src, &st) != 0)
		fatal("stat local \"%s\": %s", src, strerror(errno));
	src_is_dir = S_ISDIR(st.st_mode);
	if ((filename = basename(src)) == NULL)
		fatal("basename \"%s\": %s", src, strerror(errno));

	/* Special handling for source of '..' */
	if (strcmp(filename, "..") == 0)
		filename = "."; /* Upload to dest, not dest/.. */

	/*
	 * No need to glob here - the local shell already took care of
	 * the expansions
	 */
	if ((target = prepare_remote_path(conn, targ)) == NULL)
		cleanup_exit(255);
	target_is_dir = sftp_remote_is_dir(conn, target);
	if (targetshouldbedirectory && !target_is_dir) {
		debug("target directory \"%s\" does not exist", target);
		a.flags = SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = st.st_mode | 0700; /* ensure writable */
		if (sftp_mkdir(conn, target, &a, 1) != 0)
			cleanup_exit(255); /* error already logged */
		target_is_dir = 1;
	}
	if (target_is_dir)
		abs_dst = sftp_path_append(target, filename);
	else {
		abs_dst = target;
		target = NULL;
	}
	debug3_f("copying local %s to remote %s", src, abs_dst);

	if (src_is_dir && iamrecursive) {
		/*
		 * Parallel mode (-j N): the orchestrator walks the tree and
		 * fans the regular files across worker connections; the
		 * post-transfer verify phase runs inside sftp_parallel_wait.
		 * The per-call verify arg is resume-verify intent (-Z verified
		 * resume), distinct from HPNVerifyTransfer which is carried in
		 * the orchestrator config - so it follows resume_flag, exactly
		 * like the download sites.  Passing 0 here sent workers down
		 * the plain size-only resume path: fresh destinations failed
		 * loudly (ENOENT stat) and sparse partials were blind-appended
		 * without a hash check (silent corruption).
		 */
		if (parallel_orch != NULL) {
			if (sftp_parallel_upload_dir(parallel_orch, conn, src,
			    abs_dst, SFTP_PROGRESS_ONLY, resume_flag,
			    resume_flag) != 0) {
				error("failed to upload directory %s to %s",
				    src, targ);
				errs = 1;
			}
		} else if (sftp_upload_dir(conn, src, abs_dst, pflag,
		    SFTP_PROGRESS_ONLY, 0, resume_flag, 0, 1, 1) != 0) {
			error("failed to upload directory %s to %s", src, targ);
			errs = 1;
		}
	} else if (parallel_orch != NULL) {
		if (sftp_parallel_submit_upload(parallel_orch, conn, src,
		    abs_dst, st.st_size, st.st_mode & 07777,
		    resume_flag, resume_flag) != 0) {
			error("failed to upload file %s to %s", src, targ);
			errs = 1;
		}
	} else {
		int ur = sftp_upload(conn, src, abs_dst, pflag, 0,
		    resume_flag, 0, 1);
		if (ur == -1) {
			error("failed to upload file %s to %s", src, targ);
			errs = 1;
			transferlog_file(TRANSFERLOG_FAILED,
			    (long long)st.st_size, abs_dst);
		} else if (ur == 1) {
			/* frame mode: stdout carries binary frames, text on it
			 * corrupts the relay stream - divert to stderr */
			fmprintf(hpn_pm_active() ?
			    stderr : stdout,
			    "File skipped: %s: Identical.\n", src);
			transferlog_file(TRANSFERLOG_SKIPPED,
			    (long long)st.st_size, abs_dst);
		} else if (ur == 2) {
			fmprintf(hpn_pm_active() ?
			    stderr : stdout,
			    "File skipped: %s: Target is larger than source.\n",
			    src);
			transferlog_file(TRANSFERLOG_SKIPPED,
			    (long long)st.st_size, abs_dst);
		} else if (!hpn_verify_transfer) {
			/* TransferLog: success is final only when no verify
			 * phase follows (with -V the line defers there). */
			transferlog_file(TRANSFERLOG_SUCCESS,
			    (long long)st.st_size, abs_dst);
		}
	}

	free(abs_dst);
	free(target);
}

void
source(int argc, char **argv)
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i, statbytes, xfer_size;
	size_t amt, nr;
	int fd = -1, haderr, indx;
	char *last, *name, buf[PATH_MAX], encname[PATH_MAX];
	int len;

	for (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
#ifdef DEBUG
		fprintf(stderr, "%s index is %d, name is %s\n", hostname, indx, name);
#endif
		statbytes = 0;
		len = strlen(name);
		while (len > 1 && name[len-1] == '/')
			name[--len] = '\0';
		if ((fd = open(name, O_RDONLY|O_NONBLOCK)) == -1)
			goto syserr;
		if (strchr(name, '\n') != NULL) {
			strnvis(encname, name, sizeof(encname), VIS_NL);
			name = encname;
		}
		if (fstat(fd, &stb) == -1) {
syserr:			run_err("%s: %s", name, strerror(errno));
			goto next;
		}
		if (stb.st_size < 0) {
			run_err("%s: %s", name, "Negative file size");
			goto next;
		}
		unset_nonblock(fd);
		switch (stb.st_mode & S_IFMT) {
		case S_IFREG:
			break;
		case S_IFDIR:
			if (iamrecursive) {
				rsource(name, &stb);
				goto next;
			}
			/* FALLTHROUGH */
		default:
			run_err("%s: not a regular file", name);
			goto next;
		}
		if ((last = strrchr(name, '/')) == NULL)
			last = name;
		else
			++last;
		curfile = last;
		if (pflag) {
			if (do_times(remout, verbose_mode, &stb) < 0)
				goto next;
		}
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
		snprintf(buf, sizeof buf, "C%04o %lld %s\n",
			 (u_int) (stb.st_mode & FILEMODEMASK),
			 (long long)stb.st_size, last);

#ifdef DEBUG
		fprintf(stderr, "%s: Sending file modes: %s", hostname, buf);
#endif
		(void) atomicio(vwrite, remout, buf, strlen(buf));

		if (response() < 0) {
#ifdef DEBUG
			fprintf(stderr, "%s: response is less than 0\n", hostname);
#endif
			goto next;
		}
		xfer_size = stb.st_size;

		if ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			if (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}

#ifdef DEBUG
		fprintf(stderr, "%s: going to xfer %ld\n", hostname, xfer_size);
#endif
		if (showprogress) {
			start_progress_meter(curfile, xfer_size, &statbytes);
		}
		set_nonblock(remout);
		for (haderr = i = 0; i < xfer_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + (off_t)amt > xfer_size)
				amt = xfer_size - i;
			if (!haderr) {
				if ((nr = atomicio(read, fd, bp->buf, amt)) != amt) {
					haderr = errno;
					memset(bp->buf + nr, 0, amt - nr);
				}
			}
			/* Keep writing after error to retain sync */
			if (haderr) {
				(void)atomicio(vwrite, remout, bp->buf, amt);
				memset(bp->buf, 0, amt);
				continue;
			}
			if (atomicio6(vwrite, remout, bp->buf, amt, scpio,
			    &statbytes) != amt)
				haderr = errno;
		}
		unset_nonblock(remout);

		if (fd != -1) {
			if (close(fd) == -1 && !haderr)
				haderr = errno;
			fd = -1;
		}
		if (!haderr)
			(void) atomicio(vwrite, remout, "", 1);
		else
			run_err("%s: %s", name, strerror(haderr));
		(void) response();
		if (showprogress)
			stop_progress_meter();
	}
}

void
rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[PATH_MAX];

	if (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == NULL)
		last = name;
	else
		last++;
	if (pflag) {
		if (do_times(remout, verbose_mode, statp) < 0) {
			closedir(dirp);
			return;
		}
	}
	(void) snprintf(path, sizeof path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	if (verbose_mode)
		fmprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, sizeof path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
}

void
sink_sftp(int argc, char *dst, const char *src, struct sftp_conn *conn)
{
	char *abs_src = NULL;
	char *abs_dst = NULL;
	glob_t g;
	char *filename, *tmp = NULL;
	int i, r, err = 0, dst_is_dir;
	struct stat st;

	memset(&g, 0, sizeof(g));

	/*
	 * Here, we need remote glob as SFTP can not depend on remote shell
	 * expansions
	 */
	if ((abs_src = prepare_remote_path(conn, src)) == NULL) {
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to local %s", abs_src, dst);
	if ((r = sftp_glob(conn, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		if (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		else
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	if (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		if (sftp_stat(conn, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	if ((r = stat(dst, &st)) != 0)
		debug2_f("stat local \"%s\": %s", dst, strerror(errno));
	dst_is_dir = r == 0 && S_ISDIR(st.st_mode);

	if (g.gl_matchc > 1 && !dst_is_dir) {
		if (r == 0) {
			error("Multiple files match pattern, but destination "
			    "\"%s\" is not a directory", dst);
			err = -1;
			goto out;
		}
		debug2_f("creating destination \"%s\"", dst);
		if (mkdir(dst, 0777) != 0) {
			error("local mkdir \"%s\": %s", dst, strerror(errno));
			err = -1;
			goto out;
		}
		dst_is_dir = 1;
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		if ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for destination of '..' */
		if (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		if (dst_is_dir)
			abs_dst = sftp_path_append(dst, filename);
		else
			abs_dst = xstrdup(dst);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		if (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			/*
			 * Parallel mode (-j N): the orchestrator walks the
			 * remote tree, fans the files across worker connections
			 * and runs the post-transfer verify phase in
			 * sftp_parallel_wait.  verify carries scp's -Z
			 * verified-resume intent, matching the single-stream
			 * calls below; HPNVerifyTransfer rides on the
			 * orchestrator config.
			 */
			if (parallel_orch != NULL) {
				if (sftp_parallel_download_dir(parallel_orch,
				    conn, g.gl_pathv[i], abs_dst,
				    SFTP_PROGRESS_ONLY, resume_flag,
				    resume_flag) == -1)
					err = -1;
			} else if (sftp_download_dir(conn, g.gl_pathv[i],
			    abs_dst, NULL, pflag, SFTP_PROGRESS_ONLY,
			    resume_flag, resume_flag /* verify */, 0, 1, 1)
			    == -1)
				err = -1;
		} else if (parallel_orch != NULL) {
			/*
			 * Single file: stat it so the orchestrator can size the
			 * range-split decision and meter, then submit.
			 */
			Attrib ga;
			off_t fsize = 0;
			mode_t fmode = 0;

			if (sftp_stat(conn, g.gl_pathv[i], 1, &ga) == 0) {
				if (ga.flags & SSH2_FILEXFER_ATTR_SIZE)
					fsize = (off_t)ga.size;
				if (ga.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
					fmode = ga.perm & 07777;
			}
			if (sftp_parallel_submit_download(parallel_orch, conn,
			    g.gl_pathv[i], abs_dst, fsize, fmode,
			    resume_flag, resume_flag) != 0)
				err = -1;
		} else {
			int dr = sftp_download(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag, resume_flag, 0, 1,
			    resume_flag /* verify */);
			if (dr == -1)
				err = -1;
			else if (dr == 1)
				fmprintf(hpn_pm_active() ?
				    stderr : stdout,	/* keep frames clean */
				    "File skipped: %s: Identical.\n",
				    g.gl_pathv[i]);
			else if (dr == 2)
				fmprintf(hpn_pm_active() ?
				    stderr : stdout,
				    "File skipped: %s: Target is larger"
				    " than source.\n", g.gl_pathv[i]);
			/* TransferLog: size from the local dest (present on
			 * success/skip; -1 when the failure left nothing).
			 * Success defers to the verify phase under -V. */
			if (transferlog_active() &&
			    (dr != 0 || !hpn_verify_transfer)) {
				struct stat lsb;
				long long sz = (stat(abs_dst, &lsb) == 0) ?
				    (long long)lsb.st_size : -1;

				transferlog_file(dr == -1 ? TRANSFERLOG_FAILED :
				    (dr == 0 ? TRANSFERLOG_SUCCESS :
				    TRANSFERLOG_SKIPPED), sz, abs_dst);
			}
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(tmp);
	globfree(&g);
	if (err == -1)
		errs = 1;
}


#define TYPE_OVERFLOW(type, val) \
	((sizeof(type) == 4 && (val) > INT32_MAX) || \
	 (sizeof(type) == 8 && (val) > INT64_MAX) || \
	 (sizeof(type) != 4 && sizeof(type) != 8))


void
sink(int argc, char **argv, const char *src)
{
	static BUF buffer;
	struct stat stb;
	BUF *bp;
	off_t i;
	size_t j, count;
	int amt, exists, first, ofd;
	mode_t mode, omode, mask;
	off_t size, statbytes, xfer_size;
	unsigned long long ull;
	int setimes, targisdir, wrerr;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[16384], visbuf[16384];
	char **patterns = NULL;
	size_t n, npatterns = 0;
	struct timeval tv[2];
	np = NULL; /* this was originally '/0' but that's wrong */


#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

#ifdef DEBUG
       fprintf (stderr, "%s: LOCAL In sink with %s\n", hostname, src);
#endif
	if (TYPE_OVERFLOW(time_t, 0) || TYPE_OVERFLOW(off_t, 0))
		SCREWUP("Unexpected off_t/time_t size");

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag) {
		(void) umask(mask);
		mask |= 07000;
	}
	if (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);

#ifdef DEBUG
	fprintf (stderr, "%s: Sending null to remout.\n",hostname);
#endif
	(void) atomicio(vwrite, remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;

#ifdef DEBUG
	fprintf(stderr, "%s: Target is %s with a size of %ld\n", hostname, targ, stb.st_size);
#endif
	if (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		if (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}

	for (first = 1;; first = 0) {
#ifdef DEBUG
		fprintf(stderr, "%s: At start of loop buf is %s\n", hostname, buf);
#endif
		cp = buf;
		if (atomicio(read, remin, cp, 1) != 1)
			goto done;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;
		if (verbose_mode)
			fmprintf(stderr, "Sink: %s", buf);

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0) {
				(void) snmprintf(visbuf, sizeof(visbuf),
				    NULL, "%s", buf + 1);
				(void) atomicio(vwrite, STDERR_FILENO,
				    visbuf, strlen(visbuf));
			}
			if (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		if (buf[0] == 'E') {
#ifdef DEBUG
			fprintf (stderr, "%s: Sending null to remout.\n", hostname);
#endif
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		if (ch == '\n')
			*--cp = 0;

		cp = buf;
#ifdef DEBUG
		fprintf(stderr, "%s: buf is %s\n", hostname, buf);
#endif
		if (*cp == 'T') {
			setimes++;
			cp++;
			if (!isdigit((unsigned char)*cp))
				SCREWUP("mtime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			if (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			mtime.tv_sec = ull;
			mtime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ' || mtime.tv_usec < 0 ||
			    mtime.tv_usec > 999999)
				SCREWUP("mtime.usec not delimited");
			if (!isdigit((unsigned char)*cp))
				SCREWUP("atime.sec not present");
			ull = strtoull(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			if (TYPE_OVERFLOW(time_t, ull))
				setimes = 0;	/* out of range */
			atime.tv_sec = ull;
			atime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != '\0' || atime.tv_usec < 0 ||
			    atime.tv_usec > 999999)
				SCREWUP("atime.usec not delimited");

#ifdef DEBUG
			fprintf (stderr, "%s: Sending null to remout.\n", hostname);
#endif
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
#ifdef DEBUG
		fprintf(stderr, "%s: buf is %s\n", hostname, buf);
		fprintf(stderr, "%s: cp is %s\n", hostname, cp);
#endif
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (!pflag)
			mode &= ~mask;
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

#ifdef DEBUG
		fprintf(stderr, "%s: cp is %s\n", hostname, cp);
#endif

		if (!isdigit((unsigned char)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		if (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		if (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

#ifdef DEBUG
		fprintf(stderr, "%s: cp is %s\n", hostname, cp);
#endif
		if (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
#ifdef DEBUG
		fprintf(stderr, "%s cp is %s\n", hostname, cp);
#endif
		if (npatterns > 0) {
			for (n = 0; n < npatterns; n++) {
				if (strcmp(patterns[n], cp) == 0 ||
				    fnmatch(patterns[n], cp, 0) == 0)
					break;
			}
			if (n >= npatterns) {
				debug2_f("incoming filename \"%s\" does not "
				    "match any of %zu expected patterns", cp,
				    npatterns);
				for (n = 0; n < npatterns; n++) {
					debug3_f("expected pattern %zu: \"%s\"",
					    n, patterns[n]);
				}
				SCREWUP("filename does not match request");
			}
		}
		if (targisdir) {
			static char *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				free(namebuf);
				namebuf = xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			int mod_flag = pflag;
			if (!iamrecursive)
				SCREWUP("received directory without -r");
			if (exists) {
				if (!S_ISDIR(stb.st_mode)) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void) chmod(np, mode);
			} else {
				/* Handle copying from a read-only directory */
				mod_flag = 1;
				if (mkdir(np, mode | S_IRWXU) == -1)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect, src);
			if (setimes) {
				setimes = 0;
				(void) utimes(vect[0], tv);
			}
			if (mod_flag)
				(void) chmod(vect[0], mode);
			free(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWUSR;
		xfer_size = size;

		ofd = open(np, O_WRONLY|O_CREAT, mode);
		if (ofd == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}

		/* ack the file header now that the local file is open; scp's
		 * protocol depends on this call-and-response dance. */
#ifdef DEBUG
		fprintf (stderr, "%s: Sending null to remout.\n", hostname);
#endif
		(void) atomicio(vwrite, remout, "", 1);

		if ((bp = allocbuf(&buffer, ofd, COPY_BUFLEN)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = 0;

		/*
		 * NB. do not use run_err() unless immediately followed by
		 * exit() below as it may send a spurious reply that might
		 * desynchronise us from the peer. Use note_err() instead.
		 */
		statbytes = 0;
		if (showprogress)
			start_progress_meter(curfile, xfer_size, &statbytes);
		set_nonblock(remin);
#ifdef DEBUG
		fprintf(stderr, "%s: xfer_size is %ld\n", hostname, xfer_size);
#endif
		for (count = i = 0; i < xfer_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > xfer_size)
				amt = xfer_size - i;
			count += amt;
			/* read the data from the socket*/
			do {

				j = atomicio6(read, remin, cp, amt,
				    scpio, &statbytes);
				if (j == 0) {
					run_err("%s", j != EPIPE ?
					    strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);
			if (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				if (!wrerr) {
					if (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						note_err("%s: %s", np,
						    strerror(errno));
						wrerr = 1;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		unset_nonblock(remin);
		if (count != 0 && !wrerr &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			note_err("%s: %s", np, strerror(errno));
			wrerr = 1;
		}
		if (!wrerr && (!exists || S_ISREG(stb.st_mode)) &&
		    ftruncate(ofd, size) != 0)
			note_err("%s: truncate: %s", np, strerror(errno));

		if (pflag) {
			if (exists || omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		} else {
			if (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode & ~mask)) {
#else /* HAVE_FCHMOD */
				if (chmod(np, omode & ~mask)) {
#endif /* HAVE_FCHMOD */
					note_err("%s: set mode: %s",
					    np, strerror(errno));
				}
		}
		if (close(ofd) == -1)
			note_err("%s: close: %s", np, strerror(errno));
		(void) response();
		if (showprogress)
			stop_progress_meter();
		if (setimes && !wrerr) {
			setimes = 0;
			if (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		if (note_err(NULL) == 0) {
#ifdef DEBUG
			fprintf (stderr, "%s: Sending null to remout.\n", hostname);
#endif
			(void) atomicio(vwrite, remout, "", 1); }
        }
done:
	for (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	return;
screwup:
	for (n = 0; n < npatterns; n++)
		free(patterns[n]);
	free(patterns);
	run_err("protocol error: %s", why);
	exit(1);
}

void
throughlocal_sftp(struct sftp_conn *from, struct sftp_conn *to,
    char *src, char *targ)
{
	char *target = NULL, *filename = NULL, *abs_dst = NULL;
	char *abs_src = NULL, *tmp = NULL;
	glob_t g;
	int i, r, targetisdir, err = 0;

	if ((filename = basename(src)) == NULL)
		fatal("basename %s: %s", src, strerror(errno));

	if ((abs_src = prepare_remote_path(from, src)) == NULL ||
	    (target = prepare_remote_path(to, targ)) == NULL)
		cleanup_exit(255);
	memset(&g, 0, sizeof(g));

	targetisdir = sftp_remote_is_dir(to, target);
	if (!targetisdir && targetshouldbedirectory) {
		error("%s: destination is not a directory", targ);
		err = -1;
		goto out;
	}

	debug3_f("copying remote %s to remote %s", abs_src, target);
	if ((r = sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK,
	    NULL, &g)) != 0) {
		if (r == GLOB_NOSPACE)
			error("%s: too many glob matches", src);
		else
			error("%s: %s", src, strerror(ENOENT));
		err = -1;
		goto out;
	}

	/* Did we actually get any matches back from the glob? */
	if (g.gl_matchc == 0 && g.gl_pathc == 1 && g.gl_pathv[0] != NULL) {
		/*
		 * If nothing matched but a path returned, then it's probably
		 * a GLOB_NOCHECK result. Check whether the unglobbed path
		 * exists so we can give a nice error message early.
		 */
		if (sftp_stat(from, g.gl_pathv[0], 1, NULL) != 0) {
			error("%s: %s", src, strerror(ENOENT));
			err = -1;
			goto out;
		}
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		if ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			err = -1;
			goto out;
		}

		/* Special handling for source of '..' */
		if (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		if (targetisdir)
			abs_dst = sftp_path_append(target, filename);
		else
			abs_dst = xstrdup(target);

		debug("Fetching %s to %s\n", g.gl_pathv[i], abs_dst);
		if (sftp_globpath_is_dir(g.gl_pathv[i]) && iamrecursive) {
			if (sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag, SFTP_PROGRESS_ONLY, 1) == -1)
				err = -1;
		} else {
			if (sftp_crossload(from, to, g.gl_pathv[i], abs_dst,
			    NULL, pflag) == -1)
				err = -1;
		}
		free(abs_dst);
		abs_dst = NULL;
		free(tmp);
		tmp = NULL;
	}

out:
	free(abs_src);
	free(abs_dst);
	free(target);
	free(tmp);
	globfree(&g);
	if (err == -1)
		errs = 1;
}

int
response(void)
{
	char ch, *cp, resp, rbuf[2048], visbuf[2048];

	if (atomicio(read, remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;

	switch (resp) {
	case 0:		/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by error msg */
	case 2:		/* fatal error, "" */
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		if (!iamremote) {
			cp[-1] = '\0';
			(void) snmprintf(visbuf, sizeof(visbuf),
			    NULL, "%s\n", rbuf);
			(void) atomicio(vwrite, STDERR_FILENO,
			    visbuf, strlen(visbuf));
		}
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/* NOTREACHED */
}

void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: hpnscp [-346ABCOpqRrsTVvZ] [-c cipher] [-D sftp_server_path]\n"
	    "              [-F ssh_config] [-i identity_file] [-J destination] [-j streams]\n"
	    "              [-l limit] [-M range_split_min] [-o ssh_option] [-P port]\n"
	    "              [-S program] [-w writers_per_file] [-X sftp_option] [-z level]\n"
	    "              source ... target\n");
	exit(1);

}

void
run_err(const char *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	if (fp != NULL || (remout != -1 && (fp = fdopen(remout, "w")))) {
		(void) fprintf(fp, "%c", 0x01);
		(void) fprintf(fp, "scp: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}

	if (!iamremote) {
		va_start(ap, fmt);
		vfmprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

/*
 * Notes a sink error for sending at the end of a file transfer. Returns 0 if
 * no error has been noted or -1 otherwise. Use note_err(NULL) to flush
 * any active error at the end of the transfer.
 */
int
note_err(const char *fmt, ...)
{
	static char *emsg;
	va_list ap;

	/* Replay any previously-noted error */
	if (fmt == NULL) {
		if (emsg == NULL)
			return 0;
		run_err("%s", emsg);
		free(emsg);
		emsg = NULL;
		return -1;
	}

	errs++;
	/* Prefer first-noted error */
	if (emsg != NULL)
		return -1;

	va_start(ap, fmt);
	vasnmprintf(&emsg, INT_MAX, NULL, fmt, ap);
	va_end(ap);
	return -1;
}

void
verifydir(char *cp)
{
	struct stat stb;

	if (!stat(cp, &stb)) {
		if (S_ISDIR(stb.st_mode))
			return;
		errno = ENOTDIR;
	}
	run_err("%s: %s", cp, strerror(errno));
	killchild(0);
}

int
okname(char *cp0)
{
	int c;
	char *cp;

	cp = cp0;
	do {
		c = (int)*cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit((unsigned char)c)) {
			switch (c) {
			case '\'':
			case '"':
			case '`':
			case ' ':
			case '#':
				goto bad;
			default:
				break;
			}
		}
	} while (*++cp);
	return (1);

bad:	fmprintf(stderr, "%s: invalid user name\n", cp0);
	return (0);
}

BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) == -1) {
		run_err("fstat: %s", strerror(errno));
		return (NULL);
	}
	size = ROUNDUP(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	if (bp->cnt >= size)
		return (bp);
	bp->buf = xrecallocarray(bp->buf, bp->cnt, size, 1);
	bp->cnt = size;
	return (bp);
}

void
lostconn(int signo)
{
	if (!iamremote)
		(void)write(STDERR_FILENO, "lost connection\n", 16);
	if (signo)
		_exit(1);
	else
		exit(1);
}

void
cleanup_exit(int i)
{
	if (remin > 0)
		close(remin);
	if (remout > 0)
		close(remout);
	if (remin2 > 0)
		close(remin2);
	if (remout2 > 0)
		close(remout2);
	if (do_cmd_pid > 0)
		(void)waitpid(do_cmd_pid, NULL, 0);
	if (do_cmd_pid2 > 0)
		(void)waitpid(do_cmd_pid2, NULL, 0);
	exit(i);
}
