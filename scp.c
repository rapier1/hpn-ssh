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
 * Copyright (c) 2026 Chris Rapier. All rights reserved.
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
#include "misc.h"
#include "progressmeter.h"
#include "utf8.h"
#include "sftp.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "hpn-status-frame.h"	/* HPN: HPNS_FF_* failure kinds */
#include "hpn-launch-args.h"	/* HPN: launcher args and the -R launch */
#include "hpn-meter.h"	/* HPN: meter for scp-protocol (-O) transfers */
#include "hpn-compress.h"	/* HPN: -z zstd level bounds */
#include "sftp-client-internal.h"	/* HPN: sftp_conn accessors */
#include "sftp-hpn-verify.h"	/* HPN: sftp_hpn_verify_repair_resolve */
#include "sftp-hpn-transferlog.h"	/* HPN: -X TransferLog */
#include "sftp-parallel.h"	/* HPN: -j parallel transfers */
#include "sftp-lustre-client.h"	/* HPN: maybe_apply_lustre_layout_parent */

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

/* Needed for sftp */
_Atomic sig_atomic_t interrupted = 0;	/* HPN: match the externs */

int sftp_glob(struct sftp_conn *, const char *, int,
    int (*)(const char *, int), glob_t *); /* proto for sftp-glob.c */

/* HPN-SSH additions.
 *
 * The file-scope variables and prototype in this block are HPN-specific
 * with no upstream counterpart. They are collected here so the upstream
 * declarations above keep their original order and OpenSSH merges do
 * not collide with HPN code. */

/* HPN: the -j orchestrator. NULL runs single-stream, the default. */
static struct sftp_parallel *parallel_orch = NULL;

/* HPN: worker count from -j. 1, the default, runs single-stream. Each
 * launch caps a copy by that connection's server, so this keeps the
 * original request. Also passed to the source scp under -R. */
static int parallel_num_streams = 1;

/* HPN: -i and -F, passed to the -j workers' ssh. */
static const char *parallel_identity = NULL;
static const char *parallel_config_file = NULL;

/* HPN: -o options for the -j workers' ssh: each -o as given, plus the -o
 * forms of -4, -6, -C, -c, -J and -z. */
static arglist parallel_extra_o;

/* HPN: -V, verify every transfer. Also passed to the source scp under
 * -R. */
static int hpn_verify_transfer = 0;

/* HPN: -Z, verified resume over SFTP. Also passed to the source scp
 * under -R. */
static int resume_flag = 0;

/* HPN: -X VerifyRepair=no sets it, so files that fail verify are not
 * repaired. */
static int no_verify_repair = 0;

/* HPN: set when a file fails verify. main then exits
 * SFTP_EX_VERIFY_FAILED. */
static int hpn_verify_failed = 0;

/* HPN: -4/-6 and -C, passed to the source scp under -R. */
static int family_flag = 0;
static int compress_flag = 0;

/* HPN: -z zstd level, 0 if unset. main passes it to ssh and the -j
 * workers as ZstdLevel, and to the source scp under -R. */
static int zstd_level = 0;

/* HPN: -M minimum range size in MiB, bounded to [RANGE_SPLIT_MIN_MB_FLOOR,
 * RANGE_SPLIT_MIN_MB_CEILING] at parse time. 0 means unset, and the fleet
 * uses RANGE_SPLIT_MIN_SIZE_DEFAULT. */
static int range_split_min_mb_user = 0;

/* HPN: -w cap on concurrent range writers per file, bounded to
 * [HPN_RANGE_WRITERS_CAP_FLOOR, HPN_RANGE_WRITERS_CAP_MAX] at parse time.
 * 0 means unset, and the fleet uses HPN_RANGE_WRITERS_CAP_DEFAULT. */
static int writers_cap_user = 0;

/* HPN: showprogress as it was before sftp_parallel_start cleared it to
 * keep each worker's own meter off. The -j aggregate meter checks this
 * instead. */
static int parallel_want_progress = 0;

/* HPN: tolocal calls it before its definition. */
static char *prepare_remote_path(struct sftp_conn *, const char *);

/* HPN: the attributes sftp_glob fetched for a matched path, so a -j
 * download does not stat the file again, and the byte total of the
 * matched files for the -j meter. Defined in sftp-glob.c. */
void sftp_glob_match_attrib(struct sftp_conn *, const char *, Attrib *);
off_t sftp_glob_files_total(const glob_t *, int *);

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

	/* HPN: a third-party launcher may send the arguments on stdin */
	hpn_launch_args_stdin(&argc, &argv);

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
		case 'A':
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			addargs(&remote_remote_args, "-%c", ch);
			/* HPN: the -j workers' ssh takes -4, -6 and -C as -o
			 * options, and the -R source scp takes them as flags.
			 * -A stays off the workers. */
			if (ch == '4') {
				addargs(&parallel_extra_o, "AddressFamily=inet");
				family_flag = 4;
			} else if (ch == '6') {
				addargs(&parallel_extra_o, "AddressFamily=inet6");
				family_flag = 6;
			} else if (ch == 'C') {
				addargs(&parallel_extra_o, "Compression=yes");
				compress_flag = 1;
			}
			break;
		case 'z':
			/* HPN: zstd@hpnssh.org at this level, passed as
			 * ZstdLevel to the main ssh and each -j worker's, and
			 * as -z to the -R source scp. */
			zstd_level = (int)strtonum(optarg, HPN_ZSTD_LEVEL_MIN,
			    HPN_ZSTD_LEVEL_MAX, &errstr);
			if (errstr != NULL)
				fatal("Invalid -z zstd level \"%s\": %s "
				    "(range %d-%d)", optarg, errstr,
				    HPN_ZSTD_LEVEL_MIN, HPN_ZSTD_LEVEL_MAX);
			addargs(&args, "-oZstdLevel=%d", zstd_level);
			addargs(&parallel_extra_o, "ZstdLevel=%d", zstd_level);
			break;
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
		case 'c':
		case 'i':
		case 'F':
		case 'J':
			addargs(&remote_remote_args, "-%c", ch);
			addargs(&remote_remote_args, "%s", optarg);
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			/* HPN: the -j workers' ssh takes -i and -F as given,
			 * and -o, -c and -J as -o options. */
			if (ch == 'i')
				parallel_identity = optarg;
			else if (ch == 'F')
				parallel_config_file = optarg;
			else if (ch == 'o')
				addargs(&parallel_extra_o, "%s", optarg);
			else if (ch == 'c')
				addargs(&parallel_extra_o, "Ciphers=%s",
				    optarg);
			else if (ch == 'J')
				addargs(&parallel_extra_o, "ProxyJump=%s",
				    optarg);
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
		case 'Z':	/* HPN */
			resume_flag = 1;
			break;
		case 'V':
			/* HPN: verify every transfer. It is a flag, not a
			 * config keyword, because plain hpnssh would parse and
			 * ignore an ssh-wide -o option. */
			hpn_verify_transfer = 1;
			break;
		case 'j':	/* HPN */
			parallel_num_streams = (int)strtonum(optarg, 1,
			    SFTP_PARALLEL_MAX_WORKERS, &errstr);
			if (errstr != NULL)
				fatal("Number of parallel streams must be "
				    "between 1 and %d: \"%s\": %s",
				    SFTP_PARALLEL_MAX_WORKERS, optarg, errstr);
			break;
		case 'M':
			/* HPN: the minimum size, in MiB, of the byte ranges a
			 * large file is split into for -j. A file splits only
			 * at twice this size. The bounds keep a tiny value from
			 * over-chunking and a huge one from never splitting. */
			range_split_min_mb_user = (int)strtonum(optarg,
			    RANGE_SPLIT_MIN_MB_FLOOR,
			    RANGE_SPLIT_MIN_MB_CEILING, &errstr);
			if (errstr != NULL)
				fatal("Range-split minimum (-M) must be between "
				    "%d and %d MiB: \"%s\": %s",
				    RANGE_SPLIT_MIN_MB_FLOOR,
				    RANGE_SPLIT_MIN_MB_CEILING, optarg, errstr);
			break;
		case 'w':
			/* HPN: the most -j workers that write ranges of one
			 * file at once. Buffered writes to one inode serialise
			 * on its lock, and the default of 4 is the measured
			 * throughput knee. The cap in effect is the smaller of
			 * this and -j. */
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
			if (transferlog_option(optarg))	/* HPN */
				break;
			/* HPN: StrictArgs governs the -R launch */
			if (hpn_launch_args_option(optarg))
				break;
			/* HPN: VerifyRepair= and Pacing= */
			if (sftp_hpn_x_option(optarg, &no_verify_repair))
				break;
			/* Please keep in sync with sftp.c -X */
			/* HPN: the names match case-insensitively */
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
				/* HPN: capped as the derived default is, at
				 * SFTP_HPN_MAX_REQUESTS */
				llv = strtonum(optarg + 10, 1,
					       SFTP_HPN_MAX_REQUESTS, &errstr);
				if (errstr != NULL) {
					fatal("Invalid number of requests. Must be between 1 and %d. "
					      "\"%s\": %s", SFTP_HPN_MAX_REQUESTS,
					      optarg + 10, errstr);
				}
				sftp_nrequests = (size_t)llv;
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

	/* HPN: verified resume (-Z) runs over SFTP only, so -Z with the scp
	 * protocol is refused. The remote scp sees -Z only from a client
	 * older than HPN-SSH 19, which asks for resume over the scp
	 * protocol. */
	if (resume_flag && mode == MODE_SCP) {
		if (iamremote)
			fatal("Resume (-Z) over the scp protocol is not "
			    "supported. Please upgrade the client to at least "
			    "HPN-SSH 19.0.0, or run without -Z.");
		fatal("-Z (verified resume) requires SFTP mode and cannot be "
		    "used with -O");
	}

	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	if (!isatty(STDOUT_FILENO)) {
		/* HPN: ENV-VAR HPN_ENABLE_REMOTE_PROGRESS. A frame consumer,
		 * such as the hpnscp that launched a -R transfer, sets it to
		 * get binary progress frames on stdout instead of the text
		 * meter. The value "log" also asks for per-file FILEDONE
		 * frames. It is an env var, not a flag, so binaries without
		 * it ignore the request instead of failing. Otherwise a pipe
		 * gets no meter, unless HPN_PM_DEBUG is set. */
		const char *rprog = getenv("HPN_ENABLE_REMOTE_PROGRESS");

		if (rprog != NULL) {
			hpn_pm_frame_mode((u_int)parallel_num_streams);
			if (strcmp(rprog, "log") == 0)
				transferlog_frames(1);
		} else if (getenv("HPN_PM_DEBUG") == NULL)
			showprogress = 0;
	}

	/* HPN: open the -X TransferLog now, before any connection. The open
	 * checks that the path is writable, so a bad path fails the run
	 * before work starts. */
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
	/* HPN: expand the operands no shell saw, before they are counted */
	hpn_launch_args_glob(&argc, &argv);
	if (argc < 2)
		usage();
	if (argc > 2)
		targetshouldbedirectory = 1;

	remin = remout = -1;
	do_cmd_pid = -1;
	/* Command to be executed on remote system using "ssh". */
	/* HPN: when the server's binaries carry the hpn prefix, clientloop.c
	 * rewrites this command to run hpnscp. */
	(void) snprintf(cmd, sizeof cmd, "scp%s%s%s%s",
	    verbose_mode ? " -v" : "",
	    iamrecursive ? " -r" : "", pflag ? " -p" : "",
	    targetshouldbedirectory ? " -d" : "");

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
	/* HPN: send the status relay's END frame, a no-op unless frames are
	 * on, and close the TransferLog. A frame consumer takes the result
	 * from the exit status. A verify failure exits
	 * SFTP_EX_VERIFY_FAILED. */
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

/* HPN: set up the transfers on conn. Latches -V, verify repair and the
 * HPN ssh_config options on the connection, then starts the -j fleet when
 * -j asks for more than one worker and the server allows it. If the
 * fleet does not start, parallel_orch stays NULL and the transfers run
 * single-stream. */
static void
scp_parallel_launch(struct sftp_conn *conn, const char *host,
    const char *user, int port)
{
	struct sftp_parallel_config pcfg;
	char portbuf[16] = "";
	int eff_streams = 0;	/* per-call effective stream count after the cap */

	/* sftp_parallel_start clears showprogress, so save it for the
	 * aggregate meter checks. */
	parallel_want_progress = showprogress;

	/* -V latches verify on the connection, so single-stream transfers
	 * verify through it, and reaches the fleet in pcfg below. A -V the
	 * server cannot honour stops the run before any data moves. */
	if (hpn_verify_transfer && !sftp_conn_verify_transfer_supported(conn))
		fatal("%s", VERIFY_INCOMPAT_MSG);
	sftp_conn_set_verify_transfer(conn, hpn_verify_transfer);

	/* Verify repair, on unless -X VerifyRepair=no, with
	 * VERIFY_REPAIR_ATTEMPTS attempts. The connection takes it for
	 * single-stream transfers, and the fleet gets no_verify_repair in
	 * pcfg below. */
	{
		int rep_enabled, rep_attempts;

		sftp_hpn_verify_repair_resolve(no_verify_repair,
		    &rep_enabled, &rep_attempts);
		sftp_conn_set_verify_repair(conn, rep_enabled, rep_attempts);
	}

	/* HPN: resolve the HPN ssh_config options once, before the
	 * single-stream returns below. Without -j the serial walks run on
	 * this connection, so it takes the bundle, Lustre and failure log
	 * settings from here. With -j, pcfg carries the rest to the fleet. A
	 * failed resolve leaves the defaults in pcfg. */
	memset(&pcfg, 0, sizeof(pcfg));
	(void)sftp_parallel_apply_ssh_config(&pcfg, host,
	    parallel_config_file, parallel_extra_o.list);
	sftp_conn_set_bundle_config(conn, pcfg.use_bundle,
	    pcfg.bundle_size, pcfg.writer_pool);
	/* The layout hooks read HPNLustreStripeCount from the connection,
	 * for the walker's directories and single files alike. */
	sftp_conn_set_lustre_stripe_count(conn, pcfg.lustre_stripe_count);
	transferlog_failure_config(pcfg.failure_log);

	if (parallel_num_streams <= 1)
		return;			/* single-stream: no orchestrator */

	/* HPN: cap the -j request by this connection's server. Downloads
	 * relaunch per source argument, and each may be a different host, so
	 * parallel_num_streams stays the original request. */
	eff_streams = sftp_parallel_cap_workers(conn, parallel_num_streams);
	if (eff_streams <= 1)
		return;			/* clamped down to single-stream */

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
	pcfg.extra_argv    = parallel_extra_o.list;
	pcfg.transfer_buflen = (u_int)sftp_copy_buflen;
	pcfg.num_requests  = (u_int)sftp_nrequests;
	pcfg.no_verify_repair = no_verify_repair;
	pcfg.limit_kbps    = (uint64_t)limit_kbps;
	pcfg.writers_per_inode_cap = writers_cap_user;
	pcfg.range_split_min_mb = range_split_min_mb_user;
	pcfg.verbose_level = verbose_mode;
	pcfg.preserve_flag = pflag;
	pcfg.print_flag    = showprogress ? SFTP_PROGRESS_ONLY : SFTP_QUIET;
	/* scp follows symlinks in a recursive walk and writes files in place,
	 * as the serial path does through sftp_upload_dir and
	 * sftp_download_dir. sftp leaves both at 0. */
	pcfg.follow_link_flag = 1;
	pcfg.inplace_flag  = 1;
	pcfg.verify_transfer = hpn_verify_transfer;	/* -V, not ssh_config */
	/* The stall detector's defaults, shared with sftp.c. */
	sftp_parallel_set_stall_defaults(&pcfg);

	if (showprogress)
		logit("Parallel streams: -j %d", eff_streams);
	parallel_orch = sftp_parallel_start(&pcfg);
	if (parallel_orch == NULL) {
		logit("Parallel-streams setup failed; falling back to "
		    "single-stream mode.");
		return;
	}
	/* Ignore SIGPIPE from here on. scp's handler, lostconn, would end the
	 * process on a write to one dead worker's pipe. Ignored, the write
	 * fails with EPIPE, the worker's connection is marked dead and its
	 * unit moves to a respawned worker. */
	(void)ssh_signal(SIGPIPE, SIG_IGN);
	/* HPN: the path RTT sizes the born-dead threshold and the watchdog's
	 * warmup budget. Without it they keep RTT-free defaults. */
	sftp_parallel_sample_path_rtt(parallel_orch, conn);
	/* No interrupt flag is registered with the fleet. On SIGINT killchild
	 * passes the signal to the control connection's ssh and exits, and
	 * the workers end as their pipes close. A one-shot command wants
	 * that, so the fleet's graceful abort goes unused. */
}

/* HPN: print each path with prefix, record it for the status relay as
 * kind, and free the list. total counts the paths the capped list left
 * out too. */
static void
report_failed_paths(const char *prefix, u_int kind, char **paths, int used,
    int total)
{
	int i;

	for (i = 0; i < used; i++) {
		fmprintf(stderr, "%s: %s\n", prefix, paths[i]);
		hpn_pm_filefail(kind, paths[i], strlen(paths[i]));
		free(paths[i]);
	}
	free(paths);
	if (total > used)
		fmprintf(stderr, "%s: %d more not listed\n", prefix,
		    total - used);
}

/* HPN: finish the transfers on conn. With a -j fleet, drain it (its
 * verify runs in the drain), print the summary and the failed paths, and
 * stop it. Without one, run the connection's verify when -V is on. A
 * failed path or an abort adds to errs. A verify failure sets
 * hpn_verify_failed, so main exits SFTP_EX_VERIFY_FAILED. */
static void
scp_parallel_finish(struct sftp_conn *conn)
{
	char **paths = NULL;
	int total, used = 0;

	if (parallel_orch != NULL) {
		struct sftp_parallel_stats pstats;

		sftp_parallel_wait(parallel_orch, conn);
		/* A fleet abort must not exit 0. The destination is
		 * incomplete. */
		if (sftp_parallel_is_aborting(parallel_orch)) {
			fmprintf(stderr, "scp: transfer aborted\n");
			++errs;
		}
		/* The reporter's last tick can lag a fast transfer, so publish
		 * the walker's final file counts before the meter and the END
		 * frame read them. */
		hpn_pm_set_files(
		    sftp_parallel_files_submitted(parallel_orch),
		    sftp_parallel_files_total(parallel_orch),
		    sftp_parallel_files_total_known(parallel_orch));
		sftp_parallel_progress_stop(parallel_orch);
		sftp_parallel_get_stats(parallel_orch, &pstats);
		if (parallel_want_progress)
			sftp_parallel_report_session(&pstats);
		total = sftp_parallel_drain_failed_paths(parallel_orch,
		    &paths, &used);
		if (total > 0) {
			report_failed_paths("scp: transfer incomplete",
			    HPNS_FF_TRANSFER, paths, used, total);
			++errs;
		}
		total = sftp_parallel_drain_verify_failures(parallel_orch,
		    &paths, &used);
		if (total > 0) {
			report_failed_paths("Verification FAILED",
			    HPNS_FF_VERIFY, paths, used, total);
			hpn_verify_failed = 1;
		}
		sftp_parallel_stop(parallel_orch);
		parallel_orch = NULL;
	} else if (hpn_verify_transfer) {
		sftp_conn_verify_run_phase(conn);
		total = sftp_conn_drain_verify_failures(conn, &paths, &used);
		if (total > 0) {
			report_failed_paths("Verification FAILED",
			    HPNS_FF_VERIFY, paths, used, total);
			hpn_verify_failed = 1;
		}
	}
}

void
toremote(int argc, char **argv, enum scp_mode_e mode, char *sftp_direct)
{
	char *suser = NULL, *host = NULL, *src = NULL;
	char *bp, *tuser, *thost, *targ;
	int sport = -1, tport = -1;
	struct sftp_conn *conn = NULL, *conn2 = NULL;
	struct hpn_scp_remote remote;	/* HPN */
	int i, r, status;
	struct stat sb;

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
				/* HPN: -j, -V and -Z do not apply to a
				 * through-local (crossload) transfer, so
				 * refuse them rather than run without them.
				 * The direct -R transfer supports all
				 * three. */
				if (parallel_num_streams > 1)
					fatal("-j does not apply to a "
					    "through-local (crossload) "
					    "transfer; use -R for a direct "
					    "source-to-destination transfer");
				if (hpn_verify_transfer)
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

			/* HPN: the launch keeps the arguments off the source's
			 * shell; hpn-launch-args.c builds and runs it */
			memset(&remote, 0, sizeof(remote));
			remote.ssh_program = ssh_program;
			remote.ssh_args = &remote_remote_args;
			remote.host = host;
			remote.user = suser;
			remote.port = sport;
			remote.src = src;
			remote.target_user = tuser;
			remote.target_host = thost;
			remote.target_port = tport;
			remote.target_path = targ;
			remote.verbose = verbose_mode;
			remote.recursive = iamrecursive;
			remote.preserve = pflag;
			remote.target_is_dir = targetshouldbedirectory;
			remote.streams = parallel_num_streams;
			remote.family = family_flag;
			remote.compress = compress_flag;
			remote.zstd_level = zstd_level;
			remote.verify = hpn_verify_transfer;
			remote.resume = resume_flag;
			remote.show_meter = showprogress;
			remote.pidp = &do_cmd_pid;
			/* HPN: the runner sets and clears do_cmd_pid, and
			 * killchild reads it */
			ssh_signal(SIGTERM, killchild);
			ssh_signal(SIGINT, killchild);
			ssh_signal(SIGHUP, killchild);
			r = hpn_launch_args_scp_remote(&remote);
			/* HPN: a refused legacy source stops the whole copy */
			if (r == HPN_EXIT_STRICT_ARGS)
				exit(HPN_EXIT_STRICT_ARGS);
			if (r != 0)
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
					/* HPN: latch -V and the HPN options on
					 * the new connection and start the -j
					 * fleet. */
					scp_parallel_launch(conn, thost, tuser,
					    tport > 0 ? tport : sshport);
					/* HPN: start the -j meter once, sized
					 * to every source argument. The file
					 * total also feeds the status relay. */
					if (parallel_orch != NULL &&
					    parallel_want_progress) {
						off_t total_bytes = 0;
						uint64_t total_files = 0, fc;
						int k;

						for (k = 0; k < argc - 1; k++) {
							fc = 0;
							total_bytes +=
							    sftp_parallel_scan_upload_total(
							    parallel_orch, argv[k], &fc);
							total_files += fc;
						}
						sftp_parallel_progress_add(
						    parallel_orch, "Uploading",
						    total_bytes, (int)total_files);
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
	scp_parallel_finish(conn);	/* HPN */
out:
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
			/* HPN: latch -V and the HPN options on this source's
			 * connection and start its -j fleet. Each source may be
			 * on a different host, so each gets its own fleet,
			 * finished below. */
			scp_parallel_launch(conn, host, suser,
			    sport > 0 ? sport : sshport);
			/* The protocol */
			sink_sftp(1, argv[argc - 1], src, conn);

			scp_parallel_finish(conn);	/* HPN */

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
		/* HPN: with -j the fleet walks the tree and runs its verify
		 * phase in sftp_parallel_wait. The verify argument follows -Z,
		 * as at the download sites, so a resume hash-checks a partial
		 * file instead of trusting its size. -V travels in the fleet's
		 * config. */
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
		Attrib sa;

		/* HPN: HPNLustreStripeCount stripes the remote destination
		 * directory first */
		maybe_apply_lustre_layout_parent(parallel_orch, conn, abs_dst, 0);
		stat_to_attrib(&st, &sa);
		if (sftp_parallel_submit_upload(parallel_orch, conn, src,
		    abs_dst, &sa, resume_flag, resume_flag) != 0) {
			error("failed to upload file %s to %s", src, targ);
			errs = 1;
		}
	} else {
		int outcome;

		outcome = sftp_upload(conn, src, abs_dst, pflag, 0,
		    resume_flag, 0, 1);
		/* HPN: report first, since the line below would replace the
		 * reason. */
		if (sftp_hpn_report_transfer(conn, TRANSFERLOG_UPLOAD, outcome,
		    src, abs_dst, st.st_size) == -1)
			errs = 1;
		if (outcome == -1)
			error("failed to upload file %s to %s", src, targ);
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
	off_t i, statbytes;
	size_t amt, nr;
	int fd = -1, haderr, indx;
	char *last, *name, buf[PATH_MAX + 128], encname[PATH_MAX];
	int len;

	for (indx = 0; indx < argc; ++indx) {
		name = argv[indx];
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
		if (verbose_mode)
			fmprintf(stderr, "Sending file modes: %s", buf);
		(void) atomicio(vwrite, remout, buf, strlen(buf));
		if (response() < 0)
			goto next;
		if ((bp = allocbuf(&buffer, fd, COPY_BUFLEN)) == NULL) {
next:			if (fd != -1) {
				(void) close(fd);
				fd = -1;
			}
			continue;
		}
		if (showprogress)	/* HPN: the meter core */
			hpn_meter_start(hpn_meter_serial(), &statbytes,
			    HPN_METER_FILE, HPN_METER_DOM_TRANSFER,
			    curfile, stb.st_size, &statbytes, 1);
		set_nonblock(remout);
		for (haderr = i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + (off_t)amt > stb.st_size)
				amt = stb.st_size - i;
			if (!haderr) {
				if ((nr = atomicio(read, fd,
				    bp->buf, amt)) != amt) {
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
		if (showprogress)	/* HPN */
			hpn_meter_stop(hpn_meter_serial(), &statbytes);
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

	/* HPN: start the -j meter for this source, sized from the attributes
	 * sftp_glob cached */
	if (parallel_orch != NULL && parallel_want_progress) {
		off_t dtotal;
		int nfiles;

		dtotal = sftp_glob_files_total(&g, &nfiles);
		sftp_parallel_progress_add(parallel_orch, "Downloading",
		    dtotal, nfiles);
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
			/* HPN: with -j the fleet walks the remote tree and
			 * runs its verify phase in sftp_parallel_wait. The
			 * verify argument follows -Z, as in the single-stream
			 * calls below. -V travels in the fleet's config. */
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
			/* HPN: with -j, submit the file with its attributes.
			 * Its size drives the range-split choice. */
			Attrib ga;

			sftp_glob_match_attrib(conn, g.gl_pathv[i], &ga);
			/* HPN: HPNLustreStripeCount stripes the local
			 * destination directory first */
			maybe_apply_lustre_layout_parent(parallel_orch, conn,
			    abs_dst, 1);
			if (sftp_parallel_submit_download(parallel_orch, conn,
			    g.gl_pathv[i], abs_dst, &ga,
			    resume_flag, resume_flag) != 0)
				err = -1;
		} else {
			struct stat lsb;
			off_t sz = -1;
			int outcome;

			outcome = sftp_download(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag, resume_flag, 0, 1,
			    resume_flag /* verify */);
			/* HPN: report the outcome, which prints a skip notice
			 * and writes the TransferLog line. The line carries the
			 * local copy's size, -1 when nothing landed. */
			if (transferlog_active() && stat(abs_dst, &lsb) == 0)
				sz = lsb.st_size;
			if (sftp_hpn_report_transfer(conn,
			    TRANSFERLOG_DOWNLOAD, outcome, g.gl_pathv[i],
			    abs_dst, sz) == -1)
				err = -1;
		}
		/* HPN: a dead connection ends the command, with one line in
		 * the failure log. Every later match would fail the same
		 * way. */
		if (sftp_conn_is_dead(conn)) {
			if (!interrupted)
				transferlog_connection_lost(
				    TRANSFERLOG_DOWNLOAD, g.gl_pathv[i],
				    abs_dst);
			free(abs_dst);
			abs_dst = NULL;
			err = -1;
			break;
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
	off_t size, statbytes;
	unsigned long long ull;
	int setimes, targisdir, wrerr;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[16384], visbuf[16384];
	char **patterns = NULL;
	size_t n, npatterns = 0;
	struct timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

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

	(void) atomicio(vwrite, remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	if (src != NULL && !iamrecursive && !Tflag) {
		/*
		 * Prepare to try to restrict incoming filenames to match
		 * the requested destination file glob.
		 */
		if (brace_expand(src, &patterns, &npatterns) != 0)
			fatal_f("could not expand pattern");
	}
	for (first = 1;; first = 0) {
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
			(void) atomicio(vwrite, remout, "", 1);
			goto done;
		}
		if (ch == '\n')
			*--cp = 0;

		cp = buf;
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
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (!pflag)
			mode &= ~mask;
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

		if (!isdigit((unsigned char)*cp))
			SCREWUP("size not present");
		ull = strtoull(cp, &cp, 10);
		if (!cp || *cp++ != ' ')
			SCREWUP("size not delimited");
		if (TYPE_OVERFLOW(off_t, ull))
			SCREWUP("size out of range");
		size = (off_t)ull;

		if (*cp == '\0' || strchr(cp, '/') != NULL ||
		    strcmp(cp, ".") == 0 || strcmp(cp, "..") == 0) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
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
		if ((ofd = open(np, O_WRONLY|O_CREAT, mode)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
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
		if (showprogress)	/* HPN: the meter core */
			hpn_meter_start(hpn_meter_serial(), &statbytes,
			    HPN_METER_FILE, HPN_METER_DOM_TRANSFER,
			    curfile, size, &statbytes, 1);
		set_nonblock(remin);
		for (count = i = 0; i < size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > size)
				amt = size - i;
			count += amt;
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
		if (showprogress)	/* HPN */
			hpn_meter_stop(hpn_meter_serial(), &statbytes);
		if (setimes && !wrerr) {
			setimes = 0;
			if (utimes(np, tv) == -1) {
				note_err("%s: set times: %s",
				    np, strerror(errno));
			}
		}
		/* If no error was noted then signal success for this file */
		if (note_err(NULL) == 0)
			(void) atomicio(vwrite, remout, "", 1);
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
			    NULL, pflag) == -1) {
				/* HPN: an interrupt is not a failure to
				 * record */
				if (!interrupted)
					transferlog_failure(
					    TRANSFERLOG_CROSSLOAD,
					    g.gl_pathv[i], abs_dst,
					    hpn_get_last_error());
				err = -1;
			}
		}
		/* HPN: a dead connection at either end ends the command, with
		 * one line in the failure log. Every later match would fail
		 * the same way. */
		if (sftp_conn_is_dead(from) || sftp_conn_is_dead(to)) {
			if (!interrupted)
				transferlog_connection_lost(
				    TRANSFERLOG_CROSSLOAD, g.gl_pathv[i],
				    abs_dst);
			err = -1;
			break;
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
