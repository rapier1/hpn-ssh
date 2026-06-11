/* $OpenBSD: sftp.c,v 1.250 2026/02/11 17:01:34 dtucker Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <glob.h>
#include <paths.h>
#include <libgen.h>
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef USE_LIBEDIT
#include <histedit.h>
#else
typedef void EditLine;
#endif
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "xmalloc.h"
#include "log.h"
#include "pathnames.h"
#include "misc.h"
#include "utf8.h"

#include "sftp.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_set_verify_transfer */
#include "sftp-usergroup.h"
#include "sftp-parallel.h"

/* File to read commands from */
FILE* infile;

/* Parallel-streams orchestrator: NULL = single-stream (default) */
static struct sftp_parallel *parallel_orch = NULL;
static int parallel_num_streams = 1;
/* 1 if the user explicitly passed -j N; 0 otherwise.  When 0, hpnsftp
 * runs as a plain single-stream client (no orchestrator, no autotuning) so
 * default behaviour matches upstream sftp.  -j N opts into the parallel
 * worker pool, which stays fixed at N for the lifetime of the transfer. */
static int parallel_user_opt_in = 0;

/* User-facing range-split minimum size, in MiB.  0 = unset (orchestrator
 * uses RANGE_SPLIT_MIN_SIZE_DEFAULT).  Set by -M flag.  Bounded to
 * [64, 10240] MiB at parse time. */
static int range_split_min_mb_user = 0;

/* User-facing per-inode concurrent range-writer cap.  0 = unset (orchestrator
 * uses HPN_RANGE_WRITERS_CAP_DEFAULT).  Set by -w flag; bounded to
 * [HPN_RANGE_WRITERS_CAP_FLOOR, HPN_RANGE_WRITERS_CAP_MAX] at parse time. */
static int writers_cap_user = 0;

/* Directory for per-worker SSH stderr capture, set by -W flag.  NULL = off
 * (production default - worker stderr is inherited so connection errors
 * reach the user's terminal).  When set, each parallel worker writes its
 * SSH child's stderr to <dir>/hpnssh-worker-<pid>.stderr.  Validated to be
 * an existing writable directory at parse time. */
static const char *worker_log_dir = NULL;

/*
 * When non-zero, process_put / process_get do NOT call sftp_parallel_wait
 * after submitting their files.  Submissions pile up in the queue and the
 * caller is responsible for calling parallel_flush() at the appropriate time
 * (typically end-of-batch).  Enabled automatically in batch mode so that
 *     put file1
 *     put file2
 *     put file3
 * pipelines all three files instead of serialising on each command's wait.
 *
 * Interactive mode leaves this at 0 by default - users expect their prompt
 * to come back when an upload completes.  A future "job submission mode" in
 * the interactive shell can flip this on per-session via the same hook.
 */
static int defer_parallel_wait = 0;

/*
 * Sticky session-wide failure flag.  parallel_flush sets this to 1
 * whenever it detects undelivered files (units_failed_aggregate or
 * walker_failures_aggregate > 0).  Consulted by interactive_loop's
 * final return so the process exits non-zero whenever ANY transfer
 * during the session lost data - even if a later command succeeded
 * and reset the local err counter.
 *
 * Why this exists: in interactive (non-batch) mode,
 * parse_dispatch_command intentionally returns 0 for failed individual
 * commands so the session continues to the next prompt.  That
 * swallows the per-command failure signal.  Batch mode propagates it
 * directly (err_abort = 1).  This flag is the bridge so the user
 * always gets a non-zero exit when data was lost, regardless of mode.
 */
static int session_had_failure = 0;

/* Are we in batchfile mode? */
int batchmode = 0;

/* PID of ssh transport process */
static volatile pid_t sshpid = -1;

/* Suppress diagnostic messages */
int quiet = 0;

/* This is set to 0 if the progressmeter is not desired. */
int showprogress = 1;

/* When this option is set, we always recursively download/upload directories */
int global_rflag = 0;

/* When this option is set, we resume download or upload if possible */
int global_aflag = 0;

/* When this option is set, the file transfers will always preserve times */
int global_pflag = 0;

/* When this option is set, transfers will have fsync() called on each file */
int global_fflag = 0;

/*
 * HPNVerifyTransfer: when enabled (ssh_config HPNVerifyTransfer yes,
 * resolved at startup), every successfully transferred single-stream file
 * is XXH3-verified end-to-end after transfer.  A mismatch does NOT abort -
 * it is logged loudly and recorded; at exit a summary is printed and the
 * process returns SFTP_EX_VERIFY_FAILED (57).
 */
static int hpn_verify_transfer = 0;
static char **verify_fail_list = NULL;
static u_int verify_fail_count = 0;

/* SIGINT received during command processing */
volatile sig_atomic_t interrupted = 0;

/* I wish qsort() took a separate ctx for the comparison function...*/
int sort_flag;
glob_t *sort_glob;

/* Context used for commandline completion */
struct complete_ctx {
	struct sftp_conn *conn;
	char **remote_pathp;
};

int sftp_glob(struct sftp_conn *, const char *, int,
    int (*)(const char *, int), glob_t *); /* proto for sftp-glob.c */
int sftp_glob_get_attrib(const char *, Attrib *);  /* proto for sftp-glob.c */

extern char *__progname;

/* Separators for interactive commands */
#define WHITESPACE " \t\r\n"

/* ls flags */
#define LS_LONG_VIEW	0x0001	/* Full view ala ls -l */
#define LS_SHORT_VIEW	0x0002	/* Single row view ala ls -1 */
#define LS_NUMERIC_VIEW	0x0004	/* Long view with numeric uid/gid */
#define LS_NAME_SORT	0x0008	/* Sort by name (default) */
#define LS_TIME_SORT	0x0010	/* Sort by mtime */
#define LS_SIZE_SORT	0x0020	/* Sort by file size */
#define LS_REVERSE_SORT	0x0040	/* Reverse sort order */
#define LS_SHOW_ALL	0x0080	/* Don't skip filenames starting with '.' */
#define LS_SI_UNITS	0x0100	/* Display sizes as K, M, G, etc. */

#define VIEW_FLAGS	(LS_LONG_VIEW|LS_SHORT_VIEW|LS_NUMERIC_VIEW|LS_SI_UNITS)
#define SORT_FLAGS	(LS_NAME_SORT|LS_TIME_SORT|LS_SIZE_SORT)

/* Commands for interactive mode */
enum sftp_command {
	I_CHDIR = 1,
	I_CHGRP,
	I_CHMOD,
	I_CHOWN,
	I_COPY,
	I_DEFER,
	I_DF,
	I_GET,
	I_HELP,
	I_LCHDIR,
	I_LINK,
	I_LLS,
	I_LMKDIR,
	I_LPWD,
	I_LS,
	I_LUMASK,
	I_MKDIR,
	I_PUT,
	I_PWD,
	I_QUIT,
	I_REGET,
	I_VREGET,
	I_RENAME,
	I_REPUT,
	I_VREPUT,
	I_RM,
	I_RMDIR,
	I_SHELL,
	I_SYMLINK,
	I_VERSION,
	I_PROGRESS,
	I_WAIT,
};

struct CMD {
	const char *c;
	const int n;
	const int t;	/* Completion type for the first argument */
	const int t2;	/* completion type for the optional second argument */
};

/* Type of completion */
#define NOARGS	0
#define REMOTE	1
#define LOCAL	2

static const struct CMD cmds[] = {
	{ "bye",	I_QUIT,		NOARGS,		NOARGS	},
	{ "cd",		I_CHDIR,	REMOTE,		NOARGS	},
	{ "chdir",	I_CHDIR,	REMOTE,		NOARGS	},
	{ "chgrp",	I_CHGRP,	REMOTE,		NOARGS	},
	{ "chmod",	I_CHMOD,	REMOTE,		NOARGS	},
	{ "chown",	I_CHOWN,	REMOTE,		NOARGS	},
	{ "copy",	I_COPY,		REMOTE,		LOCAL	},
	{ "cp",		I_COPY,		REMOTE,		LOCAL	},
	{ "defer",	I_DEFER,	NOARGS,		NOARGS	},
	{ "df",		I_DF,		REMOTE,		NOARGS	},
	{ "dir",	I_LS,		REMOTE,		NOARGS	},
	{ "exit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "get",	I_GET,		REMOTE,		LOCAL	},
	{ "help",	I_HELP,		NOARGS,		NOARGS	},
	{ "lcd",	I_LCHDIR,	LOCAL,		NOARGS	},
	{ "lchdir",	I_LCHDIR,	LOCAL,		NOARGS	},
	{ "lls",	I_LLS,		LOCAL,		NOARGS	},
	{ "lmkdir",	I_LMKDIR,	LOCAL,		NOARGS	},
	{ "ln",		I_LINK,		REMOTE,		REMOTE	},
	{ "lpwd",	I_LPWD,		LOCAL,		NOARGS	},
	{ "ls",		I_LS,		REMOTE,		NOARGS	},
	{ "lumask",	I_LUMASK,	NOARGS,		NOARGS	},
	{ "mkdir",	I_MKDIR,	REMOTE,		NOARGS	},
	{ "mget",	I_GET,		REMOTE,		LOCAL	},
	{ "mput",	I_PUT,		LOCAL,		REMOTE	},
	{ "progress",	I_PROGRESS,	NOARGS,		NOARGS	},
	{ "put",	I_PUT,		LOCAL,		REMOTE	},
	{ "pwd",	I_PWD,		REMOTE,		NOARGS	},
	{ "quit",	I_QUIT,		NOARGS,		NOARGS	},
	{ "reget",	I_REGET,	REMOTE,		LOCAL	},
	{ "regetv",	I_VREGET,	REMOTE,		LOCAL	},
	{ "rename",	I_RENAME,	REMOTE,		REMOTE	},
	{ "reput",	I_REPUT,	LOCAL,		REMOTE	},
	{ "reputv",	I_VREPUT,	LOCAL,		REMOTE	},
	{ "rm",		I_RM,		REMOTE,		NOARGS	},
	{ "rmdir",	I_RMDIR,	REMOTE,		NOARGS	},
	{ "symlink",	I_SYMLINK,	REMOTE,		REMOTE	},
	{ "version",	I_VERSION,	NOARGS,		NOARGS	},
	{ "wait",	I_WAIT,		NOARGS,		NOARGS	},
	{ "!",		I_SHELL,	NOARGS,		NOARGS	},
	{ "?",		I_HELP,		NOARGS,		NOARGS	},
	{ NULL,		-1,		-1,		-1	}
};

static void
killchild(int signo)
{
	pid_t pid;

	pid = sshpid;
	if (pid > 1) {
		kill(pid, SIGTERM);
		(void)waitpid(pid, NULL, 0);
	}

	_exit(1);
}

static void
suspchild(int signo)
{
	int save_errno = errno;
	if (sshpid > 1) {
		kill(sshpid, signo);
		while (waitpid(sshpid, NULL, WUNTRACED) == -1 && errno == EINTR)
			continue;
	}
	kill(getpid(), SIGSTOP);
	errno = save_errno;
}

static void
cmd_interrupt(int signo)
{
	const char msg[] = "\rInterrupt  \n";
	int olderrno = errno;

	(void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
	interrupted = 1;
	errno = olderrno;
}

static void
read_interrupt(int signo)
{
	interrupted = 1;
}

static void
sigchld_handler(int sig)
{
	int save_errno = errno;
	pid_t pid;
	const char msg[] = "\rConnection closed.  \n";

	/* Report if ssh transport process dies. */
	while ((pid = waitpid(sshpid, NULL, WNOHANG)) == -1 && errno == EINTR)
		continue;
	if (pid == sshpid) {
		if (!quiet)
		    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
		sshpid = -1;
	}

	errno = save_errno;
}

static void
help(void)
{
	printf("Available commands:\n"
	    "bye                                Quit sftp\n"
	    "cd path                            Change remote directory to 'path'\n"
	    "chgrp [-h] grp path                Change group of file 'path' to 'grp'\n"
	    "chmod [-h] mode path               Change permissions of file 'path' to 'mode'\n"
	    "chown [-h] own path                Change owner of file 'path' to 'own'\n"
	    "copy oldpath newpath               Copy remote file\n"
	    "cp oldpath newpath                 Copy remote file\n"
	    "defer [on|off]                     Toggle deferred put/get (parallel mode);\n"
	    "                                   no arg prints current state\n"
	    "df [-hi] [path]                    Display statistics for current directory or\n"
	    "                                   filesystem containing 'path'\n"
	    "exit                               Quit sftp\n"
	    "get [-afpRv] remote [local]        Download file (-v: verified resume)\n"
	    "help                               Display this help text\n"
	    "lcd path                           Change local directory to 'path'\n"
	    "lls [ls-options [path]]            Display local directory listing\n"
	    "lmkdir path                        Create local directory\n"
	    "ln [-s] oldpath newpath            Link remote file (-s for symlink)\n"
	    "lpwd                               Print local working directory\n"
	    "ls [-1afhlnrSt] [path]             Display remote directory listing\n"
	    "lumask umask                       Set local umask to 'umask'\n"
	    "mkdir path                         Create remote directory\n"
	    "progress                           Toggle display of progress meter\n"
	    "put [-afpRv] local [remote]        Upload file (-v: verified resume)\n"
	    "pwd                                Display remote working directory\n"
	    "quit                               Quit sftp\n"
	    "reget [-fpR] remote [local]        Resume download file\n"
	    "regetv [-fpR] remote [local]       Resume download with hash verification\n"
	    "rename oldpath newpath             Rename remote file\n"
	    "reput [-fpR] local [remote]        Resume upload file\n"
	    "reputv [-fpR] local [remote]       Resume upload with hash verification\n"
	    "rm path                            Delete remote file\n"
	    "rmdir path                         Remove remote directory\n"
	    "symlink oldpath newpath            Symlink remote file\n"
	    "version                            Show SFTP version\n"
	    "wait                               Block until all deferred put/get are done\n"
	    "!command                           Execute 'command' in local shell\n"
	    "!                                  Escape to local shell\n"
	    "?                                  Synonym for help\n");
}

static void
local_do_shell(const char *args)
{
	int status;
	char *shell;
	pid_t pid;

	if (!*args)
		args = NULL;

	if ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	if ((pid = fork()) == -1)
		fatal("Couldn't fork: %s", strerror(errno));

	if (pid == 0) {
		/* XXX: child has pipe fds to ssh subproc open - issue? */
		if (args) {
			debug3("Executing %s -c \"%s\"", shell, args);
			execl(shell, shell, "-c", args, (char *)NULL);
		} else {
			debug3("Executing %s", shell);
			execl(shell, shell, (char *)NULL);
		}
		fprintf(stderr, "Couldn't execute \"%s\": %s\n", shell,
		    strerror(errno));
		_exit(1);
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal("Couldn't wait for child: %s", strerror(errno));
	if (!WIFEXITED(status))
		error("Shell exited abnormally");
	else if (WEXITSTATUS(status))
		error("Shell exited with status %d", WEXITSTATUS(status));
}

static void
local_do_ls(const char *args)
{
	if (!args || !*args)
		local_do_shell(_PATH_LS);
	else {
		int len = strlen(_PATH_LS " ") + strlen(args) + 1;
		char *buf = xmalloc(len);

		/* XXX: quoting - rip quoting code from ftp? */
		snprintf(buf, len, _PATH_LS " %s", args);
		local_do_shell(buf);
		free(buf);
	}
}

/* Strip one path (usually the pwd) from the start of another */
static char *
path_strip(const char *path, const char *strip)
{
	size_t len;

	if (strip == NULL)
		return (xstrdup(path));

	len = strlen(strip);
	if (strncmp(path, strip, len) == 0) {
		if (strip[len - 1] != '/' && path[len] == '/')
			len++;
		return (xstrdup(path + len));
	}

	return (xstrdup(path));
}

static int
parse_getput_flags(const char *cmd, char **argv, int argc,
    int *aflag, int *fflag, int *pflag, int *rflag, int *vflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*aflag = *fflag = *rflag = *pflag = *vflag = 0;
	while ((ch = getopt(argc, argv, "afPpRrv")) != -1) {
		switch (ch) {
		case 'a':
			*aflag = 1;
			break;
		case 'f':
			*fflag = 1;
			break;
		case 'p':
		case 'P':
			*pflag = 1;
			break;
		case 'r':
		case 'R':
			*rflag = 1;
			break;
		case 'v':
			*vflag = 1;
			*aflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_link_flags(const char *cmd, char **argv, int argc, int *sflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*sflag = 0;
	while ((ch = getopt(argc, argv, "s")) != -1) {
		switch (ch) {
		case 's':
			*sflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_rename_flags(const char *cmd, char **argv, int argc, int *lflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = 0;
	while ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		case 'l':
			*lflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_ls_flags(char **argv, int argc, int *lflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*lflag = LS_NAME_SORT;
	while ((ch = getopt(argc, argv, "1Safhlnrt")) != -1) {
		switch (ch) {
		case '1':
			*lflag &= ~VIEW_FLAGS;
			*lflag |= LS_SHORT_VIEW;
			break;
		case 'S':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_SIZE_SORT;
			break;
		case 'a':
			*lflag |= LS_SHOW_ALL;
			break;
		case 'f':
			*lflag &= ~SORT_FLAGS;
			break;
		case 'h':
			*lflag |= LS_SI_UNITS;
			break;
		case 'l':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_LONG_VIEW;
			break;
		case 'n':
			*lflag &= ~LS_SHORT_VIEW;
			*lflag |= LS_NUMERIC_VIEW|LS_LONG_VIEW;
			break;
		case 'r':
			*lflag |= LS_REVERSE_SORT;
			break;
		case 't':
			*lflag &= ~SORT_FLAGS;
			*lflag |= LS_TIME_SORT;
			break;
		default:
			error("ls: Invalid flag -%c", optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_df_flags(const char *cmd, char **argv, int argc, int *hflag, int *iflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = *iflag = 0;
	while ((ch = getopt(argc, argv, "hi")) != -1) {
		switch (ch) {
		case 'h':
			*hflag = 1;
			break;
		case 'i':
			*iflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_ch_flags(const char *cmd, char **argv, int argc, int *hflag)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	*hflag = 0;
	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			*hflag = 1;
			break;
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static int
parse_no_flags(const char *cmd, char **argv, int argc)
{
	extern int opterr, optind, optopt, optreset;
	int ch;

	optind = optreset = 1;
	opterr = 0;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			error("%s: Invalid flag -%c", cmd, optopt);
			return -1;
		}
	}

	return optind;
}

static char *
escape_glob(const char *s)
{
	size_t i, o, len;
	char *ret;

	len = strlen(s);
	ret = xcalloc(2, len + 1);
	for (i = o = 0; i < len; i++) {
		if (strchr("[]?*\\", s[i]) != NULL)
			ret[o++] = '\\';
		ret[o++] = s[i];
	}
	ret[o++] = '\0';
	return ret;
}

/*
 * Arg p must be dynamically allocated.  make_absolute will either return it
 * or free it and allocate a new one.  Caller must free returned string.
 */
static char *
make_absolute_pwd_glob(char *p, const char *pwd)
{
	char *ret, *escpwd;

	escpwd = escape_glob(pwd);
	if (p == NULL)
		return escpwd;
	ret = sftp_make_absolute(p, escpwd);
	free(escpwd);
	return ret;
}

static int
local_is_dir(const char *path)
{
	struct stat sb;

	if (stat(path, &sb) == -1)
		return 0;
	return S_ISDIR(sb.st_mode);
}

/*
 * Drain all submissions sitting in the parallel orchestrator's queue.
 *
 * Centralises the wait + progress_stop + protocol-violation summary that
 * process_get / process_put used to do at the end of each command.  Called
 * directly by those functions in interactive mode, or once at end-of-batch
 * by the caller (interactive_loop) when defer_parallel_wait is set.
 *
 * Safe to call when parallel_orch is NULL (no-op) or when no submissions are
 * outstanding (sftp_parallel_wait returns immediately).
 */
/*
 * Drains the parallel orchestrator and returns 0 if every submitted
 * unit completed successfully, -1 if any unit was permanently lost
 * (units_failed_aggregate > 0).  Callers MUST propagate -1 up to the
 * sftp exit code: silent data loss is unacceptable.  When parallel_orch
 * is NULL (parallel mode off) the function is a no-op returning 0.
 */
static int
parallel_flush(void)
{
	struct sftp_parallel_stats pstats;
	int rc = 0;

	if (parallel_orch == NULL)
		return 0;

	sftp_parallel_wait(parallel_orch);
	sftp_parallel_progress_stop(parallel_orch);
	sftp_parallel_get_stats(parallel_orch, &pstats);

	/* End-of-transfer summary.  Leads with bytes/throughput so the
	 * operator gets a one-line health check; appends the respawn
	 * count when non-zero (so a clean transfer stays terse), and a
	 * tuning hint when respawn churn crosses ~25 % of -j - the same
	 * threshold the outlier detector uses, and the empirically
	 * observed knee-of-the-curve for too many parallel streams on a
	 * saturated path.  Emitted BEFORE any TRANSFER INCOMPLETE block
	 * so the signal isn't buried under a long failed-paths list. */
	if (pstats.elapsed_ms > 0 && pstats.bytes_total_aggregate > 0) {
		double secs   = pstats.elapsed_ms / 1000.0;
		double wired  = (double)pstats.bytes_wired_aggregate;
		/*
		 * Primary number is bytes actually transferred (wired) and
		 * throughput is computed against it - operators care about
		 * what moved over the network, not what was visited.  When
		 * chunked-resume or prefix-resume avoided pushing bytes that
		 * were already correct on the peer, we tack on a "Y skipped
		 * via resume" beat so the savings are visible.  No beat is
		 * emitted for fresh transfers where nothing was skippable.
		 */
		uint64_t skipped_b =
		    pstats.bytes_total_aggregate > pstats.bytes_wired_aggregate
		    ? pstats.bytes_total_aggregate - pstats.bytes_wired_aggregate
		    : 0;
		const char *wired_unit;
		double wired_val;
		if (wired >= 1024.0 * 1024.0 * 1024.0) {
			wired_val  = wired / (1024.0 * 1024.0 * 1024.0);
			wired_unit = "GiB";
		} else {
			wired_val  = wired / (1024.0 * 1024.0);
			wired_unit = "MiB";
		}
		char skipped_str[64];
		skipped_str[0] = '\0';
		if (skipped_b > 0) {
			double skipped_d = (double)skipped_b;
			const char *skipped_unit;
			double skipped_val;
			if (skipped_d >= 1024.0 * 1024.0 * 1024.0) {
				skipped_val  = skipped_d /
				    (1024.0 * 1024.0 * 1024.0);
				skipped_unit = "GiB";
			} else {
				skipped_val  = skipped_d / (1024.0 * 1024.0);
				skipped_unit = "MiB";
			}
			snprintf(skipped_str, sizeof(skipped_str),
			    "; %.2f %s skipped via resume",
			    skipped_val, skipped_unit);
		}
		int j         = pstats.num_workers > 0
		    ? pstats.num_workers : parallel_num_streams;
		int respawn_hint_threshold = (j + 3) / 4; /* ceil(j / 4) */
		const char *churn_hint =
		    (pstats.total_respawns >= respawn_hint_threshold &&
		     respawn_hint_threshold > 0)
		    ? " - consider lowering -j" : "";
		/* No rate figure: elapsed runs from orchestrator start, so
		 * in an interactive session it includes idle time between
		 * commands and the average reads artificially low.  Health
		 * breakdown (wedge/peer-stall) folds in here; only nonzero
		 * parts are shown.  The old separate "parallel transfer
		 * health" line said the respawn count twice. */
		char brk[64] = "";
		if (pstats.wedge_terminations > 0 &&
		    pstats.peer_stall_terminations > 0)
			snprintf(brk, sizeof(brk), " (%d wedge, %d peer-stall)",
			    pstats.wedge_terminations,
			    pstats.peer_stall_terminations);
		else if (pstats.wedge_terminations > 0)
			snprintf(brk, sizeof(brk), " (%d wedge)",
			    pstats.wedge_terminations);
		else if (pstats.peer_stall_terminations > 0)
			snprintf(brk, sizeof(brk), " (%d peer-stall)",
			    pstats.peer_stall_terminations);
		if (pstats.total_respawns > 0) {
			logit("Parallel streams: %.2f %s transferred in %.1fs"
			    "%s; %d worker respawn%s%s%s",
			    wired_val, wired_unit, secs,
			    skipped_str,
			    pstats.total_respawns,
			    pstats.total_respawns == 1 ? "" : "s",
			    brk, churn_hint);
		} else {
			logit("Parallel streams: %.2f %s transferred in %.1fs"
			    "%s",
			    wired_val, wired_unit, secs, skipped_str);
		}
	}

	if (pstats.total_respawns > 0 || pstats.wedge_terminations > 0 ||
	    pstats.peer_stall_terminations > 0) {
		debug("parallel transfer health: %d worker respawn(s) "
		    "(%d wedge, %d peer-stall)",
		    pstats.total_respawns, pstats.wedge_terminations,
		    pstats.peer_stall_terminations);
	}
	if (pstats.protocol_violations > 0) {
		logit("warning: %d worker protocol violation detected "
		    "(recovered via worker respawn) - investigate if "
		    "this recurs across transfers",
		    pstats.protocol_violations);
	}
	/* A USER interrupt is not an error: the casualties below are
	 * consequences of the Ctrl-C, so they get one calm summary line
	 * (what is incomplete + how to resume) instead of error theater,
	 * and the path inventory drops to debug.  Genuine failures keep
	 * the loud framing. */
	int user_int = sftp_parallel_user_abort(parallel_orch);

	if (user_int) {
		/* Mid-transfer interrupts usually record NO failures - the
		 * in-flight/queued work is simply abandoned (units_pending) -
		 * so key the summary on both. */
		uint64_t n = pstats.units_failed_aggregate +
		    pstats.walker_failures_aggregate;
		if (n > 0) {
			logit("Transfer interrupted: %llu file(s) incomplete; "
			    "partials left in place (resume with "
			    "reputv / regetv).", (unsigned long long)n);
			rc = -1;
		} else if (pstats.units_pending > 0) {
			logit("Transfer interrupted; partial file(s) left in "
			    "place (resume with reputv / regetv).");
			rc = -1;
		}
	} else {
		if (pstats.units_failed_aggregate > 0) {
			error("TRANSFER INCOMPLETE: %llu file(s) could not be "
			    "delivered after retries",
			    (unsigned long long)pstats.units_failed_aggregate);
			rc = -1;
		}
		if (pstats.walker_failures_aggregate > 0) {
			error("TRANSFER INCOMPLETE: %llu file(s) or director(y/ies) "
			    "were skipped during the directory walk "
			    "(stat/readdir/symlink errors)",
			    (unsigned long long)pstats.walker_failures_aggregate);
			rc = -1;
		}
	}

	/* Drain the failed-paths list and print it.  This is the
	 * user-facing inventory of what didn't make it - separate from
	 * the per-aggregate counts above because a path can show up via
	 * the worker-failure or walker-failure code path.  Always drained
	 * (it owns the memory); printed at debug after a user interrupt. */
	{
		char  **paths     = NULL;
		size_t  paths_used = 0;
		uint64_t total = sftp_parallel_drain_failed_paths(
		    parallel_orch, &paths, &paths_used);
		if (total > 0) {
			if (user_int) {
				debug("  Incomplete paths (%llu total):",
				    (unsigned long long)total);
			} else if (paths_used >= total) {
				error("  Failed paths (%llu total):",
				    (unsigned long long)total);
			} else {
				error("  Failed paths (showing first %zu; "
				    "list exceeds current limit of %zu files):",
				    paths_used, paths_used);
			}
			for (size_t i = 0; i < paths_used; i++) {
				if (user_int)
					debug("    %s", paths[i]);
				else
					error("    %s", paths[i]);
				free(paths[i]);
			}
			free(paths);
		}
	}

	if (rc != 0)
		session_had_failure = 1;
	return rc;
}

/*
 * HPNVerifyTransfer: verify one just-transferred file end-to-end and record
 * a mismatch for the end-of-run summary.  Never fails the transfer.
 */
static void
verify_one(struct sftp_conn *conn, const char *local_path,
    const char *remote_path)
{
	int r = sftp_hpn_verify_transfer(conn, local_path, remote_path);

	if (r == 0) {
		debug("verify: \"%s\" OK", remote_path);
		return;
	}
	if (r < 0) {
		logit("VERIFY SKIPPED: \"%s\": could not verify (server "
		    "lacks hpn-check-file@hpnssh.org or read error)",
		    remote_path);
		return;
	}
	/* r == 1: content mismatch - loud, recorded, but don't abort. */
	error("VERIFY FAILED: \"%s\" (post-transfer hash mismatch - the "
	    "transferred file does NOT match the source)", remote_path);
	verify_fail_list = xreallocarray(verify_fail_list,
	    verify_fail_count + 1, sizeof(*verify_fail_list));
	verify_fail_list[verify_fail_count++] = xstrdup(remote_path);
}

/*
 * Print the verify-failure summary at exit.  Returns the number of files
 * that failed verification (0 = all clean / verify off).
 */
static u_int
verify_print_summary(void)
{
	u_int i;

	if (verify_fail_count == 0)
		return 0;
	mprintf("\nHPNVerifyTransfer: %u file(s) FAILED post-transfer "
	    "verification:\n", verify_fail_count);
	for (i = 0; i < verify_fail_count; i++)
		mprintf("    %s\n", verify_fail_list[i]);
	return verify_fail_count;
}

/*
 * Captured launch inputs for the parallel orchestrator, so the fleet can be
 * re-created after an interrupt tears it down (parallel_orch_ensure_alive).
 * Filled once in main() before the first launch; the pointers reference
 * main()'s storage, which lives for the whole session.
 */
static struct {
	char        *host;
	char        *user;
	int          port;
	char        *ssh_program;
	const char  *identity;
	const char  *config_file;
	char       **extra_o;
	size_t       buflen;
	size_t       num_requests;
	long long    limit_kbps;
	int          debug_level;
	int          valid;
} parallel_launch;

/*
 * Build and start the parallel orchestrator from the captured launch
 * parameters.  Factored out of main() so the post-interrupt rebuild can call
 * it again; behaviour is identical to the original inline block.  On failure
 * leaves parallel_orch NULL and falls back to single-stream mode.
 */
static void
parallel_orch_launch(struct sftp_conn *conn)
{
	struct sftp_parallel_config pcfg;
	char portbuf[16] = "";

	if (!parallel_launch.valid)
		return;
	memset(&pcfg, 0, sizeof(pcfg));
	pcfg.num_streams      = parallel_num_streams;
	pcfg.host             = parallel_launch.host;
	pcfg.user             = parallel_launch.user;
	if (parallel_launch.port > 0) {
		snprintf(portbuf, sizeof(portbuf), "%d", parallel_launch.port);
		pcfg.port = portbuf;
	}
	pcfg.ssh_binary       = parallel_launch.ssh_program;
	pcfg.identity         = parallel_launch.identity;
	pcfg.config_file      = parallel_launch.config_file;
	pcfg.extra_argv       = parallel_launch.extra_o;
	pcfg.transfer_buflen  = (unsigned int)parallel_launch.buflen;
	pcfg.num_requests     = (unsigned int)parallel_launch.num_requests;
	pcfg.limit_kbps       = parallel_launch.limit_kbps;
	pcfg.range_split_min_mb = range_split_min_mb_user;
	pcfg.writers_per_inode_cap = writers_cap_user ?
	    writers_cap_user : HPN_RANGE_WRITERS_CAP_DEFAULT;
	pcfg.worker_log_dir     = worker_log_dir;
	pcfg.verbose_level      = parallel_launch.debug_level;
	/* Resolve HPNUseBundle and any other ssh_config-derived
	 * pcfg fields.  Sets pcfg.use_bundle; defaults to 1 (yes)
	 * if parsing fails or the option isn't set. */
	(void)sftp_parallel_apply_ssh_config(&pcfg, parallel_launch.host,
	    parallel_launch.config_file, parallel_launch.extra_o);
	pcfg.preserve_flag    = global_pflag;
	pcfg.fsync_flag       = global_fflag;
	pcfg.print_flag       = quiet ? 0 : 1;

	/*
	 * Adaptive throughput-outlier stall detection.  On by default
	 * in parallel mode with conservative settings suited to WAN
	 * bulk transfer.  Override or disable via env vars:
	 *
	 *   SFTP_TPUT_HEALTHY_KBPS=N  override minimum path rate (kbps)
	 *                             that must be seen before outlier
	 *                             classification fires; set to 0 to
	 *                             disable the feature entirely
	 *   SFTP_TPUT_FRACTION=F      worker is outlier if its kbps
	 *                             is less than F * max_kbps
	 *                             (default 0.25)
	 *   SFTP_TPUT_CONSEC=N        consecutive outlier ticks before
	 *                             STALLED (default 5); DEAD at 2N
	 *   SFTP_TPUT_EMA_ALPHA=F     EMA smoothing factor (default 0.2)
	 */
	{
		/* ENV-VAR SFTP_TPUT_HEALTHY_KBPS - developer-only:
		 * adaptive stall detector path-health floor (kbps).
		 * Tuning knob for the throughput-outlier detector; not
		 * meaningful to end users. */
		const char *e_h = getenv("SFTP_TPUT_HEALTHY_KBPS");
		/* ENV-VAR SFTP_TPUT_FRACTION - developer-only:
		 * adaptive stall detector outlier fraction (0-1). */
		const char *e_f = getenv("SFTP_TPUT_FRACTION");
		/* ENV-VAR SFTP_TPUT_CONSEC - developer-only:
		 * adaptive stall detector consecutive-tick count. */
		const char *e_c = getenv("SFTP_TPUT_CONSEC");
		/* ENV-VAR SFTP_TPUT_EMA_ALPHA - developer-only:
		 * adaptive stall detector EMA smoothing factor. */
		const char *e_a = getenv("SFTP_TPUT_EMA_ALPHA");
		pcfg.tput_path_healthy_kbps =
		    (e_h && *e_h) ? strtoull(e_h, NULL, 10) : 2000;
		pcfg.tput_outlier_fraction =
		    (e_f && *e_f) ? strtod(e_f, NULL) : 0.25;
		pcfg.tput_consec_required =
		    (e_c && *e_c) ? atoi(e_c) : 5;
		pcfg.tput_ema_alpha =
		    (e_a && *e_a) ? strtod(e_a, NULL) : 0.0;
	}

	if (!quiet)
		logit("Parallel streams: -j %d",
		    parallel_num_streams);
	/* Mirror to debug for batch-mode runs (quiet=1). */
	debug_f("parallel mode: -j %d defer_parallel_wait=%d",
	    parallel_num_streams, defer_parallel_wait);
	if (pcfg.tput_path_healthy_kbps > 0) {
		double eff_alpha = pcfg.tput_ema_alpha > 0.0
		    ? pcfg.tput_ema_alpha : 0.2;
		debug_f("tput-outlier detection: healthy_kbps=%llu "
		    "frac=%.2f consec=%d ema_alpha=%.2f",
		    (unsigned long long)pcfg.tput_path_healthy_kbps,
		    pcfg.tput_outlier_fraction,
		    pcfg.tput_consec_required,
		    eff_alpha);
	}
	parallel_orch = sftp_parallel_start(&pcfg);
	if (parallel_orch == NULL) {
		logit("Parallel-streams setup failed; "
		    "falling back to single-stream mode.");
		parallel_num_streams = 1;
	} else {
		sftp_parallel_set_interrupt_flag(parallel_orch,
		    &interrupted);

		/*
		 * Sample app-layer path RTT on the control connection.
		 * sftp_realpath does one SSH2_FXP_REALPATH round trip,
		 * which is the cheapest small request available after
		 * do_init has run.  Median of a few samples filters
		 * jitter from a single noisy round-trip without paying
		 * many extra RTTs at startup.  Passed to the orchestrator
		 * so the reporter can size its outlier-warmup correctly
		 * (see RAMP_RTTS in sftp-parallel.c).
		 */
		{
			uint64_t samples[3] = {0, 0, 0};
			int got = 0;
			for (int i = 0; i < 3; i++) {
				double t0 = monotime_double();
				char *r = sftp_realpath(conn, ".");
				double t1 = monotime_double();
				if (r == NULL)
					break;
				free(r);
				samples[got++] = (uint64_t)
				    ((t1 - t0) * 1e6);
			}
			if (got > 0) {
				/* Simple insertion sort + median. */
				for (int i = 1; i < got; i++) {
					uint64_t v = samples[i];
					int j = i - 1;
					while (j >= 0 &&
					    samples[j] > v) {
						samples[j+1] =
						    samples[j];
						j--;
					}
					samples[j+1] = v;
				}
				uint64_t rtt_us = samples[got / 2];
				sftp_parallel_set_path_rtt(
				    parallel_orch, rtt_us);
				debug_f("control-path RTT: "
				    "%llu us (median of %d samples)",
				    (unsigned long long)rtt_us, got);
			}
		}
	}
}

/*
 * Post-interrupt fleet rebuild.  A SIGINT during a parallel transfer makes
 * the orchestrator abort: abort_flag latches, the work queue shuts down, and
 * every worker connection is closed.  That state is terminal by design
 * ("abort means abort"), but it used to leak into the NEXT command: submit()
 * refuses units while abort_flag is set, so a subsequent put/get failed
 * instantly ("submit range N failed") and the file was reported INCOMPLETE
 * despite never starting.  Tear the dead orchestrator down and launch a
 * fresh fleet instead - a few seconds of reconnects, fresh TCP state,
 * correct by construction.  No-op when the orchestrator is healthy or
 * parallel mode is off.
 */
static void
parallel_orch_ensure_alive(struct sftp_conn *conn)
{
	if (parallel_orch == NULL || !sftp_parallel_is_aborting(parallel_orch))
		return;
	logit("Parallel workers were shut down by an interrupt; "
	    "rebuilding the worker fleet.");
	sftp_parallel_stop(parallel_orch);
	parallel_orch = NULL;
	parallel_orch_launch(conn);
	if (parallel_orch == NULL)
		logit("Worker fleet rebuild failed; this transfer will run "
		    "single-stream.");
}

static int
process_get(struct sftp_conn *conn, const char *src, const char *dst,
    const char *pwd, int pflag, int rflag, int resume, int fflag, int verify)
{
	char *filename, *abs_src = NULL, *abs_dst = NULL, *tmp = NULL;
	glob_t g;
	int i, r, err = 0;

	/* Rebuild the worker fleet if a prior interrupt tore it down. */
	parallel_orch_ensure_alive(conn);

	abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
	memset(&g, 0, sizeof(g));

	debug3("Looking up %s", abs_src);
	if ((r = sftp_glob(conn, abs_src, GLOB_MARK, NULL, &g)) != 0) {
		if (r == GLOB_NOSPACE) {
			error("Too many matches for \"%s\".", abs_src);
		} else {
			error("File \"%s\" not found.", abs_src);
		}
		err = -1;
		goto out;
	}

	/*
	 * If multiple matches then dst must be a directory or
	 * unspecified.
	 */
	if (g.gl_matchc > 1 && dst != NULL && !local_is_dir(dst)) {
		error("Multiple source paths, but destination "
		    "\"%s\" is not a directory", dst);
		err = -1;
		goto out;
	}

	if (parallel_orch != NULL && !quiet && g.gl_matchc > 0) {
		char label[64];
		snprintf(label, sizeof(label),
		    "Fetching %d file%s in parallel", (int)g.gl_matchc,
		    g.gl_matchc == 1 ? "" : "s");
		sftp_parallel_progress_start(parallel_orch, label, 0);
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		tmp = xstrdup(g.gl_pathv[i]);
		if ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}

		/* Special handling for dest of '..' */
		if (strcmp(filename, "..") == 0)
			filename = "."; /* Download to dest, not dest/.. */

		if (g.gl_matchc == 1 && dst) {
			if (local_is_dir(dst)) {
				abs_dst = sftp_path_append(dst, filename);
			} else {
				abs_dst = xstrdup(dst);
			}
		} else if (dst) {
			abs_dst = sftp_path_append(dst, filename);
		} else {
			abs_dst = xstrdup(filename);
		}
		free(tmp);

		resume |= global_aflag;
		if (!quiet && verify)
			mprintf("Downloading %s to %s (verified resume)\n",
			    g.gl_pathv[i], abs_dst);
		else if (!quiet && resume)
			mprintf("Resuming %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		else if (!quiet && !resume)
			mprintf("Fetching %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow link flag */
		if (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			if (parallel_orch != NULL) {
				if (sftp_parallel_download_dir(parallel_orch,
				    conn, g.gl_pathv[i], abs_dst, 1,
				    resume, verify) == -1)
					err = -1;
			} else if (sftp_download_dir(conn, g.gl_pathv[i],
			    abs_dst, NULL, pflag || global_pflag, 1, resume,
			    verify, fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} else if (parallel_orch != NULL) {
			/*
			 * Download parity for HPNLustreStripeCount: mirror of
			 * the upload-side parent-dir hook below (process_put),
			 * but the destination is LOCAL, so the layout is
			 * applied directly instead of via the wire extension.
			 * A single-file -j N get into an un-striped local
			 * Lustre directory then fans out across OSTs too.
			 */
			{
				const char *slash = strrchr(abs_dst, '/');
				char *parent;
				if (slash == NULL) {
					parent = xstrdup(".");
				} else if (slash == abs_dst) {
					parent = xstrdup("/");
				} else {
					size_t plen = (size_t)(slash - abs_dst);
					parent = xmalloc(plen + 1);
					memcpy(parent, abs_dst, plen);
					parent[plen] = '\0';
				}
				maybe_apply_lustre_layout_local(parallel_orch,
				    conn, parent);
				free(parent);
			}
			/*
			 * Recover size and mode from the glob attrib cache so
			 * maybe_submit_download can decide whether to range-
			 * split this file.  sftp_glob already paid an RTT for
			 * the stat via fudge_stat/fudge_lstat; we just reuse it.
			 *
			 * If the lookup misses (rare - typically only the
			 * GLOB_NOCHECK fallback path), do an explicit stat so
			 * that the single-file get case (the workload most
			 * likely to benefit from range splitting) still gets
			 * a known size.
			 */
			Attrib ga;
			off_t fsize = 0;
			mode_t fmode = 0;
			int have = (sftp_glob_get_attrib(g.gl_pathv[i],
			    &ga) == 0);
			if (!have &&
			    sftp_stat(conn, g.gl_pathv[i], 1, &ga) == 0)
				have = 1;
			if (have) {
				if (ga.flags & SSH2_FILEXFER_ATTR_SIZE)
					fsize = (off_t)ga.size;
				if (ga.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
					fmode = ga.perm & 07777;
			}
			if (sftp_parallel_submit_download(parallel_orch, conn,
			    g.gl_pathv[i], abs_dst, fsize, fmode,
			    resume, verify) != 0)
				err = -1;
		} else {
			int dr = sftp_download(conn, g.gl_pathv[i], abs_dst,
			    NULL, pflag || global_pflag, resume,
			    fflag || global_fflag, 0, verify);
			if (dr == -1)
				err = -1;
			else if (dr == 1)
				mprintf("File skipped: %s: Identical.\n",
				    g.gl_pathv[i]);
			else if (dr == 2)
				mprintf("File skipped: %s: Target is larger"
				    " than source.\n", g.gl_pathv[i]);
			else if (hpn_verify_transfer)	/* dr==0: downloaded */
				verify_one(conn, abs_dst, g.gl_pathv[i]);
		}
		free(abs_dst);
		abs_dst = NULL;
	}

	/*
	 * In deferred-wait mode (batch mode or future "job submission mode"),
	 * skip the drain - the caller (interactive_loop end-of-batch) will
	 * flush the queue once after all commands have been submitted, which
	 * lets multiple get commands pipeline their files instead of stalling
	 * each get on a slow chunk from the previous one.  Err reporting and
	 * the protocol-violation summary then happen at flush time.
	 */
	if (parallel_orch != NULL && !defer_parallel_wait) {
		if (parallel_flush() != 0)
			err = -1;
	}

out:
	free(abs_src);
	globfree(&g);
	return(err);
}

static int
process_put(struct sftp_conn *conn, const char *src, const char *dst,
    const char *pwd, int pflag, int rflag, int resume, int fflag, int verify)
{
	char *tmp_dst = NULL;
	char *abs_dst = NULL;
	char *tmp = NULL, *filename = NULL;
	glob_t g;
	int err = 0;
	int i, dst_is_dir = 1;
	struct stat sb;

	/* Rebuild the worker fleet if a prior interrupt tore it down. */
	parallel_orch_ensure_alive(conn);

	if (dst) {
		tmp_dst = xstrdup(dst);
		tmp_dst = sftp_make_absolute(tmp_dst, pwd);
	}

	memset(&g, 0, sizeof(g));
	debug3("Looking up %s", src);
	if (glob(src, GLOB_NOCHECK | GLOB_MARK, NULL, &g)) {
		error("File \"%s\" not found.", src);
		err = -1;
		goto out;
	}

	/* If we aren't fetching to pwd then stash this status for later */
	if (tmp_dst != NULL)
		dst_is_dir = sftp_remote_is_dir(conn, tmp_dst);

	/* If multiple matches, dst may be directory or unspecified */
	if (g.gl_matchc > 1 && tmp_dst && !dst_is_dir) {
		error("Multiple paths match, but destination "
		    "\"%s\" is not a directory", tmp_dst);
		err = -1;
		goto out;
	}

	if (parallel_orch != NULL && !quiet && g.gl_matchc > 0) {
		char label[64];
		off_t total_bytes = 0;
		long total_files = 0, fc = 0;
		for (i = 0; g.gl_pathv[i]; i++) {
			fc = 0;
			total_bytes += sftp_parallel_scan_upload_total(
			    g.gl_pathv[i], &fc);
			total_files += fc;
		}
		snprintf(label, sizeof(label),
		    "Uploading %ld file%s in parallel", total_files,
		    total_files == 1 ? "" : "s");
		sftp_parallel_progress_start(parallel_orch, label, total_bytes);
	}

	for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
		if (stat(g.gl_pathv[i], &sb) == -1) {
			err = -1;
			error("stat %s: %s", g.gl_pathv[i], strerror(errno));
			continue;
		}

		tmp = xstrdup(g.gl_pathv[i]);
		if ((filename = basename(tmp)) == NULL) {
			error("basename %s: %s", tmp, strerror(errno));
			free(tmp);
			err = -1;
			goto out;
		}
		/* Special handling for source of '..' */
		if (strcmp(filename, "..") == 0)
			filename = "."; /* Upload to dest, not dest/.. */

		free(abs_dst);
		abs_dst = NULL;
		if (g.gl_matchc == 1 && tmp_dst) {
			/* If directory specified, append filename */
			if (dst_is_dir)
				abs_dst = sftp_path_append(tmp_dst, filename);
			else
				abs_dst = xstrdup(tmp_dst);
		} else if (tmp_dst) {
			abs_dst = sftp_path_append(tmp_dst, filename);
		} else {
			abs_dst = sftp_make_absolute(xstrdup(filename), pwd);
		}
		free(tmp);

		resume |= global_aflag;
		if (!quiet && verify)
			mprintf("Uploading %s to %s (verified resume)\n",
			    g.gl_pathv[i], abs_dst);
		else if (!quiet && resume)
			mprintf("Resuming upload of %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		else if (!quiet && !resume)
			mprintf("Uploading %s to %s\n",
			    g.gl_pathv[i], abs_dst);
		/* XXX follow_link_flag */
		if (sftp_globpath_is_dir(g.gl_pathv[i]) &&
		    (rflag || global_rflag)) {
			if (parallel_orch != NULL) {
				if (sftp_parallel_upload_dir(parallel_orch,
				    conn, g.gl_pathv[i], abs_dst, 1,
				    resume, verify) == -1)
					err = -1;
			} else if (sftp_upload_dir(conn, g.gl_pathv[i],
			    abs_dst, pflag || global_pflag, 1, resume, verify,
			    fflag || global_fflag, 0, 0) == -1)
				err = -1;
		} else if (parallel_orch != NULL) {
			/*
			 * HPNLustreStripeCount: same-thread analogue of the
			 * walker hook.  Apply the layout to the parent
			 * directory of `abs_dst` (the file's destination
			 * directory) so a single-file -j N upload to an
			 * un-striped Lustre directory also fans out across
			 * OSTs.  Idempotent; the declined-latch on conn
			 * prevents log spam after the first failure.
			 */
			{
				const char *slash = strrchr(abs_dst, '/');
				char *parent;
				if (slash == NULL) {
					parent = xstrdup(".");
				} else if (slash == abs_dst) {
					parent = xstrdup("/");
				} else {
					size_t plen = (size_t)(slash - abs_dst);
					parent = xmalloc(plen + 1);
					memcpy(parent, abs_dst, plen);
					parent[plen] = '\0';
				}
				maybe_apply_lustre_layout(parallel_orch, conn,
				    parent);
				free(parent);
			}
			if (sftp_parallel_submit_upload(parallel_orch, conn,
			    g.gl_pathv[i], abs_dst,
			    sb.st_size, sb.st_mode, resume, verify) != 0)
				err = -1;
		} else {
			int ur = sftp_upload(conn, g.gl_pathv[i], abs_dst,
			    pflag || global_pflag, resume, verify,
			    fflag || global_fflag, 0);
			if (ur == -1)
				err = -1;
			else if (ur == 1)
				mprintf("File skipped: %s: Identical.\n",
				    g.gl_pathv[i]);
			else if (ur == 2)
				mprintf("File skipped: %s: Target is larger"
				    " than source.\n", g.gl_pathv[i]);
			else if (hpn_verify_transfer)	/* ur==0: uploaded */
				verify_one(conn, g.gl_pathv[i], abs_dst);
		}
	}

	/* See process_get - deferred mode skips the per-command drain so
	 * successive put commands pipeline their files instead of each one
	 * stalling on a slow tail chunk from the previous file. */
	if (parallel_orch != NULL && !defer_parallel_wait) {
		if (parallel_flush() != 0)
			err = -1;
	}

out:
	free(abs_dst);
	free(tmp_dst);
	globfree(&g);
	return(err);
}

static int
sdirent_comp(const void *aa, const void *bb)
{
	SFTP_DIRENT *a = *(SFTP_DIRENT **)aa;
	SFTP_DIRENT *b = *(SFTP_DIRENT **)bb;
	int rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	if (sort_flag & LS_NAME_SORT)
		return (rmul * strcmp(a->filename, b->filename));
	else if (sort_flag & LS_TIME_SORT)
		return (rmul * NCMP(a->a.mtime, b->a.mtime));
	else if (sort_flag & LS_SIZE_SORT)
		return (rmul * NCMP(a->a.size, b->a.size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement for directories */
static int
do_ls_dir(struct sftp_conn *conn, const char *path,
    const char *strip_path, int lflag)
{
	int n;
	u_int c = 1, colspace = 0, columns = 1;
	SFTP_DIRENT **d;

	if ((n = sftp_readdir(conn, path, &d)) != 0)
		return (n);

	if (!(lflag & LS_SHORT_VIEW)) {
		u_int m = 0, width = 80;
		struct winsize ws;
		char *tmp;

		/* Count entries for sort and find longest filename */
		for (n = 0; d[n] != NULL; n++) {
			if (d[n]->filename[0] != '.' || (lflag & LS_SHOW_ALL))
				m = MAXIMUM(m, strlen(d[n]->filename));
		}

		/* Add any subpath that also needs to be counted */
		tmp = path_strip(path, strip_path);
		m += strlen(tmp);
		free(tmp);

		if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
			width = ws.ws_col;

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
		colspace = MINIMUM(colspace, width);
	}

	if (lflag & SORT_FLAGS) {
		for (n = 0; d[n] != NULL; n++)
			;	/* count entries */
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(d, n, sizeof(*d), sdirent_comp);
	}

	get_remote_user_groups_from_dirents(conn, d);
	for (n = 0; d[n] != NULL && !interrupted; n++) {
		char *tmp, *fname;

		if (d[n]->filename[0] == '.' && !(lflag & LS_SHOW_ALL))
			continue;

		tmp = sftp_path_append(path, d[n]->filename);
		fname = path_strip(tmp, strip_path);
		free(tmp);

		if (lflag & LS_LONG_VIEW) {
			if ((lflag & (LS_NUMERIC_VIEW|LS_SI_UNITS)) != 0 ||
			    sftp_can_get_users_groups_by_id(conn)) {
				char *lname;
				struct stat sb;

				memset(&sb, 0, sizeof(sb));
				attrib_to_stat(&d[n]->a, &sb);
				lname = ls_file(fname, &sb, 1,
				    (lflag & LS_SI_UNITS),
				    ruser_name(sb.st_uid),
				    rgroup_name(sb.st_gid));
				mprintf("%s\n", lname);
				free(lname);
			} else
				mprintf("%s\n", d[n]->longname);
		} else {
			mprintf("%-*s", colspace, fname);
			if (c >= columns) {
				printf("\n");
				c = 1;
			} else
				c++;
		}

		free(fname);
	}

	if (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

	sftp_free_dirents(d);
	return (0);
}

static int
sglob_comp(const void *aa, const void *bb)
{
	u_int a = *(const u_int *)aa;
	u_int b = *(const u_int *)bb;
	const char *ap = sort_glob->gl_pathv[a];
	const char *bp = sort_glob->gl_pathv[b];
	const struct stat *as = sort_glob->gl_statv[a];
	const struct stat *bs = sort_glob->gl_statv[b];
	int rmul = sort_flag & LS_REVERSE_SORT ? -1 : 1;

#define NCMP(a,b) (a == b ? 0 : (a < b ? 1 : -1))
	if (sort_flag & LS_NAME_SORT)
		return (rmul * strcmp(ap, bp));
	else if (sort_flag & LS_TIME_SORT) {
#if defined(HAVE_STRUCT_STAT_ST_MTIM)
		if (timespeccmp(&as->st_mtim, &bs->st_mtim, ==))
			return 0;
		return timespeccmp(&as->st_mtim, &bs->st_mtim, <) ?
		    rmul : -rmul;
#elif defined(HAVE_STRUCT_STAT_ST_MTIME)
		return (rmul * NCMP(as->st_mtime, bs->st_mtime));
#else
	return rmul * 1;
#endif
	} else if (sort_flag & LS_SIZE_SORT)
		return (rmul * NCMP(as->st_size, bs->st_size));

	fatal("Unknown ls sort type");
}

/* sftp ls.1 replacement which handles path globs */
static int
do_globbed_ls(struct sftp_conn *conn, const char *path,
    const char *strip_path, int lflag)
{
	char *fname, *lname;
	glob_t g;
	int err, r;
	struct winsize ws;
	u_int i, j, nentries, *indices = NULL, c = 1;
	u_int colspace = 0, columns = 1, m = 0, width = 80;

	memset(&g, 0, sizeof(g));

	if ((r = sftp_glob(conn, path,
	    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE|GLOB_KEEPSTAT|GLOB_NOSORT,
	    NULL, &g)) != 0 ||
	    (g.gl_pathc && !g.gl_matchc)) {
		if (g.gl_pathc)
			globfree(&g);
		if (r == GLOB_NOSPACE) {
			error("Can't ls: Too many matches for \"%s\"", path);
		} else {
			error("Can't ls: \"%s\" not found", path);
		}
		return -1;
	}

	if (interrupted)
		goto out;

	/*
	 * If the glob returns a single match and it is a directory,
	 * then just list its contents.
	 */
	if (g.gl_matchc == 1 && g.gl_statv[0] != NULL &&
	    S_ISDIR(g.gl_statv[0]->st_mode)) {
		err = do_ls_dir(conn, g.gl_pathv[0], strip_path, lflag);
		globfree(&g);
		return err;
	}

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	if (!(lflag & LS_SHORT_VIEW)) {
		/* Count entries for sort and find longest filename */
		for (i = 0; g.gl_pathv[i]; i++)
			m = MAXIMUM(m, strlen(g.gl_pathv[i]));

		columns = width / (m + 2);
		columns = MAXIMUM(columns, 1);
		colspace = width / columns;
	}

	/*
	 * Sorting: rather than mess with the contents of glob_t, prepare
	 * an array of indices into it and sort that. For the usual
	 * unsorted case, the indices are just the identity 1=1, 2=2, etc.
	 */
	for (nentries = 0; g.gl_pathv[nentries] != NULL; nentries++)
		;	/* count entries */
	indices = xcalloc(nentries, sizeof(*indices));
	for (i = 0; i < nentries; i++)
		indices[i] = i;

	if (lflag & SORT_FLAGS) {
		sort_glob = &g;
		sort_flag = lflag & (SORT_FLAGS|LS_REVERSE_SORT);
		qsort(indices, nentries, sizeof(*indices), sglob_comp);
		sort_glob = NULL;
	}

	get_remote_user_groups_from_glob(conn, &g);
	for (j = 0; j < nentries && !interrupted; j++) {
		i = indices[j];
		fname = path_strip(g.gl_pathv[i], strip_path);
		if (lflag & LS_LONG_VIEW) {
			if (g.gl_statv[i] == NULL) {
				error("no stat information for %s", fname);
				free(fname);
				continue;
			}
			lname = ls_file(fname, g.gl_statv[i], 1,
			    (lflag & LS_SI_UNITS),
			    ruser_name(g.gl_statv[i]->st_uid),
			    rgroup_name(g.gl_statv[i]->st_gid));
			mprintf("%s\n", lname);
			free(lname);
		} else {
			mprintf("%-*s", colspace, fname);
			if (c >= columns) {
				printf("\n");
				c = 1;
			} else
				c++;
		}
		free(fname);
	}

	if (!(lflag & LS_LONG_VIEW) && (c != 1))
		printf("\n");

 out:
	if (g.gl_pathc)
		globfree(&g);
	free(indices);

	return 0;
}

static int
do_df(struct sftp_conn *conn, const char *path, int hflag, int iflag)
{
	struct sftp_statvfs st;
	char s_used[FMT_SCALED_STRSIZE], s_avail[FMT_SCALED_STRSIZE];
	char s_root[FMT_SCALED_STRSIZE], s_total[FMT_SCALED_STRSIZE];
	char s_icapacity[16], s_dcapacity[16];

	if (sftp_statvfs(conn, path, &st, 1) == -1)
		return -1;
	if (st.f_files == 0)
		strlcpy(s_icapacity, "ERR", sizeof(s_icapacity));
	else {
		snprintf(s_icapacity, sizeof(s_icapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_files - st.f_ffree) /
		    st.f_files));
	}
	if (st.f_blocks == 0)
		strlcpy(s_dcapacity, "ERR", sizeof(s_dcapacity));
	else {
		snprintf(s_dcapacity, sizeof(s_dcapacity), "%3llu%%",
		    (unsigned long long)(100 * (st.f_blocks - st.f_bfree) /
		    st.f_blocks));
	}
	if (iflag) {
		printf("     Inodes        Used       Avail      "
		    "(root)    %%Capacity\n");
		printf("%11llu %11llu %11llu %11llu         %s\n",
		    (unsigned long long)st.f_files,
		    (unsigned long long)(st.f_files - st.f_ffree),
		    (unsigned long long)st.f_favail,
		    (unsigned long long)st.f_ffree, s_icapacity);
	} else if (hflag) {
		strlcpy(s_used, "error", sizeof(s_used));
		strlcpy(s_avail, "error", sizeof(s_avail));
		strlcpy(s_root, "error", sizeof(s_root));
		strlcpy(s_total, "error", sizeof(s_total));
		fmt_scaled((st.f_blocks - st.f_bfree) * st.f_frsize, s_used);
		fmt_scaled(st.f_bavail * st.f_frsize, s_avail);
		fmt_scaled(st.f_bfree * st.f_frsize, s_root);
		fmt_scaled(st.f_blocks * st.f_frsize, s_total);
		printf("    Size     Used    Avail   (root)    %%Capacity\n");
		printf("%7sB %7sB %7sB %7sB         %s\n",
		    s_total, s_used, s_avail, s_root, s_dcapacity);
	} else {
		printf("        Size         Used        Avail       "
		    "(root)    %%Capacity\n");
		printf("%12llu %12llu %12llu %12llu         %s\n",
		    (unsigned long long)(st.f_frsize * st.f_blocks / 1024),
		    (unsigned long long)(st.f_frsize *
		    (st.f_blocks - st.f_bfree) / 1024),
		    (unsigned long long)(st.f_frsize * st.f_bavail / 1024),
		    (unsigned long long)(st.f_frsize * st.f_bfree / 1024),
		    s_dcapacity);
	}
	return 0;
}

/*
 * Undo escaping of glob sequences in place. Used to undo extra escaping
 * applied in makeargv() when the string is destined for a function that
 * does not glob it.
 */
static void
undo_glob_escape(char *s)
{
	size_t i, j;

	for (i = j = 0;;) {
		if (s[i] == '\0') {
			s[j] = '\0';
			return;
		}
		if (s[i] != '\\') {
			s[j++] = s[i++];
			continue;
		}
		/* s[i] == '\\' */
		++i;
		switch (s[i]) {
		case '?':
		case '[':
		case '*':
		case '\\':
			s[j++] = s[i++];
			break;
		case '\0':
			s[j++] = '\\';
			s[j] = '\0';
			return;
		default:
			s[j++] = '\\';
			s[j++] = s[i++];
			break;
		}
	}
}

/*
 * Split a string into an argument vector using sh(1)-style quoting,
 * comment and escaping rules, but with some tweaks to handle glob(3)
 * wildcards.
 * The "sloppy" flag allows for recovery from missing terminating quote, for
 * use in parsing incomplete commandlines during tab autocompletion.
 *
 * Returns NULL on error or a NULL-terminated array of arguments.
 *
 * If "lastquote" is not NULL, the quoting character used for the last
 * argument is placed in *lastquote ("\0", "'" or "\"").
 *
 * If "terminated" is not NULL, *terminated will be set to 1 when the
 * last argument's quote has been properly terminated or 0 otherwise.
 * This parameter is only of use if "sloppy" is set.
 */
#define MAXARGS		128
#define MAXARGLEN	8192
static char **
makeargv(const char *arg, int *argcp, int sloppy, char *lastquote,
    u_int *terminated)
{
	int argc, quot;
	size_t i, j;
	static char argvs[MAXARGLEN];
	static char *argv[MAXARGS + 1];
	enum { MA_START, MA_SQUOTE, MA_DQUOTE, MA_UNQUOTED } state, q;

	*argcp = argc = 0;
	if (strlen(arg) > sizeof(argvs) - 1) {
 args_too_longs:
		error("string too long");
		return NULL;
	}
	if (terminated != NULL)
		*terminated = 1;
	if (lastquote != NULL)
		*lastquote = '\0';
	state = MA_START;
	i = j = 0;
	for (;;) {
		if ((size_t)argc >= sizeof(argv) / sizeof(*argv)){
			error("Too many arguments.");
			return NULL;
		}
		if (isspace((unsigned char)arg[i])) {
			if (state == MA_UNQUOTED) {
				/* Terminate current argument */
				argvs[j++] = '\0';
				argc++;
				state = MA_START;
			} else if (state != MA_START)
				argvs[j++] = arg[i];
		} else if (arg[i] == '"' || arg[i] == '\'') {
			q = arg[i] == '"' ? MA_DQUOTE : MA_SQUOTE;
			if (state == MA_START) {
				argv[argc] = argvs + j;
				state = q;
				if (lastquote != NULL)
					*lastquote = arg[i];
			} else if (state == MA_UNQUOTED)
				state = q;
			else if (state == q)
				state = MA_UNQUOTED;
			else
				argvs[j++] = arg[i];
		} else if (arg[i] == '\\') {
			if (state == MA_SQUOTE || state == MA_DQUOTE) {
				quot = state == MA_SQUOTE ? '\'' : '"';
				/* Unescape quote we are in */
				/* XXX support \n and friends? */
				if (arg[i + 1] == quot) {
					i++;
					argvs[j++] = arg[i];
				} else if (arg[i + 1] == '?' ||
				    arg[i + 1] == '[' || arg[i + 1] == '*') {
					/*
					 * Special case for sftp: append
					 * double-escaped glob sequence -
					 * glob will undo one level of
					 * escaping. NB. string can grow here.
					 */
					if (j >= sizeof(argvs) - 5)
						goto args_too_longs;
					argvs[j++] = '\\';
					argvs[j++] = arg[i++];
					argvs[j++] = '\\';
					argvs[j++] = arg[i];
				} else {
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				}
			} else {
				if (state == MA_START) {
					argv[argc] = argvs + j;
					state = MA_UNQUOTED;
					if (lastquote != NULL)
						*lastquote = '\0';
				}
				if (arg[i + 1] == '?' || arg[i + 1] == '[' ||
				    arg[i + 1] == '*' || arg[i + 1] == '\\') {
					/*
					 * Special case for sftp: append
					 * escaped glob sequence -
					 * glob will undo one level of
					 * escaping.
					 */
					argvs[j++] = arg[i++];
					argvs[j++] = arg[i];
				} else {
					/* Unescape everything */
					/* XXX support \n and friends? */
					i++;
					argvs[j++] = arg[i];
				}
			}
		} else if (arg[i] == '#') {
			if (state == MA_SQUOTE || state == MA_DQUOTE)
				argvs[j++] = arg[i];
			else
				goto string_done;
		} else if (arg[i] == '\0') {
			if (state == MA_SQUOTE || state == MA_DQUOTE) {
				if (sloppy) {
					state = MA_UNQUOTED;
					if (terminated != NULL)
						*terminated = 0;
					goto string_done;
				}
				error("Unterminated quoted argument");
				return NULL;
			}
 string_done:
			if (state == MA_UNQUOTED) {
				argvs[j++] = '\0';
				argc++;
			}
			break;
		} else {
			if (state == MA_START) {
				argv[argc] = argvs + j;
				state = MA_UNQUOTED;
				if (lastquote != NULL)
					*lastquote = '\0';
			}
			if ((state == MA_SQUOTE || state == MA_DQUOTE) &&
			    (arg[i] == '?' || arg[i] == '[' || arg[i] == '*')) {
				/*
				 * Special case for sftp: escape quoted
				 * glob(3) wildcards. NB. string can grow
				 * here.
				 */
				if (j >= sizeof(argvs) - 3)
					goto args_too_longs;
				argvs[j++] = '\\';
				argvs[j++] = arg[i];
			} else
				argvs[j++] = arg[i];
		}
		i++;
	}
	*argcp = argc;
	return argv;
}

static int
parse_args(const char **cpp, int *ignore_errors, int *disable_echo, int *aflag,
	  int *fflag, int *hflag, int *iflag, int *lflag, int *pflag,
	  int *rflag, int *sflag, int *vflag,
    unsigned long *n_arg, char **path1, char **path2)
{
	const char *cmd, *cp = *cpp;
	char *cp2, **argv;
	int base = 0;
	long long ll;
	int path1_mandatory = 0, i, cmdnum, optidx, argc;

	/* Skip leading whitespace */
	cp = cp + strspn(cp, WHITESPACE);

	/*
	 * Check for leading '-' (disable error processing) and '@' (suppress
	 * command echo)
	 */
	*ignore_errors = 0;
	*disable_echo = 0;
	for (;*cp != '\0'; cp++) {
		if (*cp == '-') {
			*ignore_errors = 1;
		} else if (*cp == '@') {
			*disable_echo = 1;
		} else {
			/* all other characters terminate prefix processing */
			break;
		}
	}
	cp = cp + strspn(cp, WHITESPACE);

	/* Ignore blank lines and lines which begin with comment '#' char */
	if (*cp == '\0' || *cp == '#')
		return (0);

	if ((argv = makeargv(cp, &argc, 0, NULL, NULL)) == NULL)
		return -1;

	/* Figure out which command we have */
	for (i = 0; cmds[i].c != NULL; i++) {
		if (argv[0] != NULL && strcasecmp(cmds[i].c, argv[0]) == 0)
			break;
	}
	cmdnum = cmds[i].n;
	cmd = cmds[i].c;

	/* Special case */
	if (*cp == '!') {
		cp++;
		cmdnum = I_SHELL;
	} else if (cmdnum == -1) {
		error("Invalid command.");
		return -1;
	}

	/* Get arguments and parse flags */
	*aflag = *fflag = *hflag = *iflag = *lflag = *pflag = 0;
	*rflag = *sflag = 0;
	*path1 = *path2 = NULL;
	optidx = 1;
	switch (cmdnum) {
	case I_GET:
	case I_REGET:
	case I_VREGET:
	case I_REPUT:
	case I_VREPUT:
	case I_PUT:
		if ((optidx = parse_getput_flags(cmd, argv, argc,
		    aflag, fflag, pflag, rflag, vflag)) == -1)
			return -1;
		/* Get first pathname (mandatory) */
		if (argc - optidx < 1) {
			error("You must specify at least one path after a "
			    "%s command.", cmd);
			return -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Get second pathname (optional) */
		if (argc - optidx > 1) {
			*path2 = xstrdup(argv[optidx + 1]);
			/* Destination is not globbed */
			undo_glob_escape(*path2);
		}
		break;
	case I_LINK:
		if ((optidx = parse_link_flags(cmd, argv, argc, sflag)) == -1)
			return -1;
		goto parse_two_paths;
	case I_COPY:
		if ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			return -1;
		goto parse_two_paths;
	case I_RENAME:
		if ((optidx = parse_rename_flags(cmd, argv, argc, lflag)) == -1)
			return -1;
		goto parse_two_paths;
	case I_SYMLINK:
		if ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			return -1;
 parse_two_paths:
		if (argc - optidx < 2) {
			error("You must specify two paths after a %s "
			    "command.", cmd);
			return -1;
		}
		*path1 = xstrdup(argv[optidx]);
		*path2 = xstrdup(argv[optidx + 1]);
		/* Paths are not globbed */
		undo_glob_escape(*path1);
		undo_glob_escape(*path2);
		break;
	case I_RM:
	case I_MKDIR:
	case I_RMDIR:
	case I_LMKDIR:
		path1_mandatory = 1;
		/* FALLTHROUGH */
	case I_CHDIR:
	case I_LCHDIR:
		if ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			return -1;
		/* Get pathname (mandatory) */
		if (argc - optidx < 1) {
			if (!path1_mandatory)
				break; /* return a NULL path1 */
			error("You must specify a path after a %s command.",
			    cmd);
			return -1;
		}
		*path1 = xstrdup(argv[optidx]);
		/* Only "rm" globs */
		if (cmdnum != I_RM)
			undo_glob_escape(*path1);
		break;
	case I_DF:
		if ((optidx = parse_df_flags(cmd, argv, argc, hflag,
		    iflag)) == -1)
			return -1;
		/* Default to current directory if no path specified */
		if (argc - optidx < 1)
			*path1 = NULL;
		else {
			*path1 = xstrdup(argv[optidx]);
			undo_glob_escape(*path1);
		}
		break;
	case I_LS:
		if ((optidx = parse_ls_flags(argv, argc, lflag)) == -1)
			return(-1);
		/* Path is optional */
		if (argc - optidx > 0)
			*path1 = xstrdup(argv[optidx]);
		break;
	case I_LLS:
		/* Skip ls command and following whitespace */
		cp = cp + strlen(cmd) + strspn(cp, WHITESPACE);
	case I_SHELL:
		/* Uses the rest of the line */
		break;
	case I_LUMASK:
	case I_CHMOD:
		base = 8;
		/* FALLTHROUGH */
	case I_CHOWN:
	case I_CHGRP:
		if ((optidx = parse_ch_flags(cmd, argv, argc, hflag)) == -1)
			return -1;
		/* Get numeric arg (mandatory) */
		if (argc - optidx < 1)
			goto need_num_arg;
		errno = 0;
		ll = strtoll(argv[optidx], &cp2, base);
		if (cp2 == argv[optidx] || *cp2 != '\0' ||
		    ((ll == LLONG_MIN || ll == LLONG_MAX) && errno == ERANGE) ||
		    ll < 0 || ll > UINT32_MAX) {
 need_num_arg:
			error("You must supply a numeric argument "
			    "to the %s command.", cmd);
			return -1;
		}
		*n_arg = ll;
		if (cmdnum == I_LUMASK)
			break;
		/* Get pathname (mandatory) */
		if (argc - optidx < 2) {
			error("You must specify a path after a %s command.",
			    cmd);
			return -1;
		}
		*path1 = xstrdup(argv[optidx + 1]);
		break;
	case I_QUIT:
	case I_PWD:
	case I_LPWD:
	case I_HELP:
	case I_VERSION:
	case I_PROGRESS:
	case I_WAIT:
		if ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			return -1;
		break;
	case I_DEFER:
		/* "defer" alone reports state; "defer on" / "defer off"
		 * toggles.  No other args accepted. */
		if ((optidx = parse_no_flags(cmd, argv, argc)) == -1)
			return -1;
		if (argc - optidx > 1) {
			error("Too many arguments to defer (use on/off)");
			return -1;
		}
		if (argc - optidx == 1)
			*path1 = xstrdup(argv[optidx]);
		break;
	default:
		fatal("Command not implemented");
	}

	*cpp = cp;
	return(cmdnum);
}

static int
parse_dispatch_command(struct sftp_conn *conn, const char *cmd, char **pwd,
    const char *startdir, int err_abort, int echo_command)
{
	const char *ocmd = cmd;
	char *path1, *path2, *tmp;
	int ignore_errors = 0, disable_echo = 1;
	int aflag = 0, fflag = 0, hflag = 0, iflag = 0;
	int lflag = 0, pflag = 0, rflag = 0, sflag = 0, vflag = 0;
	int cmdnum, i;
	unsigned long n_arg = 0;
	Attrib a, aa;
	char path_buf[PATH_MAX];
	int err = 0;
	glob_t g;

	path1 = path2 = NULL;
	cmdnum = parse_args(&cmd, &ignore_errors, &disable_echo, &aflag, &fflag,
	    &hflag, &iflag, &lflag, &pflag, &rflag, &sflag, &vflag, &n_arg,
	    &path1, &path2);
	if (ignore_errors != 0)
		err_abort = 0;

	if (echo_command && !disable_echo)
		mprintf("sftp> %s\n", ocmd);

	memset(&g, 0, sizeof(g));

	/* Perform command */
	switch (cmdnum) {
	case 0:
		/* Blank line */
		break;
	case -1:
		/* Unrecognized command */
		err = -1;
		break;
	case I_VREGET:
		aflag = 1;
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag, 1 /* verify */);
		break;
	case I_REGET:
		aflag = 1;
		/* FALLTHROUGH */
	case I_GET:
		err = process_get(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag, vflag /* verify */);
		break;
	case I_VREPUT:
		aflag = 1;
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag, 1 /* verify */);
		break;
	case I_REPUT:
		aflag = 1;
		/* FALLTHROUGH */
	case I_PUT:
		err = process_put(conn, path1, path2, *pwd, pflag,
		    rflag, aflag, fflag, vflag /* verify */);
		break;
	case I_COPY:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_copy(conn, path1, path2);
		break;
	case I_RENAME:
		path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = sftp_rename(conn, path1, path2, lflag);
		break;
	case I_SYMLINK:
		sflag = 1;
		/* FALLTHROUGH */
	case I_LINK:
		if (!sflag)
			path1 = sftp_make_absolute(path1, *pwd);
		path2 = sftp_make_absolute(path2, *pwd);
		err = (sflag ? sftp_symlink : sftp_hardlink)(conn,
		    path1, path2);
		break;
	case I_RM:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			if (!quiet)
				mprintf("Removing %s\n", g.gl_pathv[i]);
			err = sftp_rm(conn, g.gl_pathv[i]);
			if (err != 0 && err_abort)
				break;
		}
		break;
	case I_MKDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = 0777;
		err = sftp_mkdir(conn, path1, &a, 1);
		break;
	case I_RMDIR:
		path1 = sftp_make_absolute(path1, *pwd);
		err = sftp_rmdir(conn, path1);
		break;
	case I_CHDIR:
		if (path1 == NULL || *path1 == '\0')
			path1 = xstrdup(startdir);
		path1 = sftp_make_absolute(path1, *pwd);
		if ((tmp = sftp_realpath(conn, path1)) == NULL) {
			err = 1;
			break;
		}
		if (sftp_stat(conn, tmp, 0, &aa) != 0) {
			free(tmp);
			err = 1;
			break;
		}
		if (!(aa.flags & SSH2_FILEXFER_ATTR_PERMISSIONS)) {
			error("Can't change directory: Can't check target");
			free(tmp);
			err = 1;
			break;
		}
		if (!S_ISDIR(aa.perm)) {
			error("Can't change directory: \"%s\" is not "
			    "a directory", tmp);
			free(tmp);
			err = 1;
			break;
		}
		free(*pwd);
		*pwd = tmp;
		break;
	case I_LS:
		if (!path1) {
			do_ls_dir(conn, *pwd, *pwd, lflag);
			break;
		}

		/* Strip pwd off beginning of non-absolute paths */
		tmp = NULL;
		if (!path_absolute(path1))
			tmp = *pwd;

		path1 = make_absolute_pwd_glob(path1, *pwd);
		err = do_globbed_ls(conn, path1, tmp, lflag);
		break;
	case I_DF:
		/* Default to current directory if no path specified */
		if (path1 == NULL)
			path1 = xstrdup(*pwd);
		path1 = sftp_make_absolute(path1, *pwd);
		err = do_df(conn, path1, hflag, iflag);
		break;
	case I_LCHDIR:
		if (path1 == NULL || *path1 == '\0')
			path1 = xstrdup("~");
		tmp = tilde_expand_filename(path1, getuid());
		free(path1);
		path1 = tmp;
		if (chdir(path1) == -1) {
			error("Couldn't change local directory to "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		break;
	case I_LMKDIR:
		if (mkdir(path1, 0777) == -1) {
			error("Couldn't create local directory "
			    "\"%s\": %s", path1, strerror(errno));
			err = 1;
		}
		break;
	case I_LLS:
		local_do_ls(cmd);
		break;
	case I_SHELL:
		local_do_shell(cmd);
		break;
	case I_LUMASK:
		umask(n_arg);
		printf("Local umask: %03lo\n", n_arg);
		break;
	case I_CHMOD:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		attrib_clear(&a);
		a.flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
		a.perm = n_arg;
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			if (!quiet)
				mprintf("Changing mode on %s\n",
				    g.gl_pathv[i]);
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &a);
			if (err != 0 && err_abort)
				break;
		}
		break;
	case I_CHOWN:
	case I_CHGRP:
		path1 = make_absolute_pwd_glob(path1, *pwd);
		sftp_glob(conn, path1, GLOB_NOCHECK, NULL, &g);
		for (i = 0; g.gl_pathv[i] && !interrupted; i++) {
			if ((hflag ? sftp_lstat : sftp_stat)(conn,
			    g.gl_pathv[i], 0, &aa) != 0) {
				if (err_abort) {
					err = -1;
					break;
				} else
					continue;
			}
			if (!(aa.flags & SSH2_FILEXFER_ATTR_UIDGID)) {
				error("Can't get current ownership of "
				    "remote file \"%s\"", g.gl_pathv[i]);
				if (err_abort) {
					err = -1;
					break;
				} else
					continue;
			}
			aa.flags &= SSH2_FILEXFER_ATTR_UIDGID;
			if (cmdnum == I_CHOWN) {
				if (!quiet)
					mprintf("Changing owner on %s\n",
					    g.gl_pathv[i]);
				aa.uid = n_arg;
			} else {
				if (!quiet)
					mprintf("Changing group on %s\n",
					    g.gl_pathv[i]);
				aa.gid = n_arg;
			}
			err = (hflag ? sftp_lsetstat : sftp_setstat)(conn,
			    g.gl_pathv[i], &aa);
			if (err != 0 && err_abort)
				break;
		}
		break;
	case I_PWD:
		mprintf("Remote working directory: %s\n", *pwd);
		break;
	case I_LPWD:
		if (!getcwd(path_buf, sizeof(path_buf))) {
			error("Couldn't get local cwd: %s", strerror(errno));
			err = -1;
			break;
		}
		mprintf("Local working directory: %s\n", path_buf);
		break;
	case I_QUIT:
		/* Processed below */
		break;
	case I_HELP:
		help();
		break;
	case I_VERSION:
		printf("SFTP protocol version %u\n", sftp_proto_version(conn));
		break;
	case I_PROGRESS:
		showprogress = !showprogress;
		if (showprogress)
			printf("Progress meter enabled\n");
		else
			printf("Progress meter disabled\n");
		break;
	case I_DEFER:
		/*
		 * Toggle the deferred-wait flag.  When ON, `put` and `get`
		 * return as soon as their submissions hit the queue rather
		 * than blocking until completion, so successive commands
		 * pipeline through the worker pool.
		 *
		 * Transitioning from ON to OFF drains any pending work
		 * first (parallel_flush) - `defer off` is a synchronisation
		 * barrier as well as a state change.  Going ON to ON or OFF
		 * to OFF is a no-op.  With no argument, the current state
		 * is printed.
		 *
		 * Useful in interactive mode where the user wants to queue
		 * several uploads back-to-back without waiting for each to
		 * finish, then synchronise at a chosen point.  In batch mode
		 * the flag starts ON automatically; this command can disable
		 * it mid-batch when the next operations depend on prior ones
		 * having completed.
		 */
		if (path1 == NULL) {
			printf("defer is %s\n",
			    defer_parallel_wait ? "on" : "off");
		} else if (strcasecmp(path1, "on") == 0 ||
		    strcasecmp(path1, "yes") == 0 ||
		    strcmp(path1, "1") == 0) {
			defer_parallel_wait = 1;
			if (!quiet)
				printf("defer on\n");
		} else if (strcasecmp(path1, "off") == 0 ||
		    strcasecmp(path1, "no") == 0 ||
		    strcmp(path1, "0") == 0) {
			if (defer_parallel_wait && parallel_orch != NULL) {
				if (parallel_flush() != 0)
					err = -1;
			}
			defer_parallel_wait = 0;
			if (!quiet)
				printf("defer off\n");
		} else {
			error("defer: argument must be on or off "
			    "(got \"%s\")", path1);
			err = -1;
		}
		break;
	case I_WAIT:
		/* Synchronisation barrier: drain any submissions queued by
		 * deferred put/get commands.  No-op when nothing is in
		 * flight or when the orchestrator isn't running.  Always
		 * safe - independent of the defer flag. */
		if (parallel_orch != NULL) {
			if (parallel_flush() != 0)
				err = -1;
		}
		if (!quiet)
			printf("wait: drained\n");
		break;
	default:
		fatal("%d is not implemented", cmdnum);
	}

	if (g.gl_pathc)
		globfree(&g);
	free(path1);
	free(path2);

	/* If an unignored error occurs in batch mode we should abort. */
	if (err_abort && err != 0)
		return (-1);
	else if (cmdnum == I_QUIT)
		return (1);

	return (0);
}

#ifdef USE_LIBEDIT
static char *
prompt(EditLine *el)
{
	return ("sftp> ");
}

/* Display entries in 'list' after skipping the first 'len' chars */
static void
complete_display(char **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	struct winsize ws;
	char *tmp;

	/* Count entries for sort and find longest */
	for (y = 0; list[y]; y++)
		m = MAXIMUM(m, strlen(list[y]));

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAXIMUM(columns, 1);
	colspace = width / columns;
	colspace = MINIMUM(colspace, width);

	printf("\n");
	m = 1;
	for (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		mprintf("%-*s", colspace, tmp);
		if (m >= columns) {
			printf("\n");
			m = 1;
		} else
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion that extends "word" by the next
 * characters common to all entries in "list".
 */
static char *
complete_ambiguous(const char *word, char **list, size_t count)
{
	size_t i, j, matchlen;
	char *tmp;
	int len;

	if (word == NULL)
		return NULL;

	if (count == 0)
		return xstrdup(word); /* no options to complete */

	/* Find length of common stem across list */
	matchlen = strlen(list[0]);
	for (i = 1; i < count && list[i] != NULL; i++) {
		for (j = 0; j < matchlen; j++)
			if (list[0][j] != list[i][j])
				break;
		matchlen = j;
	}

	/*
	 * Now check that the common stem doesn't finish in the middle of
	 * a multibyte character.
	 */
	mblen(NULL, 0);
	for (i = 0; i < matchlen;) {
		len = mblen(list[0] + i, matchlen - i);
		if (len <= 0 || i + (size_t)len > matchlen)
			break;
		i += (size_t)len;
	}
	/* If so, truncate */
	if (i < matchlen)
		matchlen = i;

	if (matchlen > strlen(word)) {
		tmp = xstrdup(list[0]);
		tmp[matchlen] = '\0';
		return tmp;
	}

	return xstrdup(word);
}

/* Autocomplete a sftp command */
static int
complete_cmd_parse(EditLine *el, char *cmd, int lastarg, char quote,
    int terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	char *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = xcalloc((sizeof(cmds) / sizeof(*cmds)) + 1, sizeof(char *));

	/* No command specified: display all available commands */
	if (cmd == NULL) {
		for (y = 0; cmds[y].c; y++)
			list[count++] = xstrdup(cmds[y].c);

		list[count] = NULL;
		complete_display(list, 0);

		for (y = 0; list[y] != NULL; y++)
			free(list[y]);
		free(list);
		return count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	for (y = 0; cmds[y].c; y++)  {
		if (!strncasecmp(cmd, cmds[y].c, cmdlen))
			list[count++] = xstrdup(cmds[y].c);
	}
	list[count] = NULL;

	if (count == 0) {
		free(list);
		return 0;
	}

	/* Complete ambiguous command */
	tmp = complete_ambiguous(cmd, list, count);
	if (count > 1)
		complete_display(list, 0);

	for (y = 0; list[y]; y++)
		free(list[y]);
	free(list);

	if (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		if (tmplen > cmdlen)
			if (el_insertstr(el, tmp + cmdlen) == -1)
				fatal("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		if (count == 1) {
			y = 0;
			if (!terminated)
				argterm[y++] = quote;
			if (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			if (y > 0 && el_insertstr(el, argterm) == -1)
				fatal("el_insertstr failed.");
		}
		free(tmp);
	}

	return count;
}

/*
 * Determine whether a particular sftp command's arguments (if any) represent
 * local or remote files. The "cmdarg" argument specifies the actual argument
 * and accepts values 1 or 2.
 */
static int
complete_is_remote(char *cmd, int cmdarg) {
	int i;

	if (cmd == NULL)
		return -1;

	for (i = 0; cmds[i].c; i++) {
		if (!strncasecmp(cmd, cmds[i].c, strlen(cmds[i].c))) {
			if (cmdarg == 1)
				return cmds[i].t;
			else if (cmdarg == 2)
				return cmds[i].t2;
			break;
		}
	}

	return -1;
}

/* Autocomplete a filename "file" */
static int
complete_match(EditLine *el, struct sftp_conn *conn, char *remote_path,
    char *file, int remote, int lastarg, char quote, int terminated)
{
	glob_t g;
	char *tmp, *tmp2, ins[8];
	u_int i, hadglob, pwdlen, len, tmplen, filelen, cesc, isesc, isabs;
	int clen;
	const LineInfo *lf;

	/* Glob from "file" location */
	if (file == NULL)
		tmp = xstrdup("*");
	else
		xasprintf(&tmp, "%s*", file);

	/* Check if the path is absolute. */
	isabs = path_absolute(tmp);

	memset(&g, 0, sizeof(g));
	if (remote != LOCAL) {
		tmp = make_absolute_pwd_glob(tmp, remote_path);
		sftp_glob(conn, tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	} else
		(void)glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);

	/* Determine length of pwd so we can trim completion display */
	for (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		if (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			if (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			break;
		}
		if (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		if (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	free(tmp);
	tmp = NULL;

	if (g.gl_matchc == 0)
		goto out;

	if (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	/* Don't try to extend globs */
	if (file == NULL || hadglob)
		goto out;

	tmp2 = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);
	tmp = path_strip(tmp2, isabs ? NULL : remote_path);
	free(tmp2);

	if (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	/* Count the number of escaped characters in the input string. */
	cesc = isesc = 0;
	for (i = 0; i < filelen; i++) {
		if (!isesc && file[i] == '\\' && i + 1 < filelen){
			isesc = 1;
			cesc++;
		} else
			isesc = 0;
	}

	if (tmplen > (filelen - cesc)) {
		tmp2 = tmp + filelen - cesc;
		len = strlen(tmp2);
		/* quote argument on way out */
		mblen(NULL, 0);
		for (i = 0; i < len; i += clen) {
			if ((clen = mblen(tmp2 + i, len - i)) < 0 ||
			    (size_t)clen > sizeof(ins) - 2)
				fatal("invalid multibyte character");
			ins[0] = '\\';
			memcpy(ins + 1, tmp2 + i, clen);
			ins[clen + 1] = '\0';
			switch (tmp2[i]) {
			case '\'':
			case '"':
			case '\\':
			case '\t':
			case '[':
			case ' ':
			case '#':
			case '*':
				if (quote == '\0' || tmp2[i] == quote) {
					if (el_insertstr(el, ins) == -1)
						fatal("el_insertstr "
						    "failed.");
					break;
				}
				/* FALLTHROUGH */
			default:
				if (el_insertstr(el, ins + 1) == -1)
					fatal("el_insertstr failed.");
				break;
			}
		}
	}

	lf = el_line(el);
	if (g.gl_matchc == 1) {
		i = 0;
		if (!terminated && quote != '\0')
			ins[i++] = quote;
		if (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		if (i > 0 && el_insertstr(el, ins) == -1)
			fatal("el_insertstr failed.");
	}
	free(tmp);

 out:
	globfree(&g);
	return g.gl_matchc;
}

/* tab-completion hook function, called via libedit */
static unsigned char
complete(EditLine *el, int ch)
{
	char **argv, *line, quote;
	int argc, carg;
	u_int cursor, len, terminated, ret = CC_ERROR;
	const LineInfo *lf;
	struct complete_ctx *complete_ctx;

	lf = el_line(el);
	if (el_get(el, EL_CLIENTDATA, (void**)&complete_ctx) != 0)
		fatal_f("el_get failed");

	/* Figure out which argument the cursor points to */
	cursor = lf->cursor - lf->buffer;
	line = xmalloc(cursor + 1);
	memcpy(line, lf->buffer, cursor);
	line[cursor] = '\0';
	argv = makeargv(line, &carg, 1, &quote, &terminated);
	free(line);

	/* Get all the arguments on the line */
	len = lf->lastchar - lf->buffer;
	line = xmalloc(len + 1);
	memcpy(line, lf->buffer, len);
	line[len] = '\0';
	argv = makeargv(line, &argc, 1, NULL, NULL);

	/* Ensure cursor is at EOL or a argument boundary */
	if (line[cursor] != ' ' && line[cursor] != '\0' &&
	    line[cursor] != '\n') {
		free(line);
		return ret;
	}

	if (carg == 0) {
		/* Show all available commands */
		complete_cmd_parse(el, NULL, argc == carg, '\0', 1);
		ret = CC_REDISPLAY;
	} else if (carg == 1 && cursor > 0 && line[cursor - 1] != ' ')  {
		/* Handle the command parsing */
		if (complete_cmd_parse(el, argv[0], argc == carg,
		    quote, terminated) != 0)
			ret = CC_REDISPLAY;
	} else if (carg >= 1) {
		/* Handle file parsing */
		int remote = 0;
		int i = 0, cmdarg = 0;
		char *filematch = NULL;

		if (carg > 1 && line[cursor-1] != ' ')
			filematch = argv[carg - 1];

		for (i = 1; i < carg; i++) {
			/* Skip flags */
			if (argv[i][0] != '-')
				cmdarg++;
		}

		/*
		 * If previous argument is complete, then offer completion
		 * on the next one.
		 */
		if (line[cursor - 1] == ' ')
			cmdarg++;

		remote = complete_is_remote(argv[0], cmdarg);

		if ((remote == REMOTE || remote == LOCAL) &&
		    complete_match(el, complete_ctx->conn,
		    *complete_ctx->remote_pathp, filematch,
		    remote, carg == argc, quote, terminated) != 0)
			ret = CC_REDISPLAY;
	}

	free(line);
	return ret;
}
#endif /* USE_LIBEDIT */

static int
interactive_loop(struct sftp_conn *conn, char *file1, char *file2)
{
	char *remote_path;
	char *dir = NULL, *startdir = NULL;
	char cmd[2048];
	int err, interactive;
	EditLine *el = NULL;
#ifdef USE_LIBEDIT
	const char *editor;
	History *hl = NULL;
	HistEvent hev;
	extern char *__progname;
	struct complete_ctx complete_ctx;

	if (!batchmode && isatty(STDIN_FILENO)) {
		if ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
			fatal("Couldn't initialise editline");
		if ((hl = history_init()) == NULL)
			fatal("Couldn't initialise editline history");
		history(hl, &hev, H_SETSIZE, 100);
		el_set(el, EL_HIST, history, hl);

		el_set(el, EL_PROMPT, prompt);
		el_set(el, EL_EDITOR, "emacs");
		el_set(el, EL_TERMINAL, NULL);
		el_set(el, EL_SIGNAL, 1);
		el_source(el, NULL);

		/* Tab Completion */
		el_set(el, EL_ADDFN, "ftp-complete",
		    "Context sensitive argument completion", complete);
		complete_ctx.conn = conn;
		complete_ctx.remote_pathp = &remote_path;
		el_set(el, EL_CLIENTDATA, (void*)&complete_ctx);
		el_set(el, EL_BIND, "^I", "ftp-complete", NULL);
		/* enable ctrl-left-arrow and ctrl-right-arrow */
		el_set(el, EL_BIND, "\\e[1;5C", "em-next-word", NULL);
		el_set(el, EL_BIND, "\\e\\e[C", "em-next-word", NULL);
		el_set(el, EL_BIND, "\\e[1;5D", "ed-prev-word", NULL);
		el_set(el, EL_BIND, "\\e\\e[D", "ed-prev-word", NULL);
		/* make ^w match ksh behaviour */
		el_set(el, EL_BIND, "^w", "ed-delete-prev-word", NULL);

		/* el_source() may have changed EL_EDITOR to vi */
		if (el_get(el, EL_EDITOR, &editor) == 0 && editor[0] == 'v')
			el_set(el, EL_BIND, "^[", "vi-command-mode", NULL);
	}
#endif /* USE_LIBEDIT */

	if ((remote_path = sftp_realpath(conn, ".")) == NULL) {
		/* Distinguish protocol corruption from a generic "no cwd" so
		 * the user knows whether to investigate the server. */
		if (sftp_conn_is_protocol_violation(conn))
			fatal("control connection protocol violation during "
			    "init - possible MITM or server corruption");
		fatal("Need cwd");
	}
	startdir = xstrdup(remote_path);

	if (file1 != NULL) {
		dir = xstrdup(file1);
		dir = sftp_make_absolute(dir, remote_path);

		if (sftp_remote_is_dir(conn, dir) && file2 == NULL) {
			if (!quiet)
				mprintf("Changing to: %s\n", dir);
			snprintf(cmd, sizeof cmd, "cd \"%s\"", dir);
			if (parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0) != 0) {
				/* Early dispatch (pre-interactive_loop): same
				 * fail-stop on protocol violation as the main
				 * loop check at the bottom of interactive_loop. */
				if (sftp_conn_is_protocol_violation(conn))
					fatal("control connection protocol "
					    "violation - possible MITM or "
					    "server corruption");
				free(dir);
				free(startdir);
				free(remote_path);
				free(conn);
				return (-1);
			}
		} else {
			/* XXX this is wrong wrt quoting */
			snprintf(cmd, sizeof cmd, "get%s %s%s%s",
			    global_aflag ? " -a" : "", dir,
			    file2 == NULL ? "" : " ",
			    file2 == NULL ? "" : file2);
			err = parse_dispatch_command(conn, cmd,
			    &remote_path, startdir, 1, 0);
			/* Early dispatch (pre-interactive_loop): same
			 * fail-stop on protocol violation as the main loop. */
			if (sftp_conn_is_protocol_violation(conn))
				fatal("control connection protocol violation "
				    "- possible MITM or server corruption");
			free(dir);
			free(startdir);
			free(remote_path);
			free(conn);
			return (err);
		}
		free(dir);
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(infile, NULL, _IOLBF, 0);

	interactive = !batchmode && isatty(STDIN_FILENO);
	err = 0;
	for (;;) {
		struct sigaction sa;

		interrupted = 0;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = interactive ? read_interrupt : killchild;
		if (sigaction(SIGINT, &sa, NULL) == -1) {
			debug3("sigaction(%s): %s", strsignal(SIGINT),
			    strerror(errno));
			break;
		}
		if (el == NULL) {
			if (interactive) {
				printf("sftp> ");
				fflush(stdout);
			}
			if (fgets(cmd, sizeof(cmd), infile) == NULL) {
				if (interactive)
					printf("\n");
				if (interrupted)
					continue;
				break;
			}
		} else {
#ifdef USE_LIBEDIT
			const char *line;
			int count = 0;

			if ((line = el_gets(el, &count)) == NULL ||
			    count <= 0) {
				printf("\n");
				if (interrupted)
					continue;
				break;
			}
			history(hl, &hev, H_ENTER, line);
			if (strlcpy(cmd, line, sizeof(cmd)) >= sizeof(cmd)) {
				fprintf(stderr, "Error: input line too long\n");
				continue;
			}
#endif /* USE_LIBEDIT */
		}

		cmd[strcspn(cmd, "\n")] = '\0';

		/* Handle user interrupts gracefully during commands */
		interrupted = 0;
		ssh_signal(SIGINT, cmd_interrupt);

		err = parse_dispatch_command(conn, cmd, &remote_path,
		    startdir, batchmode, !interactive && el == NULL);
		if (sftp_conn_is_protocol_violation(conn))
			fatal("control connection protocol violation - "
			    "possible MITM or server corruption");
		if (err != 0)
			break;
	}

	/*
	 * End-of-batch drain.  In deferred mode (batch mode, or a future
	 * interactive "job submission mode") process_put / process_get only
	 * submit to the queue and return; the actual wait happens here.  Safe
	 * to call unconditionally - parallel_flush() is a no-op when no
	 * orchestrator exists or no submissions are outstanding.
	 *
	 * In non-deferred interactive mode this is also safe: each command
	 * already drained itself, so the queue is empty and the wait returns
	 * immediately.
	 */
	if (parallel_flush() != 0)
		err = -1;

	ssh_signal(SIGCHLD, SIG_DFL);
	free(remote_path);
	free(startdir);
	free(conn);

#ifdef USE_LIBEDIT
	if (hl != NULL)
		history_end(hl);
	if (el != NULL)
		el_end(el);
#endif /* USE_LIBEDIT */

	/*
	 * err == 1 signifies normal "quit" exit; err == -1 is a failed
	 * command in batch mode.  Additionally, session_had_failure
	 * captures any parallel_flush failure that interactive mode
	 * intentionally swallowed at the parse_dispatch_command layer.
	 * Either signal forces non-zero exit so the user always knows
	 * when data was lost.
	 */
	if (session_had_failure)
		return (-1);
	return (err >= 0 ? 0 : -1);
}

static void
connect_to_server(char *path, char **args, int *in, int *out)
{
	int c_in, c_out;
#ifdef USE_PIPES
	int pin[2], pout[2];

	if ((pipe(pin) == -1) || (pipe(pout) == -1))
		fatal("pipe: %s", strerror(errno));
	*in = pin[0];
	*out = pout[1];
	c_in = pout[0];
	c_out = pin[1];
#else /* USE_PIPES */
	int inout[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) == -1)
		fatal("socketpair: %s", strerror(errno));
	*in = *out = inout[0];
	c_in = c_out = inout[1];
#endif /* USE_PIPES */

	if ((sshpid = fork()) == -1)
		fatal("fork: %s", strerror(errno));
	else if (sshpid == 0) {
		if ((dup2(c_in, STDIN_FILENO) == -1) ||
		    (dup2(c_out, STDOUT_FILENO) == -1)) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(*in);
		close(*out);
		close(c_in);
		close(c_out);

		/*
		 * The underlying ssh is in the same process group, so we must
		 * ignore SIGINT if we want to gracefully abort commands,
		 * otherwise the signal will make it to the ssh process and
		 * kill it too.  Contrawise, since sftp sends SIGTERMs to the
		 * underlying ssh, it must *not* ignore that signal.
		 */
		ssh_signal(SIGINT, SIG_IGN);
		ssh_signal(SIGTERM, SIG_DFL);
		execvp(path, args);
		fprintf(stderr, "exec: %s: %s\n", path, strerror(errno));
		_exit(1);
	}

	ssh_signal(SIGTERM, killchild);
	ssh_signal(SIGINT, killchild);
	ssh_signal(SIGHUP, killchild);
	ssh_signal(SIGTSTP, suspchild);
	ssh_signal(SIGTTIN, suspchild);
	ssh_signal(SIGTTOU, suspchild);
	ssh_signal(SIGCHLD, sigchld_handler);
	close(c_in);
	close(c_out);

	/* Announce the control ssh child PID so post-mortem diagnostics can
	 * tell it apart from worker PIDs (worker PIDs are logged by the
	 * parallel orchestrator's watchdog as "worker N: ... pid=...").
	 * Useful when investigating control-connection deaths in -j mode. */
	logit("hpnsftp control: ssh child pid=%ld", (long)sshpid);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr,
	    "usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n"
	    "          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n"
	    "          [-J destination] [-j parallel_streams] [-l limit]\n"
	    "          [-M range_split_min_mb] [-o ssh_option] [-P port]\n"
	    "          [-R num_requests] [-S program] [-w writers_per_file]\n"
	    "          [-s subsystem | sftp_server] [-X sftp_option]\n"
	    "          [--bundle-size N[KMG]] destination\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int r, in, out, ch, err, tmp, port = -1, noisy = 0;
	char *host = NULL, *user, *cp, **cpp, *file2 = NULL;
	int debug_level = 0;
	char *file1 = NULL, *sftp_server = NULL;
	char *ssh_program = _PATH_SSH_PROGRAM, *sftp_direct = NULL;
	const char *errstr;
	LogLevel ll = SYSLOG_LEVEL_INFO;
	arglist args;
	extern int optind;
	extern char *optarg;
	struct sftp_conn *conn;
	size_t copy_buffer_len = 0;
	size_t num_requests = 0;
	long long llv, limit_kbps = 0;

	/* Pass-through state for the parallel-streams ControlMaster.
	 * Captured during getopt and forwarded into sftp_parallel_config so
	 * the master and worker connections honor the same -i / -F / -o
	 * options the user gave the main connection. */
	const char *parallel_identity = NULL;
	const char *parallel_config_file = NULL;
	char **parallel_extra_o = NULL;
	size_t parallel_extra_o_count = 0;
	size_t parallel_extra_o_cap = 0;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();
	msetlocale();

	/*
	 * Ignore SIGPIPE process-wide.  Without this, a write to a closed
	 * pipe terminates the entire process - fatal in parallel mode
	 * because a worker thread writing to its (now-dead) ssh child
	 * delivers SIGPIPE to the whole sftp process, killing the control
	 * connection and the orchestrator as collateral damage.  After this
	 * call, those writes return EPIPE which our code already handles.
	 */
	ssh_signal(SIGPIPE, SIG_IGN);

	__progname = ssh_get_progname(argv[0]);
	memset(&args, '\0', sizeof(args));
	args.list = NULL;
	addargs(&args, "%s", ssh_program);
	addargs(&args, "-oForwardX11 no");
	addargs(&args, "-oPermitLocalCommand no");
	addargs(&args, "-oClearAllForwardings yes");
	addargs(&args, "-oControlMaster no");

	ll = SYSLOG_LEVEL_INFO;
	infile = stdin;

	/*
	 * Long-only option pre-scan.  hpnsftp uses the openbsd-compat
	 * BSDgetopt (defines.h macros `optarg` → `BSDoptarg` when
	 * HAVE_GETOPT_OPTRESET is undefined), so a getopt_long() call
	 * from glibc writes its own `optarg` while our code reads
	 * BSDoptarg - they're different symbols.  Easier than wrestling
	 * with that mismatch: pre-scan argv before getopt runs, extract
	 * any `--bundle-size=N[KMG]` or `--bundle-size N[KMG]`, propagate
	 * to the parallel layer via `-oHPNBundleSize=...`, and compact
	 * argv so getopt never sees the flag.
	 */
	{
		int i, j;
		for (i = 1; i < argc; ) {
			const char *arg = argv[i];
			const char *val = NULL;
			int consume = 0;
			if (arg == NULL) { i++; continue; }
			if (strncmp(arg, "--bundle-size=", 14) == 0) {
				val = arg + 14;
				consume = 1;
			} else if (strcmp(arg, "--bundle-size") == 0) {
				if (i + 1 >= argc)
					fatal("--bundle-size requires an "
					    "argument");
				val = argv[i + 1];
				consume = 2;
			}
			if (consume == 0) { i++; continue; }
			{
				long long bsv;
				if (scan_scaled((char *)val, &bsv) == -1)
					fatal("--bundle-size: bad value "
					    "\"%s\": %s",
					    val, strerror(errno));
				if (bsv < (long long)(1 * 1024 * 1024)) {
					fprintf(stderr, "--bundle-size %lld "
					    "is below the minimum (1 MiB); "
					    "clamping to 1 MiB.\n", bsv);
					bsv = 1 * 1024 * 1024;
				} else if (bsv >
				    (long long)(64 * 1024 * 1024)) {
					fprintf(stderr, "--bundle-size %lld "
					    "is above the maximum (64 MiB); "
					    "clamping to 64 MiB.\n", bsv);
					bsv = 64 * 1024 * 1024;
				}
				{
					char buf[64];
					snprintf(buf, sizeof(buf),
					    "HPNBundleSize=%lld", bsv);
					addargs(&args, "-o%s", buf);
					if (parallel_extra_o_count + 2 >
					    parallel_extra_o_cap) {
						parallel_extra_o_cap =
						    parallel_extra_o_cap ?
						    parallel_extra_o_cap * 2
						    : 8;
						parallel_extra_o =
						    xreallocarray(
						    parallel_extra_o,
						    parallel_extra_o_cap,
						    sizeof(*parallel_extra_o));
					}
					parallel_extra_o[
					    parallel_extra_o_count++] =
					    xstrdup(buf);
					parallel_extra_o[
					    parallel_extra_o_count] = NULL;
				}
			}
			/* Shift remaining argv left over the consumed slot(s). */
			for (j = i; j + consume < argc; j++)
				argv[j] = argv[j + consume];
			argc -= consume;
			argv[argc] = NULL;
			/* don't increment i - re-examine the now-shifted slot */
		}
	}

	while ((ch = getopt(argc, argv,
	    "1246AafhNpqrvCc:D:i:j:l:o:s:S:b:B:F:J:M:P:R:W:w:X:")) != -1) {
		switch (ch) {
		/* Passed through to ssh(1) */
		case 'A':
		case '4':
		case '6':
		case 'C':
			addargs(&args, "-%c", ch);
			break;
		/* Passed through to ssh(1) with argument */
		case 'J':
		case 'c':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			break;
		case 'F':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			parallel_config_file = optarg;
			break;
		case 'i':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			parallel_identity = optarg;
			break;
		case 'o':
			addargs(&args, "-%c", ch);
			addargs(&args, "%s", optarg);
			if (parallel_extra_o_count + 2 > parallel_extra_o_cap) {
				parallel_extra_o_cap =
				    parallel_extra_o_cap ?
				    parallel_extra_o_cap * 2 : 8;
				parallel_extra_o = xreallocarray(
				    parallel_extra_o, parallel_extra_o_cap,
				    sizeof(*parallel_extra_o));
			}
			parallel_extra_o[parallel_extra_o_count++] =
			    xstrdup(optarg);
			parallel_extra_o[parallel_extra_o_count] = NULL;
			break;
		case 'q':
			ll = SYSLOG_LEVEL_ERROR;
			quiet = 1;
			showprogress = 0;
			addargs(&args, "-%c", ch);
			break;
		case 'P':
			port = a2port(optarg);
			if (port <= 0)
				fatal("Bad port \"%s\"\n", optarg);
			break;
		case 'v':
			if (debug_level < 3) {
				addargs(&args, "-v");
				ll = SYSLOG_LEVEL_DEBUG1 + debug_level;
			}
			debug_level++;
			break;
		case '1':
			fatal("SSH protocol v.1 is no longer supported");
			break;
		case '2':
			/* accept silently */
			break;
		case 'a':
			global_aflag = 1;
			break;
		case 'B':
			copy_buffer_len = strtol(optarg, &cp, 10);
			if (copy_buffer_len == 0 || *cp != '\0')
				fatal("Invalid buffer size \"%s\"", optarg);
			break;
		case 'b':
			if (batchmode)
				fatal("Batch file already specified.");

			/* Allow "-" as stdin */
			if (strcmp(optarg, "-") != 0 &&
			    (infile = fopen(optarg, "r")) == NULL)
				fatal("%s (%s).", strerror(errno), optarg);
			showprogress = 0;
			quiet = batchmode = 1;
			/*
			 * Batch mode submits commands sequentially from a file.
			 * Deferring the per-command parallel_flush lets multiple
			 * `put`/`get` commands pipeline their files through the
			 * worker pool instead of each command stalling on the
			 * slowest chunk of the previous one.  parallel_flush() is
			 * called once after the command loop exits.
			 */
			defer_parallel_wait = 1;
			addargs(&args, "-obatchmode yes");
			break;
		case 'f':
			global_fflag = 1;
			break;
		case 'N':
			noisy = 1; /* Used to clear quiet mode after getopt */
			break;
		case 'p':
			global_pflag = 1;
			break;
		case 'D':
			sftp_direct = optarg;
			break;
		case 'j':
			parallel_num_streams = (int)strtonum(optarg, 1,
			    SFTP_PARALLEL_MAX_WORKERS, &errstr);
			if (errstr != NULL)
				fatal("Number of parallel streams must be between 1 and %d: \"%s\": %s",
				    SFTP_PARALLEL_MAX_WORKERS,optarg, errstr);
			parallel_user_opt_in = 1;
			break;
		case 'M':
			/* Range-split minimum size (in MiB).  Files at or below
			 * this size are uploaded as whole-file work units; larger
			 * files are split into byte ranges across workers.  Hard
			 * bounded to [64, 10240] MiB so neither degenerate value
			 * can produce pathological behavior (very small => over-
			 * chunking, very large => no parallelism for huge files). */
			range_split_min_mb_user = (int)strtonum(optarg, 64,
			    10240, &errstr);
			if (errstr != NULL)
				fatal("Range-split minimum (-M) must be between "
				    "64 and 10240 MiB: \"%s\": %s",
				    optarg, errstr);
			break;
		case 'w':
			/* Max concurrent range-writers per inode.  Caps how many
			 * range-split workers write one file at once; buffered
			 * multi-writer into a single inode serialises on the
			 * per-inode lock (4 is the measured throughput knee).
			 * Effective cap is min(this, -j). */
			writers_cap_user = (int)strtonum(optarg,
			    HPN_RANGE_WRITERS_CAP_FLOOR,
			    HPN_RANGE_WRITERS_CAP_MAX, &errstr);
			if (errstr != NULL)
				fatal("Concurrent range-writers per inode (-w) "
				    "must be between %d and %d: \"%s\": %s",
				    HPN_RANGE_WRITERS_CAP_FLOOR,
				    HPN_RANGE_WRITERS_CAP_MAX, optarg, errstr);
			break;
		case 'l':
			limit_kbps = strtonum(optarg, 1, 100 * 1024 * 1024,
			    &errstr);
			if (errstr != NULL)
				usage();
			limit_kbps *= 1024; /* kbps */
			break;
		case 'r':
			global_rflag = 1;
			break;
		case 'R':
			num_requests = strtol(optarg, &cp, 10);
			if (num_requests == 0 || *cp != '\0')
				fatal("Invalid number of requests \"%s\"",
				    optarg);
			break;
		case 's':
			sftp_server = optarg;
			break;
		case 'S':
			ssh_program = optarg;
			replacearg(&args, 0, "%s", ssh_program);
			break;
		case 'W':
			/* Per-worker SSH stderr capture directory.  Diagnostic
			 * aid: when set, each parallel worker writes its SSH
			 * child's stderr to <dir>/hpnssh-worker-<pid>.stderr,
			 * giving users a clear per-worker log to send when
			 * reporting failures.  Off by default - production
			 * inherits stderr so connection errors / banners /
			 * warnings reach the user's terminal directly.
			 *
			 * Validates: must be a non-empty path that names a
			 * writable directory.  If the path doesn't exist we
			 * create it (mkdir-p semantics, mode 0755).  Anything
			 * else (missing arg, dash-prefixed token, mkdir
			 * failure, existing path that isn't a directory, no
			 * write access) is fatal - the user typed something
			 * they probably didn't mean. */
			if (optarg == NULL || *optarg == '\0' ||
			    *optarg == '-')
				fatal("-W requires a directory path argument "
				    "(got \"%s\")",
				    optarg ? optarg : "(none)");
			{
				struct stat st;
				if (stat(optarg, &st) != 0) {
					if (errno != ENOENT)
						fatal("-W \"%s\": %s",
						    optarg, strerror(errno));
					if (mkdir_p(optarg, 0755) != 0)
						fatal("-W could not create "
						    "\"%s\": %s",
						    optarg, strerror(errno));
					if (stat(optarg, &st) != 0)
						fatal("-W \"%s\" missing "
						    "after mkdir: %s",
						    optarg, strerror(errno));
				}
				if (!S_ISDIR(st.st_mode))
					fatal("-W \"%s\" is not a directory",
					    optarg);
				if (access(optarg, W_OK | X_OK) != 0)
					fatal("-W \"%s\" not writable: %s",
					    optarg, strerror(errno));
			}
			worker_log_dir = optarg;
			break;
		case 'X':
			/* Please keep in sync with scp.c -X */
			if (strncmp(optarg, "buffer=", 7) == 0) {
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
				copy_buffer_len = (size_t)llv;
			} else if (strncmp(optarg, "nrequests=", 10) == 0) {
				/* more than 10k to 15k requests starts stalling the connection
				 * 8192 * default buffer size is 256MB of outstanding data.
				 * if users need more then they need to up the buffer size */
				llv = strtonum(optarg + 10, 1, 8 * 1024,
					       &errstr);
				if (errstr != NULL) {
					fatal("Invalid number of requests. Must be between 1 and 8192. "
					      "\"%s\": %s", optarg + 10, errstr);
				}
				num_requests = (size_t)llv;
			} else {
				fatal("Invalid -X option");
			}
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* Do this last because we want the user to be able to override it */
	addargs(&args, "-oForwardAgent no");

	if (!isatty(STDERR_FILENO))
		showprogress = 0;

	if (noisy)
		quiet = 0;

	log_init(argv[0], ll, SYSLOG_FACILITY_USER, 1);

	if (sftp_direct == NULL) {
		if (optind == argc || argc > (optind + 2))
			usage();
		argv += optind;

		switch (parse_uri("sftp", *argv, &user, &host, &tmp, &file1)) {
		case -1:
			usage();
			break;
		case 0:
			if (tmp != -1)
				port = tmp;
			break;
		default:
			/* Try with user, host and path. */
			if (parse_user_host_path(*argv, &user, &host,
			    &file1) == 0)
				break;
			/* Try with user and host. */
			if (parse_user_host_port(*argv, &user, &host, NULL)
			    == 0)
				break;
			/* Treat as a plain hostname. */
			host = xstrdup(*argv);
			host = cleanhostname(host);
			break;
		}
		file2 = *(argv + 1);

		if (!*host) {
			fprintf(stderr, "Missing hostname\n");
			usage();
		}

		if (port != -1)
			addargs(&args, "-oPort %d", port);
		if (user != NULL) {
			addargs(&args, "-l");
			addargs(&args, "%s", user);
		}

		/* no subsystem if the server-spec contains a '/' */
		if (sftp_server == NULL || strchr(sftp_server, '/') == NULL)
			addargs(&args, "-s");

		addargs(&args, "--");
		addargs(&args, "%s", host);
		addargs(&args, "%s", (sftp_server != NULL ?
		    sftp_server : "sftp"));

		connect_to_server(ssh_program, args.list, &in, &out);
	} else {
		if ((r = argv_split(sftp_direct, &tmp, &cpp, 1)) != 0)
			fatal_r(r, "Parse -D arguments");
		if (cpp[0] == NULL)
			fatal("No sftp server specified via -D");
		connect_to_server(cpp[0], cpp, &in, &out);
		argv_free(cpp, tmp);
	}
	freeargs(&args);

	conn = sftp_init(in, out, copy_buffer_len, num_requests, limit_kbps);
	if (conn == NULL)
		fatal("Couldn't initialise connection to server");

	if (!quiet) {
		if (sftp_direct == NULL)
			fprintf(stderr, "Connected to %s.\n", host);
		else
			fprintf(stderr, "Attached to %s.\n", sftp_direct);
	}

	/*
	 * Start the parallel-streams orchestrator only when the user
	 * explicitly opted in via -j N.  Without -j, hpnsftp behaves as a
	 * plain single-stream client (no orchestrator, no autotuning) so
	 * default behaviour is identical to upstream sftp.  -j N opts into
	 * the adaptive scaler, treating N as the starting point.
	 *
	 * The master and workers honor the same -i / -F / -o options the
	 * user gave the main connection (captured during getopt above).
	 */
	/*
	 * Capture the orchestrator launch inputs so the fleet can be
	 * re-created after an interrupt (parallel_orch_ensure_alive),
	 * then launch via the shared helper.
	 */
	parallel_launch.host         = host;
	parallel_launch.user         = user;
	parallel_launch.port         = port;
	parallel_launch.ssh_program  = ssh_program;
	parallel_launch.identity     = parallel_identity;
	parallel_launch.config_file  = parallel_config_file;
	parallel_launch.extra_o      = parallel_extra_o;
	parallel_launch.buflen       = copy_buffer_len;
	parallel_launch.num_requests = num_requests;
	parallel_launch.limit_kbps   = limit_kbps;
	parallel_launch.debug_level  = debug_level;
	parallel_launch.valid        = 1;
	if (parallel_user_opt_in && sftp_direct == NULL)
		parallel_orch_launch(conn);

	/*
	 * Resolve HPNVerifyTransfer from ssh_config for the single-stream
	 * transfer paths (the parallel orchestrator resolves it into pcfg
	 * separately).  Safe with a NULL/empty host (returns 0 = off).
	 */
	hpn_verify_transfer = sftp_resolve_hpn_verify_transfer(host,
	    parallel_config_file, parallel_extra_o);
	/*
	 * Propagate HPNVerifyTransfer state onto the connection so the
	 * resume-decision hash callers can flag the hpn-check-file request
	 * as STRICT (no sparse-skip sentinel).  When set, the user has
	 * explicitly asked for maximum verification and shouldn't accept
	 * the size+allocation trust optimisation.
	 */
	sftp_conn_set_verify_transfer(conn, hpn_verify_transfer);

	/*
	 * Propagate HPNLustreStripeCount (EXPERIMENTAL) onto the connection
	 * so the parallel upload-walker's dir-layout decision site can see
	 * it.  Value: -1 = auto (use -j N), 0 = feature off, >0 = explicit.
	 */
	sftp_conn_set_lustre_stripe_count(conn,
	    sftp_resolve_hpn_lustre_stripe_count(host, parallel_config_file,
	        parallel_extra_o));

	err = interactive_loop(conn, file1, file2);

	/*
	 * Fold any parallel post-transfer verify mismatches into the global
	 * verify-failure list (drain transfers ownership of the strings), so
	 * the single end-of-run summary + SFTP_EX_VERIFY_FAILED exit path
	 * covers both single-stream and parallel transfers.  Must run before
	 * sftp_parallel_stop frees the orchestrator.
	 */
	if (parallel_orch != NULL) {
		char  **vpaths = NULL;
		size_t  vused = 0, i;

		(void)sftp_parallel_drain_verify_failures(parallel_orch,
		    &vpaths, &vused);
		for (i = 0; i < vused; i++) {
			verify_fail_list = xreallocarray(verify_fail_list,
			    verify_fail_count + 1, sizeof(*verify_fail_list));
			verify_fail_list[verify_fail_count++] = vpaths[i];
		}
		free(vpaths);
	}

	if (parallel_orch != NULL) {
		sftp_parallel_stop(parallel_orch);
		parallel_orch = NULL;
	}
	if (parallel_extra_o != NULL) {
		for (size_t pi = 0; pi < parallel_extra_o_count; pi++)
			free(parallel_extra_o[pi]);
		free(parallel_extra_o);
		parallel_extra_o = NULL;
	}

#if !defined(USE_PIPES)
	shutdown(in, SHUT_RDWR);
	shutdown(out, SHUT_RDWR);
#endif

	close(in);
	close(out);
	if (batchmode)
		fclose(infile);

	while (waitpid(sshpid, NULL, 0) == -1 && sshpid > 1)
		if (errno != EINTR)
			fatal("Couldn't wait for ssh process: %s",
			    strerror(errno));

	/*
	 * HPNVerifyTransfer: if any file failed post-transfer verification,
	 * print the summary and exit with the distinct SFTP_EX_VERIFY_FAILED
	 * code so automation can detect silent-corruption even though the
	 * transfer itself was not aborted.  This takes precedence over the
	 * generic error code since it flags data integrity specifically.
	 */
	if (verify_print_summary() > 0)
		exit(SFTP_EX_VERIFY_FAILED);

	exit(err == 0 ? 0 : 1);
}
