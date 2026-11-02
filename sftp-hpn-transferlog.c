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

/* sftp-hpn-transferlog.c - the per-file transfer log and the failure log.
 * What they are for is in sftp-hpn-transferlog.h.
 *
 * One writer behind a mutex serves every thread that finishes a file: the
 * main thread on the serial paths and for frame consumers such as hpn3scp,
 * the parallel workers for completions and verify results, and the
 * tracker's finalize. A line is written only once a file's status is
 * final, so each file appears exactly once. That is at completion when no
 * verify phase follows, and at the verify result when one does. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "hpn-status-frame.h"
#include "hpn-progressmeter.h"
#include "sftp-hpn-transferlog.h"

/* The log's state. option(), begin(), and frames() set it up before any
 * worker starts. tl_mu then serializes the line writes, the footer
 * counters, and close(). */
static int tl_want;			/* option given, open at begin() */
static char *tl_path;			/* NULL = default location */
static FILE *tl_out;			/* NULL until begin() opens it */
static int tl_frames;			/* mirror statuses as FILEDONE frames */
static pthread_mutex_t tl_mu = PTHREAD_MUTEX_INITIALIZER;
static double tl_start;			/* monotonic start, for the footer */
static int tl_files;			/* lines written, for the footer */
static uint64_t tl_bytes;		/* their sizes, for the footer */
static int tl_begun;			/* begin() has run */

/* The failure log's state, under tl_mu like the rest. option(),
 * failure_config(), and begin() set it up. The file is created at the
 * first failure, and an open or write error closes it for the rest of
 * the run. */
static int fl_want;			/* asked for by -X or HPNFailureLog */
static char *fl_path;			/* the -X path, then the resolved one */
static int fl_ready;			/* fl_path is resolved and usable */
static FILE *fl_out;			/* NULL until the first failure */
static int fl_dead;			/* open or write failed, stop trying */
static int fl_failures;			/* failures seen, logged or not */
static int fl_conn_lost;		/* the connection-lost line is done */

/* Claim -X name or -X name=path for one of the logs, setting *want and
 * *path. A path must be non-empty and free of control characters, so it
 * can always be printed on one line. Returns 1 if claimed. */
static int
claim_log_option(const char *opt, const char *name, int *want, char **path)
{
	size_t len = strlen(name);
	const u_char *p;

	if (strncasecmp(opt, name, len) != 0 ||
	    (opt[len] != '\0' && opt[len] != '='))
		return 0;
	free(*path);
	*path = NULL;
	if (opt[len] == '=') {
		if (opt[len + 1] == '\0')
			fatal("Missing %s path", name);
		for (p = (const u_char *)opt + len + 1; *p != '\0'; p++)
			if (*p < 0x20 || *p == 0x7f)
				fatal("%s path contains a control character",
				    name);
		*path = xstrdup(opt + len + 1);
	}
	*want = 1;
	return 1;
}

/* Claim a -X option if it is TransferLog or FailureLog, with or without
 * =path, and remember it for begin(). Returns 1 if claimed and 0
 * otherwise. A claimed option is not forwarded, since the logs belong to
 * this host. */
int
transferlog_option(const char *opt)
{
	return claim_log_option(opt, "TransferLog", &tl_want, &tl_path) ||
	    claim_log_option(opt, "FailureLog", &fl_want, &fl_path);
}

/* The file a log goes to: stem.PID.log in the current directory without
 * a path, the same name inside a directory, or else the path itself. The
 * PID keeps runs in one directory from sharing a log. */
static char *
resolve_log_path(const char *given, const char *stem)
{
	struct stat sb;
	char *path;

	if (given == NULL)
		xasprintf(&path, "%s.%ld.log", stem, (long)getpid());
	else if (stat(given, &sb) == 0 && S_ISDIR(sb.st_mode))
		xasprintf(&path, "%s/%s.%ld.log", given, stem,
		    (long)getpid());
	else
		path = xstrdup(given);
	return path;
}

/* Open a log for appending, mode 0600. It takes neither a symlink nor
 * anything but a regular file, so one planted under a predictable name in
 * a shared directory cannot redirect or stall the writes. O_NONBLOCK only
 * keeps the open from waiting on a FIFO. Returns NULL with *why set on
 * failure. */
static FILE *
open_log(const char *path, const char **why)
{
	struct stat sb;
	FILE *f;
	int fd, flags = O_WRONLY|O_CREAT|O_APPEND|O_NONBLOCK;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	if ((fd = open(path, flags, 0600)) == -1) {
		*why = strerror(errno);
		return NULL;
	}
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
		*why = "not a regular file";
		close(fd);
		return NULL;
	}
	if ((flags = fcntl(fd, F_GETFL)) != -1)
		(void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	if ((f = fdopen(fd, "a")) == NULL) {
		*why = strerror(errno);
		close(fd);
		return NULL;
	}
	return f;
}

/* Work out where the failure log goes. The path is made absolute, so a
 * later lcd in hpnsftp cannot move it. A directory that cannot be written
 * is reported now and the log stays off, since the transfer is still
 * worth running. */
static void
failure_log_setup(void)
{
	char cwd[PATH_MAX], *path, *abs, *dir, *slash;

	path = resolve_log_path(fl_path, "hpnssh-transfer-failure");
	if (*path != '/' && getcwd(cwd, sizeof(cwd)) != NULL) {
		xasprintf(&abs, "%s/%s", cwd, path);
		free(path);
		path = abs;
	}
	free(fl_path);
	fl_path = path;
	fl_ready = 1;
	dir = xstrdup(path);
	if ((slash = strrchr(dir, '/')) == NULL)
		strlcpy(dir, ".", strlen(dir) + 1);
	else if (slash == dir)
		slash[1] = '\0';
	else
		*slash = '\0';
	if (access(dir, W_OK) != 0) {
		error("FailureLog \"%s\": %s. Failed transfers will not be "
		    "recorded.", fl_path, strerror(errno));
		fl_dead = 1;
	}
	free(dir);
}

/* Turn the failure log on from ssh_config (HPNFailureLog). "no" leaves an
 * -X FailureLog on. The callers read ssh_config after begin() has run, so
 * the log is set up here when that has happened. */
void
transferlog_failure_config(int on)
{
	if (!on || fl_want)
		return;
	fl_want = 1;
	if (tl_begun)
		failure_log_setup();
}

/* Open the TransferLog and write the run's start line, if it was asked
 * for, and work out where the failure log goes, if that was. A
 * TransferLog that cannot be opened is fatal. Calling it again does
 * nothing. */
void
transferlog_begin(void)
{
	const char *why;
	char *path, stamp[64];

	if (tl_begun)
		return;
	tl_begun = 1;
	if (fl_want)
		failure_log_setup();
	if (!tl_want)
		return;
	/* The open is the early writability check. Callers run this before
	 * any connection is established, so an unwritable target fails the
	 * run before work starts. */
	path = resolve_log_path(tl_path, "hpnssh-transfer");
	if ((tl_out = open_log(path, &why)) == NULL)
		fatal("TransferLog \"%s\": %s", path, why);
	free(path);
	tl_start = monotime_double();
	format_absolute_time(time(NULL), stamp, sizeof(stamp));
	fprintf(tl_out, "# hpnssh transfer log - run started %s\n", stamp);
	fflush(tl_out);
}

/* Turn the FILEDONE mirror on or off. A source started by a relay
 * consumer turns it on, and then sends every final status as a FILEDONE
 * frame for the consumer's log. */
void
transferlog_frames(int on)
{
	tl_frames = on;
}

/* Returns 1 if either sink is armed, the log file or the FILEDONE
 * mirror, and 0 otherwise. Callers use it to skip the status work a
 * line needs when nothing would record it. */
int
transferlog_active(void)
{
	return tl_out != NULL || tl_frames;
}

/* Write one log line and add it to the footer counts. The caller has
 * already made path safe to display. A NULL path is written as
 * "(unknown)". */
static void
write_line(enum hpns_fd_status status, off_t size, const char *path)
{
	if (path == NULL)
		path = "(unknown)";
	pthread_mutex_lock(&tl_mu);
	if (tl_out != NULL) {
		fprintf(tl_out, "%s\t%lld\t%s\n",
		    hpns_fd_status_word(status), (long long)size, path);
		tl_files++;
		if (size > 0)
			tl_bytes += (uint64_t)size;
	}
	pthread_mutex_unlock(&tl_mu);
}

/* Record one file's final status. The line goes to the log if it is
 * open, and to the relay consumer as a FILEDONE frame if the mirror is
 * on. path is local text. The frame carries it as given, and the log line
 * percent-encodes it, so a tab, newline, or control byte in a file name
 * can neither split the line nor reach a terminal raw. */
void
transferlog_file(enum hpns_fd_status status, off_t size, const char *path)
{
	char enc[3 * PATH_MAX + 1];	/* every byte as %XX */

	if (tl_out != NULL) {
		if (path == NULL)
			write_line(status, size, NULL);
		else {
			hpns_pct_encode(enc, sizeof(enc), (const u_char *)path,
			    strlen(path));
			write_line(status, size, enc);
		}
	}
	/* On the source side of a relay armed with "log", mirror the status
	 * as a FILEDONE frame for the consumer's log or GUI file list. */
	if (tl_frames && path != NULL)
		hpn_pm_filedone(status, size, path, strlen(path));
}

/* A text field for a failure-log line, escaped with strnvis(3) so a tab,
 * newline, or control byte reaches neither the line nor a terminal raw.
 * NULL becomes "(unknown)". The caller frees it. */
static char *
failure_field(const char *text)
{
	size_t len;
	char *out;

	if (text == NULL || *text == '\0')
		return xstrdup("(unknown)");
	len = 4 * strlen(text) + 1;
	out = xmalloc(len);
	(void)strnvis(out, text, len, VIS_OCTAL|VIS_TAB|VIS_NL);
	return out;
}

/* Write one failure-log line of direction, source, destination, and
 * reason. The first line creates the log, with a header, and says where
 * it is. An open or write error closes it, says so once, and the
 * transfer carries on. A failure is counted even when the log is off, for
 * the note transferlog_close() prints. The connection-lost line is
 * written once per run and is not counted. */
static void
write_failure(enum transferlog_dir dir, const char *src, const char *dst,
    const char *reason, int conn_lost)
{
	static const char *dirword[] = {
		"download", "upload", "crossload", "third-party"
	};
	char *esrc, *edst, *ereason, stamp[64];
	const char *why = NULL;
	int opened = 0, failed = 0;

	esrc = failure_field(src);
	edst = failure_field(dst);
	ereason = failure_field(reason);
	pthread_mutex_lock(&tl_mu);
	if (conn_lost) {
		if (fl_conn_lost)
			goto out;
		fl_conn_lost = 1;
	} else
		fl_failures++;
	if (!fl_want || !fl_ready || fl_dead)
		goto out;
	if (fl_out == NULL) {
		if ((fl_out = open_log(fl_path, &why)) == NULL) {
			fl_dead = 1;
			goto out;
		}
		opened = 1;
		format_absolute_time(time(NULL), stamp, sizeof(stamp));
		fprintf(fl_out, "# hpnssh transfer failure log - pid %ld, "
		    "run started %s\n", (long)getpid(), stamp);
	}
	if (fprintf(fl_out, "%s\t%s\t%s\t%s\n", dirword[dir], esrc, edst,
	    ereason) < 0 || fflush(fl_out) != 0) {
		why = strerror(errno);
		(void)fclose(fl_out);
		fl_out = NULL;
		fl_dead = 1;
		failed = 1;
	}
 out:
	pthread_mutex_unlock(&tl_mu);
	free(esrc);
	free(edst);
	free(ereason);
	/* Report outside the lock, since logging takes its own. */
	if (opened)
		logit("Recording failed transfers in \"%s\"", fl_path);
	if (why != NULL)
		error("FailureLog \"%s\": %s. %s", fl_path, why, failed ?
		    "Later failures will not be recorded." :
		    "Failed transfers will not be recorded.");
}

/* Record a path that should have been transferred and was not. */
void
transferlog_failure(enum transferlog_dir dir, const char *src,
    const char *dst, const char *reason)
{
	write_failure(dir, src, dst, reason, 0);
}

/* Record a directory or a whole tree that failed: a failed TransferLog
 * line for dst and a failure-log line. */
void
transferlog_tree_failure(enum transferlog_dir dir, const char *src,
    const char *dst, const char *reason)
{
	transferlog_file(HPNS_FD_FAILED, -1, dst);
	write_failure(dir, src, dst, reason, 0);
}

/* Record that a connection died and ended the transfer early. */
void
transferlog_connection_lost(enum transferlog_dir dir, const char *src,
    const char *dst)
{
	write_failure(dir, src, dst, "connection lost", 1);
}

/* Write the log line for a file a remote source reported in a FILEDONE
 * frame. The path is remote bytes, so it is percent-encoded before it
 * reaches the log. A failure also goes to the failure log, with what the
 * frame carries, which is no source and no reason. */
void
transferlog_file_bytes(enum hpns_fd_status status, off_t size,
    const u_char *path, size_t path_len)
{
	char enc[3 * HPNS_FILEDONE_MAXPATH + 1];	/* every byte as %XX */

	hpns_pct_encode(enc, sizeof(enc), path, path_len);
	write_line(status, size, enc);
	if (status == HPNS_FD_FAILED)
		write_failure(TRANSFERLOG_THIRDPARTY, NULL, enc, NULL, 0);
}

/* Map a FILEDONE status byte to its status, ignoring the flag bits. An
 * unknown value maps to HPNS_FD_FAILED, so a status the consumer cannot
 * read is never logged as a success. */
enum hpns_fd_status
transferlog_status_from_wire(u_char wire)
{
	u_char status = wire & HPNS_FD_STATUSMASK;

	if (status >= HPNS_FD_COUNT)
		return HPNS_FD_FAILED;	/* unknown: fail closed */
	return (enum hpns_fd_status)status;
}

/* Write each log's footer and close it, then say how many transfers
 * failed and where they are recorded. With the failure log off, point at
 * the switch. Closing logs that are not open does nothing, so a second
 * call is harmless. */
void
transferlog_close(void)
{
	double elapsed;
	int failures, recorded, wanted;

	pthread_mutex_lock(&tl_mu);
	if (tl_out != NULL) {
		elapsed = monotime_double() - tl_start;
		fprintf(tl_out, "total: %d files, %llu bytes, %.1f seconds\n",
		    tl_files, (unsigned long long)tl_bytes, elapsed);
		fclose(tl_out);
		tl_out = NULL;
	}
	recorded = fl_out != NULL;
	if (fl_out != NULL) {
		fprintf(fl_out, "total: %d failed\n", fl_failures);
		fclose(fl_out);
		fl_out = NULL;
	}
	failures = fl_failures;
	wanted = fl_want;
	fl_failures = 0;
	fl_conn_lost = 0;
	pthread_mutex_unlock(&tl_mu);

	/* A log with no failures counted holds only the connection-lost
	 * line, since nothing else creates it. */
	if (recorded && failures == 0)
		logit("The lost connection is recorded in \"%s\"", fl_path);
	else if (recorded)
		logit("%d failed transfer%s recorded in \"%s\"", failures,
		    failures == 1 ? "" : "s", fl_path);
	else if (failures > 0 && !wanted)
		logit("%d transfer%s failed. -X FailureLog records each one.",
		    failures, failures == 1 ? "" : "s");
}
