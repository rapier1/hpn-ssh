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

/* sftp-hpn-transferlog.c - the per-file transfer log. What it is for is in
 * sftp-hpn-transferlog.h.
 *
 * One writer behind a mutex serves every thread that finishes a file: the
 * main thread on the serial paths and for frame consumers such as hpn3scp,
 * the parallel workers for completions and verify results, and the
 * tracker's finalize. A line is written only once a file's status is
 * final, so each file appears exactly once. That is at completion when no
 * verify phase follows, and at the verify result when one does. */

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* Claim a -X option if it is TransferLog or TransferLog=path, and
 * remember it for begin(). Returns 1 if claimed and 0 otherwise. A
 * claimed option is not forwarded, since the log belongs to this host. */
int
transferlog_option(const char *opt)
{
	const char *path = NULL;

	if (strncasecmp(opt, "TransferLog=", 12) == 0) {
		path = opt + 12;
		if (*path == '\0')
			fatal("Missing TransferLog path");
	} else if (strcasecmp(opt, "TransferLog") != 0)
		return 0;
	tl_want = 1;
	free(tl_path);
	tl_path = NULL;
	if (path != NULL)
		tl_path = xstrdup(path);
	return 1;
}

/* Open the log for appending and write the run's start line, if
 * TransferLog was given. A failed open is fatal. Calling it again does
 * nothing. */
void
transferlog_begin(void)
{
	const char *path;
	char stamp[64];
	int fd;

	if (!tl_want || tl_out != NULL)
		return;
	path = "./hpnssh-transfer.log";
	if (tl_path != NULL)
		path = tl_path;
	/* The open is the early writability check. Callers run this before
	 * any connection is established, so an unwritable target fails the
	 * run before work starts. */
	if ((fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0600)) == -1 ||
	    (tl_out = fdopen(fd, "a")) == NULL)
		fatal("TransferLog \"%s\": %s", path, strerror(errno));
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
 * on. path is local text and is written as given. */
void
transferlog_file(enum hpns_fd_status status, off_t size, const char *path)
{
	write_line(status, size, path);
	/* On the source side of a relay armed with "log", mirror the status
	 * as a FILEDONE frame for the consumer's log or GUI file list. */
	if (tl_frames && path != NULL)
		hpn_pm_filedone(status, size, path, strlen(path));
}

/* Write the log line for a file a remote source reported in a FILEDONE
 * frame. The path is remote bytes, so it is percent-encoded before it
 * reaches the log. */
void
transferlog_file_bytes(enum hpns_fd_status status, off_t size,
    const u_char *path, size_t path_len)
{
	char enc[3 * HPNS_FILEDONE_MAXPATH + 1];	/* every byte as %XX */

	hpns_pct_encode(enc, sizeof(enc), path, path_len);
	write_line(status, size, enc);
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

/* Write the run's footer and close the log. Does nothing if the log
 * is not open, so a second call is harmless. */
void
transferlog_close(void)
{
	double elapsed;

	pthread_mutex_lock(&tl_mu);
	if (tl_out != NULL) {
		elapsed = monotime_double() - tl_start;
		fprintf(tl_out, "total: %d files, %llu bytes, %.1f seconds\n",
		    tl_files, (unsigned long long)tl_bytes, elapsed);
		fclose(tl_out);
		tl_out = NULL;
	}
	pthread_mutex_unlock(&tl_mu);
}
