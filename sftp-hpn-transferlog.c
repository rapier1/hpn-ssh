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
 * sftp-hpn-transferlog.c - per-file transfer log (see the header).
 *
 * One writer guarded by a mutex: lines arrive from the main thread
 * (serial paths, frame consumers), worker threads (parallel
 * completions, verify resolutions), and tracker finalize.  Lines are
 * written when a file's status is FINAL - at completion when no verify
 * phase follows, at verify resolution when one does - so each file
 * appears exactly once.
 */

#include "includes.h"

#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "hpn-status-frame.h"
#include "progressmeter.h"
#include "sftp-hpn-transferlog.h"

static int tl_want;			/* option given; open at begin() */
static char *tl_path;			/* NULL = default location */
static FILE *tl_out;
static int tl_frames;			/* mirror statuses as FILEDONE frames */
static pthread_mutex_t tl_mu = PTHREAD_MUTEX_INITIALIZER;
static double tl_start;
static unsigned long long tl_files, tl_bytes;

static const char *
status_word(enum transferlog_status st)
{
	switch (st) {
	case TRANSFERLOG_SUCCESS:	return "success";
	case TRANSFERLOG_SKIPPED:	return "skipped";
	case TRANSFERLOG_VERIFIED:	return "verified";
	case TRANSFERLOG_REPAIRED:	return "repaired";
	case TRANSFERLOG_FAILED:	return "failed";
	}
	return "unknown";
}

int
transferlog_option(const char *opt)
{
	static const char key[] = "transferlog";
	const size_t klen = sizeof(key) - 1;

	if (strncasecmp(opt, key, klen) != 0)
		return 0;
	opt += klen;
	if (*opt != '\0' && *opt != '=' && *opt != ' ' && *opt != '\t')
		return 0;	/* a different option with this prefix */
	while (*opt == '=' || *opt == ' ' || *opt == '\t')
		opt++;
	tl_want = 1;
	free(tl_path);
	tl_path = *opt != '\0' ? xstrdup(opt) : NULL;
	return 1;
}

void
transferlog_begin(void)
{
	const char *path;
	char stamp[64];
	time_t now;
	struct tm *tm;

	if (!tl_want || tl_out != NULL)
		return;
	path = tl_path != NULL ? tl_path : "./hpnssh-transfer.log";
	/* The open IS the early writability check: callers run this before
	 * any connection is established, so an unwritable target fails the
	 * run before work starts, per the option's contract. */
	if ((tl_out = fopen(path, "a")) == NULL)
		fatal("TransferLog \"%s\": %s", path, strerror(errno));
	tl_start = monotime_double();
	now = time(NULL);
	if ((tm = localtime(&now)) != NULL &&
	    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S%z", tm) > 0)
		fprintf(tl_out, "# hpnssh transfer log - run started %s\n",
		    stamp);
	fflush(tl_out);
}

void
transferlog_frames(int on)
{
	tl_frames = on;
}

int
transferlog_active(void)
{
	return tl_out != NULL || tl_frames;
}

/* shared line writer; caller guarantees path is display-safe */
static void
write_line(enum transferlog_status st, long long size, const char *path)
{
	if (tl_out == NULL)
		return;
	pthread_mutex_lock(&tl_mu);
	fprintf(tl_out, "%s\t%lld\t%s\n", status_word(st), size,
	    path != NULL ? path : "(unknown)");
	tl_files++;
	if (size > 0)
		tl_bytes += (unsigned long long)size;
	pthread_mutex_unlock(&tl_mu);
}

void
transferlog_file(enum transferlog_status st, long long size, const char *path)
{
	write_line(st, size, path);
	/* Source side of a relay armed with "log": mirror the status as a
	 * FILEDONE frame for the consumer's log / GUI file list. */
	if (tl_frames && path != NULL)
		hpn_pm_filedone((u_int)st, size, path,
		    strlen(path));
}

/*
 * Percent-encode helper for remote path bytes, sibling of the encoder in
 * hpn3scp-proto.c: every byte outside a fixed safe printable-ASCII set
 * becomes %XX, so terminal escapes and raw multibyte can never reach a
 * display through the log.
 */
static int
pct_safe(u_char c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '.' || c == '_' || c == '-' || c == ':' ||
	    c == '/' || c == '@' || c == '+');
}

void
transferlog_file_bytes(enum transferlog_status st, long long size,
    const u_char *path, size_t path_len)
{
	static const char hex[] = "0123456789ABCDEF";
	char enc[2048];		/* >= 3 * max frame path + 1, all escaped */
	size_t i, o = 0;

	for (i = 0; i < path_len && o + 4 < sizeof(enc); i++) {
		u_char c = path[i];

		if (pct_safe(c))
			enc[o++] = (char)c;
		else {
			enc[o++] = '%';
			enc[o++] = hex[c >> 4];
			enc[o++] = hex[c & 0x0f];
		}
	}
	enc[o] = '\0';
	write_line(st, size, enc);
}

enum transferlog_status
transferlog_status_from_wire(u_char wire)
{
	switch (wire & HPNS_FD_STATUSMASK) {
	case HPNS_FD_SUCCESS:	return TRANSFERLOG_SUCCESS;
	case HPNS_FD_SKIPPED:	return TRANSFERLOG_SKIPPED;
	case HPNS_FD_VERIFIED:	return TRANSFERLOG_VERIFIED;
	case HPNS_FD_REPAIRED:	return TRANSFERLOG_REPAIRED;
	case HPNS_FD_FAILED:	return TRANSFERLOG_FAILED;
	}
	return TRANSFERLOG_FAILED;	/* unknown: fail closed */
}

void
transferlog_close(void)
{
	double elapsed;

	if (tl_out == NULL)
		return;
	elapsed = monotime_double() - tl_start;
	pthread_mutex_lock(&tl_mu);
	fprintf(tl_out, "total: %llu files, %llu bytes, %.1f seconds\n",
	    tl_files, tl_bytes, elapsed);
	fclose(tl_out);
	tl_out = NULL;
	pthread_mutex_unlock(&tl_mu);
}
