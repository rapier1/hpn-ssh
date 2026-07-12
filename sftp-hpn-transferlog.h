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
 * sftp-hpn-transferlog.h - per-file transfer log (-oTransferLog).
 *
 * Observability ONLY: one tab-delimited line per file with its final
 * status, ending with a run footer carrying the total time.  Nothing
 * ever reads this file back to decide whether to skip transfer or
 * verification work, so tampering or staleness cannot affect integrity
 * behavior (the property that distinguishes it from the rejected
 * resume sidecar - see project_transfer_log).
 *
 * Two producers feed one line writer: the local collection sites (the
 * process moving the data), and - on a relay consumer such as hpn3scp
 * or the hpnscp -R launcher - FILEDONE frames from the remote source.
 * A source armed with HPN_ENABLE_REMOTE_PROGRESS=log mirrors every
 * final status as a FILEDONE frame (transferlog_frames).
 */

#ifndef SFTP_HPN_TRANSFERLOG_H
#define SFTP_HPN_TRANSFERLOG_H

#include <sys/types.h>

/* Per-file final status, most specific wins.  repaired and verified
 * imply the transfer itself succeeded.  Values double as the FILEDONE
 * wire encoding (HPNS_FD_*); transferlog_status_from_wire maps back. */
enum transferlog_status {
	TRANSFERLOG_SUCCESS = 0,	/* transferred */
	TRANSFERLOG_SKIPPED = 1,	/* resume: identical / target larger */
	TRANSFERLOG_VERIFIED = 2,	/* transferred + post-verify matched */
	TRANSFERLOG_REPAIRED = 3,	/* verify mismatch spliced good */
	TRANSFERLOG_FAILED = 4		/* transfer or verification failed */
};

/*
 * Consume "-o TransferLog[=path]" (key case-insensitive; '=' or blank
 * separated; no value = default ./hpnssh-transfer.log).  Returns 1 when
 * the argument was TransferLog - the caller must NOT forward it to ssh,
 * which would reject the unknown keyword.
 */
int	transferlog_option(const char *opt);

/*
 * When the option was given, open the log (append) and write the run
 * header.  fatal()s on an unwritable target - callers invoke this
 * EARLY, before any connection is established, so a bad path fails the
 * run before work starts.  No-op when the option was not given.
 */
void	transferlog_begin(void);

/* Source side: mirror every final status as a FILEDONE frame (armed
 * when the relay consumer requested the "log" env value). */
void	transferlog_frames(int on);

/* Is any sink (file or frames) armed?  Callers may skip status
 * bookkeeping cost (stats) when off. */
int	transferlog_active(void);

/* One file's final line: status TAB size TAB path.  Thread-safe.
 * path is LOCAL text (our own argv/paths), written as-is. */
void	transferlog_file(enum transferlog_status st, long long size,
	    const char *path);

/*
 * Consumer-side variant: path is OPAQUE REMOTE bytes (a FILEDONE
 * payload) and is percent-encoded before it lands in the log - log
 * files get displayed (cat), so remote bytes are neutralized with the
 * same discipline as every other frame consumer.  Never re-emits
 * frames.
 */
void	transferlog_file_bytes(enum transferlog_status st, long long size,
	    const u_char *path, size_t path_len);

/* Map a FILEDONE wire status byte to the enum (flag bits masked off);
 * unknown values map to TRANSFERLOG_FAILED (fail-closed for display). */
enum transferlog_status transferlog_status_from_wire(u_char wire);

/* Write the run footer (totals + elapsed seconds) and close. */
void	transferlog_close(void);

#endif /* SFTP_HPN_TRANSFERLOG_H */
