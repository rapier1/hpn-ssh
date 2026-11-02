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

/* sftp-hpn-transferlog.h - per-file transfer log (-X TransferLog) and
 * failure log (-X FailureLog).
 *
 * The transfer log is for observation only. It holds one tab-delimited
 * line per file with its final status, between a start line and a footer
 * that gives the file count, byte total, and elapsed time. Nothing ever
 * reads the file back to decide whether to skip transfer or verification
 * work, so tampering or staleness cannot affect integrity behavior.
 *
 * The failure log is for a person to read after a long run nobody
 * watched. It holds one tab-delimited line for each path that should
 * have been transferred and was not: the direction, the source and
 * destination paths, and the reason, which is the error the transfer
 * printed. A directory that could not be read or created is one line,
 * which stands for everything below it. A connection that dies and ends
 * the transfer early adds one line, the first time only. Retries, work
 * passed between workers, and an interrupt are not failures. The file is
 * created at the first failure, and its footer gives the failure count.
 *
 * Two producers feed one line writer. The first is the process moving
 * the data, which writes a line as each file's status becomes final.
 * The second is a relay consumer, such as hpn3scp or the hpnscp -R
 * launcher, which writes a line for each FILEDONE frame from the remote
 * source. A source armed with HPN_ENABLE_REMOTE_PROGRESS=log mirrors
 * every final status as a FILEDONE frame (transferlog_frames). */

#ifndef SFTP_HPN_TRANSFERLOG_H
#define SFTP_HPN_TRANSFERLOG_H

#include <sys/types.h>

#include "hpn-status-frame.h"	/* enum hpns_fd_status */

/* The direction a failure-log line names. */
enum transferlog_dir {
	TRANSFERLOG_DOWNLOAD,
	TRANSFERLOG_UPLOAD,
	TRANSFERLOG_CROSSLOAD,
	TRANSFERLOG_THIRDPARTY
};

/* Claim "-X TransferLog[=path]" or "-X FailureLog[=path]", with the name
 * matched case-insensitively. Without a path a log goes to
 * ./hpnssh-transfer.<PID>.log or ./hpnssh-transfer-failure.<PID>.log, and
 * a directory gets that name inside it. An empty path or one with a
 * control character is fatal. Returns 1 if claimed, so the caller does
 * not forward it, and 0 otherwise. */
int	transferlog_option(const char *);

/* Turn the failure log on from ssh_config (HPNFailureLog). Off does not
 * undo -X FailureLog. Safe to call before or after transferlog_begin(). */
void	transferlog_failure_config(int);

/* Work out where the failure log goes, if it is on. A directory that
 * cannot be written is reported and leaves it off. Then, if TransferLog
 * was given, open that log for appending and write the run's start line.
 * An unwritable target, a symlink, or anything but a regular file is
 * fatal, so callers run this before any connection is made and a bad
 * path fails the run before any work starts. A second call does
 * nothing. */
void	transferlog_begin(void);

/* Turn the FILEDONE mirror on or off. A source started by a relay
 * consumer that asked for the "log" value of HPN_ENABLE_REMOTE_PROGRESS
 * turns it on, and then sends every final status to the consumer as a
 * FILEDONE frame. */
void	transferlog_frames(int);

/* Returns 1 if the log file or the FILEDONE mirror is on, and 0
 * otherwise. Callers use it to skip the work a status line needs, such
 * as a stat for the size, and a relay launcher uses it to decide whether
 * to ask its source for FILEDONE frames. */
int	transferlog_active(void);

/* Record one file's final status as a line of status, size, and path,
 * separated by tabs. The path is local text from our own arguments, and
 * the log line percent-encodes it. A NULL path is written as "(unknown)"
 * and is not mirrored. When the FILEDONE mirror is on, the status also
 * goes to the relay consumer. Safe to call from any thread. */
void	transferlog_file(enum hpns_fd_status, off_t, const char *);

/* The relay consumer's form, for a file a remote source reported in a
 * FILEDONE frame. The path is opaque remote bytes with a length. It is
 * percent-encoded before it reaches the log, because log files get
 * displayed and remote bytes must never reach a terminal raw. A failed
 * status also goes to the failure log as a third-party line, with no
 * source or reason, since the frame carries neither. This never sends a
 * frame of its own. */
void	transferlog_file_bytes(enum hpns_fd_status, off_t, const u_char *,
	    size_t);

/* Map a FILEDONE status byte to its status, flag bits masked off. An
 * unknown value maps to HPNS_FD_FAILED, so it is never logged as a
 * success. */
enum hpns_fd_status transferlog_status_from_wire(u_char);

/* Record a path that should have been transferred and was not, with its
 * direction, source and destination, and the reason. The line goes to
 * the failure log if that is on, and the failure is counted either way.
 * A NULL field is written as "(unknown)". Safe to call from any thread. */
void	transferlog_failure(enum transferlog_dir, const char *, const char *,
	    const char *);

/* The same for a directory or a whole tree that failed, which also gets
 * a failed TransferLog line for the destination. */
void	transferlog_tree_failure(enum transferlog_dir, const char *,
	    const char *, const char *);

/* Record that a connection died and ended the transfer early, for the
 * transfer of src to dst that was running. Only the first call in a run
 * writes a line, and it is not counted as a failed transfer. */
void	transferlog_connection_lost(enum transferlog_dir, const char *,
	    const char *);

/* Write each log's footer and close it: the file count, byte total, and
 * elapsed seconds for the TransferLog, the failure count for the failure
 * log. Then say how many transfers failed and where they are recorded,
 * or, with the failure log off, how to record them. A second call is
 * harmless. */
void	transferlog_close(void);

#endif /* SFTP_HPN_TRANSFERLOG_H */
