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

/* sftp-hpn-transferlog.h - per-file transfer log (-X TransferLog).
 *
 * The log is for observation only. It holds one tab-delimited line per
 * file with its final status, between a start line and a footer that
 * gives the file count, byte total, and elapsed time. Nothing ever reads
 * the file back to decide whether to skip transfer or verification work,
 * so tampering or staleness cannot affect integrity behavior.
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

/* Claim "-X TransferLog[=path]", with the name matched case-insensitively.
 * Without a path the log goes to ./hpnssh-transfer.log, and an empty path
 * is fatal. Returns 1 if claimed, so the caller does not forward it, and 0
 * otherwise. */
int	transferlog_option(const char *);

/* If TransferLog was given, open the log for appending and write the
 * run's start line. An unwritable target is fatal, so callers run this
 * before any connection is made and a bad path fails the run before any
 * work starts. Does nothing when the option was not given or the log is
 * already open. */
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
 * separated by tabs. The path is local text from our own arguments and
 * is written as given. A NULL path is written as "(unknown)" and is not
 * mirrored. When the FILEDONE mirror is on, the status also goes to the
 * relay consumer. Safe to call from any thread. */
void	transferlog_file(enum hpns_fd_status, off_t, const char *);

/* The relay consumer's form, for a file a remote source reported in a
 * FILEDONE frame. The path is opaque remote bytes with a length. It is
 * percent-encoded before it reaches the log, because log files get
 * displayed and remote bytes must never reach a terminal raw. This never
 * sends a frame of its own. */
void	transferlog_file_bytes(enum hpns_fd_status, off_t, const u_char *,
	    size_t);

/* Map a FILEDONE status byte to its status, flag bits masked off. An
 * unknown value maps to HPNS_FD_FAILED, so it is never logged as a
 * success. */
enum hpns_fd_status transferlog_status_from_wire(u_char);

/* Write the run's footer, with the file count, byte total, and elapsed
 * seconds, and close the log. Does nothing if the log is not open, so a
 * second call is harmless. */
void	transferlog_close(void);

#endif /* SFTP_HPN_TRANSFERLOG_H */
