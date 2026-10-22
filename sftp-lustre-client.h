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

/* sftp-lustre-client.h - the client's Lustre layout policy for parallel
 * transfers (HPNLustreStripeCount). It sets a destination directory's
 * layout before files land in it, so they inherit it. This module decides
 * when and what to ask for. The layout ABI and the calls that set and read
 * layouts live in sftp-lustre.c. */

#ifndef SFTP_LUSTRE_CLIENT_H
#define SFTP_LUSTRE_CLIENT_H

struct sftp_parallel;
struct sftp_conn;

/* What maybe_apply_lustre_layout() learned about its directory. UNKNOWN
 * means it stopped before asking, or the query failed, so the next call
 * asks again. NOT_LUSTRE means the directory is on another filesystem.
 * SETTLED means a layout was set or refused, or the directory already had
 * the plain stripe asked for. */
enum lustre_layout_result {
	LUSTRE_LAYOUT_UNKNOWN,
	LUSTRE_LAYOUT_NOT_LUSTRE,
	LUSTRE_LAYOUT_SETTLED
};

/* Upload side. The arguments are the fleet, the connection, and a remote
 * destination directory. The parallel walker calls it for each directory
 * it enters, and maybe_apply_lustre_layout_parent() for a single-file
 * upload. It does nothing unless the transfer is parallel,
 * HPNLustreStripeCount is not 0, the server has hpn-fs-info and
 * hpn-file-layout, and the directory is on Lustre. A plain stripe of N
 * skips a directory already at exactly N. Success logs at debug level. Any
 * other reply logs once and stops later requests on the connection. Returns
 * what it learned about the directory. */
enum lustre_layout_result maybe_apply_lustre_layout(struct sftp_parallel *,
    struct sftp_conn *, const char *);

/* Download side, the same policy applied to a local destination directory
 * through sftp-lustre.c. The arguments are the fleet, the connection, and
 * the directory. The parallel walker calls it after each mkdir, and
 * maybe_apply_lustre_layout_parent() for a single-file download. There is
 * no fs-info query. A directory that is not on Lustre gets NOT_FS from the
 * setter, logs at debug level, and the next directory is tried again. PERM
 * and FAIL log once at INFO and stop later attempts on the connection. */
void maybe_apply_lustre_layout_local(struct sftp_parallel *,
    struct sftp_conn *, const char *);

/* Apply the layout to the parent directory of a single-file -j transfer's
 * destination, the case the walker does not cover. The arguments are the
 * fleet, the connection, the destination file's path, and 1 for a local
 * destination (a download) or 0 for a remote one (an upload). sftp.c and
 * scp.c call it before submitting the file. The files of one command share
 * a parent, so the connection remembers the last parent that got an
 * answer, and later calls for it return at once. */
void maybe_apply_lustre_layout_parent(struct sftp_parallel *,
    struct sftp_conn *, const char *, int);

#endif /* SFTP_LUSTRE_CLIENT_H */
