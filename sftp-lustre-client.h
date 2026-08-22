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
 * sftp-lustre-client.h - client-side Lustre layout policy for the
 * parallel-streams orchestrator (HPNLustreStripeCount).  The filesystem
 * MECHANISM (layout ABI, setstripe/getstripe wrappers) lives in
 * sftp-lustre.c; this module is the client POLICY deciding when and how
 * to apply a layout to a destination directory.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 */
#ifndef SFTP_LUSTRE_CLIENT_H
#define SFTP_LUSTRE_CLIENT_H

struct sftp_parallel;
struct sftp_conn;

/*
 * HPNLustreStripeCount entry point.  Called by the recursive walker after
 * mkdir of a destination subdirectory, and by sftp.c's single-file upload
 * dispatch on the destination directory.  No-op when the feature is
 * disabled (HPNLustreStripeCount=0), not in parallel mode, the server
 * does not advertise hpn-file-layout, the destination is not on Lustre,
 * the current stripe count already meets or exceeds the desired count,
 * or a prior call on the same conn returned a non-success status (the
 * declined-latch is checked first so subsequent calls short-circuit).
 * On success emits one INFO log line.  Safe to call repeatedly on the
 * same directory - Lustre setstripe is idempotent.
 */
void maybe_apply_lustre_layout(struct sftp_parallel *fleet,
    struct sftp_conn *conn, const char *dst);

/*
 * Local twin of maybe_apply_lustre_layout for DOWNLOADS: dst is a LOCAL
 * destination directory and this process is the writer, so the layout is
 * applied directly via sftp-lustre.c instead of the wire extension.  Same
 * HPNLustreStripeCount policy (0=off, unset=tiered composite sized to the
 * worker count, N=plain N-stripe with an exact-match skip).  Non-Lustre
 * destinations are skipped silently.  conn supplies only the resolved
 * config value.
 */
void maybe_apply_lustre_layout_local(struct sftp_parallel *fleet,
    struct sftp_conn *conn, const char *dst);

#endif /* SFTP_LUSTRE_CLIENT_H */
