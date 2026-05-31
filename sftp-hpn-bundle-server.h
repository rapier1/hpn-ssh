/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the BSD 2-Clause License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the BSD 2-Clause License for more
 * details.
 *
 * You should have received a copy of the BSD 2-Clause License along with this
 * library; if not, see https://opensource.org/license/bsd-2-clause.
 *
 */

/*
 * sftp-hpn-bundle-server.h — server-side bundle protocol module.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * Scope: the server end of the SFTP bundle path —
 *
 *   hpn-bundle-open@hpnssh.org   (upload  — accept tar bytes via WRITE,
 *                                  feed codec parser inline, write files
 *                                  as entries are recognised)
 *   hpn-bundle-fetch@hpnssh.org  (download — accept file list, queue
 *                                  into codec writer, serve READs via
 *                                  pack_next on demand)
 *
 * Most of the server-facing bundle API (sftp_hpn_server_bundle_*) is
 * still declared in sftp-hpn-server.h because sftp-server.c calls
 * those directly from its WRITE / READ / CLOSE dispatch and from
 * process_init's extension advertisement.  This header carries only
 * the two RPC handlers that the dispatcher (sftp_hpn_server_dispatch,
 * in sftp-hpn-server.c) routes by extension name.
 *
 * Module split rationale (2026-05-31): hpn-bundle server protocol +
 * accumulator state had grown to ~1060 lines inside the larger
 * sftp-hpn-server.c (dispatcher, hash-range, file-layout, …).  Moving
 * it out follows the "purpose-named modules" direction in
 * project_hpn_code_organization_vision.md.
 */

#ifndef _SFTP_HPN_BUNDLE_SERVER_H
#define _SFTP_HPN_BUNDLE_SERVER_H

struct sshbuf;

/*
 * Process the hpn-bundle-open@hpnssh.org extended request.
 * Allocates a bundle handle (UPLOAD mode) and replies with
 * SSH_FXP_HANDLE.  On error replies with SSH_FXP_STATUS.
 * Called by sftp_hpn_server_dispatch (sftp-hpn-server.c).
 */
void process_hpn_bundle_open(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

/*
 * Process the hpn-bundle-fetch@hpnssh.org extended request.
 * Reads each path, stat()s, queues into the codec writer, signals
 * EOA via writer_finish, installs the bundle_state on the handle
 * table, replies with SSH_FXP_HANDLE.  File reads + tar packing
 * happen lazily inside sftp_hpn_server_bundle_read as the client
 * drains via SSH_FXP_READ.  Called by sftp_hpn_server_dispatch.
 */
void process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

#endif /* _SFTP_HPN_BUNDLE_SERVER_H */
