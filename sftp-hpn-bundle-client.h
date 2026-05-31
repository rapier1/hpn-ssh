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
 * sftp-hpn-bundle-client.h — client-side bundle protocol module.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * Scope: the client end of the SFTP bundle path —
 *
 *   hpn-bundle-open@hpnssh.org   (upload  — pack tar bytes,
 *                                  ship via WRITE, drain STATUSes)
 *   hpn-bundle-fetch@hpnssh.org  (download — fire READs ahead,
 *                                  feed wire bytes into the codec
 *                                  parser as they arrive)
 *
 * The public entry points (sftp_hpn_bundle_download,
 * sftp_hpn_bundle_upload) are declared in sftp-client.h because
 * the parallel orchestrator calls them with an opaque struct sftp_conn.
 * This header is intentionally minimal — it documents the module's
 * boundary and serves as an include hook for any future intra-bundle
 * declarations.  Everything inside sftp-hpn-bundle-client.c is static.
 *
 * Module split rationale (2026-05-31): hpn-bundle wire protocol +
 * batching glue had grown to ~870 lines inside the larger
 * sftp-hpn-client.c (controller, fault inj, hash-range, check-file,
 * file-layout, …).  Moving it out follows the "purpose-named modules"
 * direction in project_hpn_code_organization_vision.md.
 */

#ifndef _SFTP_HPN_BUNDLE_CLIENT_H
#define _SFTP_HPN_BUNDLE_CLIENT_H

/* Public function prototypes live in sftp-client.h, where the
 * opaque struct sftp_conn is in scope.  Bundle-internal types and
 * helpers are all file-static inside sftp-hpn-bundle-client.c. */

#endif /* _SFTP_HPN_BUNDLE_CLIENT_H */
