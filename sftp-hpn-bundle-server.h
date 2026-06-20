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
 * sftp-hpn-bundle-server.h - server-side bundle protocol module.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * Scope: the server end of the SFTP bundle path -
 *
 *   hpn-bundle-open@hpnssh.org   (upload  - accept tar bytes via WRITE,
 *                                  feed codec parser inline, write files
 *                                  as entries are recognised)
 *   hpn-bundle-fetch@hpnssh.org  (download - accept file list, queue
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

/* ── Extension wire names (advertised in SSH_FXP_VERSION) ───────────────
 *
 * Strings the dispatcher (sftp-hpn-server.c) routes by, and that
 * sftp-server.c uses in compose_extension at session init.  Moved here
 * from sftp-hpn-server.h during the 2026-05-31 module split - bundle-
 * scope macros belong with the bundle module's other public interface. */
#define HPN_EXT_BUNDLE          "hpn-bundle@hpnssh.org"         /* capability advert */
#define HPN_EXT_BUNDLE_OPEN     "hpn-bundle-open@hpnssh.org"    /* upload  bundle open  */
#define HPN_EXT_BUNDLE_FETCH    "hpn-bundle-fetch@hpnssh.org"   /* download bundle open */

/* ── Bundle handle dispatch (called from sftp-server.c) ─────────────────
 *
 * Bundle handles are allocated by the hpn-bundle-open@hpnssh.org or
 * hpn-bundle-fetch@hpnssh.org extension handlers.  They appear in
 * sftp-server.c's handle table as HANDLE_BUNDLE (a new use type).
 * sftp-server.c's WRITE / READ / CLOSE dispatchers call the helpers
 * below before their standard fd-based dispatch when the handle is
 * marked HANDLE_BUNDLE. */

/*
 * True iff the given handle index refers to a bundle handle allocated
 * by this module.  sftp-server.c calls this in process_write,
 * process_read, and process_close before its standard fd-based
 * dispatch.
 */
int sftp_hpn_server_is_bundle_handle(int handle);

/*
 * Feed WRITE bytes for an upload bundle handle into the streaming
 * codec parser.  Entry callbacks open output files, write data, and
 * close on EOA.  Returns SSH2_FX_OK on success or an SSH2_FX_* error.
 */
int sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len);

/*
 * Close a bundle handle: for UPLOAD, the streaming extract already
 * happened during the WRITE sequence - close just verifies parser
 * state and frees.  For FETCH, close releases the writer and any
 * still-open input file.  Always frees the handle.  Returns the
 * SSH2_FX_* status for the caller to send.
 */
int sftp_hpn_server_bundle_close(int handle, u_int id, struct sshbuf *oqueue);

/*
 * Produce up to `len` bytes of tar stream for a fetch-mode bundle
 * handle into out_buf.  The codec writer packs files into the buffer
 * on demand (no in-memory accumulator).  Returns SSH2_FX_OK with
 * *out_len > 0 while data remains; SSH2_FX_EOF when the writer
 * reaches end-of-archive.
 *
 * Off is monotonic per handle; backward seeks return SSH2_FX_FAILURE.
 * Forward gaps (off > bytes_produced) are absorbed silently - they
 * happen naturally when a previous read returned fewer than CHUNK
 * bytes because the bundle ended mid-chunk.
 *
 * Used by sftp-server.c's process_read for handles where
 * sftp_hpn_server_is_bundle_handle() returns true.
 */
int sftp_hpn_server_bundle_read(int handle, uint64_t off,
    u_char *out_buf, size_t len, size_t *out_len);

/*
 * True iff the bundle path is enabled at this server.  Driven by
 * sshd_config's HPNUseBundle (propagated via the HPN_USE_BUNDLE env
 * var that sshd-session sets).  When false:
 *   - sftp-server.c omits hpn-bundle / hpn-bundle-fetch from the
 *     SSH_FXP_VERSION extension list.
 *   - The bundle handlers refuse bundle-open / bundle-fetch with
 *     SSH2_FX_OP_UNSUPPORTED if a misbehaving client tries anyway.
 *
 * The check is cached after the first call; safe to invoke on any
 * code path without performance concern.
 */
int sftp_hpn_server_bundle_enabled(void);

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
