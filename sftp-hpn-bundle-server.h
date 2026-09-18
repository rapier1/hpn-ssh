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

/* sftp-hpn-bundle-server.h - server side of the SFTP bundle protocol.
 *
 * Two extended requests: hpn-bundle-open@hpnssh.org, an upload whose
 * WRITE payloads are fed to the codec parser and extracted as the
 * entries arrive, and hpn-bundle-fetch@hpnssh.org, a download whose
 * requested files are queued into the codec writer and packed on
 * demand as the READs arrive. sftp-server.c routes WRITE, READ and
 * CLOSE on a bundle handle to the functions here, and advertises the
 * extension names at session init. The two request handlers are called
 * by the dispatcher in sftp-hpn-server.c. */

#ifndef _SFTP_HPN_BUNDLE_SERVER_H
#define _SFTP_HPN_BUNDLE_SERVER_H

/* Extension names, advertised in SSH_FXP_VERSION and routed by the
 * dispatcher. hpn-bundle is the capability, the other two are the
 * requests. */
#define HPN_EXT_BUNDLE          "hpn-bundle@hpnssh.org"
#define HPN_EXT_BUNDLE_OPEN     "hpn-bundle-open@hpnssh.org"
#define HPN_EXT_BUNDLE_FETCH    "hpn-bundle-fetch@hpnssh.org"

struct sshbuf;

/* Bundle handles live in sftp-server.c's handle table as HANDLE_BUNDLE.
 * Its WRITE, READ and CLOSE handlers test for one with the predicate
 * and call the matching function below instead of their fd path. */
int sftp_hpn_server_is_bundle_handle(int handle);

/* Feed WRITE bytes for an upload bundle handle into the streaming codec
 * parser, whose callbacks extract the entries as they arrive, inline or
 * through the writer pool. Returns SSH2_FX_OK or an SSH2_FX_* error. */
int sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len);

/* Pack up to len bytes of archive for a fetch bundle handle into
 * out_buf, setting *out_len. Returns SSH2_FX_OK while data remains and
 * SSH2_FX_EOF once the archive is exhausted. off must not go backward.
 * A forward gap is normal once the archive has ended, the client fires
 * reads ahead at fixed offsets, and yields EOF. */
int sftp_hpn_server_bundle_read(int handle, uint64_t off,
    u_char *out_buf, size_t len, size_t *out_len);

/* Close a bundle handle. For an upload the extract already happened
 * during the WRITEs, so close fails on a parser error or a missing end
 * marker, joins the writer pool and frees. For a fetch it releases the
 * writer and any open input file. Always frees the handle. Returns the
 * SSH2_FX_* status for the caller to send. */
int sftp_hpn_server_bundle_close(int handle);

/* True iff the bundle path is enabled at this server. Driven by
 * sshd_config's HPNUseBundle, handed to sftp-server as the -B argv flag.
 * When false sftp-server.c omits hpn-bundle and hpn-bundle-fetch from
 * the SSH_FXP_VERSION extension list, and the bundle handlers refuse
 * bundle-open and bundle-fetch with SSH2_FX_OP_UNSUPPORTED if a client
 * tries anyway. */
int sftp_hpn_server_bundle_enabled(void);

/* The two extended-request handlers. Each creates a bundle handle and
 * replies with SSH_FXP_HANDLE, or with SSH_FXP_STATUS on failure. */
void process_hpn_bundle_open(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);
void process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

#endif /* _SFTP_HPN_BUNDLE_SERVER_H */
