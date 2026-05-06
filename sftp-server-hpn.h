/* sftp-server-hpn.h — HPN-SSH server-side SFTP extensions.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Server-side HPN extension handlers are isolated here so that
 * sftp-server.c carries a minimal diff against upstream.
 *
 * Current extensions (Phase 3):
 *   hpn-fs-info@hpnssh.org — returns filesystem type and stripe geometry
 *     for a given path, allowing the client to align byte-range parallel
 *     transfers to Lustre/GPFS stripe boundaries.
 *
 * Upstream merge note: sftp-server.c gains only:
 *   #include "sftp-server-hpn.h"
 *   sftp_server_hpn_handles() / sftp_server_hpn_dispatch() calls in the
 *   SSH2_FXP_EXTENDED dispatch block.
 */

#ifndef _SFTP_SERVER_HPN_H
#define _SFTP_SERVER_HPN_H

struct sshbuf;

/*
 * Returns non-zero if the named extension is handled by this module.
 * Called from sftp-server.c's SSH2_FXP_EXTENDED dispatch to route
 * HPN-specific extension requests without modifying the upstream table.
 */
int sftp_server_hpn_handles(const char *name);

/*
 * Dispatch an HPN extension request.  Called only when
 * sftp_server_hpn_handles() returned non-zero.
 *
 *   id      — SFTP request ID from the client
 *   name    — extension name string
 *   iqueue  — input buffer (positioned after the extension name)
 *   oqueue  — output buffer for the reply
 */
void sftp_server_hpn_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue);

#endif /* _SFTP_SERVER_HPN_H */
