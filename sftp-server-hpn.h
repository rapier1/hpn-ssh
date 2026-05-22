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

/* Extension names advertised in SSH_FXP_VERSION and dispatched by sftp-server.c. */
#define HPN_EXT_FS_INFO     "hpn-fs-info@hpnssh.org"
#define HPN_EXT_BUNDLE      "hpn-bundle@hpnssh.org"        /* capability advert */
#define HPN_EXT_BUNDLE_OPEN "hpn-bundle-open@hpnssh.org"   /* extended open request */

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

/* ── BEGIN Phase 5: bundle handle support ─────────────────────────────────
 *
 * Bundle handles are allocated by the hpn-bundle-open@hpnssh.org extension
 * handler.  They appear in sftp-server.c's handle table as HANDLE_BUNDLE
 * (a new use type).  Subsequent SSH_FXP_WRITE messages on a bundle handle
 * append data to an accumulation buffer; SSH_FXP_CLOSE triggers libarchive
 * extraction into the destination directory, then frees the bundle state.
 *
 * The sftp-server.c WRITE/CLOSE dispatchers detect bundle handles via
 * the use type and call the functions below.  All bundle state lives
 * inside sftp-server-hpn.c so sftp-server.c carries a minimal diff.
 *
 * Compiled in only when WITH_LIBARCHIVE is defined; otherwise the handler
 * returns SSH2_FX_OP_UNSUPPORTED on open and the bundle code path is
 * unreachable.
 */

/*
 * True iff the given handle index refers to a bundle handle allocated
 * by this module.  sftp-server.c calls this in process_write and
 * process_close before its standard fd-based dispatch.
 */
int sftp_server_hpn_is_bundle_handle(int handle);

/*
 * Append WRITE data to a bundle handle's accumulation buffer.
 * Returns SSH2_FX_OK on success or an SSH2_FX_* error.
 */
int sftp_server_hpn_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len);

/*
 * Close a bundle handle: run libarchive extraction on the accumulated
 * tar bytes, then release all bundle state and the handle itself.
 * Returns SSH2_FX_OK if every file in the bundle was extracted
 * successfully, otherwise an SSH2_FX_* error.
 */
int sftp_server_hpn_bundle_close(int handle);

/* ── END Phase 5 ─────────────────────────────────────────────────────── */

#endif /* _SFTP_SERVER_HPN_H */
