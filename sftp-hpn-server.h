/* sftp-hpn-server.h — HPN-SSH server-side SFTP extensions.
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
 *   #include "sftp-hpn-server.h"
 *   sftp_hpn_server_dispatch() calls in the SSH2_FXP_EXTENDED dispatch
 *   block (extensions are registered in the extended_handlers[] table
 *   at the top of sftp-server.c, which routes by name to dispatch).
 */

#ifndef _SFTP_SERVER_HPN_H
#define _SFTP_SERVER_HPN_H

/* Extension names advertised in SSH_FXP_VERSION and dispatched by sftp-server.c. */
#define HPN_EXT_FS_INFO      "hpn-fs-info@hpnssh.org"
#define HPN_EXT_BUNDLE       "hpn-bundle@hpnssh.org"        /* capability advert */
#define HPN_EXT_BUNDLE_OPEN  "hpn-bundle-open@hpnssh.org"   /* upload  bundle open  */
#define HPN_EXT_BUNDLE_FETCH "hpn-bundle-fetch@hpnssh.org"  /* download bundle open */
#define HPN_EXT_HASH_RANGE   "sftp-hash-range@hpnssh.org"   /* chunked-resume ranged hashing */

/*
 * hpn-check-file@hpnssh.org sparse-skip protocol (19.0):
 *
 * The wire-format request now carries a flags field after length:
 *
 *   string  path
 *   uint64  length
 *   uint32  flags
 *
 * The server short-circuits the read+hash and returns the sentinel
 * HPN_HASH_FULLY_ALLOCATED_SENTINEL when:
 *   - the client did NOT set HPN_CHECK_FILE_STRICT, AND
 *   - length == st.st_size (the client is asking about the whole file),
 *   - st.st_blocks * 512 >= 95% of st.st_size (fully allocated).
 *
 * Client sets HPN_CHECK_FILE_STRICT when HPNVerifyTransfer is enabled
 * (the user explicitly asked for maximum verification; no trust-based
 * shortcuts).  Strict mode forces the server to compute and return the
 * real XXH3.
 *
 * Collision probability of a real XXH3 producing the sentinel value is
 * 1 in 2^64 — effectively zero in any realistic workload.
 *
 * Within 19.0: all servers and clients implement this.  Cross-version
 * 19.0 <-> 18.x is handled by the existing extension-advertisement
 * mechanism (18.x doesn't advertise hpn-check-file, 19.0 client falls
 * through to RESUME_INCOMPAT_MSG; 18.x client never sends the request).
 */
#define HPN_HASH_FULLY_ALLOCATED_SENTINEL \
	((u_int64_t)0xDEADBEEFCAFEBABEULL)
#define HPN_CHECK_FILE_STRICT		0x00000001U

struct sshbuf;

/*
 * Dispatch an HPN extension request from sftp-server.c's
 * SSH2_FXP_EXTENDED handler.  The caller has already routed by
 * extension name (via the extended_handlers[] table in sftp-server.c),
 * so this entry point switches on `name` to call the right HPN-side
 * handler.
 *
 *   id      — SFTP request ID from the client
 *   name    — extension name string (one of HPN_EXT_*)
 *   iqueue  — input buffer (positioned after the extension name)
 *   oqueue  — output buffer for the reply
 */
void sftp_hpn_server_dispatch(u_int id, const char *name,
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
 * inside sftp-hpn-server.c so sftp-server.c carries a minimal diff.
 *
 * Requires libarchive (-larchive); enforced as a hard configure
 * requirement.
 */

/*
 * True iff the given handle index refers to a bundle handle allocated
 * by this module.  sftp-server.c calls this in process_write and
 * process_close before its standard fd-based dispatch.
 */
int sftp_hpn_server_is_bundle_handle(int handle);

/*
 * Append WRITE data to a bundle handle's accumulation buffer.
 * Returns SSH2_FX_OK on success or an SSH2_FX_* error.
 */
int sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len);

/*
 * Close a bundle handle: run libarchive extraction on the accumulated
 * tar bytes, then release all bundle state and the handle itself.
 * Returns SSH2_FX_OK if every file in the bundle was extracted
 * successfully, otherwise an SSH2_FX_* error.
 *
 * For fetch-mode handles (download-side bundles populated up front by
 * process_hpn_bundle_fetch), close simply releases the accumulator and
 * always returns SSH2_FX_OK.
 */
int sftp_hpn_server_bundle_close(int handle);

/*
 * Read up to len bytes from a fetch-mode bundle handle's accumulator
 * into out_buf, starting at offset off.
 *
 * On success returns SSH2_FX_OK and sets *out_len to the number of bytes
 * actually returned (0 < *out_len <= len for in-range reads).
 *
 * Returns SSH2_FX_EOF if off >= accumulator length (end of bundle).
 *
 * Returns an SSH2_FX_* error if the handle is not a fetch-mode bundle
 * (e.g. an upload-side bundle being WRITten into) or other failure.
 *
 * Used by sftp-server.c's process_read for handles where
 * sftp_hpn_server_is_bundle_handle() returns true.
 */
int sftp_hpn_server_bundle_read(int handle, uint64_t off,
    u_char *out_buf, size_t len, size_t *out_len);

/*
 * Apply operator-supplied per-bundle and total bundle-accumulator caps
 * from K/M/G-suffixed byte strings (e.g. "64M", "1500M", "2G").  Either
 * argument may be NULL or "" to leave that cap at its compiled default.
 * Values outside the supported range are clamped to the nearest bound
 * with a warning to stderr; unparseable values cause exit via fatal().
 *
 * Bounds:
 *   per-bundle: [1 MiB, 1 GiB]   default 64 MiB
 *   total:      [16 MiB, 16 GiB] default 1.5 GiB
 *
 * Called by sftp-server.c after parsing -B / -T CLI flags, before the
 * SFTP main loop starts.  Safe to call with both NULLs (no-op).
 */
void sftp_hpn_server_set_bundle_caps(const char *per_arg,
    const char *total_arg);

/* ── END Phase 5 ─────────────────────────────────────────────────────── */

#endif /* _SFTP_SERVER_HPN_H */
