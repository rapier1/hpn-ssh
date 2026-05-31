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
#define HPN_EXT_FILE_LAYOUT  "hpn-file-layout@hpnssh.org"   /* filesystem layout (Lustre stripe today) */

/*
 * hpn-file-layout@hpnssh.org wire format (revision 1):
 *
 *   request:  string path
 *             uint32 stripe_count   (0 = "use all available" per Lustre lfs -c 0)
 *
 *   reply:    uint32 status         (0 = applied, non-zero = error code; see below)
 *             uint32 applied_count  (what the server actually set; may be
 *                                    clamped below the requested value if the
 *                                    filesystem has fewer OSTs than requested,
 *                                    zero on any error)
 *
 * Status values:
 *   0                          — applied successfully; applied_count valid
 *   HPN_FILE_LAYOUT_NOT_FS     — path is not on a layout-capable filesystem
 *                                (today: not Lustre). Client treats as "skip"
 *                                without warning.
 *   HPN_FILE_LAYOUT_PERM       — server lacks permission to set the layout
 *                                (EPERM / restricted OST pool). Client warns
 *                                once per connection then short-circuits all
 *                                further hpn-file-layout calls.
 *   HPN_FILE_LAYOUT_FAIL       — other error (ENOENT, ENOSPC during OST pick,
 *                                etc.). Client warns once and short-circuits.
 *
 * Lustre is the only backend today.  The generic extension name leaves room
 * to add GPFS / BeeGFS / etc. with the same wire shape (a single uint32
 * "layout count" that each backend can interpret appropriately).
 *
 * EXPERIMENTAL: behaviour may change in future revisions.  Operators who
 * need to disable it set HPNLustreStripeCount=0 in ssh_config.
 */
#define HPN_FILE_LAYOUT_OK        0u
#define HPN_FILE_LAYOUT_NOT_FS    1u
#define HPN_FILE_LAYOUT_PERM      2u
#define HPN_FILE_LAYOUT_FAIL      3u

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

/*
 * Heartbeat protocol for long-running HPN hash extensions (19.0):
 *
 * Server-side hash loops (process_extended_hpn_check_file in sftp-server.c
 * and process_hpn_hash_range in this file) emit a tiny "still working"
 * reply on the SFTP out-queue every HPN_HEARTBEAT_EMIT_INTERVAL_SEC seconds
 * of elapsed wall time inside the inner read+hash loop.  The client treats
 * each heartbeat as proof of life and refreshes the orchestrator's
 * watchdog-pause window to HPN_HEARTBEAT_REFRESH_SEC from now.
 *
 * Heartbeat wire format is the EXTENDED_REPLY shape of the underlying
 * extension, with a reserved sentinel in the "result" field:
 *
 *   hpn-check-file heartbeat:   u8 EXTENDED_REPLY | u32 id |
 *                               u64 HPN_HASH_CHECK_FILE_HEARTBEAT
 *   sftp-hash-range heartbeat:  u8 EXTENDED_REPLY | u32 id |
 *                               u32 HPN_NUM_HASHES_HEARTBEAT
 *
 * Each sentinel is impossible as a real result:
 *   - HPN_HASH_CHECK_FILE_HEARTBEAT collides with a real XXH3_64 with
 *     probability 1/2^64;
 *   - HPN_NUM_HASHES_HEARTBEAT is well above SFTP_HASH_RANGE_MAX_RANGES
 *     (65536), so it can never appear as a legitimate count.
 *
 * The heartbeat replaces the brittle grace-formula model that estimated
 * hash duration from file size and assumed 1 GB/s disk read.  Under
 * parallel-worker contention on a single device, that assumption was off
 * by ~4x and triggered watchdog-driven worker kills mid-hash.  With
 * heartbeats, the watchdog timeout (HPN_HEARTBEAT_REFRESH_SEC) is
 * "how long without any word from the server" — independent of file size
 * or disk speed.
 *
 * Within 19.0 both ends always speak heartbeats; no negotiation needed.
 */
#define HPN_HEARTBEAT_EMIT_INTERVAL_SEC	5u
#define HPN_HEARTBEAT_REFRESH_SEC	30u
#define HPN_HASH_CHECK_FILE_HEARTBEAT \
	((u_int64_t)0xC0FFEEDEADBEEF42ULL)
#define HPN_NUM_HASHES_HEARTBEAT	0xFFFFFFFEU

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

/*
 * Direct-to-file diagnostic logger for the 2026-05-31 bundle truncation
 * hunt.  Bypasses the standard syslog/journal path so the per-iter test
 * setup can write to a known file controlled by HPN_BUNDLE_DEBUG_LOG
 * (defaults to /tmp/hpn-bundle-debug.log).  Each line is
 * "<unix_sec>.<usec> pid=<PID> <fmt-expanded>".
 *
 * Declared here only so sftp-server.c can call it from process_read /
 * process_close paths.  REMOVE OR GATE this declaration along with the
 * implementation once the hunt closes.
 */
void bundle_debug_log(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

#endif /* _SFTP_SERVER_HPN_H */
