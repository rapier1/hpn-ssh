/* sftp-hpn-server.h - HPN-SSH server-side SFTP extensions.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Server-side HPN extension handlers are isolated here so that
 * sftp-server.c carries a minimal diff against upstream.
 *
 * Current extensions (Phase 3):
 *   hpn-fs-info@hpnssh.org - returns filesystem type and stripe geometry
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

/* Extension names advertised in SSH_FXP_VERSION and dispatched by sftp-server.c.
 *
 * Bundle-scope extension names (HPN_EXT_BUNDLE, _OPEN, _FETCH,
 * _MAX_SIZE) moved to sftp-hpn-bundle-server.h on 2026-05-31 alongside
 * the bundle code itself. */
#define HPN_EXT_FS_INFO      "hpn-fs-info@hpnssh.org"
#define HPN_EXT_CHECK_FILE	"hpn-check-file@hpnssh.org"
#define HPN_EXT_HASH_RANGE   "sftp-hash-range@hpnssh.org"   /* chunked-resume ranged hashing */
#define HPN_EXT_FILE_LAYOUT  "hpn-file-layout@hpnssh.org"   /* filesystem layout (Lustre stripe today) */

/*
 * hpn-file-layout@hpnssh.org wire format (revision 1):
 *
 *   request:  string path
 *             uint32 stripe_count   (0 = "use all available" per Lustre lfs -c 0)
 *             uint32 small_threshold (rev 2; 0 = plain stripe.  >0 requests a
 *                                    tiered composite layout: [0,small_threshold)
 *                                    on a single OST (stripe_count=1),
 *                                    [small_threshold,EOF) striped across
 *                                    stripe_count OSTs.  A rev-1 client omits
 *                                    this; the server defaults it to 0.  Before
 *                                    19.0 this field was the Data-on-MDT
 *                                    component size; same wire u32.)
 *
 *   reply:    uint32 status         (0 = applied, non-zero = error code; see below)
 *             uint32 applied_count  (what the server actually set; may be
 *                                    clamped below the requested value if the
 *                                    filesystem has fewer OSTs than requested,
 *                                    zero on any error)
 *             uint32 layout_kind    (rev 2; 0 = plain stripe, 1 = tiered
 *                                    composite.  Absent from a rev-1 server;
 *                                    client treats a missing field as 0.)
 *
 * Status values:
 *   0                          - applied successfully; applied_count valid
 *   HPN_FILE_LAYOUT_NOT_FS     - path is not on a layout-capable filesystem
 *                                (today: not Lustre). Client treats as "skip"
 *                                without warning.
 *   HPN_FILE_LAYOUT_PERM       - server lacks permission to set the layout
 *                                (EPERM / restricted OST pool). Client warns
 *                                once per connection then short-circuits all
 *                                further hpn-file-layout calls.
 *   HPN_FILE_LAYOUT_FAIL       - other error (ENOENT, ENOSPC during OST pick,
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
 * 1 in 2^64 - effectively zero in any realistic workload.
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
 * "how long without any word from the server" - independent of file size
 * or disk speed.
 *
 * Within 19.0 both ends always speak heartbeats; no negotiation needed.
 */
#define HPN_HEARTBEAT_EMIT_INTERVAL_SEC	5u

/*
 * Heartbeats prove liveness, not progress: each one carries a u64
 * bytes-hashed-so-far figure, and a client seeing no advance for this
 * many seconds treats the connection as failed (a backend so stalled
 * it heartbeats forever would otherwise hang the verify eternally).
 * The op cannot be abandoned on a live connection - a late reply would
 * desync it - so the bail is a connection death.
 */
#define HPN_VERIFY_PROGRESS_STALL_SEC	120u
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
 *   id      - SFTP request ID from the client
 *   name    - extension name string (one of HPN_EXT_*)
 *   iqueue  - input buffer (positioned after the extension name)
 *   oqueue  - output buffer for the reply
 */
void sftp_hpn_server_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue);

/* Bundle handle dispatch (sftp_hpn_server_bundle_*, _is_bundle_handle,
 * _enabled) moved to sftp-hpn-bundle-server.h on 2026-05-31 alongside the
 * bundle code itself.  sftp-server.c now includes both this header (for the
 * dispatcher + hash-range / file-layout decls) and
 * sftp-hpn-bundle-server.h (for the bundle ones). */

#endif /* _SFTP_SERVER_HPN_H */
