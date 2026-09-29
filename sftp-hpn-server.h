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

/* sftp-hpn-server.h - HPN-SSH server-side SFTP extensions.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Server-side HPN extension handlers are isolated here so that
 * sftp-server.c carries a minimal diff against upstream.
 *
 * Upstream merge note: sftp-server.c's extended_handlers[] table names
 * the HPN handlers declared here and in the bundle and tree headers
 * directly; they have upstream's handler shape, so no wrapper sits
 * between the table and them.
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

/* Most ranges one sftp-hash-range request may carry. The server allocates
 * that many range and hash entries up front, and the client caps its
 * chunked resume requests at the same number. */
#define SFTP_HASH_RANGE_MAX_RANGES	65536

/*
 * hpn-fs-info@hpnssh.org wire format:
 *
 *   request:  string path
 *
 *   reply:    string fs_type       "lustre", "gpfs", "xfs", "ext4", "nfs",
 *                                  "tmpfs", "btrfs" or "unknown"
 *             uint64 stripe_size   bytes per stripe; 0 off Lustre
 *             uint32 stripe_count  stripes (OSTs); 0 off Lustre
 *             uint64 block_size    optimal I/O block size, always set
 *
 * A path that does not exist yet is answered for its first existing
 * ancestor.  A malformed request gets SSH2_FX_BAD_MESSAGE.
 */

/*
 * hpn-file-layout@hpnssh.org wire format:
 *
 *   request:  string path
 *             uint32 stripe_count   (0 = "use all available" per Lustre lfs -c 0)
 *             uint32 small_threshold (0 = plain stripe.  >0 requests a
 *                                    tiered composite layout: [0,small_threshold)
 *                                    on a single OST (stripe_count=1),
 *                                    [small_threshold,EOF) striped across
 *                                    stripe_count OSTs.)
 *
 *   reply:    uint32 status         (0 = applied, non-zero = error code; see below)
 *             uint32 applied_count  (what the server actually set; may be
 *                                    clamped below the requested value if the
 *                                    filesystem has fewer OSTs than requested,
 *                                    zero on any error)
 *             uint32 layout_kind    (HPN_FILE_LAYOUT_KIND_STRIPE or
 *                                    HPN_FILE_LAYOUT_KIND_TIERED: the layout
 *                                    actually set)
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

/* The layout_kind values of an hpn-file-layout reply. */
#define HPN_FILE_LAYOUT_KIND_STRIPE	0u	/* plain RAID0 stripe */
#define HPN_FILE_LAYOUT_KIND_TIERED	1u	/* tiered composite */

/*
 * hpn-check-file@hpnssh.org wire format (19.0):
 *
 *   string  path
 *   uint64  length
 *
 * The server ALWAYS computes a full strict XXH3 read-back (fsync + O_DIRECT) -
 * size/allocation is never trusted as a content signal, so the request carries
 * no options.  (An earlier 19.0 development format had a uint32 flags field for
 * a sparse-skip sentinel; both were removed - the sentinel traded correctness
 * for I/O savings, and with the sentinel gone the flag had nothing to gate.)
 * Cross-version 19.0 <-> 18.x is handled by the extension-advertisement
 * mechanism: 18.x doesn't advertise hpn-check-file, so the client never sends
 * this request to an 18.x server.
 */

/*
 * Heartbeat protocol for long-running HPN hash extensions (19.0):
 *
 * The server's hash handlers, process_hpn_check_file and
 * process_hpn_hash_range in sftp-hpn-server.c, emit a tiny "still working"
 * reply on the SFTP out-queue every HPN_HASH_HEARTBEAT_INTERVAL_SEC seconds
 * of elapsed wall time while they hash.  The client treats
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
 * Hash-progress heartbeat cadence (HPN).  The server-side read-back hashes
 * (sftp-hash-range and hpn-check-file) carry bytes-hashed-so-far; the client
 * drives the verify progress meter from those.  The meter redraws every
 * UPDATE_INTERVAL (1 s, progressmeter.c), so emit hash progress every 1 s -
 * one fresh data point per redraw gives a smooth bar and a real rate.  This is
 * a progress feed, not the liveness ping (HPN_HEARTBEAT_EMIT_INTERVAL_SEC),
 * and is kept separate so non-hash heartbeat users are unaffected.
 */
#define HPN_HASH_HEARTBEAT_INTERVAL_SEC	1u

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

/* Send what is queued on sftp-server.c's oqueue now, during a handler;
 * shared with the tree walk. The other reply helpers are upstream's,
 * through sftp-server-internal.h. */
void flush_oqueue_blocking(void);

/* The extension handlers, in the shape of sftp-server.c's own: each reads
 * its request from iqueue and replies through send_msg or send_status.
 * Wire formats above. */
void process_hpn_fs_info(uint32_t id);
void process_hpn_check_file(uint32_t id);
void process_hpn_hash_range(uint32_t id);
void process_hpn_file_layout(uint32_t id);

/* Close hook for the handles the HPN modules own, bundle and tree.
 * Returns 1 and sets *status when handle was one of them, so
 * sftp-server.c's CLOSE sends that status instead of taking its fd
 * path. Returns 0 for a FILE or DIR handle. */
int sftp_hpn_server_close_handle(int handle, int *status);

#endif /* _SFTP_SERVER_HPN_H */
