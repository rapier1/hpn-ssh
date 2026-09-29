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

#ifndef _SFTP_HPN_SERVER_H
#define _SFTP_HPN_SERVER_H

#include <stdint.h>

/* The extensions this file's handlers answer, as advertised in
 * SSH_FXP_VERSION. The bundle and tree walk names live in their own
 * headers. Each reply below is an SSH2_FXP_EXTENDED_REPLY carrying the
 * request id, and a malformed request gets SSH2_FX_BAD_MESSAGE. */
#define HPN_EXT_FS_INFO		"hpn-fs-info@hpnssh.org"
#define HPN_EXT_CHECK_FILE	"hpn-check-file@hpnssh.org"
#define HPN_EXT_HASH_RANGE	"sftp-hash-range@hpnssh.org"
#define HPN_EXT_FILE_LAYOUT	"hpn-file-layout@hpnssh.org"

/*
 * hpn-fs-info: a path's filesystem type and stripe geometry.
 *
 *   request:  string path
 *   reply:    string fs_type        "lustre", "gpfs", "xfs", "ext4", "nfs",
 *                                   "tmpfs", "btrfs" or "unknown"
 *             uint64 stripe_size    bytes per stripe, 0 off Lustre
 *             uint32 stripe_count   stripes (OSTs), 0 off Lustre
 *             uint64 block_size     optimal I/O block size, always set
 *
 * A path that does not exist yet is answered for its first existing
 * ancestor.
 */

/*
 * hpn-check-file: the hash of a file's first length bytes.
 *
 *   request:  string path
 *             uint64 length         bytes from offset 0, clamped to the
 *                                   file's size
 *   reply:    uint64 hash           XXH3_64 of those bytes
 *
 * The server always hashes a read-back from disk, fsync then O_DIRECT;
 * size and allocation are never taken as content.
 */

/*
 * sftp-hash-range: the hashes of up to SFTP_HASH_RANGE_MAX_RANGES
 * ranges of a file in one request.
 *
 *   request:  string path
 *             uint32 num_ranges     1 to SFTP_HASH_RANGE_MAX_RANGES
 *             num_ranges * (uint64 offset, uint64 length)
 *   reply:    uint32 num_hashes     equal to num_ranges
 *             num_hashes * uint64   XXH3_64 of each range, in order
 *
 * The bytes come from disk as for hpn-check-file. A range past EOF is
 * clamped to it. All or nothing: any failure is one SSH2_FXP_STATUS and
 * no hashes. The client caps its requests at the same limit.
 */
#define SFTP_HASH_RANGE_MAX_RANGES	65536

/*
 * hpn-file-layout: set a stripe layout on a directory before files land
 * in it. EXPERIMENTAL; HPNLustreStripeCount=0 in ssh_config turns it off.
 *
 *   request:  string path
 *             uint32 stripe_count   0 for all available, as lfs -c 0
 *             uint32 small_threshold
 *                                   0 for a plain stripe; above 0, a tiered
 *                                   composite with [0, small_threshold) on
 *                                   one OST and the rest striped across
 *                                   stripe_count OSTs
 *   reply:    uint32 status         one of the codes below
 *             uint32 applied_count  the count set, which the filesystem may
 *                                   clamp below the request; 0 on error
 *             uint32 layout_kind    one of the kinds below
 *
 * Lustre is the only backend today; the generic name leaves room for
 * others with the same wire shape. After PERM or FAIL the client warns
 * once and stops asking for the rest of the connection; after NOT_FS it
 * skips quietly.
 */
#define HPN_FILE_LAYOUT_OK	0	/* applied */
#define HPN_FILE_LAYOUT_NOT_FS	1	/* no layouts on this fs */
#define HPN_FILE_LAYOUT_PERM	2	/* the site forbids it */
#define HPN_FILE_LAYOUT_FAIL	3	/* any other error */

#define HPN_FILE_LAYOUT_KIND_STRIPE	0	/* plain RAID0 stripe */
#define HPN_FILE_LAYOUT_KIND_TIERED	1	/* tiered composite */

/*
 * Heartbeats for the two hash extensions. The server's check-file and
 * hash-range handlers send one every HPN_HASH_HEARTBEAT_INTERVAL_SEC
 * while they hash, once a second so the client's meter has a fresh
 * figure at each redraw. Each renews the client's watchdog pause for
 * HPN_HEARTBEAT_REFRESH_SEC, so the client can tell a slow hash from a
 * dead one: the watchdog's limit becomes how long the server has been
 * silent rather than a guess at how long a hash should take.
 *
 * A heartbeat has its extension's reply shape with a sentinel in the
 * first field and the bytes hashed so far after it:
 *
 *   hpn-check-file:   uint64 HPN_HASH_CHECK_FILE_HEARTBEAT, uint64 done
 *   sftp-hash-range:  uint32 HPN_NUM_HASHES_HEARTBEAT, uint64 done
 *
 * Neither sentinel can be a real result: a real XXH3_64 matches the first
 * with probability 1/2^64, and the second is far above
 * SFTP_HASH_RANGE_MAX_RANGES.
 *
 * Heartbeats prove liveness, not progress. A client that sees done stop
 * advancing for HPN_VERIFY_PROGRESS_STALL_SEC fails the connection, since
 * the request cannot be abandoned on a live one: a late reply would
 * desynchronize it.
 */
#define HPN_HASH_HEARTBEAT_INTERVAL_SEC	1
#define HPN_HEARTBEAT_REFRESH_SEC	30
#define HPN_VERIFY_PROGRESS_STALL_SEC	120
#define HPN_HASH_CHECK_FILE_HEARTBEAT	0xC0FFEEDEADBEEF42ULL
#define HPN_NUM_HASHES_HEARTBEAT	0xFFFFFFFE

/* Send what is queued on sftp-server.c's oqueue now, during a handler;
 * shared with the tree walk. The other reply helpers are upstream's,
 * through sftp-server-internal.h. */
void flush_oqueue_blocking(void);

/* The extension handlers, in the shape of sftp-server.c's own: each reads
 * its request from iqueue and replies through send_msg or send_status. */
void process_hpn_fs_info(uint32_t id);
void process_hpn_check_file(uint32_t id);
void process_hpn_hash_range(uint32_t id);
void process_hpn_file_layout(uint32_t id);

/* Close hook for the handles the HPN modules own, bundle and tree.
 * Returns 1 and sets *status when handle was one of them, so
 * sftp-server.c's CLOSE sends that status instead of taking its fd
 * path. Returns 0 for a FILE or DIR handle. */
int sftp_hpn_server_close_handle(int handle, int *status);

#endif /* _SFTP_HPN_SERVER_H */
