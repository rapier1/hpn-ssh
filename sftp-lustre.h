/*
 * sftp-lustre.h - Lustre layout mechanism for HPN-SSH SFTP.
 *
 * Part of HPN-SSH, NOT upstream OpenSSH.  Public interface to the Lustre layout
 * helpers extracted from sftp-hpn-server.c.  Linked into BOTH the server (which
 * applies layout for uploads via the hpn-file-layout extension) and the client
 * (which applies layout to LOCAL destinations for downloads).  The layout ABI
 * structs/constants are private to sftp-lustre.c; callers only need these
 * prototypes.  Setters return HPN_FILE_LAYOUT_* codes (sftp-hpn-server.h).
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#ifndef _SFTP_LUSTRE_H
#define _SFTP_LUSTRE_H

#include <stdint.h>

/*
 * Apply a simple RAID0 stripe to an open directory or freshly-created file FD.
 * Returns HPN_FILE_LAYOUT_OK/_NOT_FS/_PERM/_FAIL; on OK *applied_count is set to
 * the requested count (Lustre clamps silently to the OST count).
 */
uint32_t lustre_set_stripe_fd(int fd, uint32_t requested_count,
    uint32_t *applied_count);

/*
 * Apply a composite TIERED layout to an open directory FD (the no-MDT
 * replacement for Data-on-MDT): [0, small_threshold) on a single OST
 * (stripe_count=1), [small_threshold, EOF) striped RAID0 across overflow_count
 * OSTs.  Small files land wholly in the stripe-1 component (one OST, no
 * over-striping, no MDT data); large files stripe wide.  Written via
 * fsetxattr("lustre.lov") (LL_IOC_LOV_SETSTRIPE rejects composite layouts).
 * Returns HPN_FILE_LAYOUT_OK/_NOT_FS/_PERM/_FAIL.
 */
uint32_t lustre_set_tiered_layout_fd(int fd, uint32_t small_threshold,
    uint32_t overflow_count);

/*
 * Read a directory's default OST stripe geometry (count + size) via
 * getxattr("lustre.lov") - no lfs(1) subprocess.  Reports the OST (non-MDT)
 * component of a composite/DoM layout.  Returns 1 iff both *stripe_size and
 * *stripe_count are > 0, else 0.
 */
int lustre_get_stripe(const char *path, uint64_t *stripe_size,
    uint32_t *stripe_count);

/*
 * Path conveniences over the fd variants above, for the CLIENT side
 * (download parity): the orchestrator writes the local destination itself,
 * so it applies layout directly to a just-created local directory instead of
 * asking a server over the wire.  Open the directory read-only, delegate to
 * the fd variant, close.  Return the fd variant's HPN_FILE_LAYOUT_* code;
 * an unopenable path maps to HPN_FILE_LAYOUT_FAIL.
 */
uint32_t lustre_set_stripe_path(const char *dir, uint32_t requested_count,
    uint32_t *applied_count);
uint32_t lustre_set_tiered_layout_path(const char *dir,
    uint32_t small_threshold, uint32_t overflow_count);

#endif /* _SFTP_LUSTRE_H */
