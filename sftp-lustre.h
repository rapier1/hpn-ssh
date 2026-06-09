/*
 * sftp-lustre.h - Lustre layout mechanism for HPN-SSH server-side SFTP.
 *
 * Part of HPN-SSH, NOT upstream OpenSSH.  Public interface to the Lustre layout
 * helpers extracted from sftp-hpn-server.c.  The layout ABI structs/constants
 * are private to sftp-lustre.c; callers only need these prototypes.  All three
 * return HPN_FILE_LAYOUT_* codes (defined in sftp-hpn-server.h).
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#ifndef _SFTP_LUSTRE_H
#define _SFTP_LUSTRE_H

#include <stdint.h>
#include <stddef.h>

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
 * O_DIRECT aligned-write helper.  Bypasses the per-inode buffered-write
 * serialization that throttles parallel range-split writes into one Lustre
 * file.  Used for all write-intent opens (with a buffered fallback when the
 * target rejects O_DIRECT).  The state is opaque; the server
 * attaches one per write handle.  _new() returns NULL on allocation failure
 * (caller must then keep the fd buffered).  _write() write-combines into a
 * page-aligned buffer and flushes aligned chunks via O_DIRECT; _close() flushes
 * the unaligned tail buffered, frees the state, and does NOT close the fd.
 * Both _write and _close return 0 on success, -1 on I/O error (errno set).
 * Upload-only for now; see project_odirect_lustre_writes for the download side.
 */
struct sftp_lustre_odirect;
struct sftp_lustre_odirect *sftp_lustre_odirect_new(int fd);
int sftp_lustre_odirect_write(struct sftp_lustre_odirect *od, uint64_t off,
    const void *data, size_t len);
int sftp_lustre_odirect_close(struct sftp_lustre_odirect *od);

#endif /* _SFTP_LUSTRE_H */
