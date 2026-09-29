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

#ifndef _SFTP_LUSTRE_H
#define _SFTP_LUSTRE_H

#include <stdint.h>

/*
 * The layout status for the errno of a failed layout call: a filesystem
 * that cannot take the layout, not Lustre or without composite support,
 * answers HPN_FILE_LAYOUT_NOT_FS, a site that forbids it _PERM, and
 * anything else _FAIL.  The setters here and the server's directory open
 * share it, so every failure maps the same way.
 */
uint32_t lustre_layout_status(int err);

/*
 * Set the layout a directory should get, the one policy for both ends of a
 * transfer: a tiered composite when small_threshold is above zero and the
 * filesystem takes it - [0, small_threshold) on one OST, the rest striped
 * across stripe_count - otherwise, or when the composite is refused, a
 * plain stripe_count-wide RAID0 stripe.  The _fd form works on an open
 * directory, the server's case; the _path form opens it, for the client's
 * local destination (download parity).  Returns HPN_FILE_LAYOUT_OK/_NOT_FS/
 * _PERM/_FAIL and reports the count applied and the HPN_FILE_LAYOUT_KIND_*
 * set.  Off Linux both answer NOT_FS.
 */
uint32_t lustre_set_layout_fd(int fd, uint32_t stripe_count,
    uint32_t small_threshold, uint32_t *applied_out, uint32_t *kind_out);
uint32_t lustre_set_layout_path(const char *dir, uint32_t stripe_count,
    uint32_t small_threshold, uint32_t *applied_out, uint32_t *kind_out);

/*
 * Read a directory's default OST stripe geometry (count + size) via
 * getxattr("lustre.lov") - no lfs(1) subprocess.  Reports the OST (non-MDT)
 * component of a composite/DoM layout.  Returns 1 iff both *stripe_size and
 * *stripe_count are > 0, else 0.
 */
int lustre_get_stripe(const char *path, uint64_t *stripe_size,
    uint32_t *stripe_count);

#endif /* _SFTP_LUSTRE_H */
