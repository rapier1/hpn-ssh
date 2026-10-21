/*
 * Copyright (c) 2024-2026 The Board of Trustees of Carnegie Mellon University.
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

/* sftp-lustre.h - the Lustre layout interface: set a directory's layout,
 * and read the stripe geometry a path gets.
 *
 * Both ends link it. The server applies layouts for the hpn-file-layout
 * extension, and the client applies them to local destinations on
 * download. The layout ABI stays private to sftp-lustre.c, and the setters
 * return the HPN_FILE_LAYOUT_* codes from sftp-hpn-server.h. */

#ifndef _SFTP_LUSTRE_H
#define _SFTP_LUSTRE_H

#include <stdint.h>

/* The stripe geometry that files created at a path get: the path, then
 * where to put the stripe size and count. Each field comes from the
 * nearest layout up the tree that sets it, and a composite layout gives
 * its first component not on the MDT. Returns 1 with both fields above 0,
 * or 0 with both 0. Off Linux it always returns 0. */
int lustre_get_stripe(const char *, uint64_t *, uint32_t *);

/* Map the errno of a failed layout call, or of opening a directory for
 * one, to an HPN_FILE_LAYOUT_* status: NOT_FS for a filesystem that cannot
 * take the layout, PERM for a site that forbids it, and FAIL for anything
 * else. The setters and the server's directory open share it, so every
 * failure maps the same way. */
uint32_t lustre_layout_status(int);

/* Set the layout a directory should get, one policy for both ends of a
 * transfer. The arguments are the directory, the stripe count, the tiered
 * threshold, and where to put the count applied and the
 * HPN_FILE_LAYOUT_KIND_* set. With a threshold above 0 the layout is a
 * tiered composite: [0, threshold) on one OST, the rest across stripe count
 * OSTs. Otherwise, or when the filesystem refuses the composite, it is a
 * plain RAID0 stripe across stripe count OSTs. A stripe count above 0xFFFF
 * fails. The _fd form takes an open directory, the server's case. The
 * _path form opens one, following a symlink, for the client's local
 * destination on download. Both return an HPN_FILE_LAYOUT_* status, and
 * the count applied is the one requested, which Lustre may clamp silently.
 * Off Linux the setters behind them return NOT_FS. */
uint32_t lustre_set_layout_fd(int, uint32_t, uint32_t, uint32_t *,
    uint32_t *);
uint32_t lustre_set_layout_path(const char *, uint32_t, uint32_t,
    uint32_t *, uint32_t *);

#endif /* _SFTP_LUSTRE_H */
