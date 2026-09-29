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

/*
 * sftp-hpn-verify-hash.h - shared verify hashing primitives for
 * Verify transfer, linked into both the client and the server.
 *
 * The hash reader and sftp_hpn_hash_range_ondisk hash what actually
 * landed on the platter (fsync + O_DIRECT), not the page cache.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 */
#ifndef SFTP_HPN_VERIFY_HASH_H
#define SFTP_HPN_VERIFY_HASH_H

#include <sys/types.h>
#include <stdint.h>

/*
 * Periodic progress callback, invoked once per read chunk during a long
 * read-back hash so the caller can keep a heartbeat / watchdog alive.
 * `bytes` is the cumulative count hashed so far.  May be NULL.
 */
typedef void (*sftp_hpn_readback_progress)(void *arg, uint64_t bytes);

/*
 * Hash [offset, offset+length) of `path` with XXH3_64bits.
 *
 * When `ondisk` is nonzero the read reflects the platter: fsync flushes any
 * dirty pages, posix_fadvise drops the clean cached copy (best-effort), and
 * the data is read back via O_DIRECT through a large page-aligned buffer -
 * falling back to a buffered read where O_DIRECT is unavailable or the
 * filesystem refuses it, such as at an unaligned offset.  When `ondisk` is
 * zero it is a plain buffered read.  The file is opened O_RDONLY and a
 * symlink is followed, as SFTP's own open does.  A file shorter than the
 * range hashes what it has.
 *
 * Returns 0 and writes *hash_out on success, -1 on error.
 */
int sftp_hpn_hash_range_ondisk(const char *path, uint64_t offset,
    uint64_t length, int ondisk, uint64_t *hash_out,
    sftp_hpn_readback_progress cb, void *cb_arg);

/*
 * The same hashing for a caller that hashes many ranges of one file: the
 * reader holds the open file, its on-disk mode, one aligned read buffer and
 * one XXH3 state, so a many-range request opens and allocates once.  open
 * returns NULL with errno set, and gives the file's size in *size_out when
 * that is non-NULL.  attach wraps an fd the caller already has, reads it
 * buffered, and leaves it open at close; `path` is for messages.  range
 * hashes [offset, offset+length) with the same
 * rules as sftp_hpn_hash_range_ondisk; cb, when set, gets the bytes hashed
 * so far in this range; it returns 0 with *hash_out set or -1 with errno
 * set.  close takes NULL.
 */
struct sftp_hpn_hash_reader;
struct sftp_hpn_hash_reader *sftp_hpn_hash_reader_open(const char *path,
    int ondisk, off_t *size_out);
struct sftp_hpn_hash_reader *sftp_hpn_hash_reader_attach(int fd,
    const char *path);
int sftp_hpn_hash_reader_range(struct sftp_hpn_hash_reader *reader,
    uint64_t offset, uint64_t length, uint64_t *hash_out,
    sftp_hpn_readback_progress cb, void *cb_arg);
void sftp_hpn_hash_reader_close(struct sftp_hpn_hash_reader *reader);

/*
 * Switch an already-open fd to read from the platter rather than the page
 * cache: flush dirty DATA (fdatasync; fsync fallback), drop the now-clean
 * cached pages (best-effort), and set O_DIRECT.  Returns 1 if O_DIRECT
 * engaged, 0 if it could not be set (caller must read buffered).  Shared so
 * the client read-back and the server's range-hash reply mean the same thing
 * by "on-disk".  `path` is used only for log messages.
 */
int sftp_hpn_fd_set_ondisk(int fd, const char *path);

#endif /* SFTP_HPN_VERIFY_HASH_H */
