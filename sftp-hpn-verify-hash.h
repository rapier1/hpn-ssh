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
 * HPNVerifyTransfer, linked into both the client and the server.
 *
 * Target side: sftp_hpn_hash_file_ondisk hashes what actually landed on the
 * platter (fsync + O_DIRECT), not the page cache.  Source side:
 * sftp_hpn_src_hashset accumulates per-entry XXH3 of bundled files as they
 * are packed (it implements the tar writer's data tap).
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
 * Hash the first `length` bytes of `path` with XXH3_64bits.
 *
 * When `ondisk` is nonzero the read reflects the platter: fsync flushes any
 * dirty pages, posix_fadvise drops the clean cached copy (best-effort), and
 * the data is read back via O_DIRECT through a large page-aligned buffer -
 * falling back to a buffered read where O_DIRECT is unavailable.  When
 * `ondisk` is zero it is a plain buffered read.  The file is opened
 * O_RDONLY|O_NOFOLLOW.
 *
 * Returns 0 and writes *hash_out on success, -1 on error.
 */
int sftp_hpn_hash_file_ondisk(const char *path, uint64_t length, int ondisk,
    uint64_t *hash_out, sftp_hpn_readback_progress cb, void *cb_arg);

/*
 * Range variant: hash [offset, offset+length) of `path`.  `offset` must be
 * O_DIRECT-aligned in `ondisk` mode (verify chunks are >=256 MiB, so they are).
 * Used by the range-granular parallel verify to read back one chunk of a large
 * file.  Same return contract as sftp_hpn_hash_file_ondisk.
 */
int sftp_hpn_hash_range_ondisk(const char *path, uint64_t offset,
    uint64_t length, int ondisk, uint64_t *hash_out,
    sftp_hpn_readback_progress cb, void *cb_arg);

/*
 * Switch an already-open fd to read from the platter rather than the page
 * cache: flush dirty DATA (fdatasync; fsync fallback), drop the now-clean
 * cached pages (best-effort), and set O_DIRECT.  Returns 1 if O_DIRECT
 * engaged, 0 if it could not be set (caller must read buffered).  Shared so
 * the client read-back and the server's range-hash reply mean the same thing
 * by "on-disk".  `path` is used only for log messages.
 */
int sftp_hpn_fd_set_ondisk(int fd, const char *path);

/*
 * Per-entry source-hash accumulator (bundle integrity, source side).
 * Implements the tar writer's data tap: XXH3 each bundled file's source bytes
 * as they are packed, keyed by archive_path.  Plug sftp_hpn_src_hashset_tap
 * (with the set as arg) into a struct sftp_hpn_tar_data_tap; after packing,
 * look hashes up by path with _get.  Matches the tap's on_data signature.
 */
struct sftp_hpn_src_hashset;
struct sftp_hpn_src_hashset *sftp_hpn_src_hashset_new(void);
void sftp_hpn_src_hashset_free(struct sftp_hpn_src_hashset *s);
void sftp_hpn_src_hashset_tap(void *arg, const char *archive_path,
    const u_char *data, size_t len, int final);
int  sftp_hpn_src_hashset_get(struct sftp_hpn_src_hashset *s,
    const char *archive_path, uint64_t *hash_out);
/* Iterate every (archive_path, hash) pair in insertion order. */
void sftp_hpn_src_hashset_foreach(struct sftp_hpn_src_hashset *s,
    void (*cb)(void *arg, const char *archive_path, uint64_t hash), void *arg);

#endif /* SFTP_HPN_VERIFY_HASH_H */
