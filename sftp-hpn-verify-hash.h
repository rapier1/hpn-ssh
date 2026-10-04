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

/* sftp-hpn-verify-hash.h - the hash reader every verify path shares.
 *
 * Hashes byte ranges of a file with XXH3. With ondisk set, the read
 * reflects the device rather than the page cache. sftp-hpn-verify-hash.c
 * describes how, and who links it. */

#ifndef SFTP_HPN_VERIFY_HASH_H
#define SFTP_HPN_VERIFY_HASH_H

#include <sys/types.h>
#include <stdint.h>

/* Progress callback, called after each read with the bytes of the range
 * hashed so far, so a caller can keep its heartbeat, watchdog, or meter
 * moving through a long hash. The first argument is the caller's context.
 * Callers that do not need it pass NULL. */
typedef void (*sftp_hpn_readback_progress)(void *, uint64_t);

/* Opaque. sftp-hpn-verify-hash.c defines it. */
struct sftp_hpn_hash_reader;

/* Hash a range of a file, given by an offset and then a length, with XXH3,
 * opening and closing the file for the one call. With ondisk set, the read
 * reflects the device rather than the page cache, falling back to buffered
 * where O_DIRECT is unavailable or refused. Without it, the read is
 * buffered. The file is opened read-only and a symlink is followed, as
 * SFTP's own open does. A file shorter than the range hashes what it has.
 * The progress callback may be NULL. Returns 0 with the hash set, or -1
 * after logging the cause. */
int sftp_hpn_hash_range(const char *, uint64_t, uint64_t, int, uint64_t *,
    sftp_hpn_readback_progress, void *);

/* The same hashing for a caller that hashes many ranges of one file. The
 * reader holds the open file, its on-disk mode, one aligned read buffer,
 * and one XXH3 state, so a many-range request opens and allocates once.
 * open gives the file's size through its last argument when that is
 * non-NULL, and returns NULL with errno set. attach wraps an fd the caller
 * already has, reads it buffered, and leaves it open at close. Its path is
 * used only in messages. range hashes a range given by an offset and then
 * a length, with the same rules as sftp_hpn_hash_range, and the progress
 * callback, when set, gets the bytes hashed so far in that range. It
 * returns 0 with the hash set, or -1 with errno set. close takes NULL. */
struct sftp_hpn_hash_reader *sftp_hpn_hash_reader_open(const char *, int,
    off_t *);
struct sftp_hpn_hash_reader *sftp_hpn_hash_reader_attach(int, const char *);
int sftp_hpn_hash_reader_range(struct sftp_hpn_hash_reader *, uint64_t,
    uint64_t, uint64_t *, sftp_hpn_readback_progress, void *);
void sftp_hpn_hash_reader_close(struct sftp_hpn_hash_reader *);

#endif /* SFTP_HPN_VERIFY_HASH_H */
