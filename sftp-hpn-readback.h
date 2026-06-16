/*
 * sftp-hpn-readback.h - on-disk read-back hashing for HPNVerifyTransfer.
 *
 * Shared by the client (download target read-back) and, in a later step, the
 * server (upload target read-back).  The point of "read-back" is to hash what
 * actually landed on the platter rather than what sits in the page cache, so a
 * verified transfer's guarantee is about durable bytes, not cached ones.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 */
#ifndef SFTP_HPN_READBACK_H
#define SFTP_HPN_READBACK_H

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

#endif /* SFTP_HPN_READBACK_H */
