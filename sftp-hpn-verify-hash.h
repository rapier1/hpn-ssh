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
