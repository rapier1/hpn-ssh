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

/* sftp-hpn-verify.h - client-side verification and verified-resume API. */

#ifndef SFTP_HPN_VERIFY_H
#define SFTP_HPN_VERIFY_H

#include <sys/types.h>
#include <stdint.h>

struct sftp_conn;
struct sftp_hpn_conn;

/* The whole-file and prefix gates of verified resume. Equal sizes do not
 * prove equal content, and a partial destination is safe to append to
 * only when its bytes match the source's prefix, so both sides hash the
 * first length bytes and compare. Returns 1 when the hashes match, 0 when
 * they differ, or -1 when either hash failed. */
int sftp_hpn_prefix_match(struct sftp_conn *conn, int local_fd,
    const char *remote_path, uint64_t length);

/* Inline source hash for -V. Hashing the source as the upload reads it
 * spares the verify phase a second full read of every source file. The
 * state lives in the verify_src_* fields of struct sftp_hpn_conn: arm
 * before the first read, feed each buffer, finish after the last, and
 * take the result at park time if it covers the whole file; dispose
 * drops it on abort or teardown. All are no-ops when not armed or hpn is
 * NULL. hash_buf is the one-shot form for a source read in a single
 * buffer. */
void sftp_hpn_src_arm(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_feed(struct sftp_hpn_conn *hpn, const u_char *buf,
    size_t len);
void sftp_hpn_src_finish(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_dispose(struct sftp_hpn_conn *hpn);
int  sftp_hpn_src_take(struct sftp_hpn_conn *hpn, uint64_t expect_bytes,
    uint64_t *hash_out);
int  sftp_hpn_src_hash_buf(struct sftp_hpn_conn *hpn, const u_char *buf,
    size_t len, uint64_t *hash_out);

/* Verified resume through the chunked engine, called from the resume
 * branches of sftp_upload and sftp_download before the whole-file hash
 * gate. A range-split partial can hold holes below its size, so a prefix
 * resume could append past bad bytes, and re-sending the whole file
 * throws away the good ones; hashing in chunks and moving only the
 * chunks that differ avoids both. The whole file is the span. dest_size
 * is the destination's current size, so chunks past it move without
 * being hashed. Returns 1 when every chunk matched and the transfer can
 * be skipped, 0 when the mismatched chunks moved and the transfer is
 * complete, or -1 when the chunked path declined, quietly for a server
 * without sftp-hash-range or a file under the two-chunk floor, or
 * failed, loudly, and the caller falls through to the whole-file gate.
 * The fd's position after return is undefined. */
int sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size);
int sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size,
    off_t dest_size);

/* Resolve the verify auto-repair settings once for both the orchestrator
 * and the single-connection path, so they cannot drift. The -X
 * VerifyRepair=no token is the only disable, and the attempt cap is 3. */
void sftp_hpn_verify_repair_resolve(int no_verify_repair_cli,
    int *enabled_out, int *attempts_out);

/* Post-transfer verify with auto-repair. A mismatch found after the
 * transfer is repaired in place, by re-sending only what differs, rather
 * than failing the file, and one implementation serves the fleet and
 * the single-connection verify phase so both behave alike. The file form
 * compares the sizes first and reports a difference as a mismatch, since
 * a size difference cannot be repaired in place; the range form checks
 * one range. local_is_target says which side was written: 0 for an
 * upload, 1 for a download. have_local_hash and local_hash supply a
 * source hash already computed, which skips the local read. Both return
 * 0 when verified, after a repair if one ran and *repaired_out is then
 * set (NULL is fine), 1 when unrepairable, or -1 when nothing could be
 * verified. */
int sftp_hpn_verify_repair_file(struct sftp_conn *conn,
    const char *local_path, const char *remote_path, int local_is_target,
    int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out);
int sftp_hpn_verify_repair_range(struct sftp_conn *conn,
    const char *local_path, const char *remote_path, int local_is_target,
    off_t off, off_t len, int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out);

/* Verify transfer's entry to the engine. len 0 verifies the whole file,
 * otherwise the range [off, off + len). An unverifiable result on a live
 * connection is retried, and one that never resolves is a failure for
 * the caller to record. A dead connection returns -1 at once so the
 * caller can requeue the work. */
int sftp_hpn_verify_transfer(struct sftp_conn *, const char *,
    const char *, int, off_t, off_t, int, uint64_t, int, int, int *);

#endif /* SFTP_HPN_VERIFY_H */
