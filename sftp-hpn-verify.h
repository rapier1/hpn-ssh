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

/* The whole-file and prefix gates of verified resume: hash the first
 * length bytes of the local file behind local_fd and of the remote
 * file at remote_path and compare them. Returns 1 when the hashes
 * match, 0 when they differ, or -1 when either hash failed. */
int sftp_hpn_prefix_match(struct sftp_conn *conn, int local_fd,
    const char *remote_path, uint64_t length);

/* Verified resume through the chunked engine, called from the resume
 * branches of sftp_upload and sftp_download before the whole-file hash
 * gate, for a destination of the same size or a partial one. The whole
 * file is the span. dest_size is the destination's current size, so
 * chunks past it move without being hashed. Returns 1 when every chunk
 * matched and the transfer can be skipped, 0 when the mismatched chunks
 * moved and the transfer is complete, or -1 when the chunked path
 * declined, quietly for a server without sftp-hash-range or a file
 * under the two-chunk floor, or failed, loudly, and the caller falls
 * through to the whole-file gate. The fd's position after return is
 * undefined. */
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

/* Verify a file or one range of it against the other side and, on a
 * mismatch with repair enabled, repair and re-verify up to max_attempts
 * times, stopping early when two failed destination hashes in a row
 * show a deterministic fault. local_is_target says which side was
 * written: 0 for an upload, 1 for a download. have_local_hash and
 * local_hash supply a source hash already computed, which skips the
 * local read. A range at or above the chunk floor is repaired by
 * splicing only the mismatched chunks; a smaller one is re-sent whole.
 * The file form compares the sizes first and reports a difference as a
 * mismatch. Both return 0 when verified, after a repair if one ran and
 * *repaired_out is then set (NULL is fine), 1 when unrepairable, or -1
 * when nothing could be verified, which callers treat as skipped. One
 * implementation serves the orchestrator and the single-connection
 * verify phase. */
int sftp_hpn_verify_repair_file(struct sftp_conn *conn,
    const char *local_path, const char *remote_path, int local_is_target,
    int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out);
int sftp_hpn_verify_repair_range(struct sftp_conn *conn,
    const char *local_path, const char *remote_path, int local_is_target,
    off_t off, off_t len, int have_local_hash, uint64_t local_hash,
    int repair_enabled, int max_attempts, int *repaired_out);

/* Inline source hash for verify transfer, on the verify_src_* state of
 * struct sftp_hpn_conn. arm starts a streaming XXH3, feed adds bytes as
 * the source is read, finish digests, dispose abandons a partial result,
 * and take returns the hash if it covers expect_bytes. All are no-ops
 * when not armed or hpn is NULL. hash_buf is the one-shot form for a
 * source read in a single buffer. */
void sftp_hpn_src_arm(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_feed(struct sftp_hpn_conn *hpn, const u_char *buf,
    size_t len);
void sftp_hpn_src_finish(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_dispose(struct sftp_hpn_conn *hpn);
int  sftp_hpn_src_take(struct sftp_hpn_conn *hpn, uint64_t expect_bytes,
    uint64_t *hash_out);
int  sftp_hpn_src_hash_buf(struct sftp_hpn_conn *hpn, const u_char *buf,
    size_t len, uint64_t *hash_out);

#endif /* SFTP_HPN_VERIFY_H */
