/*
 * sftp-hpn-verify.h - client-side verification / verified-resume API.
 * Chained from sftp-hpn-client.h so existing consumers see no change.
 */

#ifndef SFTP_HPN_VERIFY_H
#define SFTP_HPN_VERIFY_H

/* ── Chunked resume: sftp-hash-range@hpnssh.org client helpers ──────────────
 *
 * The chunked-resume code in sftp_upload / sftp_download builds a chunk
 * layout for a same-size source/destination pair, hashes each chunk locally,
 * asks the server to hash the same chunks via sftp-hash-range, then issues
 * a contiguous-run re-transfer for each set of mismatched chunks.  These two
 * helpers expose the wire-level hash query and the local-side XXH3 of a
 * range so the decision-flow code stays free of protocol details.
 *
 * `struct sftp_hash_range` is the parameter type for batched range queries;
 * the same struct describes both sides (client request, server response is
 * a parallel hashes[] array).
 */
struct sftp_hash_range {
	u_int64_t	off;
	u_int64_t	len;
};

struct sftp_conn;

/*
 * Ask the server to XXH3 each (off, len) range of `path` and write the N
 * resulting hashes into `hashes_out` (caller-allocated, n entries).
 *
 * All-or-nothing semantics: returns 0 only when the server returned all N
 * hashes successfully.  Returns -1 on any failure (server STATUS reply,
 * transport error, parse error, server lacks the extension); emits a
 * user-visible `logit_f` so the operator knows the chunked path bailed out
 * before the caller falls back to whole-file hashing or full re-transfer.
 *
 * Caller must verify `sftp_conn_has_hash_range(conn)` before calling; if
 * the extension is not advertised, this returns -1 immediately with a
 * debug log (the upstream lacks-extension case is not loud - it's expected).
 */
int sftp_hpn_hash_remote_ranges(struct sftp_conn *conn, const char *path,
    const struct sftp_hash_range *ranges, u_int n, u_int64_t *hashes_out);

/*
 * Per-range post-transfer verify for a range-split upload (HPNVerifyTransfer).
 * local_hashes[i] / valid[i] carry the worker's send-time tee for each range;
 * ranges that did not tee cleanly are re-read here.  Returns 0 (match),
 * 1 (mismatch / size disagreement = corruption), -1 (could not verify).
 */
int sftp_hpn_verify_transfer_ranges(struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    const struct sftp_hash_range *ranges, const u_int64_t *local_hashes,
    const int *valid, u_int n);

/*
 * Verify one [off, off+len) chunk of a file (range-granular parallel verify):
 * local range hash vs remote sftp-hash-range, compared.  Caller picks local vs
 * remote per direction.  When have_local_hash is set, local_hash (a teed upload
 * source hash) is used and the local read is skipped; otherwise the local range
 * is O_DIRECT-read back.  0 = match, 1 = mismatch, -1 = unverifiable.
 */
int sftp_hpn_verify_chunk(struct sftp_conn *conn, const char *local_path,
    const char *remote_path, off_t off, off_t len,
    int have_local_hash, uint64_t local_hash);

int sftp_hpn_xxhash_local_fd(struct sftp_conn *, int, uint64_t, uint64_t *);
int sftp_hpn_hash_remote_file(struct sftp_conn *, const char *, uint64_t,
    uint32_t, uint64_t *);
/*
 * Post-transfer integrity check.  local_is_target is 1 when the local file is
 * one this host just wrote (a download): its hash is taken as a fsync+O_DIRECT
 * read-back of what landed on disk.  0 when the local file is the source (an
 * upload): the hash comes from the inline accumulator or a buffered re-read.
 *
 * trust_inline_src applies only to the upload case (local_is_target 0): 1 lets
 * the source hash come from the per-connection inline accumulator - safe only
 * when this verify runs on the connection that just uploaded THIS file (the
 * classic inline path).  0 forces a fresh source re-read.  The decoupled
 * post-transfer verify MUST pass 0: it can run on a different connection than
 * the uploader, where the accumulator (keyed by size alone) may hold another
 * same-size file's hash.
 */
int sftp_hpn_verify_transfer(struct sftp_conn *, const char *, const char *,
    int local_is_target, int trust_inline_src);
int sftp_hpn_xxhash_local_range(int fd, u_int64_t offset, u_int64_t length,
    u_int64_t *hash_out);

/*
 * Attempt a chunked-resume upload when remote and local sizes match.
 *
 * Called from sftp_upload's size-match branch BEFORE the existing whole-file
 * hash gate.  Builds a chunk layout for [0, file_size), hashes each chunk
 * locally and remotely, then re-transfers each contiguous run of mismatched
 * chunks via sftp_upload_range.  This is the cost-saving half of the
 * sparse-hole gate: instead of trucating the whole file when sizes match
 * but content differs (which is what the existing path does), we transfer
 * only the chunks that actually need it.
 *
 * Decline conditions (fall through to existing full-file gate):
 *   - server does not advertise sftp-hash-range@hpnssh.org
 *   - file is below CHUNK_HASH_MIN_FILE_SIZE (overhead not worth it)
 *   - chunk count would exceed MAX_RANGES_PER_REQUEST
 *   - local hashing failed (I/O error on the source)
 *
 * Returns:
 *    1  all chunks matched - file is already identical, caller should
 *       skip (return 1 from sftp_upload).
 *    0  one or more chunks mismatched - they have been re-transferred
 *       successfully, caller should treat the upload as complete
 *       (return 0 from sftp_upload).
 *   -1  declined or any failure during the chunked path; caller should
 *       fall through to the existing whole-file hash gate.  User-visible
 *       warnings are emitted by the helpers (via logit_f) for server
 *       failures; quiet (debug) for "extension not available" and other
 *       declined-by-policy paths.
 *
 * The fd's position after return is undefined; caller re-seeks as needed.
 */
int sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size);

/*
 * Symmetric download-side helper to sftp_hpn_try_chunked_resume_upload.
 *
 * Called from sftp_download's size-match branch BEFORE the existing whole-
 * file hash gate.  Hashes each chunk of `local_fd` (the partially-downloaded
 * destination) and of `remote_path` (the authoritative source), then for
 * each contiguous run of mismatched chunks calls sftp_download_range to
 * re-fetch only those bytes.  Same three-value return semantics as the
 * upload sibling; same decline conditions; same user-visible logit on
 * success and on server-side hash failure.
 *
 * Returns:
 *    1  all chunks matched - local file already identical to remote, caller
 *       should treat the resume as skip (sets skip_ret=1, goto resume_fail).
 *    0  one or more chunks mismatched and were re-fetched successfully,
 *       caller should treat the download as complete (sets skip_ret=0,
 *       goto resume_fail).
 *   -1  declined or failure; caller should fall through to the existing
 *       whole-file hash gate.
 *
 * The fd's position after return is undefined.
 */
int sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size);

#endif /* SFTP_HPN_VERIFY_H */
