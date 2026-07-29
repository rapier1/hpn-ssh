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

/* sftp-hpn-bundle.h - shared wire-protocol constants for the HPN-SSH
 * bundle extensions (hpn-bundle-open@hpnssh.org for upload,
 * hpn-bundle-fetch@hpnssh.org for download).
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * Both ends MUST agree on these values.  They live in a single header
 * so the compiler enforces the agreement - previously they were
 * defined separately in sftp-hpn-client.c and sftp-hpn-server.c with
 * "must match the other side" comments, which is the kind of contract
 * that drifts during refactoring.
 */

#ifndef _SFTP_HPN_BUNDLE_H
#define _SFTP_HPN_BUNDLE_H

/*
 * Bundle flags carried in the SSH_FXP_EXTENDED open / fetch request:
 *
 *   PRESERVE - keep mtime + perm bits on the extracted/packed file
 *              (mirror of the standard SFTP -p semantics).
 *   FSYNC    - request the server fsync() each file after extraction.
 *              Upload-side only; ignored on the download/fetch path
 *              (fsync is a server-side operation).
 *
 * Encoded as a single uint32_t after the dest_dir / path-list.
 */
#define HPN_BUNDLE_FLAG_PRESERVE   0x00000001U
#define HPN_BUNDLE_FLAG_FSYNC      0x00000002U
/* NO_POOL: client asks the server to extract WITHOUT the writer pool (set when
 * the user disables it via HPNWriterPool=no).  The server-side operator toggle
 * (sshd_config HPNWriterPool / HPN_WRITER_POOL env) can also force the pool off
 * regardless of this flag. */
#define HPN_BUNDLE_FLAG_NO_POOL    0x00000004U

/*
 * Tar codec output block size.  Each block becomes one SSH_FXP_WRITE
 * message on the upload path; on the download path it's the chunk
 * size for reading the packed tar buffer.  128 KiB matches
 * DEFAULT_TRANSFER_BUFLEN.  Both ends use the same value so block
 * alignment is consistent across pack/unpack.
 */
#define HPN_BUNDLE_BLOCK_BYTES     (128 * 1024)

/*
 * Bundle-eligibility policy, shared by the parallel planner and the
 * serial recursive walks so both make identical bundling decisions
 * for the same corpus.  A file at or above BUNDLE_FILE_MAX_BYTES(target)
 * does not amortise the per-file OPEN/CLOSE round trips a bundle
 * exists to avoid; it takes the regular single-file path.
 */
#define BUNDLE_MIN_FILES_PER_BUNDLE  4
#define BUNDLE_FILE_MAX_BYTES(target) \
    ((target) / BUNDLE_MIN_FILES_PER_BUNDLE)

/* Safety ceiling on members per bundle: a pathological stream of tiny
 * files cannot grow a single batch without bound; the byte cap binds
 * first for any file >= ~1 KiB. */
#define BUNDLE_BATCH_MAX_FILES  8192

/* Wire cost of one file in a bundle: the fixed record header (type +
 * mode + mtime + size + path_len = 23 bytes, see sftp-hpn-tar.h) plus
 * the archive path plus the file data, with no padding.  Accumulators
 * size bundles by this framed cost rather than raw payload, so a
 * bundle's wire size stays near the byte cap even when tiny-file
 * headers/paths dominate. */
#define BUNDLE_REC_FRAME_BYTES(plen, sz) \
    (23ULL + (uint64_t)(plen) + (uint64_t)(sz))

/*
 * Shared accumulation decisions - one source of truth used by BOTH the
 * parallel producer (sftp-parallel-unit.c) and the serial walk
 * accumulator (sftp-hpn-client.c), so the two modes group bundles
 * identically for the same corpus.
 */
static inline int
hpn_bundle_file_eligible(uint64_t file_size, uint64_t bundle_target)
{
	return file_size < BUNDLE_FILE_MAX_BYTES(bundle_target);
}

static inline int
hpn_bundle_should_flush(uint64_t framed_bytes, int members,
    uint64_t bundle_target)
{
	return framed_bytes >= bundle_target ||
	    members >= BUNDLE_BATCH_MAX_FILES;
}

#endif /* _SFTP_HPN_BUNDLE_H */
