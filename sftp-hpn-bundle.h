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
/*
 *   VERIFY - HPNVerifyTransfer: after extracting and fsyncing the batch, the
 *            server reads each file back (O_DIRECT) and returns per-file XXH3
 *            hashes in the CLOSE reply (SSH_FXP_EXTENDED_REPLY instead of
 *            STATUS) so the client can compare against the source hashes it
 *            teed during pack.  Upload path only.
 */
#define HPN_BUNDLE_FLAG_VERIFY     0x00000004U

/*
 * Tar codec output block size.  Each block becomes one SSH_FXP_WRITE
 * message on the upload path; on the download path it's the chunk
 * size for reading the packed tar buffer.  128 KiB matches
 * DEFAULT_TRANSFER_BUFLEN.  Both ends use the same value so block
 * alignment is consistent across pack/unpack.
 */
#define HPN_BUNDLE_BLOCK_BYTES     (128 * 1024)

#endif /* _SFTP_HPN_BUNDLE_H */
