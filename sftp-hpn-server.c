/*
 * sftp-hpn-server.c - HPN-SSH server-side SFTP extensions.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Isolating HPN-specific extension handlers here keeps sftp-server.c's
 * diff against upstream small.
 *
 * hpn-fs-info@hpnssh.org
 * -----------------------
 * Returns filesystem type and stripe geometry for a given path so that
 * the parallel client (sftp-parallel.c) can align byte-range transfers to
 * Lustre/GPFS stripe boundaries.
 *
 * Detection layers (each falls back to the next):
 *   1. statfs() f_type magic number → filesystem type string
 *   2. Lustre: invoke "lfs getstripe -d --yaml <path>" as subprocess
 *      (safe: path is passed as argv, not interpolated into a shell command)
 *   3. GPFS:   type detected via magic; block_size from statvfs()
 *   4. Fallback: block_size from statvfs(), zeros for stripe fields
 *
 * Wire format (SSH_FXP_EXTENDED_REPLY):
 *   fs_type      string   "lustre"|"gpfs"|"xfs"|"ext4"|"nfs"|"unknown"|...
 *   stripe_size  uint64   bytes per stripe; 0 if not applicable
 *   stripe_count uint32   number of stripes/OSTs; 0 if not applicable
 *   block_size   uint64   optimal I/O block size (always present)
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#include "includes.h"

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "atomicio.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-bundle.h"
#include "sftp-hpn-server.h"
#include "sftp-hpn-readback.h"		/* sftp_hpn_hash_file_ondisk */
#include "sftp-hpn-bundle-server.h"	/* process_hpn_bundle_open / _fetch */
#include "sftp-lustre.h"		/* lustre_set_stripe_fd / _tiered_layout_fd / _get_stripe */
#define XXH_INLINE_ALL
#include "xxhash.h"

/* Linux filesystem type magic numbers. */
#ifndef EXT4_SUPER_MAGIC
# define EXT4_SUPER_MAGIC   0xEF53
#endif
#ifndef XFS_SUPER_MAGIC
# define XFS_SUPER_MAGIC    0x58465342
#endif
#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC    0x6969
#endif
#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC        0x01021994
#endif
#ifndef BTRFS_SUPER_MAGIC
# define BTRFS_SUPER_MAGIC  0x9123683E
#endif
/*
 * Lustre magic - may not appear in older <linux/magic.h>.
 * GPFS has no widely-distributed magic; we rely on a less-common value
 * that matches GPFS internal superblock type.
 */
#ifndef LUSTRE_SUPER_MAGIC
# define LUSTRE_SUPER_MAGIC 0x0BD00BD0
#endif
#define GPFS_SUPER_MAGIC    0x47504653u   /* 'G','P','F','S' - unofficial */

/*
 * Map a statfs() f_type value to a printable filesystem name.
 * Returns a static string (no allocation needed).
 */
static const char *
fstype_from_magic(unsigned long ftype)
{
	switch (ftype) {
	case LUSTRE_SUPER_MAGIC: return "lustre";
	case GPFS_SUPER_MAGIC:   return "gpfs";
	case EXT4_SUPER_MAGIC:   return "ext4";
	case XFS_SUPER_MAGIC:    return "xfs";
	case NFS_SUPER_MAGIC:    return "nfs";
	case TMPFS_MAGIC:        return "tmpfs";
	case BTRFS_SUPER_MAGIC:  return "btrfs";
	default:                 return "unknown";
	}
}

/* process_hpn_bundle_open / process_hpn_bundle_fetch declarations live
 * in sftp-hpn-bundle-server.h (included above).  The dispatcher routes
 * the SSH2_FXP_EXTENDED messages with those extension names to those
 * handlers; the implementation moved to sftp-hpn-bundle-server.c during
 * the 2026-05-31 structural refactor. */

/*
 * Translate errno to an SFTP wire status code, mirroring the
 * errno_to_portable() helper in sftp-server.c (which is file-local
 * static and therefore not reachable from here).  Keep in sync if
 * upstream extends the mapping.
 */
static u_int
errno_to_sftp_status(int e)
{
	switch (e) {
	case 0:
		return SSH2_FX_OK;
	case ENOENT:
	case ENOTDIR:
	case EBADF:
	case ELOOP:
		return SSH2_FX_NO_SUCH_FILE;
	case EPERM:
	case EACCES:
	case EFAULT:
		return SSH2_FX_PERMISSION_DENIED;
	case ENAMETOOLONG:
	case EINVAL:
		return SSH2_FX_BAD_MESSAGE;
	case ENOSYS:
		return SSH2_FX_OP_UNSUPPORTED;
	default:
		return SSH2_FX_FAILURE;
	}
}

/*
 * Compose and enqueue an SSH2_FXP_STATUS reply with empty error message
 * and language tag onto oqueue.  Mirrors the inline pattern used by the
 * bundle handlers; factored out for handlers that need it more than once.
 */
static void
send_status_oqueue(struct sshbuf *oqueue, u_int id, u_int status)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose status");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue status");
	sshbuf_free(msg);
}


/* ── BEGIN sftp-hash-range: chunked-resume ranged XXH3 hashing ─────────────
 *
 * Multi-range variant of hpn-check-file: client supplies N (offset, length)
 * tuples in one request, server returns N XXH3_64bits hashes in one reply.
 * Used by chunked resume to identify exactly which chunks of a same-size
 * destination differ from the source, so only those chunks get re-transferred
 * instead of the whole file (closes the cost half of the sparse-hole gate).
 *
 * Wire format:
 *   request:  string path | uint32 num_ranges
 *             | num_ranges * (uint64 off, uint64 len)
 *   reply:    uint32 num_hashes (== num_ranges)
 *             | num_hashes * uint64 hash
 *
 * Error model: all-or-nothing.  Any range that fails to hash (I/O error,
 * resource cap, file vanished mid-request) rejects the entire request with
 * a single SSH2_FXP_STATUS reply -- no partial hashes.  The client falls
 * back to hpn-check-file whole-file hash on this failure, then to full
 * re-transfer if that also fails.
 *
 * EOF clamping: offset+length > file_size is clamped to [offset, file_size);
 * offset >= file_size hashes zero bytes (well-defined XXH3 constant).  The
 * client sees a mismatch against its local "full chunk" hash and correctly
 * flags the chunk as incomplete.
 */
#define SFTP_HASH_RANGE_MAX_RANGES	65536U
#define SFTP_HASH_RANGE_MAX_LEN		((u_int64_t)SSHBUF_SIZE_MAX)

struct hash_range {
	u_int64_t	off;
	u_int64_t	len;
};

/*
 * Drain oqueue synchronously to STDOUT_FILENO via atomicio().  Used by the
 * heartbeat path so the bytes actually reach the SSH transport mid-handler
 * instead of sitting in oqueue until the handler returns (sftp-server's
 * main poll loop does not iterate during a handler call).  Order is
 * preserved: pre-handler pending bytes leave first, the heartbeat after.
 */
static void
flush_oqueue_blocking(struct sshbuf *oqueue)
{
	size_t	len, wrote;

	len = sshbuf_len(oqueue);
	if (len == 0)
		return;
	wrote = atomicio(vwrite, STDOUT_FILENO,
	    (void *)sshbuf_ptr(oqueue), len);
	if (wrote > 0)
		(void)sshbuf_consume(oqueue, wrote);
}

/*
 * Emit an sftp-hash-range heartbeat into oqueue, then synchronously
 * drain.  Wire shape matches the final reply prefix
 * (type | id | num_hashes) but with the reserved sentinel
 * HPN_NUM_HASHES_HEARTBEAT in num_hashes, followed by a u64
 * bytes-hashed-so-far figure so the client can distinguish a slow
 * backend from a stalled one.  Called from the inner read
 * loop every HPN_HEARTBEAT_EMIT_INTERVAL_SEC seconds; lets the client
 * refresh its watchdog-pause window so the parallel orchestrator doesn't
 * kill the worker mid-hash on a slow / contended disk.
 */
static void
send_hpn_hash_range_heartbeat(u_int id, struct sshbuf *oqueue,
    u_int64_t progress)
{
	struct sshbuf	*msg;
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg,
	        (u_int32_t)HPN_NUM_HASHES_HEARTBEAT)) != 0 ||
	    (r = sshbuf_put_u64(msg, progress)) != 0)
		fatal_fr(r, "compose heartbeat");
	debug3("sftp-hash-range: heartbeat id=%u", id);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue heartbeat");
	sshbuf_free(msg);
	flush_oqueue_blocking(oqueue);
}

static void
process_hpn_hash_range(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char			*path = NULL;
	u_int32_t		 num_ranges = 0;
	struct hash_range	*ranges = NULL;
	u_int64_t		*hashes = NULL;
	XXH3_state_t		*state = NULL;
	struct sshbuf		*msg = NULL;
	struct stat		 st;
	u_char			 buf[65536];
	u_int64_t		 fsize = 0;
	u_int64_t		 hashed_total = 0;
	time_t			 last_hb_sec;
	u_int32_t		 i;
	int			 fd = -1;
	int			 r;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &num_ranges)) != 0) {
		error_f("parse: %s", ssh_err(r));
		goto fail_status;
	}

	debug3("request %u: sftp-hash-range \"%s\" num_ranges=%u",
	    id, path, num_ranges);

	if (num_ranges == 0) {
		error_f("rejecting sftp-hash-range with num_ranges=0 "
		    "for \"%s\"", path);
		send_status_oqueue(oqueue, id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	if (num_ranges > SFTP_HASH_RANGE_MAX_RANGES) {
		error_f("rejecting sftp-hash-range num_ranges=%u > cap %u "
		    "for \"%s\"", num_ranges, SFTP_HASH_RANGE_MAX_RANGES,
		    path);
		goto fail_status;
	}

	if ((ranges = calloc(num_ranges, sizeof(*ranges))) == NULL ||
	    (hashes = calloc(num_ranges, sizeof(*hashes))) == NULL) {
		error_f("calloc for %u ranges failed", num_ranges);
		goto fail_status;
	}
	for (i = 0; i < num_ranges; i++) {
		if ((r = sshbuf_get_u64(iqueue, &ranges[i].off)) != 0 ||
		    (r = sshbuf_get_u64(iqueue, &ranges[i].len)) != 0) {
			error_f("parse range %u: %s", i, ssh_err(r));
			goto fail_status;
		}
		if (ranges[i].len > SFTP_HASH_RANGE_MAX_LEN) {
			error_f("range %u length %llu > cap %llu for \"%s\"",
			    i, (unsigned long long)ranges[i].len,
			    (unsigned long long)SFTP_HASH_RANGE_MAX_LEN, path);
			goto fail_status;
		}
	}

	logit("sftp-hash-range \"%s\" num_ranges=%u", path, num_ranges);

	if ((fd = open(path, O_RDONLY|O_NOFOLLOW)) == -1) {
		send_status_oqueue(oqueue, id,
		    errno_to_sftp_status(errno));
		goto out;
	}
	if (fstat(fd, &st) == -1) {
		send_status_oqueue(oqueue, id,
		    errno_to_sftp_status(errno));
		goto out;
	}
	fsize = (u_int64_t)st.st_size;

	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		goto fail_status;
	}

	/*
	 * For each range, lseek to the offset and hash bytes
	 * [offset, min(offset+length, file_size)).  EOF clamping handled by
	 * starting `remaining` at the clamped length (zero if offset >= fsize).
	 * All-or-nothing: any read or hash failure bails out with a single
	 * SSH2_FXP_STATUS reply.
	 *
	 * Heartbeats: every HPN_HEARTBEAT_EMIT_INTERVAL_SEC of elapsed wall
	 * time inside this loop we enqueue a tiny "still working" reply on
	 * oqueue.  Lets the client's parallel orchestrator's watchdog see
	 * proof of life so it doesn't kill the worker mid-hash on slow /
	 * contended storage.  See sftp-hpn-server.h for the wire format.
	 */
	last_hb_sec = monotime();
	for (i = 0; i < num_ranges; i++) {
		u_int64_t	 off = ranges[i].off;
		u_int64_t	 want = ranges[i].len;
		u_int64_t	 remaining;
		ssize_t		 nread;

		if (XXH3_64bits_reset(state) == XXH_ERROR) {
			error_f("XXH3_64bits_reset failed at range %u", i);
			goto fail_status;
		}

		if (off >= fsize) {
			remaining = 0;
		} else {
			u_int64_t avail = fsize - off;
			remaining = want < avail ? want : avail;
		}

		if (remaining > 0) {
			if (lseek(fd, (off_t)off, SEEK_SET) == (off_t)-1) {
				send_status_oqueue(oqueue, id,
				    errno_to_sftp_status(errno));
				goto out;
			}
			while (remaining > 0) {
				size_t toread = (size_t)MINIMUM(
				    (u_int64_t)sizeof(buf), remaining);
				nread = read(fd, buf, toread);
				if (nread == 0)
					break;	/* shouldn't happen given
						 * clamp, but defensive */
				if (nread < 0) {
					send_status_oqueue(oqueue, id,
					    errno_to_sftp_status(errno));
					goto out;
				}
				if (XXH3_64bits_update(state, buf,
				    (size_t)nread) == XXH_ERROR) {
					error_f("XXH3_64bits_update failed "
					    "at range %u", i);
					goto fail_status;
				}
				remaining -= (u_int64_t)nread;
				hashed_total += (u_int64_t)nread;

				/* Time-keyed heartbeat (see comment above). */
				{
					time_t now =
					    monotime();
					if (now != 0 && last_hb_sec != 0 &&
					    (now - last_hb_sec) >=
					    (time_t)
					    HPN_HEARTBEAT_EMIT_INTERVAL_SEC) {
						send_hpn_hash_range_heartbeat(
						    id, oqueue, hashed_total);
						last_hb_sec = now;
					}
				}
			}
		}
		hashes[i] = (u_int64_t)XXH3_64bits_digest(state);
	}

	debug3("sftp-hash-range: computed %u hashes for \"%s\"",
	    num_ranges, path);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, num_ranges)) != 0)
		fatal_fr(r, "compose header");
	for (i = 0; i < num_ranges; i++) {
		if ((r = sshbuf_put_u64(msg, hashes[i])) != 0)
			fatal_fr(r, "compose hash %u", i);
	}
	debug3("sftp-hash-range: sending EXTENDED_REPLY id=%u num_hashes=%u",
	    id, num_ranges);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue reply");
	goto out;

fail_status:
	send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
out:
	if (msg != NULL)
		sshbuf_free(msg);
	if (state != NULL)
		XXH3_freeState(state);
	if (fd != -1)
		close(fd);
	free(ranges);
	free(hashes);
	free(path);
}

/* ── END sftp-hash-range ───────────────────────────────────────────────── */

/*
 * Emit an hpn-check-file heartbeat reply (EXTENDED_REPLY with the reserved
 * HPN_HASH_CHECK_FILE_HEARTBEAT sentinel in the hash field).  Called from
 * the inner read+hash loop every HPN_HEARTBEAT_EMIT_INTERVAL_SEC seconds;
 * lets the client refresh its watchdog-pause window so the parallel
 * orchestrator doesn't kill the worker mid-hash on a slow / contended
 * disk.  Wire shape matches the final reply; only the hash value differs.
 *
 * Append to oqueue then synchronously drain so the bytes actually leave
 * the process during the handler (the main poll loop is blocked here).
 * Lives in sftp-hpn-server.c so sftp-server.c keeps a minimal upstream
 * diff; oqueue is threaded through from the dispatch.
 */
static void
send_hpn_check_file_heartbeat(uint32_t id, uint64_t progress,
    struct sshbuf *oqueue)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg,
	        (uint64_t)HPN_HASH_CHECK_FILE_HEARTBEAT)) != 0 ||
	    (r = sshbuf_put_u64(msg, progress)) != 0)
		fatal_fr(r, "compose heartbeat");
	debug3("hpn-check-file: heartbeat id=%u", id);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue heartbeat");
	sshbuf_free(msg);
	flush_oqueue_blocking(oqueue);
}

/*
 * Heartbeat context for the hpn-check-file read-back hash.  The shared
 * read-back helper invokes this per chunk; we throttle the actual heartbeat
 * emission to HPN_HEARTBEAT_EMIT_INTERVAL_SEC so the client's watchdog-pause
 * stays refreshed during a long hash.
 */
struct hpn_check_file_hb {
	u_int          id;
	struct sshbuf *oqueue;
	time_t         last_hb_sec;
};

static void
hpn_check_file_hb_progress(void *arg, uint64_t done)
{
	struct hpn_check_file_hb *c = arg;
	time_t now = monotime();

	if (now != 0 && c->last_hb_sec != 0 &&
	    (now - c->last_hb_sec) >= (time_t)HPN_HEARTBEAT_EMIT_INTERVAL_SEC) {
		send_hpn_check_file_heartbeat(c->id, done, c->oqueue);
		c->last_hb_sec = now;
	}
}

void
process_hpn_check_file(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue)
{
	char *path = NULL;
	uint64_t length;
	uint32_t flags;
	int r;
	int fd = -1;
	uint64_t hash = 0;
	struct hpn_check_file_hb hb;
	struct sshbuf *msg;
	struct stat st;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &length)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hpn-check-file \"%s\" length %llu flags=0x%x",
	    id, path, (unsigned long long)length, flags);
	logit("hpn-check-file \"%s\" length %llu flags=0x%x", path,
	    (unsigned long long)length, flags);

	if ((fd = open(path, O_RDONLY|O_NOFOLLOW)) == -1) {
		send_status_oqueue(oqueue, id, errno_to_sftp_status(errno));
		goto out;
	}

	if (fstat(fd, &st) == -1) {
		send_status_oqueue(oqueue, id, errno_to_sftp_status(errno));
		goto out;
	}
	/* Clamp to actual file size to prevent a malicious client from
	 * requesting a hash of UINT64_MAX bytes and causing unbounded I/O. */
	if (length > (uint64_t)st.st_size)
		length = (uint64_t)st.st_size;

	/*
	 * Sparse-skip optimisation: when the client asks about the WHOLE
	 * file (length == st_size) AND the file is fully allocated
	 * (st_blocks*512 >= 95% of st_size, with the 5% margin covering
	 * filesystem metadata blocks + minor legitimate sparseness) AND
	 * the client did NOT set HPN_CHECK_FILE_STRICT, short-circuit:
	 * return HPN_HASH_FULLY_ALLOCATED_SENTINEL without doing any
	 * read+hash work.  Saves bilateral disk I/O + CPU on multi-file
	 * resumes where most files completed before the interrupt.
	 *
	 * Strict mode (set by client when HPNVerifyTransfer is enabled)
	 * skips this short-circuit so the user gets full-hash verification
	 * even for fully-allocated files.
	 */
	if ((flags & HPN_CHECK_FILE_STRICT) == 0 &&
	    length == (uint64_t)st.st_size &&
	    (uint64_t)st.st_blocks * 512 >=
	        (uint64_t)st.st_size * 95 / 100) {
		hash = (XXH64_hash_t)HPN_HASH_FULLY_ALLOCATED_SENTINEL;
		debug3("hpn-check-file: sparse-skip short-circuit, sending "
		    "sentinel for \"%s\" (st_size=%lld st_blocks=%lld)",
		    path, (long long)st.st_size, (long long)st.st_blocks);
		goto sentinel_reply;
	}

	/*
	 * Hash the file via the shared on-disk read-back helper.  Strict mode
	 * (HPNVerifyTransfer) gets fsync + O_DIRECT so the hash reflects the
	 * platter; plain (non-strict) resume check-file stays buffered.  The
	 * helper opens its own fd, so release ours first; the heartbeat
	 * callback keeps the client's watchdog-pause refreshed during a long
	 * hash.
	 */
	close(fd);
	fd = -1;
	hb.id = id;
	hb.oqueue = oqueue;
	hb.last_hb_sec = monotime();
	if (sftp_hpn_hash_file_ondisk(path, length,
	    (flags & HPN_CHECK_FILE_STRICT) != 0, &hash,
	    hpn_check_file_hb_progress, &hb) != 0) {
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		goto out;
	}
	debug3("hpn-check-file: computed hash %016llx for \"%s\" length %llu",
	    (unsigned long long)hash, path, (unsigned long long)length);

 sentinel_reply:
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg, (uint64_t)hash)) != 0)
		fatal_fr(r, "compose");
	debug3("hpn-check-file: sending EXTENDED_REPLY id=%u hash=%016llx",
	    id, (unsigned long long)hash);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue reply");
	sshbuf_free(msg);
out:
	if (fd != -1)
		close(fd);
	free(path);
}

/* ── BEGIN hpn-file-layout: filesystem layout (Lustre stripe today) ──────
 *
 * Client requests a stripe count for a destination directory before any
 * files land in it; server opens the directory and issues
 * LL_IOC_LOV_SETSTRIPE on the directory FD.  Subsequent files created in
 * the directory inherit the layout - including files extracted from a
 * bundle, which means the bundling path costs nothing extra.
 *
 * On non-Lustre destinations the ioctl returns ENOTTY / EINVAL and we
 * reply HPN_FILE_LAYOUT_NOT_FS without touching the path.  On EPERM /
 * EACCES (restricted OST pools or controlled layouts) we reply
 * HPN_FILE_LAYOUT_PERM; the client warns once per connection and
 * short-circuits future calls.
 *
 * EXPERIMENTAL feature.  See sftp-hpn-server.h for wire format.
 */
static void
process_hpn_file_layout(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char		*path = NULL;
	u_int32_t	 requested = 0;
	u_int32_t	 small_threshold = 0;
	u_int32_t	 applied = 0;
	u_int32_t	 layout_kind = 0;   /* 0 = plain stripe, 1 = tiered composite */
	u_int32_t	 status = HPN_FILE_LAYOUT_FAIL;
	int		 fd = -1;
	int		 r;
	struct sshbuf	*msg = NULL;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &requested)) != 0) {
		error_f("parse: %s", ssh_err(r));
		goto out;
	}
	/* rev-2 adds small_threshold (0 = plain stripe); a rev-1 client omits it.
	 * (This u32 carried the DoM component size before 19.0; same wire field,
	 * now the small/large extent boundary for the tiered composite.) */
	if (sshbuf_get_u32(iqueue, &small_threshold) != 0)
		small_threshold = 0;

	debug3("request %u: hpn-file-layout \"%s\" stripe_count=%u small_threshold=%u",
	    id, path, requested, small_threshold);

	/*
	 * The path is expected to be a directory the client has already
	 * created (mkdir succeeded earlier in the SFTP session).  Open
	 * O_RDONLY|O_DIRECTORY|O_NOFOLLOW for the ioctl.  Non-directories
	 * fall through to ENOTDIR → HPN_FILE_LAYOUT_FAIL, which client
	 * logs once and short-circuits.
	 */
	fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1) {
		debug3("hpn-file-layout: open \"%s\": %s",
		    path, strerror(errno));
		switch (errno) {
		case EACCES:
		case EPERM:
			status = HPN_FILE_LAYOUT_PERM;
			break;
		default:
			status = HPN_FILE_LAYOUT_FAIL;
			break;
		}
		goto reply;
	}

	/*
	 * small_threshold > 0 requests a tiered composite layout (small files on
	 * a single OST below the threshold, the overflow striped across
	 * `requested` OSTs).  If composite/PFL is unsupported on this Lustre the
	 * EA write returns NOT_FS; fall back to a plain `requested`-wide stripe so
	 * the destination still gets a layout.
	 */
	if (small_threshold > 0) {
		status = lustre_set_tiered_layout_fd(fd, small_threshold,
		    requested);
		if (status == HPN_FILE_LAYOUT_OK) {
			layout_kind = 1;
			applied = requested;
		} else {
			/* composite unsupported or the EA was rejected - fall
			 * back to a plain stripe so the dest still gets a layout
			 * rather than erroring out. */
			status = lustre_set_stripe_fd(fd, requested, &applied);
		}
	} else {
		status = lustre_set_stripe_fd(fd, requested, &applied);
	}

	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		logit("hpn-file-layout \"%s\": %s, stripe_count %u (requested %u)",
		    path, layout_kind ? "tiered composite" : "plain stripe",
		    applied, requested);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug3("hpn-file-layout: \"%s\" not on a layout-capable fs",
		    path);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("hpn-file-layout \"%s\": permission denied", path);
		break;
	default:
		logit("hpn-file-layout \"%s\": %s", path, strerror(errno));
		break;
	}

 reply:
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0 ||
	    (r = sshbuf_put_u32(msg, applied)) != 0 ||
	    (r = sshbuf_put_u32(msg, layout_kind)) != 0)
		fatal_fr(r, "compose hpn-file-layout reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue hpn-file-layout reply");

 out:
	if (msg != NULL)
		sshbuf_free(msg);
	if (fd != -1)
		close(fd);
	free(path);
}

/* ── END hpn-file-layout ─────────────────────────────────────────────── */

void
sftp_hpn_server_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *path = NULL;
	const char *fs_type = "unknown";
	uint64_t stripe_size = 0, block_size = 4096;
	uint32_t stripe_count = 0;
	struct sshbuf *msg;
	int r;

	/* Phase 5: bundle-open / bundle-fetch dispatch to their own handlers. */
	if (strcmp(name, HPN_EXT_BUNDLE_OPEN) == 0) {
		process_hpn_bundle_open(id, iqueue, oqueue);
		return;
	}
	if (strcmp(name, HPN_EXT_BUNDLE_FETCH) == 0) {
		process_hpn_bundle_fetch(id, iqueue, oqueue);
		return;
	}

	/* Chunked-resume ranged hashing - see process_hpn_hash_range above. */
	if (strcmp(name, HPN_EXT_CHECK_FILE) == 0) {
		process_hpn_check_file(id, iqueue, oqueue);
		return;
	}
	if (strcmp(name, HPN_EXT_HASH_RANGE) == 0) {
		process_hpn_hash_range(id, iqueue, oqueue);
		return;
	}

	/* Lustre / future-fs layout - see process_hpn_file_layout above. */
	if (strcmp(name, HPN_EXT_FILE_LAYOUT) == 0) {
		process_hpn_file_layout(id, iqueue, oqueue);
		return;
	}

	if (strcmp(name, HPN_EXT_FS_INFO) != 0)
		goto unsupported;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0) {
		error_f("parse path: %s", ssh_err(r));
		goto unsupported;
	}
	debug3("request %u: hpn-fs-info \"%s\"", id, path);

	/*
	 * The client typically asks about the destination file BEFORE it
	 * exists (path is the upload target, not yet created).  statfs /
	 * statvfs / lfs getstripe all need an existing path, so walk up
	 * the path's ancestors until we find one that exists.  Lustre /
	 * GPFS stripe geometry inherits per-directory, so the first
	 * existing ancestor gives the same answer.
	 *
	 * effective_path is a writable copy we whittle down with dirname()
	 * style component stripping; freed before return.
	 */
	char *effective_path = strdup(path);
	if (effective_path == NULL)
		fatal_f("strdup failed");
	{
		struct stat st;
		while (stat(effective_path, &st) != 0) {
			char *slash = strrchr(effective_path, '/');
			if (slash == NULL) {
				/* Ran out of slashes - bail.  Server returns
				 * "unknown" / zeros; client falls back. */
				debug3("hpn-fs-info: no existing ancestor "
				    "for \"%s\"", path);
				break;
			}
			if (slash == effective_path) {
				/* Reached "/" itself. */
				effective_path[1] = '\0';
				if (stat(effective_path, &st) != 0) {
					debug3("hpn-fs-info: even / does "
					    "not stat for \"%s\"", path);
				}
				break;
			}
			*slash = '\0';
		}
		if (strcmp(effective_path, path) != 0)
			debug3("hpn-fs-info: walked \"%s\" -> existing "
			    "ancestor \"%s\"", path, effective_path);
	}

#ifdef HAVE_STATFS
	{
		struct statfs sfs;
		if (statfs(effective_path, &sfs) == 0)
			fs_type = fstype_from_magic(
			    (unsigned long)sfs.f_type);
		else
			debug3("hpn-fs-info: statfs \"%s\": %s",
			    effective_path, strerror(errno));
	}
#endif

	{
		struct statvfs svfs;
		if (statvfs(effective_path, &svfs) == 0 && svfs.f_bsize > 0)
			block_size = (uint64_t)svfs.f_bsize;
	}

	if (strcmp(fs_type, "lustre") == 0) {
		if (lustre_get_stripe(effective_path, &stripe_size,
		    &stripe_count)) {
			debug3("hpn-fs-info: lustre stripe_size=%llu "
			    "stripe_count=%u (path \"%s\")",
			    (unsigned long long)stripe_size, stripe_count,
			    effective_path);
		} else {
			debug3("hpn-fs-info: lfs getstripe unavailable "
			    "for \"%s\", using block_size only",
			    effective_path);
		}
	}

	free(effective_path);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, fs_type)) != 0 ||
	    (r = sshbuf_put_u64(msg, stripe_size)) != 0 ||
	    (r = sshbuf_put_u32(msg, stripe_count)) != 0 ||
	    (r = sshbuf_put_u64(msg, block_size)) != 0)
		fatal_fr(r, "compose");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	free(path);
	return;

 unsupported:
	free(path);
	send_status_oqueue(oqueue, id, SSH2_FX_OP_UNSUPPORTED);
}
