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
 *   2. Lustre: read the "lustre.lov" extended attribute via getxattr()
 *      (lustre_get_stripe -> read_lov_layout, sftp-lustre.c) - a plain
 *      syscall, no fork/exec or subprocess
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

#include "includes.h"

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>		/* Linux: struct statfs / statfs() */
#elif defined(HAVE_SYS_MOUNT_H)
# include <sys/param.h>		/* BSD: struct statfs / statfs() */
# include <sys/mount.h>
#endif

#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "atomicio.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "xmalloc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-bundle.h"
#include "sftp-hpn-server.h"
#include "sftp-hpn-tree.h"		/* hpn-discover-tree codec + constants */
#include "sftp-hpn-verify-hash.h"		/* sftp_hpn_hash_file_ondisk */
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
	/*
	 * Read-back buffer: 4 MiB page-aligned for O_DIRECT (matches the
	 * client's HPN_READBACK_BUFSZ - the measured large-FS sweet spot,
	 * 64 KiB ~43 MB/s vs 4 MiB ~340 MB/s on Lustre).  Heap-allocated.
	 */
	const size_t		 bufsz = 4 * 1024 * 1024;
	u_char			*buf = NULL;
	int			 direct = 0;
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
	}

	logit("sftp-hash-range \"%s\" num_ranges=%u", path, num_ranges);

	if ((fd = open(path, O_RDONLY)) == -1) {
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

	/*
	 * Total-work guard against crafted requests.  A legitimate request
	 * (range-split upload verify, chunked verified resume) tiles [0, fsize)
	 * exactly, so the bytes it asks us to hash sum to the file size.  A
	 * single over-large len is already harmless - it EOF-clamps to one
	 * end-of-file read.  The real attack is many overlapping / redundant
	 * ranges (up to SFTP_HASH_RANGE_MAX_RANGES of them) crafted to make the
	 * server re-hash the file many times over.  EOF-clamp each range and
	 * reject if the clamped total runs past 2x the file size: that can only
	 * be such a request.  This bounds our work to reading the file at most
	 * twice per request, regardless of file size, while never rejecting a
	 * legitimate tiling.  Overflow-safe: the running total never passes cap.
	 */
	{
		u_int64_t cap = fsize > UINT64_MAX / 2 ? UINT64_MAX : fsize * 2;
		u_int64_t total = 0, clamped;

		for (i = 0; i < num_ranges; i++) {
			clamped = ranges[i].off >= fsize ? 0 :
			    MINIMUM(ranges[i].len, fsize - ranges[i].off);
			if (clamped > cap - total) {
				error_f("sftp-hash-range \"%s\": clamped range "
				    "total exceeds 2x file size (%llu) - "
				    "rejecting crafted request", path,
				    (unsigned long long)fsize);
				goto fail_status;
			}
			total += clamped;
		}
	}

	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		goto fail_status;
	}

	if (posix_memalign((void **)&buf, 4096, bufsz) != 0) {
		buf = NULL;
		error_f("posix_memalign(%zu) failed", bufsz);
		goto fail_status;
	}

	/*
	 * Read the bytes from the platter, not the page cache: an upload
	 * verify must check what actually landed on the server's disk, not
	 * the copy still warm in cache from the just-finished write.  Mirrors
	 * the client's read-back (sftp_hpn_hash_range_ondisk).  O_DIRECT (with
	 * the EINVAL fallback below) where the fs supports it, buffered
	 * otherwise.
	 */
	direct = sftp_hpn_fd_set_ondisk(fd, path);
	debug_f("range-hash read-back of \"%s\" via %s", path,
	    direct ? "O_DIRECT" : "buffered");

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
				/*
				 * O_DIRECT requires block-aligned request
				 * lengths, so in direct mode always read a full
				 * (aligned) buffer and clamp the hashed byte
				 * count to what remains; a short read at EOF is
				 * fine.  Buffered mode clamps the request.
				 */
				size_t toread = direct ? bufsz :
				    (size_t)MINIMUM((u_int64_t)bufsz, remaining);
				size_t hbytes;

				nread = read(fd, buf, toread);
#ifdef O_DIRECT
				if (nread < 0 && direct && errno == EINVAL) {
					/* O_DIRECT rejected at read time on
					 * this fs; drop it and retry the same
					 * offset buffered. */
					int fl = fcntl(fd, F_GETFL);
					if (fl != -1)
						(void)fcntl(fd, F_SETFL,
						    fl & ~O_DIRECT);
					direct = 0;
					continue;
				}
#endif
				if (nread == 0)
					break;	/* EOF before length bytes -
						 * hash what we have */
				if (nread < 0) {
					send_status_oqueue(oqueue, id,
					    errno_to_sftp_status(errno));
					goto out;
				}
				/* never hash past the requested length */
				hbytes = (u_int64_t)nread > remaining ?
				    (size_t)remaining : (size_t)nread;
				if (XXH3_64bits_update(state, buf,
				    hbytes) == XXH_ERROR) {
					error_f("XXH3_64bits_update failed "
					    "at range %u", i);
					goto fail_status;
				}
				remaining -= (u_int64_t)hbytes;
				hashed_total += (u_int64_t)hbytes;

				/* Time-keyed heartbeat (see comment above). */
				{
					time_t now =
					    monotime();
					if (now != 0 && last_hb_sec != 0 &&
					    (now - last_hb_sec) >=
					    (time_t)
					    HPN_HASH_HEARTBEAT_INTERVAL_SEC) {
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
	free(buf);
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
	    (now - c->last_hb_sec) >= (time_t)HPN_HASH_HEARTBEAT_INTERVAL_SEC) {
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
	int r;
	int fd = -1;
	uint64_t hash = 0;
	struct hpn_check_file_hb hb;
	struct sshbuf *msg;
	struct stat st;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &length)) != 0)
		fatal_fr(r, "parse");

	debug3("request %u: hpn-check-file \"%s\" length %llu",
	    id, path, (unsigned long long)length);
	logit("hpn-check-file \"%s\" length %llu", path,
	    (unsigned long long)length);

	if ((fd = open(path, O_RDONLY)) == -1) {
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
	 * Hash the file via the shared on-disk read-back helper, ALWAYS with
	 * fsync + O_DIRECT so the hash reflects the platter, not the page cache.
	 * Size/allocation is never trusted as a content signal (the old
	 * sparse-skip sentinel short-circuit was removed) - every check is a full
	 * strict hash.  The helper opens its own fd, so release ours first; the
	 * heartbeat callback keeps the client's watchdog-pause refreshed during a
	 * long hash.
	 */
	close(fd);
	fd = -1;
	hb.id = id;
	hb.oqueue = oqueue;
	hb.last_hb_sec = monotime();
	if (sftp_hpn_hash_file_ondisk(path, length, /*ondisk=*/1, &hash,
	    hpn_check_file_hb_progress, &hb) != 0) {
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		goto out;
	}
	debug3("hpn-check-file: computed hash %016llx for \"%s\" length %llu",
	    (unsigned long long)hash, path, (unsigned long long)length);

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

/* ---- hpn-discover-tree: server-side recursive directory enumeration ---- */

/* Records buffered per streamed chunk before a DATA reply is drained. */
#define DTREE_CHUNK_RECORDS	256

/*
 * Byte ceiling on the same chunk.  A record carries the walk-root-relative
 * path, which grows with tree depth, so a record count alone does not bound
 * the reply size: 256 records averaging about a kilobyte of path overflow
 * SFTP_MAX_MSG_LENGTH, and the client treats an over-long message as fatal
 * rather than recoverable.  The reserve covers the chunk header plus one
 * full-length record, since the trigger is tested after the record is
 * appended.  Same shape and reasoning as BUNDLE_DL_FETCH_REQ_MAX.
 */
#define DTREE_CHUNK_MAX_BYTES \
    ((size_t)SFTP_MAX_MSG_LENGTH - PATH_MAX - 1024)

/* One directory on the current recursion path, for symlink-loop detection. */
struct dtree_pathent {
	dev_t	dev;
	ino_t	ino;
	int	valid;			/* the fstat behind it succeeded */
};

struct dtree_emit {
	u_int		 id;
	struct sshbuf	*oqueue;
	struct sshbuf	*recbuf;	/* records accumulated for this chunk */
	u_int32_t	 count;		/* records currently in recbuf */
	/* Directories from the walk root down to the one being read, indexed
	 * by depth.  Only maintained when following symlinks, which is the
	 * only way a directory can reappear beneath itself. */
	struct dtree_pathent path[HPN_WALK_MAX_DEPTH];
};

/*
 * Wrap recbuf in an EXTENDED_REPLY chunk (version | kind | count | records),
 * enqueue it, and synchronously drain oqueue so the bytes leave now instead
 * of buffering the whole tree.  Resets recbuf for the next chunk.
 */
static void
dtree_flush(struct dtree_emit *emit, u_char kind)
{
	struct sshbuf	*msg;
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, emit->id)) != 0 ||
	    (r = sshbuf_put_u8(msg, HPN_DTREE_VERSION)) != 0 ||
	    (r = sshbuf_put_u8(msg, kind)) != 0 ||
	    (r = sshbuf_put_u32(msg, emit->count)) != 0 ||
	    (r = sshbuf_putb(msg, emit->recbuf)) != 0)
		fatal_fr(r, "compose dtree chunk");
	if ((r = sshbuf_put_stringb(emit->oqueue, msg)) != 0)
		fatal_fr(r, "enqueue dtree chunk");
	sshbuf_free(msg);
	flush_oqueue_blocking(emit->oqueue);
	sshbuf_reset(emit->recbuf);
	emit->count = 0;
}

/* Append one record; flush a DATA chunk once the buffer is full. */
static void
dtree_add(struct dtree_emit *emit, const char *relpath, u_char rectype,
    const Attrib *a, u_int32_t status)
{
	int r;

	if ((r = sftp_tree_put_record(emit->recbuf, relpath, rectype, a,
	    status)) != 0)
		fatal_fr(r, "encode dtree record");
	if (++emit->count >= DTREE_CHUNK_RECORDS ||
	    sshbuf_len(emit->recbuf) >= DTREE_CHUNK_MAX_BYTES)
		dtree_flush(emit, HPN_DTREE_CHUNK_DATA);
}

/*
 * Is st one of the directories from the walk root down to the current one?
 * A followed symlink pointing back at an ancestor otherwise re-enumerates that
 * subtree once per link, which the depth cap bounds only in path length: k
 * self-referential links at one level cost k^depth traversals, all inside a
 * single uninterruptible request.
 */
static int
dtree_on_path(const struct dtree_emit *emit, int depth, const struct stat *st)
{
	int i;

	for (i = 0; i <= depth && i < HPN_WALK_MAX_DEPTH; i++) {
		if (emit->path[i].valid && emit->path[i].dev == st->st_dev &&
		    emit->path[i].ino == st->st_ino)
			return 1;
	}
	return 0;
}

/*
 * Open one directory for the walk.  Below the root, and only when the client
 * asked not to follow symlinks, refuse a final component that has become a
 * symlink: the entry was classified by an earlier lstat, and the name can be
 * replaced in the window between that decision and this open, which would
 * redirect the walk outside the requested tree.  O_NOFOLLOW covers exactly the
 * component at risk, so the enumeration stays where the client asked.  The
 * root is named by the client and is stat'd by the caller, so it opens as
 * given, and a follow walk resolves links because that is what was requested.
 *
 * Ancestors are still resolved by path on each open, and the lstat that
 * classifies an entry remains a separate call, so a raced entry can still be
 * recorded with the wrong type.  Neither leaves the requested tree.
 *
 * Platforms without fdopendir keep the plain path-based open, which is what
 * OpenSSH's own OPENDIR handler does.
 */
static DIR *
dtree_opendir(const char *abspath, int depth, int follow)
{
#ifdef HAVE_FDOPENDIR
	DIR	*dir_handle;
	int	 fd, oerrno, flags = O_RDONLY | O_DIRECTORY;

	if (depth > 0 && !follow)
		flags |= O_NOFOLLOW;
	if ((fd = open(abspath, flags)) == -1)
		return NULL;
	if ((dir_handle = fdopendir(fd)) == NULL) {
		oerrno = errno;
		close(fd);
		errno = oerrno;
	}
	return dir_handle;
#else
	return opendir(abspath);
#endif
}

/*
 * Recursively enumerate abspath, emitting one record per entry with paths
 * relative to the walk root (relbase, "" at the root). A directory record is
 * emitted before its contents, so parents precede children on the wire. "."
 * and ".." are excluded. An unreadable directory emits one ERROR record and
 * is otherwise skipped, so one bad subtree never aborts the walk.
 *
 * A symlink is emitted as a SYMLINK record and not descended, unless follow
 * is set (the client's follow_link_flag, which scp uses). When follow is set
 * the link target is stat'd and the entry is treated as that target: a
 * directory target is descended, a regular target is emitted as REG. A broken
 * link emits an ERROR record. A target that resolves to a directory already on
 * the path from the walk root is a loop: it emits an ERROR record and is not
 * descended (see dtree_on_path). The depth cap still backstops everything else.
 */
static void
dtree_walk(struct dtree_emit *emit, const char *abspath, const char *relbase,
    int depth, int follow)
{
	DIR		*dir_handle;
	struct dirent	*entry;
	struct stat	 dir_st;

	/*
	 * Report the cap rather than returning quietly.  The parent already
	 * emitted this directory's DIR record and the stream still ends with a
	 * normal END chunk, so a bare return leaves the client with a listing
	 * that looks complete: it builds the skeleton, copies what it was told
	 * about, and exits 0 having silently dropped everything deeper.  The
	 * readdir walk errors out for the same condition, and a client picks
	 * its walk from what the server advertises, so staying quiet here makes
	 * the same command behave differently against an HPN server.  An ERROR
	 * record reaches the client's existing arm, which fails the transfer.
	 */
	if (depth >= HPN_WALK_MAX_DEPTH) {
		error_f("max directory depth %d reached at \"%s\"",
		    HPN_WALK_MAX_DEPTH, abspath);
		dtree_add(emit, relbase, HPN_DTREE_REC_ERROR, NULL,
		    SSH2_FX_FAILURE);
		return;
	}
	if ((dir_handle = dtree_opendir(abspath, depth, follow)) == NULL) {
		dtree_add(emit, relbase, HPN_DTREE_REC_ERROR, NULL,
		    errno_to_sftp_status(errno));
		return;
	}
	/* Put this directory on the recursion path so a followed symlink that
	 * resolves back to it, or to any ancestor, is caught below. */
	emit->path[depth].valid = 0;
	if (follow && fstat(dirfd(dir_handle), &dir_st) == 0) {
		emit->path[depth].dev = dir_st.st_dev;
		emit->path[depth].ino = dir_st.st_ino;
		emit->path[depth].valid = 1;
	}
	/*
	 * readdir returns NULL both at the end of the directory and on error,
	 * and the two are told apart only by errno, which it does not clear on
	 * success.  Without the reset a failure part way through reads as a
	 * short directory: the client is told about the entries seen so far and
	 * nothing about the rest.
	 */
	for (;;) {
		char		*child_abs, *child_rel;
		struct stat	 st;
		Attrib		 a;

		errno = 0;
		if ((entry = readdir(dir_handle)) == NULL) {
			if (errno != 0) {
				error_f("readdir \"%s\": %s", abspath,
				    strerror(errno));
				dtree_add(emit, relbase, HPN_DTREE_REC_ERROR,
				    NULL, errno_to_sftp_status(errno));
			}
			break;
		}

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		xasprintf(&child_abs, "%s/%s", abspath, entry->d_name);
		if (*relbase == '\0')
			child_rel = xstrdup(entry->d_name);
		else
			xasprintf(&child_rel, "%s/%s", relbase, entry->d_name);

		if (lstat(child_abs, &st) != 0) {
			dtree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
			    errno_to_sftp_status(errno));
		} else if (S_ISLNK(st.st_mode) && !follow) {
			stat_to_attrib(&st, &a);
			dtree_add(emit, child_rel, HPN_DTREE_REC_SYMLINK, &a, 0);
		} else if (S_ISLNK(st.st_mode) && stat(child_abs, &st) != 0) {
			/* follow requested but the link target is unreachable */
			dtree_add(emit, child_rel, HPN_DTREE_REC_ERROR, NULL,
			    errno_to_sftp_status(errno));
		} else {
			/* a regular entry, or a symlink resolved to its target */
			stat_to_attrib(&st, &a);
			if (S_ISDIR(st.st_mode) &&
			    dtree_on_path(emit, depth, &st)) {
				/* Followed a link back into our own path. */
				dtree_add(emit, child_rel, HPN_DTREE_REC_ERROR,
				    NULL, SSH2_FX_FAILURE);
			} else if (S_ISDIR(st.st_mode)) {
				dtree_add(emit, child_rel, HPN_DTREE_REC_DIR, &a, 0);
				dtree_walk(emit, child_abs, child_rel, depth + 1,
				    follow);
			} else if (S_ISREG(st.st_mode)) {
				dtree_add(emit, child_rel, HPN_DTREE_REC_REG, &a, 0);
			} else {
				dtree_add(emit, child_rel, HPN_DTREE_REC_OTHER, &a, 0);
			}
		}
		free(child_abs);
		free(child_rel);
	}
	closedir(dir_handle);
}

/*
 * hpn-discover-tree handler: parse (root, flags), then push-stream the
 * subtree under root as chunked EXTENDED_REPLY records, terminated by an END
 * chunk.  Record paths are relative to root; the client re-validates them.
 * FOLLOW_SYMLINKS is accepted but dormant (OpenSSH's -L is an upstream stub).
 */
static void
process_hpn_discover_tree(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char			*root = NULL;
	u_int32_t		 flags = 0;
	struct dtree_emit	 emit;
	struct stat		 st;
	int			 r;

	if ((r = sshbuf_get_cstring(iqueue, &root, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0) {
		error_f("parse hpn-discover-tree request: %s", ssh_err(r));
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		free(root);
		return;
	}
	debug3("request %u: hpn-discover-tree \"%s\" flags=0x%x",
	    id, root, flags);

	emit.id = id;
	emit.oqueue = oqueue;
	emit.count = 0;
	if ((emit.recbuf = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");

	if (stat(root, &st) != 0)
		dtree_add(&emit, "", HPN_DTREE_REC_ERROR, NULL,
		    errno_to_sftp_status(errno));
	else if (!S_ISDIR(st.st_mode))
		dtree_add(&emit, "", HPN_DTREE_REC_ERROR, NULL, SSH2_FX_FAILURE);
	else
		dtree_walk(&emit, root, "", 0,
		    (flags & HPN_DTREE_FOLLOW_SYMLINKS) != 0);

	/* Flush any partial DATA chunk, then the terminal END chunk. */
	if (emit.count > 0)
		dtree_flush(&emit, HPN_DTREE_CHUNK_DATA);
	dtree_flush(&emit, HPN_DTREE_CHUNK_END);

	sshbuf_free(emit.recbuf);
	free(root);
}

/* ---- END hpn-discover-tree --------------------------------------------- */

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

	/* Remote-tree enumeration - see process_hpn_discover_tree above. */
	if (strcmp(name, HPN_EXT_DISCOVER_TREE) == 0) {
		process_hpn_discover_tree(id, iqueue, oqueue);
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
