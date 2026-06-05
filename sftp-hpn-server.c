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
#include "sftp-hpn-bundle-server.h"	/* process_hpn_bundle_open / _fetch */
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

/*
 * Lustre layout ioctl ABI - inlined to avoid a build-time dependency on
 * liblustreapi.  The constants and struct shape are stable kernel ABI; any
 * Lustre install that supports stripe-set via lfs(1) also supports this
 * ioctl on an open directory or freshly-created (zero-data) file.
 *
 * We only need v1 to set stripe_count.  Stripe size and pool selection are
 * future revisions of hpn-file-layout - payload is intentionally just the
 * stripe_count today.
 */
#ifndef LOV_USER_MAGIC_V1
# define LOV_USER_MAGIC_V1     0x0BD10BD0
#endif
#ifndef LL_IOC_LOV_SETSTRIPE
# define LL_IOC_LOV_SETSTRIPE  _IOW('f', 154, long)
#endif

struct hpn_lov_user_md_v1 {
	uint32_t lmm_magic;
	uint32_t lmm_pattern;        /* 0 = RAID0 (default) */
	uint64_t lmm_object_id;
	uint64_t lmm_object_seq;
	uint32_t lmm_stripe_size;    /* bytes per stripe; 0 = filesystem default */
	uint16_t lmm_stripe_count;   /* requested count; 0 = "use all OSTs" */
	uint16_t lmm_stripe_offset;  /* starting OST index; (uint16_t)-1 = MDT picks */
} __attribute__((packed));

/*
 * Composite "Data-on-MDT" (DoM) layout ABI, also inlined from the Lustre uapi
 * header (lustre 2.15 lov_comp_md_v1) - same rationale as the v1 struct above:
 * NO liblustreapi link and NO `lfs` subprocess.  Restricted data-transfer
 * nodes commonly allow only sftp and would block a fork/exec, and we keep the
 * build dependency-free (off-Lustre the ioctl just returns NOT_FS).  See
 * lustre_set_dom_layout_fd().
 */
#ifndef LOV_USER_MAGIC_V3
# define LOV_USER_MAGIC_V3       0x0BD30BD0
#endif
#ifndef LOV_USER_MAGIC_COMP_V1
# define LOV_USER_MAGIC_COMP_V1  0x0BD60BD0
#endif
#ifndef LOV_PATTERN_MDT
# define LOV_PATTERN_MDT         0x100   /* Data-on-MDT component */
#endif
#ifndef LUSTRE_EOF
# define LUSTRE_EOF              0xffffffffffffffffULL
#endif

struct hpn_lu_extent {
	uint64_t e_start;
	uint64_t e_end;
} __attribute__((packed));

struct hpn_lov_comp_md_entry_v1 {
	uint32_t lcme_id;
	uint32_t lcme_flags;
	struct hpn_lu_extent lcme_extent;
	uint32_t lcme_offset;       /* byte offset (from header) to sub-layout */
	uint32_t lcme_size;         /* size of that sub-layout blob */
	uint32_t lcme_layout_gen;
	uint64_t lcme_timestamp;
	uint32_t lcme_padding_1;
} __attribute__((packed));      /* 48 bytes */

struct hpn_lov_comp_md_v1 {
	uint32_t lcm_magic;         /* LOV_USER_MAGIC_COMP_V1 */
	uint32_t lcm_size;          /* overall size incl. entries + sub-layouts */
	uint32_t lcm_layout_gen;
	uint16_t lcm_flags;
	uint16_t lcm_entry_count;
	uint16_t lcm_mirror_count;
	uint16_t lcm_padding1[3];
	uint64_t lcm_padding2;
	/* followed by lcm_entry_count entries, then their sub-layouts */
} __attribute__((packed));      /* 32 bytes */

/*
 * Apply a stripe layout to an open directory or freshly-created file FD.
 * Caller is responsible for opening the path with the appropriate flags
 * (directories: O_RDONLY; new files: O_CREAT|O_RDWR with no prior writes).
 *
 * Returns one of HPN_FILE_LAYOUT_OK / _NOT_FS / _PERM / _FAIL.
 * On OK, *applied_count is set to the count we asked for (Lustre clamps
 * silently if the filesystem has fewer OSTs; we report the requested
 * value, since the actual landed-on-disk count is what subsequent file
 * creates will inherit).
 */
static uint32_t
lustre_set_stripe_fd(int fd, uint32_t requested_count,
    uint32_t *applied_count)
{
	struct hpn_lov_user_md_v1 lum;

	memset(&lum, 0, sizeof(lum));
	lum.lmm_magic         = LOV_USER_MAGIC_V1;
	lum.lmm_pattern       = 0;   /* RAID0 */
	lum.lmm_stripe_size   = 0;   /* fs default */
	lum.lmm_stripe_count  = (uint16_t)(requested_count & 0xFFFFu);
	lum.lmm_stripe_offset = (uint16_t)-1;

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum) == 0) {
		if (applied_count != NULL)
			*applied_count = requested_count;
		return HPN_FILE_LAYOUT_OK;
	}
	if (applied_count != NULL)
		*applied_count = 0;
	switch (errno) {
	case ENOTTY:
	case EINVAL:
	case EOPNOTSUPP:
		return HPN_FILE_LAYOUT_NOT_FS;
	case EPERM:
	case EACCES:
		return HPN_FILE_LAYOUT_PERM;
	default:
		return HPN_FILE_LAYOUT_FAIL;
	}
}

/*
 * Apply a composite Data-on-MDT (DoM) layout to an open directory FD:
 * [0, dom_size) on the MDT, [dom_size, EOF) striped RAID0 across
 * overflow_count OSTs.  Files created under the directory inherit it, so the
 * small files a bundle extracts land entirely on the MDT - no OST object per
 * file, which is what dominates small-file Lustre create cost.  Large files
 * spill past dom_size onto OSTs as usual.
 *
 * Built as a composite layout EA and written with fsetxattr("lustre.lov") -
 * LL_IOC_LOV_SETSTRIPE only accepts SIMPLE layouts (it returns ENOTSUPP for a
 * composite magic), so the directory default composite is set by writing the
 * raw EA directly: the same "lustre.lov" blob lustre_get_stripe reads back.
 * Works on the O_RDONLY dir fd.  Same rationale as the simple path: NO `lfs`
 * subprocess (restricted DTNs allow sftp only and would block fork/exec) and NO
 * liblustreapi link.  Buffer shape (lustre 2.15): 32B header + two 48B entries
 * + two 32B lov_user_md_v1 sub-layouts = 192B.  Returns HPN_FILE_LAYOUT_OK /
 * _NOT_FS (DoM off/unsupported, or not Lustre) / _PERM / _FAIL.
 */
static uint32_t
lustre_set_dom_layout_fd(int fd, uint32_t dom_size, uint32_t overflow_count)
{
	enum {
		HDR   = sizeof(struct hpn_lov_comp_md_v1),       /* 32 */
		ENT   = sizeof(struct hpn_lov_comp_md_entry_v1), /* 48 */
		SUB   = sizeof(struct hpn_lov_user_md_v1),       /* 32 */
		OFF0  = HDR + 2 * ENT,                           /* 128: sub-layout 0 */
		OFF1  = OFF0 + SUB,                              /* 160: sub-layout 1 */
		TOTAL = OFF1 + SUB                               /* 192 */
	};
	unsigned char buf[TOTAL];
	struct hpn_lov_comp_md_v1       *cm = (void *)buf;
	struct hpn_lov_comp_md_entry_v1 *e0 = (void *)(buf + HDR);
	struct hpn_lov_comp_md_entry_v1 *e1 = (void *)(buf + HDR + ENT);
	struct hpn_lov_user_md_v1       *s0 = (void *)(buf + OFF0);
	struct hpn_lov_user_md_v1       *s1 = (void *)(buf + OFF1);

	memset(buf, 0, sizeof(buf));

	cm->lcm_magic       = LOV_USER_MAGIC_COMP_V1;
	cm->lcm_size        = TOTAL;
	cm->lcm_entry_count = 2;

	/* Component 1: [0, dom_size) on the MDT (Data-on-MDT).  lcme_id stays 0
	 * (the kernel assigns component ids); stripe_offset -1 = Lustre picks. */
	e0->lcme_extent.e_start = 0;
	e0->lcme_extent.e_end   = dom_size;
	e0->lcme_offset         = OFF0;
	e0->lcme_size           = SUB;
	s0->lmm_magic           = LOV_USER_MAGIC_V1;
	s0->lmm_pattern         = LOV_PATTERN_MDT;
	s0->lmm_stripe_size     = dom_size;
	s0->lmm_stripe_count    = 0;
	s0->lmm_stripe_offset   = (uint16_t)-1;

	/* Component 2: [dom_size, EOF) striped RAID0 across overflow_count OSTs. */
	e1->lcme_extent.e_start = dom_size;
	e1->lcme_extent.e_end   = LUSTRE_EOF;
	e1->lcme_offset         = OFF1;
	e1->lcme_size           = SUB;
	s1->lmm_magic           = LOV_USER_MAGIC_V1;
	s1->lmm_pattern         = 0;          /* RAID0 */
	s1->lmm_stripe_size     = dom_size;   /* OST stripe size for the overflow */
	s1->lmm_stripe_count    = (uint16_t)(overflow_count & 0xFFFFu);
	s1->lmm_stripe_offset   = (uint16_t)-1;

	if (fsetxattr(fd, "lustre.lov", buf, sizeof(buf), 0) == 0)
		return HPN_FILE_LAYOUT_OK;
	switch (errno) {
	case ENOTTY:
	case ENODATA:
	case EINVAL:
	case EOPNOTSUPP:   /* == ENOTSUP: non-Lustre, or DoM off/unsupported */
		return HPN_FILE_LAYOUT_NOT_FS;
	case EPERM:
	case EACCES:
		return HPN_FILE_LAYOUT_PERM;
	default:
		return HPN_FILE_LAYOUT_FAIL;
	}
}

/*
 * Read a directory's default OST stripe geometry (count + size) WITHOUT a
 * subprocess: getxattr the raw "lustre.lov" layout EA and parse it.  Replaces a
 * fork()+execlp("lfs","getstripe","-d") - a fork/exec is a liability on
 * seccomp-hardened data-transfer nodes (a blocked execve can SIGSYS the child),
 * and getxattr is a plain syscall any sftp-capable node allows.
 *
 * The EA is either a simple lov_user_md_v1/v3 (read its stripe_count/size) or a
 * composite lov_comp_md_v1 (a DoM/PFL layout - report the non-MDT, i.e. OST,
 * component: the geometry large files stripe with).  Struct ABI is the inlined
 * set above.  ENOTSUP/ENODATA (non-Lustre, or no explicit default) -> 0.
 */
static int
lustre_get_stripe(const char *path, uint64_t *stripe_size, uint32_t *stripe_count)
{
	unsigned char buf[8192];
	ssize_t n;
	uint32_t magic;

	n = getxattr(path, "lustre.lov", buf, sizeof(buf));
	if (n < (ssize_t)sizeof(magic))
		return 0;
	memcpy(&magic, buf, sizeof(magic));

	if (magic == LOV_USER_MAGIC_V1 || magic == LOV_USER_MAGIC_V3) {
		const struct hpn_lov_user_md_v1 *lum = (const void *)buf;

		if (n < (ssize_t)sizeof(*lum))
			return 0;
		*stripe_count = lum->lmm_stripe_count;
		*stripe_size  = lum->lmm_stripe_size;
	} else if (magic == LOV_USER_MAGIC_COMP_V1) {
		const struct hpn_lov_comp_md_v1 *cm = (const void *)buf;
		int found = 0;
		uint16_t i;

		if (n < (ssize_t)sizeof(*cm))
			return 0;
		for (i = 0; i < cm->lcm_entry_count; i++) {
			size_t eoff = sizeof(*cm) + (size_t)i *
			    sizeof(struct hpn_lov_comp_md_entry_v1);
			const struct hpn_lov_comp_md_entry_v1 *e;
			const struct hpn_lov_user_md_v1 *sub;

			if (eoff + sizeof(*e) > (size_t)n)
				break;
			e = (const void *)(buf + eoff);
			if ((size_t)e->lcme_offset + sizeof(*sub) > (size_t)n)
				continue;
			sub = (const void *)(buf + e->lcme_offset);
			if ((sub->lmm_pattern & LOV_PATTERN_MDT) != 0)
				continue;   /* skip the Data-on-MDT component */
			*stripe_count = sub->lmm_stripe_count;
			*stripe_size  = sub->lmm_stripe_size;
			found = 1;
			break;
		}
		if (!found)
			return 0;
	} else {
		return 0;
	}

	return *stripe_size > 0 && *stripe_count > 0;
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
 * HPN_NUM_HASHES_HEARTBEAT in num_hashes.  Called from the inner read
 * loop every HPN_HEARTBEAT_EMIT_INTERVAL_SEC seconds; lets the client
 * refresh its watchdog-pause window so the parallel orchestrator doesn't
 * kill the worker mid-hash on a slow / contended disk.
 */
static void
send_hpn_hash_range_heartbeat(u_int id, struct sshbuf *oqueue)
{
	struct sshbuf	*msg;
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg,
	        (u_int32_t)HPN_NUM_HASHES_HEARTBEAT)) != 0)
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

				/* Time-keyed heartbeat (see comment above). */
				{
					time_t now =
					    monotime();
					if (now != 0 && last_hb_sec != 0 &&
					    (now - last_hb_sec) >=
					    (time_t)
					    HPN_HEARTBEAT_EMIT_INTERVAL_SEC) {
						send_hpn_hash_range_heartbeat(
						    id, oqueue);
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
	u_int32_t	 dom_size = 0;
	u_int32_t	 applied = 0;
	u_int32_t	 layout_kind = 0;   /* 0 = plain stripe, 1 = Data-on-MDT */
	u_int32_t	 status = HPN_FILE_LAYOUT_FAIL;
	int		 fd = -1;
	int		 r;
	struct sshbuf	*msg = NULL;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &requested)) != 0) {
		error_f("parse: %s", ssh_err(r));
		goto out;
	}
	/* rev-2 adds dom_size (0 = plain stripe); a rev-1 client omits it. */
	if (sshbuf_get_u32(iqueue, &dom_size) != 0)
		dom_size = 0;

	debug3("request %u: hpn-file-layout \"%s\" stripe_count=%u dom_size=%u",
	    id, path, requested, dom_size);

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
	 * dom_size > 0 requests a Data-on-MDT composite layout (small files on
	 * the MDT, the overflow striped across `requested` OSTs).  If DoM is
	 * off/unsupported on this Lustre the ioctl returns NOT_FS; fall back to a
	 * plain `requested`-wide stripe so the destination still gets a layout.
	 */
	if (dom_size > 0) {
		status = lustre_set_dom_layout_fd(fd, dom_size, requested);
		if (status == HPN_FILE_LAYOUT_OK) {
			layout_kind = 1;
			applied = requested;
		} else {
			/* DoM failed (off/unsupported, or the EA was rejected) -
			 * fall back to a plain stripe so the dest still gets a
			 * layout rather than erroring out. */
			status = lustre_set_stripe_fd(fd, requested, &applied);
		}
	} else {
		status = lustre_set_stripe_fd(fd, requested, &applied);
	}

	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		logit("hpn-file-layout \"%s\": %s, stripe_count %u (requested %u)",
		    path, layout_kind ? "Data-on-MDT" : "plain stripe",
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
