/*
 * sftp-lustre.c - Lustre layout mechanism for HPN-SSH server-side SFTP.
 *
 * Part of HPN-SSH, NOT upstream OpenSSH.  Extracted from sftp-hpn-server.c so
 * the Lustre-specific layout ABI and ioctl/xattr code lives in one place; future
 * FS-specific modules (GPFS/BeeGFS) can follow the same pattern.  The SFTP
 * protocol dispatch (process_hpn_file_layout / process_hpn_fs_info) stays in
 * sftp-hpn-server.c and calls into these helpers.
 *
 * No liblustreapi link and no lfs(1) subprocess: the layout ABI is inlined and
 * applied via ioctl (simple stripe) or fsetxattr("lustre.lov") (composite/DoM),
 * read back via getxattr - plain syscalls a restricted (sftp-only / seccomp)
 * data-transfer node allows.  Off-Lustre the calls return HPN_FILE_LAYOUT_NOT_FS.
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "sftp-hpn-server.h"	/* HPN_FILE_LAYOUT_* */
#include "sftp-lustre.h"

/*
 * Lustre is a Linux-only filesystem: the layout ABI uses Linux ioctls and the
 * Linux xattr API (fsetxattr/getxattr).  Build the real implementation only on
 * Linux -- which covers glibc and musl/Alpine alike -- and stub the public API
 * everywhere else (BSD, macOS) so those builds link and report "not Lustre".
 * (Gating on __linux__, not HAVE_SYS_XATTR_H: macOS has <sys/xattr.h> but no
 * Lustre and a different getxattr signature.)
 */
#ifdef __linux__
#include <sys/xattr.h>


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
 * Composite (PFL) layout ABI, also inlined from the Lustre uapi header
 * (lustre 2.15 lov_comp_md_v1) - same rationale as the v1 struct above:
 * NO liblustreapi link and NO `lfs` subprocess.  Restricted data-transfer
 * nodes commonly allow only sftp and would block a fork/exec, and we keep the
 * build dependency-free (off-Lustre the ioctl just returns NOT_FS).  See
 * lustre_set_tiered_layout_fd().
 *
 * LOV_PATTERN_MDT below is retained only so lustre_get_stripe() can recognise
 * and skip the MDT component when reading back a directory that some site (or
 * an older HPN-SSH) configured as Data-on-MDT; the setter no longer creates
 * DoM layouts.  The MDT-backed composite is recoverable from git commit
 * 6e585150c ("sftp-hpn-server: set DoM composite layout via fsetxattr").
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
uint32_t
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
 * Apply a composite TIERED layout to an open directory FD - the no-MDT
 * replacement for the old Data-on-MDT layout:
 *   [0, small_threshold) = RAID0 stripe_count=1   (small files -> one OST)
 *   [small_threshold, EOF) = RAID0 stripe_count=overflow_count (large files
 *                                                  stripe wide as usual)
 * Files created under the directory inherit it.  Small files land wholly in the
 * stripe-1 component: one OST object, no over-striping - which is what
 * dominates small-file Lustre create cost - and NO data on the MDT, so this
 * works wherever DoM is disabled or forbidden by site policy.  Large files
 * spill past small_threshold and stripe across overflow_count OSTs.
 *
 * (The MDT-backed variant this replaces is recoverable from git commit
 * 6e585150c if DoM ever needs to come back; measurement 2026-06-06 showed
 * single-OST placement matches or beats DoM for small files - see
 * project_dom_stripe1_pfl_fallback.)
 *
 * Built as a composite layout EA and written with fsetxattr("lustre.lov") -
 * LL_IOC_LOV_SETSTRIPE only accepts SIMPLE layouts (it returns ENOTSUPP for a
 * composite magic), so the directory default composite is set by writing the
 * raw EA directly: the same "lustre.lov" blob lustre_get_stripe reads back.
 * Works on the O_RDONLY dir fd.  Same rationale as the simple path: NO `lfs`
 * subprocess (restricted DTNs allow sftp only and would block fork/exec) and NO
 * liblustreapi link.  Buffer shape (lustre 2.15): 32B header + two 48B entries
 * + two 32B lov_user_md_v1 sub-layouts = 192B.  Returns HPN_FILE_LAYOUT_OK /
 * _NOT_FS (composite/PFL unsupported, or not Lustre) / _PERM / _FAIL.
 */
uint32_t
lustre_set_tiered_layout_fd(int fd, uint32_t small_threshold,
    uint32_t overflow_count)
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

	/* Component 1: [0, small_threshold) on a SINGLE OST (stripe_count=1,
	 * RAID0, offset -1 so the MDS round-robins which OST).  Small files land
	 * wholly here - one OST object, no over-striping, NO data on the MDT.
	 * stripe_size 0 = filesystem default.  lcme_id stays 0 (kernel assigns). */
	e0->lcme_extent.e_start = 0;
	e0->lcme_extent.e_end   = small_threshold;
	e0->lcme_offset         = OFF0;
	e0->lcme_size           = SUB;
	s0->lmm_magic           = LOV_USER_MAGIC_V1;
	s0->lmm_pattern         = 0;            /* RAID0 (was LOV_PATTERN_MDT) */
	s0->lmm_stripe_size     = 0;            /* filesystem default */
	s0->lmm_stripe_count    = 1;            /* one OST */
	s0->lmm_stripe_offset   = (uint16_t)-1;

	/* Component 2: [small_threshold, EOF) striped RAID0 across overflow_count
	 * OSTs - large files stripe wide as usual. */
	e1->lcme_extent.e_start = small_threshold;
	e1->lcme_extent.e_end   = LUSTRE_EOF;
	e1->lcme_offset         = OFF1;
	e1->lcme_size           = SUB;
	s1->lmm_magic           = LOV_USER_MAGIC_V1;
	s1->lmm_pattern         = 0;          /* RAID0 */
	s1->lmm_stripe_size     = 0;          /* filesystem default */
	s1->lmm_stripe_count    = (uint16_t)(overflow_count & 0xFFFFu);
	s1->lmm_stripe_offset   = (uint16_t)-1;

	if (fsetxattr(fd, "lustre.lov", buf, sizeof(buf), 0) == 0)
		return HPN_FILE_LAYOUT_OK;
	switch (errno) {
	case ENOTTY:
	case ENODATA:
	case EINVAL:
	case EOPNOTSUPP:   /* == ENOTSUP: non-Lustre, or composite/PFL unsupported */
		return HPN_FILE_LAYOUT_NOT_FS;
	case EPERM:
	case EACCES:
		return HPN_FILE_LAYOUT_PERM;
	default:
		return HPN_FILE_LAYOUT_FAIL;
	}
}

/*
 * Parse one path's "lustre.lov" layout EA WITHOUT a subprocess: getxattr the
 * raw EA and read its geometry.  Replaces a fork()+execlp("lfs","getstripe")
 * - a fork/exec is a liability on seccomp-hardened data-transfer nodes (a
 * blocked execve can SIGSYS the child), and getxattr is a plain syscall any
 * sftp-capable node allows.  The EA is either a simple lov_user_md_v1/v3 or a
 * composite lov_comp_md_v1 (DoM/PFL - report the non-MDT, i.e. OST, component).
 *
 * Returns 1 if a LOV layout was present and parsed (sets *stripe_size and
 * *stripe_count, EITHER of which may be 0 when the layout says "inherit the
 * filesystem default"); 0 if the path carries no LOV layout at all
 * (non-Lustre / ENODATA / ENOTSUP).
 */
static int
read_lov_layout(const char *path, uint64_t *stripe_size, uint32_t *stripe_count)
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
		return 1;
	} else if (magic == LOV_USER_MAGIC_COMP_V1) {
		const struct hpn_lov_comp_md_v1 *cm = (const void *)buf;
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
			return 1;
		}
		return 0;
	}
	return 0;
}

/*
 * Resolve a usable OST stripe geometry for `path`.  A layout whose
 * stripe_size is 0 means "inherit the filesystem default", so when the path's
 * own layout is the default we walk up ancestor directories reading each
 * default layout until a CONCRETE geometry is found (the Lustre mount root
 * always carries one).  This makes the client see a real stripe on Lustre
 * even for default-striped files, so its no-stripe path reliably means "not
 * Lustre" (-> plain per_range range-splitting) rather than a guessed default.
 * Returns 1 with a concrete stripe_size and stripe_count, else 0.
 *
 * NOTE: the walk-up default resolution is UNVERIFIED on a live Lustre mount
 * (none in the dev environment) - validate on br008.
 */
int
lustre_get_stripe(const char *path, uint64_t *stripe_size, uint32_t *stripe_count)
{
	char p[PATH_MAX];
	char *slash;

	if (strlcpy(p, path, sizeof(p)) >= sizeof(p))
		return 0;
	for (;;) {
		*stripe_size  = 0;
		*stripe_count = 0;
		if (read_lov_layout(p, stripe_size, stripe_count) &&
		    *stripe_size > 0 && *stripe_count > 0)
			return 1;
		/* Non-Lustre, or an "inherit default" layout: step to the parent
		 * directory and read its default.  Stop at the top component. */
		slash = strrchr(p, '/');
		if (slash == NULL || slash == p)
			break;
		*slash = '\0';
	}
	return 0;
}

/*
 * Path wrappers over the fd setters, for the CLIENT side (download parity).
 * The download orchestrator writes the local destination itself, so it
 * applies layout directly to the just-created local directory - no wire
 * extension involved.  O_DIRECTORY makes a non-directory path fail at open
 * rather than inside the xattr call.
 */
uint32_t
lustre_set_stripe_path(const char *dir, uint32_t requested_count,
    uint32_t *applied_count)
{
	uint32_t rc;
	int fd = open(dir, O_RDONLY | O_DIRECTORY);

	if (fd == -1)
		return HPN_FILE_LAYOUT_FAIL;
	rc = lustre_set_stripe_fd(fd, requested_count, applied_count);
	close(fd);
	return rc;
}

uint32_t
lustre_set_tiered_layout_path(const char *dir, uint32_t small_threshold,
    uint32_t overflow_count)
{
	uint32_t rc;
	int fd = open(dir, O_RDONLY | O_DIRECTORY);

	if (fd == -1)
		return HPN_FILE_LAYOUT_FAIL;
	rc = lustre_set_tiered_layout_fd(fd, small_threshold, overflow_count);
	close(fd);
	return rc;
}

#else /* !__linux__ -- no Lustre off Linux; stub the API so the build links */

uint32_t
lustre_set_stripe_fd(int fd, uint32_t requested_count, uint32_t *applied_count)
{
	(void)fd; (void)requested_count;
	if (applied_count != NULL)
		*applied_count = 0;
	return HPN_FILE_LAYOUT_NOT_FS;
}

uint32_t
lustre_set_tiered_layout_fd(int fd, uint32_t small_threshold,
    uint32_t overflow_count)
{
	(void)fd; (void)small_threshold; (void)overflow_count;
	return HPN_FILE_LAYOUT_NOT_FS;
}

int
lustre_get_stripe(const char *path, uint64_t *stripe_size,
    uint32_t *stripe_count)
{
	(void)path; (void)stripe_size; (void)stripe_count;
	return 0;
}

uint32_t
lustre_set_stripe_path(const char *dir, uint32_t requested_count,
    uint32_t *applied_count)
{
	(void)dir; (void)requested_count;
	if (applied_count != NULL)
		*applied_count = 0;
	return HPN_FILE_LAYOUT_NOT_FS;
}

uint32_t
lustre_set_tiered_layout_path(const char *dir, uint32_t small_threshold,
    uint32_t overflow_count)
{
	(void)dir; (void)small_threshold; (void)overflow_count;
	return HPN_FILE_LAYOUT_NOT_FS;
}

#endif /* __linux__ */
