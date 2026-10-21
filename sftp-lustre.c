/*
 * Copyright (c) 2024-2026 The Board of Trustees of Carnegie Mellon University.
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

/* sftp-lustre.c - the Lustre layout mechanism: set a stripe or a tiered
 * layout on a file or directory, and read a layout back.
 *
 * The server applies layouts for the hpn-file-layout extension, and the
 * client applies them to local destinations on download. The SFTP protocol
 * dispatch stays in sftp-hpn-server.c, and the client policy in
 * sftp-lustre-client.c.
 *
 * There is no liblustreapi link and no lfs(1) subprocess. The layout ABI is
 * inlined and applied with an ioctl (simple stripe) or
 * fsetxattr("lustre.lov") (tiered composite), and read back with getxattr.
 * These are plain syscalls that a restricted sftp-only or seccomp data
 * transfer node allows. Off Lustre the setters report
 * HPN_FILE_LAYOUT_NOT_FS. */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/xattr.h>
#endif

#include "log.h"
#include "sftp-hpn-server.h"	/* HPN_FILE_LAYOUT_* */
#include "sftp-lustre.h"

/* Lustre is a Linux-only filesystem. Its layout ABI uses Linux ioctls and
 * the Linux xattr API (fsetxattr, getxattr), so the real implementation is
 * built only on Linux, which covers glibc and musl alike. Everywhere else
 * (BSD, macOS) the public API is stubbed, so those builds link and report
 * no Lustre. The gate is __linux__, not HAVE_SYS_XATTR_H, because macOS
 * has <sys/xattr.h> with a different getxattr signature and no Lustre. */
#ifdef __linux__

/* The plain stripe ABI, inlined so the build needs no liblustreapi. The
 * constants and the struct shape are stable kernel ABI. Any Lustre install
 * that sets stripes with lfs(1) also takes this ioctl on an open directory
 * or on a file with no data yet. The stripe size and the pool are left to
 * the filesystem. Choosing them would be a later revision of
 * hpn-file-layout. */
#ifndef LOV_USER_MAGIC_V1
# define LOV_USER_MAGIC_V1     0x0BD10BD0
#endif
#ifndef LL_IOC_LOV_SETSTRIPE
# define LL_IOC_LOV_SETSTRIPE  _IOW('f', 154, long)
#endif

/* lov_user_md_v1, field for field. A plain stripe is set through
 * LL_IOC_LOV_SETSTRIPE, each tiered component carries one as its
 * sub-layout, and the reader parses it from getxattr. The object fields
 * only hold their places. */
struct hpn_lov_user_md_v1 {
	uint32_t lmm_magic;
	uint32_t lmm_pattern;        /* 0 = RAID0 (default) */
	uint64_t lmm_object_id;
	uint64_t lmm_object_seq;
	uint32_t lmm_stripe_size;    /* bytes, 0 = filesystem default */
	uint16_t lmm_stripe_count;   /* 0 = fs default, 0xFFFF = all OSTs */
	uint16_t lmm_stripe_offset;  /* first OST, (uint16_t)-1 = MDS picks */
} __attribute__((packed));

/* The composite (PFL) layout ABI, inlined from the Lustre 2.15 uapi
 * lov_comp_md_v1 for the same reasons as the v1 struct. Restricted data
 * transfer nodes often allow only sftp and block a fork and exec of lfs,
 * and the build stays free of dependencies. lustre_set_tiered_layout_fd
 * writes it with fsetxattr("lustre.lov"), and off Lustre that call fails
 * and reports NOT_FS.
 *
 * The setter no longer creates Data-on-MDT layouts. LOV_PATTERN_MDT stays
 * only so lustre_get_stripe can skip the MDT component of a directory that
 * a site, or an older HPN-SSH, set up with Data-on-MDT. The setter that
 * created them is recoverable from commit 6e585150c ("sftp-hpn-server: set
 * DoM composite layout via fsetxattr, not ioctl"). */
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

/* lov_comp_md_v1 and its parts, field for field: the header, then
 * lcm_entry_count entries, each naming its extent and the offset of its
 * v1 sub-layout. Fields this file does not set only hold their places. */
struct hpn_lu_extent {
	uint64_t e_start;
	uint64_t e_end;
} __attribute__((packed));

struct hpn_lov_comp_md_entry_v1 {
	uint32_t lcme_id;
	uint32_t lcme_flags;
	struct hpn_lu_extent lcme_extent;
	uint32_t lcme_offset;       /* from the header to the sub-layout */
	uint32_t lcme_size;         /* the sub-layout's size */
	uint32_t lcme_layout_gen;
	uint64_t lcme_timestamp;
	uint32_t lcme_padding_1;
} __attribute__((packed));      /* 48 bytes */

struct hpn_lov_comp_md_v1 {
	uint32_t lcm_magic;         /* LOV_USER_MAGIC_COMP_V1 */
	uint32_t lcm_size;          /* whole blob, entries and sub-layouts */
	uint32_t lcm_layout_gen;
	uint16_t lcm_flags;
	uint16_t lcm_entry_count;
	uint16_t lcm_mirror_count;
	uint16_t lcm_padding1[3];
	uint64_t lcm_padding2;
	/* followed by lcm_entry_count entries, then their sub-layouts */
} __attribute__((packed));      /* 32 bytes */

/* Set a plain stripe of requested_count OSTs on an open directory, or a
 * file with no data yet. Returns an HPN_FILE_LAYOUT_* status. On OK,
 * *applied_count is the requested count. Lustre clamps a count above its
 * OSTs silently, so the layout may be narrower. */
static uint32_t
lustre_set_stripe_fd(int fd, uint32_t requested_count,
    uint32_t *applied_count)
{
	struct hpn_lov_user_md_v1 lum;

	/* RAID0 at the filesystem's stripe size, starting at whichever OST
	 * the MDS picks */
	memset(&lum, 0, sizeof(lum));
	lum.lmm_magic         = LOV_USER_MAGIC_V1;
	lum.lmm_pattern       = 0;   /* RAID0 */
	lum.lmm_stripe_size   = 0;   /* filesystem default */
	lum.lmm_stripe_count  = (uint16_t)requested_count;
	lum.lmm_stripe_offset = (uint16_t)-1;

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum) == 0) {
		if (applied_count != NULL)
			*applied_count = requested_count;
		return HPN_FILE_LAYOUT_OK;
	}
	/* the errno tells a filesystem without layouts from a refusal */
	if (applied_count != NULL)
		*applied_count = 0;
	return lustre_layout_status(errno);
}

/* Set a tiered composite layout on an open directory:
 *   [0, small_threshold)    RAID0 on one OST
 *   [small_threshold, EOF)  RAID0 across overflow_count OSTs
 * Files created in the directory inherit it. A small file lands wholly in
 * the first component, so it costs one OST object and puts no data on the
 * MDT, which keeps the layout usable where a site disables Data-on-MDT. A
 * large file spills past small_threshold and stripes wide. Measured on
 * 2026-06-06, one-OST placement matched or beat Data-on-MDT for small
 * files, so this replaced the Data-on-MDT layout.
 *
 * LL_IOC_LOV_SETSTRIPE takes only plain layouts and fails a composite with
 * ENOTSUPP, so the layout is written as the raw "lustre.lov" attribute, the
 * same blob lustre_get_stripe reads back. That works on the O_RDONLY
 * directory descriptor. The blob is a 32-byte header, two 48-byte entries,
 * and two 32-byte v1 sub-layouts, 192 bytes in all (Lustre 2.15). Returns
 * an HPN_FILE_LAYOUT_* status, with NOT_FS when the filesystem is not
 * Lustre or takes no composite layouts. */
static uint32_t
lustre_set_tiered_layout_fd(int fd, uint32_t small_threshold,
    uint32_t overflow_count)
{
	enum {
		HDR   = sizeof(struct hpn_lov_comp_md_v1),       /* 32 */
		ENT   = sizeof(struct hpn_lov_comp_md_entry_v1), /* 48 */
		SUB   = sizeof(struct hpn_lov_user_md_v1),       /* 32 */
		OFF0  = HDR + 2 * ENT,                           /* 128 */
		OFF1  = OFF0 + SUB,                              /* 160 */
		TOTAL = OFF1 + SUB                               /* 192 */
	};
	unsigned char buf[TOTAL];
	struct hpn_lov_comp_md_v1       *header = (void *)buf;
	struct hpn_lov_comp_md_entry_v1 *small_entry = (void *)(buf + HDR);
	struct hpn_lov_comp_md_entry_v1 *large_entry =
	    (void *)(buf + HDR + ENT);
	struct hpn_lov_user_md_v1       *small_layout = (void *)(buf + OFF0);
	struct hpn_lov_user_md_v1       *large_layout = (void *)(buf + OFF1);

	/* the header, then two entries, then their sub-layouts */
	memset(buf, 0, sizeof(buf));
	header->lcm_magic = LOV_USER_MAGIC_COMP_V1;
	header->lcm_size = TOTAL;
	header->lcm_entry_count = 2;

	/* Component 1, [0, small_threshold): RAID0 on one OST at the
	 * filesystem's stripe size, with the MDS picking the OST. lcme_id
	 * stays 0, and the kernel assigns it. */
	small_entry->lcme_extent.e_start = 0;
	small_entry->lcme_extent.e_end = small_threshold;
	small_entry->lcme_offset = OFF0;
	small_entry->lcme_size = SUB;
	small_layout->lmm_magic = LOV_USER_MAGIC_V1;
	small_layout->lmm_pattern = 0;		/* RAID0 */
	small_layout->lmm_stripe_size = 0;	/* filesystem default */
	small_layout->lmm_stripe_count = 1;	/* one OST */
	small_layout->lmm_stripe_offset = (uint16_t)-1;

	/* Component 2, [small_threshold, EOF): RAID0 across overflow_count
	 * OSTs. */
	large_entry->lcme_extent.e_start = small_threshold;
	large_entry->lcme_extent.e_end = LUSTRE_EOF;
	large_entry->lcme_offset = OFF1;
	large_entry->lcme_size = SUB;
	large_layout->lmm_magic = LOV_USER_MAGIC_V1;
	large_layout->lmm_pattern = 0;		/* RAID0 */
	large_layout->lmm_stripe_size = 0;	/* filesystem default */
	large_layout->lmm_stripe_count = (uint16_t)overflow_count;
	large_layout->lmm_stripe_offset = (uint16_t)-1;

	/* the whole blob becomes the directory's default layout */
	if (fsetxattr(fd, "lustre.lov", buf, sizeof(buf), 0) == 0)
		return HPN_FILE_LAYOUT_OK;
	return lustre_layout_status(errno);
}

/* Read the stripe geometry from path's "lustre.lov" attribute with one
 * getxattr, so no lfs subprocess is needed. The attribute holds a plain
 * lov_user_md_v1 or v3, or a composite lov_comp_md_v1. For a composite
 * this reports the first component that is not on the MDT. Returns 1 when
 * a layout was parsed, with *stripe_size and *stripe_count set, and either
 * may be 0 for the filesystem default. Returns 0 when path has no layout:
 * not on Lustre, no attribute (ENODATA, ENOTSUP), or one larger than the
 * buffer (ERANGE). */
static int
read_lov_layout(const char *path, uint64_t *stripe_size, uint32_t *stripe_count)
{
	unsigned char buf[8192];
	ssize_t ea_len;
	uint32_t magic;

	/* 8 KiB holds any directory default. A file striped over more than
	 * about 340 OSTs lists more objects than that and fails with ERANGE,
	 * and lustre_get_stripe then falls back on its directory. */
	ea_len = getxattr(path, "lustre.lov", buf, sizeof(buf));
	if (ea_len < (ssize_t)sizeof(magic))
		return 0;
	memcpy(&magic, buf, sizeof(magic));

	/* v3 adds a pool name after the fields read here, so one struct
	 * reads both */
	if (magic == LOV_USER_MAGIC_V1 || magic == LOV_USER_MAGIC_V3) {
		const struct hpn_lov_user_md_v1 *lum = (const void *)buf;

		if (ea_len < (ssize_t)sizeof(*lum))
			return 0;
		*stripe_count = lum->lmm_stripe_count;
		*stripe_size  = lum->lmm_stripe_size;
		return 1;
	} else if (magic == LOV_USER_MAGIC_COMP_V1) {
		const struct hpn_lov_comp_md_v1 *header = (const void *)buf;
		int i;

		if (ea_len < (ssize_t)sizeof(*header))
			return 0;
		/* each entry, and the sub-layout it points to, must lie inside
		 * what getxattr returned */
		for (i = 0; i < header->lcm_entry_count; i++) {
			size_t entry_off = sizeof(*header) + (size_t)i *
			    sizeof(struct hpn_lov_comp_md_entry_v1);
			const struct hpn_lov_comp_md_entry_v1 *entry;
			const struct hpn_lov_user_md_v1 *sub;

			if (entry_off + sizeof(*entry) > (size_t)ea_len)
				break;
			entry = (const void *)(buf + entry_off);
			if ((size_t)entry->lcme_offset + sizeof(*sub) >
			    (size_t)ea_len)
				continue;
			sub = (const void *)(buf + entry->lcme_offset);
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

/* Resolve the stripe geometry that files created at path get. A layout
 * field left at 0 inherits, so each field is taken from the nearest layout
 * that sets it, walking up from path through its ancestor directories. The
 * Lustre mount root always sets both. With a real geometry on every Lustre
 * path, a reply without one means the filesystem does not stripe, and the
 * client splits ranges evenly. Returns 1 with both fields set, or 0 with
 * both 0. Not yet checked on a live Lustre mount. */
int
lustre_get_stripe(const char *path, uint64_t *stripe_size,
    uint32_t *stripe_count)
{
	char walk_path[PATH_MAX];
	uint64_t size;
	uint32_t count;
	char *slash;

	*stripe_size = 0;
	*stripe_count = 0;
	if (strlcpy(walk_path, path, sizeof(walk_path)) >= sizeof(walk_path))
		return 0;
	for (;;) {
		/* keep the first nonzero value of each field on the way up */
		size = 0;
		count = 0;
		if (read_lov_layout(walk_path, &size, &count)) {
			if (*stripe_size == 0)
				*stripe_size = size;
			if (*stripe_count == 0)
				*stripe_count = count;
			if (*stripe_size > 0 && *stripe_count > 0)
				return 1;
		}
		/* step to the parent directory, and stop below the first
		 * component */
		slash = strrchr(walk_path, '/');
		if (slash == NULL || slash == walk_path)
			break;
		*slash = '\0';
	}
	*stripe_size = 0;
	*stripe_count = 0;
	return 0;
}

#else /* !__linux__ */

static uint32_t
lustre_set_stripe_fd(int fd, uint32_t requested_count, uint32_t *applied_count)
{
	(void)fd;
	(void)requested_count;
	if (applied_count != NULL)
		*applied_count = 0;
	return HPN_FILE_LAYOUT_NOT_FS;
}

static uint32_t
lustre_set_tiered_layout_fd(int fd, uint32_t small_threshold,
    uint32_t overflow_count)
{
	(void)fd;
	(void)small_threshold;
	(void)overflow_count;
	return HPN_FILE_LAYOUT_NOT_FS;
}

int
lustre_get_stripe(const char *path, uint64_t *stripe_size,
    uint32_t *stripe_count)
{
	(void)path;
	*stripe_size = 0;
	*stripe_count = 0;
	return 0;
}

#endif /* __linux__ */

/* Map the errno of a failed layout call, or of opening the directory for
 * one, to an HPN_FILE_LAYOUT_* status. */
uint32_t
lustre_layout_status(int err)
{
	switch (err) {
	/* No layouts here: a filesystem that refuses the ioctl or the
	 * "lustre.lov" attribute, or a Lustre without composite layouts
	 * (EOPNOTSUPP, which is ENOTSUP on Linux). EINVAL is ambiguous, since
	 * Lustre can also return it for a layout it rejects. */
	case ENOTTY:
	case EINVAL:
	case EOPNOTSUPP:
		return HPN_FILE_LAYOUT_NOT_FS;
	/* the site forbids it */
	case EPERM:
	case EACCES:
		return HPN_FILE_LAYOUT_PERM;
	/* anything else, such as a path that is gone or not a directory */
	default:
		return HPN_FILE_LAYOUT_FAIL;
	}
}

/* The layout policy behind both entry points: the tiered composite when
 * small_threshold is set, and a plain stripe when it is not or the
 * filesystem refuses the composite. */
uint32_t
lustre_set_layout_fd(int fd, uint32_t stripe_count, uint32_t small_threshold,
    uint32_t *applied_out, uint32_t *kind_out)
{
	uint32_t status;

	*kind_out = HPN_FILE_LAYOUT_KIND_STRIPE;
	*applied_out = 0;
	/* lmm_stripe_count is 16 bits, so a larger count would wrap to a
	 * different one. 0xFFFF itself means all OSTs. */
	if (stripe_count > 0xFFFF) {
		debug_f("stripe count %u does not fit a Lustre layout",
		    stripe_count);
		return HPN_FILE_LAYOUT_FAIL;
	}
	/* a tiered composite when asked for and the filesystem takes it */
	if (small_threshold > 0) {
		status = lustre_set_tiered_layout_fd(fd, small_threshold,
		    stripe_count);
		if (status == HPN_FILE_LAYOUT_OK) {
			*kind_out = HPN_FILE_LAYOUT_KIND_TIERED;
			*applied_out = stripe_count;
			return HPN_FILE_LAYOUT_OK;
		}
		debug_f("tiered layout refused (status %u), trying a plain "
		    "stripe", status);
	}
	/* otherwise, or when the composite is refused, a plain stripe */
	return lustre_set_stripe_fd(fd, stripe_count, applied_out);
}

/* The same policy for the directory at dir, the client's case for a local
 * download destination. Unlike the server's open, this one follows a
 * symlink, since the download writes its files through it too. */
uint32_t
lustre_set_layout_path(const char *dir, uint32_t stripe_count,
    uint32_t small_threshold, uint32_t *applied_out, uint32_t *kind_out)
{
	uint32_t status;
	int fd;

	/* O_DIRECTORY fails a non-directory at the open, not in the call */
	if ((fd = open(dir, O_RDONLY | O_DIRECTORY)) == -1) {
		*kind_out = HPN_FILE_LAYOUT_KIND_STRIPE;
		*applied_out = 0;
		return lustre_layout_status(errno);
	}
	status = lustre_set_layout_fd(fd, stripe_count, small_threshold,
	    applied_out, kind_out);
	close(fd);
	return status;
}
