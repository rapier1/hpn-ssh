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

/* sftp-hpn-server.c - the server side of the HPN SFTP extensions, kept
 * here so sftp-server.c carries only the dispatch and close calls.
 * fs-info reports a path's filesystem type and stripe geometry,
 * hpn-check-file and sftp-hash-range hash a file prefix or a set of
 * ranges read from disk, with heartbeats during a long hash, and
 * file-layout sets a Lustre stripe layout on a directory. Bundle and
 * tree walk requests are routed to their own modules. Wire formats are
 * in sftp-hpn-server.h. */

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
#include "sftp-hpn-tree.h"		/* tree walk record codec + constants */
#include "sftp-hpn-tree-server.h"	/* chunked tree walk handlers */
#include "sftp-hpn-verify-hash.h"	/* the on-disk hash reader */
#include "sftp-hpn-bundle-server.h"	/* process_hpn_bundle_open / _fetch */
#include "sftp-lustre.h"		/* lustre_set_stripe_fd / _tiered_layout_fd / _get_stripe */

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
u_int
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
void
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


/* Drain oqueue to STDOUT_FILENO now, blocking. A heartbeat must reach
 * the client while the handler is still running, and sftp-server's poll
 * loop does not turn during a handler. Bytes already queued leave first,
 * so the order holds. */
void
flush_oqueue_blocking(struct sshbuf *oqueue)
{
	size_t len, wrote;

	len = sshbuf_len(oqueue);
	if (len == 0)
		return;
	wrote = atomicio(vwrite, STDOUT_FILENO,
	    (void *)sshbuf_ptr(oqueue), len);
	if (wrote > 0)
		(void)sshbuf_consume(oqueue, wrote);
}

/* One heartbeat stream for a long hash. The client's watchdog would take
 * a silent minute of hashing for a dead worker, so the handler sends a
 * reply-shaped heartbeat every HPN_HASH_HEARTBEAT_INTERVAL_SEC: the
 * reply's first field holds a sentinel of that field's width, 4 bytes
 * for sftp-hash-range's count and 8 for hpn-check-file's hash, and the
 * bytes hashed so far follow. base is the bytes of earlier ranges, so the
 * figure stays monotone across a many-range request. */
struct hash_heartbeat {
	const char	*name;		/* the extension, for messages */
	u_int		 id;
	struct sshbuf	*oqueue;
	int		 sentinel_width;
	uint64_t	 sentinel;
	uint64_t	 base;
	time_t		 last_sec;
};

static void
hash_heartbeat_send(struct hash_heartbeat *hb, uint64_t progress)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, hb->id)) != 0 ||
	    (r = hb->sentinel_width == 4 ?
	    sshbuf_put_u32(msg, (uint32_t)hb->sentinel) :
	    sshbuf_put_u64(msg, hb->sentinel)) != 0 ||
	    (r = sshbuf_put_u64(msg, progress)) != 0)
		fatal_fr(r, "compose heartbeat");
	debug3("%s: heartbeat id=%u", hb->name, hb->id);
	if ((r = sshbuf_put_stringb(hb->oqueue, msg)) != 0)
		fatal_fr(r, "enqueue heartbeat");
	sshbuf_free(msg);
	flush_oqueue_blocking(hb->oqueue);
}

/* Progress callback for the hash reader: send a heartbeat when one is
 * due. */
static void
hash_heartbeat_progress(void *arg, uint64_t done)
{
	struct hash_heartbeat *hb = arg;
	time_t now = monotime();

	if (now != 0 && hb->last_sec != 0 &&
	    now - hb->last_sec >= (time_t)HPN_HASH_HEARTBEAT_INTERVAL_SEC) {
		hash_heartbeat_send(hb, hb->base + done);
		hb->last_sec = now;
	}
}

/* One (offset, length) range of a hash-range request. */
struct hash_range {
	uint64_t	off;
	uint64_t	len;
};

/* sftp-hash-range: hash each of up to SFTP_HASH_RANGE_MAX_RANGES ranges of
 * a file in one request, so chunked verified resume and the per-range
 * verify learn which chunks differ without a round trip per chunk. The
 * bytes come from the platter, not the page cache, since an upload
 * verify must check what landed on disk. A range past EOF is clamped to
 * it, and one wholly past EOF hashes no bytes; the client's full-length
 * hash then mismatches, which is the right answer for a short file. All
 * or nothing: any failure is one STATUS reply and no hashes. Wire format
 * in sftp-hpn-server.h. */
static void
process_hpn_hash_range(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *path = NULL;
	uint32_t num_ranges = 0, i;
	struct hash_range *ranges = NULL;
	uint64_t *hashes = NULL;
	struct sftp_hpn_hash_reader *reader = NULL;
	struct hash_heartbeat hb;
	struct sshbuf *msg = NULL;
	uint64_t fsize, cap, total = 0;
	off_t size;
	int r;

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
	debug("sftp-hash-range \"%s\" num_ranges=%u", path, num_ranges);

	if ((reader = sftp_hpn_hash_reader_open(path, 1, &size)) == NULL) {
		send_status_oqueue(oqueue, id, errno_to_sftp_status(errno));
		goto out;
	}
	fsize = (uint64_t)size;

	/* Clamp each range to EOF, and guard the total work. A legitimate
	 * request tiles [0, fsize), so its clamped lengths sum to the file
	 * size; only a crafted one of many overlapping ranges can pass twice
	 * the size, and it would make us re-read the file over and over.
	 * The running total never passes cap, so it cannot overflow. */
	cap = fsize > UINT64_MAX / 2 ? UINT64_MAX : fsize * 2;
	for (i = 0; i < num_ranges; i++) {
		ranges[i].len = ranges[i].off >= fsize ? 0 :
		    MINIMUM(ranges[i].len, fsize - ranges[i].off);
		if (ranges[i].len > cap - total) {
			error_f("sftp-hash-range \"%s\": clamped range "
			    "total exceeds 2x file size (%llu) - "
			    "rejecting crafted request", path,
			    (unsigned long long)fsize);
			goto fail_status;
		}
		total += ranges[i].len;
	}

	hb = (struct hash_heartbeat){ .name = "sftp-hash-range", .id = id,
	    .oqueue = oqueue, .sentinel_width = 4,
	    .sentinel = HPN_NUM_HASHES_HEARTBEAT, .last_sec = monotime() };
	for (i = 0; i < num_ranges; i++) {
		if (sftp_hpn_hash_reader_range(reader, ranges[i].off,
		    ranges[i].len, &hashes[i], hash_heartbeat_progress,
		    &hb) != 0) {
			send_status_oqueue(oqueue, id,
			    errno_to_sftp_status(errno));
			goto out;
		}
		hb.base += ranges[i].len;
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
	sshbuf_free(msg);
	sftp_hpn_hash_reader_close(reader);
	free(ranges);
	free(hashes);
	free(path);
}

/* hpn-check-file: hash the first length bytes of a file, the whole-file
 * and prefix gates of verified resume. The bytes come from the platter
 * so the answer reflects the disk, and every check is a full hash: size
 * and allocation are never taken as content. length is clamped to the
 * file's size, so a request for UINT64_MAX bytes cannot drive unbounded
 * I/O. Wire format in sftp-hpn-server.h. */
static void
process_hpn_check_file(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue)
{
	char *path = NULL;
	uint64_t length, hash = 0;
	struct sftp_hpn_hash_reader *reader = NULL;
	struct hash_heartbeat hb;
	struct sshbuf *msg;
	off_t size;
	int r;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &length)) != 0)
		fatal_fr(r, "parse");
	debug("hpn-check-file \"%s\" length %llu", path,
	    (unsigned long long)length);

	if ((reader = sftp_hpn_hash_reader_open(path, 1, &size)) == NULL) {
		send_status_oqueue(oqueue, id, errno_to_sftp_status(errno));
		goto out;
	}
	if (length > (uint64_t)size)
		length = (uint64_t)size;
	hb = (struct hash_heartbeat){ .name = "hpn-check-file", .id = id,
	    .oqueue = oqueue, .sentinel_width = 8,
	    .sentinel = HPN_HASH_CHECK_FILE_HEARTBEAT, .last_sec = monotime() };
	if (sftp_hpn_hash_reader_range(reader, 0, length, &hash,
	    hash_heartbeat_progress, &hb) != 0) {
		send_status_oqueue(oqueue, id, SSH2_FX_FAILURE);
		goto out;
	}
	debug3("hpn-check-file: computed hash %016llx for \"%s\" length %llu",
	    (unsigned long long)hash, path, (unsigned long long)length);

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg, hash)) != 0)
		fatal_fr(r, "compose");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue reply");
	sshbuf_free(msg);
 out:
	sftp_hpn_hash_reader_close(reader);
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
	uint32_t	 requested = 0;
	uint32_t	 small_threshold = 0;
	uint32_t	 applied = 0;
	uint32_t	 layout_kind = 0;   /* 0 = plain stripe, 1 = tiered composite */
	uint32_t	 status = HPN_FILE_LAYOUT_FAIL;
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

/* CLOSE on a handle the HPN modules own. Bundle handles finish their
 * extract or release their writer, tree handles close their open
 * directories. See sftp-hpn-server.h. */
int
sftp_hpn_server_close_handle(int handle, int *status)
{
	if (sftp_hpn_server_is_bundle_handle(handle)) {
		*status = sftp_hpn_server_bundle_close(handle);
		return 1;
	}
	if (sftp_hpn_tree_is_handle(handle)) {
		*status = sftp_hpn_tree_close(handle);
		return 1;
	}
	return 0;
}

/* hpn-fs-info: report a path's filesystem type and stripe geometry, so
 * the parallel client can align its byte ranges to Lustre or GPFS stripe
 * boundaries. The type comes from the statfs() magic number and the
 * block size from statvfs(). On Lustre the stripe size and count come
 * from the lustre.lov extended attribute through lustre_get_stripe, a
 * plain syscall; elsewhere they are zero. The path is usually an upload
 * target that does not exist yet, so the first existing ancestor
 * answers; stripe layout inherits per directory, so its answer is the
 * same. Wire format in sftp-hpn-server.h. */
static void
process_hpn_fs_info(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *path = NULL, *effective_path, *slash;
	const char *fs_type = "unknown";
	uint64_t stripe_size = 0, block_size = 4096;
	uint32_t stripe_count = 0;
	struct sshbuf *msg;
	struct statvfs svfs;
	struct stat st;
#ifdef HAVE_STATFS
	struct statfs sfs;
#endif
	int r;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0) {
		error_f("parse path: %s", ssh_err(r));
		send_status_oqueue(oqueue, id, SSH2_FX_BAD_MESSAGE);
		return;
	}
	debug3("request %u: hpn-fs-info \"%s\"", id, path);

	/* walk up to the first existing ancestor, stopping at "/" */
	effective_path = xstrdup(path);
	while (stat(effective_path, &st) != 0) {
		if ((slash = strrchr(effective_path, '/')) == NULL) {
			/* a relative path with no existing ancestor: answer
			 * "unknown" and zeros, and the client falls back */
			debug3("hpn-fs-info: no existing ancestor "
			    "for \"%s\"", path);
			break;
		}
		if (slash == effective_path) {
			effective_path[1] = '\0';
			if (stat(effective_path, &st) != 0)
				debug3("hpn-fs-info: even / does "
				    "not stat for \"%s\"", path);
			break;
		}
		*slash = '\0';
	}
	if (strcmp(effective_path, path) != 0)
		debug3("hpn-fs-info: walked \"%s\" -> existing "
		    "ancestor \"%s\"", path, effective_path);

#ifdef HAVE_STATFS
	if (statfs(effective_path, &sfs) == 0)
		fs_type = fstype_from_magic((unsigned long)sfs.f_type);
	else
		debug3("hpn-fs-info: statfs \"%s\": %s",
		    effective_path, strerror(errno));
#endif
	if (statvfs(effective_path, &svfs) == 0 && svfs.f_bsize > 0)
		block_size = (uint64_t)svfs.f_bsize;

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
}

/* The HPN extensions by wire name, in the shape of sftp-server.c's own
 * handler table. */
static const struct hpn_ext_handler {
	const char *name;
	void (*handler)(u_int, struct sshbuf *, struct sshbuf *);
} hpn_ext_handlers[] = {
	{ HPN_EXT_FS_INFO,	process_hpn_fs_info },
	{ HPN_EXT_CHECK_FILE,	process_hpn_check_file },
	{ HPN_EXT_HASH_RANGE,	process_hpn_hash_range },
	{ HPN_EXT_FILE_LAYOUT,	process_hpn_file_layout },
	{ HPN_EXT_BUNDLE_OPEN,	process_hpn_bundle_open },
	{ HPN_EXT_BUNDLE_FETCH,	process_hpn_bundle_fetch },
	{ HPN_EXT_DTREE_OPEN,	sftp_hpn_tree_open },
	{ HPN_EXT_DTREE_READ,	sftp_hpn_tree_read },
	{ NULL, NULL }
};

void
sftp_hpn_server_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	int i;

	for (i = 0; hpn_ext_handlers[i].name != NULL; i++) {
		if (strcmp(name, hpn_ext_handlers[i].name) == 0) {
			hpn_ext_handlers[i].handler(id, iqueue, oqueue);
			return;
		}
	}
	send_status_oqueue(oqueue, id, SSH2_FX_OP_UNSUPPORTED);
}
