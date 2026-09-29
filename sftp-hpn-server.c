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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>		/* Linux: struct statfs / statfs() */
#elif defined(HAVE_SYS_MOUNT_H)
# include <sys/param.h>		/* BSD: struct statfs / statfs() */
# include <sys/mount.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "xmalloc.h"

#include "sftp.h"
#include "sftp-common.h"		/* Attrib, which sftp-hpn-tree.h uses */
#include "sftp-hpn-server.h"
#include "sftp-server-internal.h"	/* upstream reply helpers, queues */
#include "sftp-hpn-bundle-server.h"	/* bundle handlers and handles */
#include "sftp-hpn-tree.h"		/* tree walk wire names */
#include "sftp-hpn-tree-server.h"	/* tree walk handlers and handles */
#include "sftp-hpn-verify-hash.h"	/* the on-disk hash reader */
#include "sftp-lustre.h"		/* stripe get and set */

/* statfs() f_type values for the filesystems fs-info names. Nothing here
 * includes <linux/magic.h>, so they are defined locally, and the guards
 * defer to a system definition should one arrive. Lustre's is missing
 * from older headers and GPFS has none in any header; its value spells
 * "GPFS" in ASCII. ext2 and ext3 share ext4's value. The BSDs number
 * f_type differently, so fs-info answers "unknown" there, which costs
 * nothing since neither Lustre nor GPFS serves from a BSD host. */
#ifndef EXT4_SUPER_MAGIC
# define EXT4_SUPER_MAGIC	0xEF53
#endif
#ifndef XFS_SUPER_MAGIC
# define XFS_SUPER_MAGIC	0x58465342
#endif
#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC	0x6969
#endif
#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC		0x01021994
#endif
#ifndef BTRFS_SUPER_MAGIC
# define BTRFS_SUPER_MAGIC	0x9123683E
#endif
#ifndef LUSTRE_SUPER_MAGIC
# define LUSTRE_SUPER_MAGIC	0x0BD00BD0
#endif
#ifndef GPFS_SUPER_MAGIC
# define GPFS_SUPER_MAGIC	0x47504653u
#endif

/* One heartbeat stream for a long hash. The client pauses its watchdog
 * for HPN_HEARTBEAT_REFRESH_SEC at a time, so a longer hash needs the
 * pause renewed; the handler sends a reply-shaped heartbeat every
 * HPN_HASH_HEARTBEAT_INTERVAL_SEC. The reply's first field holds a
 * sentinel of that field's width, 4 bytes for sftp-hash-range's count
 * and 8 for hpn-check-file's hash, and the bytes hashed so far follow.
 * base is the bytes of earlier ranges, so the figure stays monotone
 * across a many-range request. */
struct hash_heartbeat {
	const char	*name;		/* extension, for messages */
	u_int		 id;
	int		 sentinel_width;
	uint64_t	 sentinel;
	uint64_t	 base;
	time_t		 last_sec;
};

/* One (offset, length) range of a hash-range request. */
struct hash_range {
	uint64_t	off;
	uint64_t	len;
};

/* The printable filesystem name for a statfs() f_type value, a static
 * string. */
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

/* Drain oqueue to STDOUT_FILENO now, blocking. A heartbeat must reach
 * the client while the handler is still running, and sftp-server's poll
 * loop does not turn during a handler. Bytes already queued leave first,
 * so the order holds. */
void
flush_oqueue_blocking(void)
{
	size_t len, wrote;
	int r;

	len = sshbuf_len(oqueue);
	if (len == 0)
		return;
	wrote = atomicio(vwrite, STDOUT_FILENO,
	    (void *)sshbuf_ptr(oqueue), len);
	/* a short write means the client is gone or the pipe failed, so
	 * exit as the main loop would rather than hash on for nobody */
	if (wrote != len) {
		if (errno == EPIPE) {
			debug("write eof");
			sftp_server_cleanup_exit(0);
		}
		error_f("write: %s", strerror(errno));
		sftp_server_cleanup_exit(1);
	}
	if ((r = sshbuf_consume(oqueue, wrote)) != 0)
		fatal_fr(r, "consume");
}

/* Queue one heartbeat and push it to the client now: the poll loop does
 * not turn until the handler returns, so a queued heartbeat would sit
 * behind the hash it reports on. */
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
	send_msg(msg);
	sshbuf_free(msg);
	flush_oqueue_blocking();
}

/* Progress callback for the hash reader: send a heartbeat when one is
 * due. */
static void
hash_heartbeat_progress(void *arg, uint64_t done)
{
	struct hash_heartbeat *hb = arg;
	time_t now = monotime();

	if (now - hb->last_sec >= (time_t)HPN_HASH_HEARTBEAT_INTERVAL_SEC) {
		hash_heartbeat_send(hb, hb->base + done);
		hb->last_sec = now;
	}
}

/* sftp-hash-range: hash each of up to SFTP_HASH_RANGE_MAX_RANGES ranges of
 * a file in one request, so chunked verified resume and the per-range
 * verify learn which chunks differ without a round trip per chunk. The
 * bytes come from the platter, not the page cache, since an upload
 * verify must check what landed on disk. A range past EOF is clamped to
 * it, and one wholly past EOF hashes no bytes; the client's full-length
 * hash then mismatches, which is the right answer for a short file. All
 * or nothing: any failure is one STATUS reply and no hashes. Wire format
 * in sftp-hpn-server.h. */
void
process_hpn_hash_range(uint32_t id)
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

	/* the path and how many ranges follow */
	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &num_ranges)) != 0) {
		error_f("parse: %s", ssh_err(r));
		send_status(id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	debug3("request %u: sftp-hash-range \"%s\" num_ranges=%u",
	    id, path, num_ranges);
	/* a request outside the protocol's bounds is malformed */
	if (num_ranges == 0 || num_ranges > SFTP_HASH_RANGE_MAX_RANGES) {
		error_f("rejecting sftp-hash-range num_ranges=%u, the "
		    "bounds are 1 to %u, for \"%s\"", num_ranges,
		    SFTP_HASH_RANGE_MAX_RANGES, path);
		send_status(id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	/* the ranges themselves, one hash slot each */
	ranges = xcalloc(num_ranges, sizeof(*ranges));
	hashes = xcalloc(num_ranges, sizeof(*hashes));
	for (i = 0; i < num_ranges; i++) {
		if ((r = sshbuf_get_u64(iqueue, &ranges[i].off)) != 0 ||
		    (r = sshbuf_get_u64(iqueue, &ranges[i].len)) != 0) {
			error_f("parse range %u: %s", i, ssh_err(r));
			send_status(id, SSH2_FX_BAD_MESSAGE);
			goto out;
		}
	}

	/* open once for every range, reading from the platter */
	if ((reader = sftp_hpn_hash_reader_open(path, /*ondisk=*/1,
	    &size)) == NULL) {
		send_status(id, errno_to_portable(errno));
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
			    "total exceeds 2x file size (%llu), "
			    "rejecting crafted request", path,
			    (unsigned long long)fsize);
			send_status(id, SSH2_FX_FAILURE);
			goto out;
		}
		total += ranges[i].len;
	}

	/* hash each range, with heartbeats while it runs */
	hb = (struct hash_heartbeat){
		.name = "sftp-hash-range",
		.id = id,
		.sentinel_width = 4,
		.sentinel = HPN_NUM_HASHES_HEARTBEAT,
		.last_sec = monotime() };
	for (i = 0; i < num_ranges; i++) {
		if (sftp_hpn_hash_reader_range(reader, ranges[i].off,
		    ranges[i].len, &hashes[i], hash_heartbeat_progress,
		    &hb) != 0) {
			send_status(id, errno_to_portable(errno));
			goto out;
		}
		hb.base += ranges[i].len;
	}

	/* reply with the hashes in request order */
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
	debug3("sftp-hash-range: sending %u hashes for \"%s\" id=%u",
	    num_ranges, path, id);
	send_msg(msg);
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
void
process_hpn_check_file(uint32_t id)
{
	char *path = NULL;
	uint64_t length, hash = 0;
	struct sftp_hpn_hash_reader *reader = NULL;
	struct hash_heartbeat hb;
	struct sshbuf *msg;
	off_t size;
	int r;

	/* the path and how many of its bytes to hash */
	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u64(iqueue, &length)) != 0) {
		error_f("parse: %s", ssh_err(r));
		send_status(id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	debug3("request %u: hpn-check-file \"%s\" length %llu", id, path,
	    (unsigned long long)length);

	/* open, reading from the platter */
	if ((reader = sftp_hpn_hash_reader_open(path, /*ondisk=*/1,
	    &size)) == NULL) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}
	/* never past the file's end */
	if (length > (uint64_t)size)
		length = (uint64_t)size;

	/* hash, with heartbeats while it runs */
	hb = (struct hash_heartbeat){
		.name = "hpn-check-file",
		.id = id,
		.sentinel_width = 8,
		.sentinel = HPN_HASH_CHECK_FILE_HEARTBEAT,
		.last_sec = monotime() };
	if (sftp_hpn_hash_reader_range(reader, 0, length, &hash,
	    hash_heartbeat_progress, &hb) != 0) {
		send_status(id, errno_to_portable(errno));
		goto out;
	}
	debug3("hpn-check-file: computed hash %016llx for \"%s\" length %llu",
	    (unsigned long long)hash, path, (unsigned long long)length);

	/* reply with the hash */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u64(msg, hash)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
 out:
	sftp_hpn_hash_reader_close(reader);
	free(path);
}

/* hpn-file-layout: set a stripe layout on a destination directory before
 * any files land in it, so every file created there inherits it,
 * including files extracted from a bundle, at no extra cost to bundling.
 * A small_threshold above zero asks for a tiered composite: files below
 * it on one OST, the rest striped across stripe_count. Where the
 * filesystem cannot take a composite the handler falls back to a plain
 * stripe, so the directory still gets a layout. Off Lustre the calls fail
 * with NOT_FS without touching the path, and a site that forbids layouts
 * answers PERM; the client warns once and stops asking. The directory is
 * opened O_NOFOLLOW because the calls change it. EXPERIMENTAL; wire
 * format in sftp-hpn-server.h. */
void
process_hpn_file_layout(uint32_t id)
{
	char *path = NULL;
	uint32_t requested, small_threshold, status, applied = 0;
	uint32_t layout_kind = HPN_FILE_LAYOUT_KIND_STRIPE;
	struct sshbuf *msg;
	int fd = -1, r;

	/* the directory, the stripe count and the tiered boundary */
	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &requested)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &small_threshold)) != 0) {
		error_f("parse: %s", ssh_err(r));
		send_status(id, SSH2_FX_BAD_MESSAGE);
		goto out;
	}
	debug3("request %u: hpn-file-layout \"%s\" stripe_count=%u "
	    "small_threshold=%u", id, path, requested, small_threshold);

	/* the directory the client created; anything else fails here */
	if ((fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)) == -1) {
		debug3("hpn-file-layout: open \"%s\": %s", path,
		    strerror(errno));
		status = lustre_layout_status(errno);
		goto reply;
	}

	/* the shared layout policy, tiered or plain */
	status = lustre_set_layout_fd(fd, requested, small_threshold,
	    &applied, &layout_kind);

	/* an applied or refused layout is worth a line in the log */
	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		logit("hpn-file-layout \"%s\": %s, stripe_count %u "
		    "(requested %u)", path,
		    layout_kind == HPN_FILE_LAYOUT_KIND_TIERED ?
		    "tiered composite" : "plain stripe", applied, requested);
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
	/* the status, the count applied and the kind of layout */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0 ||
	    (r = sshbuf_put_u32(msg, applied)) != 0 ||
	    (r = sshbuf_put_u32(msg, layout_kind)) != 0)
		fatal_fr(r, "compose hpn-file-layout reply");
	send_msg(msg);
	sshbuf_free(msg);
 out:
	if (fd != -1)
		close(fd);
	free(path);
}

/* CLOSE on a handle the HPN modules own. Bundle handles finish their
 * extract or release their writer, tree handles close their open
 * directories. See sftp-hpn-server.h. */
int
sftp_hpn_server_close_handle(int handle, int *status)
{
	if (handle_is_bundle(handle)) {
		*status = sftp_hpn_server_bundle_close(handle);
		return 1;
	}
	if (handle_is_tree(handle)) {
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
void
process_hpn_fs_info(uint32_t id)
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

	/* the path to report on */
	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0) {
		error_f("parse path: %s", ssh_err(r));
		send_status(id, SSH2_FX_BAD_MESSAGE);
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
		/* down to "/", which always exists */
		if (slash == effective_path) {
			effective_path[1] = '\0';
			break;
		}
		*slash = '\0';
	}
	if (strcmp(effective_path, path) != 0)
		debug3("hpn-fs-info: walked \"%s\" -> existing "
		    "ancestor \"%s\"", path, effective_path);

	/* the type from statfs, the block size from statvfs */
#ifdef HAVE_STATFS
	if (statfs(effective_path, &sfs) == 0)
		fs_type = fstype_from_magic((unsigned long)sfs.f_type);
	else
		debug3("hpn-fs-info: statfs \"%s\": %s",
		    effective_path, strerror(errno));
#endif
	if (statvfs(effective_path, &svfs) == 0 && svfs.f_bsize > 0)
		block_size = (uint64_t)svfs.f_bsize;

	/* on Lustre, the stripe geometry of the directory's layout */
	if (strcmp(fs_type, "lustre") == 0) {
		if (lustre_get_stripe(effective_path, &stripe_size,
		    &stripe_count)) {
			debug3("hpn-fs-info: lustre stripe_size=%llu "
			    "stripe_count=%u (path \"%s\")",
			    (unsigned long long)stripe_size, stripe_count,
			    effective_path);
		} else {
			debug3("hpn-fs-info: no lustre.lov layout "
			    "for \"%s\", using block_size only",
			    effective_path);
		}
	}
	free(effective_path);

	/* the type, the stripe geometry and the block size */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_cstring(msg, fs_type)) != 0 ||
	    (r = sshbuf_put_u64(msg, stripe_size)) != 0 ||
	    (r = sshbuf_put_u32(msg, stripe_count)) != 0 ||
	    (r = sshbuf_put_u64(msg, block_size)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
	free(path);
}
