/*
 * sftp-hpn-verify-hash.c - shared verify hashing primitives for
 * HPNVerifyTransfer, linked into both the client and the server.
 *
 * Two complementary primitives live here:
 *   - sftp_hpn_hash_file_ondisk: fsync + posix_fadvise(DONTNEED) + O_DIRECT
 *     read-back of a file, so a verified transfer's guarantee is about bytes
 *     on the platter rather than bytes in the page cache (buffered fallback
 *     where O_DIRECT is unavailable).  The TARGET side of the check.
 *   - sftp_hpn_src_hashset: a per-entry source-hash accumulator implementing
 *     the tar writer's data tap (XXH3 each bundled file's source bytes as
 *     they are packed, keyed by archive_path).  The SOURCE side.
 *
 * Self-contained (libc + xxhash + log) so it links into both binaries.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 */

#include "includes.h"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"		/* xcalloc / xstrdup */
#include "log.h"
#include "misc.h"		/* MINIMUM */
#define XXH_INLINE_ALL		/* xxhash is header-only; inline the XXH3 API */
#include "xxhash.h"
#include "sftp-hpn-verify-hash.h"

/*
 * On-disk read-back buffer.  4 MiB matches the measured large-filesystem
 * sweet spot (64 KiB ~43 MB/s vs 4 MiB ~340 MB/s on Lustre); page-aligned for
 * O_DIRECT.  Heap-allocated (too large for the stack).
 */
#define HPN_READBACK_BUFSZ	(4 * 1024 * 1024)
#define HPN_READBACK_ALIGN	4096

int
sftp_hpn_hash_range_ondisk(const char *path, uint64_t offset, uint64_t length,
    int ondisk, uint64_t *hash_out, sftp_hpn_readback_progress cb, void *cb_arg)
{
	int fd = -1, direct = 0, rc = -1;
	XXH3_state_t *state = NULL;
	u_char *buf = NULL;
	size_t bufsz = HPN_READBACK_BUFSZ;
	uint64_t remaining, done = 0;
	ssize_t nread;

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1) {
		error_f("open \"%s\": %s", path, strerror(errno));
		return -1;
	}
	if (posix_memalign((void **)&buf, HPN_READBACK_ALIGN, bufsz) != 0) {
		buf = NULL;
		error_f("posix_memalign failed");
		goto out;
	}
	if (ondisk) {
		/*
		 * Flush dirty pages to the platter, drop the now-clean cached
		 * copy (best-effort), then read via O_DIRECT so the hash
		 * reflects the device, not the page cache.  Buffered fallback
		 * where O_DIRECT is unavailable.
		 *
		 * fdatasync, not fsync: the read-back only needs the file DATA
		 * durable, not the inode metadata (mtime/ctime), so we skip the
		 * metadata flush.  On a networked filesystem (e.g. Lustre) that
		 * avoids an extra MDS round-trip - a real per-file cost and a
		 * separate stall risk.  fsync is the fallback where fdatasync is
		 * absent (e.g. macOS); a configure HAVE_FDATASYNC check would
		 * extend the fast path to the BSDs too.
		 */
#if defined(HAVE_FDATASYNC) || defined(__linux__)
		if (fdatasync(fd) == -1)
			debug_f("fdatasync \"%s\": %s (read-back may reflect "
			    "cache)", path, strerror(errno));
#else
		if (fsync(fd) == -1)
			debug_f("fsync \"%s\": %s (read-back may reflect cache)",
			    path, strerror(errno));
#endif
#ifdef POSIX_FADV_DONTNEED
		(void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
#ifdef O_DIRECT
		{
			int fl = fcntl(fd, F_GETFL);
			if (fl != -1 && fcntl(fd, F_SETFL, fl | O_DIRECT) != -1)
				direct = 1;
		}
#endif
		debug_f("on-disk read-back of \"%s\" via %s", path,
		    direct ? "O_DIRECT" : "buffered");
	}
	if ((state = XXH3_createState()) == NULL ||
	    XXH3_64bits_reset(state) == XXH_ERROR) {
		error_f("XXH3 state init failed");
		goto out;
	}

	/* Range start.  Callers pass O_DIRECT-aligned offsets (verify chunks are
	 * >=256 MiB, so always block-aligned); offset 0 is the whole-file case. */
	if (offset != 0 && lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
		error_f("lseek \"%s\" to %llu: %s", path,
		    (unsigned long long)offset, strerror(errno));
		goto out;
	}

	remaining = length;
	while (remaining > 0) {
		/*
		 * O_DIRECT requires block-aligned request lengths, so in direct
		 * mode always read a full (aligned) buffer and clamp the hashed
		 * byte count to what remains; a short read at EOF is fine.
		 * Buffered mode clamps the request itself.
		 */
		size_t toread = direct ? bufsz :
		    (size_t)MINIMUM((uint64_t)bufsz, remaining);
		size_t hbytes;

		nread = read(fd, buf, toread);
#ifdef O_DIRECT
		if (nread < 0 && direct && errno == EINVAL) {
			/* O_DIRECT rejected at read time on this fs; drop it
			 * and retry the same offset with a buffered read. */
			int fl = fcntl(fd, F_GETFL);
			if (fl != -1)
				(void)fcntl(fd, F_SETFL, fl & ~O_DIRECT);
			direct = 0;
			continue;
		}
#endif
		if (nread == 0)
			break;	/* EOF before length bytes - hash what we have */
		if (nread < 0) {
			error_f("read \"%s\": %s", path, strerror(errno));
			goto out;
		}
		/* never hash past the requested length (length may be < size) */
		hbytes = (uint64_t)nread > remaining ?
		    (size_t)remaining : (size_t)nread;
		if (XXH3_64bits_update(state, buf, hbytes) == XXH_ERROR) {
			error_f("XXH3 update failed");
			goto out;
		}
		remaining -= (uint64_t)hbytes;
		done += (uint64_t)hbytes;
		if (cb != NULL)
			cb(cb_arg, done);
	}
	*hash_out = (uint64_t)XXH3_64bits_digest(state);
	rc = 0;
 out:
	if (state != NULL)
		XXH3_freeState(state);
	if (fd != -1)
		close(fd);
	free(buf);
	return rc;
}

/* Whole-file convenience wrapper: hash [0, length). */
int
sftp_hpn_hash_file_ondisk(const char *path, uint64_t length, int ondisk,
    uint64_t *hash_out, sftp_hpn_readback_progress cb, void *cb_arg)
{
	return sftp_hpn_hash_range_ondisk(path, 0, length, ondisk, hash_out,
	    cb, cb_arg);
}

/* ── Source-hash accumulator (bundle pack-time source side) ───────────────
 *
 * Implements struct sftp_hpn_tar_data_tap's on_data: the tar writer feeds
 * each entry's source bytes here as it packs them; we XXH3 them per entry,
 * keyed by archive_path, and stash the digest.  The caller looks results up
 * by path after packing (the source hash to compare against the server's
 * O_DIRECT read-back of what landed).  The codec stays hash-agnostic.
 */
struct src_hash_node {
	char    *archive_path;
	uint64_t hash;
	struct src_hash_node *next;
};

struct sftp_hpn_src_hashset {
	XXH3_state_t *cur;		/* in-progress entry hash, or NULL */
	struct src_hash_node *head, *tail;
};

struct sftp_hpn_src_hashset *
sftp_hpn_src_hashset_new(void)
{
	return xcalloc(1, sizeof(struct sftp_hpn_src_hashset));
}

void
sftp_hpn_src_hashset_free(struct sftp_hpn_src_hashset *s)
{
	struct src_hash_node *n, *nn;

	if (s == NULL)
		return;
	for (n = s->head; n != NULL; n = nn) {
		nn = n->next;
		free(n->archive_path);
		free(n);
	}
	if (s->cur != NULL)
		XXH3_freeState(s->cur);
	free(s);
}

void
sftp_hpn_src_hashset_tap(void *arg, const char *archive_path,
    const u_char *data, size_t len, int final)
{
	struct sftp_hpn_src_hashset *s = arg;
	struct src_hash_node *n;

	if (s == NULL)
		return;
	/* The codec emits an entry's chunks contiguously, so a NULL cur means
	 * a new entry is starting. */
	if (s->cur == NULL) {
		s->cur = XXH3_createState();
		if (s->cur != NULL)
			(void)XXH3_64bits_reset(s->cur);
	}
	if (s->cur != NULL && len > 0)
		(void)XXH3_64bits_update(s->cur, data, len);
	if (!final)
		return;
	n = xcalloc(1, sizeof(*n));
	n->archive_path = xstrdup(archive_path);
	n->hash = (s->cur != NULL) ? (uint64_t)XXH3_64bits_digest(s->cur) : 0;
	if (s->tail != NULL)
		s->tail->next = n;
	else
		s->head = n;
	s->tail = n;
	if (s->cur != NULL) {
		XXH3_freeState(s->cur);
		s->cur = NULL;
	}
}

int
sftp_hpn_src_hashset_get(struct sftp_hpn_src_hashset *s, const char *archive_path,
    uint64_t *hash_out)
{
	struct src_hash_node *n;

	if (s == NULL || archive_path == NULL || hash_out == NULL)
		return -1;
	for (n = s->head; n != NULL; n = n->next) {
		if (strcmp(n->archive_path, archive_path) == 0) {
			*hash_out = n->hash;
			return 0;
		}
	}
	return -1;
}

void
sftp_hpn_src_hashset_foreach(struct sftp_hpn_src_hashset *s,
    void (*cb)(void *arg, const char *archive_path, uint64_t hash), void *arg)
{
	struct src_hash_node *n;

	if (s == NULL || cb == NULL)
		return;
	for (n = s->head; n != NULL; n = n->next)
		cb(arg, n->archive_path, n->hash);
}
