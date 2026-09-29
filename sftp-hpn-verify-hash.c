/*
 * sftp-hpn-verify-hash.c - shared verify hashing primitives for
 * Verify transfer, linked into both the client and the server.
 *
 * The primitive that lives here is the hash reader and its one-range
 * wrapper, sftp_hpn_hash_range_ondisk: an fsync + posix_fadvise(DONTNEED)
 * + O_DIRECT read-back of a file, so a verified transfer's guarantee is
 * about bytes on the platter rather than bytes in the page cache
 * (buffered fallback where O_DIRECT is unavailable).  The TARGET side of
 * the check.
 *
 * Self-contained (libc + xxhash + log) so it links into both binaries.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
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
#include <sys/stat.h>

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

/*
 * Switch an open fd to platter reads.  fdatasync (not fsync): the read-back
 * only needs the file DATA durable, not inode metadata (mtime/ctime), so we
 * skip the metadata flush - on a networked filesystem (e.g. Lustre) that
 * avoids an extra MDS round-trip, a real per-file cost and a separate stall
 * risk.  fsync is the fallback where fdatasync is absent (e.g. macOS); a
 * configure HAVE_FDATASYNC check would extend the fast path to the BSDs too.
 * posix_fadvise drops the now-clean cached copy; O_DIRECT then bypasses the
 * cache so the hash reflects the device.  Buffered fallback where O_DIRECT is
 * unavailable.
 */
int
sftp_hpn_fd_set_ondisk(int fd, const char *path)
{
	int direct = 0;

#if defined(HAVE_FDATASYNC) || defined(__linux__)
	if (fdatasync(fd) == -1)
		debug_f("fdatasync \"%s\": %s (read-back may reflect cache)",
		    path, strerror(errno));
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
	return direct;
}

/* The reader behind every hash in this module; see the header. */
struct sftp_hpn_hash_reader {
	int		 fd;
	int		 direct;	/* O_DIRECT in effect */
	char		*path;		/* for messages */
	u_char		*buf;		/* HPN_READBACK_BUFSZ, aligned */
	XXH3_state_t	*state;
};

struct sftp_hpn_hash_reader *
sftp_hpn_hash_reader_open(const char *path, int ondisk, off_t *size_out)
{
	struct sftp_hpn_hash_reader *reader;
	struct stat st;
	int saved_errno;

	reader = xcalloc(1, sizeof(*reader));
	reader->path = xstrdup(path);
	if ((reader->fd = open(path, O_RDONLY)) == -1 ||
	    fstat(reader->fd, &st) == -1)
		goto fail;
	if (posix_memalign((void **)&reader->buf, HPN_READBACK_ALIGN,
	    HPN_READBACK_BUFSZ) != 0) {
		reader->buf = NULL;
		errno = ENOMEM;
		goto fail;
	}
	if ((reader->state = XXH3_createState()) == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	if (ondisk) {
		reader->direct = sftp_hpn_fd_set_ondisk(reader->fd, path);
		debug_f("read-back of \"%s\" via %s", path,
		    reader->direct ? "O_DIRECT" : "buffered");
	}
	if (size_out != NULL)
		*size_out = st.st_size;
	return reader;
 fail:
	saved_errno = errno;
	sftp_hpn_hash_reader_close(reader);
	errno = saved_errno;
	return NULL;
}

int
sftp_hpn_hash_reader_range(struct sftp_hpn_hash_reader *reader,
    uint64_t offset, uint64_t length, uint64_t *hash_out,
    sftp_hpn_readback_progress cb, void *cb_arg)
{
	uint64_t remaining = length, done = 0;
	ssize_t nread;
	int saved_errno;

	if (XXH3_64bits_reset(reader->state) == XXH_ERROR) {
		error_f("XXH3 reset failed");
		errno = EIO;
		return -1;
	}
	/* nothing to read for an empty range, which hashes to the XXH3 of
	 * no bytes */
	if (length > 0 &&
	    lseek(reader->fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
		saved_errno = errno;
		error_f("lseek \"%s\" to %llu: %s", reader->path,
		    (unsigned long long)offset, strerror(errno));
		errno = saved_errno;
		return -1;
	}
	while (remaining > 0) {
		/*
		 * O_DIRECT requires block-aligned request lengths, so in direct
		 * mode always read a full (aligned) buffer and clamp the hashed
		 * byte count to what remains; a short read at EOF is fine.
		 * Buffered mode clamps the request itself.
		 */
		size_t toread = reader->direct ? HPN_READBACK_BUFSZ :
		    (size_t)MINIMUM((uint64_t)HPN_READBACK_BUFSZ, remaining);
		size_t hbytes;

		nread = read(reader->fd, reader->buf, toread);
#ifdef O_DIRECT
		if (nread < 0 && reader->direct && errno == EINVAL) {
			/* O_DIRECT refused at read time, an unaligned offset
			 * or a filesystem without it; drop it and retry the
			 * same offset buffered */
			int flags = fcntl(reader->fd, F_GETFL);

			if (flags != -1)
				(void)fcntl(reader->fd, F_SETFL,
				    flags & ~O_DIRECT);
			reader->direct = 0;
			continue;
		}
#endif
		/* EOF before length bytes: hash what was read */
		if (nread == 0)
			break;
		if (nread < 0) {
			saved_errno = errno;
			error_f("read \"%s\": %s", reader->path,
			    strerror(errno));
			errno = saved_errno;
			return -1;
		}
		/* never hash past the requested length */
		hbytes = (uint64_t)nread > remaining ?
		    (size_t)remaining : (size_t)nread;
		if (XXH3_64bits_update(reader->state, reader->buf,
		    hbytes) == XXH_ERROR) {
			error_f("XXH3 update failed");
			errno = EIO;
			return -1;
		}
		remaining -= (uint64_t)hbytes;
		done += (uint64_t)hbytes;
		if (cb != NULL)
			cb(cb_arg, done);
	}
	*hash_out = (uint64_t)XXH3_64bits_digest(reader->state);
	return 0;
}

void
sftp_hpn_hash_reader_close(struct sftp_hpn_hash_reader *reader)
{
	if (reader == NULL)
		return;
	if (reader->state != NULL)
		XXH3_freeState(reader->state);
	if (reader->fd != -1)
		close(reader->fd);
	free(reader->buf);
	free(reader->path);
	free(reader);
}

/* One range through a reader of its own. */
int
sftp_hpn_hash_range_ondisk(const char *path, uint64_t offset, uint64_t length,
    int ondisk, uint64_t *hash_out, sftp_hpn_readback_progress cb, void *cb_arg)
{
	struct sftp_hpn_hash_reader *reader;
	int rc;

	if ((reader = sftp_hpn_hash_reader_open(path, ondisk, NULL)) == NULL) {
		error_f("open \"%s\": %s", path, strerror(errno));
		return -1;
	}
	rc = sftp_hpn_hash_reader_range(reader, offset, length, hash_out,
	    cb, cb_arg);
	sftp_hpn_hash_reader_close(reader);
	return rc;
}
