/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
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

/* sftp-hpn-verify-hash.c - the hash reader every verify path shares.
 *
 * A reader hashes byte ranges of one file with XXH3 through a 4 MiB
 * aligned buffer. Opened with ondisk set, it first flushes the file's data
 * and drops its cached pages, then reads with O_DIRECT, so the hash reflects
 * the device rather than the page cache. That is how the side that was
 * written proves what reached the disk. Without ondisk, or where O_DIRECT
 * is unavailable, it reads buffered. A reader can also be attached to an
 * fd the caller already has open.
 *
 * The client's verify and verified-resume code (sftp-hpn-verify.c) and the
 * server's hash extensions (sftp-hpn-server.c) use it, so it is linked into
 * hpnsftp, hpnscp, hpnsftp-server, hpnsshd-session, and hpnsshd-auth. */

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

/* The reader's buffer: 4 MiB, the measured sweet spot on a large
 * filesystem (about 43 MB/s at 64 KiB against 340 MB/s at 4 MiB on
 * Lustre), aligned for O_DIRECT, and allocated on the heap because it is
 * too large for the stack. XXX: This may need to be revisited for finer
 * tuning.*/
#define HPN_READBACK_BUFSZ	(4 * 1024 * 1024)
#define HPN_READBACK_ALIGN	4096

/* One open file being hashed, with the buffer and XXH3 state it reuses for
 * every range. The header describes how callers use it. */
struct sftp_hpn_hash_reader {
	int		 fd;		/* the file being hashed */
	int		 owns_fd;	/* opened here, so closed here */
	int		 direct;	/* O_DIRECT in effect */
	char		*path;		/* for messages */
	u_char		*buf;		/* HPN_READBACK_BUFSZ, aligned */
	XXH3_state_t	*state;		/* reset at the start of each range */
};

/* Switch an open fd to reading from the device rather than the page cache.
 * It flushes the file's data with fdatasync, which skips the inode metadata
 * (mtime, ctime) the read-back does not need. On a networked filesystem
 * such as Lustre that saves a metadata server round trip per file, which is
 * a real cost and a separate stall risk. fsync is the fallback where
 * fdatasync is not declared, as on macOS. A failed flush is an error, since
 * the read-back may then see cached data rather than the device's.
 * posix_fadvise then drops the now-clean cached pages and O_DIRECT bypasses
 * the cache, so the hash reflects the device. Returns 1 if O_DIRECT engaged
 * and 0 if the caller must read buffered. */
static int
fd_set_ondisk(int fd, const char *path)
{
	int direct = 0;

#if defined(HAVE_DECL_FDATASYNC) && HAVE_DECL_FDATASYNC
	if (fdatasync(fd) == -1)
		error_f("fdatasync \"%s\": %s (read-back may reflect cache)",
		    path, strerror(errno));
#else
	if (fsync(fd) == -1)
		error_f("fsync \"%s\": %s (read-back may reflect cache)",
		    path, strerror(errno));
#endif
#ifdef POSIX_FADV_DONTNEED
	(void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
#ifdef O_DIRECT
	{
		int flags = fcntl(fd, F_GETFL);

		if (flags != -1 && fcntl(fd, F_SETFL, flags | O_DIRECT) != -1)
			direct = 1;
	}
#endif
	return direct;
}

/* Allocate a reader with its buffer and hash state but no fd yet, which
 * open and attach supply. Returns NULL with errno ENOMEM if the buffer or
 * the hash state cannot be allocated. */
static struct sftp_hpn_hash_reader *
hash_reader_new(const char *path)
{
	struct sftp_hpn_hash_reader *reader;

	reader = xcalloc(1, sizeof(*reader));
	/* no fd until open or attach supplies one, and close skips -1 */
	reader->fd = -1;
	reader->path = xstrdup(path);
	/* O_DIRECT needs a buffer aligned to the device's block size, and
	 * 4096 covers the common sizes. On failure the pointer is undefined,
	 * so clear it before close frees it. */
	if (posix_memalign((void **)&reader->buf, HPN_READBACK_ALIGN,
	    HPN_READBACK_BUFSZ) != 0) {
		reader->buf = NULL;
		goto fail;
	}
	/* one XXH3 state, reset for each range the reader hashes */
	if ((reader->state = XXH3_createState()) == NULL)
		goto fail;
	return reader;
 fail:
	/* close copes with a partly built reader. Set errno after it, since
	 * the frees may change it. */
	sftp_hpn_hash_reader_close(reader);
	errno = ENOMEM;
	return NULL;
}

/* Open path read-only and wrap it in a reader. With ondisk set, the fd is
 * switched to device reads first. Gives the file's size in *size_out when
 * that is non-NULL. Returns NULL with errno set. */
struct sftp_hpn_hash_reader *
sftp_hpn_hash_reader_open(const char *path, int ondisk, off_t *size_out)
{
	struct sftp_hpn_hash_reader *reader;
	struct stat st;
	int saved_errno;

	if ((reader = hash_reader_new(path)) == NULL)
		return NULL;
	reader->owns_fd = 1;
	if ((reader->fd = open(path, O_RDONLY)) == -1 ||
	    fstat(reader->fd, &st) == -1) {
		/* keep the cause, since close may change errno */
		saved_errno = errno;
		sftp_hpn_hash_reader_close(reader);
		errno = saved_errno;
		return NULL;
	}
	if (ondisk) {
		reader->direct = fd_set_ondisk(reader->fd, path);
		debug_f("read-back of \"%s\" via %s", path,
		    reader->direct ? "O_DIRECT" : "buffered");
	}
	if (size_out != NULL)
		*size_out = st.st_size;
	return reader;
}

/* Wrap an fd the caller already has open. The reader reads it buffered and
 * leaves it open at close. path is used only in messages. Returns NULL with
 * errno ENOMEM. */
struct sftp_hpn_hash_reader *
sftp_hpn_hash_reader_attach(int fd, const char *path)
{
	struct sftp_hpn_hash_reader *reader;

	if ((reader = hash_reader_new(path)) == NULL)
		return NULL;
	/* owns_fd and direct stay 0 from the calloc, so reads are buffered
	 * and close leaves the caller's fd open */
	reader->fd = fd;
	return reader;
}

/* Hash [offset, offset + length) of the reader's file into *hash_out. A
 * file that ends early hashes what it has, so the comparison with the
 * peer's hash then fails. cb, when set, gets the bytes hashed so far after
 * each read. Returns 0, or -1 with errno set after logging the cause. */
int
sftp_hpn_hash_reader_range(struct sftp_hpn_hash_reader *reader,
    uint64_t offset, uint64_t length, uint64_t *hash_out,
    sftp_hpn_readback_progress cb, void *cb_arg)
{
	uint64_t remaining = length, done = 0;
	ssize_t nread;
	int saved_errno;

	/* the state carries over between ranges, so start each one fresh */
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
		/* O_DIRECT needs block-aligned request lengths, so direct mode
		 * always reads a full buffer and hashes only what the range
		 * still needs. A short read at EOF is fine. Buffered mode
		 * clamps the request itself. */
		size_t toread = reader->direct ? HPN_READBACK_BUFSZ :
		    (size_t)MINIMUM((uint64_t)HPN_READBACK_BUFSZ, remaining);
		size_t hbytes;

		nread = read(reader->fd, reader->buf, toread);
		if (nread < 0 && errno == EINTR)
			continue;
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
		hbytes = (size_t)MINIMUM((uint64_t)nread, remaining);
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

/* Free a reader, closing its fd only if open opened it. Takes NULL, and a
 * partly built reader from hash_reader_new. */
void
sftp_hpn_hash_reader_close(struct sftp_hpn_hash_reader *reader)
{
	if (reader == NULL)
		return;
	if (reader->state != NULL)
		XXH3_freeState(reader->state);
	if (reader->owns_fd && reader->fd != -1)
		close(reader->fd);
	free(reader->buf);
	free(reader->path);
	free(reader);
}

/* Hash one range of path through a reader opened for it and closed after.
 * The header has the rules. Returns 0 with *hash_out set, or -1 after
 * logging the cause. */
int
sftp_hpn_hash_range(const char *path, uint64_t offset, uint64_t length,
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
