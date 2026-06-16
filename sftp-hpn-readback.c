/*
 * sftp-hpn-readback.c - on-disk read-back hashing for HPNVerifyTransfer.
 *
 * See sftp-hpn-readback.h.  The fsync + posix_fadvise(DONTNEED) + O_DIRECT
 * read-back is what makes a verified transfer's guarantee about bytes on the
 * platter rather than bytes in the page cache; it falls back to a buffered
 * read where O_DIRECT is unavailable.  Self-contained (libc + xxhash + log)
 * so it can link into both the client and the server.
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

#include "log.h"
#include "misc.h"		/* MINIMUM */
#define XXH_INLINE_ALL		/* xxhash is header-only; inline the XXH3 API */
#include "xxhash.h"
#include "sftp-hpn-readback.h"

/*
 * On-disk read-back buffer.  4 MiB matches the measured large-filesystem
 * sweet spot (64 KiB ~43 MB/s vs 4 MiB ~340 MB/s on Lustre); page-aligned for
 * O_DIRECT.  Heap-allocated (too large for the stack).
 */
#define HPN_READBACK_BUFSZ	(4 * 1024 * 1024)
#define HPN_READBACK_ALIGN	4096

int
sftp_hpn_hash_file_ondisk(const char *path, uint64_t length, int ondisk,
    uint64_t *hash_out, sftp_hpn_readback_progress cb, void *cb_arg)
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
		 */
		if (fsync(fd) == -1)
			debug_f("fsync \"%s\": %s (read-back may reflect cache)",
			    path, strerror(errno));
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
