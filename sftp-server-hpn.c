/*
 * sftp-server-hpn.c — HPN-SSH server-side SFTP extensions.
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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-server-hpn.h"

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
 * Lustre magic — may not appear in older <linux/magic.h>.
 * GPFS has no widely-distributed magic; we rely on a less-common value
 * that matches GPFS internal superblock type.
 */
#ifndef LUSTRE_SUPER_MAGIC
# define LUSTRE_SUPER_MAGIC 0x0BD00BD0
#endif
#define GPFS_SUPER_MAGIC    0x47504653u   /* 'G','P','F','S' — unofficial */

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
 * Run "lfs getstripe -d --yaml <path>" as a child process (no shell —
 * path is passed as an argv element to execlp, preventing command injection)
 * and parse stripe_count / stripe_size from the YAML output.
 *
 * Lustre 2.x YAML output contains lines like:
 *   stripe_count:  4
 *   stripe_size:   1048576
 * (older Lustre uses "lmm_" prefixes on the same keys)
 *
 * Returns 1 if both were found with sensible values, 0 otherwise.
 */
static int
lustre_get_stripe(const char *path, uint64_t *stripe_size, uint32_t *stripe_count)
{
	int pipefd[2];
	pid_t pid;
	FILE *f;
	char line[256];
	int got_size = 0, got_count = 0;

	if (pipe(pipefd) < 0)
		return 0;
	/* Set CLOEXEC so the parent's copy of the write-end closes on exec. */
	FD_CLOSEONEXEC(pipefd[0]);
	FD_CLOSEONEXEC(pipefd[1]);

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 0;
	}
	if (pid == 0) {
		/* Child: wire pipefd[1] to stdout, then exec lfs. */
		int devnull = open("/dev/null", O_WRONLY);
		close(pipefd[0]);
		/* dup2 clears CLOEXEC on STDOUT_FILENO so it survives exec. */
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pipefd[1]);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execlp("lfs", "lfs", "getstripe", "-d", "--yaml", path,
		    (char *)NULL);
		_exit(127);
	}

	/* Parent: read lfs output. */
	close(pipefd[1]);
	if ((f = fdopen(pipefd[0], "r")) == NULL) {
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return 0;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long long v = 0;
		if (sscanf(line, " stripe_count: %llu", &v) == 1 ||
		    sscanf(line, " lmm_stripe_count: %llu", &v) == 1) {
			*stripe_count = (uint32_t)v;
			got_count = 1;
		} else if (sscanf(line, " stripe_size: %llu", &v) == 1 ||
		           sscanf(line, " lmm_stripe_size: %llu", &v) == 1) {
			*stripe_size = (uint64_t)v;
			got_size = 1;
		}
	}
	fclose(f);   /* closes pipefd[0] */
	waitpid(pid, NULL, 0);

	return got_size && got_count && *stripe_size > 0 && *stripe_count > 0;
}

/* Forward decl: definition lives at the bottom of the file inside the
 * WITH_LIBARCHIVE block (and as a stub when libarchive is absent). */
static void process_hpn_bundle_open(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

int
sftp_server_hpn_handles(const char *name)
{
	return strcmp(name, HPN_EXT_FS_INFO) == 0
	    || strcmp(name, HPN_EXT_BUNDLE_OPEN) == 0;
}

/* ── BEGIN Phase 5: bundle handle implementation ──────────────────────────
 *
 * Bundle handles are allocated when the client sends an
 * `hpn-bundle-open@hpnssh.org` extended request.  We reuse sftp-server.c's
 * handle table (via handle_new_bundle + handle_get_bundle) so the handle
 * number is returned as a normal SSH_FXP_HANDLE and subsequent
 * SSH_FXP_WRITE / SSH_FXP_CLOSE messages target it via standard SFTP
 * framing.
 *
 * Strategy (per design): buffer all WRITE data in memory until CLOSE,
 * then run libarchive's read API on the complete buffer.  Memory cost
 * per active bundle is bounded by the client's bundle target size
 * (currently 4 MiB default).  This trades streaming-during-receive for
 * implementation simplicity; future work may switch to a threaded
 * streaming model if memory pressure or close-latency becomes a problem.
 *
 * The CLOSE handler is synchronous — extraction completes (or fails)
 * before the client receives the CLOSE STATUS.  An async variant could
 * return STATUS sooner and complete extraction in the background, but
 * synchronous keeps per-bundle results clean.
 */

#ifdef WITH_LIBARCHIVE
# include <sys/stat.h>
# include <archive.h>
# include <archive_entry.h>
# include <libgen.h>     /* dirname() for mkdir-on-extract */

/* Bundle state allocated for each open handle.  Lifetime spans from
 * hpn-bundle-open through close.  Owned by sftp-server-hpn.c; stored on
 * the handle table via handle_new_bundle's opaque field. */
struct hpn_bundle_state {
	char    *dest_dir;       /* absolute or relative dir to extract into */
	uint32_t flags;          /* HPN_BUNDLE_FLAG_* */
	u_char  *accum;          /* growing tar-stream buffer */
	size_t   accum_len;
	size_t   accum_cap;
};

/* Flags — must match the client side in sftp-client.c. */
#define HPN_BUNDLE_FLAG_PRESERVE   0x00000001U
#define HPN_BUNDLE_FLAG_FSYNC      0x00000002U

/* These callbacks live in sftp-server.c so sftp-server-hpn.c doesn't
 * need to know about the handle table internals. */
extern int    handle_new_bundle(void *opaque);
extern void  *handle_get_bundle(int handle);
extern void   handle_free_bundle(int handle);
extern int    handle_is_bundle(int handle);

static struct hpn_bundle_state *
bundle_state_new(const char *dest_dir, uint32_t flags)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->dest_dir = strdup(dest_dir);
	if (s->dest_dir == NULL) {
		free(s);
		return NULL;
	}
	s->flags     = flags;
	s->accum     = NULL;
	s->accum_len = 0;
	s->accum_cap = 0;
	return s;
}

static void
bundle_state_free(struct hpn_bundle_state *s)
{
	if (s == NULL)
		return;
	free(s->dest_dir);
	free(s->accum);
	free(s);
}

/* Ensure accum has room for `need` additional bytes. */
static int
bundle_state_reserve(struct hpn_bundle_state *s, size_t need)
{
	if (s->accum_len + need <= s->accum_cap)
		return 0;
	size_t new_cap = s->accum_cap ? s->accum_cap : 65536;
	while (new_cap < s->accum_len + need) {
		if (new_cap > SIZE_MAX / 2)
			return -1;
		new_cap *= 2;
	}
	u_char *p = realloc(s->accum, new_cap);
	if (p == NULL)
		return -1;
	s->accum     = p;
	s->accum_cap = new_cap;
	return 0;
}

int
sftp_server_hpn_is_bundle_handle(int handle)
{
	return handle_is_bundle(handle);
}

int
sftp_server_hpn_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;
	/* Client writes monotonically — `off` should equal accum_len.
	 * Tolerate skew by reseting to off when smaller (idempotent
	 * retry case) but reject gaps. */
	if (off != s->accum_len) {
		error_f("hpn-bundle write offset mismatch: got %llu have %zu",
		    (unsigned long long)off, s->accum_len);
		return SSH2_FX_FAILURE;
	}
	if (bundle_state_reserve(s, len) != 0) {
		error_f("hpn-bundle: out of memory growing accumulator");
		return SSH2_FX_FAILURE;
	}
	memcpy(s->accum + s->accum_len, data, len);
	s->accum_len += len;
	return SSH2_FX_OK;
}

/*
 * Recursively create `dirpath`.  Used so tar paths like "a/b/c.dat" get
 * extracted correctly when "a" or "a/b" don't yet exist.
 *
 * NOTE: this is hand-rolled mkdir-p.  libarchive offers
 * archive_read_extract / archive_write_disk which would do this and
 * more (xattrs, owners, etc.) automatically.  Worth migrating to that
 * path if subdirectory creation becomes a hotspot or correctness
 * concern; see comment in sftp_server_hpn_bundle_close.
 */
static int
mkdir_p(const char *dirpath, mode_t mode)
{
	char *p, *q;
	int rc = 0;

	if (dirpath == NULL || *dirpath == '\0')
		return -1;
	p = strdup(dirpath);
	if (p == NULL)
		return -1;
	/* Walk path components, mkdir each. */
	for (q = p + 1; *q != '\0'; q++) {
		if (*q == '/') {
			*q = '\0';
			if (mkdir(p, mode) != 0 && errno != EEXIST) {
				rc = -1;
				break;
			}
			*q = '/';
		}
	}
	if (rc == 0) {
		if (mkdir(p, mode) != 0 && errno != EEXIST)
			rc = -1;
	}
	free(p);
	return rc;
}

/*
 * libarchive read callback that pulls bytes from the accumulator buffer.
 * Used by archive_read_open under sftp_server_hpn_bundle_close.
 */
struct bundle_read_ctx {
	const u_char *p;
	size_t        remaining;
};

static la_ssize_t
bundle_archive_read_cb(struct archive *a, void *cd, const void **buffer)
{
	struct bundle_read_ctx *ctx = cd;
	(void)a;
	if (ctx->remaining == 0)
		return 0;
	*buffer = ctx->p;
	la_ssize_t r = (la_ssize_t)ctx->remaining;
	ctx->p         += ctx->remaining;
	ctx->remaining  = 0;
	return r;
}

int
sftp_server_hpn_bundle_close(int handle)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;

	int status = SSH2_FX_OK;
	struct archive *a = NULL;
	struct archive_entry *ae;
	struct bundle_read_ctx ctx = { s->accum, s->accum_len };
	int preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (s->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;
	int n_extracted = 0;

	debug_f("hpn-bundle close: handle=%d dest=\"%s\" accum=%zu bytes "
	    "preserve=%d fsync=%d",
	    handle, s->dest_dir, s->accum_len, preserve, do_fsync);

	if (s->accum_len == 0) {
		/* Empty bundle — nothing to do. */
		goto out;
	}

	a = archive_read_new();
	if (a == NULL) {
		error_f("hpn-bundle: archive_read_new failed");
		status = SSH2_FX_FAILURE;
		goto out;
	}
	/* Accept any tar-family format; the client uses ustar but pax /
	 * gnutar are also accepted in case future clients change. */
	archive_read_support_format_tar(a);
	if (archive_read_open(a, &ctx, NULL,
	    bundle_archive_read_cb, NULL) != ARCHIVE_OK) {
		error_f("hpn-bundle: archive_read_open: %s",
		    archive_error_string(a));
		status = SSH2_FX_FAILURE;
		goto out;
	}

	while (1) {
		int r = archive_read_next_header(a, &ae);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
			error_f("hpn-bundle: read_next_header: %s",
			    archive_error_string(a));
			status = SSH2_FX_FAILURE;
			break;
		}

		const char *path = archive_entry_pathname(ae);
		if (path == NULL || *path == '\0') {
			error_f("hpn-bundle: empty pathname in tar record");
			status = SSH2_FX_FAILURE;
			break;
		}
		/* Compose full destination path.  Empty dest_dir means the
		 * client supplied per-record paths that should be interpreted
		 * verbatim against the server's current working directory
		 * (the user's home, as set by the standard SFTP entry point).
		 * Prepending "/" in that case would silently root the path at
		 * filesystem root — which is both wrong and a privilege issue.
		 * Non-empty dest_dir uses the natural "dir/path" composition. */
		char *full;
		if (*s->dest_dir == '\0') {
			full = strdup(path);
		} else {
			size_t full_len = strlen(s->dest_dir) + 1 +
			    strlen(path) + 1;
			full = malloc(full_len);
			if (full != NULL)
				snprintf(full, full_len, "%s/%s",
				    s->dest_dir, path);
		}
		if (full == NULL) {
			error_f("hpn-bundle: out of memory");
			status = SSH2_FX_FAILURE;
			break;
		}

		/* Create parent directories on demand.  NOTE: libarchive's
		 * archive_write_disk + archive_read_extract would handle
		 * this automatically AND deal with ownership/xattrs/sparse
		 * files cleanly.  Hand-rolled here for the first cut; if
		 * subdir trees become common we should switch to the
		 * write_disk path. */
		{
			char *full_copy = strdup(full);
			if (full_copy != NULL) {
				char *parent = dirname(full_copy);
				if (parent && strcmp(parent, ".") != 0
				    && strcmp(parent, "/") != 0)
					(void)mkdir_p(parent, 0755);
				free(full_copy);
			}
		}

		mode_t mode = preserve
		    ? (mode_t)(archive_entry_perm(ae) & 07777)
		    : 0644;
		int fd = open(full, O_WRONLY | O_CREAT | O_TRUNC, mode);
		if (fd < 0) {
			error_f("hpn-bundle: open \"%s\": %s",
			    full, strerror(errno));
			free(full);
			status = SSH2_FX_FAILURE;
			break;
		}

		/* Stream data from the archive entry to the file. */
		la_int64_t total_written = 0;
		const void *blob;
		size_t blob_len;
		la_int64_t blob_off;
		int file_ok = 1;
		while ((r = archive_read_data_block(a, &blob, &blob_len,
		    &blob_off)) == ARCHIVE_OK) {
			ssize_t w;
			const u_char *bp = blob;
			size_t remaining = blob_len;
			while (remaining > 0) {
				w = write(fd, bp, remaining);
				if (w <= 0) {
					error_f("hpn-bundle: write \"%s\": %s",
					    full,
					    w < 0 ? strerror(errno) : "EOF");
					file_ok = 0;
					break;
				}
				bp        += w;
				remaining -= (size_t)w;
				total_written += w;
			}
			if (!file_ok)
				break;
		}
		if (r != ARCHIVE_EOF && r != ARCHIVE_OK && file_ok) {
			error_f("hpn-bundle: read_data_block \"%s\": %s",
			    full, archive_error_string(a));
			file_ok = 0;
		}

		if (file_ok && preserve) {
			time_t mt = archive_entry_mtime(ae);
			struct timespec ts[2];
			ts[0].tv_sec = mt; ts[0].tv_nsec = 0;
			ts[1].tv_sec = mt; ts[1].tv_nsec = 0;
			(void)futimens(fd, ts);
		}
		if (file_ok && do_fsync)
			(void)fsync(fd);

		if (close(fd) != 0 && file_ok) {
			error_f("hpn-bundle: close \"%s\": %s",
			    full, strerror(errno));
			file_ok = 0;
		}
		if (!file_ok)
			status = SSH2_FX_FAILURE;
		else
			n_extracted++;
		free(full);

		if (!file_ok)
			break;
	}

 out:
	if (a != NULL) {
		archive_read_close(a);
		archive_read_free(a);
	}
	debug_f("hpn-bundle close: handle=%d extracted=%d status=%d",
	    handle, n_extracted, status);
	bundle_state_free(s);
	handle_free_bundle(handle);
	return status;
}

/*
 * Process the hpn-bundle-open@hpnssh.org extended request.
 * Allocates a bundle handle and replies with SSH_FXP_HANDLE.
 * On error replies with SSH_FXP_STATUS / SSH2_FX_FAILURE.
 */
static void
process_hpn_bundle_open(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *dest_dir = NULL;
	uint32_t flags = 0;
	struct sshbuf *msg = NULL;
	struct hpn_bundle_state *s = NULL;
	int handle = -1;
	int r, status = SSH2_FX_FAILURE;

	if ((r = sshbuf_get_cstring(iqueue, &dest_dir, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &flags)) != 0) {
		error_f("parse hpn-bundle-open: %s", ssh_err(r));
		goto fail;
	}
	debug3("request %u: hpn-bundle-open dest=\"%s\" flags=0x%x",
	    id, dest_dir, flags);

	/* Make sure the destination directory exists (mkdir -p semantics).
	 * Don't fail if it already exists.  Empty dest_dir means the client
	 * is supplying absolute (or otherwise pre-rooted) per-record paths;
	 * the per-entry extract loop handles parent-directory creation on
	 * each record, so the up-front mkdir is unnecessary in that case. */
	if (*dest_dir != '\0' &&
	    mkdir_p(dest_dir, 0755) != 0 && errno != EEXIST) {
		error_f("hpn-bundle-open: mkdir_p \"%s\": %s",
		    dest_dir, strerror(errno));
		status = errno == ENOENT ? SSH2_FX_NO_SUCH_FILE
		       : errno == EACCES ? SSH2_FX_PERMISSION_DENIED
		       :                   SSH2_FX_FAILURE;
		goto fail;
	}

	s = bundle_state_new(dest_dir, flags);
	if (s == NULL) {
		status = SSH2_FX_FAILURE;
		goto fail;
	}

	handle = handle_new_bundle(s);
	if (handle < 0) {
		error_f("hpn-bundle-open: handle table full");
		bundle_state_free(s);
		status = SSH2_FX_FAILURE;
		goto fail;
	}

	/* Reply with SSH_FXP_HANDLE — standard SFTP framing. */
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	u_char hbuf[sizeof(int32_t)];
	put_u32(hbuf, (uint32_t)handle);
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
		fatal_fr(r, "compose bundle handle reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle handle reply");
	sshbuf_free(msg);
	free(dest_dir);
	return;

 fail:
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose bundle open failure");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle open failure");
	sshbuf_free(msg);
	free(dest_dir);
}

#else  /* !WITH_LIBARCHIVE */

/* Stubs when libarchive is not available — bundle support is compiled out.
 * The extension is NOT advertised in this case (see compose_extension calls
 * in sftp-server.c, which check WITH_LIBARCHIVE). */

int
sftp_server_hpn_is_bundle_handle(int handle)
{
	(void)handle;
	return 0;
}

int
sftp_server_hpn_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	(void)handle; (void)off; (void)data; (void)len;
	return SSH2_FX_OP_UNSUPPORTED;
}

int
sftp_server_hpn_bundle_close(int handle)
{
	(void)handle;
	return SSH2_FX_OP_UNSUPPORTED;
}

static void
process_hpn_bundle_open(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	struct sshbuf *msg;
	int r;
	(void)iqueue;
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FX_OP_UNSUPPORTED)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose unsupported reply");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue unsupported reply");
	sshbuf_free(msg);
}

#endif /* WITH_LIBARCHIVE */
/* ── END Phase 5 ───────────────────────────────────────────────────────── */

void
sftp_server_hpn_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char *path = NULL;
	const char *fs_type = "unknown";
	uint64_t stripe_size = 0, block_size = 4096;
	uint32_t stripe_count = 0;
	struct sshbuf *msg;
	int r;

	/* Phase 5: bundle-open dispatches to its own handler. */
	if (strcmp(name, HPN_EXT_BUNDLE_OPEN) == 0) {
		process_hpn_bundle_open(id, iqueue, oqueue);
		return;
	}

	if (strcmp(name, HPN_EXT_FS_INFO) != 0)
		goto unsupported;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0) {
		error_f("parse path: %s", ssh_err(r));
		goto unsupported;
	}
	debug3("request %u: hpn-fs-info \"%s\"", id, path);

#ifdef HAVE_STATFS
	{
		struct statfs sfs;
		if (statfs(path, &sfs) == 0)
			fs_type = fstype_from_magic(
			    (unsigned long)sfs.f_type);
		else
			debug3("hpn-fs-info: statfs \"%s\": %s",
			    path, strerror(errno));
	}
#endif

	{
		struct statvfs svfs;
		if (statvfs(path, &svfs) == 0 && svfs.f_bsize > 0)
			block_size = (uint64_t)svfs.f_bsize;
	}

	if (strcmp(fs_type, "lustre") == 0) {
		if (lustre_get_stripe(path, &stripe_size, &stripe_count)) {
			debug3("hpn-fs-info: lustre stripe_size=%llu "
			    "stripe_count=%u",
			    (unsigned long long)stripe_size, stripe_count);
		} else {
			debug3("hpn-fs-info: lfs getstripe unavailable "
			    "for \"%s\", using block_size only", path);
		}
	}

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
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FX_OP_UNSUPPORTED)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose error");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
}
