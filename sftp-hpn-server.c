/*
 * sftp-hpn-server.c — HPN-SSH server-side SFTP extensions.
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
#include "sftp-hpn-server.h"

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
		/* Keep as `unsigned long long` to match the %llu format
		 * specifier — sscanf is strict about the underlying type
		 * (u_int64_t is `unsigned long int` on LP64 Linux, not
		 * `unsigned long long`).  Same exception as the printf cast
		 * idiom — format-spec matching wins over typedef preference. */
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
sftp_hpn_server_handles(const char *name)
{
	return strcmp(name, HPN_EXT_FS_INFO) == 0
	    || strcmp(name, HPN_EXT_BUNDLE_OPEN) == 0
	    || strcmp(name, HPN_EXT_BUNDLE_FETCH) == 0;
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
# include <fcntl.h>      /* O_RDONLY for bundle_fetch_pack_one */
# include <sys/stat.h>
# include <archive.h>
# include <archive_entry.h>
# include <libgen.h>     /* dirname() for mkdir-on-extract */

/* libarchive write block size: matches sftp-client.c, picked to amortise
 * tar header overhead over a reasonable payload chunk. */
# define BUNDLE_BLOCK_BYTES (128 * 1024)

/* Bundle handle mode: upload (open + write + close => extract) vs.
 * download (fetch packs the tar buffer up-front, client drains via
 * SSH_FXP_READ, close releases). */
enum hpn_bundle_mode {
	HPN_BUNDLE_MODE_UPLOAD = 0,   /* hpn-bundle-open */
	HPN_BUNDLE_MODE_FETCH  = 1,   /* hpn-bundle-fetch */
};

/* Bundle state allocated for each open handle.  Lifetime spans from
 * hpn-bundle-open/fetch through close.  Owned by sftp-hpn-server.c; stored on
 * the handle table via handle_new_bundle's opaque field. */
struct hpn_bundle_state {
	enum hpn_bundle_mode mode;
	char    *dest_dir;       /* upload mode: dir to extract into; unused for fetch */
	uint32_t flags;          /* HPN_BUNDLE_FLAG_* */
	u_char  *accum;          /* upload: growing receive buffer; fetch: packed tar */
	size_t   accum_len;
	size_t   accum_cap;
};

/* Flags — must match the client side in sftp-client.c. */
#define HPN_BUNDLE_FLAG_PRESERVE   0x00000001U
#define HPN_BUNDLE_FLAG_FSYNC      0x00000002U

/* ── Server-side bundle accumulator caps ─────────────────────────────────
 *
 * SFTP is normally bounded by SFTP_MAX_MSG_LENGTH (256 KiB per message).
 * Bundle handles break that invariant: an upload bundle accepts a long
 * sequence of WRITEs into a malloc'd accumulator, and a download bundle
 * pre-allocates a tar buffer sized by the client's path list.  Without a
 * server-side cap a malicious or misconfigured client can drive the
 * server to OOM.
 *
 * Caps are process-local — sftp-server is forked per user connection by
 * sshd, so the "total across handles" cap is per-connection.  Per-system
 * memory protection (RLIMIT_AS, sshd's MaxStartups) is the OS's
 * responsibility.
 *
 * Default per-bundle cap is 16× the empirical 4 MiB bundle target,
 * giving operators headroom while still capping abuse at a small number.
 * Default total cap is SFTP_PARALLEL_MAX_WORKERS (24) × per-bundle —
 * matches the maximum concurrent worker count on the client side.
 *
 * Both are tunable via env vars (HPN_BUNDLE_MAX_BYTES,
 * HPN_BUNDLE_MAX_TOTAL_BYTES) read once on first use.  An operator can
 * set these in the sshd unit's environment.  Promotion to a real
 * sshd_config option (HPNBundleMaxSize) is a future cleanup; the env
 * vars exist so the cap is reachable today without plumbing through
 * servconf.c.
 */
#define HPN_BUNDLE_PER_CAP_DEFAULT   ((size_t)64  * 1024 * 1024)  /* 64 MiB */
#define HPN_BUNDLE_TOTAL_CAP_DEFAULT ((size_t)1536* 1024 * 1024)  /* 1.5 GiB */

static size_t bundle_per_cap   = 0;   /* 0 = uninitialised */
static size_t bundle_total_cap = 0;
static size_t bundle_total_bytes = 0; /* sum of accum_cap across open handles */

/* Parse env_var as a byte count; honours K/M/G suffix.  Returns fallback
 * if unset, empty, unparseable, or if the value would overflow when
 * multiplied by the suffix.  The overflow guard is intentional: the
 * env var is operator-controlled, so a typo like 9999999999G should
 * fall back to the default rather than wrap to a bogus small value. */
static size_t
parse_bytes_env(const char *env_var, size_t fallback)
{
	const char *v = getenv(env_var);
	if (v == NULL || *v == '\0')
		return fallback;
	char *end = NULL;
	u_int64_t n = strtoull(v, &end, 10);
	u_int64_t mult = 1;
	if (end == v)
		return fallback;
	switch (*end) {
	case 'G': case 'g': mult = 1024ULL * 1024 * 1024; break;
	case 'M': case 'm': mult = 1024ULL * 1024;        break;
	case 'K': case 'k': mult = 1024ULL;               break;
	case '\0':                                         break;
	default: return fallback;
	}
	/* Overflow check BEFORE multiplying.  If n > SIZE_MAX / mult, the
	 * multiplication would wrap. */
	if (mult > 1 && n > (u_int64_t)SIZE_MAX / mult)
		return fallback;
	n *= mult;
	if (n == 0 || n > SIZE_MAX)
		return fallback;
	return (size_t)n;
}

static void
bundle_caps_init(void)
{
	if (bundle_per_cap != 0)
		return;
	/* ENV-VAR HPN_BUNDLE_MAX_BYTES — server-side: per-bundle accumulator
	 * cap.  Reject WRITE / pack expansion past this point.  Defaults
	 * 64 MiB.  Operator-tunable; raise carefully on high-concurrency
	 * sites since memory cost scales with concurrent bundle handles. */
	bundle_per_cap   = parse_bytes_env("HPN_BUNDLE_MAX_BYTES",
	    HPN_BUNDLE_PER_CAP_DEFAULT);
	/* ENV-VAR HPN_BUNDLE_MAX_TOTAL_BYTES — server-side: aggregate
	 * accumulator cap across all open bundle handles in this
	 * sftp-server process.  Reject new bundle opens / growth past this
	 * point.  Defaults 1.5 GiB. */
	bundle_total_cap = parse_bytes_env("HPN_BUNDLE_MAX_TOTAL_BYTES",
	    HPN_BUNDLE_TOTAL_CAP_DEFAULT);
	debug_f("hpn-bundle caps: per=%zu MiB total=%zu MiB",
	    bundle_per_cap   / (1024*1024),
	    bundle_total_cap / (1024*1024));
}

/* These callbacks live in sftp-server.c so sftp-hpn-server.c doesn't
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
	s->mode = HPN_BUNDLE_MODE_UPLOAD;
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

/* Fetch-mode counterpart: no dest_dir (server-side reads, doesn't extract),
 * accum starts unallocated and is filled by the fetch handler's
 * libarchive write pass before the handle is returned to the client. */
static struct hpn_bundle_state *
bundle_state_new_fetch(uint32_t flags)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->mode      = HPN_BUNDLE_MODE_FETCH;
	s->dest_dir  = NULL;
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
	/* Release this handle's contribution to the process-wide total
	 * before freeing the buffer. */
	if (s->accum_cap > 0) {
		if (bundle_total_bytes >= s->accum_cap)
			bundle_total_bytes -= s->accum_cap;
		else
			bundle_total_bytes = 0;
	}
	free(s->dest_dir);
	free(s->accum);
	free(s);
}

/*
 * Ensure accum has room for `need` additional bytes.
 *
 * Enforces two caps:
 *   - per-bundle: accum_len + need must not exceed bundle_per_cap
 *   - total: the new accum_cap minus the old accum_cap (i.e. the bytes
 *     this growth would add to bundle_total_bytes) must keep
 *     bundle_total_bytes <= bundle_total_cap
 *
 * Returns 0 on success, -1 on allocation failure OR cap exceeded.
 * Callers translate -1 into SSH2_FX_FAILURE on the wire.
 */
static int
bundle_state_reserve(struct hpn_bundle_state *s, size_t need)
{
	bundle_caps_init();

	if (s->accum_len > SIZE_MAX - need ||
	    s->accum_len + need > bundle_per_cap) {
		error_f("hpn-bundle: per-bundle cap exceeded "
		    "(would be %zu, cap %zu)",
		    s->accum_len + need, bundle_per_cap);
		return -1;
	}
	if (s->accum_len + need <= s->accum_cap)
		return 0;

	size_t new_cap = s->accum_cap ? s->accum_cap : 65536;
	while (new_cap < s->accum_len + need) {
		if (new_cap > SIZE_MAX / 2)
			return -1;
		new_cap *= 2;
	}
	/* Clamp the geometric growth to the per-bundle cap so we don't
	 * over-allocate beyond what the bundle could ever legitimately
	 * hold. */
	if (new_cap > bundle_per_cap)
		new_cap = bundle_per_cap;

	size_t added = new_cap - s->accum_cap;
	if (bundle_total_bytes > SIZE_MAX - added ||
	    bundle_total_bytes + added > bundle_total_cap) {
		error_f("hpn-bundle: total-across-handles cap exceeded "
		    "(would be %zu, cap %zu)",
		    bundle_total_bytes + added, bundle_total_cap);
		return -1;
	}

	u_char *p = realloc(s->accum, new_cap);
	if (p == NULL)
		return -1;
	s->accum     = p;
	s->accum_cap = new_cap;
	bundle_total_bytes += added;
	return 0;
}

int
sftp_hpn_server_is_bundle_handle(int handle)
{
	return handle_is_bundle(handle);
}

int
sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;
	if (s->mode != HPN_BUNDLE_MODE_UPLOAD) {
		error_f("hpn-bundle: WRITE on non-upload bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
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

int
sftp_hpn_server_bundle_read(int handle, uint64_t off, u_char *out_buf,
    size_t len, size_t *out_len)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL || out_buf == NULL || out_len == NULL)
		return SSH2_FX_FAILURE;
	if (s->mode != HPN_BUNDLE_MODE_FETCH) {
		error_f("hpn-bundle: READ on non-fetch bundle handle %d",
		    handle);
		return SSH2_FX_FAILURE;
	}
	if (off >= s->accum_len) {
		*out_len = 0;
		return SSH2_FX_EOF;
	}
	size_t avail = s->accum_len - (size_t)off;
	size_t n = len < avail ? len : avail;
	memcpy(out_buf, s->accum + off, n);
	*out_len = n;
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
 * concern; see comment in sftp_hpn_server_bundle_close.
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
 * Used by archive_read_open under sftp_hpn_server_bundle_close.
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
sftp_hpn_server_bundle_close(int handle)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;

	/* Fetch-mode handles already finished their server-side work in the
	 * hpn-bundle-fetch handler (packed tar into accum).  Close is just a
	 * resource release — no libarchive extraction. */
	if (s->mode == HPN_BUNDLE_MODE_FETCH) {
		debug_f("hpn-bundle close (fetch): handle=%d accum=%zu bytes",
		    handle, s->accum_len);
		bundle_state_free(s);
		handle_free_bundle(handle);
		return SSH2_FX_OK;
	}

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

/*
 * libarchive_write callback writing into the bundle_state accumulator
 * via bundle_state_reserve / memcpy.  Mirror of bundle_write_cb on the
 * client upload side, but here the destination is in-process memory
 * rather than the SFTP wire.
 */
static la_ssize_t
bundle_fetch_archive_write_cb(struct archive *a, void *client_data,
    const void *buf, size_t len)
{
	struct hpn_bundle_state *s = client_data;
	(void)a;
	if (bundle_state_reserve(s, len) != 0)
		return -1;
	memcpy(s->accum + s->accum_len, buf, len);
	s->accum_len += len;
	return (la_ssize_t)len;
}

/*
 * Pack one path into the libarchive writer.  Returns 0 on success.
 * On read/header errors the entry is skipped (logged) and the bundle
 * continues — symmetric to upload-side per-entry skip behaviour.
 */
static int
bundle_fetch_pack_one(struct archive *a, const char *path)
{
	struct archive_entry *ae = NULL;
	struct stat sb;
	int fd = -1;
	int rc = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		error_f("hpn-bundle-fetch: open \"%s\": %s",
		    path, strerror(errno));
		goto out;
	}
	if (fstat(fd, &sb) < 0) {
		error_f("hpn-bundle-fetch: fstat \"%s\": %s",
		    path, strerror(errno));
		goto out;
	}
	if (!S_ISREG(sb.st_mode)) {
		debug_f("hpn-bundle-fetch: \"%s\" not a regular file, skipping",
		    path);
		goto out;
	}

	ae = archive_entry_new();
	if (ae == NULL) {
		error_f("hpn-bundle-fetch: archive_entry_new failed");
		goto out;
	}
	archive_entry_set_pathname(ae, path);
	archive_entry_set_size(ae, (la_int64_t)sb.st_size);
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_perm(ae, sb.st_mode & 07777);
	archive_entry_set_mtime(ae, sb.st_mtime, 0);

	if (archive_write_header(a, ae) != ARCHIVE_OK) {
		error_f("hpn-bundle-fetch: header \"%s\": %s",
		    path, archive_error_string(a));
		goto out;
	}

	{
		off_t remaining = sb.st_size;
		u_char buf[65536];
		while (remaining > 0) {
			ssize_t n = read(fd, buf,
			    remaining < (off_t)sizeof(buf)
			    ? (size_t)remaining : sizeof(buf));
			if (n < 0) {
				if (errno == EINTR)
					continue;
				error_f("hpn-bundle-fetch: read \"%s\": %s",
				    path, strerror(errno));
				goto out;
			}
			if (n == 0)
				break;
			if (archive_write_data(a, buf, (size_t)n) != n) {
				error_f("hpn-bundle-fetch: write_data "
				    "\"%s\": %s", path,
				    archive_error_string(a));
				goto out;
			}
			remaining -= n;
		}
	}
	rc = 0;

 out:
	if (ae != NULL)
		archive_entry_free(ae);
	if (fd >= 0)
		(void)close(fd);
	return rc;
}

/*
 * Process the hpn-bundle-fetch@hpnssh.org extended request.
 *
 * Wire format (after extension name):
 *   u32 flags
 *   u32 n_paths
 *   for i in [0, n_paths): cstring path
 *
 * Server reads each file, packs into a libarchive ustar buffer held on
 * a new fetch-mode bundle handle, replies with SSH_FXP_HANDLE.  Client
 * drains the buffer via SSH_FXP_READ and closes the handle when done.
 *
 * On error replies SSH_FXP_STATUS with the appropriate SSH2_FX_* code.
 */
static void
process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	uint32_t flags = 0, n_paths = 0;
	char **paths = NULL;
	uint32_t n_collected = 0;
	struct hpn_bundle_state *s = NULL;
	struct archive *a = NULL;
	struct sshbuf *msg = NULL;
	int handle = -1;
	int r, status = SSH2_FX_FAILURE;
	uint32_t i;

	if ((r = sshbuf_get_u32(iqueue, &flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &n_paths)) != 0) {
		error_f("parse hpn-bundle-fetch header: %s", ssh_err(r));
		goto fail;
	}
	if (n_paths == 0 || n_paths > 65535) {
		error_f("hpn-bundle-fetch: implausible n_paths=%u", n_paths);
		goto fail;
	}
	paths = calloc(n_paths, sizeof(*paths));
	if (paths == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}
	for (i = 0; i < n_paths; i++) {
		if ((r = sshbuf_get_cstring(iqueue, &paths[i], NULL)) != 0) {
			error_f("parse hpn-bundle-fetch path[%u]: %s",
			    i, ssh_err(r));
			goto fail;
		}
		n_collected++;
	}

	debug3("request %u: hpn-bundle-fetch n=%u flags=0x%x",
	    id, n_paths, flags);

	s = bundle_state_new_fetch(flags);
	if (s == NULL) {
		error_f("hpn-bundle-fetch: out of memory");
		goto fail;
	}

	a = archive_write_new();
	if (a == NULL) {
		error_f("hpn-bundle-fetch: archive_write_new failed");
		goto fail;
	}
	if (archive_write_set_format_ustar(a) != ARCHIVE_OK ||
	    archive_write_set_bytes_per_block(a, BUNDLE_BLOCK_BYTES)
	        != ARCHIVE_OK ||
	    archive_write_open(a, s, NULL,
	        bundle_fetch_archive_write_cb, NULL) != ARCHIVE_OK) {
		error_f("hpn-bundle-fetch: libarchive setup: %s",
		    archive_error_string(a));
		goto fail;
	}

	/* Pack each path.  Per-entry failures are logged and skipped so a
	 * single bad file (race-deleted, permission flap) doesn't kill the
	 * whole bundle — symmetric to upload-side per-entry skip. */
	for (i = 0; i < n_paths; i++)
		(void)bundle_fetch_pack_one(a, paths[i]);

	if (archive_write_close(a) != ARCHIVE_OK) {
		error_f("hpn-bundle-fetch: archive_write_close: %s",
		    archive_error_string(a));
		goto fail;
	}
	archive_write_free(a);
	a = NULL;

	handle = handle_new_bundle(s);
	if (handle < 0) {
		error_f("hpn-bundle-fetch: handle table full");
		goto fail;
	}

	debug_f("hpn-bundle-fetch: handle=%d n_paths=%u accum=%zu bytes",
	    handle, n_paths, s->accum_len);

	/* Hand ownership of `s` over to the handle table. */
	s = NULL;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	{
		u_char hbuf[sizeof(int32_t)];
		put_u32(hbuf, (uint32_t)handle);
		if ((r = sshbuf_put_u8(msg, SSH2_FXP_HANDLE)) != 0 ||
		    (r = sshbuf_put_u32(msg, id)) != 0 ||
		    (r = sshbuf_put_string(msg, hbuf, sizeof(hbuf))) != 0)
			fatal_fr(r, "compose bundle-fetch handle reply");
	}
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle-fetch handle reply");
	sshbuf_free(msg);

	for (i = 0; i < n_collected; i++)
		free(paths[i]);
	free(paths);
	return;

 fail:
	if (a != NULL)
		archive_write_free(a);
	if (s != NULL)
		bundle_state_free(s);
	for (i = 0; i < n_collected; i++)
		free(paths[i]);
	free(paths);
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, status)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose bundle-fetch failure");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue bundle-fetch failure");
	sshbuf_free(msg);
}

#else  /* !WITH_LIBARCHIVE */

/* Stubs when libarchive is not available — bundle support is compiled out.
 * The extension is NOT advertised in this case (see compose_extension calls
 * in sftp-server.c, which check WITH_LIBARCHIVE). */

int
sftp_hpn_server_is_bundle_handle(int handle)
{
	(void)handle;
	return 0;
}

int
sftp_hpn_server_bundle_write(int handle, uint64_t off,
    const u_char *data, size_t len)
{
	(void)handle; (void)off; (void)data; (void)len;
	return SSH2_FX_OP_UNSUPPORTED;
}

int
sftp_hpn_server_bundle_close(int handle)
{
	(void)handle;
	return SSH2_FX_OP_UNSUPPORTED;
}

int
sftp_hpn_server_bundle_read(int handle, uint64_t off, u_char *out_buf,
    size_t len, size_t *out_len)
{
	(void)handle; (void)off; (void)out_buf; (void)len;
	if (out_len)
		*out_len = 0;
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

static void
process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
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
				/* Ran out of slashes — bail.  Server returns
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
