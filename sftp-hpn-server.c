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
#include <time.h>
#include <unistd.h>

#include "atomicio.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-hpn-bundle.h"
#include "sftp-hpn-server.h"
#define XXH_INLINE_ALL
#include "xxhash.h"

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

/* Forward decl: definition lives at the bottom of the file. */
static void process_hpn_bundle_open(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

/*
 * Translate errno to an SFTP wire status code, mirroring the
 * errno_to_portable() helper in sftp-server.c (which is file-local
 * static and therefore not reachable from here).  Keep in sync if
 * upstream extends the mapping.
 */
static u_int
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
static void
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

#include <fcntl.h>      /* O_RDONLY for bundle_fetch_pack_one */
#include <sys/stat.h>
#include <archive.h>
#include <archive_entry.h>
# include <libgen.h>     /* dirname() for mkdir-on-extract */

/* Bundle handle mode: upload (client streams WRITE-by-WRITE, server
 * extracts at close) vs. fetch (server packs tar up-front, client
 * drains via READ, close just releases). */
enum hpn_bundle_mode {
	HPN_BUNDLE_MODE_UPLOAD = 0,   /* hpn-bundle-open */
	HPN_BUNDLE_MODE_FETCH  = 1,   /* hpn-bundle-fetch */
};

/* ── Bundle handle state and lifecycle ────────────────────────────────
 *
 * One struct hpn_bundle_state per open bundle handle.  Stored on the
 * handle table via handle_new_bundle's opaque slot.  Two distinct
 * lifecycles based on `mode`:
 *
 * UPLOAD (hpn-bundle-open@hpnssh.org):
 *   process_hpn_bundle_open
 *     ↓ bundle_state_new (mode=UPLOAD, dest_dir set, accum=NULL)
 *     ↓ handle_new_bundle (transfers ownership to handle table)
 *     ↓ replies SSH_FXP_HANDLE
 *   ...client sends one or more SSH_FXP_WRITE on the handle...
 *     each WRITE → sftp_hpn_server_bundle_write
 *       → bundle_state_reserve  (grows accum, updates bundle_total_bytes)
 *       → memcpy into accum
 *   ...client sends SSH_FXP_CLOSE...
 *     → sftp_hpn_server_bundle_close (UPLOAD branch)
 *       → libarchive read on accum, extract files to dest_dir
 *       → bundle_state_free + handle_free_bundle
 *
 * FETCH (hpn-bundle-fetch@hpnssh.org):
 *   process_hpn_bundle_fetch
 *     ↓ bundle_state_new_fetch (mode=FETCH, dest_dir=NULL, accum=NULL)
 *     ↓ libarchive write_open with bundle_fetch_archive_write_cb
 *     ↓ per requested path: read file → archive_write_data
 *         (callback calls bundle_state_reserve + memcpy — accum grows
 *          and bundle_total_bytes is updated)
 *     ↓ archive_write_close (flushes trailing block into accum)
 *     ↓ handle_new_bundle (transfers ownership)
 *     ↓ replies SSH_FXP_HANDLE
 *   ...client sends one or more SSH_FXP_READ on the handle...
 *     each READ → sftp_hpn_server_bundle_read (memcpy out of accum)
 *   ...client sends SSH_FXP_CLOSE...
 *     → sftp_hpn_server_bundle_close (FETCH branch — short-circuits)
 *       → bundle_state_free + handle_free_bundle (no extraction)
 *
 * Death paths (all converge on bundle_state_free):
 *   1. Normal close — extracted (UPLOAD) or released (FETCH)
 *   2. process_hpn_bundle_fetch fail label — packing failed before
 *      the handle was registered; the local `s` is freed via the
 *      fail-label cleanup
 *   3. process_hpn_bundle_open fail label — bundle_state_new succeeded
 *      but handle_new_bundle failed (handle table full); local `s`
 *      freed via the fail label
 *   4. sftp-server process exit — handle table cleanup eventually
 *      reaches bundle_close paths (handled by sftp-server.c)
 *
 * Ownership invariants:
 *   - After bundle_state_new[_fetch], the local pointer `s` owns
 *     the struct.
 *   - After handle_new_bundle succeeds, ownership transfers to the
 *     handle table; the local pointer MUST be set to NULL so the
 *     fail-label cleanup doesn't double-free.
 *   - bundle_state_free is idempotent against NULL; safe to call
 *     from any fail label.
 *
 * Memory accounting invariants (see bundle_state_reserve /
 * bundle_state_free for enforcement):
 *   - accum_len ≤ accum_cap always.
 *   - accum is NULL iff accum_cap == 0 (fresh state, not yet grown).
 *   - The process-wide static `bundle_total_bytes` is the sum of
 *     accum_cap across all currently-allocated bundle states.  Only
 *     bundle_state_reserve increments it; only bundle_state_free
 *     decrements it.  Any other code path that touches accum/accum_cap
 *     would violate the cap enforcement — don't do that.
 */
struct hpn_bundle_state {
	enum hpn_bundle_mode mode;
	char    *dest_dir;       /* UPLOAD: dir to extract into; FETCH: NULL */
	uint32_t flags;          /* HPN_BUNDLE_FLAG_*, see sftp-hpn-bundle.h */
	u_char  *accum;          /* UPLOAD: incoming WRITE buffer;
				  * FETCH:  pre-packed tar stream */
	size_t   accum_len;      /* bytes valid in accum */
	size_t   accum_cap;      /* bytes allocated for accum */
};

/* Flag constants and HPN_BUNDLE_BLOCK_BYTES live in sftp-hpn-bundle.h, the
 * shared HPN-only header.  Single source of truth for client + server. */

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
 * Both are tunable via the sftp-server -B (per-bundle) and -T (total)
 * CLI flags, which the operator sets on the sshd_config Subsystem line:
 *
 *   Subsystem  sftp  /usr/libexec/hpnsftp-server -B 64M -T 1500M
 *
 * sftp-server.c parses the flags and calls sftp_hpn_server_set_bundle_caps
 * before the SFTP main loop runs.  Unset flags leave the compiled
 * defaults in place.
 */
#define HPN_BUNDLE_PER_CAP_DEFAULT   ((size_t)64   * 1024 * 1024)        /* 64 MiB */
#define HPN_BUNDLE_PER_CAP_MIN       ((size_t)1    * 1024 * 1024)        /* 1 MiB */
#define HPN_BUNDLE_PER_CAP_MAX       ((size_t)1024 * 1024 * 1024)        /* 1 GiB */
#define HPN_BUNDLE_TOTAL_CAP_DEFAULT ((size_t)1536 * 1024 * 1024)        /* 1.5 GiB */
#define HPN_BUNDLE_TOTAL_CAP_MIN     ((size_t)16   * 1024 * 1024)        /* 16 MiB */
#define HPN_BUNDLE_TOTAL_CAP_MAX     ((size_t)16ULL * 1024 * 1024 * 1024) /* 16 GiB */

static size_t bundle_per_cap   = 0;   /* 0 = uninitialised */
static size_t bundle_total_cap = 0;
static size_t bundle_total_bytes = 0; /* sum of accum_cap across open handles */

/*
 * Parse a K/M/G-suffixed byte count.  Returns the parsed value on
 * success, or 0 if spec is NULL/empty/unparseable or would overflow
 * size_t when the suffix is applied.  Callers must check for 0
 * separately from a legitimately-parsed value, since 0 itself is never
 * a valid cap.
 */
static size_t
parse_bytes_arg(const char *spec)
{
	char *end = NULL;
	u_int64_t n, mult = 1;

	if (spec == NULL || *spec == '\0')
		return 0;
	n = strtoull(spec, &end, 10);
	if (end == spec)
		return 0;
	switch (*end) {
	case 'G': case 'g': mult = 1024ULL * 1024 * 1024; break;
	case 'M': case 'm': mult = 1024ULL * 1024;        break;
	case 'K': case 'k': mult = 1024ULL;               break;
	case '\0':                                         break;
	default: return 0;
	}
	/* Overflow check BEFORE multiplying. */
	if (mult > 1 && n > (u_int64_t)SIZE_MAX / mult)
		return 0;
	n *= mult;
	if (n == 0 || n > SIZE_MAX)
		return 0;
	return (size_t)n;
}

/*
 * Clamp value into [lo, hi], warning to stderr on either boundary so
 * the operator notices that their request was adjusted.
 */
static size_t
clamp_cap(const char *flag, size_t v, size_t lo, size_t hi)
{
	if (v < lo) {
		fprintf(stderr,
		    "%s %zu bytes is below minimum %zu MiB; clamping.\n",
		    flag, v, lo / (1024 * 1024));
		return lo;
	}
	if (v > hi) {
		fprintf(stderr,
		    "%s %zu bytes is above maximum %zu MiB; clamping.\n",
		    flag, v, hi / (1024 * 1024));
		return hi;
	}
	return v;
}

void
sftp_hpn_server_set_bundle_caps(const char *per_arg, const char *total_arg)
{
	if (per_arg != NULL && *per_arg != '\0') {
		size_t v = parse_bytes_arg(per_arg);
		if (v == 0)
			fatal("Invalid -B value \"%s\"", per_arg);
		bundle_per_cap = clamp_cap("-B", v,
		    HPN_BUNDLE_PER_CAP_MIN, HPN_BUNDLE_PER_CAP_MAX);
	}
	if (total_arg != NULL && *total_arg != '\0') {
		size_t v = parse_bytes_arg(total_arg);
		if (v == 0)
			fatal("Invalid -T value \"%s\"", total_arg);
		bundle_total_cap = clamp_cap("-T", v,
		    HPN_BUNDLE_TOTAL_CAP_MIN, HPN_BUNDLE_TOTAL_CAP_MAX);
	}
}

static void
bundle_caps_init(void)
{
	static int initialised = 0;

	if (initialised)
		return;
	if (bundle_per_cap == 0)
		bundle_per_cap = HPN_BUNDLE_PER_CAP_DEFAULT;
	if (bundle_total_cap == 0)
		bundle_total_cap = HPN_BUNDLE_TOTAL_CAP_DEFAULT;
	initialised = 1;
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
 * Validate a tar entry pathname before composing it into a destination
 * path.  Rejects:
 *   - NULL or empty
 *   - any "/"-separated component equal to ".." (traversal — always
 *     anomalous for a bundle producer; plain SFTP OPEN never has
 *     reason to encode a "../" climb in a single pathname)
 *   - leading "/" ONLY when dest_dir is non-empty.  When dest_dir is
 *     empty the protocol explicitly delegates path interpretation to
 *     the server's standard SFTP path-resolution (mirroring plain
 *     SFTP OPEN semantics, including absolute paths the user has
 *     permission to write); when dest_dir is non-empty an absolute
 *     pathname composed as "dest_dir/" + "/abs/path" produces weird
 *     semantics that the protocol never intends.
 *
 * Returns 1 if the pathname is safe to extract under the given
 * dest_dir, 0 if it must be rejected.
 */
static int
bundle_path_is_safe(const char *p, const char *dest_dir)
{
	const char *start, *q;

	if (p == NULL || *p == '\0')
		return 0;
	if (*p == '/' && dest_dir != NULL && *dest_dir != '\0')
		return 0;
	start = p;
	for (q = p; ; q++) {
		if (*q == '/' || *q == '\0') {
			size_t len = (size_t)(q - start);
			if (len == 2 && start[0] == '.' && start[1] == '.')
				return 0;
			if (*q == '\0')
				break;
			start = q + 1;
		}
	}
	return 1;
}

/*
 * Tar paths like "a/b/c.dat" need their parent directories created
 * before we can open() the file.  The on-the-fly mkdir-p is in
 * misc.c so both client (-W setup) and server (this file) can share
 * it.  See the libarchive archive_write_disk path comment in
 * sftp_hpn_server_bundle_close for a future cleanup direction.
 */

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
		if (!bundle_path_is_safe(path, s->dest_dir)) {
			/* Loud rejection — anyone seeing this in the sftp
			 * server log should investigate the originating
			 * client.  Mark the whole bundle as failed so the
			 * client gets a clear signal too. */
			error("hpn-bundle: REJECTED unsafe tar pathname "
			    "\"%s\" (\"..\" component, or absolute path with "
			    "non-empty dest_dir); possible path-traversal "
			    "attempt", path);
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
	    archive_write_set_bytes_per_block(a, HPN_BUNDLE_BLOCK_BYTES)
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

/* ── END Phase 5 ───────────────────────────────────────────────────────── */

/* ── BEGIN sftp-hash-range: chunked-resume ranged XXH3 hashing ─────────────
 *
 * Multi-range variant of hpn-check-file: client supplies N (offset, length)
 * tuples in one request, server returns N XXH3_64bits hashes in one reply.
 * Used by chunked resume to identify exactly which chunks of a same-size
 * destination differ from the source, so only those chunks get re-transferred
 * instead of the whole file (closes the cost half of the sparse-hole gate).
 *
 * Wire format:
 *   request:  string path | uint32 num_ranges
 *             | num_ranges * (uint64 off, uint64 len)
 *   reply:    uint32 num_hashes (== num_ranges)
 *             | num_hashes * uint64 hash
 *
 * Error model: all-or-nothing.  Any range that fails to hash (I/O error,
 * resource cap, file vanished mid-request) rejects the entire request with
 * a single SSH2_FXP_STATUS reply -- no partial hashes.  The client falls
 * back to hpn-check-file whole-file hash on this failure, then to full
 * re-transfer if that also fails.
 *
 * EOF clamping: offset+length > file_size is clamped to [offset, file_size);
 * offset >= file_size hashes zero bytes (well-defined XXH3 constant).  The
 * client sees a mismatch against its local "full chunk" hash and correctly
 * flags the chunk as incomplete.
 */
#define SFTP_HASH_RANGE_MAX_RANGES	65536U
#define SFTP_HASH_RANGE_MAX_LEN		((u_int64_t)SSHBUF_SIZE_MAX)

struct hash_range {
	u_int64_t	off;
	u_int64_t	len;
};

/*
 * Drain oqueue synchronously to STDOUT_FILENO via atomicio().  Used by the
 * heartbeat path so the bytes actually reach the SSH transport mid-handler
 * instead of sitting in oqueue until the handler returns (sftp-server's
 * main poll loop does not iterate during a handler call).  Order is
 * preserved: pre-handler pending bytes leave first, the heartbeat after.
 */
static void
flush_oqueue_blocking(struct sshbuf *oqueue)
{
	size_t	len, wrote;

	len = sshbuf_len(oqueue);
	if (len == 0)
		return;
	wrote = atomicio(vwrite, STDOUT_FILENO,
	    (void *)sshbuf_ptr(oqueue), len);
	if (wrote > 0)
		(void)sshbuf_consume(oqueue, wrote);
}

/*
 * Emit an sftp-hash-range heartbeat into oqueue, then synchronously
 * drain.  Wire shape matches the final reply prefix
 * (type | id | num_hashes) but with the reserved sentinel
 * HPN_NUM_HASHES_HEARTBEAT in num_hashes.  Called from the inner read
 * loop every HPN_HEARTBEAT_EMIT_INTERVAL_SEC seconds; lets the client
 * refresh its watchdog-pause window so the parallel orchestrator doesn't
 * kill the worker mid-hash on a slow / contended disk.
 */
static void
send_hpn_hash_range_heartbeat(u_int id, struct sshbuf *oqueue)
{
	struct sshbuf	*msg;
	int		 r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_EXTENDED_REPLY)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg,
	        (u_int32_t)HPN_NUM_HASHES_HEARTBEAT)) != 0)
		fatal_fr(r, "compose heartbeat");
	debug3("sftp-hash-range: heartbeat id=%u", id);
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue heartbeat");
	sshbuf_free(msg);
	flush_oqueue_blocking(oqueue);
}

static time_t
hpn_hash_range_monotonic_sec(void)
{
	struct timespec	 ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return ts.tv_sec;
}

static void
process_hpn_hash_range(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	char			*path = NULL;
	u_int32_t		 num_ranges = 0;
	struct hash_range	*ranges = NULL;
	u_int64_t		*hashes = NULL;
	XXH3_state_t		*state = NULL;
	struct sshbuf		*msg = NULL;
	struct stat		 st;
	u_char			 buf[65536];
	u_int64_t		 fsize = 0;
	time_t			 last_hb_sec;
	u_int32_t		 i;
	int			 fd = -1;
	int			 r;

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
		if (ranges[i].len > SFTP_HASH_RANGE_MAX_LEN) {
			error_f("range %u length %llu > cap %llu for \"%s\"",
			    i, (unsigned long long)ranges[i].len,
			    (unsigned long long)SFTP_HASH_RANGE_MAX_LEN, path);
			goto fail_status;
		}
	}

	logit("sftp-hash-range \"%s\" num_ranges=%u", path, num_ranges);

	if ((fd = open(path, O_RDONLY|O_NOFOLLOW)) == -1) {
		send_status_oqueue(oqueue, id,
		    errno_to_sftp_status(errno));
		goto out;
	}
	if (fstat(fd, &st) == -1) {
		send_status_oqueue(oqueue, id,
		    errno_to_sftp_status(errno));
		goto out;
	}
	fsize = (u_int64_t)st.st_size;

	if ((state = XXH3_createState()) == NULL) {
		error_f("XXH3_createState failed");
		goto fail_status;
	}

	/*
	 * For each range, lseek to the offset and hash bytes
	 * [offset, min(offset+length, file_size)).  EOF clamping handled by
	 * starting `remaining` at the clamped length (zero if offset >= fsize).
	 * All-or-nothing: any read or hash failure bails out with a single
	 * SSH2_FXP_STATUS reply.
	 *
	 * Heartbeats: every HPN_HEARTBEAT_EMIT_INTERVAL_SEC of elapsed wall
	 * time inside this loop we enqueue a tiny "still working" reply on
	 * oqueue.  Lets the client's parallel orchestrator's watchdog see
	 * proof of life so it doesn't kill the worker mid-hash on slow /
	 * contended storage.  See sftp-hpn-server.h for the wire format.
	 */
	last_hb_sec = hpn_hash_range_monotonic_sec();
	for (i = 0; i < num_ranges; i++) {
		u_int64_t	 off = ranges[i].off;
		u_int64_t	 want = ranges[i].len;
		u_int64_t	 remaining;
		ssize_t		 nread;

		if (XXH3_64bits_reset(state) == XXH_ERROR) {
			error_f("XXH3_64bits_reset failed at range %u", i);
			goto fail_status;
		}

		if (off >= fsize) {
			remaining = 0;
		} else {
			u_int64_t avail = fsize - off;
			remaining = want < avail ? want : avail;
		}

		if (remaining > 0) {
			if (lseek(fd, (off_t)off, SEEK_SET) == (off_t)-1) {
				send_status_oqueue(oqueue, id,
				    errno_to_sftp_status(errno));
				goto out;
			}
			while (remaining > 0) {
				size_t toread = (size_t)MINIMUM(
				    (u_int64_t)sizeof(buf), remaining);
				nread = read(fd, buf, toread);
				if (nread == 0)
					break;	/* shouldn't happen given
						 * clamp, but defensive */
				if (nread < 0) {
					send_status_oqueue(oqueue, id,
					    errno_to_sftp_status(errno));
					goto out;
				}
				if (XXH3_64bits_update(state, buf,
				    (size_t)nread) == XXH_ERROR) {
					error_f("XXH3_64bits_update failed "
					    "at range %u", i);
					goto fail_status;
				}
				remaining -= (u_int64_t)nread;

				/* Time-keyed heartbeat (see comment above). */
				{
					time_t now =
					    hpn_hash_range_monotonic_sec();
					if (now != 0 && last_hb_sec != 0 &&
					    (now - last_hb_sec) >=
					    (time_t)
					    HPN_HEARTBEAT_EMIT_INTERVAL_SEC) {
						send_hpn_hash_range_heartbeat(
						    id, oqueue);
						last_hb_sec = now;
					}
				}
			}
		}
		hashes[i] = (u_int64_t)XXH3_64bits_digest(state);
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
	if (msg != NULL)
		sshbuf_free(msg);
	if (state != NULL)
		XXH3_freeState(state);
	if (fd != -1)
		close(fd);
	free(ranges);
	free(hashes);
	free(path);
}

/* ── END sftp-hash-range ───────────────────────────────────────────────── */

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

	/* Chunked-resume ranged hashing — see process_hpn_hash_range above. */
	if (strcmp(name, HPN_EXT_HASH_RANGE) == 0) {
		process_hpn_hash_range(id, iqueue, oqueue);
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
	send_status_oqueue(oqueue, id, SSH2_FX_OP_UNSUPPORTED);
}
