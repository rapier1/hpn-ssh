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
 * Lustre layout ioctl ABI — inlined to avoid a build-time dependency on
 * liblustreapi.  The constants and struct shape are stable kernel ABI; any
 * Lustre install that supports stripe-set via lfs(1) also supports this
 * ioctl on an open directory or freshly-created (zero-data) file.
 *
 * We only need v1 to set stripe_count.  Stripe size and pool selection are
 * future revisions of hpn-file-layout — payload is intentionally just the
 * stripe_count today.
 */
#ifndef LOV_USER_MAGIC_V1
# define LOV_USER_MAGIC_V1     0x0BD10BD0
#endif
#ifndef LL_IOC_LOV_SETSTRIPE
# define LL_IOC_LOV_SETSTRIPE  _IOW('f', 154, long)
#endif

struct hpn_lov_user_md_v1 {
	uint32_t lmm_magic;
	uint32_t lmm_pattern;        /* 0 = RAID0 (default) */
	uint64_t lmm_object_id;
	uint64_t lmm_object_seq;
	uint32_t lmm_stripe_size;    /* bytes per stripe; 0 = filesystem default */
	uint16_t lmm_stripe_count;   /* requested count; 0 = "use all OSTs" */
	uint16_t lmm_stripe_offset;  /* starting OST index; (uint16_t)-1 = MDT picks */
} __attribute__((packed));

/*
 * Apply a stripe layout to an open directory or freshly-created file FD.
 * Caller is responsible for opening the path with the appropriate flags
 * (directories: O_RDONLY; new files: O_CREAT|O_RDWR with no prior writes).
 *
 * Returns one of HPN_FILE_LAYOUT_OK / _NOT_FS / _PERM / _FAIL.
 * On OK, *applied_count is set to the count we asked for (Lustre clamps
 * silently if the filesystem has fewer OSTs; we report the requested
 * value, since the actual landed-on-disk count is what subsequent file
 * creates will inherit).
 */
static uint32_t
lustre_set_stripe_fd(int fd, uint32_t requested_count,
    uint32_t *applied_count)
{
	struct hpn_lov_user_md_v1 lum;

	memset(&lum, 0, sizeof(lum));
	lum.lmm_magic         = LOV_USER_MAGIC_V1;
	lum.lmm_pattern       = 0;   /* RAID0 */
	lum.lmm_stripe_size   = 0;   /* fs default */
	lum.lmm_stripe_count  = (uint16_t)(requested_count & 0xFFFFu);
	lum.lmm_stripe_offset = (uint16_t)-1;

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum) == 0) {
		if (applied_count != NULL)
			*applied_count = requested_count;
		return HPN_FILE_LAYOUT_OK;
	}
	if (applied_count != NULL)
		*applied_count = 0;
	switch (errno) {
	case ENOTTY:
	case EINVAL:
	case EOPNOTSUPP:
		return HPN_FILE_LAYOUT_NOT_FS;
	case EPERM:
	case EACCES:
		return HPN_FILE_LAYOUT_PERM;
	default:
		return HPN_FILE_LAYOUT_FAIL;
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

#include <fcntl.h>      /* O_RDONLY for the bundle pack file reads */
#include <sys/stat.h>
#include <libgen.h>     /* dirname() for mkdir-on-extract */
#include "sftp-hpn-tar.h"

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
/* ── Bundle handle state (codec-based) ──────────────────────────────────
 *
 * After the 2026-05-31 libarchive removal, both UPLOAD and FETCH bundles
 * stream through the sftp-hpn-tar codec instead of buffering the whole
 * tar in RAM.  Memory per worker becomes O(1) — just the codec's 512-byte
 * header scratch + the currently-open output file (UPLOAD) or the
 * currently-reading input file (FETCH).
 *
 * UPLOAD path (hpn-bundle-open):
 *   bundle_state holds a parser + per-entry tracking (open fd, remaining
 *   bytes, mode/mtime, last-mkdir cache for dir pre-create optimisation).
 *   sftp_hpn_server_bundle_write feeds the parser; entry callbacks open
 *   the output file, write bytes, then close + apply metadata.
 *
 * FETCH path (hpn-bundle-fetch):
 *   bundle_state holds a writer with all paths queued (finish() called
 *   at OPEN time).  sftp_hpn_server_bundle_read drives pack_next() to
 *   produce bytes on demand into the SFTP DATA reply.
 *
 * Per-bundle and total-process byte caps still apply (see bundle_per_cap
 * / bundle_total_cap), but enforcement shifts: instead of capping the
 * accumulator's allocation, we track total bytes that have flowed
 * through this bundle and trip the cap if exceeded.  The total cap is
 * sized via fetch_writer_total_bytes (FETCH: sum of declared file sizes)
 * and upload_total_bytes_received (UPLOAD: bytes parsed). */
struct hpn_bundle_state {
	enum hpn_bundle_mode mode;
	char    *dest_dir;          /* UPLOAD: dir to extract into; FETCH: NULL */
	uint32_t flags;             /* HPN_BUNDLE_FLAG_*, see sftp-hpn-bundle.h */

	/* UPLOAD-mode fields. */
	struct sftp_hpn_tar_parser *parser;
	uint64_t bytes_received;    /* cumulative WRITE bytes fed to parser */
	uint64_t next_write_off;    /* expected SSH_FXP_WRITE offset */
	/* Per-entry state set by the parser callbacks. */
	char    *cur_full_path;     /* malloc'd dest_dir + "/" + entry path */
	int      cur_fd;            /* open output fd, or -1 */
	uint64_t cur_size;          /* declared size from header */
	mode_t   cur_mode;
	time_t   cur_mtime;
	char    *last_mkdir_dir;    /* last parent dir already mkdir_p'd (D) */

	/* FETCH-mode fields. */
	struct sftp_hpn_tar_writer *writer;
	uint64_t bytes_produced;    /* cumulative pack_next bytes returned */
	uint64_t next_read_off;     /* expected SSH_FXP_READ offset */
	uint64_t fetch_total_size;  /* sum of declared file sizes (cap check) */
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
 * Operator master toggle (sshd_config: HPNUseBundle).  When 0, the
 * server omits the hpn-bundle* extensions from SSH_FXP_VERSION and
 * refuses bundle-open / bundle-fetch with SSH2_FX_OP_UNSUPPORTED.
 * Read from the HPN_USE_BUNDLE env var that sshd-session sets from
 * options.hpn_use_bundle.  Defaults to 1 when the env var is absent
 * or unparseable (preserves prior behaviour for callers that haven't
 * propagated the option).
 *
 * Cached after the first lookup so the hot path is a simple read.
 */
static int    bundle_enabled    = -1;   /* -1 = uninitialised */

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
	const char *ev;

	if (initialised)
		return;

	/* HPN_MAX_BUNDLE_SIZE (sshd_config: HPNMaxBundleSize) — server-
	 * side hard cap on per-bundle accumulator.  Overrides the -B
	 * CLI default if the env var is set and the operator did not
	 * already pass -B explicitly (CLI -B takes precedence). */
	if (bundle_per_cap == 0) {
		ev = getenv("HPN_MAX_BUNDLE_SIZE");
		if (ev != NULL && *ev != '\0') {
			size_t v = parse_bytes_arg(ev);
			if (v > 0)
				bundle_per_cap = clamp_cap("HPNMaxBundleSize",
				    v, HPN_BUNDLE_PER_CAP_MIN,
				    HPN_BUNDLE_PER_CAP_MAX);
		}
	}
	if (bundle_per_cap == 0)
		bundle_per_cap = HPN_BUNDLE_PER_CAP_DEFAULT;
	if (bundle_total_cap == 0)
		bundle_total_cap = HPN_BUNDLE_TOTAL_CAP_DEFAULT;

	/* HPN_USE_BUNDLE (sshd_config: HPNUseBundle) — master toggle.
	 * Absent / unparseable defaults to 1 (enabled). */
	if (bundle_enabled == -1) {
		ev = getenv("HPN_USE_BUNDLE");
		if (ev != NULL && *ev != '\0') {
			if (strcmp(ev, "0") == 0 || strcmp(ev, "no") == 0)
				bundle_enabled = 0;
			else
				bundle_enabled = 1;
		} else {
			bundle_enabled = 1;
		}
	}

	initialised = 1;
	debug_f("hpn-bundle: enabled=%d per_cap=%zu MiB total_cap=%zu MiB",
	    bundle_enabled,
	    bundle_per_cap   / (1024*1024),
	    bundle_total_cap / (1024*1024));
}

/* These callbacks live in sftp-server.c so sftp-hpn-server.c doesn't
 * need to know about the handle table internals. */
extern int    handle_new_bundle(void *opaque);
extern void  *handle_get_bundle(int handle);
extern void   handle_free_bundle(int handle);
extern int    handle_is_bundle(int handle);

/* Forward declarations for parser callbacks (defined below) and the
 * path-safety check (defined later in the file). */
static int bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime);
static int bundle_upload_data_cb(void *ctx, const u_char *data, size_t len);
static int bundle_upload_entry_end_cb(void *ctx);
static int bundle_path_is_safe(const char *p, const char *dest_dir);

static const struct sftp_hpn_tar_callbacks bundle_upload_callbacks = {
	.entry_cb     = bundle_upload_entry_cb,
	.data_cb      = bundle_upload_data_cb,
	.entry_end_cb = bundle_upload_entry_end_cb,
};

static struct hpn_bundle_state *
bundle_state_new(const char *dest_dir, uint32_t flags)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->mode     = HPN_BUNDLE_MODE_UPLOAD;
	s->dest_dir = strdup(dest_dir);
	if (s->dest_dir == NULL) {
		free(s);
		return NULL;
	}
	s->flags  = flags;
	s->cur_fd = -1;
	s->parser = sftp_hpn_tar_parser_new(&bundle_upload_callbacks, s);
	if (s->parser == NULL) {
		free(s->dest_dir);
		free(s);
		return NULL;
	}
	return s;
}

/* Fetch-mode counterpart: no dest_dir (server-side reads, doesn't extract),
 * writer is allocated empty; the fetch handler queues paths into it
 * and calls finish() before installing the handle. */
static struct hpn_bundle_state *
bundle_state_new_fetch(uint32_t flags)
{
	struct hpn_bundle_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->mode   = HPN_BUNDLE_MODE_FETCH;
	s->flags  = flags;
	s->cur_fd = -1;
	s->writer = sftp_hpn_tar_writer_new();
	if (s->writer == NULL) {
		free(s);
		return NULL;
	}
	return s;
}

static void
bundle_state_free(struct hpn_bundle_state *s)
{
	if (s == NULL)
		return;
	/* Release total-cap accounting: subtract the larger of declared-
	 * total (FETCH) or bytes-received (UPLOAD) — whichever this bundle
	 * contributed to the running counter. */
	uint64_t contributed = (s->mode == HPN_BUNDLE_MODE_FETCH)
	    ? s->fetch_total_size
	    : s->bytes_received;
	if (contributed > 0) {
		if (bundle_total_bytes >= contributed)
			bundle_total_bytes -= (size_t)contributed;
		else
			bundle_total_bytes = 0;
	}
	if (s->cur_fd >= 0)
		(void)close(s->cur_fd);
	free(s->cur_full_path);
	free(s->last_mkdir_dir);
	if (s->parser != NULL)
		sftp_hpn_tar_parser_free(s->parser);
	if (s->writer != NULL)
		sftp_hpn_tar_writer_free(s->writer);
	free(s->dest_dir);
	free(s);
}

int
sftp_hpn_server_is_bundle_handle(int handle)
{
	return handle_is_bundle(handle);
}

int
sftp_hpn_server_bundle_enabled(void)
{
	bundle_caps_init();	/* ensures bundle_enabled is populated */
	return bundle_enabled;
}

size_t
sftp_hpn_server_bundle_per_cap(void)
{
	bundle_caps_init();
	if (!bundle_enabled)
		return 0;
	return bundle_per_cap;
}

/* Compose the full destination path for one tar entry.  Returns a
 * malloc'd string on success or NULL on OOM / unsafe path.  *out_safe
 * is set to 0 (unsafe path; caller fails the bundle) or 1 (OK). */
static char *
bundle_compose_path(const char *dest_dir, const char *entry_path, int *out_safe)
{
	char *full;

	*out_safe = 0;
	if (!bundle_path_is_safe(entry_path, dest_dir))
		return NULL;
	if (*dest_dir == '\0') {
		full = strdup(entry_path);
	} else {
		size_t full_len = strlen(dest_dir) + 1 +
		    strlen(entry_path) + 1;
		full = malloc(full_len);
		if (full != NULL)
			snprintf(full, full_len, "%s/%s",
			    dest_dir, entry_path);
	}
	if (full == NULL)
		return NULL;
	*out_safe = 1;
	return full;
}

/* Parser entry callback: header parsed, open output fd, mkdir parent.
 *
 * The "last-mkdir-dir" cache (D) skips redundant mkdir_p calls when many
 * consecutive entries share the same parent directory — the common case
 * for many-small bundles.  Without it every file in a 1000-file bundle
 * does its own dirname() + stat() + mkdir() walk; with it most calls
 * are a single strcmp. */
static int
bundle_upload_entry_cb(void *ctx, const char *path, uint64_t size,
    mode_t mode, time_t mtime)
{
	struct hpn_bundle_state *s = ctx;
	int    safe;
	int    preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;

	/* Per-bundle cap: bytes_received + new entry size must stay in
	 * bounds.  Using uint64 arithmetic; overflow check first. */
	bundle_caps_init();
	if (size > UINT64_MAX - s->bytes_received ||
	    s->bytes_received + size > bundle_per_cap) {
		error_f("hpn-bundle: entry \"%s\" would exceed per-bundle cap "
		    "(have %llu, +size %llu > cap %zu)",
		    path,
		    (unsigned long long)s->bytes_received,
		    (unsigned long long)size,
		    bundle_per_cap);
		return -1;
	}

	s->cur_full_path = bundle_compose_path(s->dest_dir, path, &safe);
	if (!safe) {
		error("hpn-bundle: REJECTED unsafe tar pathname \"%s\" "
		    "(\"..\" component, or absolute path with non-empty "
		    "dest_dir); possible path-traversal attempt", path);
		return -1;
	}
	if (s->cur_full_path == NULL) {
		error_f("hpn-bundle: out of memory composing path");
		return -1;
	}

	/* Pre-create parent directory.  Skip if last_mkdir_dir matches. */
	{
		char *full_copy = strdup(s->cur_full_path);
		if (full_copy != NULL) {
			char *parent = dirname(full_copy);
			if (parent != NULL && strcmp(parent, ".") != 0 &&
			    strcmp(parent, "/") != 0) {
				if (s->last_mkdir_dir == NULL ||
				    strcmp(s->last_mkdir_dir, parent) != 0) {
					(void)mkdir_p(parent, 0755);
					free(s->last_mkdir_dir);
					s->last_mkdir_dir = strdup(parent);
				}
			}
			free(full_copy);
		}
	}

	mode_t perm = preserve ? (mode & 07777) : 0644;
	s->cur_fd = open(s->cur_full_path, O_WRONLY | O_CREAT | O_TRUNC, perm);
	if (s->cur_fd < 0) {
		error_f("hpn-bundle: open \"%s\": %s",
		    s->cur_full_path, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* (E) Pre-allocate extents for fewer fragments + faster sequential
	 * writes on extents-based FS (ext4 / xfs / lustre).  Failure is
	 * non-fatal — write() will just allocate on demand. */
	if (size > 0)
		(void)posix_fallocate(s->cur_fd, 0, (off_t)size);
#endif
	s->cur_size  = size;
	s->cur_mode  = mode;
	s->cur_mtime = mtime;
	return 0;
}

static int
bundle_upload_data_cb(void *ctx, const u_char *data, size_t len)
{
	struct hpn_bundle_state *s = ctx;
	size_t remaining = len;

	if (s->cur_fd < 0)
		return -1;	/* shouldn't happen — parser always pairs */
	while (remaining > 0) {
		ssize_t n = write(s->cur_fd, data, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			error_f("hpn-bundle: write \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			return -1;
		}
		data      += n;
		remaining -= (size_t)n;
	}
	s->bytes_received += (uint64_t)len;
	return 0;
}

static int
bundle_upload_entry_end_cb(void *ctx)
{
	struct hpn_bundle_state *s = ctx;
	int preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (s->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;
	int rc       = 0;

	if (s->cur_fd >= 0) {
		if (preserve) {
			struct timespec ts[2];
			ts[0].tv_sec = s->cur_mtime; ts[0].tv_nsec = 0;
			ts[1].tv_sec = s->cur_mtime; ts[1].tv_nsec = 0;
			(void)futimens(s->cur_fd, ts);
		}
		if (do_fsync && fsync(s->cur_fd) != 0) {
			error_f("hpn-bundle: fsync \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			rc = -1;
		}
		if (close(s->cur_fd) != 0) {
			error_f("hpn-bundle: close \"%s\": %s",
			    s->cur_full_path, strerror(errno));
			rc = -1;
		}
		s->cur_fd = -1;
	}
	free(s->cur_full_path);
	s->cur_full_path = NULL;
	s->cur_size = 0;
	return rc;
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
	/* Client writes monotonically; reject gaps or overlaps. */
	if (off != s->next_write_off) {
		error_f("hpn-bundle write offset mismatch: got %llu "
		    "have %llu",
		    (unsigned long long)off,
		    (unsigned long long)s->next_write_off);
		return SSH2_FX_FAILURE;
	}
	if (s->parser == NULL)
		return SSH2_FX_FAILURE;
	/* Feed bytes straight to the parser; entry callbacks open files
	 * and write data inline (no accumulator).  Streaming preserves
	 * O(1) per-worker memory regardless of bundle size. */
	int pr = sftp_hpn_tar_parser_feed(s->parser, data, len);
	if (pr < 0) {
		error_f("hpn-bundle WRITE: parser error: %s",
		    sftp_hpn_tar_parser_error(s->parser));
		return SSH2_FX_FAILURE;
	}
	s->next_write_off += len;
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
	if (s->writer == NULL) {
		*out_len = 0;
		return SSH2_FX_EOF;
	}
	/* SFTP READs arrive in offset order on a single channel.  Reject
	 * backward seeks loudly — streaming codec can't replay produced
	 * bytes.  Forward "gaps" (off > bytes_produced) are silently
	 * absorbed: they happen naturally when a previous read returned
	 * fewer than CHUNK_BYTES because the bundle ended mid-chunk.  The
	 * client fires each read at fixed chunk_index × CHUNK_BYTES, so
	 * once one read is short, every subsequent read has off >
	 * bytes_produced.  We just produce whatever's left (probably 0,
	 * past the EOA marker) and return EOF.  Without this graceful
	 * absorbtion the client's drain-of-orphan-reads sees STATUS
	 * FAILURE replies, bails the drain, and the next bundle's READs
	 * collide with leftover orphan replies on the wire — surfacing as
	 * "ID mismatch" sftp_conn_die calls and worker abort. */
	if (off < s->bytes_produced) {
		error_f("hpn-bundle READ: backward seek %llu (next %llu)",
		    (unsigned long long)off,
		    (unsigned long long)s->bytes_produced);
		return SSH2_FX_FAILURE;
	}

	/* Fill up to `len` bytes by looping pack_next.  Returns 0 when
	 * EOA has been emitted and no more bytes will follow. */
	size_t produced = 0;
	while (produced < len) {
		ssize_t n = sftp_hpn_tar_writer_pack_next(s->writer,
		    out_buf + produced, len - produced);
		if (n < 0) {
			error_f("hpn-bundle READ: writer error: %s",
			    sftp_hpn_tar_writer_error(s->writer));
			return SSH2_FX_FAILURE;
		}
		if (n == 0)
			break;	/* EOA */
		produced += (size_t)n;
	}
	*out_len = produced;
	s->bytes_produced += produced;
	if (produced == 0)
		return SSH2_FX_EOF;
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

int
sftp_hpn_server_bundle_close(int handle)
{
	struct hpn_bundle_state *s = handle_get_bundle(handle);
	if (s == NULL)
		return SSH2_FX_FAILURE;

	/* Fetch-mode handles already finished their server-side work in the
	 * hpn-bundle-fetch handler (queued paths + finish()).  Close is just
	 * a resource release; the writer's destructor closes any open input
	 * file and discards the queue. */
	if (s->mode == HPN_BUNDLE_MODE_FETCH) {
		debug_f("hpn-bundle close (fetch): handle=%d produced=%llu",
		    handle, (unsigned long long)s->bytes_produced);
		bundle_state_free(s);
		handle_free_bundle(handle);
		return SSH2_FX_OK;
	}

	/* UPLOAD: streaming extract already happened during the WRITE
	 * sequence.  All that remains is to verify the parser reached EOA
	 * (signalled by the trailing two zero blocks) and release the
	 * state.  If the parser hasn't seen EOA we accept that as success
	 * (matches the prior libarchive behaviour where an empty / partial
	 * stream simply produced no extracted files) but log it. */
	int status = SSH2_FX_OK;
	int preserve = (s->flags & HPN_BUNDLE_FLAG_PRESERVE) != 0;
	int do_fsync = (s->flags & HPN_BUNDLE_FLAG_FSYNC) != 0;

	debug_f("hpn-bundle close: handle=%d dest=\"%s\" received=%llu "
	    "preserve=%d fsync=%d",
	    handle, s->dest_dir,
	    (unsigned long long)s->bytes_received, preserve, do_fsync);

	const char *perr = sftp_hpn_tar_parser_error(s->parser);
	if (perr != NULL) {
		error_f("hpn-bundle close: parser error: %s", perr);
		status = SSH2_FX_FAILURE;
	}

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

	/* Operator master toggle: refuse bundle ops with OP_UNSUPPORTED
	 * when sshd_config has HPNUseBundle=no.  Belt-and-suspenders —
	 * the extension is normally not advertised in that mode, but a
	 * misbehaving client could still send a bundle-open. */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-open refused: HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}

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
 * Process the hpn-bundle-fetch@hpnssh.org extended request.
 *
 * Wire format (after extension name):
 *   u32 flags
 *   u32 n_paths
 *   for i in [0, n_paths): cstring path
 *
 * Streaming model (2026-05-31 libarchive removal):
 *   1. Read each path, stat() it for size/perms/mtime.
 *   2. Queue (src_path, archive_path, mode, size, mtime) into the
 *      writer state machine.
 *   3. Call writer_finish() to signal EOA.
 *   4. Install the bundle_state on the handle table; reply HANDLE.
 *
 * The actual file reads + tar packing happen lazily inside
 * sftp_hpn_server_bundle_read() as the client drains via SSH_FXP_READ.
 * Server memory stays O(1) per bundle (one open file at a time +
 * 512-byte header scratch).
 *
 * Error model: bundle is all-or-nothing.  A per-path stat() failure or
 * non-regular file is logged and skipped (matching upload-side per-
 * entry skip), but the per-bundle size cap is enforced before the
 * handle is installed so an abusive client can't pin too much server
 * memory.  Mid-pack failures surface in bundle_read as
 * SSH2_FX_FAILURE.
 */
static void
process_hpn_bundle_fetch(u_int id, struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	uint32_t flags = 0, n_paths = 0;
	char **paths = NULL;
	uint32_t n_collected = 0;
	struct hpn_bundle_state *s = NULL;
	struct sshbuf *msg = NULL;
	int handle = -1;
	int r, status = SSH2_FX_FAILURE;
	uint32_t i;

	/* Operator master toggle (same as bundle-open). */
	if (!sftp_hpn_server_bundle_enabled()) {
		debug_f("hpn-bundle-fetch refused: HPNUseBundle=no");
		status = SSH2_FX_OP_UNSUPPORTED;
		goto fail;
	}

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

	bundle_caps_init();
	for (i = 0; i < n_paths; i++) {
		struct stat sb;
		int fd = open(paths[i], O_RDONLY);
		if (fd < 0) {
			error_f("hpn-bundle-fetch: open \"%s\": %s",
			    paths[i], strerror(errno));
			continue;
		}
		if (fstat(fd, &sb) < 0) {
			error_f("hpn-bundle-fetch: fstat \"%s\": %s",
			    paths[i], strerror(errno));
			(void)close(fd);
			continue;
		}
		(void)close(fd);
		if (!S_ISREG(sb.st_mode)) {
			debug_f("hpn-bundle-fetch: \"%s\" not regular, skip",
			    paths[i]);
			continue;
		}
		uint64_t fsize = (uint64_t)sb.st_size;
		if (fsize > UINT64_MAX - s->fetch_total_size ||
		    s->fetch_total_size + fsize > bundle_per_cap) {
			error_f("hpn-bundle-fetch: total size would exceed "
			    "per-bundle cap (have %llu, +%llu > cap %zu)",
			    (unsigned long long)s->fetch_total_size,
			    (unsigned long long)fsize, bundle_per_cap);
			goto fail;
		}
		if (sftp_hpn_tar_writer_add_file(s->writer,
		    paths[i], paths[i],
		    sb.st_mode, fsize, sb.st_mtime) < 0) {
			error_f("hpn-bundle-fetch: writer_add_file "
			    "\"%s\" rejected (path too long?)", paths[i]);
			continue;
		}
		s->fetch_total_size += fsize;
	}
	sftp_hpn_tar_writer_finish(s->writer);

	if (s->fetch_total_size > SIZE_MAX - bundle_total_bytes ||
	    bundle_total_bytes + (size_t)s->fetch_total_size >
	    bundle_total_cap) {
		error_f("hpn-bundle-fetch: would exceed total-across-handles "
		    "cap (have %zu, +%llu > cap %zu)",
		    bundle_total_bytes,
		    (unsigned long long)s->fetch_total_size,
		    bundle_total_cap);
		goto fail;
	}
	bundle_total_bytes += (size_t)s->fetch_total_size;

	handle = handle_new_bundle(s);
	if (handle < 0) {
		error_f("hpn-bundle-fetch: handle table full");
		goto fail;
	}

	debug_f("hpn-bundle-fetch: handle=%d n_paths=%u total_size=%llu",
	    handle, n_paths,
	    (unsigned long long)s->fetch_total_size);

	s = NULL;	/* ownership transferred to handle table */

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

/* ── BEGIN hpn-file-layout: filesystem layout (Lustre stripe today) ──────
 *
 * Client requests a stripe count for a destination directory before any
 * files land in it; server opens the directory and issues
 * LL_IOC_LOV_SETSTRIPE on the directory FD.  Subsequent files created in
 * the directory inherit the layout — including files extracted from a
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
	u_int32_t	 requested = 0;
	u_int32_t	 applied = 0;
	u_int32_t	 status = HPN_FILE_LAYOUT_FAIL;
	int		 fd = -1;
	int		 r;
	struct sshbuf	*msg = NULL;

	if ((r = sshbuf_get_cstring(iqueue, &path, NULL)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &requested)) != 0) {
		error_f("parse: %s", ssh_err(r));
		goto out;
	}

	debug3("request %u: hpn-file-layout \"%s\" stripe_count=%u",
	    id, path, requested);

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

	status = lustre_set_stripe_fd(fd, requested, &applied);
	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		logit("hpn-file-layout \"%s\" stripe_count %u (requested %u)",
		    path, applied, requested);
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
	    (r = sshbuf_put_u32(msg, applied)) != 0)
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

	/* Lustre / future-fs layout — see process_hpn_file_layout above. */
	if (strcmp(name, HPN_EXT_FILE_LAYOUT) == 0) {
		process_hpn_file_layout(id, iqueue, oqueue);
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
