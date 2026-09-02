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

/*
 * Parallel-streams orchestrator for the sftp client, enabled with -j N.
 *
 * One ControlMaster amortizes auth, then N independent worker SSH
 * connections each open their own SFTP subsystem. The collective workers are
 * the fleet as referenced by the sftp_parallel struct. The individual workers are
 * defined by the sftp_worker struct. These are defined in sftp-parallel-internal.h.
 *
 * A producer thread submits work units; N worker threads pop units
 * and execute them via the standard sftp_upload / sftp_download /
 * sftp_mkdir APIs. Each worker owns its own struct sftp_conn - no shared
 * cipher state, no shared TCP socket. A reporter thread aggregates
 * per-worker progress counters and drives the fleet's progress meter.
 */

#ifndef _SFTP_PARALLEL_H
#define _SFTP_PARALLEL_H

#include <sys/types.h>
#include <stdint.h>

#include "sftp.h"		/* SFTP_QUIET / SFTP_PROGRESS_ONLY */

struct sftp_parallel;
struct sftp_conn;	/* opaque; defined in sftp-client.c */

/*
 * Hard cap on the number of parallel worker SSH connections per process.
 *
 * This is intentionally a compile-time constant, not a runtime parameter.
 * Client-side rate limiting is advisory by nature - a malicious actor with
 * control of their own system can bypass any client-side check - so the
 * cap exists to prevent accidental self-DoS (e.g. scripts that launch many
 * hpnsftp processes without realising each spawns N workers) rather than
 * to defend against determined abuse. The correct defence against abusive
 * connection floods is server-side: MaxStartups, MaxSessions, pf/iptables
 * rate limiting, and fail2ban-style tools.
 */
#define SFTP_PARALLEL_MAX_WORKERS 24

/*
 * Conservative worker count the orchestrator falls back to when the server
 * advertises no parallel-worker policy (hpn-max-workers@hpnssh.org absent,
 * i.e. a stock / non-HPN server). Keeps an HPN client from opening a large
 * burst of connections to a server that expressed no preference and may not
 * be sized for it. An HPN server that advertises the extension with value 0
 * ("no cap") is honoured up to SFTP_PARALLEL_MAX_WORKERS instead.
 */
#define HPN_NO_POLICY_WORKER_DEFAULT 8

/*
 * Per-inode concurrent range-writer cap (-w). Bounds how many range-split
 * workers write one file's inode at once: buffered multi-writer into a single
 * inode serialises on the per-inode write lock (measured on Lustre - 8 writers
 * to one inode runs slower than 1 plain stream; 4 is the throughput knee).
 * DEFAULT is the built-in used when -w is absent; FLOOR/MAX bound the -w argument.
 */
#define HPN_RANGE_WRITERS_CAP_DEFAULT	4
#define HPN_RANGE_WRITERS_CAP_FLOOR	1
#define HPN_RANGE_WRITERS_CAP_MAX	10

/*
 * Default minimum file size at which a single file is split across workers
 * by byte range. Below this threshold the file is treated as a whole-file
 * work unit.
 *
 * 2 GiB empirically minimises both wall time and run-to-run variance on
 * the Lustre and ext4 sweeps. On Lustre this avoids the per-chunk
 * close()/OST-commit serialization that dominated the early formula-driven
 * approach; on ext4 it is roughly equivalent to or slightly worse than
 * aggressive chunking at j=4 but dramatically better at j=16.
 * A single static value that the operator can override is far simpler
 * than the per-fs formula it replaces.
 *
 * Override via -M MiB on the hpnsftp command line. Range [64, 10240] MiB
 * is enforced both at parse time and again in the resolver below.
 */
#define RANGE_SPLIT_MIN_SIZE_DEFAULT   ((uint64_t)2048 * 1024 * 1024)
#define RANGE_SPLIT_MIN_SIZE_FLOOR     ((uint64_t)64 * 1024 * 1024)
#define RANGE_SPLIT_MIN_SIZE_CEILING   ((uint64_t)10240 * 1024 * 1024)

/*
 * ENV-VAR HPN_PARALLEL_TRACE midstream-freeze probe (2026-06-05): the walker
 * publishes its current phase so the reporter's per-second FLEETSAMPLE can
 * show whether a producer stall (blocked mkdir/fsinfo/layout, or blocked
 * pushing to a full queue) is what starves the fleet. Set via the accessor
 * since struct sftp_parallel is private to sftp-parallel.c.
 */
enum sftp_walker_phase {
	SFTP_WKP_INIT = 0,
	SFTP_WKP_ENUM,    /* local readdir/stat enumeration */
	SFTP_WKP_MKDIR,   /* blocked in sftp_mkdir (server round-trip) */
	SFTP_WKP_FSINFO,  /* blocked in sftp_fs_info */
	SFTP_WKP_LAYOUT,  /* blocked in sftp_hpn_set_file_layout */
	SFTP_WKP_SUBMIT,  /* pushing units (blocks if the queue is full) */
	SFTP_WKP_DONE,    /* enumeration complete */
};

/*
 * Caller-filled configuration for one parallel session. sftp.c and scp.c
 * populate it from the command line and from ssh_config, then hand it to
 * sftp_parallel_start, which copies it into the fleet. Read-mostly after
 * that: workers and the reporter read it without locking, so anything that
 * changes per command must be atomic (preserve_flag) rather than plain.
 */
struct sftp_parallel_config {
	int          num_streams;       /* N - must be >= 1 */

	/* Worker SSH connection parameters */
	const char  *host;              /* required */
	const char  *port;
	const char  *user;              /* NULL = no -l flag */
	const char  *ssh_binary;        /* /path/to/hpnssh / NULL = "hpnssh" */
	const char  *identity;          /* NULL = rely on agent / default key */
	const char  *config_file;
	const char  *sftp_server;       /* -s remote subsystem name, or a
	                                 * server-command path (contains '/');
	                                 * NULL = default "sftp" subsystem.
	                                 * Always NULL from scp (no -s subsystem
	                                 * option there). */
	char *const *extra_argv;        /* additional -o KEY=VALUE; may be NULL */

	/* Per-worker sftp_init parameters */
	u_int        transfer_buflen;   /* 0 = default */
	u_int        num_requests;      /* 0 = default */
	uint64_t     limit_kbps;        /* 0 = no bandwidth limit */

	/* CLI-set range-split minimum, in MiB. 0 = unset, so the built-in
	 * default applies. Set by -M in sftp.c; bounded [64, 10240] at parse
	 * time. */
	int          range_split_min_mb;

	/* Max concurrent range-writers per inode, set by -w flag in sftp.c.
	 * Bounds how many range units of one file write its inode at once.
	 * Set to HPN_RANGE_WRITERS_CAP_DEFAULT when -w is absent; -w validates
	 * to [HPN_RANGE_WRITERS_CAP_FLOOR, HPN_RANGE_WRITERS_CAP_MAX]. */
	int          writers_per_inode_cap;

	/* Per-worker SSH stderr capture directory, set by -W flag in sftp.c.
	 * NULL = off (production default - worker stderr is inherited so
	 * connection errors reach the user's terminal). When non-NULL, each
	 * spawned worker writes its SSH child's stderr to
	 * <worker_log_dir>/hpnssh-worker-<pid>.stderr. sftp.c validates the
	 * directory exists and is writable at parse time. */
	const char  *worker_log_dir;

	/* User-supplied -v count, passed through to each worker SSH child so
	 * worker verbosity matches what was asked for at the hpnsftp layer.
	 * When worker_log_dir is set the effective level is
	 * max(verbose_level, 1), since ssh is silent on a clean handshake and
	 * an empty capture file helps nobody. */
	int          verbose_level;

	/* Bundle-mode enable, resolved from ssh_config HPNUseBundle by sftp.c
	 * (which queries `hpnssh -G host`). 0 = disabled, so small files go
	 * through the pipelined batch path instead; 1 = enabled (default,
	 * subject to the server advertising the hpn-bundle extension). */
	int          use_bundle;

	/* Writer-pool enable, resolved from ssh_config HPNWriterPool. 1 =
	 * use the bundle writer pool (default); 0 = request serial extract
	 * (sets HPN_BUNDLE_FLAG_NO_POOL on upload, skips the client download
	 * pool). */
	int          writer_pool;

	/* Tail-redistribution enable, resolved from ssh_config
	 * HPNTailRedistribute. 1 = let the tail detector make a
	 * confirmed-lagging endgame holder yield its work (default); 0 = the
	 * detector stays telemetry-only. */
	int          tail_redistribute;

	/* Retry budget per work unit, resolved from ssh_config HPNMaxRetries.
	 * Default 3, clamped to [1, 20] by readconf.c fill_default_options. */
	int          max_retries;

	/* Fleet zero-progress abort window in seconds, resolved from ssh_config
	 * HPNStallAbortTimeout. Default 60; 0 disables the abort. One of the
	 * conditions that must all hold before the fleet aborts (see
	 * parallel_watchdog_sync_check). */
	int          stall_abort_timeout;

	/* Bundle-mode accumulator target size in bytes, resolved from
	 * ssh_config HPNBundleSize. Default 32 MiB (HPN_BUNDLE_SIZE_DEFAULT),
	 * clamped to [1 MiB, 256 MiB]. 0 = unset, use the default. */
	uint64_t     bundle_size;

	/* Transfer flags applied to every submitted unit */
	/* _Atomic: per-command set_preserve() (main) races worker reads */
	_Atomic int  preserve_flag;
	int          fsync_flag;
	int          inplace_flag;
	int          follow_link_flag;
	int          verify_transfer;	/* Verify transfer: post-transfer
					 * XXH3 verify; warn+collect on
					 * mismatch, never abort */
	int          no_verify_repair;	/* auto-repair: 0 = repair on
					 * (default), 1 = disabled via the
					 * -X VerifyRepair=no CLI token. */

	/* Reporting: SFTP_QUIET / SFTP_PROGRESS_ONLY / SFTP_PRINT */
	int          print_flag;

	/*
	 * Maximum number of workers in the SSH authentication phase at once,
	 * to stay under the server's MaxStartups limit (default 10:30:100).
	 * 0 = auto (8, safely below that threshold).
	 */
	int          max_auth_concurrent;

	/*
	 * Adaptive throughput-based stall detection, enabled iff
	 * tput_path_healthy_bytes_s > 0.
	 *
	 * The time-based watchdog misses a worker whose cwnd has collapsed but
	 * which still completes the occasional file, so this compares each
	 * worker against the fastest peer rather than against a fixed floor.
	 * Comparing against a peer is what makes it safe to act on: when the
	 * fastest worker is itself under tput_path_healthy_bytes_s the path is the
	 * bottleneck, and when every worker is equally slow there is no
	 * outlier. Neither case does anything, because respawning would only
	 * churn.
	 *
	 * An outlier is a worker whose smoothed rate stays below
	 * tput_outlier_fraction of the fleet maximum for tput_consec_required
	 * consecutive ticks. It is marked STALLED for telemetry and never
	 * killed: on a saturated path TCP fairness starves some streams while
	 * peers run at line rate, and a respawn inherits the contention. Kills
	 * come only from the silence paths and born-slow.
	 *
	 * Starting values for WAN bulk transfer: 2 MiB/s path-healthy, 0.25
	 * outlier fraction, 5 consecutive ticks, 0.2 EMA alpha.
	 *
	 * The sampling itself is watchdog_sample_throughput().
	 */
	uint64_t     tput_path_healthy_bytes_s;
	double       tput_outlier_fraction;
	int          tput_consec_required;
	double       tput_ema_alpha;  /* EMA smoothing factor, [0,1] */
};

/*
 * One snapshot of the fleet's aggregate counters, filled by
 * sftp_parallel_get_stats. Every field is a whole-session total that
 * includes workers the reaper has already retired, so a snapshot taken
 * after a respawn never goes backwards.
 */
struct sftp_parallel_stats {
	int      num_workers;
	uint64_t bytes_total_aggregate;
	/* Payload bytes that actually crossed the wire (uploads: WRITE
	 * sent; downloads: DATA received), summed from
	 * sftp_conn_bytes_wired() on each worker's conn. Distinct from
	 * bytes_total_aggregate, which counts every resolved unit at full
	 * size even when chunked resume matched the data and skipped the
	 * transfer: this is what moved, that is what was resolved. */
	uint64_t bytes_wired_aggregate;
	uint64_t units_failed_aggregate;
	/* Work units submitted but not yet finalized at snapshot time.
	 * Nonzero after an abort = work abandoned in flight/queue (the
	 * interrupt summary keys on it; nothing "failed", so the failure
	 * aggregates stay zero in that case). */
	uint64_t units_pending;
	/* Files the recursive walker dropped before submission (lstat,
	 * readdir, symlink-stat failures). Counted separately from
	 * units_failed_aggregate because they happen on the main thread
	 * inside the walkers, not inside a worker. */
	uint64_t walker_failures_aggregate;
	int      protocol_violations; /* ID mismatches / bad packet types;
				       * non-zero means the transfer was aborted
				       * due to possible MITM or corruption */
	/* Lifetime worker respawn count for this orchestrator session.
	 * Incremented atomically at respawn dispatch. Surfaced in the
	 * end-of-transfer summary as the operator-visible signal for
	 * "you may have set -j too high" - once respawn churn climbs to
	 * ~25 % of -j, additional workers stop adding throughput because
	 * they're flapping in and out of the outlier-detector reap path. */
	int      total_respawns;
	/* Per-cause worker self-termination counts (a subset of
	 * total_respawns), surfaced in the end-of-transfer summary. */
	int      wedge_terminations;
	int      peer_stall_terminations;
	/* Wall-clock duration of the session in milliseconds, measured from
	 * the monotonic clock stamped in sftp_parallel_start to the moment
	 * sftp_parallel_get_stats is called. */
	uint64_t elapsed_ms;
};

/*
 * Initialise the orchestrator: spawn N independent worker SSH connections,
 * start the worker and reporter threads. Returns NULL on failure (caller
 * should warn and fall back to single-stream mode).
 */
struct sftp_parallel *sftp_parallel_start(const struct sftp_parallel_config *cfg);

/*
 * Populate pcfg fields from ssh_config resolution for `host`. Uses the
 * same two-pass parser as hpnssh (resolves Match blocks against the
 * canonicalised hostname). Today maps only:
 *   HPNUseBundle yes|no  ->  pcfg->use_bundle
 * Future ssh_config promotions (BundleSize, etc.) extend the mapping
 * in sftp-parallel-config.c.
 *
 * host            : destination host argument (may include user@)
 * user_config_file: explicit -F path, or NULL to use the standard
 *                   ~/.ssh/config + /etc/ssh/ssh_config search.
 *
 * Returns 0 on success, -1 on parse failure. On failure pcfg keeps
 * compile-time defaults (use_bundle = 1).
 */
int sftp_parallel_apply_ssh_config(struct sftp_parallel_config *pcfg,
    const char *host, const char *user_config_file,
    char *const *extra_argv);

/*
 * Set the adaptive throughput-outlier stall-detector fields of pcfg to their
 * defaults. Shared by hpnsftp and hpnscp so the tunables cannot drift
 * between the two.
 */
void sftp_parallel_set_stall_defaults(struct sftp_parallel_config *pcfg);

/*
 * Resolve HPNLustreStripeCount from ssh_config for a host.
 * `extra_argv` plumbing as above.
 * Returns: -1 = auto (default), 0 = feature off, >0 = explicit count.
 * Used by the parallel orchestrator to decide whether (and at what count)
 * to issue hpn-file-layout requests before file creation.
 */
int sftp_resolve_hpn_lustre_stripe_count(const char *host,
    const char *user_config_file, char *const *extra_argv);

/*
 * Submit a work unit. These calls copy the path strings; the caller retains
 * ownership of its own buffers. Returns 0 on success, -1 if the orchestrator
 * is in shutdown / abort state.
 *
 * On upload conn is optional: it queries stripe geometry and pre-creates
 * the remote file when speculative range-splitting applies, and NULL
 * submits the file as one whole-file unit.
 *
 * resume and verify carry the originating command's intent (reget vs
 * regetv, scp -Z); the rules they impose are documented at the definition
 * in sftp-parallel-unit.c.
 */
int sftp_parallel_submit_upload(struct sftp_parallel *fleet,
    struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode,
    int resume, int verify);
int sftp_parallel_submit_download(struct sftp_parallel *fleet,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode,
    int resume, int verify);

/*
 * Walker-helper accessors. Exposed for sftp-parallel-walk.c (the
 * recursive-directory walkers, split out of sftp-parallel.c) so it
 * doesn't need to see struct sftp_parallel's internals. All read-only
 * (or write-only-via-helper) - no callers should grow direct field
 * access to bypass these.
 */
int sftp_parallel_preserve_flag(const struct sftp_parallel *fleet);
int sftp_parallel_follow_link_flag(const struct sftp_parallel *fleet);
int sftp_parallel_is_aborting(const struct sftp_parallel *fleet);
/* 1 iff the abort was caused by the user's interrupt (Ctrl-C) rather than a
 * fleet failure; drives interrupt-aware (calm) messaging in flush/walker. */
int sftp_parallel_user_abort(const struct sftp_parallel *fleet);
/* Number of parallel worker streams configured (-j N). Returns 1 when
 * `fleet` is NULL (i.e. parallel mode is not engaged). */
int sftp_parallel_num_streams(const struct sftp_parallel *fleet);

/*
 * Walker-side failure recorder. Bumps the orchestrator's
 * walker_failures counter and appends "path: err" (or just "path"
 * when err is NULL) to the failed-paths list. Used by every walker
 * skip-on-error site.
 */
void sftp_parallel_walker_record_failure(struct sftp_parallel *fleet,
    const char *path, const char *err);

void sftp_parallel_set_walker_phase(struct sftp_parallel *fleet, int phase);

/*
 * Recursive walkers: traverse the source tree on the control connection
 * (`conn`), creating destination directories synchronously along the way,
 * and submitting regular files to the orchestrator's worker pool.
 * The walker returns once the tree has been fully visited and all files
 * submitted; the caller is responsible for sftp_parallel_wait().
 *
 * preserve_flag and follow_link_flag are taken from the orchestrator's
 * stored config.
 */
int sftp_parallel_upload_dir(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify);

int sftp_parallel_download_dir(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify);

/*
 * Register the directory of a single transferred path for whole-file verify
 * path factoring (the glob / direct-dispatch path that bypasses the walker).
 * No-op unless verify is enabled.
 */
void sftp_parallel_register_verify_dir(struct sftp_parallel *fleet,
    const char *path);

/*
 * Block until all submitted units have been completed (or failed past
 * retry limits). After this returns, no in-flight work remains. May be
 * called multiple times; subsequent submits are valid until stop().
 *
 * conn is the caller's control connection, used once the units have
 * drained to apply the directory attributes the producer walks deferred.
 * May be NULL if the caller has no connection to lend; deferred
 * attributes are then dropped and an error is logged naming how many,
 * since the directories keep the temporary modes they were created with.
 */
void sftp_parallel_wait(struct sftp_parallel *fleet, struct sftp_conn *conn);

/*
 * Asynchronous abort. Sets a flag that workers check between units; in-flight
 * units are allowed to finish. Takes locks, so it must NOT be called from
 * a signal handler: register the handler's flag with
 * sftp_parallel_set_interrupt_flag and let the reporter call this.
 */
void sftp_parallel_abort(struct sftp_parallel *fleet);

/*
 * Register an external interrupt flag (typically sftp.c's `interrupted`,
 * set by the SIGINT handler). The reporter polls it and aborts the fleet
 * when it goes non-zero, which is how a signal reaches the orchestrator
 * without calling sftp_parallel_abort from handler context.
 *
 * Call once after sftp_parallel_start returns non-NULL. Pass NULL to clear
 * a previously registered flag.
 */
void sftp_parallel_set_interrupt_flag(struct sftp_parallel *fleet,
    _Atomic sig_atomic_t *flag);

/*
 * Enable/disable the post-transfer verify phase for work submitted from here
 * on. The interactive client toggles this per command (put/getv enable it,
 * resume verbs disable it) since one orchestrator persists across commands.
 * No-op when fleet is NULL.
 */
void sftp_parallel_set_verify_transfer(struct sftp_parallel *fleet, int on);

/* Per-command preserve toggle (put/get -p) for the parallel/bundle path; the
 * orchestrator persists across commands so each command pushes its effective
 * preserve here. No-op when fleet is NULL. */
void sftp_parallel_set_preserve(struct sftp_parallel *fleet, int on);

/*
 * Register an app-layer round-trip-time estimate, in microseconds, for the
 * remote path. Sample it once on the control connection after
 * sftp_parallel_start: every worker traverses the same path. Pass 0 for
 * "unknown". What the estimate feeds is documented at the definition.
 */
void sftp_parallel_set_path_rtt(struct sftp_parallel *fleet, uint64_t rtt_us);

/*
 * Drive the fleet's progress meter for the duration of an aggregate batch
 * (e.g. a put/get command's worth of submissions). Call _start before
 * submitting and _stop after sftp_parallel_wait returns; the reporter
 * advances the meter in between.
 *
 * _start on an already-active meter is a no-op, as is _stop with no meter
 * started. label is copied internally.
 */
void sftp_parallel_progress_start(struct sftp_parallel *fleet, const char *label,
    off_t total_bytes);
void sftp_parallel_progress_set_total(struct sftp_parallel *fleet,
    off_t total_bytes, size_t nfiles);
/* Fill the one-shot fs-info cache before a streamed enumeration, so a submit
 * during the drain sends nothing on the connection carrying the reply. */
void sftp_parallel_prewarm_fs_info(struct sftp_parallel *fleet,
    struct sftp_conn *conn, const char *remote_path);
/* Block until outstanding files fall below the fleet's ceiling. Called by a
 * producer that can enumerate faster than the fleet drains, so its own memory
 * does not grow with the size of the tree. */
void sftp_parallel_await_capacity(struct sftp_parallel *fleet);
void sftp_parallel_progress_start_counted(struct sftp_parallel *fleet,
    const char *verb, off_t total_bytes);
void sftp_parallel_progress_stop(struct sftp_parallel *fleet);
/* Scan a local path recursively; return total bytes of regular files and
 * optionally the file count via file_count_out (may be NULL). */
off_t sftp_parallel_scan_upload_total(const char *src,
    uint64_t *file_count_out);

/* Store the scan-time total file count (for the progress frames/meter). */
void sftp_parallel_set_file_total(struct sftp_parallel *fleet, uint64_t total);

/* Walker-authoritative per-file counts (for a final END-frame publish). */
u_int sftp_parallel_files_submitted(struct sftp_parallel *fleet);
u_int sftp_parallel_files_total(struct sftp_parallel *fleet);

/* Non-zero after wait if the run was aborted (interrupt / control-session
 * loss / fatal error) - callers must not report success. */
int sftp_parallel_was_aborted(struct sftp_parallel *fleet);

/*
 * Tear down: signal workers to exit, join all threads, close worker SSH
 * subprocesses, free everything. The fleet itself is freed, so call
 * this once and drop the pointer.
 */
void sftp_parallel_stop(struct sftp_parallel *fleet);

/*
 * Fill out with a current snapshot. Cheap - one worker mutex held
 * briefly apiece - and safe to call from any thread.
 */
void sftp_parallel_get_stats(struct sftp_parallel *fleet,
    struct sftp_parallel_stats *out);

/*
 * Drain the orchestrator's bounded list of paths that could not be
 * delivered (permanent give-up after MAX_RETRIES, workqueue push-fail,
 * walker skip-on-error). Returns the TOTAL number of failures seen
 * (which may exceed the number of held entries - the held list is
 * bounded at orchestrator init time).
 *
 * If `out_paths` and `out_used` are non-NULL, on return *out_paths is
 * a malloc'd array of *out_used strdup'd path strings; caller frees
 * each entry and the array. Returns 0 with *out_used == 0 and
 * *out_paths == NULL when no failures have occurred.
 *
 * The list is reset by this call so subsequent failures start fresh.
 */
uint64_t sftp_parallel_drain_failed_paths(struct sftp_parallel *fleet,
    char ***out_paths, size_t *out_used);

/*
 * Drain the verify transfer post-transfer hash-mismatch list (transfers
 * ownership of the path strings to the caller). Non-zero return => some
 * file failed end-to-end verification => exit SFTP_EX_VERIFY_FAILED.
 */
uint64_t sftp_parallel_drain_verify_failures(struct sftp_parallel *fleet,
    char ***out_paths, size_t *out_used);

#endif /* _SFTP_PARALLEL_H */
