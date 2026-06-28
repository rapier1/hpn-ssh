/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/*
 * Parallel-streams orchestrator for the sftp client.
 *
 * Topology (Pattern B): one ControlMaster amortizes auth, then N independent
 * worker SSH connections each open their own SFTP subsystem. A producer
 * thread (typically the caller) submits work units; N worker threads pop
 * units and execute them via the standard sftp_upload / sftp_download /
 * sftp_mkdir APIs. Each worker owns its own struct sftp_conn - no shared
 * cipher state, no shared TCP socket. A reporter thread aggregates per-worker
 * progress counters and drives a single global progress meter.
 *
 * Step 5 (architecture). The CLI wiring (-P N) lands in step 6.
 */

#ifndef _SFTP_PARALLEL_H
#define _SFTP_PARALLEL_H

#include <sys/types.h>
#include <stdint.h>

#include "sftp.h"		/* SFTP_QUIET / SFTP_PROGRESS_ONLY */

struct sftp_parallel;
struct sftp_conn;	/* opaque; defined in sftp-client.c */

/*
 * Per-inode concurrent range-writer cap (-w).  Bounds how many range-split
 * workers write one file's inode at once: buffered multi-writer into a single
 * inode serialises on the per-inode write lock (measured on Lustre - 8 writers
 * to one inode runs slower than 1 plain stream; 4 is the throughput knee).
 * The effective cap is always min(this, num_streams).  DEFAULT is the built-in
 * used when -w is absent; FLOOR/MAX bound the -w argument.
 */
#define HPN_RANGE_WRITERS_CAP_DEFAULT	4
#define HPN_RANGE_WRITERS_CAP_FLOOR	1
#define HPN_RANGE_WRITERS_CAP_MAX	10

struct sftp_parallel_config {
	int          num_streams;       /* N - must be >= 1 */

	/* Worker SSH connection parameters */
	const char  *host;              /* required */
	const char  *port;
	const char  *user;              /* NULL = no -l flag */
	const char  *ssh_binary;        /* /path/to/hpnssh / NULL = "hpnssh" */
	const char  *identity;          /* NULL = rely on agent / default key */
	const char  *known_hosts;       /* NULL = use system/user default */
	const char  *config_file;
	const char  *sftp_server;       /* -s remote subsystem name, or a
	                                 * server-command path (contains '/');
	                                 * NULL = default "sftp" subsystem.
	                                 * Always NULL from scp (no -s subsystem
	                                 * option there). */
	char *const *extra_argv;        /* additional -o KEY=VALUE; may be NULL */

	/* Per-worker sftp_init parameters */
	u_int    transfer_buflen;       /* 0 = default */
	u_int    num_requests;          /* 0 = default */
	uint64_t limit_kbps;            /* 0 = no bandwidth limit */

	/* CLI-set range-split minimum, in MiB.  0 = unset (env or default
	 * applies).  Set by -M flag in sftp.c; bounded [64, 10240] at parse
	 * time. */
	int          range_split_min_mb;

	/* Max concurrent range-writers per inode, set by -w flag in sftp.c.
	 * Bounds how many range units of one file write its inode at once;
	 * effective cap is min(this, num_streams).  Set to
	 * HPN_RANGE_WRITERS_CAP_DEFAULT when -w is absent; -w validates to
	 * [HPN_RANGE_WRITERS_CAP_FLOOR, HPN_RANGE_WRITERS_CAP_MAX]. */
	int          writers_per_inode_cap;

	/* Per-worker SSH stderr capture directory, set by -W flag in sftp.c.
	 * NULL = off (production default - worker stderr is inherited so
	 * connection errors reach the user's terminal).  When non-NULL, each
	 * spawned worker writes its SSH child's stderr to
	 * <worker_log_dir>/hpnssh-worker-<pid>.stderr.  sftp.c validates the
	 * directory exists and is writable at parse time. */
	const char  *worker_log_dir;

	/* User-supplied -v count on the hpnsftp command line.  Passed through
	 * to each parallel worker SSH child so worker-side verbosity matches
	 * what the user asked for at the hpnsftp layer.  When worker_log_dir
	 * is also set, the effective worker level is max(verbose_level, 1)
	 * so the captured stderr files actually contain something useful. */
	int          verbose_level;

	/* Bundle-mode enable, resolved from ssh_config HPNUseBundle by
	 * sftp.c (which queries `hpnssh -G host`).  0 = disabled (force
	 * Phase-4 fallback), 1 = enabled (default; subject to server
	 * advertising the hpn-bundle extension). */
	int          use_bundle;

	/* Writer-pool enable, resolved from ssh_config HPNWriterPool.  1 =
	 * use the bundle writer pool (default); 0 = request serial extract
	 * (sets HPN_BUNDLE_FLAG_NO_POOL on upload, skips the client download
	 * pool). */
	int          writer_pool;

	/* Tail-redistribution enable, resolved from ssh_config
	 * HPNTailRedistribute.  1 = arm phase-C cooperative yield of a
	 * confirmed-lagging endgame holder (default); 0 = the tail detector
	 * stays telemetry-only. */
	int          tail_redistribute;

	/* Retry budget per work unit, resolved from ssh_config
	 * HPNMaxRetries.  Default 3, clamped to [1, 20] by readconf.c
	 * fill_default_options. */
	int          max_retries;

	/* Bundle-mode accumulator target size in bytes, resolved from
	 * ssh_config HPNBundleSize.  Default 4 MiB.  0 = unset / use
	 * default. */
	uint64_t     bundle_size;

	/* Transfer flags applied to every submitted unit */
	/* _Atomic: per-command set_preserve() (main) races worker reads */
	_Atomic int  preserve_flag;
	int          resume_flag;
	int          fsync_flag;
	int          inplace_flag;
	int          follow_link_flag;
	int          verify_transfer;	/* HPNVerifyTransfer: post-transfer
					 * XXH3 verify; warn+collect on
					 * mismatch, never abort */
	int          no_verify_repair;	/* auto-repair (#6): 0 = repair on
					 * (default), 1 = disabled via the
					 * -X VerifyRepair=no CLI token.  OR'd
					 * with HPN_NO_VERIFY_REPAIR in
					 * sftp_parallel_start. */

	/* Reporting: SFTP_QUIET / SFTP_PROGRESS_ONLY / SFTP_PRINT */
	int          print_flag;

	/*
	 * Maximum number of workers allowed in the SSH authentication phase
	 * simultaneously.  Caps concurrent unauthenticated connections to
	 * stay under the server's MaxStartups limit (default 10:30:100).
	 * 0 = auto (8, safely below the default MaxStartups threshold).
	 */
	int          max_auth_concurrent;

	/*
	 * Adaptive throughput-based stall detection (FIRST PASS, opt-in).
	 *
	 * The existing watchdog detects STALLED/DEAD via TIME since last
	 * completion. A worker whose TCP cwnd has been hammered into
	 * collapse may still complete the occasional 10 MiB file at
	 * ~800 kbps - well below useful throughput, but never crossing
	 * the 60/120 s time threshold. We add an outlier-based detector
	 * for that case.
	 *
	 * The detector is intentionally ADAPTIVE: it compares each
	 * worker's throughput to the FASTEST peer worker. Two consequences:
	 *
	 * - "Slow link" case: if the fastest worker is itself slow
	 *   (under tput_path_healthy_kbps), the PATH is the bottleneck
	 *   and we skip - respawning would only churn.
	 * - "Congestion" case: if all workers are similarly slow, no
	 *   outlier exists, no action taken - respawning would not help.
	 *
	 * The detector only acts when one worker is dramatically slower
	 * than its healthy peers - the cwnd-collapse signature.
	 *
	 * Enabled iff tput_path_healthy_kbps > 0. Per watchdog tick (~1s):
	 *   1. Sample each worker's bytes_total+live_bytes delta -> raw kbps.
	 *   2. Update per-worker EMA: ema = alpha*raw + (1-alpha)*ema.
	 *      Cold-starts at the first real measurement (seeds EMA = raw).
	 *      Raw max_kbps is used only for the path-health gate (step 3);
	 *      all outlier decisions use EMA values so a single-tick burst
	 *      from one worker cannot instantly spike the threshold.
	 *   3. If raw max_kbps < tput_path_healthy_kbps, skip (path-limited).
	 *   4. threshold = max_ema_kbps * tput_outlier_fraction.
	 *   5. A worker is an outlier if its ema_kbps < threshold. After
	 *      tput_consec_required consecutive outlier ticks, STALLED;
	 *      after 2 * tput_consec_required, DEAD.
	 *
	 * Reasonable starting values for WAN bulk transfer:
	 *   tput_path_healthy_kbps = 2000   (best worker must clear 2 MB/s)
	 *   tput_outlier_fraction  = 0.25   (outlier if < 25% of EMA max)
	 *   tput_consec_required   = 5      (sustained for ~5 sec)
	 *   tput_ema_alpha         = 0.2    (5-tick / ~5 sec time constant)
	 *
	 * Set tput_path_healthy_kbps to 0 to disable entirely.
	 *
	 * FUTURE: an SSH global request such as
	 * `hpn-conn-stats@hpnssh.org` would let the orchestrator query
	 * the server's TCP_INFO and cross-check the local-side signal
	 * against what the receiver actually observed.  Not in this
	 * first pass - see watchdog_check_workers() for the integration
	 * point.
	 */
	uint64_t     tput_path_healthy_kbps;
	double       tput_outlier_fraction;
	int          tput_consec_required;
	double       tput_ema_alpha;  /* EMA smoothing [0,1]; 0 = default 0.2 */
};

/*
 * Initialise the orchestrator: spawn N independent worker SSH connections,
 * start the worker and reporter threads. Returns NULL on failure (caller
 * should warn and fall back to single-stream mode).
 */
struct sftp_parallel *sftp_parallel_start(const struct sftp_parallel_config *cfg);

/*
 * Populate pcfg fields from ssh_config resolution for `host`.  Uses the
 * same two-pass parser as hpnssh (resolves Match blocks against the
 * canonicalised hostname).  Today maps only:
 *   HPNUseBundle yes|no  ->  pcfg->use_bundle
 * Future ssh_config promotions (BundleSize, etc.) extend the mapping
 * in sftp-parallel-config.c.
 *
 * host            : destination host argument (may include user@)
 * user_config_file: explicit -F path, or NULL to use the standard
 *                   ~/.ssh/config + /etc/ssh/ssh_config search.
 *
 * Returns 0 on success, -1 on parse failure.  On failure pcfg keeps
 * compile-time defaults (use_bundle = 1).
 */
int sftp_parallel_apply_ssh_config(struct sftp_parallel_config *pcfg,
    const char *host, const char *user_config_file,
    char *const *extra_argv);

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
 * sftp_parallel_submit_upload accepts an optional control connection (conn)
 * used to query filesystem stripe geometry and pre-create the remote file
 * when speculative range-splitting applies.  Pass NULL to skip the split
 * decision (the upload is submitted as a single whole-file work unit).
 *
 * resume/verify carry the originating command's intent (reget vs regetv,
 * scp -Z).  When either is set the file is submitted whole-file (range-split
 * resume is deferred) and, if verify is set, the remote MUST advertise
 * hpn-check-file@hpnssh.org - otherwise this is fatal (RESUME_INCOMPAT_MSG),
 * checked once up front on conn in the calling thread.
 */
int sftp_parallel_submit_upload(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode,
    int resume, int verify);
int sftp_parallel_submit_download(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode,
    int resume, int verify);

/*
 * Walker-helper accessors.  Exposed for sftp-parallel-walk.c (the
 * recursive-directory walkers, split out of sftp-parallel.c) so it
 * doesn't need to see struct sftp_parallel's internals.  All read-only
 * (or write-only-via-helper) - no callers should grow direct field
 * access to bypass these.
 */
int sftp_parallel_preserve_flag(const struct sftp_parallel *p);
int sftp_parallel_follow_link_flag(const struct sftp_parallel *p);
int sftp_parallel_is_aborting(const struct sftp_parallel *p);
/* 1 iff the abort was caused by the user's interrupt (Ctrl-C) rather than a
 * fleet failure; drives interrupt-aware (calm) messaging in flush/walker. */
int sftp_parallel_user_abort(const struct sftp_parallel *p);
/* Number of parallel worker streams configured (-j N).  Returns 1 when
 * `p` is NULL (i.e. parallel mode is not engaged). */
int sftp_parallel_num_streams(const struct sftp_parallel *p);

/*
 * HPNLustreStripeCount entry point.  Called by the recursive walker after
 * mkdir of a destination subdirectory, and by sftp.c's single-file upload
 * dispatch on the destination directory.  No-op when the feature is
 * disabled (HPNLustreStripeCount=0), not in parallel mode, the server
 * does not advertise hpn-file-layout, the destination is not on Lustre,
 * the current stripe count already meets or exceeds the desired count,
 * or a prior call on the same conn returned a non-success status (the
 * declined-latch is checked first so subsequent calls short-circuit).
 * On success emits one INFO log line.  Safe to call repeatedly on the
 * same directory - Lustre setstripe is idempotent.
 */
void maybe_apply_lustre_layout(struct sftp_parallel *p,
    struct sftp_conn *conn, const char *dst);

/*
 * Local twin of maybe_apply_lustre_layout for DOWNLOADS: dst is a LOCAL
 * destination directory and this process is the writer, so the layout is
 * applied directly via sftp-lustre.c instead of the wire extension.  Same
 * HPNLustreStripeCount policy (0=off, unset=tiered composite sized to the
 * worker count, N=plain N-stripe with an exact-match skip).  Non-Lustre
 * destinations are skipped silently.  conn supplies only the resolved
 * config value.
 */
void maybe_apply_lustre_layout_local(struct sftp_parallel *p,
    struct sftp_conn *conn, const char *dst);

/*
 * Walker-side failure recorder.  Bumps the orchestrator's
 * walker_failures counter and appends "path: err" (or just "path"
 * when err is NULL) to the failed-paths list.  Used by every walker
 * skip-on-error site.
 */
void sftp_parallel_walker_record_failure(struct sftp_parallel *p,
    const char *path, const char *err);

/*
 * ENV-VAR HPN_BUNDLE_TIMING midstream-freeze probe (2026-06-05): the walker
 * publishes its current phase so the reporter's per-second FLEETSAMPLE can
 * show whether a producer stall (blocked mkdir/fsinfo/layout, or blocked
 * pushing to a full queue) is what starves the fleet.  Set via the accessor
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
void sftp_parallel_set_walker_phase(struct sftp_parallel *p, int phase);

/*
 * Default minimum file size at which a single file is split across workers
 * by byte range.  Below this threshold the file is treated as a whole-file
 * work unit.
 *
 * 2 GiB empirically minimises both wall time and run-to-run variance on
 * the Lustre and ext4 sweeps documented in
 *   benchmark/range-split-tuning-analysis.md
 * On Lustre this avoids the per-chunk close()/OST-commit serialization that
 * dominated the early formula-driven approach; on ext4 it is roughly
 * equivalent to or slightly worse than aggressive chunking at j=4 but
 * dramatically better at j=16.  A single static value that the operator
 * can override is far simpler than the per-fs formula it replaces.
 *
 * Override via -M MiB on the hpnsftp command line.  Range [64, 10240] MiB
 * is enforced both at parse time and again in the resolver below.
 */
#define RANGE_SPLIT_MIN_SIZE_DEFAULT   ((uint64_t)2048 * 1024 * 1024)
#define RANGE_SPLIT_MIN_SIZE_FLOOR     ((uint64_t)64 * 1024 * 1024)
#define RANGE_SPLIT_MIN_SIZE_CEILING   ((uint64_t)10240 * 1024 * 1024)

/*
 * Recursive walkers (Approach B): traverse the source tree on the control
 * connection (`conn`), creating destination directories synchronously along
 * the way, and submitting regular files to the orchestrator's worker pool.
 * The walker returns once the tree has been fully visited and all files
 * submitted; the caller is responsible for sftp_parallel_wait().
 *
 * preserve_flag and follow_link_flag are taken from the orchestrator's
 * stored config.
 */
int sftp_parallel_upload_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify);

int sftp_parallel_download_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag, int resume, int verify);

/*
 * Register the directory of a single transferred path for whole-file verify
 * path factoring (the glob / direct-dispatch path that bypasses the walker).
 * No-op unless verify is enabled.  Pass both the local and remote path.
 */
void sftp_parallel_register_verify_dir(struct sftp_parallel *p,
    const char *path);

/*
 * Block until all submitted units have been completed (or failed past
 * retry limits). After this returns, no in-flight work remains. May be
 * called multiple times; subsequent submits are valid until stop().
 */
void sftp_parallel_wait(struct sftp_parallel *p);

/*
 * Asynchronous abort. Sets a flag that workers check between units; in-flight
 * units are allowed to finish. Safe to call from a signal handler.
 */
void sftp_parallel_abort(struct sftp_parallel *p);

/*
 * Register an external interrupt flag (typically sftp.c's `interrupted`,
 * a volatile sig_atomic_t set by the SIGINT handler).  The reporter thread
 * polls this pointer each tick (~200ms); when non-zero it calls
 * sftp_parallel_abort(), which wakes sftp_parallel_wait() promptly instead
 * of waiting for all in-flight units to complete naturally.
 *
 * Call once after sftp_parallel_start() returns non-NULL.  Pass NULL to
 * clear a previously registered flag.
 */
void sftp_parallel_set_interrupt_flag(struct sftp_parallel *p,
    _Atomic sig_atomic_t *flag);

/*
 * Enable/disable the post-transfer verify phase for work submitted from here
 * on.  The interactive client toggles this per command (put/getv enable it,
 * resume verbs disable it) since one orchestrator persists across commands.
 * No-op when p is NULL.
 */
void sftp_parallel_set_verify_transfer(struct sftp_parallel *p, int on);

/* Per-command preserve toggle (put/get -p) for the parallel/bundle path; the
 * orchestrator persists across commands so each command pushes its effective
 * preserve here.  No-op when p is NULL. */
void sftp_parallel_set_preserve(struct sftp_parallel *p, int on);

/*
 * Register an app-layer round-trip-time estimate (microseconds) for the
 * remote path.  Used by the reporter's tput-outlier check to compute a
 * BDP-sized warmup threshold so newly-respawned workers in TCP slow-start
 * are not killed before they have a chance to ramp.  Sampling RTT once on
 * the control connection right after sftp_parallel_start() is sufficient:
 * every worker connection traverses the same path.  Pass 0 to indicate
 * "unknown" and fall back to the fixed-tick warmup gate.
 */
void sftp_parallel_set_path_rtt(struct sftp_parallel *p, uint64_t rtt_us);

/*
 * Drive a single global progress_meter for the duration of an aggregate
 * batch (e.g. a put/get command's worth of submissions). Call _start
 * before submitting; the orchestrator's reporter thread will update the
 * meter's counter from snapshotted worker bytes_total. Call _stop after
 * sftp_parallel_wait returns.
 *
 * Calling _start while a meter is already active is a no-op. Calling
 * _stop without a started meter is a no-op. label is copied internally.
 */
void sftp_parallel_progress_start(struct sftp_parallel *p, const char *label,
    off_t total_bytes);
void sftp_parallel_progress_stop(struct sftp_parallel *p);
/* Scan a local path recursively; return total bytes of regular files and
 * optionally the file count via file_count_out (may be NULL). */
off_t sftp_parallel_scan_upload_total(const char *src, long *file_count_out);

/*
 * Tear down: signal workers to exit, join all threads, close worker SSH
 * subprocesses, free everything. Idempotent.
 */
void sftp_parallel_stop(struct sftp_parallel *p);

/*
 * Aggregate orchestrator state snapshot.  Cheap (one mutex per worker
 * briefly held).  Safe to call from any thread.
 */

struct sftp_parallel_stats {
	int      num_workers;
	size_t   queue_depth;
	size_t   queue_capacity;
	size_t   queue_high_watermark;
	uint64_t bytes_total_aggregate;
	/*
	 * Cumulative SFTP payload bytes that actually crossed the wire
	 * across all workers (uploads: SSH2_FXP_WRITE payload sent;
	 * downloads: SSH2_FXP_DATA payload received).  Distinct from
	 * bytes_total_aggregate, which counts the full size of every
	 * successfully resolved work unit even when chunked-resume verified
	 * the data already matched and skipped the transfer.  Use this when
	 * reporting "what actually moved" vs bytes_total_aggregate's "what
	 * was resolved."  Sourced from sftp_conn_bytes_wired() on each
	 * worker's conn.
	 */
	uint64_t bytes_wired_aggregate;
	uint64_t units_completed_aggregate;
	uint64_t units_failed_aggregate;
	/* Work units submitted but not yet finalized at snapshot time.
	 * Nonzero after an abort = work abandoned in flight/queue (the
	 * interrupt summary keys on it; nothing "failed", so the failure
	 * aggregates stay zero in that case). */
	uint64_t units_pending;
	/* Files the recursive walker dropped before submission
	 * (lstat / readdir / symlink-stat failures, etc.).  Counted
	 * separately from units_failed_aggregate because they happen on
	 * the main thread inside the walkers, not inside a worker. */
	uint64_t walker_failures_aggregate;
	int      protocol_violations; /* ID mismatches / bad packet types;
				       * non-zero means the transfer was aborted
				       * due to possible MITM or corruption */
	/* Lifetime worker respawn count for this orchestrator session.
	 * Incremented atomically at respawn dispatch.  Surfaced in the
	 * end-of-transfer summary as the operator-visible signal for
	 * "you may have set -j too high" - once respawn churn climbs to
	 * ~25 % of -j, additional workers stop adding throughput because
	 * they're flapping in and out of the outlier-detector reap path. */
	int      total_respawns;
	/* Per-cause worker self-termination counts (a subset of
	 * total_respawns), surfaced in the end-of-transfer summary. */
	int      wedge_terminations;
	int      peer_stall_terminations;
	int      endgame_straggler_reaps;  /* stuck-at-endgame reaps */
	/* Wall-clock duration of the parallel-streams session in
	 * milliseconds.  start_ns is captured in sftp_parallel_start();
	 * elapsed_ms is computed against the monotonic clock at
	 * sftp_parallel_get_stats() call time. */
	uint64_t elapsed_ms;
};

void sftp_parallel_get_stats(struct sftp_parallel *p,
    struct sftp_parallel_stats *out);

/*
 * Drain the orchestrator's bounded list of paths that could not be
 * delivered (permanent give-up after MAX_RETRIES, workqueue push-fail,
 * walker skip-on-error).  Returns the TOTAL number of failures seen
 * (which may exceed the number of held entries - the held list is
 * bounded at orchestrator init time).
 *
 * If `out_paths` and `out_used` are non-NULL, on return *out_paths is
 * a malloc'd array of *out_used strdup'd path strings; caller frees
 * each entry and the array.  Returns 0 with *out_used == 0 and
 * *out_paths == NULL when no failures have occurred.
 *
 * The list is reset by this call so subsequent failures start fresh.
 */
uint64_t sftp_parallel_drain_failed_paths(struct sftp_parallel *p,
    char ***out_paths, size_t *out_used);

/*
 * Drain the HPNVerifyTransfer post-transfer hash-mismatch list (transfers
 * ownership of the path strings to the caller).  Non-zero return => some
 * file failed end-to-end verification => exit SFTP_EX_VERIFY_FAILED.
 */
uint64_t sftp_parallel_drain_verify_failures(struct sftp_parallel *p,
    char ***out_paths, size_t *out_used);

/*
 * Hard cap on the number of parallel worker SSH connections per process.
 *
 * This is intentionally a compile-time constant, not a runtime parameter.
 * Client-side rate limiting is advisory by nature - a malicious actor with
 * control of their own system can bypass any client-side check - so the
 * cap exists to prevent accidental self-DoS (e.g. scripts that launch many
 * hpnsftp processes without realising each spawns N workers) rather than
 * to defend against determined abuse.  The correct defence against abusive
 * connection floods is server-side: MaxStartups, MaxSessions, pf/iptables
 * rate limiting, and fail2ban-style tools.
 */
#define SFTP_PARALLEL_MAX_WORKERS 24

/*
 * Conservative worker count the orchestrator falls back to when the server
 * advertises no parallel-worker policy (hpn-max-workers@hpnssh.org absent,
 * i.e. a stock / non-HPN server).  Keeps an HPN client from opening a large
 * burst of connections to a server that expressed no preference and may not
 * be sized for it.  An HPN server that advertises the extension with value 0
 * ("no cap") is honoured up to SFTP_PARALLEL_MAX_WORKERS instead.
 */
#define HPN_NO_POLICY_WORKER_DEFAULT 8

#endif /* _SFTP_PARALLEL_H */
