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
 * sftp_mkdir APIs. Each worker owns its own struct sftp_conn — no shared
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

struct sftp_parallel_config {
	int          num_streams;       /* N — must be >= 1 */

	/* Worker SSH connection parameters */
	const char  *host;              /* required */
	const char  *port;
	const char  *user;              /* NULL = no -l flag */
	const char  *ssh_binary;        /* /path/to/hpnssh / NULL = "hpnssh" */
	const char  *identity;          /* NULL = rely on agent / default key */
	const char  *known_hosts;       /* NULL = use system/user default */
	const char  *config_file;
	char *const *extra_argv;        /* additional -o KEY=VALUE; may be NULL */

	/* Per-worker sftp_init parameters */
	unsigned int transfer_buflen;   /* 0 = default */
	unsigned int num_requests;      /* 0 = default */
	uint64_t     limit_kbps;        /* 0 = no bandwidth limit */

	/* Transfer flags applied to every submitted unit */
	int          preserve_flag;
	int          resume_flag;
	int          fsync_flag;
	int          inplace_flag;
	int          follow_link_flag;

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
	 * ~800 kbps — well below useful throughput, but never crossing
	 * the 60/120 s time threshold. We add an outlier-based detector
	 * for that case.
	 *
	 * The detector is intentionally ADAPTIVE: it compares each
	 * worker's throughput to the FASTEST peer worker. Two consequences:
	 *
	 * - "Slow link" case: if the fastest worker is itself slow
	 *   (under tput_path_healthy_kbps), the PATH is the bottleneck
	 *   and we skip — respawning would only churn.
	 * - "Congestion" case: if all workers are similarly slow, no
	 *   outlier exists, no action taken — respawning would not help.
	 *
	 * The detector only acts when one worker is dramatically slower
	 * than its healthy peers — the cwnd-collapse signature.
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
	 * first pass — see watchdog_check_workers() for the integration
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
 * Submit a work unit. These calls copy the path strings; the caller retains
 * ownership of its own buffers. Returns 0 on success, -1 if the orchestrator
 * is in shutdown / abort state.
 *
 * sftp_parallel_submit_upload accepts an optional control connection (conn)
 * used to query filesystem stripe geometry and pre-create the remote file
 * when speculative range-splitting applies.  Pass NULL to skip the split
 * decision (the upload is submitted as a single whole-file work unit).
 */
int sftp_parallel_submit_upload(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode);
int sftp_parallel_submit_download(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode);
int sftp_parallel_submit_mkdir(struct sftp_parallel *p,
    const char *remote_path, mode_t mode);

/*
 * Minimum file size (bytes) at which a single file is split across workers
 * by byte range.  Below this threshold the file is treated as a whole-file
 * work unit.  Splitting very small files would add more overhead (extra open
 * round-trips, pre-creation) than it saves.
 */
#define RANGE_SPLIT_MIN_SIZE  (64 * 1024 * 1024)   /* 64 MiB */

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
    const char *src, const char *dst, int print_flag);

int sftp_parallel_download_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag);

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
    volatile sig_atomic_t *flag);

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

/* Observability — safe to call any time after start(). */
uint64_t sftp_parallel_bytes_total(struct sftp_parallel *p);
uint64_t sftp_parallel_units_completed(struct sftp_parallel *p);
uint64_t sftp_parallel_units_failed(struct sftp_parallel *p);

/*
 * Programmatic stats surface for adaptive control.
 *
 * sftp_parallel_get_stats() returns aggregate orchestrator state cheaply
 * (one mutex per worker briefly held). sftp_parallel_get_worker_stats()
 * fills a caller-provided array with per-worker snapshots; returns the
 * number of workers actually copied (<= max). Both are safe to call from
 * any thread including a control loop running on its own cadence.
 *
 * Worker IDs are stable across the lifetime of the orchestrator — when
 * a worker is removed, its slot compacts but its id is not reused.
 */

/* Worker health classification — mirrors the internal enum. */
#define SFTP_PARALLEL_HEALTHY  0
#define SFTP_PARALLEL_STALLED  1
#define SFTP_PARALLEL_DEAD     2

struct sftp_parallel_stats {
	int      num_workers;
	size_t   queue_depth;
	size_t   queue_capacity;
	size_t   queue_high_watermark;
	uint64_t bytes_total_aggregate;
	uint64_t units_completed_aggregate;
	uint64_t units_failed_aggregate;
	int      protocol_violations; /* ID mismatches / bad packet types;
				       * non-zero means the transfer was aborted
				       * due to possible MITM or corruption */
};

struct sftp_parallel_worker_stats {
	int      id;
	int      health;          /* SFTP_PARALLEL_{HEALTHY,STALLED,DEAD} */
	uint64_t bytes_total;
	uint64_t units_started;
	uint64_t units_completed;
	uint64_t units_failed;
	uint64_t reconnect_count;
	uint64_t last_completion_ns; /* monotonic, 0 if no completion yet */
};

void sftp_parallel_get_stats(struct sftp_parallel *p,
    struct sftp_parallel_stats *out);
int sftp_parallel_get_worker_stats(struct sftp_parallel *p,
    struct sftp_parallel_worker_stats *out, int max);

/*
 * Dynamic worker scaling for long-running transfers.
 *
 * sftp_parallel_add_worker() spawns a new independent SSH child, runs
 * sftp_init, and starts a worker thread. Synchronous — returns 0 on
 * success or -1 on failure (capped at SFTP_PARALLEL_MAX_WORKERS,
 * spawn failure, or sftp_init failure).
 *
 * sftp_parallel_remove_worker() submits an exit sentinel; whichever
 * worker pops it next finishes its current unit, sets its exited flag,
 * and terminates. The reporter thread reaps exited workers. Asynchronous
 * — returns 0 if the sentinel was queued (-1 if num_workers <= 1, queue
 * is shut down, etc.). Removal is "any available worker", not targeted
 * — targeted removal requires the in-flight cancel work that's deferred
 * past Phase 1.
 */
/*
 * Hard cap on the number of parallel worker SSH connections per process.
 *
 * This is intentionally a compile-time constant, not a runtime parameter.
 * Client-side rate limiting is advisory by nature — a malicious actor with
 * control of their own system can bypass any client-side check — so the
 * cap exists to prevent accidental self-DoS (e.g. scripts that launch many
 * hpnsftp processes without realising each spawns N workers) rather than
 * to defend against determined abuse.  The correct defence against abusive
 * connection floods is server-side: MaxStartups, MaxSessions, pf/iptables
 * rate limiting, and fail2ban-style tools.
 */
#define SFTP_PARALLEL_MAX_WORKERS 24

int sftp_parallel_add_worker(struct sftp_parallel *p);
int sftp_parallel_remove_worker(struct sftp_parallel *p);

#endif /* _SFTP_PARALLEL_H */
