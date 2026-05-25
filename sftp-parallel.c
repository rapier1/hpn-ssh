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
 * Phase 2 worker fault isolation:
 *
 * sftp-client.c's I/O helpers (send_msg, get_msg_extended) return -1 and set
 * conn->hpn->dead on EOF or write errors rather than calling fatal(). A dead
 * connection propagates up through execute_unit() back to the worker loop,
 * which re-queues the in-flight unit (if under MAX_RETRIES) and then exits.
 *
 * The reporter's watchdog detects dead workers via kill(0) probes and elapsed
 * time since last completion. When a worker is classified DEAD, it sends
 * SIGTERM to the SSH child (to unblock any pending I/O) and sets w->doomed.
 * The reap loop joins the exited worker thread, frees its resources, and
 * spawns a replacement in a detached thread so the SSH handshake doesn't
 * block the reporter's 200ms progress ticks.
 *
 * Remaining Phase 2 work: convert protocol-level fatal()s (request ID
 * mismatch, unexpected packet type) to conn->hpn->dead.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"
#include "utf8.h"
#include "progressmeter.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"

extern int showprogress;

#define WORK_QUEUE_DEPTH(N)     ((size_t)((N) * UPLOAD_BATCH_SIZE * 4 + UPLOAD_BATCH_SIZE))

/* Retry budget per work unit.  Default 3 attempts (initial + 2 retries).
 *
 * Configured via ssh_config HPNMaxRetries (parsed by readconf.c into
 * options.hpn_max_retries, then copied to pcfg->max_retries by
 * sftp-parallel-config.c).  Clamped to [1, 20] at the readconf layer:
 *   - 1 = no retries (one attempt total).  Useful for diagnosing
 *     transient-vs-permanent failures: every failure is final.
 *   - 3 = default.  Covers ordinary network hiccups; doesn't punish
 *     permanent failures (permission denied, disk full) with much
 *     wasted retry time.
 *   - 20 = upper bound.  For demonstrably flaky networks where the
 *     transport layer hasn't yet self-recovered.  Above this the
 *     retry storm itself becomes the load problem.
 */
#define HPN_MAX_RETRIES_DEFAULT 3
#define HPN_MAX_RETRIES_MIN     1
#define HPN_MAX_RETRIES_MAX     20

/* hpn_max_retries() definition is later in this file — struct
 * sftp_parallel is opaque here.  Forward declaration so callers
 * earlier than the struct definition can still resolve the symbol. */
struct sftp_parallel;
static int hpn_max_retries(struct sftp_parallel *p);

#define REPORTER_TICK_MS        200
#define DEFAULT_TRANSFER_BUFLEN 131072	/* 128 KB; matches sftp-client.c */
#define DEFAULT_NUM_REQUESTS    1024	/* 128 KB * 1024 = 128 MB in-flight per stream */

/*
 * Maximum files to pipeline in one open+write+close batch.  Sending N opens
 * before waiting for any handle reduces per-file open overhead from 1 RTT
 * each to 1 RTT total; same for closes.  64 is chosen to keep the burst
 * small enough that SSH channel window pressure is negligible while still
 * amortising RTT cost over a large group of small files.
 */
#define UPLOAD_BATCH_SIZE       64

/*
 * Soft byte cap on the size of a single upload batch.  Once a worker's
 * batch crosses this many bytes it stops grabbing additional units, even
 * if UPLOAD_BATCH_SIZE units have not been collected.  This is a SOFT cap
 * — the first unit is always added to the batch even if its size already
 * exceeds the cap (so a single huge file is never orphaned), and the cap
 * is checked AFTER each addition (so the actual batch may end up larger
 * than the cap by one unit's worth).
 *
 * Without this cap, a worker that finds many medium-to-large files in the
 * queue would grab UPLOAD_BATCH_SIZE of them in one batch.  With four
 * workers and 200x500 MiB files, all 200 files would be claimed in
 * batches of 50 within the first second of the transfer; the queue then
 * sits empty, the scaler has nothing to react to, and end-of-transfer
 * tail dominates throughput as workers drain different-sized piles.
 *
 * 256 MiB is a balance: small enough that workers don't pre-claim large
 * fractions of the workload, large enough that small-file batches still
 * amortise per-batch open/close RTT cost.  Many-small workloads (1 MiB
 * files) hit UPLOAD_BATCH_SIZE first; medium-to-large files hit this
 * byte cap first.
 */
#define UPLOAD_BATCH_BYTE_CAP   ((uint64_t)256 * 1024 * 1024)

/*
 * ── Phase 5: bundle-mode (hpn-bundle@hpnssh.org) tunables ────────────────
 *
 * When a worker has the bundle path enabled (HPNUseBundle yes in
 * ssh_config AND the server advertised hpn-bundle support), the worker
 * collects upload batches up to BUNDLE_TARGET_BYTES instead of
 * UPLOAD_BATCH_BYTE_CAP, then dispatches them as a single tar stream via
 * sftp_hpn_bundle_upload.  The smaller target produces many small bundles
 * that compose well with parallel streams — each worker can have a
 * different bundle in flight, the way each worker has a different batch
 * in flight in the non-bundle path.
 *
 * 4 MiB is a starting point; a server-side fsync after each extract on
 * the bundle close makes very large bundles bad (longer flush before the
 * next OPEN), and very small bundles add tar header overhead.  Override
 * with HPNBundleSize in ssh_config.
 */
#define BUNDLE_TARGET_BYTES     ((uint64_t)4 * 1024 * 1024)

/*
 * Maximum number of failed-path entries the orchestrator retains for
 * the end-of-transfer summary.  Beyond this, the count keeps growing
 * (so the user knows N files failed) but the per-path strings are
 * dropped to bound memory on pathological cases (e.g. permission-
 * denied across a 100k-file tree).  ~25 KiB at the default with
 * typical path lengths.  Touched by hpn_strlist_init in orchestrator
 * init; surfaced by parallel_flush's "Failed paths:" block.
 */
#define HPN_FAILED_PATHS_MAX    100

/* Watchdog thresholds. STALL: warn if a worker has had work available but
 * made no bytes-level progress (bytes_total + live_bytes flat) for this
 * long. DEAD: escalate to SIGTERM. The progress signal is bytes-based
 * (live_bytes climbs continuously during a healthy transfer regardless of
 * unit size), so these thresholds reflect "no client-side bytes pushed
 * in N seconds" rather than "no unit completed in N seconds". Real fatal
 * stalls (born-dead workers, frozen channel windows) still get caught by
 * the 5 s born-dead fast-kill before this threshold fires.
 *
 * 2026-05-21 note: tried 300/600 to tolerate ext4 writeback-stall pauses
 * in whole-file mode and the data showed whole-file parallelism is a
 * net loss on disk-bound paths anyway (worse than single-stream), so we
 * reverted to 60/120 — fine for the configurations we recommend
 * (Lustre/GPFS range-split, or non-stripe range-split at low -j). */
#define STALL_THRESHOLD_SEC     60
#define DEAD_THRESHOLD_SEC      120

/*
 * Number of watchdog ticks (~1 s each) to wait before a worker becomes
 * eligible for throughput-outlier classification.  During this window the
 * worker's EMA is still warming up from its cold-start seed, so any
 * comparison against the peer-max threshold would be unreliable.
 *
 * 5 ticks covers TCP slow-start ramp-up at RTTs up to ~50 ms.  At higher
 * RTTs (100–200 ms) slow-start takes proportionally longer in wall-clock
 * time, but the EMA warmup window still covers it because both the worker's
 * EMA and the threshold EMA are climbing together — neither side is "warm"
 * before the other.
 *
 * NOTE: an alternative approach is to measure the actual per-worker RTT
 * (e.g. via a timed SFTP extension round-trip immediately after sftp_init,
 * or by reading tcpi_rtt from TCP_INFO on the worker's socket) and compute
 * a RTT-proportional grace period.  That would be more accurate on highly
 * variable paths.  The fixed-tick approach is sufficient for the current
 * use case and avoids the complexity of per-worker RTT measurement.
 */
#define TPUT_EMA_WARMUP_TICKS   5

/*
 * Outlier-detection ramp gate.  A worker's tput EMA cannot be fairly
 * compared against the path max until the worker's TCP connection has had
 * time to ramp through slow-start.  Number of RTTs we wait for that ramp
 * before applying the outlier check.  log2(BDP / initial_cwnd) ≈ 7-9 on
 * typical Gbps/50ms paths; doubling that for safety gives ~RAMP_RTTS = 20.
 * Multiplied by the path RTT and peer throughput, this becomes a per-worker
 * "minimum bytes transferred" threshold (see watchdog_sample_throughput).
 *
 * RAMP_WARMUP_BYTES_MIN/MAX clamp the computed threshold so warmup never
 * dips below a useful floor or blows up on a high-BDP path where the EMA
 * may itself be misleading early on.
 */
#define RAMP_RTTS                 20
#define RAMP_WARMUP_BYTES_MIN     (16ULL * 1024 * 1024)    /* 16 MiB */
#define RAMP_WARMUP_BYTES_MAX     (256ULL * 1024 * 1024)   /* 256 MiB */
/*
 * Hard wall-clock cap on the bytes-based warmup gate.  At 30 Mbps a
 * worker needs ~60 s to transfer 256 MiB, so without this cap a
 * genuinely-slow respawned worker stays protected from outlier detection
 * for its entire slow lifetime.  After RAMP_MAX_WARMUP_SEC seconds from
 * unit_start_ns the gate lifts unconditionally — a healthy TCP slow-start
 * always completes in well under this.
 */
#define RAMP_MAX_WARMUP_SEC       15

/*
 * Born-dead fast-kill threshold.  A worker that has popped a unit but
 * has zero progress (bytes_total + live_bytes + units_completed all 0)
 * for this many seconds is killed and respawned.  The server-side path
 * for that SSH session is wedged — usually a Lustre OST stall that
 * froze the SSH channel window.  Waiting the full STALL_THRESHOLD_SEC
 * (60s) or even ISOLATION_PROGRESS_STALL_SEC (15s) wastes capacity:
 * we know after a few seconds that no bytes have arrived, and zero is
 * unambiguous — no peer comparison or EMA warmup needed.
 *
 * Set conservatively: 5 seconds is well above SSH auth completion
 * (~1 RTT after the worker enters the main loop) and the first OPEN
 * round-trip (~1 RTT on a 50ms path).  Anything faster risks killing
 * workers whose first chunk happens to span a slow OST.
 */
#define BORN_DEAD_KILL_SEC        5

/*
 * Born-slow fast-kill threshold.  A worker that has completed at least one
 * unit (so NOT born-dead) but whose EMA throughput is persistently below
 * BORN_SLOW_FLOOR_FRAC × cfg.tput_path_healthy_kbps for BORN_SLOW_TICKS
 * consecutive throughput samples is killed, in the hope that the respawn
 * lands a TCP connection in a better state.
 *
 * Capped globally at BORN_SLOW_MAX_KILLS per orchestrator lifetime: if
 * we've already burned this many respawns chasing slow connections and
 * the path is still slow, additional respawns would just churn — accept
 * the slow path and let remaining workers keep going.
 *
 * Tuning:
 *   BORN_SLOW_TICKS=6        × ~5 s/sample = ~30 s window
 *   BORN_SLOW_FLOOR_FRAC=0.25 below 25% of the configured healthy floor
 *                            (e.g. < 500 kbps when healthy=2000) is "born
 *                            slow" — much lower than legitimate slow paths
 *   BORN_SLOW_MAX_KILLS=5    total respawn budget for born-slow workers
 */
#define BORN_SLOW_TICKS           6
#define BORN_SLOW_FLOOR_FRAC      0.25
#define BORN_SLOW_MAX_KILLS       5

/*
 * Range-split chunk multiplier.  Each large file is split into
 * RANGE_CHUNK_MULTIPLIER × num_workers chunks rather than 1 per worker.
 * Fast workers that finish early pick up additional chunks from the queue,
 * naturally absorbing the tail cost of a slow OST without any detection
 * or respawn machinery.  Ranges align to stripe_size boundaries regardless
 * of this multiplier — no simultaneous OST contention results.
 */
#define RANGE_CHUNK_MULTIPLIER    4

/*
 * Range-split minimum: static default (RANGE_SPLIT_MIN_SIZE_DEFAULT,
 * 2 GiB) overridable via -M on the command line.  Resolved per
 * orchestrator in range_split_min_size_for() below.  See
 * benchmark/range-split-tuning-analysis.md for the empirical sweep that
 * picked 2 GiB and for the formula-driven scheme that preceded it.
 */

/*
 * Isolation progress-rate gate.  When a worker is alone with an in-flight
 * unit (queue empty, no peers transferring) the peer-EMA-based outlier path
 * has no signal to compare against — max_kbps decays to zero as peers go
 * idle, the "path is healthy" gate suppresses outlier escalation, and the
 * worker falls through to the full STALL_THRESHOLD_SEC timeout (60 s) even
 * if it's dribbling at a tiny fraction of expected throughput.
 *
 * ISOLATION_PROGRESS_STALL_SEC is a tighter timeout for that case: when a
 * worker has held a unit for at least this long AND its EMA is below the
 * configured tput_path_healthy_kbps floor, declare DEAD without waiting
 * the full STALL_THRESHOLD_SEC.  Defense-in-depth for the "last worker
 * holding the queue" wedge; the architectural fix (non-blocking
 * sftp_parallel_wait between batch commands) is the cleaner long-term
 * answer because it removes the isolation condition entirely.
 */
#define ISOLATION_PROGRESS_STALL_SEC  15

/*
 * Synchronous-stall observer.  Each reporter slow-tick (~1 s) checks whether
 * aggregate bytes transferred across all workers is zero while at least one
 * worker has a unit in flight — a Lustre/storage writeback-stall signature.
 * SYNC_STALL_WINDOW is the rolling window length in slow-ticks; the stall
 * fraction is logged when the window closes.  Observation-only.
 */
#define SYNC_STALL_WINDOW     20    /* ~20 s window */
#define SYNC_STALL_THRESHOLD  0.20  /* fraction at which the log line warns */

/*
 * Escalation timeout: how long we let a SIGTERMed SSH child clean up before
 * promoting to SIGKILL.  When the receiving TCP socket is hung (the worker's
 * I/O is stalled — exactly when we declare DEAD), SSH's clean-shutdown path
 * tries to send SSH_MSG_DISCONNECT on the same broken socket and blocks
 * indefinitely.  The worker thread is meanwhile blocked reading the ssh
 * child's now-frozen stdout pipe, so it never sets exited=1, so reap (which
 * runs the SIGKILL belt-and-suspenders) never fires.  5 seconds is generous
 * for a healthy SSH disconnect and short enough to keep zombie workers from
 * holding their in-flight unit hostage.
 */
#define SIGKILL_ESCALATION_SEC  5

#define RESPAWN_MULTIPLIER      2  /* epoch ceiling = this * num_streams;
				    * each worker slot gets one retry before
				    * triggering a cooldown pause */
#define RESPAWN_MAX_COOLDOWNS   3  /* cooldown cycles before throughput gate */
#define RESPAWN_COOLDOWN_SEC    30 /* seconds to pause respawning per cooldown */
#define RESPAWN_STABILITY_SEC  300 /* seconds without a new cooldown before the
				    * cooldown count resets; prevents a long-
				    * running transfer from accumulating a fatal
				    * count from churn spread across hours */

enum worker_health {
	WORKER_HEALTHY = 0,
	WORKER_STALLED,
	WORKER_DEAD,
};

enum sftp_op {
	SFTP_OP_UPLOAD,
	SFTP_OP_DOWNLOAD,
	SFTP_OP_MKDIR,
	SFTP_OP_EXIT_WORKER,	/* sentinel for sftp_parallel_remove_worker */
	SFTP_OP_UPLOAD_RANGE,	/* upload a byte range of a large file */
	SFTP_OP_DOWNLOAD_RANGE,	/* download a byte range of a large file */
};

/* ── Per-file range-completion tracker ────────────────────────────────
 *
 * Shared across the N range work units that make up a single
 * SFTP_OP_DOWNLOAD_RANGE or SFTP_OP_UPLOAD_RANGE transfer.  Detects
 * partial-range failure: if even one range gives up permanently after
 * retries, the pre-allocated file is silently corrupt (some range
 * offsets contain the just-written bytes, others contain zeros from
 * the pre-allocation).  Without this tracker the user has no way to
 * know — the file exists at the expected size with no error
 * indicator.
 *
 * Protocol (last-completer-frees):
 *   range_tracker_new returns a heap-allocated tracker with
 *   remaining=total and any_failed=0.  Caller stores its pointer on
 *   each of the N range work units' u->range_tracker field at submit
 *   time.
 *
 *   range_tracker_finalize is called EXACTLY ONCE per range unit on
 *   the unit's FINAL completion — success OR permanent give-up.
 *   NEVER on a retry (the unit isn't done yet).  The function takes
 *   the mutex, sets any_failed on give-up, decrements remaining.
 *   Exactly one caller sees remaining transition to 0; that caller
 *   does the post-mortem cleanup (unlink corrupt file if any_failed,
 *   destroy the mutex, free the tracker) and is the LAST owner.
 *
 *   Other callers see remaining > 0 after their decrement and return
 *   without touching the struct further — by design, they cannot
 *   race with the last completer's cleanup because the mutex was
 *   released before any of them returned.
 *
 * Invariants the caller MUST uphold:
 *
 *   (I1) Exactly `total` finalize calls per tracker, no more, no less.
 *        Over-calling drives remaining negative (undefined: free-after-
 *        free, double-unlink).  Under-calling leaks the tracker AND
 *        leaves the corrupt file in place.
 *
 *   (I2) Finalize fires on FINAL completion only.  On retry, the
 *        unit goes back on the workqueue and finalize must NOT be
 *        called yet — wait until the next attempt resolves.
 *
 *   (I3) After ANY thread's finalize returns 0, that thread must
 *        treat its u->range_tracker pointer as dead — another caller
 *        may have been the last completer in the meantime and freed
 *        the struct.  Don't deref.  (In practice this is automatic:
 *        the work unit itself is freed right after finalize in
 *        worker_process_result / worker_give_up_unit, so the dead
 *        pointer is unreachable.)
 *
 *   (I4) Worker context `w` is required only when target=REMOTE and
 *        any_failed=1 (we need w->conn to sftp_rm the corrupt remote
 *        file).  Pass NULL for LOCAL targets or when no worker
 *        context exists (e.g., synthesised finalize during a submit
 *        failure in submit_*_ranges).
 *
 *   (I5) range_tracker_finalize(NULL, ...) is a no-op.  Non-range
 *        work units have u->range_tracker == NULL; that's the
 *        intended representation.
 *
 * Memory:
 *   - tracker struct itself: xcalloc'd in new, freed by last completer
 *   - t->path: xstrdup'd in new, freed alongside the struct
 *   - t->mu: pthread_mutex_init'd in new, destroyed by last completer
 */
enum sftp_range_target {
	SFTP_RANGE_TARGET_LOCAL,   /* unlink() at finalize */
	SFTP_RANGE_TARGET_REMOTE,  /* sftp_rm()  at finalize via worker conn */
};

struct sftp_range_tracker {
	pthread_mutex_t        mu;         /* serialises decrement + cleanup */
	int                    total;      /* original range count (immutable
					    * after new; for diagnostics) */
	int                    remaining;  /* finalize calls still owed */
	int                    any_failed; /* sticky: 1 if any range failed */
	enum sftp_range_target target;
	char                  *path;       /* local OR remote path of corrupt
					    * file (xstrdup'd in new) */
};

struct sftp_work_unit {
	enum sftp_op op;
	char    *src_path;
	char    *dst_path;
	off_t    size;
	mode_t   mode;
	int      attempt;
	/* Phase 5: set to 1 after a bundle wire failure (server refused open,
	 * mid-stream error).  The worker batch loop refuses to bundle units
	 * with this flag set and dispatches them through the per-file path
	 * instead — so a server-side cap rejection (or any other bundle
	 * wire failure) does not strand the user's files.  Reset only by
	 * re-creation via make_unit on a fresh submit. */
	int      bundle_ineligible;
	/* Range fields: used only for SFTP_OP_UPLOAD_RANGE / DOWNLOAD_RANGE. */
	off_t    range_offset;
	off_t    range_length;
	/* Shared across all range units of one file.  NULL for non-range
	 * units.  See struct sftp_range_tracker above. */
	struct sftp_range_tracker *range_tracker;
};

struct sftp_worker {
	int                id;
	pthread_t          tid;
	struct sftp_parallel *parent;

	pid_t              ssh_pid;
	int                fd_in;
	int                fd_out;
	struct sftp_conn  *conn;

	/* Per-worker progress (mutex-protected for portability across
	 * platforms where 64-bit reads are not naturally atomic). The
	 * reporter snapshots all workers under their respective mutexes;
	 * workers update their own. Contention is negligible — the worker
	 * holds the lock only while bumping counters. */
	pthread_mutex_t    mu;
	uint64_t           bytes_total;
	volatile uint64_t  live_bytes;        /* incremental bytes for current
					       * in-progress file; reset to 0
					       * when file completes */
	uint64_t           units_started;     /* dispatched, may be in flight */
	uint64_t           units_completed;
	uint64_t           units_failed;
	uint64_t           reconnect_count;
	uint64_t           last_completion_ns; /* monotonic ns of last finish */

	/* Adaptive throughput-based stall detection state.  See
	 * cfg.tput_path_healthy_kbps in sftp-parallel.h for the algorithm.
	 * Updated at each watchdog tick. */
	/*
	 * Bytes-based progress signal for the watchdog.  last_progress_ns is
	 * updated by the watchdog every tick that (bytes_total + live_bytes)
	 * increases; the silence threshold (STALL/DEAD) is measured against
	 * this timestamp rather than against last_completion_ns.  Lets us
	 * detect actually-stalled workers without misfiring on long-running
	 * units (a whole-file upload of a multi-GiB file may run for minutes
	 * without a completion event, but live_bytes climbs throughout).
	 *
	 * Only touched by the reporter/watchdog thread — no locking needed.
	 */
	uint64_t           last_progress_ns;
	uint64_t           last_progress_bytes;

	uint64_t           tput_check_bytes;     /* bytes_total at last check */
	uint64_t           tput_check_ns;        /* monotime of last check */
	uint64_t           tput_current_kbps;    /* most recent raw estimate */
	uint64_t           tput_ema_kbps;        /* EMA-smoothed estimate */
	int                tput_ema_warmup_ticks; /* ticks since EMA cold-start */
	int                tput_outlier_ticks;   /* consecutive outlier ticks */
	int                tput_below_floor_ticks; /* consecutive ticks where
	                                          * EMA < BORN_SLOW_FLOOR_FRAC ×
	                                          * cfg.tput_path_healthy_kbps;
	                                          * drives born-slow fast-kill */
	uint64_t           tput_last_unit_start_ns; /* unit_start_ns at last tick;
	                                         * used to detect new-unit starts
	                                         * and reset EMA so stale frozen
	                                         * values don't suppress outlier
	                                         * detection on the new unit */

	uint64_t           idle_ns;            /* ns blocked on workqueue pop,
					        * for completed pops only */
	uint64_t           work_ns;            /* ns actively processing */
	/* Set to monotonic_ns() immediately before each blocking pop call,
	 * cleared to 0 immediately after.  The reporter adds (now -
	 * pop_start_ns) to idle_ns when computing idle fraction so that
	 * an in-progress blocking wait is included even though the pop has
	 * not yet returned.  Written/read with relaxed atomics — a brief
	 * race between clearing and the accounting update causes at most
	 * a single-tick undercount, which is harmless for a 35% threshold. */
	uint64_t           pop_start_ns;
	/* Set to monotonic_ns() when a unit is popped off the workqueue
	 * (after pop_start_ns is cleared), reset to 0 when the unit's
	 * execute_unit returns.  Lets the watchdog measure how long the
	 * worker has been holding its current unit even when
	 * last_completion_ns is still 0 (worker wedged on its very first
	 * unit — last_completion_ns never gets set, so the existing
	 * since_completion_ns gate misses this case).  Atomic ACQUIRE/
	 * RELEASE so the reporter sees a coherent value. */
	uint64_t           unit_start_ns;
	/* ── Worker state lattice ────────────────────────────────────────
	 *
	 * Three orthogonal state machines.  Each flag below tracks ONE of
	 * them; the combinations encode the full worker lifecycle.
	 *
	 * (A) Liveness classification (watchdog-owned, watchdog-written):
	 *       HEALTHY ─→ STALLED ─→ DEAD
	 *     De-escalation (DEAD → HEALTHY) never happens; once the
	 *     watchdog declares DEAD, that worker is doomed and reaped.
	 *     Set by reporter under workers_mu; mostly diagnostic.
	 *
	 * (B) Doom progression (watchdog-owned):
	 *       not_doomed ─→ doomed (SIGTERM sent) ─→ [SIGKILL escalation
	 *                                                if not yet exited]
	 *     The `doomed` flag prevents double-SIGTERM across ticks.
	 *     `doom_ns` is the SIGTERM timestamp, consulted by the
	 *     SIGKILL-escalation deadline.
	 *
	 * (C) Exit lifecycle (worker-owned):
	 *       alive ─→ exited
	 *     Set by the worker thread itself just before pthread_exit;
	 *     read by reporter for pthread_join + reap.  `exited_voluntary`
	 *     distinguishes "removed via EXIT_WORKER sentinel" (no
	 *     replacement spawn) from "died involuntarily — respawn".
	 *
	 * Valid combinations:
	 *   (HEALTHY,  ¬doomed, ¬exited)            — normal running
	 *   (STALLED,  ¬doomed, ¬exited)            — silent but not killed
	 *   (DEAD,      doomed, ¬exited)            — SIGTERMed, awaiting
	 *                                             thread exit
	 *   (DEAD,      doomed,  exited involuntary) — ready to reap +
	 *                                             respawn
	 *   (any,      ¬doomed,  exited voluntary)  — user removed worker;
	 *                                             reap, no respawn
	 *   (DEAD,      doomed,  exited voluntary)  — exited via sentinel
	 *                                             AFTER watchdog
	 *                                             already doomed it
	 *                                             (race; reap, no
	 *                                             respawn — voluntary
	 *                                             wins)
	 *
	 * Brief race window after the watchdog's transition: (DEAD,
	 * ¬doomed, ¬exited) holds for a few lines until SIGTERM is sent;
	 * no other thread observes it (the transition + SIGTERM happen in
	 * the same workers_mu critical section).
	 */
	enum worker_health health;             /* (A) HEALTHY/STALLED/DEAD;
						* set by reporter, read for
						* logging + transition gating */

	int                started;
	int                exited;             /* (C) set by worker on
						* self-exit; read by reporter
						* for reaping */
	int                exited_voluntary;   /* (C) modifier on exited;
						* EXIT_WORKER sentinel only.
						* Suppresses respawn. */
	int                doomed;             /* (B) set by watchdog before
						* SIGTERM; prevents double-kill */
	uint64_t           doom_ns;            /* (B) monotonic ns when
						* SIGTERM was sent; consulted by
						* SIGKILL-escalation deadline when
						* SSH hangs in its clean-shutdown
						* path (worker thread otherwise
						* blocks on unresponsive pipes
						* forever) */

	/* ── Phase 4 gap 1: pipelined-batch state ────────────────────
	 * The previous batch's phase-5 (CLOSE-collection) is deferred
	 * across the call to sftp_upload_batch_send for the NEXT batch.
	 * These fields hold the carry-over state.  Set during a
	 * pipelined send call, cleared by worker_drain_pipeline().
	 * All NULL/0 means "no deferred batch in flight." */
	struct sftp_upload_batch_pending *batch_prev_pending;
	struct sftp_work_unit           **batch_prev_units;
	struct sftp_upload_batch_entry   *batch_prev_entries;
	int                               batch_prev_n;
	int                               batch_pipe_disabled; /* per-worker
	                                                        * HPN_NO_BATCH_PIPELINE */

	/* ── Phase 5: bundle-mode state (hpn-bundle@hpnssh.org) ─────
	 * bundle_enabled is set once at worker startup when
	 *   ssh_config HPNUseBundle yes (the default) AND
	 *   sftp_conn_has_hpn_bundle(w->conn) is true.
	 * When set, the worker collects upload batches to bundle_target_bytes
	 * and dispatches them via sftp_hpn_bundle_upload instead of
	 * sftp_upload_batch / sftp_upload_batch_send.  No interaction with
	 * the pipelined-batch state above — bundle and pipelined paths are
	 * mutually exclusive per worker. */
	int      bundle_enabled;
	uint64_t bundle_target_bytes;
};

/*
 * Bounded thread-safe string list.  Append-only with a hard cap; the
 * `total` counter keeps growing past the cap so callers can report
 * "showing first N of TOTAL".  Drain transfers ownership of the held
 * strings to the caller.
 *
 * Failures (and other rare events we accumulate) are infrequent enough
 * that the per-append mutex acquire is uncontended in practice.  The
 * cap bounds memory on pathological inputs (e.g. a permission-denied
 * walk over a 100k-file tree) without losing the overall count.
 *
 * Generic shape so future "things-the-user-needs-to-see" accumulators
 * can reuse it without inventing a parallel struct.
 */
struct hpn_strlist {
	pthread_mutex_t  mu;
	char           **items;     /* xstrdup'd entries; NULL until init */
	size_t           used;      /* entries actually held */
	size_t           cap;       /* array capacity */
	uint64_t         total;     /* total appends seen (may exceed cap) */
};

struct sftp_parallel {
	struct sftp_parallel_config cfg;
	char                        cfg_port_buf[16]; /* owns cfg.port string */
	struct sftp_workqueue      *q;

	/* Workers held as an array of pointers so add/remove can mutate
	 * the array without invalidating pointers held by worker threads
	 * via w->parent->workers[...]. workers_mu serializes structural
	 * changes (add/remove/reap); the per-worker mu still serializes
	 * counter updates. Lock ordering: workers_mu BEFORE w->mu. */
	pthread_mutex_t             workers_mu;
	struct sftp_worker        **workers;
	int                         num_workers;
	int                         workers_cap;
	int                         next_worker_id;
	int                         pending_respawns; /* detached respawn threads
						       * not yet in workers[];
						       * guards premature abort */
	int                         total_respawns;  /* lifetime respawn count */
	uint64_t                    session_start_ns;  /* monotonic_ns() at
						       * sftp_parallel_start;
						       * elapsed surfaced in
						       * stats for the
						       * end-of-transfer
						       * summary */
	int                         respawn_epoch_count;   /* respawns in current
							    * epoch; reset when a
							    * cooldown ends */
	int                         respawn_cooldown_count; /* cooldown cycles used
							    * this stability window */
	uint64_t                    respawn_resume_ns;  /* monotonic ns when
							* cooldown ends; 0 = not
							* in cooldown */
	uint64_t                    respawn_last_cooldown_ns; /* when last cooldown
							       * was entered; drives
							       * stability timer */
	uint64_t                    tput_last_raw_max_kbps;  /* freshest raw max
							       * from watchdog; used
							       * by throughput gate */
	int                         respawn_owed;  /* involuntary deaths reaped
						    * but not yet replaced; carries
						    * across cooldowns + pthread
						    * failures so a long-lived
						    * transfer doesn't drift below
						    * num_streams over time */
	int                         protocol_violations; /* under workers_mu;
						       * abort if any non-zero;
						       * exposed via stats for
						       * post-mortem inspection */

	/* Files the walker dropped before they could become work units
	 * (stat() failed, symlink resolution failed, etc.).  These are NOT
	 * worker failures — they happen on the main thread inside the
	 * recursive walkers (sftp-parallel-walk.c) — so they aren't
	 * captured by per-worker units_failed.  parallel_flush surfaces
	 * this so the user can't mistake a non-zero walker-loss for a
	 * clean transfer.  Bumped via __atomic_fetch_add from any thread.
	 */
	uint64_t                    walker_failures;

	/* Bounded list of paths that could not be delivered, populated at
	 * every give-up site (worker MAX_RETRIES, workqueue push-fail,
	 * walker skip-on-error).  Surfaced inline in parallel_flush's
	 * TRANSFER INCOMPLETE message so users don't have to grep a
	 * potentially huge log for per-file errors.  Uses the reusable
	 * hpn_strlist below — same shape for any future "things-the-user-
	 * needs-to-see" accumulation across threads. */
	struct hpn_strlist          failed_paths;

	pthread_t                   reporter_tid;
	int                         reporter_started;

	/* Pending counter for sftp_parallel_wait. */
	pthread_mutex_t             pending_mu;
	pthread_cond_t              pending_cv;
	uint64_t                    pending;

	/*
	 * Sum of u->size across units currently in the workqueue (waiting to
	 * be popped — does NOT include in-flight work being processed by a
	 * worker).  Updated atomically by submit/pop sites.  Brief overcounts
	 * are possible during the gap between increment and queue push (or
	 * decrement and queue pop), but never undercounts — the order of
	 * operations ensures the counter leads the queue state.
	 *
	 * Originally driven by the adaptive scaler (removed 2026-05-20); kept
	 * because the watchdog still uses it to distinguish "worker stalled
	 * with work pending" from "worker idle, queue empty."
	 */
	volatile uint64_t           queued_bytes;

	/*
	 * Bytes carried by workers that have exited (fault / shutdown).
	 * snapshot_workers iterates only the live workers[] array, so an
	 * exiting worker would otherwise erase its bytes_total from the
	 * aggregate.  Captured under workers_mu just before the worker is
	 * removed from the array; read by snapshot_workers under the same
	 * lock.  Keeps aggregate_bytes_for_meter monotonic.
	 */
	uint64_t                    retired_bytes;

	/*
	 * Cached result of sftp_fs_info() on the destination filesystem.
	 * Without caching, the walker queries fs-info synchronously on the
	 * control connection for every large file — at high RTT this stalls
	 * the walker and prevents queued_bytes from rising fast enough for
	 * the scale-up trigger to fire while there is still work to do.
	 * Updated by submit_upload_maybe_split on the first invocation; read by
	 * subsequent invocations.  Single-threaded access (the walker is the
	 * only caller path that uses this).
	 */
	int                         fs_info_cached;
	struct sftp_fs_info         fs_info_cache;

	/* Set by sftp_parallel_abort, read by workers between units. */
	volatile sig_atomic_t       abort_flag;

	/* Optional pointer to caller's interrupt flag (e.g. sftp.c's
	 * `interrupted`).  When non-NULL, the reporter thread calls
	 * sftp_parallel_abort() as soon as *ext_interrupt_flag becomes
	 * non-zero, which wakes sftp_parallel_wait() within one reporter
	 * tick (~200ms) rather than waiting for workers to finish naturally. */
	volatile sig_atomic_t      *ext_interrupt_flag;

	/*
	 * App-layer RTT measured on the control connection at startup
	 * (microseconds; 0 = not measured).  Used to size the per-worker
	 * outlier-detection warmup so newly-respawned workers in TCP
	 * slow-start aren't killed before their cwnd has had ~RAMP_RTTS
	 * round-trips to ramp.  Set once via sftp_parallel_set_path_rtt;
	 * read by the reporter thread.
	 */
	uint64_t                    path_rtt_us;

	int                         saved_showprogress;
	int                         progress_meter_started;
	uint64_t                    aggregate_bytes_for_meter;
	uint64_t                    progress_bytes_baseline;    /* bytes already
								   * done when meter
								   * started; delta
								   * gives this-xfer */
	off_t                       aggregate_progress_counter; /* meter ctr */
	char                        progress_label[128];        /* stable storage
								   * for the meter
								   * label string */

	int                         started;
	int                         stopped;

	/*
	 * Synchronous-stall detector state.  Touched only by the reporter's
	 * slow-tick path (no lock needed).
	 */
	uint32_t sync_stall_ticks;      /* stall slow-ticks in current window */
	uint32_t sync_stall_window_pos; /* slow-ticks elapsed in current window */
	uint64_t sync_stall_prev_bytes; /* aggregate bytes at previous slow-tick */

	/* Born-slow respawn budget.  Total count of workers killed because
	 * their EMA throughput stayed below the floor for the configured
	 * window.  Capped at BORN_SLOW_MAX_KILLS to prevent runaway respawn
	 * churn on a path that's genuinely slow.  Set in the watchdog. */
	int      born_slow_kills;

	/* Optional per-worker stats CSV (enabled via HPN_WORKER_STATS_CSV env).
	 * Opened lazily by the reporter on first tick; closed at orchestrator
	 * stop.  Touched only by the reporter thread. */
	FILE    *stats_csv;
	uint64_t stats_csv_start_ns;
};

/* ---------- Worker SSH connection setup ---------- */

static int
spawn_worker_ssh(const struct sftp_parallel_config *cfg,
    int *fd_in_out, int *fd_out_out, pid_t *pid_out)
{
	int p2c[2] = { -1, -1 }, c2p[2] = { -1, -1 };
	char user_host[512];
	char kh_opt[PATH_MAX + 32];

	const char *ssh_bin = cfg->ssh_binary ? cfg->ssh_binary : "hpnssh";

	if (cfg->user && cfg->user[0])
		snprintf(user_host, sizeof(user_host), "%s@%s",
		    cfg->user, cfg->host);
	else
		strlcpy(user_host, cfg->host, sizeof(user_host));

	if (pipe(p2c) < 0)
		return -1;
	FD_CLOSEONEXEC(p2c[0]); FD_CLOSEONEXEC(p2c[1]);
	if (pipe(c2p) < 0) {
		close(p2c[0]); close(p2c[1]);
		return -1;
	}
	FD_CLOSEONEXEC(c2p[0]); FD_CLOSEONEXEC(c2p[1]);
	pid_t pid = fork();
	if (pid < 0) {
		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(p2c[0], STDIN_FILENO);
		dup2(c2p[1], STDOUT_FILENO);

		/*
		 * Redirect this SSH child's stderr to a per-child log file
		 * so we can post-mortem failed handshakes that would
		 * otherwise vanish into the orchestrator's interleaved
		 * stderr stream.  Path is /tmp/hpnssh-worker-PID.stderr;
		 * the child's PID becomes part of the SSH child's command
		 * line so it's easy to correlate.  Best-effort: if open
		 * fails for any reason, fall through to inherited stderr
		 * (current behaviour).
		 */
		{
			char path[64];
			int fd;
			snprintf(path, sizeof(path),
			    "/tmp/hpnssh-worker-%d.stderr", (int)getpid());
			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd >= 0) {
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}

		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);

		/* Build argv for an independent (non-mux) SSH connection. */
		char *argv[40];
		int argc = 0;
		argv[argc++] = (char *)ssh_bin;
		argv[argc++] = "-oBatchMode=yes";
		argv[argc++] = "-oControlMaster=no";
		argv[argc++] = "-oControlPath=none";
		argv[argc++] = "-oStrictHostKeyChecking=accept-new";
		/*
		 * Per-child verbose output for respawn diagnostics. Routed
		 * to /tmp/hpnssh-worker-PID.stderr by the dup2() above, so
		 * it does not pollute the orchestrator's stdout/stderr.
		 * HPNSSH_WORKER_VERBOSE controls level: 1=-v, 2=-vv, 3=-vvv.
		 * Default 0 (off); set to 1 or higher to capture worker SSH
		 * debug output when diagnosing connection or respawn failures.
		 */
		{
			/* ENV-VAR HPNSSH_WORKER_VERBOSE — developer-only:
			 * inject -v / -vv / -vvv into worker hpnssh invocations
			 * for debugging.  Not user-facing. */
			const char *e = getenv("HPNSSH_WORKER_VERBOSE");
			int lvl = (e && *e) ? atoi(e) : 0;
			if (lvl >= 1) argv[argc++] = "-v";
			if (lvl >= 2) argv[argc++] = "-vv";
			if (lvl >= 3) argv[argc++] = "-vvv";
		}
		if (cfg->port && cfg->port[0]) {
			argv[argc++] = "-p";
			argv[argc++] = (char *)cfg->port;
		}
		if (cfg->identity) {
			argv[argc++] = "-i";
			argv[argc++] = (char *)cfg->identity;
		}
		if (cfg->config_file) {
			argv[argc++] = "-F";
			argv[argc++] = (char *)cfg->config_file;
		}
		if (cfg->known_hosts) {
			snprintf(kh_opt, sizeof(kh_opt),
			    "UserKnownHostsFile=%s", cfg->known_hosts);
			argv[argc++] = "-o";
			argv[argc++] = kh_opt;
		}
		if (cfg->extra_argv) {
			for (int i = 0;
			    cfg->extra_argv[i] != NULL && argc < 35; i++) {
				argv[argc++] = "-o";
				argv[argc++] = cfg->extra_argv[i];
			}
		}
		argv[argc++] = "-s";
		argv[argc++] = user_host;
		argv[argc++] = "sftp";
		argv[argc]   = NULL;

		execvp(ssh_bin, argv);
		_exit(127);
	}
	close(p2c[0]);
	close(c2p[1]);
	*fd_in_out  = c2p[0];
	*fd_out_out = p2c[1];
	*pid_out    = pid;
	return 0;
}

static void
teardown_worker_ssh(struct sftp_worker *w)
{
	if (w->fd_in >= 0)  { close(w->fd_in);  w->fd_in = -1; }
	if (w->fd_out >= 0) { close(w->fd_out); w->fd_out = -1; }
	if (w->ssh_pid > 0) {
		int status;
		(void)waitpid(w->ssh_pid, &status, 0);
		w->ssh_pid = -1;
	}
}

/* ---------- Work units ---------- */

static struct sftp_work_unit *
make_unit(enum sftp_op op, const char *src, const char *dst,
    off_t size, mode_t mode)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op = op;
	u->src_path = src ? xstrdup(src) : NULL;
	u->dst_path = dst ? xstrdup(dst) : NULL;
	u->size = size;
	u->mode = mode;
	return u;
}

static struct sftp_work_unit *
make_range_unit(const char *src, const char *dst,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op            = SFTP_OP_UPLOAD_RANGE;
	u->src_path      = xstrdup(src);
	u->dst_path      = xstrdup(dst);
	u->size          = range_length;
	u->range_offset  = range_offset;
	u->range_length  = range_length;
	u->range_tracker = tracker;
	return u;
}

static void
free_unit(struct sftp_work_unit *u)
{
	if (u == NULL) return;
	free(u->src_path);
	free(u->dst_path);
	/* range_tracker is shared across sibling range units; never freed
	 * by free_unit.  See range_tracker_finalize for ownership rules. */
	free(u);
}

/* Forward decl — hpn_strlist_append is defined below this point but
 * sftp_parallel_walker_record_failure (defined here) needs it.  Avoids reordering
 * the file. */
static void hpn_strlist_append(struct hpn_strlist *l, const char *s);

/*
 * Worker-side failed-path recorder.  Formats "path: cause" and appends
 * to the orchestrator's failed-paths list.  If `explicit_cause` is
 * NULL we pull from hpn_get_last_error() — the TLS-captured most-
 * recent ERROR-level log message on this thread, set automatically
 * inside do_log().  This is how a failed sftp_upload / sftp_download
 * gets its error text into the summary without any plumbing through
 * the RPC API.
 *
 * Falls back to "(no error captured)" when neither source has a
 * message — shouldn't happen in practice for a real give-up.
 *
 * Called only at give-up sites in worker_process_result and
 * worker_finalize_one_entry (NOT on retry).
 */
static void
worker_record_failed_path(struct sftp_parallel *p,
    struct sftp_work_unit *u, const char *explicit_cause)
{
	char        buf[PATH_MAX + 256];
	const char *path = (u && u->src_path) ? u->src_path : "(unknown)";
	const char *cause;

	if (explicit_cause != NULL && *explicit_cause != '\0') {
		cause = explicit_cause;
	} else {
		const char *captured = hpn_get_last_error();
		cause = (captured && *captured)
		    ? captured : "(no error captured)";
	}

	snprintf(buf, sizeof(buf), "%s: %s", path, cause);
	hpn_strlist_append(&p->failed_paths, buf);

	/* Reset so the next failure on this thread starts clean instead
	 * of stale.  Captured-error contract: it reflects the most recent
	 * error AT THE TIME we record the failure. */
	hpn_clear_last_error();
}

/*
 * Walker-side failure recorder: bumps the aggregate counter and adds
 * "path: error" to the failed-paths list in one shot.  `err` may be
 * NULL when no errno-style message is available (e.g. depth limit,
 * "not a directory").  Single-call helper because every walker
 * skip-on-error site does both — bump + list.
 *
 * Public (declared in sftp-parallel.h) so the walkers in
 * sftp-parallel-walk.c can call it without seeing struct
 * sftp_parallel's internals.
 */
void
sftp_parallel_walker_record_failure(struct sftp_parallel *p, const char *path,
    const char *err)
{
	char buf[PATH_MAX + 256];

	__atomic_fetch_add(&p->walker_failures, 1, __ATOMIC_RELAXED);
	if (path == NULL)
		path = "(unknown)";
	if (err != NULL && *err != '\0')
		snprintf(buf, sizeof(buf), "%s: %s", path, err);
	else
		snprintf(buf, sizeof(buf), "%s", path);
	hpn_strlist_append(&p->failed_paths, buf);
}

/*
 * Bounded thread-safe string list — see comment on struct hpn_strlist.
 */
static void
hpn_strlist_init(struct hpn_strlist *l, size_t cap)
{
	pthread_mutex_init(&l->mu, NULL);
	l->cap   = cap;
	l->used  = 0;
	l->total = 0;
	l->items = (cap > 0) ? xcalloc(cap, sizeof(*l->items)) : NULL;
}

static void
hpn_strlist_free(struct hpn_strlist *l)
{
	if (l->items != NULL) {
		for (size_t i = 0; i < l->used; i++)
			free(l->items[i]);
		free(l->items);
		l->items = NULL;
	}
	pthread_mutex_destroy(&l->mu);
	l->used = 0;
	l->cap  = 0;
}

/*
 * Append `s` to the list.  Always bumps `total`; only allocates a
 * new entry if `used < cap`.  Silently drops the string contents when
 * over cap so memory stays bounded; the count is preserved so the
 * user knows how many were dropped.
 */
static void
hpn_strlist_append(struct hpn_strlist *l, const char *s)
{
	if (l == NULL || s == NULL)
		return;
	pthread_mutex_lock(&l->mu);
	l->total++;
	if (l->used < l->cap)
		l->items[l->used++] = xstrdup(s);
	pthread_mutex_unlock(&l->mu);
}

/*
 * Drain the list.  Returns the total append count seen, and (when
 * `out` is non-NULL) transfers ownership of the held strings to the
 * caller via *out / *out_used.  The list itself is reset to empty
 * but remains usable for further appends.  Caller frees each string
 * and the array.
 */
static uint64_t
hpn_strlist_drain(struct hpn_strlist *l, char ***out, size_t *out_used)
{
	uint64_t total;
	pthread_mutex_lock(&l->mu);
	total = l->total;
	if (out != NULL && out_used != NULL) {
		*out_used = l->used;
		if (l->used > 0) {
			*out = xcalloc(l->used, sizeof(**out));
			for (size_t i = 0; i < l->used; i++)
				(*out)[i] = l->items[i];   /* transfer ownership */
		} else {
			*out = NULL;
		}
	}
	/* Reset the list so subsequent appends start fresh. */
	if (l->items != NULL)
		memset(l->items, 0, l->cap * sizeof(*l->items));
	l->used  = 0;
	l->total = 0;
	pthread_mutex_unlock(&l->mu);
	return total;
}

/*
 * Range-completion tracker constructor.  Allocated once per range-split
 * transfer (download by submit_download_ranges, upload by
 * submit_upload_ranges) and attached to each of the N range work units
 * it creates.  Lives until the last range completes; that completer
 * frees the tracker.
 */
static struct sftp_range_tracker *
range_tracker_new(int total, enum sftp_range_target target, const char *path)
{
	struct sftp_range_tracker *t = xcalloc(1, sizeof(*t));
	pthread_mutex_init(&t->mu, NULL);
	t->total      = total;
	t->remaining  = total;
	t->any_failed = 0;
	t->target     = target;
	t->path       = xstrdup(path);
	return t;
}

/*
 * One range's final completion: `failed` = 1 on permanent give-up
 * (after MAX_RETRIES) or 0 on success.  Must be called exactly once
 * per range unit, on its final outcome only — see invariants (I1)
 * and (I2) at struct sftp_range_tracker.
 *
 * `w` is the worker reporting completion; used only for sftp_rm on
 * REMOTE-target trackers when the corrupt-file cleanup fires.  May
 * be NULL otherwise (I4).
 *
 * Returns 1 if THIS call was the last-completer AND any range
 * failed (informational — the cleanup happened inside this call
 * regardless).  Returns 0 otherwise.
 *
 * Tracker is freed when remaining hits 0; callers that saw a 0
 * return value have a dead pointer and must not deref it (I3).
 *
 * No-op on NULL t (I5).
 */
static int
range_tracker_finalize(struct sftp_range_tracker *t, int failed,
    struct sftp_worker *w)
{
	int was_last, should_remove;

	if (t == NULL)
		return 0;

	pthread_mutex_lock(&t->mu);
	if (failed)
		t->any_failed = 1;
	t->remaining--;
	was_last      = (t->remaining == 0);
	should_remove = was_last && t->any_failed;
	pthread_mutex_unlock(&t->mu);

	if (!was_last)
		return 0;

	if (should_remove) {
		if (t->target == SFTP_RANGE_TARGET_LOCAL) {
			if (unlink(t->path) == 0) {
				error("range-split: unlinked corrupt local "
				    "file \"%s\" — at least one range failed "
				    "permanently after retries", t->path);
			} else {
				error("range-split: local file \"%s\" is "
				    "corrupt (partial range failure) but "
				    "unlink failed: %s",
				    t->path, strerror(errno));
			}
		} else {
			/* REMOTE: need an SFTP connection to remove.  If the
			 * caller didn't supply a worker (shouldn't happen for
			 * upload-range), the corrupt remote file stays — log
			 * loudly so the user knows. */
			if (w != NULL && w->conn != NULL &&
			    sftp_rm(w->conn, t->path) == 0) {
				error("range-split: removed corrupt remote "
				    "file \"%s\" — at least one range failed "
				    "permanently after retries", t->path);
			} else {
				error("range-split: remote file \"%s\" is "
				    "corrupt (partial range failure); remove "
				    "FAILED — user must clean up manually",
				    t->path);
			}
		}
	}
	pthread_mutex_destroy(&t->mu);
	free(t->path);
	free(t);
	return should_remove;
}

/* ---------- Worker thread ---------- */

static uint64_t
monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void
worker_record_start(struct sftp_worker *w)
{
	pthread_mutex_lock(&w->mu);
	w->units_started++;
	pthread_mutex_unlock(&w->mu);
}

/*
 * Resolve the effective per-unit retry budget.  See the comment at the
 * HPN_MAX_RETRIES_* defines near the top of this file for the full
 * policy.  Definition lives here because struct sftp_parallel is
 * opaque earlier in the file; the forward decl appears alongside the
 * defines.
 */
static int
hpn_max_retries(struct sftp_parallel *p)
{
	if (p != NULL &&
	    p->cfg.max_retries >= HPN_MAX_RETRIES_MIN &&
	    p->cfg.max_retries <= HPN_MAX_RETRIES_MAX)
		return p->cfg.max_retries;
	return HPN_MAX_RETRIES_DEFAULT;
}

static void
worker_record_completion(struct sftp_worker *w, off_t bytes, int success)
{
	pthread_mutex_lock(&w->mu);
	if (success) {
		w->bytes_total += (uint64_t)bytes;
		w->units_completed++;
	} else {
		w->units_failed++;
	}
	/* Reset live_bytes so the completed file's bytes aren't counted twice
	 * (once here in bytes_total and once via the live_counter hook). */
	__atomic_store_n(&w->live_bytes, 0, __ATOMIC_RELAXED);
	w->last_completion_ns = monotonic_ns();
	pthread_mutex_unlock(&w->mu);
}

/*
 * Pending-counter trace: enabled when SFTP_PENDING_TRACE=1 in the
 * environment.  Writes one line per inc/dec to stderr so we can pair
 * them post-run and find any leaks.  Cheap when disabled.
 */
static int pending_trace_enabled = -1;
static int
pending_trace_on(void)
{
	if (pending_trace_enabled < 0) {
		/* ENV-VAR SFTP_PENDING_TRACE — developer-only: enable verbose
		 * pending-counter trace logging for debugging work-unit
		 * lifecycle issues.  Not user-facing. */
		const char *e = getenv("SFTP_PENDING_TRACE");
		pending_trace_enabled = (e && e[0] == '1') ? 1 : 0;
	}
	return pending_trace_enabled;
}

static void
pending_trace(const char *action, struct sftp_parallel *p,
    const struct sftp_work_unit *u, int worker_id, const char *site)
{
	if (!pending_trace_on())
		return;
	const char *src = (u && u->src_path) ? u->src_path : "(null)";
	const char *dst = (u && u->dst_path) ? u->dst_path : "(null)";
	int op = u ? (int)u->op : -1;
	logit_f("PTRACE %s pending=%llu op=%d u=%p w=%d site=%s src=%s dst=%s",
	    action, (unsigned long long)p->pending, op, (const void *)u,
	    worker_id, site, src, dst);
}

static void
pending_dec(struct sftp_parallel *p)
{
	pthread_mutex_lock(&p->pending_mu);
	if (p->pending > 0)
		p->pending--;
	if (p->pending == 0)
		pthread_cond_broadcast(&p->pending_cv);
	pthread_mutex_unlock(&p->pending_mu);
}

/* Traced variant: pass the unit and a call-site label so the trace can
 * pair each dec with the corresponding inc.  Production callers should
 * use the macro PENDING_DEC defined below, which expands to the traced
 * variant when pending_trace_on(). */
static void
pending_dec_traced(struct sftp_parallel *p, const struct sftp_work_unit *u,
    int worker_id, const char *site)
{
	if (pending_trace_on())
		pending_trace("DEC", p, u, worker_id, site);
	pending_dec(p);
}

static int
execute_unit(struct sftp_worker *w, struct sftp_work_unit *u)
{
	struct sftp_parallel *p = w->parent;
	int rc = -1;

	switch (u->op) {
	case SFTP_OP_UPLOAD:
		rc = sftp_upload(w->conn, u->src_path, u->dst_path,
		    p->cfg.preserve_flag, /*resume=*/0,
		    p->cfg.fsync_flag, p->cfg.inplace_flag);
		break;
	case SFTP_OP_UPLOAD_RANGE:
		rc = sftp_upload_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length);
		break;
	case SFTP_OP_DOWNLOAD_RANGE:
		rc = sftp_download_range(w->conn, u->src_path, u->dst_path,
		    u->range_offset, u->range_length);
		break;
	case SFTP_OP_DOWNLOAD:
		rc = sftp_download(w->conn, u->src_path, u->dst_path,
		    /*Attrib*/NULL, p->cfg.preserve_flag,
		    p->cfg.resume_flag, p->cfg.fsync_flag,
		    p->cfg.inplace_flag);
		break;
	case SFTP_OP_MKDIR:
		rc = sftp_mkdir(w->conn, u->dst_path, NULL, /*print_flag=*/0);
		break;
	case SFTP_OP_EXIT_WORKER:
		/* Intercepted in worker_thread before reaching here. */
		rc = 0;
		break;
	}
	return rc;
}

/*
 * Permanent give-up of a work unit after MAX_RETRIES.  Snapshots the
 * cause from the TLS-captured most-recent ERROR log BEFORE the give-up
 * log clobbers it, then does all the bookkeeping in one place:
 *   - log give-up at error level
 *   - record per-worker completion as failure
 *   - decrement orchestrator pending counter
 *   - finalize range tracker (NULL-safe; only meaningful for range units)
 *   - append path + cause to failed-paths list
 *   - free the unit
 *
 * `log_prefix` distinguishes the caller in the give-up log ("unit" for
 * single-unit dispatch, "batch unit" for pipelined-batch).  `trace_tag`
 * is the pending-trace tag string.
 */
static void
worker_give_up_unit(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, const char *log_prefix,
    const char *trace_tag)
{
	char        cause[256];
	const char *captured = hpn_get_last_error();

	strlcpy(cause,
	    (captured && *captured) ? captured : "(no error captured)",
	    sizeof(cause));

	error_f("worker %d: %s failed after %d attempts: %s",
	    w->id, log_prefix, u->attempt,
	    u->src_path ? u->src_path : "(null)");
	worker_record_completion(w, 0, 0);
	pending_dec_traced(p, u, w->id, trace_tag);
	(void)range_tracker_finalize(u->range_tracker, 1, w);
	worker_record_failed_path(p, u, cause);
	free_unit(u);
}

/*
 * Push-fail give-up: the workqueue refused our retry submission
 * (shutdown in progress), so this unit can never run.  Same bookkeeping
 * as worker_give_up_unit but with an explicit cause string ("queue
 * shutdown") and no give-up log line — the push-fail itself is the
 * diagnostic.
 *
 * Caller must have already failed sftp_workqueue_push BEFORE calling
 * this; we just clean up.
 */
static void
worker_give_up_pushfail(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, const char *trace_tag)
{
	if (u->size > 0)
		__atomic_fetch_sub(&p->queued_bytes,
		    (uint64_t)u->size, __ATOMIC_RELAXED);
	worker_record_completion(w, 0, 0);
	pending_dec_traced(p, u, w->id, trace_tag);
	(void)range_tracker_finalize(u->range_tracker, 1, w);
	worker_record_failed_path(p, u, "queue shutdown");
	free_unit(u);
}

/* Handle the result of executing a single work unit (retry or completion). */
static void
worker_process_result(struct sftp_worker *w, struct sftp_work_unit *u, int rc)
{
	struct sftp_parallel *p = w->parent;

	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		pending_dec_traced(p, u, w->id, "wpr/success");
		/* Range tracker: this range finished cleanly.  Last
		 * completer for the file frees the tracker. */
		(void)range_tracker_finalize(u->range_tracker, 0, w);
		free_unit(u);
	} else if (++u->attempt < hpn_max_retries(p)) {
		/* Re-queue without freeing. Keeps pending counter consistent. */
		if (u->size > 0)
			__atomic_fetch_add(&p->queued_bytes,
			    (uint64_t)u->size, __ATOMIC_RELAXED);
		if (pending_trace_on())
			pending_trace("REQUEUE", p, u, w->id, "wpr/retry");
		if (sftp_workqueue_push(p->q, u) != 0)
			worker_give_up_pushfail(p, w, u, "wpr/pushfail");
	} else {
		worker_give_up_unit(p, w, u, "unit", "wpr/maxretries");
	}
}

/* ── BEGIN Phase 4 gap 1: pipelined-batch helpers ─────────────────────────
 *
 * Three helpers manage the deferred phase-5 state across worker_thread
 * iterations:
 *
 *   worker_finalize_one_entry
 *     Records the result of a single batch entry: success → completion;
 *     failure → retry (re-queue) or maximum-retries-give-up.  Mirrors the
 *     existing inline result loop in worker_thread.
 *
 *   worker_drain_pipeline
 *     Calls sftp_upload_batch_finish on the carry-over prev batch (if
 *     any), processes per-entry results, frees the heap arrays.  Called
 *     before handling any non-batch work and at worker_thread exit.
 *
 *   worker_run_batch_pipelined
 *     Replaces the synchronous sftp_upload_batch() call.  Allocates heap
 *     entry/unit arrays so they survive across the next iteration, calls
 *     sftp_upload_batch_send (which drains prev as part of its phase 1),
 *     finalises prev (if there was one), then saves THIS batch as the
 *     new prev.  On send failure, finalises this batch inline (no carry).
 *
 * HPN_NO_BATCH_PIPELINE=1 in the environment disables the pipelining at
 * worker startup; the worker falls back to the legacy sftp_upload_batch
 * call.  Useful for A/B testing and for bisecting regressions without a
 * rebuild.
 * ──────────────────────────────────────────────────────────────────────── */

static void
worker_finalize_one_entry(struct sftp_parallel *p, struct sftp_worker *w,
    struct sftp_work_unit *u, int rc)
{
	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		pending_dec_traced(p, u, w->id, "batch/success");
		free_unit(u);
		return;
	}
	if (++u->attempt < hpn_max_retries(p)) {
		__atomic_store_n(&w->live_bytes, 0, __ATOMIC_RELAXED);
		if (u->size > 0)
			__atomic_fetch_add(&p->queued_bytes,
			    (uint64_t)u->size, __ATOMIC_RELAXED);
		if (pending_trace_on())
			pending_trace("REQUEUE", p, u, w->id, "batch/retry");
		if (sftp_workqueue_push(p->q, u) != 0)
			worker_give_up_pushfail(p, w, u, "batch/pushfail");
		return;
	}
	worker_give_up_unit(p, w, u, "batch unit", "batch/maxretries");
}

static void
worker_drain_pipeline(struct sftp_worker *w)
{
	struct sftp_parallel *p = w->parent;
	if (w->batch_prev_pending == NULL)
		return;
	(void)sftp_upload_batch_finish(w->conn, w->batch_prev_pending);
	for (int i = 0; i < w->batch_prev_n; i++)
		worker_finalize_one_entry(p, w,
		    w->batch_prev_units[i],
		    w->batch_prev_entries[i].result);
	free(w->batch_prev_units);
	free(w->batch_prev_entries);
	w->batch_prev_pending = NULL;
	w->batch_prev_units   = NULL;
	w->batch_prev_entries = NULL;
	w->batch_prev_n       = 0;
}

static void
worker_run_batch_pipelined(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_upload_batch_entry *entries;
	struct sftp_work_unit **units;
	struct sftp_upload_batch_pending *new_pending;

	if (w->batch_pipe_disabled) {
		/* Legacy un-pipelined path — kept verbatim from the
		 * pre-Phase-4 implementation for A/B comparison. */
		struct sftp_upload_batch_entry stack_entries[UPLOAD_BATCH_SIZE];
		for (int i = 0; i < bn; i++) {
			stack_entries[i].local_path  = batch[i]->src_path;
			stack_entries[i].remote_path = batch[i]->dst_path;
			stack_entries[i].result      = 0;
			worker_record_start(w);
		}
		sftp_upload_batch(w->conn, stack_entries, bn,
		    p->cfg.preserve_flag, p->cfg.fsync_flag,
		    p->cfg.inplace_flag);
		for (int i = 0; i < bn; i++)
			worker_finalize_one_entry(p, w, batch[i],
			    stack_entries[i].result);
		return;
	}

	/* Pipelined path: heap-allocate the entry and unit arrays so they
	 * survive across the next worker_thread iteration. */
	entries = xcalloc(bn, sizeof(*entries));
	units   = xcalloc(bn, sizeof(*units));
	for (int i = 0; i < bn; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		units[i]               = batch[i];
		worker_record_start(w);
	}

	/* send() drains batch_prev_pending (if any) AFTER its phase 1
	 * OPENs are on the wire — that overlap is the win. */
	new_pending = sftp_upload_batch_send(w->conn, entries, bn,
	    p->cfg.preserve_flag, p->cfg.fsync_flag,
	    p->cfg.inplace_flag,
	    w->batch_prev_pending);
	/* batch_prev_pending has been freed inside send. */
	w->batch_prev_pending = NULL;

	/* Now finalise the prev batch's results (entries already populated
	 * by the drain that just ran inside send). */
	if (w->batch_prev_units != NULL) {
		for (int i = 0; i < w->batch_prev_n; i++)
			worker_finalize_one_entry(p, w,
			    w->batch_prev_units[i],
			    w->batch_prev_entries[i].result);
		free(w->batch_prev_units);
		free(w->batch_prev_entries);
		w->batch_prev_units   = NULL;
		w->batch_prev_entries = NULL;
		w->batch_prev_n       = 0;
	}

	if (new_pending == NULL) {
		/* THIS batch's send failed.  Every entry has result == -1;
		 * finalise inline and don't carry over. */
		for (int i = 0; i < bn; i++)
			worker_finalize_one_entry(p, w, units[i],
			    entries[i].result);
		free(units);
		free(entries);
	} else {
		/* Save this batch as the new prev for the next iteration. */
		w->batch_prev_pending = new_pending;
		w->batch_prev_units   = units;
		w->batch_prev_entries = entries;
		w->batch_prev_n       = bn;
	}
}
/* ── END Phase 4 gap 1 ────────────────────────────────────────────────── */

/* ── BEGIN Phase 5: bundle-mode batch dispatch ────────────────────────────
 *
 * worker_run_bundle is the bundle-mode analogue of
 * worker_run_batch_pipelined.  When w->bundle_enabled the worker calls
 * this instead — the batch of small files is packed into a single tar
 * stream and shipped through one OPEN/WRITE×N/CLOSE on a fresh bundle
 * handle.  This eliminates the per-file open/close round-trip that limits
 * Phase 4's pipelined batch path on high-RTT links.
 *
 * Per-entry success is signalled via the result field (set by
 * sftp_hpn_bundle_upload): on bundle failure every entry is marked -1, the
 * units retry through the normal worker_finalize_one_entry path, and the
 * batch is requeued unit-by-unit (no batch-wide retry needed since the
 * units are still individual work-queue entries).
 *
 * Synchronous in this first cut: no overlap with the next batch.  Could
 * be relaxed later by splitting send/finish like Phase 4 gap 1; not worth
 * the complexity until benchmarks show bundle close latency is a problem.
 * ────────────────────────────────────────────────────────────────────── */

static void
worker_run_bundle(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_hpn_bundle_upload_entry *entries;
	uint64_t total_bytes = 0;
	int i, ok_count = 0;
	uint64_t t_start_ns, t_end_ns, elapsed_us;

	entries = xcalloc(bn, sizeof(*entries));
	for (i = 0; i < bn; i++) {
		entries[i].local_path  = batch[i]->src_path;
		entries[i].remote_path = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(w);
	}

	/* Phase-5 instrumentation: per-bundle wall time.  Always-on; one
	 * stderr line per bundle.  Format chosen so the harness can grep
	 * "BUNDLE worker=" and parse the key=value fields. */
	t_start_ns = monotonic_ns();

	/* dest_dir = "" — each remote_path is treated as an absolute path
	 * by the server-side bundle handler.  This avoids needing to
	 * compute a common prefix across the batch; the server's bundle
	 * extractor calls mkdir_p on each containing directory anyway.
	 * Slight wire-size cost (full path repeated in every tar header)
	 * but trivial compared to the small-file payloads. */
	int bundle_rc = sftp_hpn_bundle_upload(w->conn, "", entries, bn,
	    p->cfg.preserve_flag, p->cfg.fsync_flag);

	t_end_ns = monotonic_ns();
	elapsed_us = (t_end_ns - t_start_ns) / 1000ULL;
	for (i = 0; i < bn; i++)
		if (entries[i].result == 0)
			ok_count++;
	{
		double mibps = 0.0;
		if (elapsed_us > 0)
			mibps = ((double)total_bytes /
			    (1024.0 * 1024.0)) /
			    ((double)elapsed_us / 1e6);
		logit("BUNDLE worker=%d files=%d ok=%d bytes=%llu "
		    "elapsed_us=%llu MiBps=%.2f",
		    w->id, bn, ok_count,
		    (unsigned long long)total_bytes,
		    (unsigned long long)elapsed_us, mibps);
	}

	/* Bundle wire failed (server refused open, transport error): the
	 * per-entry results above all say -1, but retrying the same bundle
	 * path would hit the same failure.  Mark each unit ineligible for
	 * future bundling so the next worker_thread iteration dispatches
	 * them via the per-file SFTP path instead.  Files MUST be delivered
	 * one way or another — bundle is an optimisation, not a contract. */
	if (bundle_rc != 0) {
		for (i = 0; i < bn; i++)
			batch[i]->bundle_ineligible = 1;
	}

	for (i = 0; i < bn; i++)
		worker_finalize_one_entry(p, w, batch[i], entries[i].result);

	free(entries);
}

/*
 * Download-side counterpart of worker_run_bundle.  Builds the entries
 * array from a batch of SFTP_OP_DOWNLOAD units (src_path = remote,
 * dst_path = local), asks the server to pack the listed paths via
 * sftp_hpn_bundle_download, then finalises each work unit with its
 * per-entry result.
 *
 * Mirrors worker_run_bundle's failure handling: per-entry result is
 * propagated through worker_finalize_one_entry, which re-queues on
 * failure via the normal retry path.  If the whole transaction fails
 * (server refused extension, mid-stream wire error), every entry is
 * marked -1 and each gets retried individually.
 */
static void
worker_run_bundle_download(struct sftp_worker *w,
    struct sftp_work_unit **batch, int bn)
{
	struct sftp_parallel *p = w->parent;
	struct sftp_hpn_bundle_download_entry *entries;
	uint64_t total_bytes = 0;
	int i, ok_count = 0;
	uint64_t t_start_ns, t_end_ns, elapsed_us;

	entries = xcalloc(bn, sizeof(*entries));
	for (i = 0; i < bn; i++) {
		entries[i].remote_path = batch[i]->src_path;
		entries[i].local_path  = batch[i]->dst_path;
		entries[i].result      = 0;
		if (batch[i]->size > 0)
			total_bytes += (uint64_t)batch[i]->size;
		worker_record_start(w);
	}

	t_start_ns = monotonic_ns();
	int bundle_rc = sftp_hpn_bundle_download(w->conn, entries, bn,
	    p->cfg.preserve_flag);
	t_end_ns = monotonic_ns();
	elapsed_us = (t_end_ns - t_start_ns) / 1000ULL;
	for (i = 0; i < bn; i++)
		if (entries[i].result == 0)
			ok_count++;
	{
		double mibps = 0.0;
		if (elapsed_us > 0)
			mibps = ((double)total_bytes / (1024.0 * 1024.0)) /
			    ((double)elapsed_us / 1e6);
		logit("BUNDLE-DL worker=%d files=%d ok=%d bytes=%llu "
		    "elapsed_us=%llu MiBps=%.2f",
		    w->id, bn, ok_count,
		    (unsigned long long)total_bytes,
		    (unsigned long long)elapsed_us, mibps);
	}

	/* Bundle wire failed: mark each unit ineligible so retries go down
	 * the per-file SFTP_OP_DOWNLOAD path.  See worker_run_bundle. */
	if (bundle_rc != 0) {
		for (i = 0; i < bn; i++)
			batch[i]->bundle_ineligible = 1;
	}

	for (i = 0; i < bn; i++)
		worker_finalize_one_entry(p, w, batch[i], entries[i].result);

	free(entries);
}
/* ── END Phase 5 ──────────────────────────────────────────────────────── */

/*
 * Execute a single work unit through the non-batch path: drain any
 * deferred pipelined batch (its STATUSes would corrupt the next RPC),
 * mark the worker as actively working, run execute_unit, log the
 * dispatch-diag line, hand the result to worker_process_result.
 *
 * Used in three places by worker_thread:
 *   - the `bn == 1` branch (batch loop collected only one unit)
 *   - the leftover-after-batch dispatch
 *   - the outer else branch (DOWNLOAD without bundle, RANGE ops,
 *     mkdir, etc.)
 */
static void
worker_execute_single(struct sftp_worker *w, struct sftp_work_unit *u)
{
	worker_drain_pipeline(w);
	worker_record_start(w);
	int rc = execute_unit(w, u);
	debug_ft("dispatch-diag: worker %d executed op=%d rc=%d "
	    "offset=%lld length=%lld",
	    w->id, (int)u->op, rc,
	    (long long)u->range_offset,
	    (long long)u->range_length);
	worker_process_result(w, u, rc);
}

/*
 * One-time worker setup: signal mask, env-var parsing for the bundle
 * and batch-pipeline kill switches, and per-worker bundle target.
 * Sampled once at startup; survives the worker's lifetime.  Factored
 * out of worker_thread to keep the main loop body readable.
 */
static void
worker_thread_init(struct sftp_worker *w)
{
	/* Mask SIGALRM so progressmeter timer ticks deliver only to the
	 * main thread / reporter (which holds it unmasked). */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	/* DISPATCH-DIAG: worker has reached the main loop entry, fully
	 * past spawn_one_worker / sftp_init.  If a worker is alive in
	 * p->workers[] but this line never appears for its id, the
	 * worker_thread itself never got scheduled / never started. */
	debug_ft("dispatch-diag: worker %d entered main loop", w->id);

	/* Phase 4 gap 1: read the HPN_NO_BATCH_PIPELINE env once per worker.
	 * Disables the pipelined batch path; falls back to legacy
	 * sftp_upload_batch.  Useful for A/B testing and bisecting. */
	{
		/* ENV-VAR HPN_NO_BATCH_PIPELINE — developer-only: kill switch
		 * for Phase-4 pipelined upload batch.  Forces the legacy
		 * synchronous path for A/B testing.  Not user-facing. */
		const char *e = getenv("HPN_NO_BATCH_PIPELINE");
		if (e != NULL && *e != '\0' && *e != '0')
			w->batch_pipe_disabled = 1;
	}

	/* Phase 5 bundle-mode: ON by default when the server advertises
	 * hpn-bundle@hpnssh.org.  Disabled when:
	 *   - HPNUseBundle no   in ssh_config (resolved by sftp.c via
	 *                       `hpnssh -G host`; stored in p->cfg.use_bundle)
	 *   - server doesn't advertise the hpn-bundle extension
	 * Either forces the Phase-4 pipelined batch fallback. */
	w->bundle_target_bytes = (w->parent->cfg.bundle_size > 0)
	    ? w->parent->cfg.bundle_size
	    : BUNDLE_TARGET_BYTES;
	if (w->parent->cfg.use_bundle == 0) {
		debug_ft("worker %d: bundle disabled by "
		    "ssh_config HPNUseBundle no", w->id);
	} else if (sftp_conn_has_hpn_bundle(w->conn)) {
		w->bundle_enabled = 1;
		debug_ft("worker %d: hpn-bundle enabled (target_bytes=%llu)",
		    w->id, (unsigned long long)w->bundle_target_bytes);
	} else {
		debug_ft("worker %d: server lacks hpn-bundle extension, "
		    "using Phase-4 batch fallback", w->id);
	}
}

/*
 * Post-iteration termination check: returns 1 if the worker should
 * break out of the main loop (protocol-violation strike 1, or
 * connection died), 0 otherwise.  Strike 2 fatal()s the process and
 * never returns.
 *
 * Protocol-violation two-strikes policy:
 *   Strike 1 — log loudly, bump p->protocol_violations.  The conn is
 *     already dead (set by sftp_hpn_set_protocol_violation in
 *     sftp-client.c) so we fall through to the conn_is_dead branch
 *     immediately below and break out.  Reporter's respawn machinery
 *     replaces us with a fresh SSH child; transfer continues.
 *   Strike 2 (lifetime per hpnsftp process) — sustained pattern,
 *     not bad luck.  fatal().  The OS reaps remaining SSH children
 *     when the parent dies.  Current unit cleanup was already done by
 *     worker_process_result / batch result loop.
 *
 * Threshold is a fixed count (2), not a rate: a correctly-functioning
 * server produces zero violations regardless of worker count or
 * transfer length — SSH MAC catches all in-channel tampering below
 * this layer.  Anything reaching here is, by definition, abnormal.
 *
 * Possible causes: random bit-flip on a long transfer (historical NIC
 * silicon bug — common, benign-but-noisy, want to tolerate one) or
 * buggy/compromised server / persistent hardware fault (rare but
 * serious — must not paper over).
 */
static int
worker_should_terminate(struct sftp_worker *w)
{
	struct sftp_parallel *p = w->parent;

	if (sftp_conn_is_protocol_violation(w->conn)) {
		int total;

		pthread_mutex_lock(&p->workers_mu);
		p->protocol_violations++;
		total = p->protocol_violations;
		pthread_mutex_unlock(&p->workers_mu);

		if (total >= 2) {
			fatal("worker %d: protocol violation #%d in "
			    "this session - sustained pattern, "
			    "aborting hpnsftp (possible server "
			    "corruption, MITM, or persistent "
			    "hardware fault)", w->id, total);
		}
		error_f("worker %d: protocol violation #%d - killing "
		    "worker and respawning; one more this session "
		    "will exit hpnsftp", w->id, total);
		/* fall through to the conn_is_dead branch below: the
		 * conn is already marked dead by the protocol-violation
		 * handler in sftp-client.c. */
	}

	if (sftp_conn_is_dead(w->conn)) {
		if (!p->abort_flag && !p->stopped)
			debug_ft("worker %d: connection lost - "
			    "will attempt to respawn", w->id);
		return 1;
	}
	return 0;
}

static void *
worker_thread(void *arg)
{
	struct sftp_worker *w = arg;
	struct sftp_parallel *p = w->parent;

	worker_thread_init(w);

	while (1) {
		if (p->abort_flag)
			break;
		void *item = NULL;
		uint64_t t_idle_start = monotonic_ns();
		__atomic_store_n(&w->pop_start_ns, t_idle_start,
		    __ATOMIC_RELEASE);
		/* Phase 4 gap 1 deadlock guard: if we have a deferred
		 * pipelined batch with pending CLOSE-STATUSes in the
		 * SSH socket buffer, we cannot block on the workqueue
		 * without first reading those replies — TCP back-pressure
		 * would otherwise stall the server.  Try a non-blocking
		 * pop first; if the queue is empty, drain the deferred
		 * batch (which reads the pending STATUSes and frees them)
		 * before falling back to a blocking pop. */
		if (w->batch_prev_pending != NULL) {
			if (sftp_workqueue_trypop(p->q, &item) != 0) {
				/* queue empty — drain before blocking */
				worker_drain_pipeline(w);
				item = NULL;
			}
		}
		if (item == NULL && sftp_workqueue_pop(p->q, &item) != 0) {
			__atomic_store_n(&w->pop_start_ns, 0,
			    __ATOMIC_RELEASE);
			break;	/* shutdown && empty */
		}
		uint64_t t_work_start = monotonic_ns();
		__atomic_store_n(&w->pop_start_ns, 0, __ATOMIC_RELEASE);
		/* Mark when this worker took possession of a unit so the
		 * watchdog can measure "how long has this worker been
		 * holding the current unit" even if the worker has never
		 * completed a previous unit.  Cleared at the end of this
		 * iteration after the unit (or batch) has been processed. */
		__atomic_store_n(&w->unit_start_ns, t_work_start,
		    __ATOMIC_RELEASE);
		struct sftp_work_unit *u0 = item;
		if (u0 == NULL) {
			__atomic_store_n(&w->unit_start_ns, 0,
			    __ATOMIC_RELEASE);
			continue;
		}

		/* DISPATCH-DIAG: worker pulled a unit off the queue.  If
		 * "entered main loop" appears for a worker but no "popped"
		 * line ever follows, the worker is blocked in pop_blocking
		 * with no signal reaching it. */
		debug_ft("dispatch-diag: worker %d popped op=%d "
		    "offset=%lld length=%lld src=\"%s\" dst=\"%s\" "
		    "idle_us=%llu",
		    w->id, (int)u0->op,
		    (long long)u0->range_offset,
		    (long long)u0->range_length,
		    u0->src_path ? u0->src_path : "(null)",
		    u0->dst_path ? u0->dst_path : "(null)",
		    (unsigned long long)
		        ((t_work_start - t_idle_start) / 1000ULL));
		if (u0->size > 0)
			__atomic_fetch_sub(&p->queued_bytes,
			    (uint64_t)u0->size, __ATOMIC_RELAXED);

		/* Self-exit sentinel from sftp_parallel_remove_worker. The
		 * first worker to pop this exits its loop; the reporter
		 * thread reaps it. Mark voluntary so the reap loop does
		 * not spawn a replacement.  Drain the deferred pipelined
		 * batch (if any) so its CLOSE STATUSes are collected on
		 * a live connection before we exit. */
		if (u0->op == SFTP_OP_EXIT_WORKER) {
			worker_drain_pipeline(w);
			free_unit(u0);
			pthread_mutex_lock(&w->mu);
			w->exited_voluntary = 1;
			pthread_mutex_unlock(&w->mu);
			break;
		}

		/*
		 * Batch-open optimisation for uploads: accumulate up to
		 * UPLOAD_BATCH_SIZE upload units using non-blocking trypop,
		 * then call sftp_upload_batch to pipeline all N SSH_FXP_OPEN
		 * requests before waiting for any handle (1 RTT for N opens
		 * instead of 1 RTT each).  Same pipelining for closes.
		 * Falls back to single-unit execution if the first unit is
		 * not an upload or if the batch stays at size 1.
		 */
		/* Phase 5 (download side): only batch DOWNLOAD units when
		 * the server advertises hpn-bundle-fetch and the worker has
		 * bundle mode on; otherwise downloads continue down the
		 * single-unit branch (Phase 4 pipelining for downloads is
		 * still future work). */
		int batch_eligible_download =
		    (u0->op == SFTP_OP_DOWNLOAD &&
		     w->bundle_enabled &&
		     sftp_conn_has_hpn_bundle_fetch(w->conn));
		enum sftp_op batch_op = u0->op;

		/* Phase 5: a previous bundle attempt failed at the wire for
		 * this unit (server refused, cap exceeded, transport error).
		 * Skip the batch path entirely so this retry goes through
		 * sftp_download / sftp_upload directly.  Without this gate,
		 * the unit would loop bundle-fail → retry → bundle-fail until
		 * MAX_RETRIES, then be permanently lost. */
		if (u0->bundle_ineligible) {
			batch_eligible_download = 0;
			/* For uploads the check happens inside the block; the
			 * `bn == 1` branch below handles per-file dispatch.
			 * For downloads, dropping the eligibility gate sends
			 * the unit straight to the outer single-unit path. */
		}

		if ((u0->op == SFTP_OP_UPLOAD && !u0->bundle_ineligible) ||
		    batch_eligible_download) {
			struct sftp_work_unit *batch[UPLOAD_BATCH_SIZE];
			struct sftp_work_unit *leftover = NULL;
			int bn = 0;
			/* Soft byte cap: keep adding while batch_bytes is at or
			 * below the cap.  The first unit is always added even if
			 * its size alone exceeds the cap (so a single huge file
			 * is never orphaned).  See UPLOAD_BATCH_BYTE_CAP.
			 *
			 * Phase 5: in bundle mode use the smaller
			 * w->bundle_target_bytes cap so each tar stream stays
			 * small enough to compose well with parallel streams. */
			uint64_t batch_bytes = (u0->size > 0) ?
			    (uint64_t)u0->size : 0;
			const uint64_t batch_byte_cap = w->bundle_enabled
			    ? w->bundle_target_bytes
			    : UPLOAD_BATCH_BYTE_CAP;

			batch[bn++] = u0;
			while (bn < UPLOAD_BATCH_SIZE && !p->abort_flag &&
			    batch_bytes <= batch_byte_cap) {
				void *nxt = NULL;
				if (sftp_workqueue_trypop(p->q, &nxt) != 0)
					break; /* queue empty or shutdown */
				struct sftp_work_unit *nu = nxt;
				if (nu->size > 0)
					__atomic_fetch_sub(&p->queued_bytes,
					    (uint64_t)nu->size,
					    __ATOMIC_RELAXED);
				if (nu->op == batch_op &&
				    !nu->bundle_ineligible) {
					batch[bn++] = nu;
					if (nu->size > 0)
						batch_bytes +=
						    (uint64_t)nu->size;
				} else {
					/* Off-op OR bundle-ineligible: stop
					 * collecting, handle after batch.
					 * Ineligible units must not be bundled;
					 * leftover dispatch sends them through
					 * the per-file path. */
					leftover = nu;
					break;
				}
			}

			/*logit("sftp-parallel: worker %d batch_size=%d "
			    "(queue_depth=%zu)", w->id, bn,
			    sftp_workqueue_depth(p->q)); */

			if (bn == 1) {
				/* Single file — skip batch overhead. */
				worker_execute_single(w, batch[0]);
			} else if ((int)batch_op == (int)SFTP_OP_DOWNLOAD) {
				/*
				 * Phase 5 (download side): the eligibility
				 * gate above guarantees w->bundle_enabled and
				 * the server has hpn-bundle-fetch, so the only
				 * dispatch for a multi-unit DOWNLOAD batch is
				 * bundle-fetch.  Synchronous; no pipelined
				 * carry-over state on the download bundle path.
				 */
				worker_run_bundle_download(w, batch, bn);
			} else if (w->bundle_enabled) {
				/*
				 * Phase 5 (upload side): bundle this batch as
				 * a tar stream and ship through one
				 * OPEN/WRITE×N/CLOSE.  Synchronous; the
				 * pipelined-batch carry-over state
				 * (batch_prev_pending et al) is unused on the
				 * bundle path and stays NULL.
				 */
				worker_run_bundle(w, batch, bn);
			} else {
				/*
				 * True batch.  Phase 4 gap 1:
				 * worker_run_batch_pipelined handles the entries
				 * array, send/finish, and per-entry finalisation.
				 * In pipelined mode (default) the THIS batch's
				 * phase 5 is deferred; the PREVIOUS batch's
				 * results are finalised inside the helper.  In
				 * the kill-switch path (HPN_NO_BATCH_PIPELINE=1)
				 * it falls back to a synchronous sftp_upload_batch
				 * call with the same finalisation logic inline.
				 */
				worker_run_batch_pipelined(w, batch, bn);
			}

			/* Process the leftover non-batch unit (if any). */
			if (leftover != NULL) {
				if (leftover->op == SFTP_OP_EXIT_WORKER) {
					/* Drain pending pipelined CLOSEs on a
					 * live conn before voluntary exit. */
					worker_drain_pipeline(w);
					free_unit(leftover);
					pthread_mutex_lock(&w->mu);
					w->exited_voluntary = 1;
					pthread_mutex_unlock(&w->mu);
					break;
				}
				worker_execute_single(w, leftover);
			}
		} else {
			/* Download (no bundle), mkdir, or any range op —
			 * all bypass the upload-batch path. */
			worker_execute_single(w, u0);
		}

		/* Account for this iteration's idle and work time. */
		{
			uint64_t t_work_end = monotonic_ns();
			pthread_mutex_lock(&w->mu);
			w->idle_ns += t_work_start - t_idle_start;
			w->work_ns += t_work_end - t_work_start;
			pthread_mutex_unlock(&w->mu);
		}

		/* Unit (or batch) finished — clear the wedge-detection
		 * timestamp so the watchdog only ever counts time spent
		 * actually holding work. */
		__atomic_store_n(&w->unit_start_ns, 0, __ATOMIC_RELEASE);

		if (worker_should_terminate(w))
			break;
	}
	/* Phase 4 gap 1: drain any deferred pipelined batch state before
	 * exiting.  If the connection died, this is a best-effort drain
	 * (sftp_upload_batch_finish handles a dead conn by marking entries
	 * failed and freeing). */
	worker_drain_pipeline(w);

	/* Mark exited so the reporter thread can reap us (join + free). */
	pthread_mutex_lock(&w->mu);
	w->exited = 1;
	pthread_mutex_unlock(&w->mu);
	return NULL;
}

/* ---------- Reporter thread ---------- */

static void
snapshot_workers(struct sftp_parallel *p, uint64_t *bytes_out,
    uint64_t *completed_out, uint64_t *failed_out)
{
	uint64_t b = 0, c = 0, f = 0;
	pthread_mutex_lock(&p->workers_mu);
	/* Bytes from workers that have already exited and been reaped. */
	b += p->retired_bytes;
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		b += w->bytes_total;
		/* live_bytes is written atomically by the worker without holding
		 * w->mu (to avoid lock contention in the inner transfer loop),
		 * so read it with a relaxed atomic load for the display value. */
		b += __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);
		c += w->units_completed;
		f += w->units_failed;
		pthread_mutex_unlock(&w->mu);
	}
	pthread_mutex_unlock(&p->workers_mu);
	if (bytes_out) *bytes_out = b;
	if (completed_out) *completed_out = c;
	if (failed_out) *failed_out = f;
}

/*
 * Adaptive throughput-based stall detection (first pass).
 *
 * For each worker, computes kbps since the last tick.  Identifies the
 * fastest worker (max_kbps).  If the path looks healthy (max_kbps >=
 * cfg.tput_path_healthy_kbps), increments outlier_ticks for any worker
 * whose kbps is dramatically below max.  Returns the per-worker outlier
 * tick count via *worker_outlier_ticks[i] (caller-allocated array of
 * length p->num_workers; must be called under workers_mu).
 *
 * The caller (watchdog_check_workers) combines this with the existing
 * time-based and ssh-child-existence checks to make final classifications.
 *
 * FUTURE: a server-side query (e.g. hpn-conn-stats@hpnssh.org SSH global
 * request) could provide an independent signal about each worker's
 * receive-side state — useful when the local-side tput estimate is
 * noisy or when we want to confirm the rwnd rescue has already fired.
 * For now we rely on local bytes_total deltas only.
 */

static void
watchdog_sample_throughput(struct sftp_parallel *p, uint64_t now)
{
	if (p->cfg.tput_path_healthy_kbps == 0)
		return;	/* feature disabled */

	uint64_t max_kbps = 0;      /* raw max — path-health gate only */
	uint64_t max_ema_kbps = 0;  /* smoothed max — threshold basis */

	double alpha = (p->cfg.tput_ema_alpha > 0.0)
	    ? p->cfg.tput_ema_alpha : 0.2;

	/* First pass: compute per-worker raw kbps, update EMA, find maxima.
	 *
	 * Use bytes_total + live_bytes (continuous progress) rather than
	 * bytes_total alone (file-completion-granular).  Without live_bytes,
	 * a worker mid-transfer shows bytes_delta=0 for several seconds then
	 * a spike at completion — the outlier ticks oscillate and the consec
	 * counter never sticks.
	 *
	 * EMA smoothing (alpha default 0.2, ~5-tick time constant) prevents
	 * a single-tick burst from one worker from instantly spiking the
	 * threshold and falsely classifying slower-but-healthy peers.  The
	 * raw max is kept separately so the path-health gate (step 3) still
	 * reacts immediately to actual path state. */
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		uint64_t now_bytes;
		pthread_mutex_lock(&w->mu);
		now_bytes = w->bytes_total;
		pthread_mutex_unlock(&w->mu);
		now_bytes += __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);

		if (w->tput_check_ns == 0) {
			/* First sample: initialize baselines, skip this tick. */
			w->tput_check_bytes = now_bytes;
			w->tput_check_ns = now;
			w->tput_current_kbps = 0;
			w->tput_ema_kbps = 0;
			continue;
		}

		uint64_t elapsed_ns = now - w->tput_check_ns;
		uint64_t bytes_delta = (now_bytes >= w->tput_check_bytes)
		    ? (now_bytes - w->tput_check_bytes) : 0;
		w->tput_current_kbps = (elapsed_ns > 0)
		    ? bytes_delta * 1000000000ULL / elapsed_ns / 1024ULL : 0;
		w->tput_check_bytes = now_bytes;
		w->tput_check_ns = now;

		/* EMA update.  Skip when the worker has no unit in flight so
		 * idle gaps between files don't decay the EMA toward zero and
		 * produce spurious outlier warnings when the next unit starts.
		 * Cold-start: seed EMA from first real measurement so a fast
		 * worker registers immediately rather than climbing out of zero.
		 * Only actively-transferring workers contribute to max_ema_kbps
		 * so idle workers' frozen EMAs don't inflate the threshold.
		 *
		 * New-unit detection: when unit_start_ns changes (worker picked
		 * up a fresh work unit), reset EMA and warmup so the EMA builds
		 * from actual current throughput rather than the stale frozen
		 * value.  Without this reset the frozen healthy EMA makes the
		 * else-branch clear tput_outlier_ticks on the first tick of every
		 * new unit, preventing the consec counter from ever reaching the
		 * STALLED threshold on a persistently slow worker. */
		uint64_t cur_unit_start = __atomic_load_n(&w->unit_start_ns,
		    __ATOMIC_RELAXED);
		int w_idle = (cur_unit_start == 0);
		if (!w_idle) {
			if (cur_unit_start != w->tput_last_unit_start_ns) {
				/* Worker transitioned to a new unit: cold-start
				 * EMA so next ticks reflect actual performance. */
				w->tput_ema_kbps = 0;
				w->tput_ema_warmup_ticks = 0;
				w->tput_last_unit_start_ns = cur_unit_start;
			}
			if (w->tput_ema_kbps == 0)
				w->tput_ema_kbps = w->tput_current_kbps;
			else
				w->tput_ema_kbps = (uint64_t)(
				    alpha * (double)w->tput_current_kbps +
				    (1.0 - alpha) * (double)w->tput_ema_kbps);
			if (w->tput_ema_warmup_ticks < TPUT_EMA_WARMUP_TICKS)
				w->tput_ema_warmup_ticks++;
			if (w->tput_ema_kbps > max_ema_kbps)
				max_ema_kbps = w->tput_ema_kbps;
		}

		if (w->tput_current_kbps > max_kbps)
			max_kbps = w->tput_current_kbps;
	}

	/* Diagnostic: log per-worker raw and EMA kbps once every ~5 sec. */
	static int sample_ticks = 0;
	if ((sample_ticks++ % 5) == 0) {
		char per_worker[256];
		int off = 0;
		per_worker[0] = '\0';
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			int n = snprintf(per_worker + off,
			    sizeof(per_worker) - off,
			    " w%d=%llu(ema=%llu)", w->id,
			    (unsigned long long)w->tput_current_kbps,
			    (unsigned long long)w->tput_ema_kbps);
			if (n < 0 || (size_t)(off + n) >= sizeof(per_worker))
				break;
			off += n;
		}
		debug_ft("tput sample: max_kbps=%llu max_ema=%llu "
		    "path_healthy=%llu%s",
		    (unsigned long long)max_kbps,
		    (unsigned long long)max_ema_kbps,
		    (unsigned long long)p->cfg.tput_path_healthy_kbps,
		    per_worker);
	}

	/* Snapshot for the respawn throughput gate (checked in the reporter). */
	p->tput_last_raw_max_kbps = max_kbps;

	/* Path-health gate uses raw max_kbps so it reacts immediately when
	 * the link recovers (an EMA-smoothed gate would lag). */
	if (max_kbps < p->cfg.tput_path_healthy_kbps) {
		for (int i = 0; i < p->num_workers; i++)
			p->workers[i]->tput_outlier_ticks = 0;
		return;
	}

	/* Second pass: classify outliers using smoothed values.
	 *
	 * threshold = max_ema_kbps * fraction — both the reference and the
	 * per-worker value are EMA-smoothed, so neither side of the comparison
	 * can be swung by a single noisy tick.
	 *
	 * Only count as outlier when the worker has IN-FLIGHT WORK. An idle
	 * worker between queue pops legitimately shows kbps=0 and must not be
	 * penalised. */
	uint64_t threshold_kbps =
	    (uint64_t)(max_ema_kbps * p->cfg.tput_outlier_fraction);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		uint64_t in_flight;
		pthread_mutex_lock(&w->mu);
		in_flight = w->units_started - w->units_completed -
		    w->units_failed;
		pthread_mutex_unlock(&w->mu);

		if (w->tput_ema_warmup_ticks < TPUT_EMA_WARMUP_TICKS) {
			/* EMA not yet warm — skip outlier detection, but don't
			 * reset tput_outlier_ticks: a pre-accumulated consec count
			 * from before this unit boundary should carry forward so a
			 * persistently slow worker is caught after fewer post-warmup
			 * ticks. */
			continue;
		}

		if (in_flight == 0) {
			/* Pause — don't reset.  A persistently slow worker
			 * oscillates between in-flight and idle between units;
			 * resetting here wipes the accumulated consec count and
			 * prevents the detector from ever reaching the DEAD
			 * threshold.  Skipping the tick (without clearing) lets
			 * consec carry across unit boundaries, so a worker that
			 * is consistently slow across multiple units gets caught.
			 * The counter is cleared only when EMA >= threshold
			 * (genuine recovery) in the else branch below. */
			continue;
		}

		/*
		 * TCP slow-start gate.  A worker must transfer at least
		 * (peer-throughput × path_rtt × RAMP_RTTS) bytes before its
		 * EMA is comparable to the path max.  Without this, a fresh
		 * worker is condemned as an outlier while its cwnd is still
		 * ramping — the very failure mode that drove respawn-churn
		 * loops when one worker died and its replacement got killed
		 * on its first tick of slow-start traffic.
		 *
		 * Skip when no RTT is known (p->path_rtt_us == 0); the
		 * tick-based EMA warmup above is the fallback in that case.
		 */
		if (p->path_rtt_us > 0 && max_ema_kbps > 0) {
			uint64_t warmup_bytes =
			    ((uint64_t)max_ema_kbps * p->path_rtt_us *
			        (uint64_t)RAMP_RTTS) / 8000ULL;
			if (warmup_bytes < RAMP_WARMUP_BYTES_MIN)
				warmup_bytes = RAMP_WARMUP_BYTES_MIN;
			if (warmup_bytes > RAMP_WARMUP_BYTES_MAX)
				warmup_bytes = RAMP_WARMUP_BYTES_MAX;

			/*
			 * Use bytes_total + live_bytes (continuous progress)
			 * rather than bytes_total alone (completion-granular).
			 * A worker whose first unit is hung at the server
			 * never increments bytes_total — using it alone keeps
			 * the warmup gate suppressed forever and lets the
			 * outlier path miss a dribbling-but-not-zero worker.
			 * live_bytes counts writes-in-flight on the current
			 * unit, so once a worker has *pushed* enough bytes
			 * the gate lifts even if no unit has yet completed.
			 */
			uint64_t b;
			pthread_mutex_lock(&w->mu);
			b = w->bytes_total;
			pthread_mutex_unlock(&w->mu);
			b += __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);

			/* Time cap: lift the gate after RAMP_MAX_WARMUP_SEC
			 * regardless of bytes so a genuinely-slow worker is
			 * not protected for its entire slow lifetime. */
			uint64_t unit_start = __atomic_load_n(
			    &w->unit_start_ns, __ATOMIC_RELAXED);
			int past_time_cap = (unit_start > 0 &&
			    now - unit_start >
			    (uint64_t)RAMP_MAX_WARMUP_SEC * 1000000000ULL);

			if (b < warmup_bytes && !past_time_cap) {
				w->tput_outlier_ticks = 0;
				continue;
			}
		}

		if (w->tput_ema_kbps < threshold_kbps) {
			w->tput_outlier_ticks++;
			debug_ft("worker %d tput-outlier: "
			    "kbps=%llu ema=%llu threshold=%llu "
			    "consec=%d in_flight=%llu",
			    w->id,
			    (unsigned long long)w->tput_current_kbps,
			    (unsigned long long)w->tput_ema_kbps,
			    (unsigned long long)threshold_kbps,
			    w->tput_outlier_ticks,
			    (unsigned long long)in_flight);
		} else {
			w->tput_outlier_ticks = 0;
		}

		/* Born-slow tracking: per-worker counter of consecutive ticks
		 * the EMA stayed below an ABSOLUTE floor (a fraction of the
		 * configured tput_path_healthy_kbps).  Unlike the peer-based
		 * outlier above, this fires even when all peers are slow —
		 * the case where a connection comes up in a bad state from
		 * the start and pipelining can't lift it.  The kill itself
		 * happens in watchdog_check_workers; we just track the
		 * streak here. */
		{
			uint64_t born_slow_floor =
			    (uint64_t)(p->cfg.tput_path_healthy_kbps *
			        BORN_SLOW_FLOOR_FRAC);
			if (born_slow_floor > 0
			    && w->tput_ema_kbps < born_slow_floor
			    && w->tput_ema_warmup_ticks
			        >= TPUT_EMA_WARMUP_TICKS)
				w->tput_below_floor_ticks++;
			else
				w->tput_below_floor_ticks = 0;
		}
	}
}

/*
 * Synchronous-stall detector.  Called once per slow-tick (~1s).
 *
 * Measures aggregate bytes transferred (completions + in-progress writes)
 * across all live workers since the previous slow-tick.  If the delta is
 * zero while at least one worker has a unit in flight, it is a synchronous
 * stall: all writers hit the same storage bottleneck simultaneously.
 *
 * Keeps a rolling window of SYNC_STALL_WINDOW slow-ticks and logs the
 * stall fraction when the window closes.  Observation-only for now;
 * the fraction is intended as a future congestion-aware scale-down signal.
 */
static void
watchdog_check_sync_stall(struct sftp_parallel *p)
{
	uint64_t now_bytes = 0;
	uint64_t total_in_flight = 0;

	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		now_bytes += w->bytes_total;
		total_in_flight += w->units_started - w->units_completed -
		    w->units_failed;
		pthread_mutex_unlock(&w->mu);
		now_bytes += __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);
	}
	now_bytes += p->retired_bytes;
	pthread_mutex_unlock(&p->workers_mu);

	uint64_t delta = (now_bytes >= p->sync_stall_prev_bytes)
	    ? (now_bytes - p->sync_stall_prev_bytes) : 0;
	p->sync_stall_prev_bytes = now_bytes;

	/* First tick: prev_bytes was 0; delta = all bytes ever, not a stall. */
	if (p->sync_stall_window_pos > 0 && delta == 0 && total_in_flight > 0)
		p->sync_stall_ticks++;

	if (++p->sync_stall_window_pos >= SYNC_STALL_WINDOW) {
		double frac = (double)p->sync_stall_ticks / SYNC_STALL_WINDOW;
		debug_ft("sync-stall: %u/%u ticks (%.0f%%) — %s",
		    p->sync_stall_ticks, SYNC_STALL_WINDOW,
		    frac * 100.0,
		    frac >= SYNC_STALL_THRESHOLD
		        ? "possible write-cache saturation"
		        : "nominal");
		p->sync_stall_ticks = 0;
		p->sync_stall_window_pos = 0;
	}
}

/*
 * Watchdog: classify each worker as HEALTHY/STALLED/DEAD based on (a) its
 * ssh child's existence and (b) elapsed time since last completion when
 * the queue had work to feed it, and (c) adaptive throughput-outlier
 * detection (if cfg.tput_path_healthy_kbps > 0). Returns nonzero if any
 * worker has transitioned to DEAD, signaling the reporter to abort the
 * orchestrator.
 */
/*
 * Per-worker health classification and dooming action.  Returns 1 if
 * the worker was DEAD (or just transitioned to DEAD this tick), 0
 * otherwise — caller uses this to drive the workers_mu "any_dead"
 * tally.
 *
 * Caller must hold workers_mu; this function acquires per-worker mu
 * only for short critical sections (state read + transition).
 *
 * `tput_dead_this_tick` is the in/out throttle flag — at most one
 * throughput-outlier DEAD promotion per tick across all workers.
 */
static int
watchdog_check_one_worker(struct sftp_parallel *p, struct sftp_worker *w,
    uint64_t now, int queue_has_work, int *tput_dead_this_tick)
{
	enum worker_health prev, next;

	pthread_mutex_lock(&w->mu);
	prev = w->health;
	uint64_t in_flight = w->units_started - w->units_completed -
	    w->units_failed;
	uint64_t w_bytes_total = w->bytes_total;
	uint64_t w_units_completed = w->units_completed;
	uint64_t since_completion_ns = w->last_completion_ns ?
	    (now - w->last_completion_ns) : 0;  /* for log messages */
	pthread_mutex_unlock(&w->mu);
	uint64_t w_live_bytes = __atomic_load_n(&w->live_bytes,
	    __ATOMIC_RELAXED);

	uint64_t unit_start = __atomic_load_n(&w->unit_start_ns,
	    __ATOMIC_ACQUIRE);
	uint64_t since_unit_start_ns = (unit_start > 0 &&
	    now > unit_start) ? (now - unit_start) : 0;

	/*
	 * Effective silence: time since we last observed forward
	 * progress in bytes.  Tracks (bytes_total + live_bytes), which
	 * climbs continuously during an active transfer regardless of
	 * unit size.  Replaces the older completion-based timer that
	 * misfired on whole-file uploads of large files (a 10 GiB file
	 * at 2 Gbps takes ~50 s — close to STALL_THRESHOLD_SEC, any
	 * writeback dip would trip a false DEAD).
	 *
	 * Updated only by this thread; no atomics needed.  On first
	 * tick last_progress_ns is 0, so we seed it from now without
	 * touching last_progress_bytes (which is also 0).
	 */
	uint64_t cur_progress_bytes = w_bytes_total + w_live_bytes;
	if (w->last_progress_ns == 0 ||
	    cur_progress_bytes > w->last_progress_bytes) {
		w->last_progress_ns = now;
		w->last_progress_bytes = cur_progress_bytes;
	}
	uint64_t effective_silence_ns =
	    (w->last_progress_ns > 0 && now > w->last_progress_ns)
	    ? (now - w->last_progress_ns) : 0;

	next = WORKER_HEALTHY;

		/* SSH child gone is the strongest signal — detectable
		 * without waiting for the worker thread's next I/O.
		 *
		 * waitpid(WNOHANG|WNOWAIT) returns the pid if the child
		 * has exited (including zombies), 0 if it is still running,
		 * and -1/ECHILD if it has already been reaped.  WNOWAIT
		 * leaves the zombie in place so the reap loop's blocking
		 * waitpid still succeeds.  kill(0) alone misses the
		 * SIGKILL-then-zombie case because a zombie's pid is still
		 * present in the process table. */
		if (w->ssh_pid > 0) {
			int wstatus;
			pid_t wr = waitpid(w->ssh_pid, &wstatus,
			    WNOHANG | WNOWAIT);
			if (wr == w->ssh_pid ||
			    (wr == -1 && errno == ECHILD))
				next = WORKER_DEAD;
		}

		/*
		 * Born-dead fast-kill.  Worker popped a unit but has zero
		 * forward progress (no completions, no bytes ever, no live
		 * bytes on the current unit) for BORN_DEAD_KILL_SEC.  This is
		 * unambiguous: the SSH session reached the SFTP layer (the
		 * worker thread popped a unit) but no bytes have flowed at
		 * all.  Almost always a server-side channel-window freeze
		 * (e.g. Lustre OST stall).  Kill fast so the respawn slot
		 * gets a fresh SSH session into the same dst — usually that
		 * one lands on a healthier server-side path and recovers the
		 * capacity within ~5s instead of ~24s.
		 *
		 * Gates:
		 *  - in_flight > 0    : worker actually has a unit in hand
		 *  - units_completed == 0 && bytes_total == 0 : never made
		 *    any successful progress ever
		 *  - live_bytes == 0  : not even mid-write on the current
		 *    chunk (a slow OST that's still grinding bytes
		 *    through pwrite shouldn't be killed)
		 *  - since_unit_start > BORN_DEAD_KILL_SEC : enough time
		 *    has passed that auth + first OPEN should have completed
		 */
		if (next != WORKER_DEAD && in_flight > 0
		    && w_units_completed == 0 && w_bytes_total == 0
		    && w_live_bytes == 0
		    && since_unit_start_ns > (uint64_t)BORN_DEAD_KILL_SEC
		        * 1000000000ULL) {
			debug_ft("worker %d: born-dead fast-kill "
			    "(unit_start=%llus, 0 bytes, 0 completions)",
			    w->id,
			    (unsigned long long)
			    (since_unit_start_ns / 1000000000ULL));
			next = WORKER_DEAD;
		}

		if (next != WORKER_DEAD && queue_has_work && in_flight > 0 &&
		    effective_silence_ns > 0) {
			uint64_t s = effective_silence_ns / 1000000000ULL;
			if (s > DEAD_THRESHOLD_SEC)
				next = WORKER_DEAD;
			else if (s > STALL_THRESHOLD_SEC)
				next = WORKER_STALLED;
		} else if (!queue_has_work && in_flight > 0 &&
		    effective_silence_ns > 0) {
			/*
			 * Isolation escalation: queue is empty but this
			 * worker still has in-flight units (keeping pending
			 * > 0).  No other worker can take over its work —
			 * if it doesn't progress, sftp_parallel_wait hangs
			 * forever.  Apply a tighter threshold here: any
			 * worker that's been mute for STALL_THRESHOLD_SEC
			 * while no other work exists is the holdout, kill
			 * it so the unit gets re-queued and respawned.
			 *
			 * effective_silence_ns falls back to "time since
			 * unit was popped" when the worker has never
			 * completed anything — catches a worker wedged on
			 * its very first unit, where since_completion_ns
			 * would still be 0.
			 *
			 * Fast path: when the worker is dribbling below the
			 * configured healthy floor (peer-EMA outlier check
			 * can't fire because there are no peers), declare
			 * DEAD at ISOLATION_PROGRESS_STALL_SEC instead of
			 * the full STALL_THRESHOLD_SEC.  Gated on EMA
			 * warmup so we don't kill a worker that just popped
			 * a unit and is mid slow-start.
			 */
			uint64_t s = effective_silence_ns / 1000000000ULL;
			if (s > (uint64_t)ISOLATION_PROGRESS_STALL_SEC &&
			    p->cfg.tput_path_healthy_kbps > 0 &&
			    w->tput_ema_warmup_ticks >= TPUT_EMA_WARMUP_TICKS &&
			    w->tput_ema_kbps <
			        p->cfg.tput_path_healthy_kbps) {
				next = WORKER_DEAD;
			} else if (s > STALL_THRESHOLD_SEC) {
				next = WORKER_DEAD;
			}
		}

		/*
		 * Adaptive throughput-outlier escalation. tput_outlier_ticks
		 * is set by watchdog_sample_throughput above and is non-zero
		 * only when (a) the feature is enabled and (b) the fastest
		 * worker meets the path-healthy floor (so we know respawning
		 * could help). This catches cwnd-collapsed workers that the
		 * time-based detector misses because they're still completing
		 * the occasional file, just slowly.
		 *
		 * Only ESCALATE here, never de-escalate: if the SSH child or
		 * time-based path already classified DEAD, leave it DEAD.
		 *
		 * Throttle: kill at most ONE worker per tick via the
		 * throughput path.  Multiple workers may simultaneously hit
		 * the consec=2*req threshold on the same tick (when the
		 * tputs are uniformly low against a fast peer); killing
		 * them all at once stresses any server-side rate limit and
		 * burns the respawn budget faster than necessary.  The
		 * holdover workers stay STALLED and will be re-evaluated next
		 * tick — by then one respawn may already be in flight.
		 *
		 * Respawn budget: triggered respawns count against the
		 * epoch budget (RESPAWN_MULTIPLIER * num_streams). On
		 * budget exhaustion the orchestrator enters a cooldown
		 * pause rather than aborting immediately — see the
		 * respawn section in the reporter thread for details.
		 */
		if (next != WORKER_DEAD && p->cfg.tput_path_healthy_kbps > 0) {
			int consec = w->tput_outlier_ticks;
			int req = p->cfg.tput_consec_required > 0
			    ? p->cfg.tput_consec_required : 5;
			if (consec >= 2 * req) {
				if (!*tput_dead_this_tick) {
					next = WORKER_DEAD;
					*tput_dead_this_tick = 1;
				} else {
					/* Throttle: another worker already
					 * promoted to DEAD this tick.  Stay
					 * STALLED. */
					if (next == WORKER_HEALTHY)
						next = WORKER_STALLED;
				}
			} else if (consec >= req && next == WORKER_HEALTHY) {
				next = WORKER_STALLED;
			}
		}

		/*
		 * Born-slow fast-kill.  A connection that came up in a low-
		 * cwnd / small-recv-window state and never recovers presents
		 * as a worker whose EMA throughput stays persistently below
		 * a small fraction of the healthy floor.  Unlike the peer-
		 * based outlier above, this fires even when EVERY worker is
		 * slow (e.g. -j 2 with both connections stuck) — the case
		 * Phase 4 pipelining cannot help.  Killing triggers the
		 * normal respawn machinery; a fresh SSH session may land in
		 * a healthier TCP state.  Capped globally at BORN_SLOW_MAX_KILLS
		 * to avoid runaway respawn churn on paths that are genuinely
		 * slow rather than just unlucky.
		 */
		if (next != WORKER_DEAD
		    && p->cfg.tput_path_healthy_kbps > 0
		    && w->tput_below_floor_ticks >= BORN_SLOW_TICKS
		    && p->born_slow_kills < BORN_SLOW_MAX_KILLS) {
			uint64_t floor =
			    (uint64_t)(p->cfg.tput_path_healthy_kbps *
			        BORN_SLOW_FLOOR_FRAC);
			debug_ft("worker %d: born-slow kill "
			    "(ema=%llukbps < %llukbps for %d ticks, "
			    "global kills=%d/%d)",
			    w->id,
			    (unsigned long long)w->tput_ema_kbps,
			    (unsigned long long)floor,
			    w->tput_below_floor_ticks,
			    p->born_slow_kills + 1, BORN_SLOW_MAX_KILLS);
			p->born_slow_kills++;
			next = WORKER_DEAD;
		}

		if (next != prev) {
			pthread_mutex_lock(&w->mu);
			w->health = next;
			pthread_mutex_unlock(&w->mu);
			if (next == WORKER_STALLED) {
				debug_ft("worker %d stalled: no progress in "
				    "%llu sec (since_completion=%llus, "
				    "since_unit_start=%llus)",
				    w->id,
				    (unsigned long long)
				    (effective_silence_ns / 1000000000ULL),
				    (unsigned long long)
				    (since_completion_ns / 1000000000ULL),
				    (unsigned long long)
				    (since_unit_start_ns / 1000000000ULL));
			} else if (next == WORKER_DEAD) {
				debug_ft("worker %d declared dead: "
				    "ssh_pid=%ld silence=%llus "
				    "(since_completion=%llus, "
				    "since_unit_start=%llus)",
				    w->id, (long)w->ssh_pid,
				    (unsigned long long)
				    (effective_silence_ns / 1000000000ULL),
				    (unsigned long long)
				    (since_completion_ns / 1000000000ULL),
				    (unsigned long long)
				    (since_unit_start_ns / 1000000000ULL));
			}
		}

		/* Doom dead workers: SIGTERM the SSH child so any blocking
		 * I/O in the worker thread unblocks immediately. Guard with
		 * doomed to prevent double-SIGTERM on successive ticks. */
		if (next == WORKER_DEAD) {
			int already_doomed;
			pthread_mutex_lock(&w->mu);
			already_doomed = w->doomed || w->exited;
			if (!already_doomed) {
				w->doomed = 1;
				w->doom_ns = now;
			}
			pthread_mutex_unlock(&w->mu);
			if (!already_doomed) {
				if (w->ssh_pid > 0)
					(void)kill(w->ssh_pid, SIGTERM);
				debug_ft("worker %d: sent SIGTERM to ssh "
				    "child (pid %ld)", w->id,
				    (long)w->ssh_pid);
			}
		}

	/* SIGKILL escalation: if a doomed worker hasn't exited within
	 * SIGKILL_ESCALATION_SEC, the SSH child is hung in its clean-
	 * shutdown path (broken socket) and the worker thread is blocked
	 * on its stdout pipe.  SIGKILL closes the pipes immediately, the
	 * worker thread sees EOF/EPIPE on its next I/O call, sets
	 * exited=1, and gets reaped.  Without this we deadlock: the
	 * SIGKILL-on-reap path is gated on exited=1. */
	if (w->doomed && !w->exited && w->doom_ns > 0 && w->ssh_pid > 0 &&
	    now - w->doom_ns >
	    (uint64_t)SIGKILL_ESCALATION_SEC * 1000000000ULL) {
		(void)kill(w->ssh_pid, SIGKILL);
		debug_ft("worker %d: escalated to SIGKILL after %llus "
		    "(SSH child unresponsive to SIGTERM, pid %ld)",
		    w->id,
		    (unsigned long long)
		    ((now - w->doom_ns) / 1000000000ULL),
		    (long)w->ssh_pid);
		/* Clear doom_ns so we don't re-escalate every tick. */
		pthread_mutex_lock(&w->mu);
		w->doom_ns = 0;
		pthread_mutex_unlock(&w->mu);
	}
	return (next == WORKER_DEAD) ? 1 : 0;
}

static int
watchdog_check_workers(struct sftp_parallel *p)
{
	int any_dead = 0;
	uint64_t now = monotonic_ns();
	int queue_has_work = (sftp_workqueue_depth(p->q) > 0);

	pthread_mutex_lock(&p->workers_mu);

	/* Adaptive throughput sample for outlier detection (no-op if
	 * cfg.tput_path_healthy_kbps == 0).  Sets w->tput_outlier_ticks. */
	watchdog_sample_throughput(p, now);

	/* Throttle: at most one DEAD promotion per tick from the
	 * throughput-outlier path. */
	int tput_dead_this_tick = 0;

	for (int i = 0; i < p->num_workers; i++) {
		if (watchdog_check_one_worker(p, p->workers[i], now,
		    queue_has_work, &tput_dead_this_tick))
			any_dead = 1;
	}
	pthread_mutex_unlock(&p->workers_mu);
	return any_dead;
}

static struct sftp_worker *spawn_one_worker(struct sftp_parallel *);

/* Spawns one replacement worker, called from a detached thread so
 * the SSH handshake doesn't block the reporter's progress ticks. */
static void *
respawn_worker_thread(void *arg)
{
	struct sftp_parallel *p = arg;

	/*
	 * Brief delay before attempting the replacement's SFTP handshake.
	 * Without this, observed failures: respawn fires within ~7 ms of
	 * the dying worker's SIGTERM, the receiver's sftp-server subsystem
	 * hasn't finished cleaning up the prior session, and the new
	 * connection's SSH_FXP_INIT gets a malformed reply (type 0,
	 * "Invalid packet back from SSH2_FXP_INIT").
	 *
	 * Configurable via SFTP_RESPAWN_DELAY_MS env var; default 2000 ms.
	 * Set to 0 to disable for testing.
	 */
	{
		/* ENV-VAR SFTP_RESPAWN_DELAY_MS — developer-only: respawn-
		 * cooldown timing knob.  Adjusting it should not be needed in
		 * production; default 2000 ms is the value tuned against the
		 * sftp-server FXP_INIT race.  Not user-facing. */
		const char *e = getenv("SFTP_RESPAWN_DELAY_MS");
		long delay_ms = (e && *e) ? strtol(e, NULL, 10) : 2000;
		if (delay_ms > 0) {
			struct timespec ts = {
				.tv_sec  = delay_ms / 1000,
				.tv_nsec = (delay_ms % 1000) * 1000000L,
			};
			nanosleep(&ts, NULL);
		}
	}

	struct sftp_worker *w = spawn_one_worker(p);
	if (w == NULL) {
		error_ft("worker respawn failed");
	} else {
		pthread_mutex_lock(&w->mu);
		w->reconnect_count++;
		pthread_mutex_unlock(&w->mu);
		debug_ft("worker %d respawned (reconnect_count=%llu)",
		    w->id, (unsigned long long)w->reconnect_count);
	}
	pthread_mutex_lock(&p->workers_mu);
	p->pending_respawns--;
	pthread_mutex_unlock(&p->workers_mu);
	return NULL;
}

/*
 * Phase-5 instrumentation: per-worker stats CSV.  Enabled by
 * HPN_WORKER_STATS_CSV=/path in the environment.  Opens the file on
 * first call (lazy), emits one row per worker per slow tick.
 *
 * Columns: t_ms, worker_id, bytes_total, live_bytes, units_started,
 *          units_completed, units_failed, health, reconnect_count
 *
 * Factored out of reporter_thread to keep the slow-tick body readable.
 * Holds workers_mu while iterating, plus per-worker mu for each row.
 */
static void
reporter_emit_stats_csv(struct sftp_parallel *p)
{
	if (p->stats_csv == NULL) {
		/* ENV-VAR HPN_WORKER_STATS_CSV — developer-only: path for
		 * per-second per-worker stats CSV used by the benchmark
		 * harness.  Not user-facing. */
		const char *path = getenv("HPN_WORKER_STATS_CSV");
		if (path == NULL || *path == '\0')
			return;
		p->stats_csv = fopen(path, "w");
		if (p->stats_csv == NULL)
			return;
		setvbuf(p->stats_csv, NULL, _IOLBF, 0);
		fprintf(p->stats_csv,
		    "t_ms,worker_id,bytes_total,live_bytes,units_started"
		    ",units_completed,units_failed,health,reconnect_count\n");
		p->stats_csv_start_ns = monotonic_ns();
	}
	uint64_t t_ms =
	    (monotonic_ns() - p->stats_csv_start_ns) / 1000000ULL;
	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		fprintf(p->stats_csv,
		    "%llu,%d,%llu,%llu,%llu,%llu,%llu,%d,%llu\n",
		    (unsigned long long)t_ms,
		    w->id,
		    (unsigned long long)w->bytes_total,
		    (unsigned long long)w->live_bytes,
		    (unsigned long long)w->units_started,
		    (unsigned long long)w->units_completed,
		    (unsigned long long)w->units_failed,
		    (int)w->health,
		    (unsigned long long)w->reconnect_count);
		pthread_mutex_unlock(&w->mu);
	}
	pthread_mutex_unlock(&p->workers_mu);
}

/*
 * Reap workers that have marked themselves exited (either via
 * SFTP_OP_EXIT_WORKER sentinel or because their connection died).
 *
 * Two phases for clean locking: collect-under-lock, then join-and-free
 * outside the lock (pthread_join can take arbitrary time).
 *
 * Returns the count of NON-voluntary exits — the caller (reporter)
 * uses this to drive respawn dispatch.  Voluntary exits (worker
 * removed via sftp_parallel_remove_worker sending an EXIT_WORKER
 * sentinel) are reaped but NOT respawned.
 */
static int
reporter_reap_exited_workers(struct sftp_parallel *p)
{
	struct sftp_worker *to_reap[SFTP_PARALLEL_MAX_WORKERS];
	int to_reap_voluntary[SFTP_PARALLEL_MAX_WORKERS];
	int n_reap = 0;

	pthread_mutex_lock(&p->workers_mu);
	for (int i = p->num_workers - 1; i >= 0; i--) {
		struct sftp_worker *w = p->workers[i];
		int exited, voluntary;
		uint64_t bt;
		pthread_mutex_lock(&w->mu);
		exited    = w->exited;
		voluntary = w->exited_voluntary;
		bt        = w->bytes_total;
		/* Capture bytes_total before the worker leaves the array
		 * so the aggregate stays monotonic.  live_bytes was reset
		 * to 0 at the worker's last completion so it is not
		 * double-counted. */
		if (exited)
			p->retired_bytes += bt;
		pthread_mutex_unlock(&w->mu);
		if (exited) {
			to_reap[n_reap] = w;
			to_reap_voluntary[n_reap] = voluntary;
			n_reap++;
			memmove(&p->workers[i],
			    &p->workers[i + 1],
			    (p->num_workers - i - 1) *
			    sizeof(*p->workers));
			p->num_workers--;
		}
	}
	pthread_mutex_unlock(&p->workers_mu);

	int n_to_respawn = 0;
	for (int i = 0; i < n_reap; i++) {
		struct sftp_worker *w = to_reap[i];
		if (!to_reap_voluntary[i])
			n_to_respawn++;
		pthread_join(w->tid, NULL);
		if (w->conn) sftp_free(w->conn);
		if (w->fd_in >= 0) close(w->fd_in);
		if (w->fd_out >= 0) close(w->fd_out);
		if (w->ssh_pid > 0) {
			int s;
			/* Belt-and-suspenders: may already be dead from
			 * SIGTERM above. */
			(void)kill(w->ssh_pid, SIGKILL);
			(void)waitpid(w->ssh_pid, &s, 0);
		}
		pthread_mutex_destroy(&w->mu);
		free(w);
	}
	return n_to_respawn;
}

/*
 * Drive worker respawn dispatch for the reporter's slow tick.  Takes
 * the count of non-voluntary worker exits seen on this tick and:
 *
 *   - absorbs them into respawn_owed (the persistent backlog)
 *   - updates the epoch ceiling / cooldown state machine
 *   - launches detached respawn threads up to the available slots
 *   - aborts the transfer if every worker is gone and recovery is
 *     exhausted (cooldowns spent on an unhealthy path) or if the
 *     workforce has gone to zero with units still pending
 *
 * Returns 1 if the reporter should break out of its main loop (an
 * abort condition fired); 0 otherwise.
 *
 * Cooldown / ceiling policy:
 *   Each epoch allows RESPAWN_MULTIPLIER × num_streams respawns.
 *   On hitting the ceiling: enter a counted cooldown (pause for
 *   RESPAWN_COOLDOWN_SEC, reset epoch).  After RESPAWN_MAX_COOLDOWNS
 *   counted cooldowns, fall through to a throughput gate: if any
 *   worker is still pushing the configured healthy-path floor, grant
 *   an uncounted extension cooldown (warn but continue).  If the
 *   path itself is unhealthy, abort.
 */
static int
reporter_dispatch_respawns(struct sftp_parallel *p, int n_to_respawn)
{
	pthread_mutex_lock(&p->workers_mu);
	int cur_workers  = p->num_workers;
	int respawn_ceil = p->cfg.num_streams * RESPAWN_MULTIPLIER;
	pthread_mutex_unlock(&p->workers_mu);

	/* Absorb this tick's involuntary deaths into the backlog.
	 * respawn_owed carries across cooldowns and pthread_create
	 * failures, so the worker pool drains back up to num_streams
	 * once spawning resumes. */
	if (n_to_respawn > 0)
		p->respawn_owed += n_to_respawn;

	/* Check cooldown: suppress respawns until timer expires. */
	int in_cooldown = 0;
	if (p->respawn_resume_ns != 0) {
		uint64_t now_ns = monotonic_ns();
		if (now_ns < p->respawn_resume_ns) {
			in_cooldown = 1;
		} else {
			debug_ft("respawn cooldown ended, resuming "
			    "(epoch reset, owed=%d)", p->respawn_owed);
			p->respawn_resume_ns = 0;
			p->respawn_epoch_count = 0;
		}
	}

	/* Ceiling check + cooldown entry (only when we owe a respawn
	 * and are not already in cooldown). */
	if (!in_cooldown && p->respawn_owed > 0 &&
	    p->respawn_epoch_count >= respawn_ceil) {
		uint64_t now_ns = monotonic_ns();
		if (p->respawn_cooldown_count < RESPAWN_MAX_COOLDOWNS) {
			/* Counted cooldown. */
			p->respawn_cooldown_count++;
			p->respawn_last_cooldown_ns = now_ns;
			p->respawn_resume_ns = now_ns +
			    (uint64_t)RESPAWN_COOLDOWN_SEC * 1000000000ULL;
			p->respawn_epoch_count = 0;
			in_cooldown = 1;
			error_ft("respawn epoch ceiling reached "
			    "(%d/%d) — entering cooldown %d/%d for %ds; "
			    "healthy workers continue",
			    p->total_respawns, respawn_ceil,
			    p->respawn_cooldown_count,
			    RESPAWN_MAX_COOLDOWNS,
			    RESPAWN_COOLDOWN_SEC);
		} else {
			/* Cooldowns exhausted — throughput gate. */
			int path_ok =
			    (p->cfg.tput_path_healthy_kbps > 0) &&
			    (p->tput_last_raw_max_kbps >=
			     p->cfg.tput_path_healthy_kbps);
			if (path_ok) {
				/* Productive workers remain — extend rather
				 * than killing a partially-complete transfer. */
				p->respawn_resume_ns = now_ns +
				    (uint64_t)RESPAWN_COOLDOWN_SEC *
				    1000000000ULL;
				p->respawn_last_cooldown_ns = now_ns;
				p->respawn_epoch_count = 0;
				in_cooldown = 1;
				error_ft("WARNING: respawn cooldowns "
				    "exhausted but path still healthy "
				    "(max=%llukbps) — extending rather than "
				    "aborting; investigate connection churn",
				    (unsigned long long)
				    p->tput_last_raw_max_kbps);
			} else {
				error_ft("respawn cooldowns exhausted and "
				    "path unhealthy (max=%llukbps) — "
				    "persistent connection failure, "
				    "aborting transfer",
				    (unsigned long long)
				    p->tput_last_raw_max_kbps);
				sftp_parallel_abort(p);
				return 1;
			}
		}
	}

	int target   = p->cfg.num_streams;
	int slots    = target - cur_workers;
	int to_spawn = (!in_cooldown && p->respawn_owed > 0 && slots > 0)
	    ? ((p->respawn_owed < slots) ? p->respawn_owed : slots)
	    : 0;
	if (to_spawn > 0) {
		debug_ft("initiating respawn for %d worker(s) "
		    "(current=%d target=%d owed=%d "
		    "epoch=%d/%d cooldowns=%d/%d)",
		    to_spawn, cur_workers, target,
		    p->respawn_owed,
		    p->respawn_epoch_count + to_spawn, respawn_ceil,
		    p->respawn_cooldown_count, RESPAWN_MAX_COOLDOWNS);
	}
	for (int i = 0; i < to_spawn; i++) {
		if (p->abort_flag || p->stopped)
			break;
		pthread_mutex_lock(&p->workers_mu);
		p->pending_respawns++;
		p->total_respawns++;
		p->respawn_epoch_count++;
		pthread_mutex_unlock(&p->workers_mu);
		pthread_t rtid;
		if (pthread_create(&rtid, NULL,
		    respawn_worker_thread, p) == 0) {
			(void)pthread_detach(rtid);
			/* Drain backlog only on success; a failed create
			 * leaves owed in place so we retry next tick. */
			p->respawn_owed--;
		} else {
			error_ft("respawn thread create failed");
			pthread_mutex_lock(&p->workers_mu);
			p->pending_respawns--;
			p->total_respawns--;
			p->respawn_epoch_count--;
			pthread_mutex_unlock(&p->workers_mu);
		}
	}

	/* If every worker is gone and no respawn is in flight, all
	 * recovery attempts have failed; abort rather than letting
	 * sftp_parallel_wait hang. */
	pthread_mutex_lock(&p->workers_mu);
	int all_gone = (p->num_workers == 0 && p->pending_respawns == 0);
	pthread_mutex_unlock(&p->workers_mu);
	if (all_gone && !p->abort_flag) {
		pthread_mutex_lock(&p->pending_mu);
		int stuck = (p->pending > 0);
		pthread_mutex_unlock(&p->pending_mu);
		if (stuck) {
			error_ft("all workers gone with %llu unit(s) "
			    "pending -- aborting transfer",
			    (unsigned long long)p->pending);
			sftp_parallel_abort(p);
			return 1;
		}
	}
	return 0;
}

static void *
reporter_thread(void *arg)
{
	struct sftp_parallel *p = arg;
	struct timespec sleep_ts = {
		.tv_sec = REPORTER_TICK_MS / 1000,
		.tv_nsec = (REPORTER_TICK_MS % 1000) * 1000000L,
	};
	int slow_tick_counter = 0;

	while (1) {
		nanosleep(&sleep_ts, NULL);
		if (p->stopped)
			break;

		/* Propagate caller's interrupt signal (e.g. SIGINT / Ctrl+C).
		 * sftp_parallel_abort is idempotent; calling it every tick while
		 * the flag stays set is harmless. */
		if (p->ext_interrupt_flag != NULL && *p->ext_interrupt_flag)
			sftp_parallel_abort(p);

		uint64_t bytes;
		snapshot_workers(p, &bytes, NULL, NULL);
		p->aggregate_bytes_for_meter = bytes;
		p->aggregate_progress_counter =
		    (off_t)(bytes - p->progress_bytes_baseline);
		if (p->progress_meter_started)
			refresh_progress_meter(0);

		/* Liveness checks on a slower cadence (every 5 ticks ≈ 1s):
		 * cheaper and watchdog timing doesn't need 200ms granularity. */
		if (++slow_tick_counter >= 5) {
			slow_tick_counter = 0;

			reporter_emit_stats_csv(p);

			/* Stability timer: if no new cooldown was needed for
			 * RESPAWN_STABILITY_SEC, the cluster has been running
			 * cleanly — reset the cooldown count so a very long
			 * transfer doesn't accumulate a fatal count from
			 * isolated churn events spread over hours. */
			if (p->respawn_last_cooldown_ns != 0 &&
			    p->respawn_resume_ns == 0) {
				uint64_t now_ns = monotonic_ns();
				uint64_t stability_ns =
				    (uint64_t)RESPAWN_STABILITY_SEC * 1000000000ULL;
				if (now_ns - p->respawn_last_cooldown_ns
				    > stability_ns) {
					debug_ft("respawn stability window "
					    "expired (%ds clean) — resetting "
					    "cooldown count from %d to 0",
					    RESPAWN_STABILITY_SEC,
					    p->respawn_cooldown_count);
					p->respawn_cooldown_count = 0;
					p->respawn_last_cooldown_ns = 0;
				}
			}

			/* Watchdog classifies workers HEALTHY/STALLED/DEAD
			 * and SIGTERMs newly DEAD ones. We don't abort here;
			 * the reap loop below joins exited workers and spawns
			 * replacements. */
			(void)watchdog_check_workers(p);

			/* Track synchronous stalls (all workers at zero bytes
			 * while work is in flight) as a leading indicator of
			 * write-cache saturation from too many parallel writers.
			 * Observation-only for now; future use as a scale-down
			 * signal. */
			watchdog_check_sync_stall(p);

			int n_to_respawn = reporter_reap_exited_workers(p);

			if (reporter_dispatch_respawns(p, n_to_respawn))
				break;
		}
	}
	return NULL;
}

/* ---------- Public API ---------- */

/*
 * Spawn one worker: SSH child via the master's socket, sftp_init, attach
 * to p->workers[] under workers_mu, then start the thread. Returns the
 * worker on success, NULL on failure (with all resources cleaned up).
 * Used by sftp_parallel_start (during initial bring-up) and
 * sftp_parallel_add_worker (for dynamic scaling).
 */
static struct sftp_worker *
spawn_one_worker(struct sftp_parallel *p)
{
	struct sftp_worker *w = xcalloc(1, sizeof(*w));
	w->parent = p;
	w->fd_in = w->fd_out = -1;
	w->ssh_pid = -1;
	pthread_mutex_init(&w->mu, NULL);

	u_int buflen = p->cfg.transfer_buflen ?
	    p->cfg.transfer_buflen : DEFAULT_TRANSFER_BUFLEN;
	u_int nreq = p->cfg.num_requests ?
	    p->cfg.num_requests : DEFAULT_NUM_REQUESTS;

	if (spawn_worker_ssh(&p->cfg,
	    &w->fd_in, &w->fd_out, &w->ssh_pid) != 0) {
		error_ft("ssh spawn failed");
		goto fail;
	}
	w->conn = sftp_init(w->fd_in, w->fd_out, buflen, nreq,
	    p->cfg.limit_kbps);
	if (w->conn == NULL) {
		error_ft("sftp_init failed");
		goto fail;
	}
	sftp_set_live_counter(w->conn, &w->live_bytes);

	/* Insert into workers array under lock. */
	pthread_mutex_lock(&p->workers_mu);
	if (p->num_workers >= SFTP_PARALLEL_MAX_WORKERS) {
		pthread_mutex_unlock(&p->workers_mu);
		goto fail;
	}
	if (p->num_workers >= p->workers_cap) {
		int newcap = p->workers_cap ? p->workers_cap * 2 : 8;
		if (newcap > SFTP_PARALLEL_MAX_WORKERS)
			newcap = SFTP_PARALLEL_MAX_WORKERS;
		p->workers = xreallocarray(p->workers, newcap,
		    sizeof(*p->workers));
		p->workers_cap = newcap;
	}
	w->id = p->next_worker_id++;
	p->workers[p->num_workers++] = w;
	pthread_mutex_unlock(&p->workers_mu);

	if (pthread_create(&w->tid, NULL, worker_thread, w) != 0) {
		error_ft("pthread_create failed");
		/* Roll back insertion. */
		pthread_mutex_lock(&p->workers_mu);
		for (int i = 0; i < p->num_workers; i++) {
			if (p->workers[i] == w) {
				memmove(&p->workers[i], &p->workers[i + 1],
				    (p->num_workers - i - 1) *
				    sizeof(*p->workers));
				p->num_workers--;
				break;
			}
		}
		pthread_mutex_unlock(&p->workers_mu);
		goto fail;
	}
	w->started = 1;
	return w;

 fail:
	if (w->conn) sftp_free(w->conn);
	if (w->fd_in >= 0) close(w->fd_in);
	if (w->fd_out >= 0) close(w->fd_out);
	if (w->ssh_pid > 0) {
		int s;
		(void)waitpid(w->ssh_pid, &s, 0);
	}
	pthread_mutex_destroy(&w->mu);
	free(w);
	return NULL;
}

/* ---------- Parallel spawn helper ---------- */

/*
 * Concurrency limiter for the auth phase: at most max_in_flight workers
 * hold an unauthenticated SSH connection open simultaneously.  This keeps
 * us well under the server's MaxStartups limit (default 10:30:100) even
 * when spawning many workers.  A fixed sleep-based stagger is not used
 * because the right limit depends on actual handshake duration, which
 * varies with RTT and any tc-netem delay in effect.
 */
struct spawn_ctx {
	struct sftp_parallel *p;
	pthread_mutex_t      *auth_mu;
	pthread_cond_t       *auth_cv;
	int                  *auth_in_flight;
	int                  *started;		/* workers that have begun connecting */
	int                   total;		/* cfg->num_streams */
	int                   max_in_flight;
	int                   succeeded;
};

static void *
do_parallel_spawn(void *arg)
{
	struct spawn_ctx *ctx = arg;

	pthread_mutex_lock(ctx->auth_mu);
	while (*ctx->auth_in_flight >= ctx->max_in_flight)
		pthread_cond_wait(ctx->auth_cv, ctx->auth_mu);
	++*ctx->auth_in_flight;
	int started = ++*ctx->started;
	pthread_mutex_unlock(ctx->auth_mu);

	if (ctx->p->cfg.print_flag != SFTP_QUIET) {
		if (started % ctx->max_in_flight == 0 || started == ctx->total)
			fprintf(stderr, "Connecting workers %d of %d\n",
			    started, ctx->total);
	}

	ctx->succeeded = (spawn_one_worker(ctx->p) != NULL) ? 1 : 0;

	pthread_mutex_lock(ctx->auth_mu);
	--*ctx->auth_in_flight;
	pthread_cond_signal(ctx->auth_cv);
	pthread_mutex_unlock(ctx->auth_mu);

	return NULL;
}

/* ---------- Public API ---------- */

struct sftp_parallel *
sftp_parallel_start(const struct sftp_parallel_config *cfg)
{
	if (cfg == NULL || cfg->host == NULL || cfg->num_streams < 1 ||
	    cfg->num_streams > SFTP_PARALLEL_MAX_WORKERS) {
		errno = EINVAL;
		return NULL;
	}

	struct sftp_parallel *p = xcalloc(1, sizeof(*p));
	p->cfg = *cfg;
	/* cfg.port may point to a stack buffer in the caller that is only
	 * valid until the enclosing scope exits.  Copy it into p->cfg_port_buf
	 * so the orchestrator owns the string for its entire lifetime. */
	if (cfg->port && cfg->port[0]) {
		strlcpy(p->cfg_port_buf, cfg->port, sizeof(p->cfg_port_buf));
		p->cfg.port = p->cfg_port_buf;
	}
	pthread_mutex_init(&p->pending_mu, NULL);
	pthread_cond_init(&p->pending_cv, NULL);
	pthread_mutex_init(&p->workers_mu, NULL);

	p->session_start_ns = monotonic_ns();

	/* Cap chosen so the worst-case allocation is bounded but the
	 * "show me what failed" list is still useful for moderately
	 * broken transfers.  HPN_FAILED_PATHS_MAX × ~256 bytes typical
	 * = ~25 KiB at the default cap. */
	hpn_strlist_init(&p->failed_paths, HPN_FAILED_PATHS_MAX);

	/* 1. Workqueue. Sized for cfg->num_streams; if workers are added
	 * later via sftp_parallel_add_worker, capacity stays the same.
	 * That's fine — capacity is just backpressure, not a hard cap. */
	p->q = sftp_workqueue_new(WORK_QUEUE_DEPTH(cfg->num_streams));
	if (p->q == NULL) {
		error_f("workqueue allocation failed");
		goto fail;
	}

	/* 2. Suppress per-file progress in workers; the orchestrator drives
	 * aggregate progress when requested via sftp_parallel_progress_*. */
	p->saved_showprogress = showprogress;
	showprogress = 0;

	/* 3. Spawn workers in parallel to overlap SSH handshakes, but cap
	 * the number of simultaneous unauthenticated connections to stay
	 * under the server's MaxStartups limit (default 10:30:100). */
	{
		int n = cfg->num_streams;
		int max_in_flight = cfg->max_auth_concurrent > 0
		    ? cfg->max_auth_concurrent : 8;
		int               auth_in_flight = 0;
		int               started = 0;
		pthread_mutex_t   auth_mu;
		pthread_cond_t    auth_cv;
		struct spawn_ctx  sctx[SFTP_PARALLEL_MAX_WORKERS];
		pthread_t         stids[SFTP_PARALLEL_MAX_WORKERS];
		int               failed = 0;

		pthread_mutex_init(&auth_mu, NULL);
		pthread_cond_init(&auth_cv, NULL);

		for (int i = 0; i < n; i++) {
			sctx[i].p              = p;
			sctx[i].auth_mu        = &auth_mu;
			sctx[i].auth_cv        = &auth_cv;
			sctx[i].auth_in_flight = &auth_in_flight;
			sctx[i].started        = &started;
			sctx[i].total          = n;
			sctx[i].max_in_flight  = max_in_flight;
			sctx[i].succeeded      = 0;
			if (pthread_create(&stids[i], NULL,
			    do_parallel_spawn, &sctx[i]) != 0) {
				error_ft("spawn thread %d failed", i);
				/* Join threads already launched. */
				for (int j = 0; j < i; j++)
					pthread_join(stids[j], NULL);
				pthread_mutex_destroy(&auth_mu);
				pthread_cond_destroy(&auth_cv);
				goto fail;
			}
		}
		for (int i = 0; i < n; i++) {
			pthread_join(stids[i], NULL);
			if (!sctx[i].succeeded) {
				error_ft("worker %d setup failed", i);
				failed = 1;
			}
		}
		pthread_mutex_destroy(&auth_mu);
		pthread_cond_destroy(&auth_cv);
		if (failed)
			goto fail;
	}

	/* 4. Reporter — best-effort. */
	if (pthread_create(&p->reporter_tid, NULL, reporter_thread, p) == 0)
		p->reporter_started = 1;

	p->started = 1;
	return p;

 fail:
	sftp_parallel_stop(p);
	return NULL;
}

static int
submit(struct sftp_parallel *p, struct sftp_work_unit *u)
{
	if (p == NULL || p->stopped || p->abort_flag) {
		free_unit(u);
		return -1;
	}
	uint64_t add_bytes = (u->size > 0) ? (uint64_t)u->size : 0;
	pthread_mutex_lock(&p->pending_mu);
	p->pending++;
	pthread_mutex_unlock(&p->pending_mu);
	if (pending_trace_on())
		pending_trace("INC", p, u, -1, "submit");
	if (add_bytes)
		__atomic_fetch_add(&p->queued_bytes, add_bytes,
		    __ATOMIC_RELAXED);
	if (sftp_workqueue_push(p->q, u) != 0) {
		pthread_mutex_lock(&p->pending_mu);
		if (p->pending > 0) p->pending--;
		pthread_mutex_unlock(&p->pending_mu);
		if (pending_trace_on())
			pending_trace("DEC_PUSHFAIL", p, u, -1,
			    "submit/pushfail");
		if (add_bytes)
			__atomic_fetch_sub(&p->queued_bytes, add_bytes,
			    __ATOMIC_RELAXED);
		free_unit(u);
		return -1;
	}
	return 0;
}

/* Defined later in this file. */
static int submit_upload_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode);
static int submit_download_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode);

int
sftp_parallel_submit_upload(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path, off_t size, mode_t mode)
{
	/* When a control connection is supplied, route through the
	 * speculative-split decision so a single large file produces
	 * multiple range work units (feeds the byte-based scale-up
	 * trigger).  Otherwise, fall back to a whole-file unit. */
	if (conn != NULL)
		return submit_upload_maybe_split(p, conn, local_path, remote_path,
		    size, mode);
	return submit(p,
	    make_unit(SFTP_OP_UPLOAD, local_path, remote_path, size, mode));
}

int
sftp_parallel_submit_download(struct sftp_parallel *p,
    struct sftp_conn *conn,
    const char *remote_path, const char *local_path, off_t size, mode_t mode)
{
	if (conn != NULL)
		return submit_download_maybe_split(p, conn, remote_path, local_path,
		    size, mode);
	return submit(p,
	    make_unit(SFTP_OP_DOWNLOAD, remote_path, local_path, size, mode));
}

int
sftp_parallel_submit_mkdir(struct sftp_parallel *p,
    const char *remote_path, mode_t mode)
{
	return submit(p,
	    make_unit(SFTP_OP_MKDIR, NULL, remote_path, 0, mode));
}

void
sftp_parallel_wait(struct sftp_parallel *p)
{
	if (p == NULL) return;
	pthread_mutex_lock(&p->pending_mu);
	while (p->pending > 0 && !p->abort_flag)
		pthread_cond_wait(&p->pending_cv, &p->pending_mu);
	pthread_mutex_unlock(&p->pending_mu);
}

void
sftp_parallel_abort(struct sftp_parallel *p)
{
	if (p == NULL) return;
	p->abort_flag = 1;
	if (p->q)
		sftp_workqueue_shutdown(p->q);

	/*
	 * Close every worker's SSH FDs.  Without this, a worker blocked in
	 * get_msg / send_msg on the SSH socket won't notice abort_flag
	 * until the server eventually drops the connection (seconds to
	 * minutes).  Closing the FD here makes the blocked read return
	 * EBADF / 0 immediately; the worker propagates the I/O failure,
	 * exits execute_unit, sees abort_flag at the top of its loop, and
	 * thread-exits within milliseconds.  pthread_join in
	 * sftp_parallel_free can then return promptly.
	 *
	 * Set the FD to -1 after closing so teardown_worker_ssh (called
	 * later from sftp_parallel_free) is a no-op for these slots and
	 * doesn't double-close a (potentially reused) FD number.
	 *
	 * Policy: abort means abort.  We do not gracefully drain in-flight
	 * RPCs — the user (or the orchestrator detecting an
	 * unrecoverable condition) has asked us to stop.
	 */
	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		if (w == NULL)
			continue;
		if (w->fd_in >= 0) {
			(void)close(w->fd_in);
			w->fd_in = -1;
		}
		if (w->fd_out >= 0) {
			(void)close(w->fd_out);
			w->fd_out = -1;
		}
	}
	pthread_mutex_unlock(&p->workers_mu);

	pthread_mutex_lock(&p->pending_mu);
	pthread_cond_broadcast(&p->pending_cv);
	pthread_mutex_unlock(&p->pending_mu);
}

void
sftp_parallel_set_interrupt_flag(struct sftp_parallel *p,
    volatile sig_atomic_t *flag)
{
	if (p != NULL)
		p->ext_interrupt_flag = flag;
}

void
sftp_parallel_set_path_rtt(struct sftp_parallel *p, uint64_t rtt_us)
{
	if (p != NULL)
		p->path_rtt_us = rtt_us;
}

void
sftp_parallel_stop(struct sftp_parallel *p)
{
	if (p == NULL || p->stopped) {
		if (p) p->stopped = 1;
		return;
	}
	p->stopped = 1;

	if (p->q)
		sftp_workqueue_shutdown(p->q);

	if (p->workers) {
		/* Iterate without holding workers_mu during pthread_join (it
		 * would block). At this point p->stopped is set and the
		 * queue is shut down, so no concurrent add/remove can happen
		 * from the public API. The reporter may still be reaping
		 * exited workers, which is why we join the reporter LATER —
		 * after walking workers ourselves we accept that the reporter
		 * may have removed some entries; we only join() those still
		 * present. */
		pthread_mutex_lock(&p->workers_mu);
		int n = p->num_workers;
		struct sftp_worker **snap = NULL;
		if (n > 0) {
			snap = xcalloc(n, sizeof(*snap));
			memcpy(snap, p->workers, n * sizeof(*snap));
		}
		pthread_mutex_unlock(&p->workers_mu);

		for (int i = 0; i < n; i++) {
			if (snap[i]->started)
				pthread_join(snap[i]->tid, NULL);
		}
		free(snap);
	}
	if (p->reporter_started)
		pthread_join(p->reporter_tid, NULL);

	if (p->stats_csv != NULL) {
		fclose(p->stats_csv);
		p->stats_csv = NULL;
	}

	if (p->workers) {
		/* Reporter is now joined — no more concurrent reaping. We
		 * own everything still in p->workers; tear it down. */
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			if (w == NULL) continue;
			if (w->conn) {
				sftp_free(w->conn);
				w->conn = NULL;
			}
			teardown_worker_ssh(w);
			pthread_mutex_destroy(&w->mu);
			free(w);
		}
		free(p->workers);
		p->workers = NULL;
		p->num_workers = 0;
		p->workers_cap = 0;
	}

	if (p->q) {
		sftp_workqueue_free(p->q);
		p->q = NULL;
	}

	/* Restore the user's progress preference. */
	showprogress = p->saved_showprogress;

	pthread_mutex_destroy(&p->pending_mu);
	pthread_cond_destroy(&p->pending_cv);
	pthread_mutex_destroy(&p->workers_mu);
	hpn_strlist_free(&p->failed_paths);
	free(p);
}

static void
scan_upload_recursive(const char *src, off_t *bytes_out, long *files_out)
{
	struct stat sb;
	DIR *dirp;
	struct dirent *dp;
	char *child = NULL;

	if (lstat(src, &sb) == -1)
		return;
	if (S_ISREG(sb.st_mode)) {
		*bytes_out += sb.st_size;
		(*files_out)++;
		return;
	}
	if (!S_ISDIR(sb.st_mode))
		return;
	if ((dirp = opendir(src)) == NULL)
		return;
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;
		free(child);
		xasprintf(&child, "%s/%s", src, dp->d_name);
		scan_upload_recursive(child, bytes_out, files_out);
	}
	free(child);
	closedir(dirp);
}

off_t
sftp_parallel_scan_upload_total(const char *src, long *file_count_out)
{
	off_t bytes = 0;
	long files = 0;

	scan_upload_recursive(src, &bytes, &files);
	if (file_count_out != NULL)
		*file_count_out = files;
	return bytes;
}

void
sftp_parallel_progress_start(struct sftp_parallel *p, const char *label,
    off_t total_bytes)
{
	if (p == NULL || p->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	strlcpy(p->progress_label, label, sizeof(p->progress_label));
	/* Snapshot current accumulated bytes across all workers so the meter
	 * shows only bytes moved in this transfer, not prior transfers in the
	 * same session. */
	snapshot_workers(p, &p->progress_bytes_baseline, NULL, NULL);
	p->aggregate_progress_counter = 0;
	start_progress_meter(p->progress_label, total_bytes,
	    &p->aggregate_progress_counter);
	p->progress_meter_started = 1;
}

void
sftp_parallel_progress_stop(struct sftp_parallel *p)
{
	if (p == NULL || !p->progress_meter_started)
		return;
	p->progress_meter_started = 0;
	stop_progress_meter();
}

uint64_t
sftp_parallel_bytes_total(struct sftp_parallel *p)
{
	if (p == NULL) return 0;
	uint64_t b;
	snapshot_workers(p, &b, NULL, NULL);
	return b;
}

uint64_t
sftp_parallel_units_completed(struct sftp_parallel *p)
{
	if (p == NULL) return 0;
	uint64_t c;
	snapshot_workers(p, NULL, &c, NULL);
	return c;
}

uint64_t
sftp_parallel_units_failed(struct sftp_parallel *p)
{
	if (p == NULL) return 0;
	uint64_t f;
	snapshot_workers(p, NULL, NULL, &f);
	return f;
}

/* ---------- Recursive walkers (Approach B) ----------
 *
 * The walker runs on the producer (caller) thread and uses the control
 * connection (`conn`) for metadata operations: mkdir on the destination
 * tree, readdir/stat for downloads. Regular files are handed to the
 * orchestrator via submit_*; the workers transfer them in parallel while
 * the walker continues descending. The caller is expected to call
 * sftp_parallel_wait after the walker returns.
 *
 * Mirrors the structure of upload_dir_internal / download_dir_internal in
 * sftp-client.c. Symlinks honor the orchestrator's follow_link_flag;
 * non-regular files are skipped with a warning, matching legacy behavior.
 */

#define PARALLEL_MAX_DIR_DEPTH 64

/*
 * Pre-create remote file at the correct size, then split the local file
 * into num_ranges byte ranges and submit one SFTP_OP_UPLOAD_RANGE work unit
 * per range.  The pre-creation step (open+setstat+close) is synchronous on
 * conn so all ranges see a fully allocated remote file before any worker
 * starts writing.
 *
 * range_size    — size of each range in bytes (last range may be shorter)
 * num_ranges    — number of ranges; must be >= 2
 *
 * Returns 0 if all ranges were submitted, -1 on pre-creation failure (caller
 * should fall back to a single whole-file upload unit).
 */
static int
submit_upload_ranges(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode,
    off_t range_size, int num_ranges)
{
	int i, effective_ranges = 0;
	struct sftp_range_tracker *tracker = NULL;

	/* Pre-create remote file with O_CREAT|O_TRUNC at the correct size. */
	if (sftp_precreate(conn, remote_path, file_size) != 0) {
		error("pre-create \"%s\" failed", remote_path);
		return -1;
	}

	debug("range-split upload \"%s\": %d ranges of %lld bytes "
	    "(%.1f MiB each)", remote_path, num_ranges,
	    (long long)range_size, (double)range_size / (1024.0*1024.0));

	/* Count effective (positive-length) ranges first so the tracker
	 * knows the exact number of completions to wait for.  Mirrors the
	 * download path; see submit_download_ranges for rationale. */
	for (i = 0; i < num_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == num_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (length <= 0)
			break;
		effective_ranges++;
	}
	if (effective_ranges == 0)
		return -1;

	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_REMOTE, remote_path);

	/* Submit one SFTP_OP_UPLOAD_RANGE work unit per range. */
	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (submit(p, make_range_unit(local_path, remote_path,
		    offset, length, tracker)) != 0) {
			error("submit range %d of \"%s\" failed",
			    i, local_path);
			/* Synthesise failures for ranges we never submitted
			 * so the tracker reaches remaining=0 and removes the
			 * (now-corrupt) remote file.  NULL worker is fine —
			 * the REMOTE branch logs loudly if it can't remove. */
			int unsent;
			for (unsent = i; unsent < effective_ranges; unsent++)
				(void)range_tracker_finalize(tracker, 1, NULL);
			return -1;
		}
	}
	return 0;
}

/*
 * Validate / normalise stripe_size for use as a chunk-boundary alignment
 * unit.  Returns 1 if we have a usable stripe_size and the caller may
 * align byte-ranges to it; 0 means fall back to plain even division.
 *
 * Mutates *info in place for the GPFS heuristic only: GPFS exposes no
 * per-OST stripe via SFTP fs-info, so we substitute its statvfs
 * block_size as the alignment unit.  Other filesystems are taken at
 * face value — only stripe_size matters downstream, and overly-large
 * values simply collapse range-splitting back toward whole-file
 * uploads (the alignment-up-to-stripe rounding pushes per_range past
 * file_size), which is harmless.
 */
static int
stripe_info_viable(struct sftp_fs_info *info, const char *path)
{
	if (strcmp(info->fs_type, "gpfs") == 0 && info->stripe_size == 0) {
		/* Valid GPFS block sizes are 256 KiB–16 MiB per IBM
		 * Spectrum Scale docs; anything else is a bogus statvfs
		 * return or a fs_type false positive.  Bail rather than
		 * guessing. */
		if (info->block_size < 256 * 1024 ||
		    info->block_size > 16 * 1024 * 1024) {
			logit("hpn-fs-info: GPFS detected but block_size=%llu"
			    " is outside the valid range (256 KiB–16 MiB);"
			    " skipping stripe alignment for \"%s\"",
			    (unsigned long long)info->block_size, path);
			return 0;
		}
		info->stripe_size = info->block_size;
		debug3("hpn-fs-info: gpfs, using block_size=%llu as alignment unit",
		    (unsigned long long)info->stripe_size);
	}
	return info->stripe_size > 0;
}

/*
 * One-shot lazy fs-info accessor.  Both submit_upload_maybe_split and
 * submit_download_maybe_split need the destination filesystem's stripe geometry
 * for chunk alignment; we query it once and cache it on the orchestrator.
 * Returns 1 if we got usable stripe info, 0 if alignment should fall back
 * to plain file_size/num_ranges.  Output goes in *info_out (caller may
 * inspect info->stripe_size etc).
 */
static int
get_cached_fs_info(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, struct sftp_fs_info *info_out)
{
	if (p->fs_info_cached) {
		*info_out = p->fs_info_cache;
	} else {
		memset(info_out, 0, sizeof(*info_out));
		sftp_fs_info(conn, remote_path, info_out);
		p->fs_info_cache = *info_out;
		p->fs_info_cached = 1;
	}
	return stripe_info_viable(info_out, remote_path);
}

/*
 * Resolve the range-split minimum file size, in bytes.  Precedence:
 *   1. cfg.range_split_min_mb (set by -M CLI flag, sftp.c)
 *   2. RANGE_SPLIT_MIN_SIZE_DEFAULT (2 GiB)
 *
 * Values are clamped to [FLOOR, CEILING] = [64 MiB, 10 GiB].  Logs the
 * chosen value once per orchestrator at default verbosity.
 */
static uint64_t
range_split_min_size_for(struct sftp_parallel *p)
{
	uint64_t bytes;
	const char *source;

	if (p->cfg.range_split_min_mb > 0) {
		bytes = (uint64_t)p->cfg.range_split_min_mb * 1024ULL * 1024ULL;
		source = "-M";
	} else {
		bytes = RANGE_SPLIT_MIN_SIZE_DEFAULT;
		source = "default";
	}

	if (bytes < RANGE_SPLIT_MIN_SIZE_FLOOR)
		bytes = RANGE_SPLIT_MIN_SIZE_FLOOR;
	if (bytes > RANGE_SPLIT_MIN_SIZE_CEILING)
		bytes = RANGE_SPLIT_MIN_SIZE_CEILING;

	static struct sftp_parallel *logged_for;
	if (logged_for != p) {
		logit("range-split threshold = %llu MiB (source: %s)",
		    (unsigned long long)(bytes / (1024ULL*1024ULL)),
		    source);
		logged_for = p;
	}
	return bytes;
}

/*
 * Pre-create a local file at exactly size bytes so that parallel range-download
 * workers can open it O_WRONLY and write their ranges concurrently without
 * racing on creation.
 */
static int
precreate_local(const char *local_path, off_t size, mode_t mode)
{
	int fd;

	if (mode == 0)
		mode = 0644;
	fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, mode | S_IWUSR);
	if (fd < 0) {
		error("local pre-create \"%s\": %s", local_path,
		    strerror(errno));
		return -1;
	}
	if (ftruncate(fd, size) < 0) {
		error("local ftruncate \"%s\" to %lld: %s",
		    local_path, (long long)size, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static struct sftp_work_unit *
make_download_range_unit(const char *remote_path, const char *local_path,
    off_t range_offset, off_t range_length,
    struct sftp_range_tracker *tracker)
{
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op            = SFTP_OP_DOWNLOAD_RANGE;
	u->src_path      = xstrdup(remote_path);
	u->dst_path      = xstrdup(local_path);
	u->size          = range_length;
	u->range_offset  = range_offset;
	u->range_length  = range_length;
	u->range_tracker = tracker;
	return u;
}

/*
 * Pre-create the local file at file_size, then split the remote file into
 * num_ranges byte ranges and submit one SFTP_OP_DOWNLOAD_RANGE work unit
 * per range.
 *
 * Returns 0 if all ranges were submitted, -1 on pre-creation failure (caller
 * should fall back to a single whole-file download unit).
 */
static int
submit_download_ranges(struct sftp_parallel *p,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode,
    off_t range_size, int num_ranges)
{
	int i, effective_ranges = 0;
	struct sftp_range_tracker *tracker = NULL;

	if (precreate_local(local_path, file_size, mode) != 0) {
		error("local pre-create \"%s\" failed", local_path);
		return -1;
	}

	debug("range-split download \"%s\": %d ranges of %lld bytes "
	    "(%.1f MiB each)", remote_path, num_ranges,
	    (long long)range_size, (double)range_size / (1024.0*1024.0));

	/* Count ranges with positive length first so the tracker knows the
	 * exact number of completions to wait for.  A trailing range may be
	 * vacuous if the caller's range_size × num_ranges rounded past
	 * file_size. */
	for (i = 0; i < num_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == num_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (length <= 0)
			break;
		effective_ranges++;
	}
	if (effective_ranges == 0)
		return -1;

	tracker = range_tracker_new(effective_ranges,
	    SFTP_RANGE_TARGET_LOCAL, local_path);

	for (i = 0; i < effective_ranges; i++) {
		off_t offset = (off_t)i * range_size;
		off_t length = (i == effective_ranges - 1) ?
		    (file_size - offset) : range_size;
		if (submit(p, make_download_range_unit(remote_path, local_path,
		    offset, length, tracker)) != 0) {
			error("submit download range %d of \"%s\" failed",
			    i, remote_path);
			/* Synthesise failures for ranges we never submitted
			 * so the tracker reaches remaining=0 and unlinks the
			 * corrupt local file.  Without this the tracker
			 * leaks and the file is silently left behind.  No
			 * worker context here, so pass NULL — local target
			 * uses unlink() and doesn't need it. */
			int unsent;
			for (unsent = i; unsent < effective_ranges; unsent++)
				(void)range_tracker_finalize(tracker, 1, NULL);
			return -1;
		}
	}
	return 0;
}

static int
submit_download_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *remote_path, const char *local_path,
    off_t file_size, mode_t mode)
{
	struct sftp_fs_info info;
	off_t range_size;
	int num_ranges, max_ranges;

	/* Range splitting requires a known file size.  Callers always pass it:
	 *   - recursive walk      — from the SFTP directory listing
	 *   - upload              — from the local stat
	 *   - process_get (sftp.c) — from the glob attrib cache (free, since
	 *                            glob already stat'd via fudge_stat), with
	 *                            an explicit stat as defensive fallback.
	 * If size is still zero here (very small file or unknown), fall back
	 * to whole-file. */
	if (file_size <= 0)
		goto whole_file;

	/* Static-floor fast path: files clearly below any plausible
	 * threshold can short-circuit without paying for the fs-info RTT. */
	if ((uint64_t)file_size < RANGE_SPLIT_MIN_SIZE_FLOOR)
		goto whole_file;

	{
		uint64_t min_split =
		    range_split_min_size_for(p);
		if ((uint64_t)file_size < min_split)
			goto whole_file;
	}

	/* Diagnostic / testing escape hatch: HPN_NO_RANGE_SPLIT=1 in the
	 * environment forces the whole-file path so we can compare pure
	 * multi-file parallelism (one worker per file) against the
	 * range-split path on the same workload. */
	{
		/* ENV-VAR HPN_NO_RANGE_SPLIT — developer-only: kill switch for
		 * range-splitting (force whole-file upload).  A/B test and
		 * diagnostic only; not user-facing. */
		const char *no_split = getenv("HPN_NO_RANGE_SPLIT");
		if (no_split && *no_split && *no_split != '0')
			goto whole_file;
	}

	/* Each file is split into RANGE_CHUNK_MULTIPLIER × num_streams chunks.
	 * Bounded by file_size / effective_min so chunks stay above
	 * the splitting floor.  Fast workers absorbing additional chunks
	 * naturally limits the tail-straggler impact of a slow OST. */
	int base = p->cfg.num_streams;
	if (base < 1) base = 1;
	if (base > SFTP_PARALLEL_MAX_WORKERS)
		base = SFTP_PARALLEL_MAX_WORKERS;
	int by_size = (int)(file_size /
	    range_split_min_size_for(p));
	int want = base * RANGE_CHUNK_MULTIPLIER;
	max_ranges = (by_size < want) ? by_size : want;
	if (max_ranges < 2)
		goto whole_file;

	/* Same rationale as submit_upload_maybe_split: stripe-aligned when geometry
	 * is available, plain file_size/num_ranges otherwise. */
	int have_stripe = get_cached_fs_info(p, conn, remote_path, &info);
	num_ranges = max_ranges;
	if (num_ranges < 2)
		goto whole_file;

	{
		off_t per_range = (file_size + num_ranges - 1) / num_ranges;
		if (have_stripe && info.stripe_size > 0) {
			off_t stripe = (off_t)info.stripe_size;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		} else {
			range_size = per_range;
		}
	}

	if (submit_download_ranges(p, remote_path, local_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* Pre-creation failed — fall back to whole-file. */

 whole_file:
	return submit(p, make_unit(SFTP_OP_DOWNLOAD, remote_path, local_path,
	    file_size, mode));
}

/*
 * Decide whether and how to range-split a large file, then either submit
 * range units (via submit_upload_ranges) or fall back to a whole-file unit.
 *
 * Two range-split modes:
 *   - Stripe-aligned: when hpn-fs-info reports valid Lustre/GPFS stripe
 *     geometry, each range is rounded up to a stripe boundary so adjacent
 *     ranges target different OSTs.
 *   - Plain: when no stripe info is available (ext4/xfs/NFS/etc.), ranges
 *     are simply file_size / num_ranges.  The server pwrite()s into a
 *     pre-allocated file; whether the underlying FS actually parallelises
 *     those writes is filesystem-dependent, but exercised in practice on
 *     ext4 (juliet) without measurable regression vs. whole-file.
 */
static int
submit_upload_maybe_split(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *local_path, const char *remote_path,
    off_t file_size, mode_t mode)
{
	struct sftp_fs_info info;
	off_t range_size;
	int num_ranges, max_ranges;

	/* Static-floor fast path: avoid the fs-info RTT for clearly
	 * too-small files. */
	if ((uint64_t)file_size < RANGE_SPLIT_MIN_SIZE_FLOOR)
		goto whole_file;

	{
		uint64_t min_split =
		    range_split_min_size_for(p);
		if ((uint64_t)file_size < min_split)
			goto whole_file;
	}

	/* HPN_NO_RANGE_SPLIT=1 escape hatch, mirroring submit_upload_maybe_split. */
	{
		/* ENV-VAR HPN_NO_RANGE_SPLIT — developer-only: kill switch for
		 * range-splitting (same as upload-side use, download path). */
		const char *no_split = getenv("HPN_NO_RANGE_SPLIT");
		if (no_split && *no_split && *no_split != '0')
			goto whole_file;
	}

	/* Same rationale as submit_upload_maybe_split: RANGE_CHUNK_MULTIPLIER ×
	 * num_streams chunks, bounded by file_size / effective_min. */
	int base = p->cfg.num_streams;
	if (base < 1) base = 1;
	if (base > SFTP_PARALLEL_MAX_WORKERS)
		base = SFTP_PARALLEL_MAX_WORKERS;
	int by_size = (int)(file_size /
	    range_split_min_size_for(p));
	int want = base * RANGE_CHUNK_MULTIPLIER;
	max_ranges = (by_size < want) ? by_size : want;
	if (max_ranges < 2)
		goto whole_file;

	/* fs-info costs one RTT on the control connection.  Cache the
	 * answer per orchestrator (cached on p): the destination filesystem
	 * does not change within a transfer, and querying every file at high
	 * RTT starves the workers. */
	/* When stripe geometry is available (Lustre/GPFS), align each range
	 * to a stripe boundary so adjacent ranges target different OSTs.
	 * Otherwise (ext4/xfs/NFS/etc., where sftp_fs_info returned no stripe
	 * data), fall back to plain file_size/num_ranges chunks.  The server
	 * pwrite()s into a pre-allocated file; whether the underlying FS
	 * actually parallelises those writes is filesystem-dependent. */
	int have_stripe = get_cached_fs_info(p, conn, remote_path, &info);
	num_ranges = max_ranges;
	if (num_ranges < 2)
		goto whole_file;

	{
		off_t per_range = (file_size + num_ranges - 1) / num_ranges;
		if (have_stripe && info.stripe_size > 0) {
			off_t stripe = (off_t)info.stripe_size;
			range_size = ((per_range + stripe - 1) / stripe) * stripe;
		} else {
			range_size = per_range;
		}
	}

	if (submit_upload_ranges(p, conn, local_path, remote_path,
	    file_size, mode, range_size, num_ranges) == 0)
		return 0;
	/* Pre-creation failed — fall back to whole-file. */

 whole_file:
	return submit(p, make_unit(SFTP_OP_UPLOAD, local_path, remote_path,
	    file_size, mode));
}


/* ----------------------------------------------------------------
 * Read-only accessors for walker-helper fields.  Exposed so the
 * recursive walkers in sftp-parallel-walk.c can read config and
 * abort state without seeing struct sftp_parallel's internals.
 * ---------------------------------------------------------------- */

int
sftp_parallel_preserve_flag(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->cfg.preserve_flag : 0;
}

int
sftp_parallel_follow_link_flag(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->cfg.follow_link_flag : 0;
}

int
sftp_parallel_is_aborting(const struct sftp_parallel *p)
{
	return (p != NULL) ? p->abort_flag : 0;
}

/* ---------- Stats accessor (programmatic observability) ---------- */

void
sftp_parallel_get_stats(struct sftp_parallel *p,
    struct sftp_parallel_stats *out)
{
	if (out == NULL) return;
	memset(out, 0, sizeof(*out));
	if (p == NULL) return;

	uint64_t b = 0, c = 0, f = 0;
	pthread_mutex_lock(&p->workers_mu);
	out->num_workers        = p->num_workers;
	out->protocol_violations = p->protocol_violations;
	out->total_respawns      = p->total_respawns;
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		b += w->bytes_total;
		c += w->units_completed;
		f += w->units_failed;
		pthread_mutex_unlock(&w->mu);
	}
	pthread_mutex_unlock(&p->workers_mu);

	out->bytes_total_aggregate = b;
	out->units_completed_aggregate = c;
	out->units_failed_aggregate = f;
	out->walker_failures_aggregate =
	    __atomic_load_n(&p->walker_failures, __ATOMIC_RELAXED);

	if (p->session_start_ns != 0)
		out->elapsed_ms =
		    (monotonic_ns() - p->session_start_ns) / 1000000ULL;
	if (p->q) {
		out->queue_depth = sftp_workqueue_depth(p->q);
		out->queue_high_watermark = sftp_workqueue_high_watermark(p->q);
		/* queue capacity isn't directly queryable; derive from
		 * the formula used at construction. Slightly indirect but
		 * stable. */
		out->queue_capacity = WORK_QUEUE_DEPTH(p->cfg.num_streams);
	}
}

uint64_t
sftp_parallel_drain_failed_paths(struct sftp_parallel *p,
    char ***out_paths, size_t *out_used)
{
	if (p == NULL) {
		if (out_paths != NULL) *out_paths = NULL;
		if (out_used  != NULL) *out_used  = 0;
		return 0;
	}
	return hpn_strlist_drain(&p->failed_paths, out_paths, out_used);
}


/* ---------- Dynamic worker scaling ---------- */

int
sftp_parallel_add_worker(struct sftp_parallel *p)
{
	if (p == NULL || p->stopped || p->abort_flag) {
		errno = EINVAL;
		return -1;
	}
	struct sftp_worker *w = spawn_one_worker(p);
	return (w == NULL) ? -1 : 0;
}

int
sftp_parallel_remove_worker(struct sftp_parallel *p)
{
	if (p == NULL || p->stopped || p->abort_flag) {
		errno = EINVAL;
		return -1;
	}
	pthread_mutex_lock(&p->workers_mu);
	if (p->num_workers <= 1) {
		pthread_mutex_unlock(&p->workers_mu);
		return -1;
	}
	pthread_mutex_unlock(&p->workers_mu);

	/* Submit an exit sentinel; whichever worker pops it next will
	 * exit at the next iteration of its loop. The reporter thread
	 * reaps the exited worker. */
	struct sftp_work_unit *u = xcalloc(1, sizeof(*u));
	u->op = SFTP_OP_EXIT_WORKER;
	if (sftp_workqueue_push(p->q, u) != 0) {
		free(u);
		return -1;
	}
	return 0;
}
