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
 * sftp-parallel-internal.h - shared internal state for the parallel
 * SFTP orchestrator module family (sftp-parallel*.c). It is internal to
 * the parallel module files and should not be included elsewhere.
 */

#ifndef SFTP_PARALLEL_INTERNAL_H
#define SFTP_PARALLEL_INTERNAL_H

#include <sys/types.h>

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include "sftp-parallel.h"	/* struct sftp_parallel_config (embedded) */
#include "sftp-hpn-bundle.h"	/* shared bundle-eligibility policy */
#include "hpn-meter.h"	        /* fleet display meter object */

/* Forward declarations. sftp_conn and sftp_workqueue stay opaque here and
 * sftp_hpn_dirattr_list is defined in sftp-hpn-client.h. sftp_parallel is
 * defined below; it is named here so the structs that only hold a pointer
 * to it do not depend on that order. */
struct sftp_conn;
struct sftp_workqueue;
struct sftp_parallel;
struct sftp_hpn_dirattr_list;	/* deferred dir attrs */

/*
 * Retry budget per work unit, from ssh_config HPNMaxRetries. The default of
 * 3 covers an ordinary network hiccup without spending much time on a
 * failure that will never clear, like a permission denial or a full disk. A
 * budget of 1 makes every failure final, which is how to tell a transient
 * fault from a permanent one. The ceiling of 20 is for a demonstrably flaky
 * path; past that the retry storm is itself the load problem.
 */
#define HPN_MAX_RETRIES_DEFAULT 3
#define HPN_MAX_RETRIES_MIN     1
#define HPN_MAX_RETRIES_MAX     20

/* DO NOT CHANGE. The reporter's loop period, and the unit that a great
 * deal of tuning is counted in. Several windows are measured in ticks or
 * slow-ticks rather than in time - the tail and per-worker rate rings, the
 * EMA warmup, the born-slow counter, the sync-stall observer, the peer-stall
 * window - so changing this retunes all of them at once. Worse, the fleet
 * abort counts slow-ticks against HPNStallAbortTimeout, which is in seconds,
 * so a different tick makes the configured timeout wrong by that ratio. */
#define REPORTER_TICK_MS        200
/* One second at the tick above; the reporter's slower cadence for the
 * watchdog pass, the reap loop and the fleet sample. */
#define REPORTER_SLOW_TICKS     (1000 / REPORTER_TICK_MS)
#define DEFAULT_TRANSFER_BUFLEN 131072	/* 128 KB; matches sftp-client.c */
#define DEFAULT_NUM_REQUESTS    1024	/* 128 * 1024 = 128 MB per stream */

/*
 * Maximum files to pipeline in one open+write+close batch. Sending N opens
 * before waiting for any handle reduces per-file open overhead from 1 RTT
 * each to 1 RTT total; same for closes. 64 is chosen to keep the burst
 * small enough that SSH channel window pressure is negligible while still
 * amortising RTT cost over a large group of small files.
 */
#define UPLOAD_BATCH_SIZE       64

/*
 * Soft byte cap on a single upload batch. Without this cap,
 * a worker that finds many medium-to-large files in the
 * queue would grab UPLOAD_BATCH_SIZE of them in one batch. The leaves the
 * queue empty and en-dof-transfer tail dominates. That actually reduces
 * aggregate throughput as we become dependent on one worker with
 * what might be an dispropotionately large batch.
 *
 * 256 MiB is a balance from derived from testing. It is small enough that
 * workers don't pre-claim large fractions of the workload, large enough
 * that small-file batches still amortise per-batch open/close RTT cost.
  */
#define UPLOAD_BATCH_BYTE_CAP   (256 * 1024 * 1024)

/*
 * -- Bundle-mode (hpn-bundle@hpnssh.org) tunables ------------------------
 *
 * Target bundle size: default/min/max alias HPN_BUNDLE_SIZE_* from
 * defines.h. Overridden by HPNBundleSize in ssh_config, --bundle-size
 * on hpnsftp, or -o HPNBundleSize=N; clamped to [MIN, MAX]. The
 * eligibility policy and per-bundle ceilings live in sftp-hpn-bundle.h.
 */
#define BUNDLE_TARGET_BYTES_DEFAULT  HPN_BUNDLE_SIZE_DEFAULT
#define BUNDLE_TARGET_BYTES_MIN      HPN_BUNDLE_SIZE_MIN
#define BUNDLE_TARGET_BYTES_MAX      HPN_BUNDLE_SIZE_MAX

/* NB: BUNDLE_MIN_FILES_PER_BUNDLE and BUNDLE_FILE_MAX_BYTES(target) - the
 * eligibility policy - live in sftp-hpn-bundle.h, shared with the
 * serial recursive walks. */

/*
 * A worker assembles a batch up to bundle_target_bytes using NON-BLOCKING
 * trypop and flushes whatever is queued the instant the queue runs dry
 * via the sftp-parallel-worker.c bundle batch loop. To let all num_streams
 * workers actually reach a full bundle, the queue must hold roughly
 * num_streams full bundles' worth of small files at once, plus
 * headroom for the walker to refill during a concurrent grab, Otherwise the
 * queue starves and bundles flush at a fraction of the target. Sized for
 * a representative small file defined by BUNDLE_QUEUE_FILE_HINT,
 * Files larger than that just need fewer units, so the queue over-provisions
 * harmlessly; files smaller still under-fill, tunable via the hint. Capped at
 * WORK_QUEUE_DEPTH_MAX to bound pre-claimed work-unit memory. The ring itself
 * is pointers; the cost is the queued units the walker pre-enumerates.
 */
#define BUNDLE_QUEUE_FILE_HINT (16 * 1024) /* representative small file */
#define WORK_QUEUE_DEPTH_MAX   65536       /* hard cap on queued units */

/* Maximum number of failed-path entries the orchestrator retains for
 * the end-of-transfer summary. */
#define HPN_FAILED_PATHS_MAX    100

/* Watchdog thresholds. STALL: warn (status only, NO kill) if a worker has
 * had work available but made no bytes-level progress for this long.
 * The kill lanes live with the transport classifier in sftp-hpn-congestion.c
 * and the watchdog. */
#define STALL_THRESHOLD_SEC          60  /* STALLED warn status (no kill) */
/* reap a still-connected, byte-silent worker only after this - above the
 * 300 s transport peer-stall brake so the transport self-terminates first */
#define WORKER_SILENCE_BRAKE_SEC    330

/* Endgame stuck-straggler reap threshold. At the endgame (walker done,
 * queue drained, idle capacity) a worker with zero progress for this long
 * is reaped so its bundle re-queues and an idle worker re-bundles it on a
 * fresh connection. */
#define ENDGAME_STUCK_SEC            15

/* Number of watchdog ticks (~1 s each) to wait before a worker becomes
 * eligible for throughput-outlier classification. During this window the
 * worker's EMA is still warming up from its cold-start seed, so any
 * comparison against the peer-max threshold would be unreliable.*/
#define TPUT_EMA_WARMUP_TICKS   5

/* Outlier-detection ramp gate. A worker's tput EMA cannot be fairly
 * compared against the path max until we are out of slow start. So we need
 * to approximately estimate when we would be leaving slowstart.
 * For a 10GBps 50 ms path using log2(BDP / initial_cwnd) we get ~12 RTTs,
 * Doubling that for safety giving us RAMP_RTTS = 24. 
 * Multiplied by the path RTT and peer throughput, this becomes a per-worker
 * "minimum bytes transferred" threshold (see watchdog_sample_throughput).
 *
 * RAMP_WARMUP_BYTES_MIN/MAX clamp the computed threshold so warmup never
 * dips below a useful floor or blows up on a high-BDP path where the EMA
 * may itself be misleading early on.
 * TODO: We can actually pinpoint when we leave slow start using the
 * TCP_INFO work we've done. This gets around the approximations. Address this
 * later
 */
#define RAMP_RTTS                 24
#define RAMP_WARMUP_BYTES_MIN     (16 * 1024 * 1024)    /* 16 MiB */
#define RAMP_WARMUP_BYTES_MAX     (256 * 1024 * 1024)   /* 256 MiB */

/* Hard wall-clock cap on the bytes-based warmup gate. At 30 Mbps a
 * worker needs ~60 s to transfer 256 MiB, so without this cap a
 * genuinely-slow respawned worker stays protected from outlier detection
 * for its entire slow lifetime. After RAMP_MAX_WARMUP_SEC seconds from
 * unit_start_ms the gate lifts unconditionally - a healthy TCP slow-start
 * always completes in well under this. TODO: We can get rid of this as well
 * using TCP_INFO.
 */
#define RAMP_MAX_WARMUP_SEC       15

/* Born-dead fast-kill threshold. A worker that has popped a unit but has
 * zero progress for this many seconds is killed and respawned. 5 seconds
 * is well above SSH auth completion and the first open round-trip. The
 * effective threshold is RTT-derived at runtime (~100 round-trips); see
 * sftp_parallel_set_path_rtt.*/
#define BORN_DEAD_KILL_SEC        5    /* floor (RTT <= ~50ms) */
#define BORN_DEAD_SEC_MAX        40    /* cap (RTT >= ~400ms) */
/* If a worker ends up being reaped and then gets stuck again
 * on the same range then it might be a server side issue. In this case
 * we need to supress the reaps because we'll get into a thrash cycle.
 * Instead, supress the reap and wait. This is a key
 * tuning knob: a false stuck verdict costs up to
 * WORKER_SILENCE_BRAKE_SEC of waiting. */
#define BORN_DEAD_STUCK_KILLS     1

/* Born-slow fast-kill threshold. A worker that has completed at least
 * one unit (so NOT born-dead) but whose EMA throughput is persistently
 * below BORN_SLOW_FLOOR_FRAC x cfg.tput_path_healthy_bytes_s for
 * BORN_SLOW_TICKS consecutive samples is killed, in the hope the
 * respawn lands a TCP connection in a better state.
 *
 * Tuning:
 *   BORN_SLOW_TICKS=6        x ~5 s/sample = ~30 s window
 *   BORN_SLOW_FLOOR_FRAC=0.25 below 25% of the configured healthy floor
 * TODO: Again possibly use TCP_INFO to get kernel level data to drive these
 * decisions. */
#define BORN_SLOW_TICKS           6
#define BORN_SLOW_FLOOR_FRAC      0.25

/* Operator flares: user-facing notices that the fleet has entered a
 * degraded episode. A contiguous stretch where the orchestrator is
 * backing off respawns (cooldown active) or accepting slow-but-working
 * workers (born-slow gated off). Without them a degraded transfer just
 * looks inexplicably slow. */
#define FLARE_REMINDER_BASE_SEC  60   /* first reminder this far into an episode */
#define FLARE_REMINDER_CAP_SEC  600   /* reminder interval doubles, capped here */
#define FLARE_WARN_SEC          300   /* escalate notice -> warning after this */

/* Synchronous-stall observer. Each reporter slow-tick checks whether
 * aggregate bytes transferred across all workers is zero while at least one
 * worker has a unit in flight - a Lustre/storage writeback-stall signature.
 * SYNC_STALL_WINDOW is the rolling window length in slow-ticks. */
#define SYNC_STALL_WINDOW     20    /* ~20 s window */
#define SYNC_STALL_THRESHOLD  0.20  /* fraction at which the log line warns */

/* Abort the fleet after this * num_streams worker deaths that never
 * produced a byte. It means there is a serious problem and we should just
 * die. */
#define FLEET_ABORT_UNPRODUCTIVE_MULT  2

/* Escalation timeout: how long we let a SIGTERMed SSH child clean up before
 * promoting to SIGKILL. This can be necessary if the clean shutdown path
 * is on a broken socket leading to an indefinite block.*/
#define SIGKILL_ESCALATION_SEC  5

/* One-time "path may be unreliable" notice fires once the cumulative
 * involuntary reconnect count reaches this * num_streams */
#define HPN_PATH_CHURN_NOTICE_MULT 2

/* Cooldown backstop trigger: this many respawns per stream since the
 * last cooldown ended means the fleet is churning so pause
 * respawns. */
#define RESPAWN_MULTIPLIER      2

/* Respawn cooldown: pause on replacing dead workers when deaths look systemic
 * e.g. peer-stall burst or epoch-ceiling churn. Respawning into a
 * struggling backend just feeds it more connections to kill.
 * See reporter_dispatch_respawns (sftp-parallel-respawn.c) for details.*/
#define RESPAWN_COOLDOWN_BASE_SEC   30   /* initial pause length */
#define RESPAWN_COOLDOWN_CAP_SEC    3600 /* escalation ceiling */

/* Halve the level per this much sustained-healthy throughput, and end
 * an active pause early after this long a continuous healthy streak. */
#define RESPAWN_COOLDOWN_DECAY_SEC  30

/* A peer-stall death: the worker's ssh child exited after finding
 * the server had stopped reading its socket. This points at backend
 * overload rather than a network fault. Use these to decide when
 * a run of such deaths counts as a fleet-wide issue and trigger
 * a cooldown. Err on the side of being overly aggressive as false
 * trigger is cheap and missed causes serious perfomrance issues.*/
#define PEER_STALL_WINDOW            10  /* slow-ticks (~10 s) */
#define PEER_STALL_SYSTEMIC_FRAC_PCT 50  /* >= this % of num_streams ... */
#define PEER_STALL_SYSTEMIC_MIN       2  /* ... AND >= this many absolute */

/* Tail trend detector. Near the end of a transfer one worker can be
 * left crawling through the last of the work while the rest of the
 * fleet has nothing to do. These constants decide when that has
 * happened, at which point the straggler is asked to hand back part
 * of its work. Falling aggregate throughput alone does not qualify,
 * since every healthy transfer slows at the end. */
#define TAIL_RING_TICKS        25   /* ~5s of 200ms reporter ticks */
#define TAIL_RING_QUARTER      (TAIL_RING_TICKS / 4)
#define TAIL_DECLINE_PCT       25   /* newest-quarter median below oldest by % */
#define TAIL_PROJECT_SEC       10   /* projected solo-tail threshold */
#define TAIL_HOLDER_LAG_PCT    70   /* straggler median below this % of idle */
/* The arm condition must hold continuously this long before the
 * detector fires. Derived from measurement. */
#define TAIL_CONFIRM_SEC        8

/* Per-worker rate windows. The reporter samples each working worker's
 * rate into a small ring, so a suspected straggler is judged
 * against what the other workers have actually demonstrated as
 * opposed to a fleet average. A worker without enough history
 * isn't counted. */
#define WORKER_RATE_RING        25  /* ~5s of busy-time samples */
#define WORKER_RATE_MIN_SAMPLES 12  /* ~2.4s history before a median counts */

/* Set when the current run is aborted by the user, so message sites with
 * no path to the orchestrator can tell interrupt fallout from genuine
 * failure. The reporter sets it and sftp_parallel_start clears it for
 * the next fleet. One process-wide flag is faithful because sftp.c runs
 * one orchestrator at a time. Used in sftp-parallel-unit.c */
extern volatile sig_atomic_t parallel_user_abort_flag;

/* Possible worker states */
enum worker_health {
	WORKER_HEALTHY = 0,
	WORKER_STALLED = 1,
	WORKER_DEAD    = 2,
};

/* What a worker says it is doing with itself, written by the worker
 * at each of its own transitions. This is intent, not liveness. A
 * wedged worker goes on claiming busy because it never reaches a
 * transition, so always read this alongside worker_health,
 * which knows whether the worker is still making progress. Capped
 * means idle because this file is at its concurrent writer cap.
 * Such a worker will still take work from any other file.
 * Busy is the zero value so a worker whose thread has not
 * reached the queue is never mistaken for spare capacity.
 */
enum worker_avail {
	WORKER_AVAIL_BUSY   = 0,	/* holds a dispatched unit */
	WORKER_AVAIL_READY  = 1,	/* waiting in pop for work */
	WORKER_AVAIL_CAPPED = 2,	/* idle at this file's writer cap */
};

/* Why the watchdog doomed a worker. Set at whichever DEAD site fires and
 * read by the reap classifier; worker_doom_reason_name renders it for
 * logs. */
enum worker_doom_reason {
	WDR_NONE = 0,
	WDR_CHILD_GONE,		/* ssh child vanished */
	WDR_BORN_DEAD,		/* no bytes within the born-dead window */
	WDR_DEAD,		/* no progress, past the silence brake */
	WDR_ENDGAME_STRAGGLER,	/* stalled holding the last work */
	WDR_ISOLATION,		/* far below the fleet, others idle */
	WDR_ISO_STALL,		/* isolation, and no progress either */
	WDR_BORN_SLOW		/* persistently under the floor since birth */
};

/* What a worker is currently doing, for diagnostics only. Nothing reads
 * it but the ENV-VAR HPN_PARALLEL_TRACE fleet sample, which prints where
 * every worker stands at the instant a transfer freezes. */
enum worker_phase {
	WPH_INIT = 0,
	WPH_POP_WAIT,    /* blocked in sftp_workqueue_pop (queue empty) */
	WPH_ASSEMBLE,    /* collecting a batch via non-blocking trypop */
	WPH_RUN,         /* inside a bundle / single-file transfer */
	WPH_FINALIZE,    /* finalizing entries / draining deferred batch */
	WPH_EXIT,
};

/* What a work unit tells its worker to do. Three types: whole
 * file, byte range of one large file, and a container whose
 * members[] travel as a single tar stream. Range, resume and verify
 * units belong to a per-file tracker; whole-file and container units
 * do not. */
enum sftp_op {
	SFTP_OP_UPLOAD,
	SFTP_OP_DOWNLOAD,
	SFTP_OP_UPLOAD_RANGE,	/* upload a byte range of a large file */
	SFTP_OP_DOWNLOAD_RANGE,	/* download a byte range of a large file */
	/* Verified-resume overlap span. Hash-compare the existing partial
	 * against the source over offset and length. Splice only the
	 * runs that differ.*/
	SFTP_OP_RESUME_SPAN,
	SFTP_OP_BUNDLE_UPLOAD,
	SFTP_OP_BUNDLE_DOWNLOAD,
	/* Post-transfer verify and inline repair of a parked range
	 * tracker. */
	SFTP_OP_VERIFY,
};

/* Which side of a range transfer is written. */
enum sftp_range_target {
	SFTP_RANGE_TARGET_LOCAL,   /* write target is local (download) */
	SFTP_RANGE_TARGET_REMOTE,  /* write target is remote (upload) */
};

/* One per range of a file being verified. Only an upload fills it in,
 * from the hash tee'd off the bytes as they were sent. A resume requeue
 * can reshape a range afterwards, so valid says whether the hash still
 * describes this slot. If not re-read the range and hash it. */
struct sftp_range_vslot {
	u_int64_t off;    /* original range start in the file */
	u_int64_t len;    /* original range length */
	u_int64_t hash;   /* tee'd XXH3 of the source range (when valid) */
	int       valid;  /* 1 = hash is usable; 0 = re-read the range */
};

/* One transferred file waiting for its post-transfer verify, recorded at
 * completion and verified once the transfers drain so verify never stalls
 * a transfer. A recursive run parks one per file, so they are packed: the
 * header and both paths share one allocation, and each path is stored
 * relative to a prefix held once in the pool, or whole when its prefix
 * index is -1. Built by verify_whole_item_new (static, unit.c). */
struct verify_whole_item {
	int16_t  local_prefix;		/* pool index, -1 = no prefix */
	int16_t  remote_prefix;
	int8_t   local_is_target;	/* 0 = upload, 1 = download */
	char     buf[];			/* "local_rel\0remote_rel\0" - one alloc */
};

/* A thread-safe list of strings with a hard cap. A run keeps two: the
 * paths the fleet could not deliver, and the files that failed
 * verification. Workers and walkers append from their own threads, so
 * appends take mu. total keeps counting past the cap so the summary can
 * say how many were not shown. Draining hands the strings to the
 * caller. We limit the number to reduce memory issues on large pathological
 * transfers. */
struct hpn_strlist {
	pthread_mutex_t  mu;
	char           **items;     /* xstrdup'd entries; NULL until init */
	size_t           used;      /* entries actually held */
	size_t           cap;       /* array capacity */
	uint64_t         total;     /* total appends seen (may exceed cap) */
};

/* What one spawn thread is handed. auth_mu, auth_cv, auth_in_flight and
 * started are locals of sftp_parallel_start, borrowed and shared by
 * every spawn thread, so those threads must be joined before it
 * returns. That sharing is what makes them a limiter: at most
 * max_in_flight workers hold an unauthenticated connection at once,
 * keeping the fleet under the server's MaxStartups. */
struct spawn_ctx {
	struct sftp_parallel *fleet; /* the worker fleet */
	pthread_mutex_t      *auth_mu;
	pthread_cond_t       *auth_cv;
	int                  *auth_in_flight; /* how many not auth'd yet */
	int                  *started; /* workers starting to connect */
	int                   total;   /* cfg->num_streams */
	int                   max_in_flight; /* max outstanding auth reqs */
	int                   succeeded; /* auth'd and started */
};

/* Shared state for verifying one range-split file, with one work unit per
 * transfer range and every unit pointing here. Built from the range
 * tracker at submit and owns the paths and the four range arrays, each
 * n_ranges long and indexed by a unit's range_index. ranges_left is a
 * refcount over those units: completed and dropped units decrement it,
 * and whoever takes it to zero frees the job. */
struct verify_job {
	char     *local_path;
	char     *remote_path;
	int       local_is_target;	/* download=1 (not tee'd); upload=0 */
	int       n_ranges;
	off_t    *offs;
	off_t    *lens;
	uint64_t *hashes;		/* tee'd source hashes (upload) */
	int      *valid;		/* whether hashes[i] is usable */
	int       ranges_left;		/* atomic refcount */
	int       failed;		/* atomic: any chunk's inline repair failed */
	int       any_repaired;		/* atomic: any chunk needed a repair */
	int       any_unverified;	/* atomic: any chunk was unverifiable */
};

/* -- Per-file range-completion tracker --------------------------------
 *
 * Shared state for one file split into ranges across workers, one work unit
 * per range. Each unit finalizes exactly once, on its final outcome and
 * never on a retry. The call that retires the last range frees the tracker,
 * so every caller must treat its pointer as dead once finalize returns. A
 * file that loses a range keeps the bytes it did receive and is reported as
 * incomplete rather than deleted, so verified resume can refill the gaps.
 * The ownership rules and the NULL cases are stated with the code at
 * parallel_unit_tracker_finalize_n (sftp-parallel-unit.c).
 *
 * mu guards the mutable fields; total is set once at creation and remaining
 * counts down to zero.
 */
struct sftp_range_tracker {
	pthread_mutex_t        mu;
	int                    total;      /* original range count */
	int                    remaining;  /* finalize calls still owed */
	int                    any_failed; /* sticky: 1 if any range failed */
	enum sftp_range_target target;
	off_t                  file_bytes; /* for the transfer log line */
	char                  *path;       /* the file written (xstrdup'd) */
	char                  *src_path;   /* the file read (xstrdup'd) */
	/* Verify transfer: the last range to finalize parks the tracker for
	 * the post-transfer verify phase. */
	int                    verify;
	/* Per-inode writer cap: active_writers is the number of ranges writing
	 * now, writer_cap the ceiling. Taken in the worker's dispatch gate and
	 * released in worker_process_result. */
	int                    active_writers;
	int                    writer_cap;
	/* Writer-slot grant and denial counts, emitted at the last finalize
	 * under HPN_PARALLEL_TRACE. */
	uint64_t               cap_grants;
	uint64_t               cap_denials;
	/* Set once the first range to dispatch has created the file, so an
	 * interrupted transfer leaves no full-size empty placeholder. */
	int                    file_ensured;
	/* One slot per range, sized `total`. NULL unless the transfer is being
	 * verified. */
	struct sftp_range_vslot *vslots;
	/* vslots allocation count: `total` when allocated, 0 when not. Index by
	 * this, not total. */
	int                      vslots_n;
};

/* One schedulable piece of transfer work: the unit the producers queue and
 * the workers execute. op selects the kind and, with it, which member groups
 * apply. Everything a worker needs to run the unit travels inside it, so any
 * worker can pick up any unit with no other context.
 *
 * Created by the constructors in sftp-parallel-unit.c and freed by
 * parallel_unit_free, which also releases any op-specific state still
 * attached. A failed unit is requeued rather than recreated, so per-attempt
 * state lives here too. */
struct sftp_work_unit {
	enum sftp_op op;
	char    *src_path;
	char    *dst_path;
	off_t    size;        /* bytes this unit transfers */
	mode_t   mode;        /* source permissions, 0 = default */
	int      no_retry;    /* permanent failure, give up */
	off_t    acked_bytes; /* confirmed bytes of the latest attempt */
	int      attempt;
	/* Cooperative yield: worker id + 1 of the holder that yielded this
	 * remainder, 0 if none. */
	int      yield_from;
	/* Per-unit resume and verify intent. See the resume-implies-whole-file
	 * rule in sftp_parallel_submit_upload. */
	int      resume;
	int      verify;
	/* Set after a bundle wire failure; the batch loop then dispatches the
	 * unit through the per-file path. */
	int      bundle_ineligible;
	/* Range fields: used only for SFTP_OP_UPLOAD_RANGE / DOWNLOAD_RANGE. */
	off_t    range_offset;
	off_t    range_length;
	int      range_index; /* this range's slot in the tracker (0-based) */
	int      skipped;     /* resume found the target identical or larger */
	uint64_t range_hash;  /* verify: XXH3 of the source bytes */
	/* Shared by all range units of one file, NULL for the rest. */
	struct sftp_range_tracker *range_tracker;
	/* Bundle container: the small-file member units it carries, grouped
	 * producer-side. */
	struct sftp_work_unit **members;
	int                     n_members;
	/* SFTP_OP_VERIFY, whole file. Either verify_whole or verify_job is set,
	 * never both. */
	struct verify_whole_item *verify_whole;
	/* SFTP_OP_VERIFY, one chunk [range_offset, range_length) of a
	 * range-split file. */
	struct verify_job *verify_job;
	/* Retry-overflow list link (sftp-parallel.c retry_overflow_*). A worker
	 * requeue that finds fleet->q full parks the unit here instead of
	 * blocking. NULL and 0 when the unit is not parked. */
	struct sftp_work_unit  *overflow_next;
	int                     overflow_front;
};

/* Per-worker state: one per parallel stream, owned by the fleet and handed
 * to the worker thread it describes. The struct mixes writers: counters the
 * worker bumps under mu, watchdog bookkeeping, and the reporter's rate
 * window. The watchdog is not a thread - it is a pass the reporter thread
 * runs each tick - so watchdog-written and reporter-written fields share one
 * writer thread. */
struct sftp_worker {
	int                id;
	pthread_t          tid;
	struct sftp_parallel *parent;

	pid_t              ssh_pid;
	int                fd_in;
	int                fd_out;
	struct sftp_conn  *conn;

	/* Per-worker progress. Workers update their own counters under mu;
	 * the reporter snapshots every worker under those same mutexes. */
	pthread_mutex_t    mu;
	uint64_t           bytes_total;
	/* Bytes of the file in progress; reset to 0 when it completes. */
	volatile uint64_t  live_bytes;
	/* enum worker_phase; relaxed atomic, read by the reporter. */
	volatile int       phase;
	uint64_t           units_completed;
	uint64_t           units_failed;
	uint64_t           last_completion_ms; /* monotonic ms of last finish */

	/* Bytes-based progress signal for the watchdog: when, and at what
	 * byte level, progress was last observed. Reporter thread only; the
	 * algorithm is in sftp-parallel-watchdog.c. */
	uint64_t           last_progress_ms;
	uint64_t           last_progress_bytes;

	/* Adaptive throughput-based stall detection, updated at each watchdog
	 * tick. Reporter thread only, so these need no lock. See
	 * cfg.tput_path_healthy_bytes_s in sftp-parallel.h for the algorithm. */
	uint64_t           tput_check_bytes;     /* bytes_total at last check */
	uint64_t           tput_check_ms;        /* monotime of last check */
	uint64_t           tput_current_bytes_s;  /* most recent raw estimate */
	uint64_t           tput_ema_bytes_s;      /* EMA-smoothed estimate */
	int                tput_ema_warmup_ticks; /* ticks since EMA cold-start */
	int                tput_outlier_ticks;   /* consecutive outlier ticks */
	/* Consecutive ticks where EMA < BORN_SLOW_FLOOR_FRAC x
	 * cfg.tput_path_healthy_bytes_s; drives born-slow fast-kill. */
	int                tput_below_floor_ticks;
	/* unit_start_ms at the last tick; a change means a new unit, which
	 * resets the EMA so a stale value cannot suppress outlier detection. */
	uint64_t           tput_last_unit_start_ms;
	/* monotime_ms() when the current unit was popped off the queue; 0
	 * while idle. Acquire/release - the watchdog reads it. */
	uint64_t           unit_start_ms;
	/* The (A)/(B)/(C) tags below mark the worker's three orthogonal state
	 * machines - liveness, doom, and exit. They are explained at the top
	 * of sftp-parallel-watchdog.c. */
	/* (A) HEALTHY/STALLED/DEAD; watchdog-written, read for logging and
	 * transition gating. */
	enum worker_health health;
	/* enum worker_avail; relaxed atomic, written by the worker at
	 * voluntary transitions. Read with health by the tail detector and the
	 * fleet-median computation. */
	int                avail;
	/* Relaxed atomic; size of the currently-held unit. Feeds the tail
	 * detector's projected tail. */
	uint64_t           unit_size;
	/* Relaxed atomic; range_offset of the currently-held range unit (-1
	 * when idle or non-range). Successive born-dead reaps on the same
	 * offset mean a server-side stuck range, not a dead connection. */
	int64_t            unit_offset;
	/* Warm remote handle held across consecutive same-file range writes,
	 * which avoids the close/reopen dip at range boundaries. Worker thread
	 * only. Closed on file change and on worker exit. */
	u_char            *warm_handle;        /* open remote handle, or NULL */
	size_t             warm_handle_len;
	char              *warm_dst_path;      /* file warm_handle is open on */
	/* Per-worker rate window (reporter thread only): personal rate samples
	 * taken each tick while BUSY, retained while idle so a READY worker's
	 * demonstrated capability stays in evidence. */
	uint64_t           rate_ring[WORKER_RATE_RING];
	int                rate_ring_idx;
	int                rate_ring_count;
	uint64_t           rate_prev_bytes;
	uint64_t           rate_prev_ms;
	/* Cooperative yield request (tail redistribution): the reporter sets it
	 * on the lagging endgame holder, the worker consumes and clears it.
	 * Relaxed atomic. */
	int                yield_req;

	int                started;
	/* (C) set by the worker on self-exit; read by the reporter for
	 * reaping. */
	int                exited;
	/* (B) set by the watchdog before SIGTERM; prevents double-kill. */
	int                doomed;
	/* (B) which watchdog path doomed it (born_dead/isolation/stall/
	 * dead/born_slow); emitted in the reap trace. */
	enum worker_doom_reason doom_reason;
	/* (B) monotonic ms when SIGTERM was sent; read by the SIGKILL
	 * escalation deadline. */
	uint64_t           doom_ms;

	/* Pipelined-batch carry-over: the previous batch's CLOSE collection is
	 * deferred across the next sftp_upload_batch_send. Set during a
	 * pipelined send, cleared by worker_drain_pipeline. All NULL and 0
	 * means no deferred batch is in flight. */
	struct sftp_upload_batch_pending *batch_prev_pending;
	struct sftp_work_unit           **batch_prev_units;
	struct sftp_upload_batch_entry   *batch_prev_entries;
	int                               batch_prev_n;

	/* Bundle mode (hpn-bundle@hpnssh.org): bundle_enabled is set once at
	 * worker startup when HPNUseBundle is yes (the default) and the server
	 * advertises the extension. The worker then collects upload batches to
	 * bundle_target_bytes and dispatches them through
	 * sftp_hpn_bundle_upload. Mutually exclusive with the pipelined-batch
	 * state above. */
	int      bundle_enabled;
	uint64_t bundle_target_bytes;
};

/* The fleet: one of these per parallel transfer command. Owns the workers,
 * the shared work queue, and all cross-thread accounting for the transfer.
 * Created by sftp_parallel_start, torn down by sftp_parallel_stop. */
struct sftp_parallel {

	struct sftp_parallel_config cfg;
	char                        cfg_port_buf[16]; /* owns cfg.port string */
	struct sftp_workqueue      *q;

	/* Workers held as an array of pointers so add/remove can mutate
	 * the array without invalidating pointers held by worker threads
	 * via worker->parent->workers[...]. workers_mu serializes structural
	 * changes (add/remove/reap); the per-worker mu still serializes
	 * counter updates. Lock ordering: workers_mu BEFORE worker->mu. */
	pthread_mutex_t             workers_mu;
	struct sftp_worker        **workers;
	int                         num_workers;
	int                         workers_cap;
	int                         next_worker_id;
	/* Detached respawn threads not yet in workers[]; guards premature
	 * abort. */
	int                         pending_respawns;
	int                         total_respawns;  /* lifetime respawn count */
	/* Nth involuntary worker loss this transfer; numbers the
	 * user-facing heartbeat so it matches the summary count (reporter
	 * thread only). */
	uint64_t                    death_ordinal;
	/* One-shot: the "path may be unreliable" notice has fired once
	 * this transfer (reporter thread only). */
	int                         churn_notice_emitted;
	/* _Atomic: bumped by the reporter's unlocked reap loop and read by main
	 * in get_stats before the reporter is joined. */
	/* Workers reaped with HPN_EXIT_TCP_WEDGE. */
	_Atomic int                 wedge_terminations;
	_Atomic int                 peer_stall_terminations; /* ditto, PEER_STALL */
	/* Tail trend detector state (phase B, reporter thread only - no locking).
	 * tail_rate_ring holds per-tick aggregate-rate samples in bytes/sec; the
	 * detector compares oldest- against newest-quarter medians and latches
	 * would-arm episodes for telemetry. */
	uint64_t                    tail_rate_ring[TAIL_RING_TICKS];
	int                         tail_ring_idx;
	int                         tail_ring_count;
	uint64_t                    tail_prev_bytes;
	uint64_t                    tail_prev_ms;
	int                         tail_episode;      /* latch: in episode */
	uint64_t                    tail_episode_ms;   /* episode start */
	/* When the arm condition became continuously true; the episode
	 * latches only after it holds TAIL_CONFIRM_SEC. */
	uint64_t                    tail_lag_start_ms;
	/* HPNTailRedistribute (ssh_config, default yes): arms phase C, the
	 * cooperative yield. When off the detector stays telemetry-only. Parsed
	 * once at parallel start. */
	int                         tail_redistribute;
	/* One yield per episode latch. */
	int                         tail_yield_fired;
	/* monotime_ms() at sftp_parallel_start; elapsed surfaced in stats
	 * for the end-of-transfer summary. */
	uint64_t                    session_start_ms;
	/* Respawns in the current epoch; reset when a cooldown ends. */
	int                         respawn_epoch_count;
	/* Escalating cooldown level in SECONDS; lazy-init to BASE, x2 per
	 * burst (cap CAP), decays /2 per DECAY_SEC of sustained health. */
	time_t                      respawn_cooldown_dur_s;
	/* monotime() seconds when the current sustained-healthy streak
	 * began; 0 = unhealthy. */
	time_t                      respawn_healthy_since_s;
	/* Last second the level was decayed (or the health streak
	 * began). */
	time_t                      respawn_decay_anchor_s;
	/* Per-slow-tick deltas of peer-stall deaths. */
	int                         peer_stall_window[PEER_STALL_WINDOW];
	int                         peer_stall_window_pos; /* rolling index */
	/* peer_stall_terminations at the previous slow-tick. */
	int                         peer_stall_prev_sample;
	/* monotime() seconds when the cooldown ends; 0 = not in
	 * cooldown. */
	time_t                      respawn_resume_s;
	/* Freshest raw max from the watchdog; used by the throughput
	 * gate. */
	uint64_t                    tput_last_raw_max_bytes_s;
	/* Involuntary deaths reaped but not yet replaced; carries across
	 * cooldowns and pthread failures so a long-lived transfer doesn't
	 * drift below num_streams over time. */
	int                         respawn_owed;
	/* Under workers_mu. One violation costs the worker its connection and
	 * a respawn; the second in a session exits hpnsftp. Exposed via stats
	 * for post-mortem inspection. */
	int                         protocol_violations;

	/* Files the walker dropped before they could become work units (stat or
	 * symlink resolution failed). They happen on the main thread inside the
	 * recursive walkers, so no worker's units_failed counts them and
	 * parallel_flush surfaces them separately. Bumped with __atomic_fetch_add
	 * from any thread. */
	uint64_t                    walker_failures;

	/* Per-file progress counter (status relay + local meter): bumped once
	 * as each file is submitted for transfer, BEFORE any range-splitting,
	 * so it counts FILES not work units. files_total is the scan-time
	 * total. Both relaxed-atomic: written from the submit path / setup,
	 * read by the reporter. */
	uint64_t                    files_submitted;
	uint64_t                    files_total;

	/* enum sftp_walker_phase; relaxed atomic, set by the walker via
	 * sftp_parallel_set_walker_phase, read by the reporter FLEETSAMPLE. */
	volatile int                walker_phase;

	/* Bounded list of paths that could not be delivered, populated at every
	 * give-up site (worker MAX_RETRIES, workqueue push-fail, walker
	 * skip-on-error). Surfaced inline in parallel_flush's TRANSFER INCOMPLETE
	 * message. */
	struct hpn_strlist          failed_paths;

	/* Verify transfer: files whose post-transfer XXH3 hash did NOT
	 * match the source. The transfer is NOT aborted on a mismatch; the
	 * path is recorded here (thread-safe append from workers) and the
	 * end-of-transfer summary prints them. A non-empty list makes
	 * hpnsftp exit SFTP_EX_VERIFY_FAILED. */
	struct hpn_strlist          verify_failed_paths;

	/* Verify transfer post-transfer phase: completed files parked here
	 * (from worker threads, under verify_pending_mu) until
	 * sftp_parallel_wait submits them as SFTP_OP_VERIFY units after the
	 * transfer drains. See parallel_verify_phase_submit. */
	pthread_mutex_t             verify_pending_mu;
	struct sftp_range_tracker **verify_pending;	/* range-split files */
	int                         verify_pending_n;
	int                         verify_pending_cap;
	/* Whole-file (non-range-split) parked verifies - lightweight items, the
	 * dominant verify-phase memory term. Shares verify_pending_mu. */
	struct verify_whole_item  **verify_whole_pending;
	int                         verify_whole_pending_n;
	int                         verify_whole_pending_cap;
	/* Path-factoring prefix pool: registered directory prefixes (the recursive
	 * roots, and the glob/direct source+dest dirs). Whole-file items store
	 * each path relative to the longest-matching prefix, so the common dir is
	 * held once, not per file. Deduped, small (command-level, not per-file).
	 * Shares verify_pending_mu; freed at sftp_parallel_stop. */
	char                      **verify_prefixes;
	int                         verify_prefixes_n;
	int                         verify_prefixes_cap;

	/* Parked-verify memory gate: outstanding parked-verify bytes,
	 * charged at submit (see parallel_verify_item_bytes_estimate), and
	 * the wave budget (fixed 64 MiB, set once at start). Crossing the
	 * budget triggers a verify wave that drains the parked set and
	 * resets the counter (parallel_verify_maybe_wave). Fleet-wide;
	 * shares verify_pending_mu. */
	uint64_t                    verify_parked_bytes;
	uint64_t                    verify_park_budget;

	/* Auto-repair: on a post-transfer verify mismatch the worker splices the
	 * bad 64 MiB sub-chunks of its range inline and re-verifies, bounded by
	 * the attempt cap + convergence. ON by default; -X VerifyRepair=no
	 * disables; verify_repair_attempts is the cap (fixed at 3). */
	int                         verify_repair_enabled;
	int                         verify_repair_attempts;

	pthread_t                   reporter_tid;
	int                         reporter_started;

	/* Files still owed to sftp_parallel_wait. Counted per work unit, never
	 * per queue object: a bundle container transports many units and is
	 * not itself counted, so its members are what raise and lower this. */
	pthread_mutex_t             pending_mu;
	pthread_cond_t              pending_cv;
	uint64_t                    pending;

	/* Ceiling on outstanding (submitted but not completed) files - the
	 * workqueue's own cap counts queued objects, and one bundled object
	 * carries thousands of files. Sized from work_queue_depth(); see
	 * sftp_parallel_await_capacity. */
	uint64_t                    outstanding_cap;

	/* Worker re-queue overflow list (FIFO of already-allocated units),
	 * guarded by retry_overflow_mu. Parked units stay counted in
	 * pending, so sftp_parallel_wait cannot complete while any remain.
	 * See parallel_worker_requeue / parallel_retry_overflow_drain. */
	pthread_mutex_t             retry_overflow_mu;
	struct sftp_work_unit      *retry_overflow_head;
	struct sftp_work_unit      *retry_overflow_tail;
	size_t                      retry_overflow_n;

	/* Producer-side bundle accumulator: bundle-eligible small files are
	 * grouped into whole bundles here before pushing (see parallel_bundle_add
	 * and parallel_bundle_flush). Single-threaded by design - only the submit
	 * thread adds and flushes - so there is deliberately no lock, and a second
	 * producer must bring one. */
	struct sftp_work_unit     **bundle_pending;    /* member units, grown */
	int                         bundle_pending_n;
	int                         bundle_pending_cap;
	uint64_t                    bundle_pending_framed;  /* sum framed bytes */
	/* Download fetch request bytes (4 + remote path per member); caps
	 * the bundle at BUNDLE_DL_FETCH_REQ_MAX. */
	uint64_t                    bundle_pending_path_bytes;
	enum sftp_op                bundle_pending_op;   /* UPLOAD | DOWNLOAD */

	/* ssh child PIDs of IN-FLIGHT spawn attempts (registered between fork
	 * and sftp_init completion), so abort/stop can SIGTERM them instead
	 * of waiting out a full connect timeout - the unbounded wait held the
	 * user's exit hostage for minutes on a slow/penalizing server.
	 * Guarded by workers_mu. */
	pid_t                       spawning_pids[SFTP_PARALLEL_MAX_WORKERS];
	int                         n_spawning;
	/* monotime() seconds when each spawning_pids[] entry registered. The
	 * reporter SIGTERMs a spawn stalled past HPN_RESPAWN_STALL_SEC, which
	 * ConnectTimeout does not bound; left alone, a wedged handshake pins
	 * pending_respawns above 0 and deadlocks the abort net. Parallel to
	 * spawning_pids[], guarded by workers_mu. */
	time_t                      spawning_since[SFTP_PARALLEL_MAX_WORKERS];

	/* Carried over from reaped workers: bytes, wired bytes, and failure
	 * counts, captured under workers_mu at the reap so post-respawn
	 * aggregates (stats snapshot, meter, end-of-transfer report) stay
	 * complete and monotonic. Read under workers_mu
	 * (parallel_stats_snapshot, reporter_emit_fleetsample) and added
	 * back in sftp_parallel_get_stats. */
	uint64_t                    retired_bytes;
	uint64_t                    retired_wired;
	uint64_t                    retired_units_failed;

	/* Cached destination sftp_fs_info() (stripe geometry). Walker
	 * (main) thread only. See get_cached_fs_info. */
	int                         fs_info_cached;
	struct sftp_fs_info         fs_info_cache;

	/* Set by sftp_parallel_abort, read by workers between units. */
	volatile sig_atomic_t       abort_flag;

	/* HPN: set when a worker sees a server -P/-p request-policy denial, a
	 * class-wide refusal that would deny every file of this kind. The
	 * reporting and idempotency latch for that path; the worker also raises
	 * abort_flag and shuts the workqueue. */
	_Atomic int                 policy_denied;

	/* Abort CAUSE: 1 when the abort came from the user's interrupt
	 * (Ctrl-C via ext_interrupt_flag) rather than a fleet failure.
	 * Read by the interrupt-aware messaging - a user who hit Ctrl-C
	 * gets one calm summary instead of error theater. */
	volatile sig_atomic_t       abort_user;

	/* Caller's interrupt flag (e.g. sftp.c's interrupted), or NULL.
	 * The reporter polls it and calls sftp_parallel_abort() within one
	 * tick of it going non-zero. Doubly _Atomic: main stores the
	 * pointer (set_interrupt_flag) while the reporter is already
	 * polling, and both ends read the pointed-to flag concurrently. */
	_Atomic sig_atomic_t * _Atomic ext_interrupt_flag;

	/* App-layer RTT measured on the control connection at startup
	 * (microseconds; 0 = not measured). Sizes the per-worker outlier-detection
	 * warmup so a respawned worker in TCP slow-start is not killed before its
	 * cwnd has had ~RAMP_RTTS round-trips to ramp. _Atomic: set once by
	 * sftp_parallel_set_path_rtt on main after the reporter is running, and
	 * read by the reporter. */
	_Atomic uint64_t            path_rtt_us;

	int                         saved_showprogress;
	int                         progress_meter_started;
	/* Bytes already done when the meter started; the delta gives this
	 * transfer's own progress. */
	uint64_t                    progress_bytes_baseline;
	off_t                       aggregate_progress_counter; /* meter ctr */
	/* The fleet display meter (hpn-meter core). The reporter is the only
	 * thread that updates it after start: a walker posts into the accumulators
	 * below with atomic adds and the reporter folds them in on its next tick,
	 * so no display state is ever written off the reporter thread. */
	struct hpn_meter            meter;
	off_t                       posted_total_add;  /* walker -> reporter */
	u_int                       posted_files_add;  /* walker -> reporter */
	/* Stop handshake: the meter is bound to the reporter, so the final
	 * 100 percent paint must come from it. progress_stop snaps the
	 * counter, raises this, and waits briefly; the reporter's next tick
	 * paints and clears it. See sftp_parallel_progress_stop. */
	int                         meter_final_request;
	/* Resume-check stretch (-Z UX): while workers hash existing
	 * partials the reporter shows a "resume check" sub-meter, then
	 * restores the transfer meter from the two fields below. See
	 * resume_stretch_restore in sftp-parallel-reporter.c. */
	int                         resume_stretch_on;
	/* Transfer total to restore. */
	off_t                       progress_total_bytes;
	char                        progress_label_saved[128];
	/* Deferred file-count verb for the parallel download meter. Empty
	 * unless the client deferred its count (a directory download, where the
	 * real file count is unknown until the discover-tree walk); set by
	 * sftp_parallel_progress_start_counted, consumed by _set_total to
	 * rewrite the label to "<verb> N files in parallel". */
	char                        progress_verb[16];
	/* Post-transfer verify-phase meter (HPN). While active the reporter drives
	 * aggregate_progress_counter from verify progress rather than the
	 * transfer-byte snapshot, so the phase shows its own bar instead of a
	 * frozen 100% transfer bar. verify_meter_total is the bytes transferred
	 * this command (= the bytes to verify); verify_total_units is the
	 * SFTP_OP_VERIFY unit count. */
	_Atomic int                 verify_phase_active; /* main-set, reporter-read */
	uint64_t                    verify_total_units;
	uint64_t                    verify_done_units;   /* atomic; worker-bumped */
	/* Byte-granular verify progress: bytes hashed for fully verified files
	 * (atomic; a worker folds its per-conn in-flight count in at each file's
	 * completion). The reporter adds every worker's in-flight count on top, so
	 * one huge file's bar advances each second instead of jumping at the end. */
	uint64_t                    verify_done_bytes;
	off_t                       verify_meter_total;

	int                         started;
	/* Set by main in sftp_parallel_stop() while reporter/respawn/worker
	 * threads still poll it; _Atomic removes the cross-thread race. */
	_Atomic int                 stopped;

	/* Synchronous-stall detector state. Reporter slow-tick path only, so no
	 * locking. */
	uint32_t sync_stall_ticks;      /* stall slow-ticks in current window */
	uint32_t sync_stall_window_pos; /* slow-ticks elapsed in current window */
	uint64_t sync_stall_prev_bytes; /* aggregate bytes at previous slow-tick */
	/* First-sample guard: the delta on the very first slow-tick spans
	 * all bytes ever. */
	int      sync_seen_first_tick;

	/* Operator flare episode tracking (reporter_flare). See FLARE_*. */
	int      flare_in_episode;       /* currently inside a degraded episode */
	time_t   flare_episode_start_s;  /* monotime() when it opened */
	time_t   flare_last_reminder_s;  /* last periodic reminder emitted */
	/* Current reminder gap; x2 per reminder, capped, reset per
	 * episode. */
	time_t   flare_reminder_interval_s;
	/* Slow workers accepted (born-slow gated off) this watchdog tick;
	 * reset each pass, read by reporter_flare. */
	int      born_slow_accepting;

	/* Fleet abort: give up on the whole transfer only when no worker is alive
	 * and the fleet cannot reconnect, never while one is still moving data or
	 * heart-beating. The full condition set is at the abort site in
	 * sftp-parallel-watchdog.c. ssh_config HPNStallAbortTimeout sizes the
	 * window (default 60 s); 0 disables the abort. */
	int      noprogress_abort_s;     /* zero-progress window (s); 0 = abort off */
	int      noprogress_consec_ticks;/* consecutive whole-fleet zero-progress ticks */
	/* Consecutive worker deaths that produced 0 lifetime bytes; reset
	 * on any fleet progress or heartbeat (a sign of life). */
	int      unproductive_deaths;
	/* Last reaped worker's exit code, -1 if signaled/unknown; for the
	 * abort message. */
	int      last_worker_exit_code;
	/* 0-bytes kill threshold; RTT-derived in sftp_parallel_set_path_rtt
	 * (main) after the reporter started, read by the watchdog (reporter
	 * thread) - _Atomic. */
	_Atomic int born_dead_sec;
	/* Stuck-range detector (reporter/watchdog thread only). Successive
	 * born-dead reaps on the same range_offset mean the range is stuck
	 * server-side rather than the connection dead, so the fast-kill cascade
	 * stops and the fleet waits; the silence brake is still the backstop. */
	/* range_offset of the last born-dead reap (-1 = none). */
	int64_t  born_dead_stuck_offset;
	/* Consecutive born-dead reaps on that offset. */
	int      born_dead_stuck_count;

	/* HPN: directory attributes (final modes and times) recorded by the
	 * producer walks and applied by sftp_parallel_wait once every unit has
	 * drained, over the control connection its caller passes in - applying
	 * them earlier would lock directories still being written. Built by the
	 * shared helpers in sftp-hpn-client.c. Walking (main) thread only. */
	struct sftp_hpn_dirattr_list *dirattrs;
};

/* sftp-parallel-watchdog.c - worker health policy */
const char *worker_doom_reason_name(enum worker_doom_reason);
void	 parallel_watchdog_check(struct sftp_parallel *);
void	 parallel_watchdog_sync_check(struct sftp_parallel *);

/* sftp-parallel-reporter.c - reporter thread (reap/respawn/observe) */
void	*parallel_reporter_thread(void *);
void	 parallel_stats_snapshot(struct sftp_parallel *, uint64_t *);

/* hpn_strlist - small string-list utility (lives in sftp-parallel.c) */
void	 hpn_strlist_init(struct hpn_strlist *, size_t);
void	 hpn_strlist_free(struct hpn_strlist *);
void	 hpn_strlist_append(struct hpn_strlist *, const char *);
uint64_t hpn_strlist_drain(struct hpn_strlist *, char ***, size_t *);

/* sftp-parallel-unit.c - work units, trackers, pending, submission */
void	 parallel_unit_free(struct sftp_work_unit *);
struct sftp_work_unit *parallel_unit_make_range(const char *, const char *,
	    off_t, off_t, struct sftp_range_tracker *);
int	 parallel_unit_tracker_finalize(struct sftp_range_tracker *, int,
	    struct sftp_worker *);
int	 parallel_unit_tracker_finalize_n(struct sftp_range_tracker *, int,
	    int, struct sftp_worker *);
int	 parallel_unit_writer_acquire(struct sftp_range_tracker *);
void	 parallel_unit_writer_release(struct sftp_range_tracker *);
int	 parallel_unit_max_retries(struct sftp_parallel *);
int	 parallel_unit_submit(struct sftp_parallel *, struct sftp_work_unit *);
int	 parallel_worker_requeue(struct sftp_parallel *, struct sftp_work_unit *,
	    int front);
void	 parallel_retry_overflow_drain(struct sftp_parallel *);
void	 parallel_retry_overflow_free(struct sftp_parallel *);
void	 parallel_unit_store_range_hash(struct sftp_range_tracker *, int index,
	    uint64_t off, uint64_t len, uint64_t hash);
void	 parallel_bundle_flush_pending(struct sftp_parallel *);
void	 parallel_unit_pending_dec(struct sftp_parallel *);
uint64_t parallel_unit_split_min_size(struct sftp_parallel *);
int	 parallel_unit_ensure_file(struct sftp_conn *,
	    struct sftp_work_unit *);

/* sftp-parallel-worker.c - the worker thread */
void	*parallel_worker_thread(void *);

void	 parallel_verify_prefix_register(struct sftp_parallel *, const char *dir);
int	 parallel_verify_prefix_match(struct sftp_parallel *, const char *path,
	    const char **rel);
char	*parallel_verify_prefix_join(struct sftp_parallel *, int idx,
	    const char *rel);

void	 parallel_verify_tracker_free(struct sftp_range_tracker *);
void	 parallel_verify_park(struct sftp_parallel *,
	    struct sftp_range_tracker *);
void	 parallel_verify_park_whole_file(struct sftp_parallel *,
	    const char *local_path, const char *remote_path, int local_is_target);
int	 parallel_verify_phase_submit(struct sftp_parallel *);
void	 parallel_verify_job_free(struct verify_job *);
void	 parallel_verify_maybe_wave(struct sftp_parallel *);
void	 parallel_verify_prefix_pool_reset(struct sftp_parallel *);
void	 parallel_verify_fail_record(struct sftp_parallel *, int local_is_target,
	    const char *local_path, const char *remote_path);

/* sftp-parallel-respawn.c - spawn/respawn lifecycle */
void	 parallel_respawn_teardown_ssh(struct sftp_worker *);
int	 parallel_respawn_dispatch(struct sftp_parallel *, int);
void	*parallel_respawn_spawn_thread(void *);
void	 parallel_respawn_sweep_stalled(struct sftp_parallel *);

#endif /* SFTP_PARALLEL_INTERNAL_H */
