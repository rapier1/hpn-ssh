/*
 * sftp-parallel-internal.h - shared internal state for the parallel
 * SFTP orchestrator module family (sftp-parallel*.c).
 *
 * Everything here was previously file-static in sftp-parallel.c; it is
 * internal to the module family and must not be included elsewhere.
 */

#ifndef SFTP_PARALLEL_INTERNAL_H
#define SFTP_PARALLEL_INTERNAL_H

#include <sys/types.h>

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include "sftp-parallel.h"	/* struct sftp_parallel_config (embedded) */

struct sftp_conn;
struct sftp_workqueue;

#define HPN_MAX_RETRIES_DEFAULT 3
#define HPN_MAX_RETRIES_MIN     1
#define HPN_MAX_RETRIES_MAX     20

/* hpn_max_retries() definition is later in this file - struct
 * sftp_parallel is opaque here.  Forward declaration so callers
 * earlier than the struct definition can still resolve the symbol. */
struct sftp_parallel;

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
 * Bundle mode caps a batch by BYTES (bundle_target_bytes, default 8 MiB),
 * not by file count.  UPLOAD_BATCH_SIZE's 64-file cap is a per-file-path
 * constraint (SSH channel-window pressure from N concurrent file handles)
 * that does NOT apply to a bundle: a bundle is one tar stream over one
 * handle with its own BUNDLE_MAX_INFLIGHT write window.  This is just a high
 * safety ceiling so a pathological stream of tiny files cannot grow a single
 * batch without bound; the 8 MiB byte cap binds first for any file >= ~1 KiB.
 */
#define BUNDLE_BATCH_MAX_FILES  8192

/*
 * Download bundles (hpn-bundle-fetch) list every member's remote path in ONE
 * SFTP request, so a download bundle must also stop before that path list
 * overflows SFTP_MAX_MSG_LENGTH.  Upload streams paths inside the tar, so it is
 * immune - this cap is download-only.  Both producers (the worker accumulator
 * and parallel_bundle_add) check it AFTER adding a member, so the cap reserves
 * one PATH_MAX overshoot + the ~44-byte request header.  Expanded at the use
 * sites (worker / unit), which both have SFTP_MAX_MSG_LENGTH and PATH_MAX. */
#define BUNDLE_DL_FETCH_REQ_MAX \
    ((uint64_t)SFTP_MAX_MSG_LENGTH - PATH_MAX - 1024)

/*
 * Soft byte cap on the size of a single upload batch.  Once a worker's
 * batch crosses this many bytes it stops grabbing additional units, even
 * if UPLOAD_BATCH_SIZE units have not been collected.  This is a SOFT cap
 * - the first unit is always added to the batch even if its size already
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
 * -- Phase 5: bundle-mode (hpn-bundle@hpnssh.org) tunables ----------------
 *
 * When a worker has the bundle path enabled (HPNUseBundle yes in
 * ssh_config AND the server advertised hpn-bundle support), the worker
 * collects upload batches up to BUNDLE_TARGET_BYTES_DEFAULT instead of
 * UPLOAD_BATCH_BYTE_CAP, then dispatches them as a single tar stream via
 * sftp_hpn_bundle_upload.  The smaller target produces many small bundles
 * that compose well with parallel streams - each worker can have a
 * different bundle in flight, the way each worker has a different batch
 * in flight in the non-bundle path.
 *
 * 32 MiB default (HPN_BUNDLE_SIZE_DEFAULT in defines.h).  Override with
 * HPNBundleSize in ssh_config, --bundle-size on hpnsftp, or -o
 * HPNBundleSize=N.  Range clamped to
 * [BUNDLE_TARGET_BYTES_MIN, BUNDLE_TARGET_BYTES_MAX].
 *
 * Files larger than BUNDLE_TARGET_BYTES / BUNDLE_MIN_FILES_PER_BUNDLE
 * are excluded from the bundle path: bundling a single large file
 * doesn't amortise the OPEN/CLOSE round-trip cost the way many small
 * files do, and would just block the worker that picked it up while
 * other workers run dry.  The excluded files go through the regular
 * single-file SFTP path (which may further split via range-split).
 */
#define BUNDLE_TARGET_BYTES_DEFAULT  HPN_BUNDLE_SIZE_DEFAULT
#define BUNDLE_TARGET_BYTES_MIN      HPN_BUNDLE_SIZE_MIN
#define BUNDLE_TARGET_BYTES_MAX      HPN_BUNDLE_SIZE_MAX
#define BUNDLE_MIN_FILES_PER_BUNDLE  4

/* Maximum size of a single file the walker is willing to place in a
 * bundle.  Computed from the worker's bundle_target_bytes.  Files at
 * or above this size go through the non-bundle path. */
#define BUNDLE_FILE_MAX_BYTES(target) \
    ((target) / BUNDLE_MIN_FILES_PER_BUNDLE)

/* Back-compat: some sites still reference the old un-suffixed name. */
#define BUNDLE_TARGET_BYTES BUNDLE_TARGET_BYTES_DEFAULT

/*
 * Wire cost of one file in a bundle: the fixed record header (type + mode +
 * mtime + size + path_len = 23 bytes, see sftp-hpn-tar.h) plus the archive
 * path plus the file data, with no padding.  The producer grouper sizes
 * bundles by this framed cost rather than raw payload, so a bundle's wire size
 * stays near the byte cap even when tiny-file headers/paths dominate.
 */
#define BUNDLE_REC_FRAME_BYTES(plen, sz) \
    (23ULL + (uint64_t)(plen) + (uint64_t)(sz))

/*
 * Work-queue (ring) depth.
 *
 * Non-bundle: the historical N*UPLOAD_BATCH_SIZE*4 + one extra batch - deep
 * enough to feed the 64-file OPEN/CLOSE pipelining.
 *
 * Bundle mode needs far more.  A worker assembles a batch up to
 * bundle_target_bytes using NON-BLOCKING trypop and flushes whatever is queued
 * the instant the queue runs dry (sftp-parallel.c bundle batch loop).  So to
 * let all num_streams workers actually reach a full bundle, the queue must
 * hold roughly num_streams full bundles' worth of small files at once, plus
 * headroom for the walker to refill during a concurrent grab - otherwise the
 * queue starves and bundles flush at a fraction of the target (the old depth,
 * N*64*4, capped 8 workers at ~queue/8 files => ~4-6 MiB bundles regardless of
 * --bundle-size).  Sized for a representative small file (BUNDLE_QUEUE_FILE_HINT;
 * files larger than that just need fewer units, so the queue over-provisions
 * harmlessly; files smaller still under-fill, tunable via the hint).  Capped at
 * WORK_QUEUE_DEPTH_MAX to bound pre-claimed work-unit memory.  The ring itself
 * is pointers; the cost is the queued units the walker pre-enumerates.
 */
#define BUNDLE_QUEUE_FILE_HINT   ((uint64_t)16 * 1024)  /* representative small file */
#define WORK_QUEUE_DEPTH_MAX     ((size_t)65536)        /* hard cap on queued units */


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

/* Watchdog thresholds.  STALL: warn (status only, NO kill) if a worker has had
 * work available but made no bytes-level progress (bytes_total + live_bytes
 * flat) for this long.  The progress signal is bytes-based (live_bytes climbs
 * continuously during a healthy transfer regardless of unit size), so it
 * reflects "no client-side bytes in N seconds" rather than "no unit completed
 * in N seconds".
 *
 * Mid-stream silence is the TRANSPORT's lane.  A worker that was producing and
 * goes quiet is exactly when the connection's TCP_INFO classifier fires: WEDGE
 * reaps it (~10 s) or PEER_STALL waits and brakes at PEER_STALL_BRAKE_SECS
 * (300 s, sftp-hpn-congestion.c) - and on any of those the child exits, so the
 * child-gone check reaps it immediately with the precise cause.  The
 * orchestrator therefore only needs a backstop ABOVE the brake, for the cases
 * the transport CANNOT classify (no TCP_INFO, a LAN path, or a genuinely hung
 * worker): WORKER_SILENCE_BRAKE_SEC.  Keeping it above 300 s lets the
 * transport's wait-not-kill lead rather than the orchestrator pre-empting it at
 * 15-120 s (which re-manufactured the churn the wait was built to avoid).
 * Start-of-unit zero-bytes is a separate lane the transport is usually blind to
 * (e.g. a download worker waiting on a server disk read - the server is not
 * rwnd-limited, so no PEER_STALL), so the born-dead fast-kill (5-40 s,
 * RTT-scaled) stays responsive.
 *
 * 2026-06-05: born-dead stays fast; the mid-stream silence reaps (dead /
 * isolation) were raised from 60/120/15 s to the single backstop below. */
#define STALL_THRESHOLD_SEC          60  /* STALLED warn status (no kill) */
#define WORKER_SILENCE_BRAKE_SEC    330  /* reap a still-connected, byte-silent
                                          * worker only after this - above the
                                          * 300 s transport peer-stall brake so
                                          * the transport self-terminates first */
/*
 * Endgame stuck-straggler reap threshold.  At the endgame (walker done, queue
 * drained, idle capacity) a worker that has made zero progress for this long
 * is reaped so its bundle re-queues (the #1 TRANSPORT_FAILED path) and an idle
 * worker re-bundles it on a fresh connection.  15s sits comfortably above the
 * ~9s worst-case normal bundle, so only genuine stragglers are caught; it caps
 * the endgame tail at ~15s vs. the ~90s+ seen unguarded under heavy loss.
 */
/*
 * Endgame stuck-straggler reap threshold (validated for the 8 MiB default; well
 * above the ~9-10s worst-case normal 8 MiB bundle).  NOTE: a 2026-06-06 sweep
 * showed normal bundle duration scales ~linearly with bundle size (RTT-
 * independent), so this should eventually become size-derived (~0.5*bundle_MiB
 * + 10) once bundle sizing is finalized - see project_bundle_size_rtt_and_
 * endgame_threshold.  Fixed 15 is correct while the default is 8 MiB.
 */
#define ENDGAME_STUCK_SEC            15

/*
 * Number of watchdog ticks (~1 s each) to wait before a worker becomes
 * eligible for throughput-outlier classification.  During this window the
 * worker's EMA is still warming up from its cold-start seed, so any
 * comparison against the peer-max threshold would be unreliable.
 *
 * 5 ticks covers TCP slow-start ramp-up at RTTs up to ~50 ms.  At higher
 * RTTs (100–200 ms) slow-start takes proportionally longer in wall-clock
 * time, but the EMA warmup window still covers it because both the worker's
 * EMA and the threshold EMA are climbing together - neither side is "warm"
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
 * unit_start_ns the gate lifts unconditionally - a healthy TCP slow-start
 * always completes in well under this.
 */
#define RAMP_MAX_WARMUP_SEC       15

/*
 * Born-dead fast-kill threshold.  A worker that has popped a unit but
 * has zero progress (bytes_total + live_bytes + units_completed all 0)
 * for this many seconds is killed and respawned.  The server-side path
 * for that SSH session is wedged - usually a Lustre OST stall that
 * froze the SSH channel window.  Waiting the full WORKER_SILENCE_BRAKE_SEC
 * backstop wastes capacity here: we know after a few seconds that no bytes
 * have arrived, and zero is unambiguous - no peer comparison or EMA warmup
 * needed.  This is the start-of-unit lane the transport can't classify, so it
 * stays responsive while the mid-stream silence reaps were relaxed.
 *
 * Set conservatively: 5 seconds is well above SSH auth completion
 * (~1 RTT after the worker enters the main loop) and the first OPEN
 * round-trip (~1 RTT on a 50ms path).  Anything faster risks killing
 * workers whose first chunk happens to span a slow OST.
 *
 * RTT-dependent (br008 A/B, 2026-06-04): the *right* tolerance is ~100
 * round-trips, not a fixed 5s.  At 51ms RTT 5s was correct; at 151ms a
 * transient backend stall takes longer to clear (it's the same recoverable
 * rwnd-pin as peer-stall, just caught at the start of a unit), so 5s
 * over-fired and ~15s held throughput.  The effective threshold is therefore
 * derived from the measured path RTT: born_dead_sec = clamp(rtt_ms/10,
 * BORN_DEAD_KILL_SEC, BORN_DEAD_SEC_MAX) (integer, mantissa dropped), set in
 * sftp_parallel_set_path_rtt.
 */
#define BORN_DEAD_KILL_SEC        5    /* floor (RTT <= ~59ms) */
#define BORN_DEAD_SEC_MAX        40    /* cap (RTT >= ~400ms) */
#define BORN_DEAD_STUCK_KILLS     1    /* born-dead reaps tolerated on one
				       * range_offset before it is ruled a
				       * server-side stuck range and the fast-
				       * kill is suppressed.  1 = the first
				       * freeze kills (tests the connection-
				       * stall hypothesis via respawn/reassign);
				       * if the NEXT worker freezes on the same
				       * offset, moving the block did not help -
				       * the range is stuck, wait.  Key tuning
				       * knob: a false stuck verdict costs up to
				       * WORKER_SILENCE_BRAKE_SEC of waiting. */

/*
 * Born-slow fast-kill threshold.  A worker that has completed at least one
 * unit (so NOT born-dead) but whose EMA throughput is persistently below
 * BORN_SLOW_FLOOR_FRAC × cfg.tput_path_healthy_kbps for BORN_SLOW_TICKS
 * consecutive throughput samples is killed, in the hope that the respawn
 * lands a TCP connection in a better state.
 *
 * Two gates keep this from thrashing (it has no budget of its own - the
 * shared respawn cooldown is its budget; see reporter_dispatch_respawns):
 *
 *   1. Fleet-state gate: fire only when a healthy peer exists
 *      (tput_last_raw_max_kbps >= the floor), i.e. this worker is a TRUE
 *      outlier.  When the WHOLE fleet is slow (no healthy reference -
 *      backend saturation) born-slow is suppressed; a respawn would land on
 *      the same saturated path and just burn churn while re-queuing the
 *      worker's unit.  That all-slow case is the cooldown/probe machinery's
 *      job, not born-slow's.
 *
 *   2. Cooldown gate: suppressed while a respawn cooldown is active
 *      (respawn_resume_s != 0).  A born-slow kill is a respawn, so repeated
 *      born-slow kills push respawn_epoch_count and trip the epoch ceiling,
 *      which enters the escalating/decaying cooldown.  Once in cooldown we
 *      stop killing slow-but-working workers and accept them (best-effort);
 *      the cooldown's decay-on-health restores born-slow when the path
 *      recovers.  Born-slow and peer-stall are two views of the same
 *      backend-pressure problem at different timescales, so they share one
 *      back-off mechanism rather than each carrying its own counter.
 *
 * Tuning:
 *   BORN_SLOW_TICKS=6        × ~5 s/sample = ~30 s window
 *   BORN_SLOW_FLOOR_FRAC=0.25 below 25% of the configured healthy floor
 *                            (e.g. < 500 kbps when healthy=2000) is "born
 *                            slow" - much lower than legitimate slow paths
 */
#define BORN_SLOW_TICKS           6
#define BORN_SLOW_FLOOR_FRAC      0.25

/*
 * Operator flare cadence (reporter_flare).  A "degraded episode" is any
 * contiguous stretch where the orchestrator is backing off respawns
 * (cooldown active) or accepting slow-but-working workers (born-slow gated
 * off).  We emit ONE edge-triggered notice when an episode opens, periodic
 * reminders while it persists, and a recovery notice on the falling edge.
 * The reminder interval uses the same multiplicative back-off as the cooldown
 * itself: it starts at FLARE_REMINDER_BASE_SEC and doubles per reminder up to
 * FLARE_REMINDER_CAP_SEC, so the user learns quickly that a stall is
 * sustained without a long episode spamming the log.  Reminders escalate from
 * notice to warning wording once the episode has lasted FLARE_WARN_SEC.  All
 * of this is suppressed under -q / -b (quiet stays quiet); it replaces
 * per-event log spam with episode-level framing, with the per-worker detail
 * left at debug level.  Never implies failure - a degraded episode is
 * best-effort-in-progress, not a lost transfer.
 */
#define FLARE_REMINDER_BASE_SEC  60   /* first reminder this far into an episode */
#define FLARE_REMINDER_CAP_SEC  600   /* reminder interval doubles, capped here */
#define FLARE_WARN_SEC          300   /* escalate notice -> warning after this */

/*
 * After a worker has reconnected this many times, emit a one-time
 * user-visible notice that the path may be unreliable.  The cause of each
 * individual respawn is already reported as it happens; this is the
 * cumulative "churn" signal.
 */
#define HPN_WORKER_CHURN_NOTICE   3

/*
 * (Removed 2026-06-07: RANGE_CHUNK_MULTIPLIER.  It fed a per-file range-count
 * ceiling, min(file/floor, num_streams*4), whose stated job was tail-balancing
 * oversubscription.  In practice it acted as a cap that forced absurdly large
 * ranges on big files - a 1.5 TB file became 32 x 46 GB - and the
 * oversubscription premise is contradicted by measurement (more/smaller ranges
 * = throughput fade; see project_range_fade_2rtt_campaign).  Range size is now
 * governed solely by the floor in range_split_min_size_for(); tail-balancing is
 * to be handled at the endgame instead (project_endgame_range_split).)
 */

/*
 * Range-split minimum: static default (RANGE_SPLIT_MIN_SIZE_DEFAULT,
 * 2 GiB) overridable via -M on the command line.  Resolved per
 * orchestrator in range_split_min_size_for() below.  See
 * benchmark/range-split-tuning-analysis.md for the empirical sweep that
 * picked 2 GiB and for the formula-driven scheme that preceded it.
 */

/*
 * Synchronous-stall observer.  Each reporter slow-tick (~1 s) checks whether
 * aggregate bytes transferred across all workers is zero while at least one
 * worker has a unit in flight - a Lustre/storage writeback-stall signature.
 * SYNC_STALL_WINDOW is the rolling window length in slow-ticks; the stall
 * fraction is logged when the window closes.  Observation-only.
 */
#define SYNC_STALL_WINDOW     20    /* ~20 s window */
#define SYNC_STALL_THRESHOLD  0.20  /* fraction at which the log line warns */

/*
 * Fleet abort.  Give up on the whole transfer only when no worker is alive and
 * the fleet cannot re-establish a working connection - never while any single
 * worker is still moving data OR heart-beating (a long verify/hash holds the
 * watchdog pause; see HPN_HEARTBEAT_* in sftp-hpn-server.h).  The window below
 * is how long aggregate fleet progress must be zero; the multiplier sets how
 * many consecutive respawns must die without producing a byte (this multiplier
 * times num_streams) before we conclude reconnects are not taking hold.
 */
#define FLEET_ABORT_NOPROGRESS_SEC    60  /* default zero-progress window (s) */
#define FLEET_ABORT_UNPRODUCTIVE_MULT  2  /* abort after this * num_streams worker
                                           * deaths that never produced a byte */

/*
 * Escalation timeout: how long we let a SIGTERMed SSH child clean up before
 * promoting to SIGKILL.  When the receiving TCP socket is hung (the worker's
 * I/O is stalled - exactly when we declare DEAD), SSH's clean-shutdown path
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
				    * triggering a cooldown pause.  Cause-
				    * agnostic backstop alongside the peer-
				    * stall systemic trigger below. */

/*
 * Respawn cooldown is escalating + decaying, not count-capped.  On each
 * entry (a systemic peer-stall burst or epoch-ceiling churn) the orchestrator
 * pauses RESPAWNS ONLY - live workers keep running - for the current level,
 * starting at BASE and doubling per burst up to CAP.  Sustained healthy
 * throughput decays the level back toward BASE (halve per DECAY_SEC) and ends
 * an active pause early.  There is no cooldown-count abort: under a transient
 * backend stall the tool backs off and retries indefinitely (best-effort),
 * surfacing the condition rather than dropping the transfer.  The only
 * automatic abort remains a genuine dead-end (all workers gone and a respawn
 * probe cannot even be launched).
 */
#define RESPAWN_COOLDOWN_BASE_SEC   30   /* initial pause length */
#define RESPAWN_COOLDOWN_CAP_SEC    3600 /* escalation ceiling (~8 doublings) */
#define RESPAWN_COOLDOWN_DECAY_SEC  30   /* halve the level per this much
					  * sustained-healthy throughput, and
					  * end an active pause early after this
					  * long a continuous healthy streak */

/*
 * Systemic peer-stall detector.  Each slow-tick the reporter pushes the
 * per-tick delta of peer-stall worker DEATHS (p->peer_stall_terminations)
 * into a rolling window; when the window sum reaches the systemic threshold
 * the backend is saturated fleet-wide and we enter/escalate a cooldown.
 * Below the threshold a death is localized - the unit is just re-queued and
 * work-stolen, no cooldown.  Threshold is a fraction of num_streams with an
 * absolute floor so small -j is not tripped by a single coincidental death.
 * The cost asymmetry is lopsided (over-trigger is cheap, self-correcting, and
 * never touches live workers; under-trigger keeps loading a saturated
 * backend), so err toward backing off.
 */
#define PEER_STALL_WINDOW            10  /* slow-ticks (~10 s) */
#define PEER_STALL_SYSTEMIC_FRAC_PCT 50  /* >= this % of num_streams ... */
#define PEER_STALL_SYSTEMIC_MIN       2  /* ... AND >= this many absolute */

enum worker_health {
	WORKER_HEALTHY = 0,
	WORKER_STALLED,
	WORKER_DEAD,
};

/*
 * Worker availability INTENT, written by the worker itself at its
 * voluntary transitions (relaxed atomic).  Distinguishes purposefully
 * idle workers (healthy, ready for work) from busy ones - and from
 * wedged workers, which by definition never reach a voluntary
 * transition and therefore keep claiming BUSY while the watchdog's
 * byte-progress heuristics expose them.  Consumers always read this
 * TOGETHER with worker_health; avail never overrides health.
 *
 * READY  - blocking in pop: queue empty for this worker, fully
 *          available (e.g. the cap-surplus workers of a single-file
 *          transfer under -w).
 * CAPPED - cycling the cap-gate requeue: available for OTHER files,
 *          blocked on this file's writer cap.  Excluded from "idle
 *          capacity" for the file whose tail is being judged.
 * BUSY   - holds a dispatched unit.
 *
 * First consumers (2026-06-12, tail phase B): the fleet-rate median
 * (BUSY+HEALTHY only - idle workers must not deflate it) and the
 * tail detector's idle-capacity gate (READY+HEALTHY).  Also a hook
 * for the respawn-policy redesign and watchdog refinements.
 */
enum worker_avail {
	WORKER_AVAIL_BUSY = 0,
	WORKER_AVAIL_READY,
	WORKER_AVAIL_CAPPED,
};

/*
 * Tail trend detector (phase B, 2026-06-12): TELEMETRY ONLY - detects
 * the condition a human watching the meter flags (sustained aggregate
 * decline / an imminent long crawl) and logs would-arm episodes under
 * HPN_BUNDLE_TIMING for tuning.  No actuation; the endgame split stays
 * env-gated off.  ALL FOUR CONSTANTS ARE TUNING CANDIDATES - the
 * telemetry campaign exists to validate them (acceptance gate: zero
 * episodes across clean S and M runs).
 *
 * The trend alone CANNOT decide: every healthy transfer ends with
 * aggregate decline as workers exhaust the queue.  The deciding
 * conjunction is structural (queue empty + walker done + READY
 * capacity) AND holder-relative (the holder is SLOW versus the
 * still-busy fleet median - a healthy last worker runs at full
 * personal rate and never matches).
 */
#define TAIL_RING_TICKS        25   /* ~5s of 200ms reporter ticks */
#define TAIL_RING_QUARTER      (TAIL_RING_TICKS / 4)
#define TAIL_DECLINE_PCT       25   /* newest-quarter median below
				     * oldest-quarter median by this % */
#define TAIL_PROJECT_SEC       10   /* projected solo-tail threshold */
#define TAIL_HOLDER_LAG_PCT    70   /* holder's window median below this
				     * % of the READY baseline = lagging */
/* Mid-transfer worker substitution (HPN_MIDSTREAM_SUB - PoC, default off). */
#define MIDSTREAM_SUB_CONTRAST_PCT  15  /* a BUSY worker whose EMA is below this
				     * % of the fleet median is an extreme,
				     * unambiguous straggler */
#define MIDSTREAM_SUB_CONFIRM_TICKS  3  /* reporter ticks the contrast must
				     * hold before asking it to yield */
#define MIDSTREAM_BENCH_COOLDOWN_SEC 10 /* a subbed worker stays benched this
				     * long, then re-enters the pool; if still
				     * slow it gets re-subbed, so it is never
				     * permanently lost */
#define TAIL_CONFIRM_SEC        8   /* arm condition must hold continuously
				     * this long (wall clock) before an
				     * episode latches.  Measured basis
				     * (2026-06-12 campaign): every clean-run
				     * false positive self-resolved in 2-5s
				     * (contention reshuffle / post-respawn
				     * ramp - on a shared bottleneck one
				     * worker's fast IS another's slow), the
				     * genuine throttled straggler lagged
				     * 36s continuously.  Persistence is the
				     * discriminator; instantaneous lag
				     * ratios overlap.  Mirrors the design
				     * spec: humans tolerate brief variance
				     * and react to SUSTAINED decline. */

/*
 * Per-worker rate windows (predicate rework, 2026-06-12).  The reporter
 * samples each BUSY worker's personal rate into a small per-worker ring;
 * idle workers keep their last demonstrated samples.  The lagging test
 * becomes "holder's window median < READY workers' demonstrated medians
 * x LAG_PCT" - i.e. would the available workers demonstrably do this
 * faster?  Fixes three measured failures of the fleet-median predicate:
 * the self-referential collapse when only the straggler stays busy
 * (151842 -> 23807 kbps as the busy set shrank), idle-worker deflation,
 * and respawn-warmup false positives (episodes in ~2/3 of churny clean
 * runs: a fresh worker's warming EMA read as "lagging" - here a worker
 * with fewer than WORKER_RATE_MIN_SAMPLES contributes nothing in either
 * role).
 */
#define WORKER_RATE_RING        25  /* ~5s of BUSY-time samples */
#define WORKER_RATE_MIN_SAMPLES 12  /* ~2.4s of history before a worker's
				     * median counts (either side) */

/*
 * ENV-VAR HPN_BUNDLE_TIMING midstream-freeze probe (2026-06-05).  Each worker
 * publishes its current phase (relaxed atomic) so the reporter's per-second
 * FLEETSAMPLE shows WHERE all workers are at the instant of a freeze: blocked
 * waiting for work (popwait) vs assembling a batch vs inside a transfer.
 * Combined with the queue depth and the walker phase, a freeze becomes fully
 * attributable instead of inferred.
 */
enum worker_phase {
	WPH_INIT = 0,
	WPH_POP_WAIT,    /* blocked in sftp_workqueue_pop (queue empty) */
	WPH_ASSEMBLE,    /* collecting a batch via non-blocking trypop */
	WPH_RUN,         /* inside a bundle / single-file transfer */
	WPH_FINALIZE,    /* finalizing entries / draining deferred batch */
	WPH_EXIT,
};


enum sftp_op {
	SFTP_OP_UPLOAD,
	SFTP_OP_DOWNLOAD,
	SFTP_OP_UPLOAD_RANGE,	/* upload a byte range of a large file */
	SFTP_OP_DOWNLOAD_RANGE,	/* download a byte range of a large file */
	SFTP_OP_BUNDLE_UPLOAD,	/* container: members[] packed as one tar stream */
	SFTP_OP_BUNDLE_DOWNLOAD,/* container: members[] fetched as one tar stream */
	SFTP_OP_VERIFY,		/* post-transfer verify (+ inline auto-repair) of
				 * a parked range tracker */
};

/* -- Per-file range-completion tracker --------------------------------
 *
 * Shared across the N range work units that make up a single
 * SFTP_OP_DOWNLOAD_RANGE or SFTP_OP_UPLOAD_RANGE transfer.  Detects
 * partial-range failure: if even one range gives up permanently after
 * retries, the pre-allocated file is full-size with HOLES (some range
 * offsets contain the just-written bytes, others are still zeros from
 * the pre-allocation).  The tracker does NOT delete such a file - it
 * is left in place, resumable via verified resume (reputv / regetv,
 * which refills only the mismatched ranges) - and reports it loudly so
 * the user and automation know it is incomplete rather than finding a
 * full-size file with no error indicator.
 *
 * Protocol (last-completer-frees):
 *   range_tracker_new returns a heap-allocated tracker with
 *   remaining=total and any_failed=0.  Caller stores its pointer on
 *   each of the N range work units' u->range_tracker field at submit
 *   time.
 *
 *   range_tracker_finalize is called EXACTLY ONCE per range unit on
 *   the unit's FINAL completion - success OR permanent give-up.
 *   NEVER on a retry (the unit isn't done yet).  The function takes
 *   the mutex, sets any_failed on give-up, decrements remaining.
 *   Exactly one caller sees remaining transition to 0; that caller
 *   does the post-mortem cleanup (report the incomplete file if
 *   any_failed - leaving it in place, resumable - then destroy the
 *   mutex and free the tracker) and is the LAST owner.
 *
 *   Other callers see remaining > 0 after their decrement and return
 *   without touching the struct further - by design, they cannot
 *   race with the last completer's cleanup because the mutex was
 *   released before any of them returned.
 *
 * Invariants the caller MUST uphold:
 *
 *   (I1) Exactly `total` finalize calls per tracker, no more, no less.
 *        Over-calling drives remaining negative (undefined: free-after-
 *        free, double-free).  Under-calling leaks the tracker AND
 *        suppresses the incomplete-file report.
 *
 *   (I2) Finalize fires on FINAL completion only.  On retry, the
 *        unit goes back on the workqueue and finalize must NOT be
 *        called yet - wait until the next attempt resolves.
 *
 *   (I3) After ANY thread's finalize returns 0, that thread must
 *        treat its u->range_tracker pointer as dead - another caller
 *        may have been the last completer in the meantime and freed
 *        the struct.  Don't deref.  (In practice this is automatic:
 *        the work unit itself is freed right after finalize in
 *        worker_process_result / worker_give_up_unit, so the dead
 *        pointer is unreachable.)
 *
 *   (I4) Worker context `w` is retained in the signature but is no
 *        longer dereferenced: finalize used to need w->conn to sftp_rm
 *        a corrupt remote file, but incomplete files are now left in
 *        place for resume instead of removed.  Passing NULL is always
 *        safe (e.g., synthesised finalize during a submit failure in
 *        submit_*_ranges).
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

/*
 * HPN per-inode concurrent-writer cap.  All range units of one file share a
 * range_tracker; this bounds how many of them write the inode at once.  Piling
 * all -j workers onto a single inode is slower than fewer, because buffered
 * writes serialise on the per-inode write lock (measured on Lustre: 8 writers
 * to one inode < 1 plain stream).  Whole-file/bundle units have no tracker and
 * are never gated.  The live value is per-transfer (-w flag), carried in
 * cfg.writers_per_inode_cap into each tracker's writer_cap below; the
 * default/floor/max constants (HPN_RANGE_WRITERS_CAP_*) live in sftp-parallel.h.
 */

/*
 * Process-wide mirror of the current orchestrator's abort_user flag, for the
 * few message sites that have no path to the orchestrator (range-tracker
 * finalize may run with a NULL worker).  Set by the reporter when a USER
 * interrupt triggers the abort; cleared by sftp_parallel_start for the next
 * fleet (the post-interrupt rebuild).  sftp.c runs one orchestrator at a
 * time, so a single process-wide flag is faithful.
 */
/* Set by the reporter when an abort was USER-initiated (Ctrl-C): lets
 * p-less sites (tracker finalize) tell interrupt fallout from genuine
 * failure.  extern - exactly one definition (sftp-parallel.c); a static
 * here would silently give every module its own dead copy. */
extern volatile sig_atomic_t parallel_user_abort_flag;

/* One per range, for HPNVerifyTransfer per-range verification (upload). */
struct sftp_range_vslot {
	u_int64_t off;    /* original range start in the file */
	u_int64_t len;    /* original range length */
	u_int64_t hash;   /* teed XXH3 of the source range (when valid) */
	int       valid;  /* 1 = teed cleanly; 0 = re-read at finalize */
};

struct sftp_range_tracker {
	pthread_mutex_t        mu;         /* serialises decrement + cleanup */
	int                    total;      /* original range count (immutable
					    * after new; for diagnostics) */
	int                    remaining;  /* finalize calls still owed */
	int                    any_failed; /* sticky: 1 if any range failed */
	enum sftp_range_target target;
	char                  *path;       /* TARGET path (the file written):
					    * local on download, remote on
					    * upload (xstrdup'd in new) */
	/* HPNVerifyTransfer: when verify is set, the source path (the file
	 * read - remote on download, local on upload) and a flag so the last
	 * range to finalize runs a whole-file post-transfer verify on the
	 * finalizing worker's live conn.  src_path xstrdup'd in new. */
	char                  *src_path;
	int                    verify;
	/* HPN concurrent-writer cap (guarded by mu above): active_writers is
	 * the in-flight range count for this file; writer_cap is the ceiling.
	 * Acquired in parallel_worker_thread's dispatch gate, released in
	 * worker_process_result - exactly once per executed unit. */
	int                    active_writers;
	int                    writer_cap;
	/* Writer-slot grant/denial counters (under mu): answer the
	 * dispatch-path model question from the 2026-06-11 pacing
	 * post-mortem (predicted ~5 grants per single-file transfer;
	 * observed behavior implied far more).  Emitted at last-finalize
	 * under HPN_BUNDLE_TIMING. */
	uint64_t               cap_grants;
	uint64_t               cap_denials;
	/* Lazy file creation: first writer to dispatch a range for this
	 * file creates it (if absent - layout-created files pass through)
	 * under mu.  Until then the file does not exist on the target, so
	 * an interrupted transfer leaves no empty full-size placeholders
	 * and verified resume only ever hashes files that hold data. */
	int                    file_ensured;
	/* HPNVerifyTransfer per-range verify (upload only): one slot per range
	 * holding the original byte span and the teed source hash.  NULL unless
	 * this is a verified upload.  Sized `total`; filled at submit. */
	struct sftp_range_vslot *vslots;
	/* vslots allocation count, captured at new and NEVER mutated.  `total`
	 * can GROW at runtime (the endgame split adds pieces), so every consumer
	 * that indexes vslots must bound by this, not by total, or it walks off
	 * the end of the array. */
	int                      vslots_n;
};

/*
 * Range-granular parallel verify: one large file's transfer ranges (vslots) are
 * re-used as verify chunks that fan across the worker pool; they share this
 * per-file job, built from the tracker at submit (the tracker is then freed).
 * Each chunk compares the local range hash against the server's sftp-hash-range:
 * for uploads a valid teed source hash is re-used (no re-read); otherwise the
 * local range is read back (download dest, or any untee'd range).  ranges_left
 * counts down (atomic, both the worker-completion and the unit-drop paths) and
 * whoever drops it to 0 frees the job, recording remote_path as a failure if any
 * chunk set `failed`.  paths + the parallel range arrays are owned by the job.
 * local/remote are already direction-resolved (upload: local=source/remote=dest;
 * download: local=dest/remote=source); local_is_target == download. */
struct verify_job {
	char     *local_path;
	char     *remote_path;
	int       local_is_target;	/* download=1 (no teed); upload=0 */
	int       n_ranges;
	off_t    *offs;
	off_t    *lens;
	uint64_t *hashes;		/* teed source hashes (upload) */
	int      *valid;		/* whether hashes[i] is usable */
	int       ranges_left;		/* atomic refcount */
	int       failed;		/* atomic: any chunk's inline repair failed */
};

/*
 * Parked entry for a whole-file (non-range-split) post-transfer verify - the
 * dominant verify-phase memory term in a big recursive / large-glob transfer,
 * so it is kept small.  The fixed header plus BOTH relative paths live in ONE
 * allocation (a flexible array member): buf holds "local_rel\0remote_rel\0",
 * so a parked file costs a single malloc/free, not three.  EACH path is held
 * relative to a registered directory prefix (independently - upload and
 * download both have one side full and the other possibly relative, so the two
 * sides never share a single base):
 *   {local,remote}_prefix >= 0: the rel is relative to verify_prefixes[idx]
 *                               (the long common dir is held once in the pool).
 *   {local,remote}_prefix <  0: no prefix matched - the rel holds the path as
 *                               received (already short when it was relative).
 * The prefix indices are int16_t - the pool is capped at INT16_MAX entries in
 * parallel_verify_prefix_register (past the cap a dir stays unregistered and
 * its files store the full path).  Build ONLY via verify_whole_item_new()
 * (the single point that owns the size arithmetic); local_rel is buf, and
 * remote_rel begins just past local_rel's NUL.  Resolved to full local/remote
 * at verify time via parallel_verify_prefix_join.
 */
struct verify_whole_item {
	int16_t  local_prefix;		/* pool index, -1 = no prefix */
	int16_t  remote_prefix;
	int8_t   local_is_target;	/* 0 = upload, 1 = download */
	char     buf[];			/* "local_rel\0remote_rel\0" - one alloc */
};

struct sftp_work_unit {
	enum sftp_op op;
	char    *src_path;
	char    *dst_path;
	off_t    size;
	mode_t   mode;
	int      no_retry;   /* permanent failure (EACCES/EDQUOT/EROFS/
			      * ENOSPC class): give up without retries */
	off_t    acked_bytes; /* highwater resume (HPN): contiguous bytes
			       * confirmed transferred by the last execution
			       * attempt of this RANGE unit.  On requeue the
			       * unit advances past them instead of
			       * re-sending the whole range. */
	int      attempt;
	int      yield_from;  /* cooperative yield (phase C): worker id + 1
			       * of the holder that yielded this remainder
			       * (0 = none).  The dispatch loop gives one
			       * courtesy defer so a DIFFERENT worker picks
			       * it up; cleared on that defer so a lone
			       * worker can never deadlock on its own
			       * yield. */
	/* Per-unit resume/verify (whole-file units only - set by the public
	 * submit entry points).  Carries the originating command's intent
	 * (reget vs regetv, scp -Z) into the worker, replacing the dormant
	 * session-global cfg.resume_flag.  Range units never resume; see
	 * the resume⇒whole-file rule in sftp_parallel_submit_upload. */
	int      resume;
	int      verify;
	/* Phase 5: set to 1 after a bundle wire failure (server refused open,
	 * mid-stream error).  The worker batch loop refuses to bundle units
	 * with this flag set and dispatches them through the per-file path
	 * instead - so a server-side cap rejection (or any other bundle
	 * wire failure) does not strand the user's files.  Reset only by
	 * re-creation via make_unit on a fresh submit. */
	int      bundle_ineligible;
	/* Range fields: used only for SFTP_OP_UPLOAD_RANGE / DOWNLOAD_RANGE. */
	off_t    range_offset;
	off_t    range_length;
	int      range_index;  /* this range's slot in the tracker (0-based) */
	uint64_t range_hash;   /* HPNVerifyTransfer: XXH3 of the source bytes,
				* teed during a clean send; consumed into the
				* tracker slot when acked == range_length. */
	/* Shared across all range units of one file.  NULL for non-range
	 * units.  See struct sftp_range_tracker above. */
	struct sftp_range_tracker *range_tracker;
	/* Bundle container (SFTP_OP_BUNDLE_*) only: the small-file member units
	 * this bundle carries.  Grouped producer-side (sftp-parallel-unit.c) so
	 * workers pull a whole bundle instead of racing to accumulate one.  The
	 * worker detaches members before dispatch and worker_run_bundle frees
	 * each via worker_finalize_one_entry; parallel_unit_free frees any still
	 * attached (abort/drain).  NULL / 0 for ordinary units. */
	struct sftp_work_unit **members;
	int                     n_members;
	/* SFTP_OP_VERIFY only: the parked whole-file (small / non-range-split)
	 * verify item - just the two paths + direction, freed by the verify
	 * handler (or by parallel_unit_free if the unit was dropped before any
	 * worker ran it).  EITHER verify_whole (whole-file path) OR verify_job
	 * (range-granular chunk path) is set, never both. */
	struct verify_whole_item *verify_whole;
	/* SFTP_OP_VERIFY range-granular: one chunk [range_offset, range_length) of
	 * a large file.  Many units share one verify_job; the last to finish frees
	 * it.  parallel_unit_free decrements/frees it if the unit is dropped. */
	struct verify_job *verify_job;
	/* Retry-overflow list link (sftp-parallel.c retry_overflow_*).  A worker
	 * re-queue that finds p->q full parks the unit here instead of blocking
	 * (self-deadlock); the reporter drains it back into p->q as space frees.
	 * overflow_front preserves the unit's push_front (head) vs push (tail)
	 * intent across the parking.  Both 0 when the unit is not parked. */
	struct sftp_work_unit  *overflow_next;
	int                     overflow_front;
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
	 * workers update their own. Contention is negligible - the worker
	 * holds the lock only while bumping counters. */
	pthread_mutex_t    mu;
	uint64_t           bytes_total;
	volatile uint64_t  live_bytes;        /* incremental bytes for current
					       * in-progress file; reset to 0
					       * when file completes */
	volatile int       phase;             /* enum worker_phase; relaxed
					       * atomic, reporter reads for the
					       * HPN_BUNDLE_TIMING FLEETSAMPLE */
	uint64_t           units_started;     /* dispatched, may be in flight */
	uint64_t           units_completed;
	uint64_t           units_failed;
	uint64_t           reconnect_count;
	uint64_t           last_completion_ns; /* monotonic ns of last finish */

	/*
	 * Per-worker respawn timing - observability only, no gating decision
	 * is made on these.  Respawn limits today are session-wide (see the
	 * comment block at the respawn dispatch site).  These fields exist
	 * so post-mortem forensics on a stats CSV can answer "which worker
	 * respawned and when," which we wanted while debugging the 2026-05-30
	 * br008 Pattern 2 wedges.  Set under w->mu at the same site as
	 * reconnect_count++.  Zero values mean "never respawned this session."
	 *
	 * If we ever discover one persistently-bad worker is starving healthy
	 * workers of the session's respawn budget, the right answer is a
	 * per-worker time-windowed thrash detector (sliding window, cooldown
	 * on burst) - see the design discussion at the respawn dispatch site.
	 * Until then these are read-only stats fields.
	 */
	uint64_t           first_reconnect_ns;  /* ns of this worker's first respawn */
	uint64_t           last_reconnect_ns;   /* ns of this worker's most recent respawn */

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
	 * Only touched by the reporter/watchdog thread - no locking needed.
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
	int                midstream_slow_ticks;  /* consecutive reporter ticks a
	                                          * BUSY worker's EMA sat far
	                                          * below the fleet median; drives
	                                          * HPN_MIDSTREAM_SUB */
	time_t             midstream_benched_s;   /* if nonzero and still in the
	                                          * future (monotime seconds), this
	                                          * worker was subbed out and stays
	                                          * out of the pool until then
	                                          * (cooldown un-bench), so it cannot
	                                          * re-grab+re-dribble yet the pool
	                                          * never bleeds dry */
	uint64_t           tput_last_unit_start_ns; /* unit_start_ns at last tick;
	                                         * used to detect new-unit starts
	                                         * and reset EMA so stale frozen
	                                         * values don't suppress outlier
	                                         * detection on the new unit */

	uint64_t           idle_ns;            /* ns blocked on workqueue pop,
					        * for completed pops only */
	uint64_t           work_ns;            /* ns actively processing */
	/* Set to monotime_ns() immediately before each blocking pop call,
	 * cleared to 0 immediately after.  The reporter adds (now -
	 * pop_start_ns) to idle_ns when computing idle fraction so that
	 * an in-progress blocking wait is included even though the pop has
	 * not yet returned.  Written/read with relaxed atomics - a brief
	 * race between clearing and the accounting update causes at most
	 * a single-tick undercount, which is harmless for a 35% threshold. */
	uint64_t           pop_start_ns;
	/* Set to monotime_ns() when a unit is popped off the workqueue
	 * (after pop_start_ns is cleared), reset to 0 when the unit's
	 * execute_unit returns.  Lets the watchdog measure how long the
	 * worker has been holding its current unit even when
	 * last_completion_ns is still 0 (worker wedged on its very first
	 * unit - last_completion_ns never gets set, so the existing
	 * since_completion_ns gate misses this case).  Atomic ACQUIRE/
	 * RELEASE so the reporter sees a coherent value. */
	uint64_t           unit_start_ns;
	/* -- Worker state lattice ----------------------------------------
	 *
	 * Three orthogonal state machines.  Each flag below tracks ONE of
	 * them; the combinations encode the full worker lifecycle.
	 *
	 * (A) Liveness classification (watchdog-owned, watchdog-written):
	 *       HEALTHY -→ STALLED -→ DEAD
	 *     De-escalation (DEAD → HEALTHY) never happens; once the
	 *     watchdog declares DEAD, that worker is doomed and reaped.
	 *     Set by reporter under workers_mu; mostly diagnostic.
	 *
	 * (B) Doom progression (watchdog-owned):
	 *       not_doomed -→ doomed (SIGTERM sent) -→ [SIGKILL escalation
	 *                                                if not yet exited]
	 *     The `doomed` flag prevents double-SIGTERM across ticks.
	 *     `doom_ns` is the SIGTERM timestamp, consulted by the
	 *     SIGKILL-escalation deadline.
	 *
	 * (C) Exit lifecycle (worker-owned):
	 *       alive -→ exited
	 *     Set by the worker thread itself just before pthread_exit;
	 *     read by reporter for pthread_join + reap.  Every reap is
	 *     followed by a respawn - there is no "voluntary exit" path
	 *     in the current codebase.
	 *
	 * Valid combinations:
	 *   (HEALTHY,  ¬doomed, ¬exited)            - normal running
	 *   (STALLED,  ¬doomed, ¬exited)            - silent but not killed
	 *   (DEAD,      doomed, ¬exited)            - SIGTERMed, awaiting
	 *                                             thread exit
	 *   (DEAD,      doomed,  exited)            - ready to reap + respawn
	 *
	 * Brief race window after the watchdog's transition: (DEAD,
	 * ¬doomed, ¬exited) holds for a few lines until SIGTERM is sent;
	 * no other thread observes it (the transition + SIGTERM happen in
	 * the same workers_mu critical section).
	 */
	enum worker_health health;             /* (A) HEALTHY/STALLED/DEAD;
						* set by reporter, read for
						* logging + transition gating */
	int                avail;              /* enum worker_avail; relaxed
						* atomic, written by the worker
						* at voluntary transitions (see
						* enum comment); read with
						* health by the tail detector
						* and fleet-median computation */
	uint64_t           unit_size;          /* relaxed atomic; size of the
						* currently-held unit (set at
						* dispatch beside unit_start_ns,
						* 0 when idle); feeds the tail
						* detector's projected-tail */
	int64_t            unit_offset;        /* relaxed atomic; range_offset
						* of the currently-held RANGE
						* unit (-1 when idle or non-
						* range); lets the watchdog
						* recognise successive born-dead
						* reaps on the SAME offset = a
						* server-side stuck range, not a
						* dead connection */
	/* Warm remote handle held across consecutive same-file range writes
	 * (kills the close/reopen + cold-window dip at range boundaries).
	 * Worker thread only.  Closed on file change (execute_unit), before a
	 * blocking idle pop, and on worker exit.  Passed to sftp_upload_range
	 * as a struct sftp_range_warm built from these three fields. */
	u_char            *warm_handle;        /* open remote handle, or NULL */
	size_t             warm_handle_len;
	char              *warm_dst_path;      /* file warm_handle is open on */
	/* Per-worker rate window (reporter thread only): personal rate
	 * samples taken each tick while BUSY; retained while idle so a
	 * READY worker's demonstrated capability stays in evidence.  See
	 * WORKER_RATE_RING in the tail-detector constants. */
	uint64_t           rate_ring[WORKER_RATE_RING];
	int                rate_ring_idx;
	int                rate_ring_count;
	uint64_t           rate_prev_bytes;
	uint64_t           rate_prev_ns;
	/* Cooperative yield request (phase C tail redistribution).  Set to 1
	 * by the reporter when the detector confirms this worker is the
	 * lagging endgame holder (HPNTailRedistribute only); the range
	 * transfer loop polls it via conn->hpn->yield_flag, winds down, and
	 * worker_process_result consumes+clears it to classify the non-
	 * success return as voluntary (requeue remainder, no retry charge).
	 * Relaxed atomics; never set on a worker without rate-window
	 * evidence. */
	int                yield_req;

	int                started;
	int                exited;             /* (C) set by worker on
						* self-exit; read by reporter
						* for reaping */
	int                doomed;             /* (B) set by watchdog before
						* SIGTERM; prevents double-kill */
	const char        *doom_reason;        /* (B) which watchdog path doomed
						* it (born_dead/isolation/stall/
						* dead/tput_outlier/born_slow);
						* emitted in the reap trace */
	uint64_t           doom_ns;            /* (B) monotonic ns when
						* SIGTERM was sent; consulted by
						* SIGKILL-escalation deadline when
						* SSH hangs in its clean-shutdown
						* path (worker thread otherwise
						* blocks on unresponsive pipes
						* forever) */

	/* -- Phase 4 gap 1: pipelined-batch state --------------------
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
	int                               range_warm_disabled; /* per-worker
	                                                        * HPN_NO_RANGE_WARM
	                                                        * (A/B kill switch
	                                                        * for the warm range
	                                                        * handle) */

	/* -- Phase 5: bundle-mode state (hpn-bundle@hpnssh.org) -----
	 * bundle_enabled is set once at worker startup when
	 *   ssh_config HPNUseBundle yes (the default) AND
	 *   sftp_conn_has_hpn_bundle(w->conn) is true.
	 * When set, the worker collects upload batches to bundle_target_bytes
	 * and dispatches them via sftp_hpn_bundle_upload instead of
	 * sftp_upload_batch / sftp_upload_batch_send.  No interaction with
	 * the pipelined-batch state above - bundle and pipelined paths are
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
	uint64_t                    death_ordinal;	/* Nth involuntary worker
						 * loss this transfer; numbers
						 * the user-facing heartbeat
						 * so it matches the summary
						 * count (reporter thread
						 * only) */
	int                         wedge_terminations;	/* workers reaped with
							 * HPN_EXIT_TCP_WEDGE */
	int                         peer_stall_terminations; /* ditto, PEER_STALL */
	int                         endgame_straggler_reaps; /* endgame stuck-
							 * straggler reaps (orchestrator-doomed) */
	/* Tail trend detector state (phase B, reporter thread only - no
	 * locking).  rate_ring holds per-tick aggregate-rate samples
	 * (bytes/sec); the detector compares oldest- vs newest-quarter
	 * medians and latches would-arm EPISODES for telemetry. */
	uint64_t                    tail_rate_ring[TAIL_RING_TICKS];
	int                         tail_ring_idx;
	int                         tail_ring_count;
	uint64_t                    tail_prev_bytes;
	uint64_t                    tail_prev_ns;
	int                         tail_episode;      /* latch: in episode */
	uint64_t                    tail_episode_ns;   /* episode start */
	int                         tail_episodes_total; /* per-transfer count */
	uint64_t                    tail_lag_start_ns; /* when the arm condition
						         * became continuously
						         * true; episode latches
						         * only after it holds
						         * TAIL_CONFIRM_SEC */
	/* HPNTailRedistribute (ssh_config, default yes): arm phase C - on episode latch,
	 * ask the slowest lagging holder to cooperatively yield its
	 * unstarted remainder for redistribution to a proven READY worker.
	 * Default off: the detector stays telemetry-only.  Parsed once at
	 * parallel start. */
	int                         tail_redistribute;
	int                         tail_yield_fired;  /* one yield per
						         * episode latch */
	/* ENV-VAR HPN_RESPAWN_SCAN_IDLE=1: defer fleet-restoring respawns
	 * while READY healthy workers cover the queued demand (a respawn is
	 * a fresh connection into a possibly penalty-counting server; idle
	 * capacity restarts work instantly with no penalty exposure).
	 * respawn_owed persists, so deferred respawns fire when demand
	 * outgrows the idle pool.  Default off.  respawn_defers counts
	 * deferral ticks for telemetry. */
	int                         respawn_scan_idle;
	uint64_t                    respawn_defers;
	uint64_t                    session_start_ns;  /* monotime_ns() at
						       * sftp_parallel_start;
						       * elapsed surfaced in
						       * stats for the
						       * end-of-transfer
						       * summary */
	int                         respawn_epoch_count;   /* respawns in current
							    * epoch; reset when a
							    * cooldown ends */
	time_t                      respawn_cooldown_dur_s; /* escalating cooldown
							    * level in SECONDS; lazy-
							    * init to BASE, x2 per
							    * burst (cap CAP), decays
							    * /2 per DECAY_SEC of
							    * sustained health */
	time_t                      respawn_healthy_since_s; /* monotime() seconds
							    * when the current
							    * sustained-healthy streak
							    * began; 0 = unhealthy */
	time_t                      respawn_decay_anchor_s; /* last second the level
							    * was decayed (or the
							    * health streak began) */
	int                         peer_stall_window[PEER_STALL_WINDOW]; /* per-
							    * slow-tick deltas of
							    * peer-stall deaths */
	int                         peer_stall_window_pos; /* rolling index */
	int                         peer_stall_prev_sample; /* peer_stall_
							    * terminations at the
							    * previous slow-tick */
	time_t                      respawn_resume_s;  /* monotime() seconds when
							* cooldown ends; 0 = not
							* in cooldown */
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
	 * worker failures - they happen on the main thread inside the
	 * recursive walkers (sftp-parallel-walk.c) - so they aren't
	 * captured by per-worker units_failed.  parallel_flush surfaces
	 * this so the user can't mistake a non-zero walker-loss for a
	 * clean transfer.  Bumped via __atomic_fetch_add from any thread.
	 */
	uint64_t                    walker_failures;

	/* enum sftp_walker_phase; relaxed atomic, set by the walker via
	 * sftp_parallel_set_walker_phase, read by the reporter FLEETSAMPLE. */
	volatile int                walker_phase;

	/* Bounded list of paths that could not be delivered, populated at
	 * every give-up site (worker MAX_RETRIES, workqueue push-fail,
	 * walker skip-on-error).  Surfaced inline in parallel_flush's
	 * TRANSFER INCOMPLETE message so users don't have to grep a
	 * potentially huge log for per-file errors.  Uses the reusable
	 * hpn_strlist below - same shape for any future "things-the-user-
	 * needs-to-see" accumulation across threads. */
	struct hpn_strlist          failed_paths;

	/* HPNVerifyTransfer: files whose post-transfer XXH3 hash did NOT
	 * match the source.  The transfer is NOT aborted on a mismatch; the
	 * path is recorded here (thread-safe append from workers) and the
	 * end-of-transfer summary prints them.  A non-empty list makes
	 * hpnsftp exit SFTP_EX_VERIFY_FAILED. */
	struct hpn_strlist          verify_failed_paths;

	/* HPNVerifyTransfer post-transfer phase: completed files (whole-file or
	 * range-split) parked at completion instead of verifying inline, so
	 * verify never runs on the transfer path.  sftp_parallel_wait submits
	 * them as SFTP_OP_VERIFY units once the transfer queue drains; the now
	 * idle workers verify them in parallel on their own conns.  Guarded by
	 * verify_pending_mu (parked from worker threads at completion). */
	pthread_mutex_t             verify_pending_mu;
	struct sftp_range_tracker **verify_pending;	/* range-split files */
	int                         verify_pending_n;
	int                         verify_pending_cap;
	/* Whole-file (non-range-split) parked verifies - lightweight items, the
	 * dominant verify-phase memory term.  Shares verify_pending_mu. */
	struct verify_whole_item  **verify_whole_pending;
	int                         verify_whole_pending_n;
	int                         verify_whole_pending_cap;
	/* Path-factoring prefix pool: registered directory prefixes (the recursive
	 * roots, and the glob/direct source+dest dirs).  Whole-file items store
	 * each path relative to the longest-matching prefix, so the common dir is
	 * held once, not per file.  Deduped, small (command-level, not per-file).
	 * Shares verify_pending_mu; freed at sftp_parallel_stop. */
	char                      **verify_prefixes;
	int                         verify_prefixes_n;
	int                         verify_prefixes_cap;

	/* Parked-verify memory gate (HPN): running total of OUTSTANDING verify
	 * bytes - the parked-item footprint of every file submitted but not yet
	 * verified.  Charged at SUBMIT (parallel_verify_item_bytes_estimate), a
	 * LEADING signal the submitter sees, so the trigger fires the same in both
	 * directions (on download the walker submits everything before any file
	 * parks - charging at park would never be seen).  When it crosses
	 * verify_park_budget - or the prefix pool nears its INT16_MAX cap - submit
	 * runs a verify WAVE that quiesces the outstanding transfers, drains the
	 * parked set, and resets this to 0; submit blocks during the wave, and that
	 * block is the BACKPRESSURE that paces submission with verification and
	 * keeps the wave's quiesce (hence the peak) bounded by the budget.
	 * Fleet-wide (one shared counter, not per worker).  Reset to 0 in
	 * parallel_verify_phase_submit, not decremented per free.  Shares
	 * verify_pending_mu.  Budget set once at start from ENV-VAR
	 * HPN_VERIFY_PARK_BUDGET_MB (default 64 MiB). */
	uint64_t                    verify_parked_bytes;
	uint64_t                    verify_park_budget;

	/* Auto-repair: on a post-transfer verify mismatch the worker splices the
	 * bad 64 MiB sub-chunks of its range inline and re-verifies, bounded by
	 * the attempt cap + convergence.  ON by default; HPN_NO_VERIFY_REPAIR (or
	 * -X VerifyRepair=no) disables; verify_repair_attempts is the cap (3). */
	int                         verify_repair_enabled;
	int                         verify_repair_attempts;

	pthread_t                   reporter_tid;
	int                         reporter_started;

	/* Pending counter for sftp_parallel_wait. */
	pthread_mutex_t             pending_mu;
	pthread_cond_t              pending_cv;
	uint64_t                    pending;

	/*
	 * Worker re-queue overflow list (FIFO of already-allocated units).  When
	 * a worker re-queue finds p->q full it parks the unit here instead of
	 * blocking on the queue it is itself draining (self-deadlock; fatal at
	 * -j1).  The reporter drains this back into p->q via trypush as space
	 * frees.  Costs no new allocation (these are existing pending units, so
	 * bounded by in-flight work) and is decoupled from pending: parked units
	 * stay counted in p->pending, so sftp_parallel_wait does not complete
	 * while any remain.  Guarded by retry_overflow_mu.
	 */
	pthread_mutex_t             retry_overflow_mu;
	struct sftp_work_unit      *retry_overflow_head;
	struct sftp_work_unit      *retry_overflow_tail;
	size_t                      retry_overflow_n;

	/*
	 * Sum of u->size across units currently in the workqueue (waiting to
	 * be popped - does NOT include in-flight work being processed by a
	 * worker).  Updated atomically by submit/pop sites.  Brief overcounts
	 * are possible during the gap between increment and queue push (or
	 * decrement and queue pop), but never undercounts - the order of
	 * operations ensures the counter leads the queue state.
	 *
	 * The watchdog uses this to distinguish "worker stalled with work
	 * pending" from "worker idle, queue empty."
	 */
	volatile uint64_t           queued_bytes;

	/*
	 * Producer-side bundle accumulator (sftp-parallel-unit.c).  Bundle-
	 * eligible small files are grouped HERE by the single submit thread
	 * into whole bundles, instead of being pushed individually and raced
	 * over by workers - the startup thundering-herd that stranded a
	 * transfer's first files as un-bundled single round-trips.  Flushed
	 * into a SFTP_OP_BUNDLE_* container at the framed-byte / file-count
	 * cap (parallel_bundle_add) and at sftp_parallel_wait (the tail).
	 * bundle_mu is defensive: bundle-eligible adds are main-thread-only
	 * (worker re-submits are always bundle_ineligible, so they bypass
	 * this and push individually).
	 */
	pthread_mutex_t             bundle_mu;
	struct sftp_work_unit     **bundle_pending;    /* member units, grown */
	int                         bundle_pending_n;
	int                         bundle_pending_cap;
	uint64_t                    bundle_pending_framed;  /* sum framed bytes */
	uint64_t                    bundle_pending_path_bytes; /* download fetch
				     * request bytes (4 + remote path / member);
				     * caps the bundle at BUNDLE_DL_FETCH_REQ_MAX */
	enum sftp_op                bundle_pending_op;   /* UPLOAD | DOWNLOAD */

	/*
	 * Bytes carried by workers that have exited (fault / shutdown).
	 * snapshot_workers iterates only the live workers[] array, so an
	 * exiting worker would otherwise erase its bytes_total from the
	 * aggregate.  Captured under workers_mu just before the worker is
	 * removed from the array; read by snapshot_workers under the same
	 * lock.  Keeps aggregate_bytes_for_meter monotonic.
	 */
	/* ssh child PIDs of IN-FLIGHT spawn attempts (registered between fork
	 * and sftp_init completion), so abort/stop can SIGTERM them instead
	 * of waiting out a full connect timeout - the unbounded wait held the
	 * user's exit hostage for minutes on a slow/penalizing server.
	 * Guarded by workers_mu. */
	pid_t                       spawning_pids[SFTP_PARALLEL_MAX_WORKERS];
	int                         n_spawning;
	/* monotime() seconds when each spawning_pids[] entry registered.  The
	 * reporter SIGTERMs a spawn stalled past HPN_RESPAWN_STALL_SEC so a
	 * wedged handshake (server accepted the TCP but stalled kex/auth, which
	 * ConnectTimeout does not bound) cannot pin pending_respawns above 0 and
	 * deadlock the dead-end abort net - fatal at -j1, where the stalled
	 * respawn is the only path to progress.  Parallel to spawning_pids[],
	 * guarded by workers_mu. */
	time_t                      spawning_since[SFTP_PARALLEL_MAX_WORKERS];

	uint64_t                    retired_bytes;
	/* Companions to retired_bytes: counters that previously DIED with the
	 * reaped worker struct, silently undercounting every post-respawn
	 * aggregate (end-of-transfer report, failure counts).  Accumulated at
	 * the same reap site, added back in sftp_parallel_get_stats. */
	uint64_t                    retired_wired;
	uint64_t                    retired_units_completed;
	uint64_t                    retired_units_failed;

	/*
	 * Cached result of sftp_fs_info() on the destination filesystem.
	 * Without caching, the walker queries fs-info synchronously on the
	 * control connection for every large file - at high RTT this stalls
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

	/* Abort CAUSE: 1 when the abort came from the user's interrupt
	 * (Ctrl-C via ext_interrupt_flag) rather than a fleet failure.
	 * Read by the interrupt-aware messaging - a user who hit Ctrl-C
	 * gets one calm summary instead of error theater. */
	volatile sig_atomic_t       abort_user;

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
	/* Post-transfer verify-phase meter (HPN).  When active, the reporter
	 * drives aggregate_progress_counter from the verify pending count rather
	 * than the transfer-byte snapshot, so the meter shows verify progress
	 * (and not a frozen 100% transfer bar) for the duration of the phase.
	 * verify_meter_total is the bytes transferred this command (= bytes to
	 * verify); verify_total_units is the SFTP_OP_VERIFY unit count. */
	int                         verify_phase_active;
	uint64_t                    verify_total_units;
	uint64_t                    verify_done_units;   /* atomic; worker-bumped */
	/* Byte-granular verify progress: bytes hashed for FULLY verified files
	 * (atomic; a worker folds its per-conn in-flight count in at each file's
	 * completion).  The reporter drives the meter from verify_done_bytes plus
	 * the sum of every worker's in-flight count, so a single huge file's bar
	 * advances every second instead of jumping 0->100% at completion. */
	uint64_t                    verify_done_bytes;
	off_t                       verify_meter_total;

	int                         started;
	int                         stopped;

	/*
	 * Synchronous-stall detector state.  Touched only by the reporter's
	 * slow-tick path (no lock needed).
	 */
	uint32_t sync_stall_ticks;      /* stall slow-ticks in current window */
	uint32_t sync_stall_window_pos; /* slow-ticks elapsed in current window */
	uint64_t sync_stall_prev_bytes; /* aggregate bytes at previous slow-tick */

	/* Operator flare episode tracking (reporter_flare).  See FLARE_*. */
	int      flare_in_episode;       /* currently inside a degraded episode */
	time_t   flare_episode_start_s;  /* monotime() when it opened */
	time_t   flare_last_reminder_s;  /* last periodic reminder emitted */
	time_t   flare_reminder_interval_s; /* current reminder gap; x2 per
	                                  * reminder, capped, reset per episode */
	int      born_slow_accepting;    /* slow workers accepted (born-slow gated
	                                  * off) this watchdog tick; reset each
	                                  * pass, read by reporter_flare */

	/*
	 * Fleet abort (see the FLEET_ABORT_* comment): give up on the whole
	 * transfer only when no worker is alive and the fleet cannot reconnect -
	 * never while one worker is still moving data or heart-beating.  Fires
	 * only when ALL hold: zero aggregate progress for noprogress_abort_s,
	 * no worker watchdog-paused, unproductive_deaths >= FLEET_ABORT_UNPRODUCTIVE_MULT
	 * * num_streams, and units pending.  HPN_NOPROGRESS_ABORT_SEC overrides the
	 * window; 0 disables the abort entirely.
	 */
	int      noprogress_abort_s;     /* zero-progress window (s); 0 = abort off */
	int      noprogress_consec_ticks;/* consecutive whole-fleet zero-progress ticks */
	int      unproductive_deaths;    /* consecutive worker deaths that produced 0
	                                  * lifetime bytes; reset on any fleet progress
	                                  * or heartbeat (a sign of life) */
	int      last_worker_exit_code;  /* last reaped worker's exit code, -1 if
	                                  * signaled/unknown; for the abort message */
	int      born_dead_sec;          /* 0-bytes kill threshold; RTT-derived in
	                                  * sftp_parallel_set_path_rtt */
	/* Stuck-range detector (reporter/watchdog thread only).  born_dead's
	 * "kill fast, the respawn lands on a healthier path" assumption is
	 * false when the stall is a server-side STUCK RANGE (e.g. a Lustre OST
	 * frozen in the server's read() syscall): a fresh worker handed the
	 * same range born-dies too.  When successive born-dead reaps land on
	 * the SAME range_offset, the range is stuck server-side, not the
	 * connection - stop the fast-kill cascade and WAIT (the silence brake
	 * remains the backstop if it is genuinely dead). */
	int64_t  born_dead_stuck_offset; /* range_offset of the last born-dead
	                                  * reap (-1 = none) */
	int      born_dead_stuck_count;  /* consecutive born-dead reaps on that
	                                  * offset */

	/* Optional per-worker stats CSV (enabled via HPN_WORKER_STATS_CSV env).
	 * Opened lazily by the reporter on first tick; closed at orchestrator
	 * stop.  Touched only by the reporter thread. */
	FILE    *stats_csv;
	uint64_t stats_csv_start_ns;
};

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

/* sftp-parallel-watchdog.c - worker health policy */
int	 parallel_watchdog_check(struct sftp_parallel *);
void	 parallel_watchdog_sync_check(struct sftp_parallel *);

/* sftp-parallel-reporter.c - reporter thread (reap/respawn/observe) */
void	*parallel_reporter_thread(void *);
void	 parallel_stats_snapshot(struct sftp_parallel *, uint64_t *,
	    uint64_t *, uint64_t *);

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
int	 parallel_unit_writer_acquire(struct sftp_range_tracker *);
void	 parallel_unit_writer_release(struct sftp_range_tracker *);
int	 parallel_unit_max_retries(struct sftp_parallel *);
void	 parallel_unit_pending_trace(const char *, struct sftp_parallel *,
	    const struct sftp_work_unit *, int, const char *);
int	 parallel_unit_pending_trace_on(void);
int	 parallel_unit_submit(struct sftp_parallel *, struct sftp_work_unit *);
/* Worker-context re-queue: non-blocking.  Tries p->q (front when front!=0);
 * on a full queue parks the unit on the retry-overflow list rather than
 * blocking.  Returns 0 if the unit was placed (queue or overflow), -1 only if
 * the queue is shut down (caller does the give-up bookkeeping). */
int	 parallel_worker_requeue(struct sftp_parallel *, struct sftp_work_unit *,
	    int front);
/* Reporter-context: move overflow-parked units back into p->q while it has
 * room (non-blocking).  No-op when the overflow list is empty. */
void	 parallel_retry_overflow_drain(struct sftp_parallel *);
/* Stop/abort cleanup: free any units still parked on the overflow list. */
void	 parallel_retry_overflow_free(struct sftp_parallel *);
void	 parallel_unit_store_range_hash(struct sftp_range_tracker *, int index,
	    uint64_t off, uint64_t len, uint64_t hash);
/* Flush any partially-filled producer-side bundle (the tail); called from
 * sftp_parallel_wait once a command has finished submitting. */
void	 parallel_bundle_flush_pending(struct sftp_parallel *);
void	 parallel_unit_pending_dec(struct sftp_parallel *);
void	 parallel_unit_pending_dec_traced(struct sftp_parallel *,
	    const struct sftp_work_unit *, int, const char *);
uint64_t parallel_unit_split_min_size(struct sftp_parallel *);
int	 parallel_unit_ensure_file(struct sftp_conn *,
	    struct sftp_work_unit *);

/* sftp-parallel-worker.c export (moves there in a later step) */
void	*parallel_worker_thread(void *);
/* Post-transfer whole-file verify of one completed file, recording any
 * mismatch in the orchestrator's verify_failed_paths.  local_is_target=1
 * when the local file is the one this host wrote (download).  Runs on the
 * caller's (live) worker conn.  Used by the whole-file path and the
 * range-split finalize. */
void	 parallel_verify_one(struct sftp_worker *, const char *local_path,
	    const char *remote_path, int local_is_target);

/* Path-factoring prefix pool for whole-file verify (sftp-parallel-unit.c):
 * register() records one directory prefix (deduped; "." / relative-no-dir
 * skipped); match() finds the longest registered prefix of `path`, points *rel
 * at the suffix, and returns the prefix index (-1 = no match, *rel = path);
 * join() rebuilds a full path from an index + relative (index < 0 copies rel).
 * Each path side is factored independently, so upload and download - where one
 * side is full and the other may be relative - are handled identically. */
void	 parallel_verify_prefix_register(struct sftp_parallel *, const char *dir);
int	 parallel_verify_prefix_match(struct sftp_parallel *, const char *path,
	    const char **rel);
char	*parallel_verify_prefix_join(struct sftp_parallel *, int idx,
	    const char *rel);

/* Free a completed range tracker (range-split files reuse their transfer
 * tracker for verify; this releases it afterwards).  Defined in
 * sftp-parallel-unit.c. */
void	 parallel_verify_tracker_free(struct sftp_range_tracker *);
/* Park a completed file for the post-transfer verify phase.  park() takes a
 * range-split tracker (per-range source hashes); park_whole_file() stores a
 * lightweight verify_whole_item.  phase_submit() drains the parked sets into
 * SFTP_OP_VERIFY work units (from sftp_parallel_wait). */
void	 parallel_verify_park(struct sftp_parallel *,
	    struct sftp_range_tracker *);
void	 parallel_verify_park_whole_file(struct sftp_parallel *,
	    const char *local_path, const char *remote_path, int local_is_target);
int	 parallel_verify_phase_submit(struct sftp_parallel *);
void	 parallel_verify_job_free(struct verify_job *);
/* Parked-verify memory gate (HPN).  maybe_wave() is called by the main-thread
 * submitter after each unit; if the parked set is over budget (or the prefix
 * pool near its cap) it runs a verify WAVE: quiesce in-flight transfers, drain
 * the parked set through phase_submit, then reset the prefix pool.  pool_reset()
 * empties verify_prefixes (safe only once every parked item is verified+freed,
 * i.e. inside the wave).  Both run on the submitter thread only. */
void	 parallel_verify_maybe_wave(struct sftp_parallel *);
void	 parallel_verify_prefix_pool_reset(struct sftp_parallel *);
/* Record a verify failure in verify_failed_paths naming the DEST - the written
 * file that is actually corrupt: remote on upload, local on download - with a
 * "local file"/"remote file" label, so the end-of-run summary points at the
 * file the user has rather than the (clean) source. */
void	 parallel_verify_fail_record(struct sftp_parallel *, int local_is_target,
	    const char *local_path, const char *remote_path);

/* sftp-parallel-respawn.c - spawn/respawn lifecycle */
void	 parallel_respawn_teardown_ssh(struct sftp_worker *);
int	 parallel_respawn_dispatch(struct sftp_parallel *, int);
void	*parallel_respawn_spawn_thread(void *);
void	 parallel_respawn_sweep_stalled(struct sftp_parallel *);

#endif /* SFTP_PARALLEL_INTERNAL_H */
