/*
 * sftp-parallel-watchdog.c - worker health policy for the parallel SFTP
 * orchestrator: per-tick inactivity/throughput heuristics, doom
 * decisions and SIGKILL escalation, fleet sync-stall detection.  Split
 * from sftp-parallel.c; moves are verbatim.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_watchdog_pause_until_ns */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"

static void
watchdog_sample_throughput(struct sftp_parallel *p, uint64_t now)
{
	if (p->cfg.tput_path_healthy_kbps == 0)
		return;	/* feature disabled */

	uint64_t max_kbps = 0;      /* raw max - path-health gate only */
	uint64_t max_ema_kbps = 0;  /* smoothed max - threshold basis */

	double alpha = (p->cfg.tput_ema_alpha > 0.0)
	    ? p->cfg.tput_ema_alpha : 0.2;

	/* First pass: compute per-worker raw kbps, update EMA, find maxima.
	 *
	 * Use bytes_total + live_bytes (continuous progress) rather than
	 * bytes_total alone (file-completion-granular).  Without live_bytes,
	 * a worker mid-transfer shows bytes_delta=0 for several seconds then
	 * a spike at completion - the outlier ticks oscillate and the consec
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
	 * threshold = max_ema_kbps * fraction - both the reference and the
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
			/* EMA not yet warm - skip outlier detection, but don't
			 * reset tput_outlier_ticks: a pre-accumulated consec count
			 * from before this unit boundary should carry forward so a
			 * persistently slow worker is caught after fewer post-warmup
			 * ticks. */
			continue;
		}

		if (in_flight == 0) {
			/* Pause - don't reset.  A persistently slow worker
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
		 * ramping - the very failure mode that drove respawn-churn
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
			 * never increments bytes_total - using it alone keeps
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
		 * outlier above, this fires even when all peers are slow -
		 * the case where a connection comes up in a bad state from
		 * the start and pipelining can't lift it.  The kill itself
		 * happens in parallel_watchdog_check; we just track the
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
void
parallel_watchdog_sync_check(struct sftp_parallel *p)
{
	uint64_t now_bytes = 0;
	uint64_t total_in_flight = 0;
	uint64_t now_ns = monotime_ns();
	int any_paused = 0;	/* any worker heart-beating through a verify/hash */

	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		now_bytes += w->bytes_total;
		total_in_flight += w->units_started - w->units_completed -
		    w->units_failed;
		pthread_mutex_unlock(&w->mu);
		now_bytes += __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);
		if (sftp_conn_watchdog_pause_until_ns(w->conn) > now_ns)
			any_paused = 1;
	}
	now_bytes += p->retired_bytes;
	pthread_mutex_unlock(&p->workers_mu);

	uint64_t delta = (now_bytes >= p->sync_stall_prev_bytes)
	    ? (now_bytes - p->sync_stall_prev_bytes) : 0;
	p->sync_stall_prev_bytes = now_bytes;

	pthread_mutex_lock(&p->pending_mu);
	uint64_t pending = p->pending;
	pthread_mutex_unlock(&p->pending_mu);

	/* Sync-stall observer (write-cache saturation signal): zero aggregate
	 * progress WHILE a unit is in flight.  First tick: prev_bytes was 0 so
	 * delta = all bytes ever, not a stall. */
	int stalled_now = (p->sync_stall_window_pos > 0 && delta == 0 &&
	    total_in_flight > 0);
	if (stalled_now)
		p->sync_stall_ticks++;

	/* Fleet-abort no-progress window: zero aggregate progress while work
	 * REMAINS and no worker is heart-beating.  Unlike the observer above this
	 * does NOT require a unit in flight, so it still accrues when every worker
	 * is failing to connect (bad keys, dead backend) and holds no unit - the
	 * case total_in_flight == 0 would otherwise mask. */
	if (p->sync_stall_window_pos > 0 && delta == 0 && pending > 0 &&
	    !any_paused)
		p->noprogress_consec_ticks++;
	else
		p->noprogress_consec_ticks = 0;

	/* Any sign of life resets the unproductive-death streak: a worker moved
	 * bytes this tick, or one is heart-beating through a long verify/hash
	 * (watchdog-paused).  Either way the fleet is not dead. */
	if (delta > 0 || any_paused)
		p->unproductive_deaths = 0;

	/*
	 * Fleet abort.  Give up on the whole transfer only when EVERY base
	 * condition holds: zero aggregate fleet progress for the window, NO
	 * worker heart-beating (a verify/hash would hold the watchdog pause),
	 * FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams consecutive respawns that
	 * each died without producing a byte (reconnects are not taking hold), and
	 * work still pending.  A single worker still moving data or heart-beating
	 * keeps the
	 * transfer alive - the no-progress window and the unproductive-death
	 * streak both reset on any sign of life above.
	 */
	if (p->noprogress_abort_s > 0 && !p->abort_flag && !any_paused &&
	    pending > 0 &&
	    p->noprogress_consec_ticks >= p->noprogress_abort_s) {
		int abort_n = p->cfg.num_streams * FLEET_ABORT_UNPRODUCTIVE_MULT;
		if (abort_n < 2)
			abort_n = 2;
		if (p->unproductive_deaths >= abort_n) {
			error("transfer stalled: no worker can establish a working "
			    "connection (%d consecutive respawns produced no data, "
			    "last worker exit %d), 0 bytes moved for ~%ds with "
			    "%llu unit(s) pending - aborting",
			    p->unproductive_deaths, p->last_worker_exit_code,
			    p->noprogress_consec_ticks, (unsigned long long)pending);
			sftp_parallel_abort(p);
		}
	}

	if (++p->sync_stall_window_pos >= SYNC_STALL_WINDOW) {
		double frac = (double)p->sync_stall_ticks / SYNC_STALL_WINDOW;
		debug_ft("sync-stall: %u/%u ticks (%.0f%%) - %s",
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
 * Per-worker health classification and dooming action.  Returns 1 if
 * the worker was DEAD (or just transitioned to DEAD this tick), 0
 * otherwise - caller uses this to drive the workers_mu "any_dead"
 * tally.
 *
 * Caller must hold workers_mu; this function acquires per-worker mu
 * only for short critical sections (state read + transition).
 *
 * `tput_dead_this_tick` is the in/out throttle flag - at most one
 * throughput-outlier DEAD promotion per tick across all workers.
 */
static int
watchdog_check_one_worker(struct sftp_parallel *p, struct sftp_worker *w,
    uint64_t now, int queue_has_work, int endgame_idle,
    int *tput_dead_this_tick)
{
	enum worker_health prev, next;
	const char *doom_reason = NULL;	/* set at whichever DEAD site fires */

	pthread_mutex_lock(&w->mu);
	prev = w->health;
	/* Already doomed: the kill was sent and the worker is draining
	 * toward reap - nothing the inactivity heuristics decide matters
	 * anymore, and re-evaluating them re-triggers the doom branches
	 * every tick (observed: one ENDGAME-REAP log line per second
	 * against a worker that cannot die mid-phase).  Doom is
	 * once-per-death; only the SIGKILL escalation below still runs. */
	if (w->doomed) {
		pthread_mutex_unlock(&w->mu);
		next = prev;
		goto sigkill_escalation;
	}
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
	 * at 2 Gbps takes ~50 s - close to STALL_THRESHOLD_SEC, any
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
	/* Starting a new unit counts as progress: byte counters freeze
	 * while the fleet idles at the prompt between commands, so without
	 * this a worker dispatching the FIRST unit of the next transfer
	 * carries the whole idle gap as accrued silence - and the endgame
	 * reaper fires at 0% of a fresh put on a warm fleet.  (Sibling of
	 * the paused-tick re-seed below: silence is measured from the most
	 * recent of byte-progress / held lease / unit dispatch.) */
	if (unit_start > w->last_progress_ns)
		w->last_progress_ns = unit_start;
	uint64_t effective_silence_ns =
	    (w->last_progress_ns > 0 && now > w->last_progress_ns)
	    ? (now - w->last_progress_ns) : 0;

	next = WORKER_HEALTHY;

		/* SSH child gone is the strongest signal - detectable
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
			    (wr == -1 && errno == ECHILD)) {
				next = WORKER_DEAD;
				doom_reason = "child_gone";
			}
		}

		/*
		 * Watchdog pause: a code path on the worker side (typically
		 * a verify-hash phase, but the primitive is generic) has
		 * declared a window of legitimate non-byte-transfer work via
		 * sftp_hpn_watchdog_pause().  Suppress every inactivity-based
		 * heuristic below - none of them can tell "stuck" from
		 * "legitimately quiet" during the declared window.  The
		 * SSH-child-gone check above still ran; that's the only
		 * positive-death signal and never gets suppressed.
		 *
		 * Atomic load, no lock - paused_until_ns is written by the
		 * worker thread and read here from the watchdog thread.
		 */
		if (next != WORKER_DEAD) {
			uint64_t paused_until =
			    sftp_conn_watchdog_pause_until_ns(w->conn);
			if (paused_until > now) {
				/* A held lease counts as progress: re-seed
				 * the silence clock so that when the lease
				 * ends, silence is measured from lease END,
				 * not from the last byte moved BEFORE the
				 * quiet phase.  Without this, a verify that
				 * hashes for minutes carries a minutes-stale
				 * clock into its first post-hash tick - the
				 * suppression vanishes with the lease, the
				 * clock reads the whole hash phase as
				 * silence, and one slow first write-ack gets
				 * the worker reaped as an endgame straggler
				 * (then the verify restarts from scratch). */
				w->last_progress_ns = now;
				goto inactivity_checks_done;
			}
		}

		/*
		 * Born-dead fast-kill.  Worker popped a unit but has zero
		 * forward progress (no completions, no bytes ever, no live
		 * bytes on the current unit) for BORN_DEAD_KILL_SEC.  This is
		 * unambiguous: the SSH session reached the SFTP layer (the
		 * worker thread popped a unit) but no bytes have flowed at
		 * all.  Almost always a server-side channel-window freeze
		 * (e.g. Lustre OST stall).  Kill fast so the respawn slot
		 * gets a fresh SSH session into the same dst - usually that
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
		    && since_unit_start_ns > (uint64_t)p->born_dead_sec
		        * 1000000000ULL) {
			debug_ft("worker %d: born-dead fast-kill "
			    "(unit_start=%llus, 0 bytes, 0 completions)",
			    w->id,
			    (unsigned long long)
			    (since_unit_start_ns / 1000000000ULL));
			next = WORKER_DEAD;
			doom_reason = "born_dead";
		}

		if (next != WORKER_DEAD && queue_has_work && in_flight > 0 &&
		    effective_silence_ns > 0) {
			uint64_t s = effective_silence_ns / 1000000000ULL;
			if (s > WORKER_SILENCE_BRAKE_SEC) {
				next = WORKER_DEAD;
				doom_reason = "dead";
			} else if (s > STALL_THRESHOLD_SEC)
				next = WORKER_STALLED;
		} else if (!queue_has_work && in_flight > 0 &&
		    effective_silence_ns > 0) {
			/*
			 * Isolation: the queue is empty but this worker still
			 * has in-flight units (keeping pending > 0).  No other
			 * worker can take over - if it never progresses,
			 * sftp_parallel_wait hangs forever, so this is the one
			 * silence path that MUST eventually reap even the last
			 * worker.  Under wait-not-kill we are patient about it:
			 * reap only at the WORKER_SILENCE_BRAKE_SEC backstop
			 * (above the transport's peer-stall brake), letting a
			 * recoverable stall on the last unit drain rather than
			 * churning a respawn into the same backend.  A last
			 * worker stuck at the START of a unit (0 bytes ever) is
			 * still caught fast by born-dead above; this backstop is
			 * for one that produced, then went silent mid-stream.
			 * The below-floor branch only sets the doom_reason label
			 * (isolation vs iso_stall); both reap at the backstop.
			 *
			 * effective_silence_ns falls back to "time since the
			 * unit was popped" when the worker has never completed
			 * anything - catches a worker wedged on its very first
			 * unit, where since_completion_ns would still be 0.
			 */
			uint64_t s = effective_silence_ns / 1000000000ULL;
			if (endgame_idle && s > (uint64_t)ENDGAME_STUCK_SEC) {
				/* Endgame stuck-straggler reap (captured-level
				 * log so we can actually observe it fire). */
				if (getenv("HPN_BUNDLE_TIMING") != NULL)
					logit("HPN ENDGAME-REAP worker=%d "
					    "silence=%llus - reaping stuck "
					    "endgame straggler", w->id,
					    (unsigned long long)s);
				next = WORKER_DEAD;
				doom_reason = "endgame_straggler";
			} else if (s > (uint64_t)WORKER_SILENCE_BRAKE_SEC &&
			    p->cfg.tput_path_healthy_kbps > 0 &&
			    w->tput_ema_warmup_ticks >= TPUT_EMA_WARMUP_TICKS &&
			    w->tput_ema_kbps <
			        p->cfg.tput_path_healthy_kbps) {
				next = WORKER_DEAD;
				doom_reason = "isolation";
			} else if (s > WORKER_SILENCE_BRAKE_SEC) {
				next = WORKER_DEAD;
				doom_reason = "iso_stall";
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
		 * tick - by then one respawn may already be in flight.
		 *
		 * Respawn budget: triggered respawns count against the
		 * epoch budget (RESPAWN_MULTIPLIER * num_streams). On
		 * budget exhaustion the orchestrator enters a cooldown
		 * pause rather than aborting immediately - see the
		 * respawn section in the reporter thread for details.
		 */
		if (next != WORKER_DEAD && p->cfg.tput_path_healthy_kbps > 0) {
			int consec = w->tput_outlier_ticks;
			int req = p->cfg.tput_consec_required > 0
			    ? p->cfg.tput_consec_required : 5;
			if (consec >= 2 * req) {
				if (!*tput_dead_this_tick) {
					next = WORKER_DEAD;
					doom_reason = "tput_outlier";
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
		 * as a worker whose EMA throughput stays persistently below a
		 * small fraction of the healthy floor.  Killing triggers the
		 * normal respawn machinery; a fresh SSH session may land in a
		 * healthier TCP state.
		 *
		 * Gated two ways (see the BORN_SLOW_* comment block): fire only
		 * when a healthy peer exists (this worker is a true outlier, not
		 * part of a whole-fleet stall) AND only when no respawn cooldown
		 * is active.  Repeated born-slow kills are respawns, so they push
		 * respawn_epoch_count and trip the escalating cooldown, which
		 * then suppresses born-slow and lets the slow workers run
		 * (best-effort) until the path recovers.  No separate budget.
		 */
		if (next != WORKER_DEAD
		    && !w->doomed
		    && p->cfg.tput_path_healthy_kbps > 0
		    && w->tput_below_floor_ticks >= BORN_SLOW_TICKS) {
			/* Worker qualifies as born-slow (persistently below floor).
			 * The !w->doomed guard stops a worker already killed (but not
			 * yet reaped) from re-triggering each tick (next resets to
			 * HEALTHY every pass). */
			uint64_t floor =
			    (uint64_t)(p->cfg.tput_path_healthy_kbps *
			        BORN_SLOW_FLOOR_FRAC);
			if (p->tput_last_raw_max_kbps >=
			        p->cfg.tput_path_healthy_kbps
			    && p->respawn_resume_s == 0) {
				debug_ft("worker %d: born-slow kill "
				    "(ema=%llukbps < %llukbps for %d ticks; "
				    "healthy peer present, no cooldown)",
				    w->id,
				    (unsigned long long)w->tput_ema_kbps,
				    (unsigned long long)floor,
				    w->tput_below_floor_ticks);
				next = WORKER_DEAD;
				doom_reason = "born_slow";
			} else {
				/* Gated off: no healthy peer (whole-fleet stall) or a
				 * cooldown is active.  Accept this slow-but-working
				 * worker rather than churning a respawn; count it so
				 * reporter_flare can surface "accepting N slow
				 * worker(s)" - also the live signal for whether this
				 * gating is helping or hurting on a real path. */
				p->born_slow_accepting++;
				debug_ft("worker %d: born-slow accepted "
				    "(ema=%llukbps < %llukbps for %d ticks; "
				    "%s)",
				    w->id,
				    (unsigned long long)w->tput_ema_kbps,
				    (unsigned long long)floor,
				    w->tput_below_floor_ticks,
				    p->respawn_resume_s != 0
				        ? "cooldown active"
				        : "no healthy peer");
			}
		}

	inactivity_checks_done:
		/*
		 * ENDGAME-TRACE (HPN_BUNDLE_TIMING): one captured line per
		 * endgame-straggler tick at the convergence point - reached on
		 * EVERY path (including the pause-goto skip) - showing every
		 * decision input and the final outcome, so we can see exactly
		 * why the reaper does or does not fire.
		 */
		if (endgame_idle && in_flight > 0 &&
		    getenv("HPN_BUNDLE_TIMING") != NULL) {
			uint64_t pu =
			    sftp_conn_watchdog_pause_until_ns(w->conn);
			logit("HPN ENDGAME-TRACE worker=%d egi=%d qhw=%d "
			    "inflight=%llu silence=%llus bytes=%llu "
			    "paused=%llds next=%d reason=%s", w->id,
			    endgame_idle, queue_has_work,
			    (unsigned long long)in_flight,
			    (unsigned long long)
			        (effective_silence_ns / 1000000000ULL),
			    (unsigned long long)w_bytes_total,
			    (pu > now)
			        ? (long long)((pu - now) / 1000000000ULL) : 0LL,
			    (int)next, doom_reason ? doom_reason : "(none)");
		}
		/*
		 * Past this point: state-transition logging, doom (SIGTERM),
		 * and SIGKILL escalation.  All three honor whatever value
		 * `next` has now (whether set by an inactivity heuristic
		 * above OR by the SSH-child-gone check, which fires
		 * regardless of pause).  None of them is an inactivity
		 * inference, so pause is no longer relevant.
		 */
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
				w->doom_reason = doom_reason;
			}
			pthread_mutex_unlock(&w->mu);
			if (!already_doomed) {
				if (w->ssh_pid > 0)
					(void)kill(w->ssh_pid, SIGTERM);
				debug_ft("worker %d: sent SIGTERM to ssh "
				    "child (pid %ld)", w->id,
				    (long)w->ssh_pid);
				/*
				 * Endgame straggler: count it (for stats /
				 * debug) and log at DEBUG level only - it is an
				 * internal optimization (reap a stuck bundle and
				 * re-bundle on idle capacity), not something the
				 * user needs to act on, so it stays out of the
				 * default output.  Counted at the doom site so it
				 * is once-per-death (the SIGTERM is a signal
				 * death, not an HPN exit code, so the reap-time
				 * exit-code counters below would miss it).
				 */
				if (doom_reason != NULL && strcmp(doom_reason,
				    "endgame_straggler") == 0) {
					p->endgame_straggler_reaps++;
					debug_ft("worker %d: endgame straggler "
					    "(no progress %llus at end of "
					    "transfer) - reaping, re-bundling on "
					    "a fresh worker", w->id,
					    (unsigned long long)
					    (effective_silence_ns /
					    1000000000ULL));
				}
			}
		}

 sigkill_escalation:
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

int
parallel_watchdog_check(struct sftp_parallel *p)
{
	int any_dead = 0;
	uint64_t now = monotime_ns();
	int queue_has_work = (sftp_workqueue_depth(p->q) > 0);

	/* Per-tick scratch: count of slow workers accepted (born-slow gated
	 * off) this pass; reporter_flare reads it after the watchdog runs. */
	p->born_slow_accepting = 0;

	pthread_mutex_lock(&p->workers_mu);

	/* Endgame-idle gate: walker done, queue drained, and >=1 worker holds
	 * no in-flight unit (idle in pop, free to take over).  Only then does
	 * the per-worker isolation branch fast-reap a stuck straggler. */
	int walker_done = (__atomic_load_n(&p->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE);
	int n_idle = 0;
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *iw = p->workers[i];
		pthread_mutex_lock(&iw->mu);
		if (iw->units_started - iw->units_completed -
		    iw->units_failed == 0)
			n_idle++;
		pthread_mutex_unlock(&iw->mu);
	}
	int endgame_idle = (walker_done && !queue_has_work && n_idle > 0);

	/* Adaptive throughput sample for outlier detection (no-op if
	 * cfg.tput_path_healthy_kbps == 0).  Sets w->tput_outlier_ticks. */
	watchdog_sample_throughput(p, now);

	/* Throttle: at most one DEAD promotion per tick from the
	 * throughput-outlier path. */
	int tput_dead_this_tick = 0;

	for (int i = 0; i < p->num_workers; i++) {
		if (watchdog_check_one_worker(p, p->workers[i], now,
		    queue_has_work, endgame_idle, &tput_dead_this_tick))
			any_dead = 1;
	}
	pthread_mutex_unlock(&p->workers_mu);
	return any_dead;
}
