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
 * sftp-parallel-watchdog.c - worker health policy for the parallel SFTP
 * orchestrator: per-tick inactivity/throughput heuristics, doom
 * decisions and SIGKILL escalation, fleet sync-stall detection.
 */

/*
 * -- Worker state lattice ---------------------------------------------
 *
 * Three orthogonal state machines govern a worker's lifecycle. struct
 * sftp_worker carries one flag for each, tagged (A)/(B)/(C) at the
 * member; this file drives (A) and (B) and consumes (C).
 *
 * (A) Liveness classification (watchdog-written):
 *       HEALTHY, STALLED, DEAD
 *     Recomputed from scratch every pass: next starts at HEALTHY and
 *     the checks below demote it. A worker that recovers is HEALTHY
 *     again on the next pass, and a worker whose ssh child has
 *     vanished goes straight to DEAD. Only DEAD is terminal: once
 *     declared, the worker is doomed and reaped. Written under
 *     worker->mu by a caller that also holds workers_mu. A reader
 *     needs worker->mu, since workers_mu protects the array and not
 *     its contents. Read by the tail detector and the status relay.
 *
 * (B) Doom progression (watchdog-owned):
 *       not doomed -> doomed (SIGTERM sent) -> [SIGKILL escalation if
 *       not yet exited]
 *     The doomed flag prevents double-SIGTERM across ticks. doom_ms is
 *     the SIGTERM timestamp, consulted by the SIGKILL-escalation
 *     deadline.
 *
 * (C) Exit lifecycle (worker-owned):
 *       alive -> exited
 *     Set by the worker thread under worker->mu as the last thing it
 *     does before returning, and read by the reporter for the join and
 *     reap. Two things end a worker. The checks here declaring it DEAD,
 *     which the reap follows with a respawn, and the work queue
 *     reporting shutdown-and-empty, which happens only at teardown and
 *     never reaches this reap because sftp_parallel_stop joins the
 *     reporter before it touches workers.
 *
 * Valid combinations:
 *   (HEALTHY, not doomed, not exited)  - normal running
 *   (STALLED, not doomed, not exited)  - silent but not killed
 *   (DEAD,    doomed,     not exited)  - SIGTERMed, awaiting thread exit
 *   (DEAD,    doomed,     exited)      - ready to reap + respawn
 * Doom is gated on the DEAD verdict, so a STALLED worker is never
 * doomed.
 *
 * (DEAD, not doomed, not exited) exists briefly between the
 * classification and the SIGTERM. Both happen inside one workers_mu
 * hold, so a reader that takes workers_mu never observes it.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "misc.h"

#include "sftp-common.h"		/* Attrib, needed by sftp-client.h */
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_watchdog_pause_until_ms */
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"

/* Render a doom reason for the logs. */
const char *
worker_doom_reason_name(enum worker_doom_reason reason)
{
	switch (reason) {
	case WDR_CHILD_GONE:        return "child_gone";
	case WDR_BORN_DEAD:         return "born_dead";
	case WDR_DEAD:              return "dead";
	case WDR_ENDGAME_STRAGGLER: return "endgame_straggler";
	case WDR_ISOLATION:         return "isolation";
	case WDR_ISO_STALL:         return "iso_stall";
	case WDR_BORN_SLOW:         return "born_slow";
	case WDR_NONE:              return "(none)";
	}
	/* unknown enum value. This should not happen */
	return "(invalid)";
}

/* Adaptive throughput-based stall detection. Computes each worker's byte
 * rate since the last tick and a smoothed EMA of it, finds the fleet
 * maxima, and, when the fastest worker is at or above
 * cfg.tput_path_healthy_bytes_s, counts a tick against any worker below
 * cfg.tput_outlier_fraction of that maximum. The classification itself
 * happens in watchdog_check_one_worker, which combines these ticks with
 * its time-based and ssh-child checks. No-op when
 * cfg.tput_path_healthy_bytes_s is 0. */
static void
watchdog_sample_throughput(struct sftp_parallel *fleet, uint64_t now)
{
	if (fleet->cfg.tput_path_healthy_bytes_s == 0)
		return;	/* feature disabled */

	uint64_t max_bytes_s = 0;      /* raw max - path-health gate only */
	uint64_t max_ema_bytes_s = 0;  /* smoothed max - threshold basis */

	double alpha = fleet->cfg.tput_ema_alpha;

	/* First pass: each worker's raw byte rate since the last tick, its
	 * EMA, and the fleet maxima.
	 *
	 * The rate is measured over bytes_total + live_bytes, not bytes_total
	 * alone. bytes_total only moves at file completion, so a worker
	 * mid-transfer would read zero for seconds and then spike, making the
	 * outlier ticks oscillate instead of accumulating.
	 *
	 * The EMA keeps one worker's single-tick burst from spiking the
	 * threshold and condemning slower but healthy peers. The raw maximum
	 * is kept alongside it for the path-health gate below, which wants to
	 * react to the link immediately rather than lag behind a smoothed
	 * value. */
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		uint64_t now_bytes;
		pthread_mutex_lock(&worker->mu);
		now_bytes = worker->bytes_total;
		pthread_mutex_unlock(&worker->mu);
		now_bytes += __atomic_load_n(&worker->live_bytes, __ATOMIC_RELAXED);

		if (worker->tput_check_ms == 0) {
			/* First sample: initialize baselines, skip this tick. */
			worker->tput_check_bytes = now_bytes;
			worker->tput_check_ms = now;
			worker->tput_current_bytes_s = 0;
			worker->tput_ema_bytes_s = 0;
			continue;
		}

		uint64_t elapsed_ms = now - worker->tput_check_ms;
		uint64_t bytes_delta = (now_bytes >= worker->tput_check_bytes)
		    ? (now_bytes - worker->tput_check_bytes) : 0;
		worker->tput_current_bytes_s = (elapsed_ms > 0)
		    ? bytes_delta * 1000 / elapsed_ms : 0;
		worker->tput_check_bytes = now_bytes;
		worker->tput_check_ms = now;

		/* EMA update, for workers holding a unit only. An idle worker's
		 * EMA is left frozen rather than decayed toward zero, which
		 * would otherwise read as an outlier the moment its next unit
		 * starts, and frozen EMAs are kept out of max_ema_bytes_s so
		 * they cannot inflate the threshold. A worker with no EMA yet is
		 * seeded from its first measurement, so a fast one registers at
		 * once instead of climbing out of zero.
		 *
		 * A change in unit_start_ms means a new unit, which resets the
		 * EMA and the warmup count. Carried over, a frozen healthy EMA
		 * would clear tput_outlier_ticks on the first tick of every unit
		 * and a persistently slow worker would never reach the STALLED
		 * threshold. */
		uint64_t cur_unit_start = __atomic_load_n(&worker->unit_start_ms,
		    __ATOMIC_RELAXED);
		int w_idle = (cur_unit_start == 0);
		if (!w_idle) {
			if (cur_unit_start != worker->tput_last_unit_start_ms) {
				worker->tput_ema_bytes_s = 0;
				worker->tput_ema_warmup_ticks = 0;
				worker->tput_last_unit_start_ms = cur_unit_start;
			}
			if (worker->tput_ema_bytes_s == 0)
				worker->tput_ema_bytes_s = worker->tput_current_bytes_s;
			else
				worker->tput_ema_bytes_s = (uint64_t)(
				    alpha * (double)worker->tput_current_bytes_s +
				    (1.0 - alpha) * (double)worker->tput_ema_bytes_s);
			if (worker->tput_ema_warmup_ticks < TPUT_EMA_WARMUP_TICKS)
				worker->tput_ema_warmup_ticks++;
			if (worker->tput_ema_bytes_s > max_ema_bytes_s)
				max_ema_bytes_s = worker->tput_ema_bytes_s;
		}

		if (worker->tput_current_bytes_s > max_bytes_s)
			max_bytes_s = worker->tput_current_bytes_s;
	}

	/* Diagnostic: log per-worker raw and EMA rates once every ~5 sec. */
	static int sample_ticks = 0;
	if ((sample_ticks++ % 5) == 0) {
		char per_worker[SFTP_PARALLEL_MAX_WORKERS * 32];
		int off = 0;
		per_worker[0] = '\0';
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			int n = snprintf(per_worker + off,
			    sizeof(per_worker) - off,
			    " w%d=%llu(ema=%llu)", worker->id,
			    (unsigned long long)(worker->tput_current_bytes_s / 1024),
			    (unsigned long long)(worker->tput_ema_bytes_s / 1024));
			if (n < 0 || (size_t)(off + n) >= sizeof(per_worker))
				break;
			off += n;
		}
		debug_ft("tput sample (KiB/s): max=%llu max_ema=%llu "
		    "path_healthy=%llu%s",
		    (unsigned long long)(max_bytes_s / 1024),
		    (unsigned long long)(max_ema_bytes_s / 1024),
		    (unsigned long long)(fleet->cfg.tput_path_healthy_bytes_s /
		        1024),
		    per_worker);
	}

	/* Snapshot for the respawn throughput gate (checked in the reporter). */
	fleet->tput_last_raw_max_bytes_s = max_bytes_s;

	/* Path-health gate uses raw max_bytes_s so it reacts immediately when
	 * the link recovers (an EMA-smoothed gate would lag). */
	if (max_bytes_s < fleet->cfg.tput_path_healthy_bytes_s) {
		/* Clear the peer-relative streak only. Peers supply fresh
		 * evidence within a tick or two, so restarting it costs
		 * nothing. tput_below_floor_ticks is left alone: it measures
		 * against an absolute floor and has to survive gaps, or a
		 * single fleet-wide slow tick would reset a genuinely
		 * born-slow worker short of its threshold every time. */
		for (int i = 0; i < fleet->num_workers; i++)
			fleet->workers[i]->tput_outlier_ticks = 0;
		return;
	}

	/* Second pass: classify outliers. Both sides of the comparison are
	 * EMA-smoothed, the per-worker rate and the max it is measured
	 * against, so a single noisy tick cannot swing it either way. Only a
	 * worker holding a unit is judged: one waiting in the queue pop shows
	 * a zero rate legitimately. */
	uint64_t threshold_bytes_s =
	    (uint64_t)(max_ema_bytes_s * fleet->cfg.tput_outlier_fraction);
	/* Absolute floor for born-slow tracking. Config-derived, so it is
	 * computed once rather than per worker. */
	uint64_t born_slow_floor = (uint64_t)(
	    fleet->cfg.tput_path_healthy_bytes_s * BORN_SLOW_FLOOR_FRAC);
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		uint64_t unit_start = __atomic_load_n(&worker->unit_start_ms,
		    __ATOMIC_ACQUIRE);

		/* EMA not warm yet, so there is nothing to judge. Leave
		 * tput_outlier_ticks alone: a streak from before this unit
		 * boundary carries forward, so a persistently slow worker
		 * is caught in fewer post-warmup ticks. */
		if (worker->tput_ema_warmup_ticks < TPUT_EMA_WARMUP_TICKS)
			continue;

		/* Skip the tick without clearing. A persistently slow
		 * worker alternates between holding a unit and waiting for
		 * the next one, so clearing here would wipe the streak
		 * every few ticks and it would never reach the STALLED
		 * threshold. Only genuine recovery clears it, in the else
		 * branch below. */
		if (unit_start == 0)
			continue;

		/* TCP slow-start gate. A worker has to move roughly what the
		 * path delivers in RAMP_RTTS round trips before its EMA is
		 * comparable to the fleet maximum. Without it a fresh worker is
		 * condemned while its cwnd is still ramping, which is what drove
		 * respawn-churn loops: a replacement was killed on its first
		 * tick of slow-start traffic. With no RTT measurement the
		 * tick-based EMA warmup above is the only gate. */
		if (fleet->path_rtt_us > 0 && max_ema_bytes_s > 0) {
			/* Bytes the path delivers in RAMP_RTTS round trips:
			 * bytes/s * rtt_us / 1e6 gives bytes per RTT. */
			uint64_t warmup_bytes =
			    (max_ema_bytes_s * fleet->path_rtt_us *
			        RAMP_RTTS) / 1000000;
			if (warmup_bytes < RAMP_WARMUP_BYTES_MIN)
				warmup_bytes = RAMP_WARMUP_BYTES_MIN;
			if (warmup_bytes > RAMP_WARMUP_BYTES_MAX)
				warmup_bytes = RAMP_WARMUP_BYTES_MAX;

			/* bytes_total + live_bytes again, and here it is what
			 * keeps the gate liftable at all: a worker whose first
			 * unit hangs at the server never completes one, so
			 * bytes_total alone would hold the gate shut forever and
			 * hide a worker that is dribbling rather than stopped. */
			uint64_t bytes_moved;
			pthread_mutex_lock(&worker->mu);
			bytes_moved = worker->bytes_total;
			pthread_mutex_unlock(&worker->mu);
			bytes_moved += __atomic_load_n(&worker->live_bytes,
			    __ATOMIC_RELAXED);

			/* Time cap: lift the gate after RAMP_MAX_WARMUP_SEC
			 * regardless of bytes so a genuinely-slow worker is
			 * not protected for its entire slow lifetime. */
			uint64_t unit_start = __atomic_load_n(
			    &worker->unit_start_ms, __ATOMIC_RELAXED);
			/* Guard now > unit_start before the unsigned subtraction:
			 * the worker can store a fresh unit_start_ms after we
			 * sampled `now`, so unit_start > now would wrap to a huge
			 * delta and spuriously trip the cap. Matches the sibling
			 * since_unit_start_ms guard in watchdog_check_one_worker. */
			int past_time_cap = (unit_start > 0 && now > unit_start &&
			    now - unit_start >
			    (uint64_t)RAMP_MAX_WARMUP_SEC * 1000);

			if (bytes_moved < warmup_bytes &&
			    !past_time_cap) {
				worker->tput_outlier_ticks = 0;
				continue;
			}
		}

		/* Hash-op gate: a worker mid-hash (fresh marker on its conn)
		 * is byte-silent by design, so a zero rate is not evidence. Zero
		 * both streak counters rather than merely holding the kill:
		 * ticks accumulated across a long hash would otherwise fire
		 * the instant the marker goes stale (~3s after the engine
		 * exits), executing a worker that just did legitimate work
		 * and is ramping its first post-hash writes. */
		if (worker->conn != NULL &&
		    sftp_conn_hash_op_live_total(worker->conn) > 0) {
			worker->tput_outlier_ticks = 0;
			worker->tput_below_floor_ticks = 0;
			continue;
		}

		if (worker->tput_ema_bytes_s < threshold_bytes_s) {
			worker->tput_outlier_ticks++;
			debug_ft("worker %d tput-outlier: "
			    "KiB/s=%llu ema=%llu threshold=%llu consec=%d",
			    worker->id,
			    (unsigned long long)(worker->tput_current_bytes_s / 1024),
			    (unsigned long long)(worker->tput_ema_bytes_s / 1024),
			    (unsigned long long)(threshold_bytes_s / 1024),
			    worker->tput_outlier_ticks);
		} else {
			worker->tput_outlier_ticks = 0;
		}

		/* Born-slow tracking: per-worker counter of consecutive ticks
		 * the EMA stayed below an absolute floor (a fraction of the
		 * configured tput_path_healthy_bytes_s). Unlike the peer-based
		 * outlier above, this fires even when all peers are slow -
		 * the case where a connection comes up in a bad state from
		 * the start and pipelining can't lift it. The kill itself
		 * happens in parallel_watchdog_check; we just track the
		 * streak here. */
		if (born_slow_floor > 0 &&
		    worker->tput_ema_bytes_s < born_slow_floor)
			worker->tput_below_floor_ticks++;
		else
			worker->tput_below_floor_ticks = 0;
	}
}

/* Fleet-level progress check, run once per slow-tick (~1s). Two jobs.
 *
 * The sync-stall observer measures aggregate bytes moved since the last
 * tick, across live and reaped workers. Zero progress while a worker
 * holds a unit means every writer hit the same storage bottleneck at
 * once. That is telemetry: the stall fraction is logged when the
 * SYNC_STALL_WINDOW window closes and is intended as a future
 * scale-down signal.
 *
 * The fleet abort is not telemetry. When the fleet has moved nothing for
 * the configured window, work is still pending, no worker is
 * heart-beating, and enough respawns have died without producing a byte,
 * this gives up and aborts the transfer.*/
void
parallel_watchdog_sync_check(struct sftp_parallel *fleet)
{
	uint64_t now_bytes = 0;
	int any_in_flight = 0;
	uint64_t now_ms = monotime_ms();
	int any_paused = 0;	/* any worker heart-beating through a verify/hash */

	/* One pass for three things: the fleet byte total, whether anyone
	 * holds a unit, and whether anyone is heart-beating. */
	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		pthread_mutex_lock(&worker->mu);
		now_bytes += worker->bytes_total;
		pthread_mutex_unlock(&worker->mu);
		now_bytes += __atomic_load_n(&worker->live_bytes, __ATOMIC_RELAXED);
		if (__atomic_load_n(&worker->unit_start_ms,
		    __ATOMIC_ACQUIRE) != 0)
			any_in_flight = 1;
		if (sftp_conn_watchdog_pause_until_ms(worker->conn) > now_ms)
			any_paused = 1;
	}

	/* Reaped workers too, or the aggregate would drop each time one is
	 * reaped and the drop would read as a stall. */
	now_bytes += fleet->retired_bytes;
	pthread_mutex_unlock(&fleet->workers_mu);

	/* The aggregate can move backwards: live_bytes is zeroed at each
	 * completion and folded into bytes_total, so the sum dips between
	 * those two writes. Treat a dip as no progress, not as a negative. */
	uint64_t delta = (now_bytes >= fleet->sync_stall_prev_bytes)
	    ? (now_bytes - fleet->sync_stall_prev_bytes) : 0;
	fleet->sync_stall_prev_bytes = now_bytes;

	/* First sample: prev_bytes was 0, so delta is every byte ever moved
	 * rather than an interval. A dedicated flag rather than window_pos,
	 * which wraps every SYNC_STALL_WINDOW ticks. */
	int first_tick = !fleet->sync_seen_first_tick;
	fleet->sync_seen_first_tick = 1;

	pthread_mutex_lock(&fleet->pending_mu);
	uint64_t pending = fleet->pending;
	pthread_mutex_unlock(&fleet->pending_mu);

	/* Sync-stall observer, a write-cache saturation signal: no aggregate
	 * progress at all while a worker holds a unit. A heart-beating worker
	 * is excluded, since a fleet grinding through verify hashes moves no
	 * bytes for reasons that have nothing to do with the write cache. */
	int stalled_now = (!first_tick && delta == 0 && any_in_flight &&
	    !any_paused);
	if (stalled_now)
		fleet->sync_stall_ticks++;

	/* Fleet-abort no-progress window: no aggregate progress while work
	 * remains and no worker is heart-beating. Unlike the observer above
	 * this does not require a unit in flight, so it still accrues when
	 * every worker is failing to connect and none holds one. */
	if (!first_tick && delta == 0 && pending > 0 &&
	    !any_paused)
		fleet->noprogress_consec_ticks++;
	else
		fleet->noprogress_consec_ticks = 0;

	/* Any sign of life resets the unproductive-death streak: a worker moved
	 * bytes this tick, or one is heart-beating through a long verify/hash
	 * (watchdog-paused). Either way the fleet is not dead. */
	if (delta > 0 || any_paused)
		fleet->unproductive_deaths = 0;

	/*
	 * Give up on the whole transfer only when every condition holds at
	 * once: no aggregate progress for the window, no worker
	 * heart-beating through a verify or hash, work still pending, and
	 * FLEET_ABORT_UNPRODUCTIVE_MULT * num_streams consecutive respawns
	 * that each died without moving a byte. One worker still moving data
	 * or heart-beating keeps the transfer alive, since both the
	 * no-progress window and the unproductive-death streak reset on any
	 * sign of life above.
	 */
	if (fleet->noprogress_abort_s > 0 && !fleet->abort_flag && !any_paused &&
	    pending > 0 &&
	    fleet->noprogress_consec_ticks >= fleet->noprogress_abort_s) {
		int abort_n = fleet->cfg.num_streams * FLEET_ABORT_UNPRODUCTIVE_MULT;
		/* Never let one unproductive death abort a transfer, whatever
		 * the multiplier and stream count work out to. */
		if (abort_n < 2)
			abort_n = 2;
		if (fleet->unproductive_deaths >= abort_n) {
			error("transfer stalled: no worker can establish a working "
			    "connection (%d consecutive respawns produced no data, "
			    "last worker exit %d), 0 bytes moved for ~%ds with "
			    "%llu unit(s) pending - aborting",
			    fleet->unproductive_deaths, fleet->last_worker_exit_code,
			    fleet->noprogress_consec_ticks, (unsigned long long)pending);
			sftp_parallel_abort(fleet);
		}
	}

	/* Once every SYNC_STALL_WINDOW ticks, report what fraction of that
	 * window stalled and reset for the next one. The fraction is the
	 * signal rather than any single tick: one stalled tick is ordinary,
	 * a fifth of a window (SYNC_STALL_THRESHOLD) is the write cache
	 * saturating. */
	if (++fleet->sync_stall_window_pos >= SYNC_STALL_WINDOW) {
		double frac = (double)fleet->sync_stall_ticks / SYNC_STALL_WINDOW;
		debug_ft("sync-stall: %u/%u ticks (%.0f%%) - %s",
		    fleet->sync_stall_ticks, SYNC_STALL_WINDOW,
		    frac * 100.0,
		    frac >= SYNC_STALL_THRESHOLD
		        ? "possible write-cache saturation"
		        : "nominal");
		fleet->sync_stall_ticks = 0;
		fleet->sync_stall_window_pos = 0;
	}
}

/*
 * Per-worker health classification and dooming action.
 *
 * Caller must hold workers_mu; this function acquires per-worker mu
 * only for short critical sections (state read + transition).
 *
 * A worker already doomed skips the classifiers entirely and jumps to
 * the SIGKILL escalation at the bottom, which is the one thing that
 * runs on every path through here.
 */
static void
watchdog_check_one_worker(struct sftp_parallel *fleet, struct sftp_worker *worker,
    uint64_t now, int queue_has_work, int endgame_idle)
{
	enum worker_health prev, next;
	enum worker_doom_reason doom_reason = WDR_NONE;
	/* STALLED via the outlier flag: the worker is progressing, just slow.
	 * The transition log must not claim "no progress" for it */
	int stalled_slow = 0;

	pthread_mutex_lock(&worker->mu);
	prev = worker->health;
	/* Already doomed: the kill was sent and the worker is draining
	 * toward reap - nothing the inactivity heuristics decide matters
	 * anymore, and re-evaluating them re-triggers the doom branches
	 * every tick (observed: one ENDGAME-REAP log line per second
	 * against a worker that cannot die mid-phase). Doom is
	 * once-per-death; only the SIGKILL escalation below still runs. */
	if (worker->doomed) {
		pthread_mutex_unlock(&worker->mu);
		next = prev;
		goto sigkill_escalation;
	}
	uint64_t w_bytes_total = worker->bytes_total;
	uint64_t w_units_completed = worker->units_completed;
	uint64_t since_completion_ms = worker->last_completion_ms ?
	    (now - worker->last_completion_ms) : 0;  /* for log messages */
	pthread_mutex_unlock(&worker->mu);
	uint64_t w_live_bytes = __atomic_load_n(&worker->live_bytes,
	    __ATOMIC_RELAXED);

	/*
	 * Hash-op gate (HPN): a conn with a fresh hash-op marker is mid-hash
	 * for a resume check, verify or repair. That is byte-silent by
	 * design but provably alive, because the marker is refreshed every
	 * second by the server hash heartbeat, or per chunk locally, and
	 * self-clears about 3s after the engine stops.
	 *
	 * The watchdog pause covers the per-tick classifiers below while its
	 * lease is held. This marker covers what the pause does not: the
	 * throughput streaks in watchdog_sample_throughput, which never
	 * consult the pause, and the tail between watchdog_resume and the
	 * first post-hash bytes. Hard evidence, an ssh child exit or a reap,
	 * is unaffected, and a genuinely wedged hash stops refreshing so the
	 * gate reopens within seconds.
	 */
	int hashing = (worker->conn != NULL &&
	    sftp_conn_hash_op_live_total(worker->conn) > 0);

	uint64_t unit_start = __atomic_load_n(&worker->unit_start_ms,
	    __ATOMIC_ACQUIRE);
	uint64_t since_unit_start_ms = (unit_start > 0 &&
	    now > unit_start) ? (now - unit_start) : 0;

	/*
	 * Effective silence: time since we last observed forward
	 * progress in bytes. Tracks (bytes_total + live_bytes), which
	 * climbs continuously during an active transfer regardless of
	 * unit size. Replaces the older completion-based timer that
	 * misfired on whole-file uploads of large files (a 10 GiB file
	 * at 2 Gbps takes ~50 s - close to STALL_THRESHOLD_SEC, any
	 * writeback dip would trip a false DEAD).
	 *
	 * Updated only by this thread; no atomics needed. On first
	 * tick last_progress_ms is 0, so we seed it from now without
	 * touching last_progress_bytes (which is also 0).
	 */
	uint64_t cur_progress_bytes = w_bytes_total + w_live_bytes;
	if (worker->last_progress_ms == 0 ||
	    cur_progress_bytes > worker->last_progress_bytes) {
		worker->last_progress_ms = now;
		worker->last_progress_bytes = cur_progress_bytes;
	}
	/* Starting a new unit counts as progress: byte counters freeze
	 * while the fleet idles at the prompt between commands, so without
	 * this a worker dispatching the first unit of the next transfer
	 * carries the whole idle gap as accrued silence - and the endgame
	 * reaper fires at 0% of a fresh put on a warm fleet. (Sibling of
	 * the paused-tick re-seed below: silence is measured from the most
	 * recent of byte-progress / held lease / unit dispatch.) */
	if (unit_start > worker->last_progress_ms)
		worker->last_progress_ms = unit_start;
	uint64_t effective_silence_ms =
	    (worker->last_progress_ms > 0 && now > worker->last_progress_ms)
	    ? (now - worker->last_progress_ms) : 0;

	next = WORKER_HEALTHY;

	/* SSH child gone is the strongest signal - detectable
	 * without waiting for the worker thread's next I/O.
	 *
	 * waitpid(WNOHANG|WNOWAIT) returns the pid if the child
	 * has exited (including zombies), 0 if it is still running,
	 * and -1/ECHILD if it has already been reaped. WNOWAIT
	 * leaves the zombie in place so the reap loop's blocking
	 * waitpid still succeeds. kill(0) alone misses the
	 * SIGKILL-then-zombie case because a zombie's pid is still
	 * present in the process table. */
	if (worker->ssh_pid > 0) {
		int wstatus;
		pid_t wr = waitpid(worker->ssh_pid, &wstatus,
		    WNOHANG | WNOWAIT);
		if (wr == worker->ssh_pid ||
		    (wr == -1 && errno == ECHILD)) {
			next = WORKER_DEAD;
			doom_reason = WDR_CHILD_GONE;
		}
	}

	/*
	 * Watchdog pause: a code path on the worker side (typically
	 * a verify-hash phase, but the primitive is generic) has
	 * declared a window of legitimate non-byte-transfer work via
	 * sftp_hpn_watchdog_pause(). Suppress every inactivity-based
	 * heuristic below - none of them can tell "stuck" from
	 * "legitimately quiet" during the declared window. The
	 * SSH-child-gone check above still ran; that's the only
	 * positive-death signal and never gets suppressed.
	 *
	 * Atomic load, no lock - the pause deadline is written by the
	 * worker thread and read here from the watchdog thread.
	 */
	if (next != WORKER_DEAD) {
		uint64_t paused_until =
		    sftp_conn_watchdog_pause_until_ms(worker->conn);
		if (paused_until > now) {
			/* A held lease counts as progress, so
			 * re-seed the silence clock and measure
			 * from the end of the lease rather than
			 * from the last byte before it. Otherwise
			 * a verify that hashes for minutes carries
			 * that whole phase into its first post-hash
			 * tick as silence, and one slow write-ack
			 * reaps the worker mid-verify. */
			worker->last_progress_ms = now;
			goto inactivity_checks_done;
		}
	}

	/*
	 * Stuck-range reset: if the worker holding the offset we flagged
	 * stuck is now making progress on that unit, the range unstuck.
	 * Clear the flag so a later born-dead on the same numeric offset,
	 * a different file in a -r transfer say, is judged fresh rather
	 * than wrongly suppressed.
	 *
	 * The test keys on w_live_bytes, progress on the current unit, and
	 * not on w_bytes_total. A proven worker handed the stuck range
	 * always has a lifetime total above zero from its earlier range,
	 * so keying on that would clear the flag the instant scan-idle
	 * reassigns and the proven holder would never become
	 * born-dead-eligible.
	 */
	if (fleet->born_dead_stuck_offset >= 0 &&
	    __atomic_load_n(&worker->unit_offset, __ATOMIC_RELAXED) ==
	        fleet->born_dead_stuck_offset &&
	    w_live_bytes > 0) {
		fleet->born_dead_stuck_offset = -1;
		fleet->born_dead_stuck_count = 0;
	}

	/*
	 * Born-dead fast-kill. The SSH session reached the SFTP layer, since
	 * the worker popped a unit, but no bytes have flowed at all. That is
	 * unambiguous, and almost always a server-side channel-window freeze
	 * such as a Lustre OST stall. Killing fast gets the respawn slot a
	 * fresh session into the same destination, which usually lands on a
	 * healthier server-side path and recovers the capacity in ~5s rather
	 * than ~24s.
	 *
	 * Gates:
	 *  - unit_start > 0   : worker actually has a unit in hand
	 *  - units_completed == 0 && bytes_total == 0 : never made
	 *    any successful progress ever
	 *  - live_bytes == 0  : not even mid-write on the current
	 *    chunk (a slow OST that's still grinding bytes
	 *    through pwrite shouldn't be killed)
	 *  - since_unit_start > BORN_DEAD_KILL_SEC : enough time
	 *    has passed that auth + first OPEN should have completed
	 *
	 * Two kinds of worker are eligible. One that never moved a byte is
	 * the classic case. The second is a proven worker that took over an
	 * already-flagged stuck range, which is what scan-idle creates: the
	 * deferred respawn routes the requeued stuck range onto an idle
	 * proven worker, whose lifetime total is above zero and which would
	 * otherwise be born-dead-immune, so the same-offset cascade never
	 * forms and the suppression never fires. Such a worker qualifies on
	 * zero progress on its current unit at the known-stuck offset,
	 * without any byte counter being consulted.
	 */
	int64_t unit_offset = __atomic_load_n(&worker->unit_offset,
	    __ATOMIC_RELAXED);
	int bd_fresh = (w_units_completed == 0 && w_bytes_total == 0);
	int bd_on_stuck = (unit_offset >= 0 &&
	    unit_offset == fleet->born_dead_stuck_offset);
	if (next != WORKER_DEAD && !hashing && unit_start > 0
	    && w_live_bytes == 0
	    && (bd_fresh || bd_on_stuck)
	    && since_unit_start_ms > (uint64_t)fleet->born_dead_sec
	        * 1000) {
		/*
		 * Stuck-range guard: a prior born-dead reap already
		 * landed on this exact range_offset, so the range is
		 * stuck server-side, not the connection - killing
		 * again (and reassigning to yet another worker) just
		 * feeds the cascade. Suppress the fast-kill and wait.
		 * The silence and isolation brakes below stay the backstop
		 * if the connection really is dead.
		 */
		int stuck = (bd_on_stuck &&
		    fleet->born_dead_stuck_count >= BORN_DEAD_STUCK_KILLS);

		if (stuck) {
			debug_ft("worker %d: born-dead SUPPRESSED at "
			    "offset %lld - stuck range (%d prior "
			    "reaps), waiting not killing", worker->id,
			    (long long)unit_offset,
			    fleet->born_dead_stuck_count);
		} else {
			if (bd_on_stuck)
				fleet->born_dead_stuck_count++;
			else {
				fleet->born_dead_stuck_offset = unit_offset;
				fleet->born_dead_stuck_count = 1;
			}
			debug_ft("worker %d: born-dead fast-kill "
			    "(unit_start=%llus, 0 bytes, 0 "
			    "completions, offset=%lld, hit %d)",
			    worker->id,
			    (unsigned long long)
			    (since_unit_start_ms / 1000),
			    (long long)unit_offset,
			    fleet->born_dead_stuck_count);
			next = WORKER_DEAD;
			doom_reason = WDR_BORN_DEAD;
		}
	}

	if (next != WORKER_DEAD && unit_start > 0 &&
	    effective_silence_ms > 0) {
		uint64_t silence_s = effective_silence_ms / 1000;
		if (queue_has_work) {
			if (silence_s > WORKER_SILENCE_BRAKE_SEC) {
				next = WORKER_DEAD;
				doom_reason = WDR_DEAD;
			} else if (silence_s > STALL_THRESHOLD_SEC)
				next = WORKER_STALLED;
		} else {
			/*
			 * Isolation: the queue is empty but this
			 * worker still holds a unit, so nobody can
			 * take over and sftp_parallel_wait hangs
			 * forever if it never progresses. This is the
			 * one silence path that has to reap even the
			 * last worker, so it waits for the
			 * WORKER_SILENCE_BRAKE_SEC backstop and lets a
			 * recoverable stall drain rather than churning
			 * a respawn into the same backend. All three
			 * branches reap there; they differ only in the
			 * doom_reason they record.
			 *
			 * A worker stuck at the start of a unit is
			 * caught faster by born-dead above, so this is
			 * for one that produced and then went quiet.
			 * effective_silence_ms falls back to time
			 * since the unit was popped, which catches a
			 * worker wedged on its very first unit.
			 */
			if (endgame_idle &&
			    silence_s > (uint64_t)ENDGAME_STUCK_SEC) {
				/* Endgame stuck-straggler reap
				 * (captured-level log so we can actually
				 * observe it fire). */
				if (getenv("HPN_PARALLEL_TRACE") != NULL)
					logit("HPN ENDGAME-REAP worker=%d "
					    "silence=%llus - reaping stuck "
					    "endgame straggler", worker->id,
					    (unsigned long long)silence_s);
				next = WORKER_DEAD;
				doom_reason = WDR_ENDGAME_STRAGGLER;
			} else if (silence_s >
			    (uint64_t)WORKER_SILENCE_BRAKE_SEC &&
			    fleet->cfg.tput_path_healthy_bytes_s > 0 &&
			    worker->tput_ema_warmup_ticks >=
			        TPUT_EMA_WARMUP_TICKS &&
			    worker->tput_ema_bytes_s <
			        fleet->cfg.tput_path_healthy_bytes_s) {
				next = WORKER_DEAD;
				doom_reason = WDR_ISOLATION;
			} else if (silence_s > WORKER_SILENCE_BRAKE_SEC) {
				next = WORKER_DEAD;
				doom_reason = WDR_ISO_STALL;
			}
		}
	}

	/*
	 * Adaptive throughput-outlier flag. tput_outlier_ticks is
	 * set by watchdog_sample_throughput above and is non-zero
	 * only when (a) the feature is enabled and (b) the fastest
	 * worker meets the path-healthy floor. It surfaces workers
	 * running far below their siblings - the cwnd-collapse
	 * signature the time-based detector misses because such a
	 * worker still completes the occasional file, just slowly.
	 *
	 * This sets STALLED and never kills, because slower-than-sibling is
	 * not evidence of death. On a saturated path TCP fairness starves
	 * some streams while their siblings run at line rate: measured on
	 * one such path, 2 of 4 range-split workers ran at ~20 Mbps against
	 * ~500 Mbps peers with silence=0s, actively transferring, and a kill
	 * here aborted the whole single-file transfer. A respawn inherits
	 * the same contention, so it buys nothing.
	 *
	 * Genuinely degraded sessions are killed by born-slow below and
	 * genuinely wedged ones by the silence paths above. STALLED keeps
	 * this one visible in the reporter's telemetry.
	 */
	if (next == WORKER_HEALTHY && !hashing &&
	    fleet->cfg.tput_path_healthy_bytes_s > 0 &&
	    worker->tput_outlier_ticks >= fleet->cfg.tput_consec_required) {
		next = WORKER_STALLED;
		stalled_slow = 1;
	}

	/*
	 * Born-slow fast-kill. A connection that came up in a low-
	 * cwnd / small-recv-window state and never recovers presents
	 * as a worker whose EMA throughput stays persistently below a
	 * small fraction of the healthy floor. Killing triggers the
	 * normal respawn machinery; a fresh SSH session may land in a
	 * healthier TCP state.
	 *
	 * Gated two ways (see the BORN_SLOW_* comment block): fire only
	 * when a healthy peer exists (this worker is a true outlier, not
	 * part of a whole-fleet stall) and only when no respawn cooldown
	 * is active. Repeated born-slow kills are respawns, so they push
	 * respawn_epoch_count and trip the escalating cooldown, which
	 * then suppresses born-slow and lets the slow workers run
	 * (best-effort) until the path recovers. No separate budget.
	 */
	if (next != WORKER_DEAD
	    && !worker->doomed
	    && !hashing
	    && fleet->cfg.tput_path_healthy_bytes_s > 0
	    && worker->tput_below_floor_ticks >= BORN_SLOW_TICKS) {
		/* Worker qualifies as born-slow (persistently below floor).
		 * The !worker->doomed guard stops a worker already killed (but not
		 * yet reaped) from re-triggering each tick (next resets to
		 * HEALTHY every pass). */
		uint64_t floor =
		    (uint64_t)(fleet->cfg.tput_path_healthy_bytes_s *
		        BORN_SLOW_FLOOR_FRAC);
		if (fleet->tput_last_raw_max_bytes_s >=
		        fleet->cfg.tput_path_healthy_bytes_s
		    && fleet->respawn_resume_s == 0) {
			debug_ft("worker %d: born-slow kill "
			    "(ema=%llu < %llu KiB/s for %d ticks; "
			    "healthy peer present, no cooldown)",
			    worker->id,
			    (unsigned long long)(worker->tput_ema_bytes_s / 1024),
			    (unsigned long long)(floor / 1024),
			    worker->tput_below_floor_ticks);
			next = WORKER_DEAD;
			doom_reason = WDR_BORN_SLOW;
		} else {
			/* Gated off: no healthy peer (whole-fleet stall) or a
			 * cooldown is active. Accept this slow-but-working
			 * worker rather than churning a respawn; count it so
			 * reporter_flare can surface "accepting N slow
			 * worker(s)" - also the live signal for whether this
			 * gating is helping or hurting on a real path. */
			fleet->born_slow_accepting++;
			debug_ft("worker %d: born-slow accepted "
			    "(ema=%llu < %llu KiB/s for %d ticks; "
			    "%s)",
			    worker->id,
			    (unsigned long long)(worker->tput_ema_bytes_s / 1024),
			    (unsigned long long)(floor / 1024),
			    worker->tput_below_floor_ticks,
			    fleet->respawn_resume_s != 0
			        ? "cooldown active"
			        : "no healthy peer");
		}
	}

inactivity_checks_done:
	/*
	 * ENDGAME-TRACE (HPN_PARALLEL_TRACE): one captured line per
	 * endgame-straggler tick at the convergence point - reached on
	 * EVERY path (including the pause-goto skip) - showing every
	 * decision input and the final outcome, so we can see exactly
	 * why the reaper does or does not fire.
	 */
	if (endgame_idle && unit_start > 0 &&
	    getenv("HPN_PARALLEL_TRACE") != NULL) {
		uint64_t paused_until =
		    sftp_conn_watchdog_pause_until_ms(worker->conn);
		logit("HPN ENDGAME-TRACE worker=%d egi=%d qhw=%d "
		    "silence=%llus bytes=%llu "
		    "paused=%llds next=%d reason=%s", worker->id,
		    endgame_idle, queue_has_work,
		    (unsigned long long)
		        (effective_silence_ms / 1000),
		    (unsigned long long)w_bytes_total,
		    (paused_until > now)
		        ? (long long)((paused_until - now) / 1000) : 0LL,
		    (int)next, worker_doom_reason_name(doom_reason));
	}
	/*
	 * Past this point: state-transition logging, doom (SIGTERM),
	 * and SIGKILL escalation. All three honor whatever value
	 * `next` has now (whether set by an inactivity heuristic
	 * above OR by the SSH-child-gone check, which fires
	 * regardless of pause). None of them is an inactivity
	 * inference, so pause is no longer relevant.
	 */
	if (next != prev) {
		pthread_mutex_lock(&worker->mu);
		worker->health = next;
		pthread_mutex_unlock(&worker->mu);
		if (next == WORKER_STALLED && stalled_slow) {
			/* Flagged by the outlier detector, so this
			 * worker is progressing and merely slow. The
			 * message says so rather than reporting a
			 * stall, which would send a reader hunting a
			 * wedge that is not there. */
			debug_ft("worker %d slow vs fleet: ema=%llu "
			    "KiB/s, %d consecutive outlier ticks - "
			    "progressing, flagged only",
			    worker->id,
			    (unsigned long long)(worker->tput_ema_bytes_s / 1024),
			    worker->tput_outlier_ticks);
		} else if (next == WORKER_STALLED) {
			debug_ft("worker %d stalled: no progress in "
			    "%llu sec (since_completion=%llus, "
			    "since_unit_start=%llus)",
			    worker->id,
			    (unsigned long long)
			    (effective_silence_ms / 1000),
			    (unsigned long long)
			    (since_completion_ms / 1000),
			    (unsigned long long)
			    (since_unit_start_ms / 1000));
		} else if (next == WORKER_DEAD) {
			debug_ft("worker %d declared dead (%s): "
			    "ssh_pid=%ld silence=%llus "
			    "(since_completion=%llus, "
			    "since_unit_start=%llus)",
			    worker->id,
			    worker_doom_reason_name(doom_reason),
			    (long)worker->ssh_pid,
			    (unsigned long long)
			    (effective_silence_ms / 1000),
			    (unsigned long long)
			    (since_completion_ms / 1000),
			    (unsigned long long)
			    (since_unit_start_ms / 1000));
		}
	}

	/* Doom dead workers: SIGTERM the SSH child so any blocking
	 * I/O in the worker thread unblocks immediately. Guard with
	 * doomed to prevent double-SIGTERM on successive ticks. */
	if (next == WORKER_DEAD) {
		int already_doomed;
		pthread_mutex_lock(&worker->mu);
		already_doomed = worker->doomed || worker->exited;
		if (!already_doomed) {
			worker->doomed = 1;
			worker->doom_ms = now;
			worker->doom_reason = doom_reason;
		}
		pthread_mutex_unlock(&worker->mu);
		if (!already_doomed) {
			if (worker->ssh_pid > 0)
				(void)kill(worker->ssh_pid, SIGTERM);
			debug_ft("worker %d: sent SIGTERM to ssh "
			    "child (pid %ld)", worker->id,
			    (long)worker->ssh_pid);
			/*
			 * Endgame straggler: log at DEBUG level only.
			 * It is an internal optimization (reap a stuck
			 * bundle and re-bundle on idle capacity), not
			 * something the user needs to act on, so it
			 * stays out of the default output.
			 */
			if (doom_reason == WDR_ENDGAME_STRAGGLER) {
				debug_ft("worker %d: endgame straggler "
				    "(no progress %llus at end of "
				    "transfer) - reaping, re-bundling on "
				    "a fresh worker", worker->id,
				    (unsigned long long)
				    (effective_silence_ms /
				    1000));
			}
		}
	}

sigkill_escalation:
	/* SIGKILL escalation: if a doomed worker hasn't exited within
	 * SIGKILL_ESCALATION_SEC, the SSH child is hung in its clean-
	 * shutdown path (broken socket) and the worker thread is blocked
	 * on its stdout pipe. SIGKILL closes the pipes immediately, the
	 * worker thread sees EOF/EPIPE on its next I/O call, sets
	 * exited=1, and gets reaped. Without this we deadlock: the
	 * SIGKILL-on-reap path is gated on exited=1. */
	if (worker->doomed && !worker->exited && worker->doom_ms > 0 && worker->ssh_pid > 0 &&
	    now - worker->doom_ms >
	    (uint64_t)SIGKILL_ESCALATION_SEC * 1000) {
		(void)kill(worker->ssh_pid, SIGKILL);
		debug_ft("worker %d: escalated to SIGKILL after %llus "
		    "(SSH child unresponsive to SIGTERM, pid %ld)",
		    worker->id,
		    (unsigned long long)
		    ((now - worker->doom_ms) / 1000),
		    (long)worker->ssh_pid);
		/* Clear doom_ms so we don't re-escalate every tick. */
		pthread_mutex_lock(&worker->mu);
		worker->doom_ms = 0;
		pthread_mutex_unlock(&worker->mu);
	}
}

/*
 * Classify each worker as HEALTHY, STALLED, or DEAD, then doom the newly
 * DEAD ones with a SIGTERM to the ssh child and worker->doomed set, so
 * the reporter's reap loop can join and respawn them. The signals are the
 * ssh child's existence, how long the worker has gone without moving
 * bytes while holding a unit, and its throughput against its peers and
 * against an absolute floor. watchdog_check_one_worker has the detail.
 */
void
parallel_watchdog_check(struct sftp_parallel *fleet)
{
	uint64_t now = monotime_ms();
	int queue_has_work = (sftp_workqueue_depth(fleet->q) > 0);

	/* Per-tick scratch: the count of slow workers accepted this pass,
	 * with born-slow gated off. reporter_flare reads it after the
	 * watchdog runs. */
	fleet->born_slow_accepting = 0;

	pthread_mutex_lock(&fleet->workers_mu);

	/* Endgame-idle gate: walker done, queue drained, and >=1 worker holds
	 * no in-flight unit (idle in pop, free to take over). Only then does
	 * the per-worker isolation branch fast-reap a stuck straggler. Variables
	 * declared in the lock. */
	int walker_done = (__atomic_load_n(&fleet->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE);
	int any_idle = 0;
	for (int i = 0; i < fleet->num_workers && !any_idle; i++) {
		struct sftp_worker *worker = fleet->workers[i];

		if (__atomic_load_n(&worker->unit_start_ms,
		    __ATOMIC_ACQUIRE) == 0)
			any_idle = 1;
	}
	int endgame_idle = (walker_done && !queue_has_work && any_idle);

	/* Adaptive throughput sample for outlier detection, a no-op if
	 * cfg.tput_path_healthy_bytes_s is 0. Maintains both per-worker
	 * streaks, the peer-relative one and the absolute-floor one. */
	watchdog_sample_throughput(fleet, now);

	for (int i = 0; i < fleet->num_workers; i++)
		watchdog_check_one_worker(fleet, fleet->workers[i], now,
		    queue_has_work, endgame_idle);
	pthread_mutex_unlock(&fleet->workers_mu);
}
