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

/* sftp-parallel-reporter.c - the reporter thread for the parallel SFTP
 * orchestrator.
 *
 * One of these runs per fleet. It ticks every 200 ms and owns four jobs: it
 * aggregates progress and is the only thread allowed to paint the meter, it
 * runs the watchdog as a pass rather than a thread of its own, it reaps
 * workers that have exited and triggers their respawns, and it emits the
 * observability output - fleet samples, the CSV, and operator flares.
 *
 * Being the sole display writer is what most of the locking here protects:
 * workers post counters for the reporter to fold in, and never touch the
 * meter themselves. */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "progressmeter.h"

#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"
#include "hpn-exit-codes.h"

/* Human-readable enum names for the trace output. */
static const char *
worker_phase_name(int ph)
{
	switch (ph) {
	case WPH_POP_WAIT: return "popwait";
	case WPH_ASSEMBLE: return "assemble";
	case WPH_RUN:      return "run";
	case WPH_FINALIZE: return "finalize";
	case WPH_EXIT:     return "exit";
	default:           return "init";
	}
}

static const char *
walker_phase_name(int ph)
{
	switch (ph) {
	case SFTP_WKP_ENUM:   return "enum";
	case SFTP_WKP_MKDIR:  return "mkdir";
	case SFTP_WKP_FSINFO: return "fsinfo";
	case SFTP_WKP_LAYOUT: return "layout";
	case SFTP_WKP_SUBMIT: return "submit";
	case SFTP_WKP_DONE:   return "done";
	default:              return "init";
	}
}

/* Sum the fleet's transferred bytes: what live workers have retired, what
 * they have in flight, and what already-reaped workers contributed. Taken
 * under workers_mu and each worker's own mutex. */
void
parallel_stats_snapshot(struct sftp_parallel *fleet, uint64_t *bytes_out)
{
	uint64_t bytes = 0;

	pthread_mutex_lock(&fleet->workers_mu);
	/* Bytes from workers that have already exited and been reaped. */
	bytes += fleet->retired_bytes;
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		pthread_mutex_lock(&worker->mu);
		bytes += worker->bytes_total;
		/* live_bytes is written atomically by the worker without
		 * holding worker->mu to avoid lock contention in the inner
		 * transfer loop. Read it with a relaxed atomic load
		 * for the display value. */
		bytes += __atomic_load_n(&worker->live_bytes, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&worker->mu);
	}
	pthread_mutex_unlock(&fleet->workers_mu);
	*bytes_out = bytes;
}

/* Classify and log how a reaped worker died, from the wait status plus
 * worker->doomed (did we kill it?). Diagnostic only; the caller respawns
 * either way. Death modes:
 *
 *   - doomed                  : the watchdog terminated it (reason already
 *                               logged when it was doomed).
 *   - HPN transport exit code : the worker self-diagnosed and self-exited
 *                               (the "known cause" tier - see
 *                               hpn-exit-codes.h).
 *   - exit 255                : ssh transport error / dropped connection.
 *   - other exit code         : remote subsystem status, propagated.
 *   - SIGKILL (not doomed)    : ambiguous - this reap path force-SIGKILLs,
 *                               so it most likely reflects our own kill of
 *                               a child that had not yet exited.
 *   - other signal            : a genuine crash (we only ever send SIGKILL).
 *
 * Read on the reporter thread, which also owns the doom state - so
 * worker->doomed needs no lock here. */
static void
classify_worker_death(const struct sftp_worker *worker, int have_status, int status)
{
	struct sftp_parallel *fleet = worker->parent;
	const char *cause = NULL;
	uint64_t n;
	int quiet = 0;

	/* One plain-language heartbeat per involuntary worker loss, numbered
	 * by a transfer-global ordinal so the running count adds up to the
	 * end-of-transfer respawn summary. Full forensic detail stays at
	 * debug.
	 *
	 * Quiet causes are the high-frequency churn a fleet absorbs on its
	 * own - startup deaths, dropped connections, slow-worker cycling -
	 * and heartbeat at debug only. They still count toward the ordinal
	 * and the summary. Rare causes stay user-visible. */
	if (worker->doomed) {
		/* No default: the compiler then flags a new doom reason that
		 * nobody classified here. */
		switch (worker->doom_reason) {
		case WDR_BORN_DEAD:
			cause = "worker unresponsive at startup";
			quiet = 1;
			break;
		case WDR_ENDGAME_STRAGGLER:
			cause = "worker stalled at the endgame";
			break;
		case WDR_BORN_SLOW:
			cause = "worker persistently slow";
			quiet = 1;
			break;
		case WDR_DEAD:
		case WDR_ISO_STALL:
		case WDR_ISOLATION:
			cause = "worker stalled (no progress)";
			break;
		case WDR_CHILD_GONE:
			cause = "worker connection lost";
			quiet = 1;
			break;
		case WDR_NONE:
			/* The field is only written on a DEAD transition, and
			 * every one of those sets a reason, so this should not
			 * happen. */
			cause = "worker terminated for an unknown reason "
			    "(this should not happen)";
			break;
		}
		debug_ft("worker %d: reaped after orchestrator termination "
		    "(%s)", worker->id,
		    worker_doom_reason_name(worker->doom_reason));
	} else if (!have_status) {
		cause = "worker lost";
		debug_ft("worker %d: died (no wait status)", worker->id);
	} else if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);

		switch (code) {
		case HPN_EXIT_TCP_WEDGE:
			fleet->wedge_terminations++;
			cause = "worker connection wedged";
			debug_ft("worker %d: self-terminated: TCP wedge",
			    worker->id);
			break;
		case HPN_EXIT_TCP_PEER_STALL:
			fleet->peer_stall_terminations++;
			cause = "worker remote stopped draining";
			debug_ft("worker %d: self-terminated: peer stall",
			    worker->id);
			break;
		case 255:
			cause = "worker connection lost";
			quiet = 1;
			debug_ft("worker %d: ssh transport error / dropped "
			    "connection (exit 255)", worker->id);
			break;
		case 0:
			cause = "worker exited unexpectedly";
			debug_ft("worker %d: exited cleanly (watchdog had not "
			    "doomed it)", worker->id);
			break;
		default:
			/* The remaining transport self-checks share a code
			 * range, which is a test rather than a label. */
			if (HPN_EXIT_IS_TCP(code)) {
				cause = "worker transport self-check failed";
				debug_ft("worker %d: self-terminated: "
				    "transport (exit %d)", worker->id, code);
			} else {
				cause = "worker exited unexpectedly";
				debug_ft("worker %d: exited with status %d",
				    worker->id, code);
			}
			break;
		}
	} else if (WIFSIGNALED(status)) {
		if (WTERMSIG(status) == SIGKILL) {
			/* Our own kill during the reap. The child had not
			 * noticed its closed pipe yet, so this is not a
			 * crash. */
			cause = "worker connection closed";
			quiet = 1;
		} else {
			cause = "worker terminated unexpectedly";
		}
		debug_ft("worker %d: killed by signal %d", worker->id,
		    WTERMSIG(status));
	} else {
		cause = "worker lost";
		debug_ft("worker %d: reaped (unrecognized wait status)",
		    worker->id);
	}

	n = ++fleet->death_ordinal;
	/* During teardown the deaths are manufactured and nothing is
	 * reconnecting - keep it out of the user's face. */
	if (fleet->abort_flag || fleet->stopped)
		debug("%s (teardown)", cause);
	else if (quiet)
		debug("%s; reconnecting (respawn %llu)", cause,
		    (unsigned long long)n);
	else
		logit("%s; reconnecting (respawn %llu)", cause,
		    (unsigned long long)n);

	/* One-time heads-up once reconnects cross a fleet-scaled threshold: the
	 * per-respawn lines show the churn happening, this names it as a path
	 * reliability concern. Keyed on the session-wide death_ordinal so it
	 * survives per-worker respawns. Fires before the fleet gives up, and is
	 * suppressed during teardown. Reporter thread only, so no lock. */
	if (!fleet->abort_flag && !fleet->stopped &&
	    !fleet->churn_notice_emitted &&
	    n >= (uint64_t)fleet->cfg.num_streams * HPN_PATH_CHURN_NOTICE_MULT) {
		fleet->churn_notice_emitted = 1;
		logit("this transfer has required %llu worker reconnections; "
		    "the network path may be unreliable",
		    (unsigned long long)n);
	}
}

/* Reap workers that have marked themselves exited (connection died,
 * fault-injected exit, or fatal protocol violation). Every exit is
 * involuntary - the orchestrator always respawns.
 *
 * Two phases for clean locking: collect-under-lock, then join-and-free
 * outside the lock (pthread_join can take arbitrary time).
 *
 * Returns the count of reaped workers, which equals the number of
 * respawn slots the caller (reporter) needs to dispatch. */
static int
reporter_reap_exited_workers(struct sftp_parallel *fleet)
{
	struct sftp_worker *to_reap[SFTP_PARALLEL_MAX_WORKERS];
	int n_reap = 0;

	/* Collect the workers that have marked themselves exited, carrying
	 * their counters into the fleet's retired totals on the way out: the
	 * byte, wired and unit counts die with the struct, and the aggregate
	 * has to stay monotonic across a respawn. live_bytes was zeroed at
	 * the worker's last completion, so it is not double-counted.
	 * Backwards, so removing an entry does not disturb the indices still
	 * to be visited. */
	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = fleet->num_workers - 1; i >= 0; i--) {
		struct sftp_worker *worker = fleet->workers[i];
		int exited;
		uint64_t bytes;

		pthread_mutex_lock(&worker->mu);
		exited = worker->exited;
		bytes  = worker->bytes_total;
		if (exited) {
			uint64_t wired = worker->conn ?
			    sftp_conn_bytes_wired(worker->conn) : 0;

			fleet->retired_bytes += bytes;
			fleet->retired_wired += wired;
			fleet->retired_units_failed += worker->units_failed;
			debug("reap-capture: worker %d conn=%p wired=%llu "
			    "bytes=%llu retired_wired_now=%llu", worker->id,
			    (void *)worker->conn, (unsigned long long)wired,
			    (unsigned long long)bytes,
			    (unsigned long long)fleet->retired_wired);
		}
		pthread_mutex_unlock(&worker->mu);
		if (exited) {
			to_reap[n_reap++] = worker;
			memmove(&fleet->workers[i],
			    &fleet->workers[i + 1],
			    (fleet->num_workers - i - 1) *
			    sizeof(*fleet->workers));
			fleet->num_workers--;
		}
	}
	pthread_mutex_unlock(&fleet->workers_mu);

	/* Shut each collected worker down and free it. Nothing outside this
	 * function refers to them now and their threads have exited, so the
	 * worker fields are read without the worker mutex. The fleet fields
	 * written here are only ever written from this thread, which also
	 * runs the watchdog pass, so they need no lock either. */
	for (int i = 0; i < n_reap; i++) {
		struct sftp_worker *worker = to_reap[i];
		uint64_t lifetime_bytes;
		int status = 0, reaped = 0, exit_code;

		pthread_join(worker->tid, NULL);
		lifetime_bytes = worker->bytes_total;
		if (worker->conn)
			sftp_free(worker->conn);
		if (worker->fd_in >= 0)
			close(worker->fd_in);
		if (worker->fd_out >= 0)
			close(worker->fd_out);
		if (worker->ssh_pid > 0) {
			/* Belt-and-suspenders: may already be dead from
			 * SIGTERM above. A child that self-exited is already a
			 * zombie, so this SIGKILL is a no-op and waitpid still
			 * returns its real exit code. */
			(void)kill(worker->ssh_pid, SIGKILL);
			reaped = (waitpid(worker->ssh_pid, &status, 0) ==
			    worker->ssh_pid);
		}
		/* Classify unconditionally, not just when there was a wait
		 * status: an in-array worker always has a live ssh_pid, and one
		 * without should still reach the summary rather than being
		 * freed silently. */
		exit_code = (reaped && WIFEXITED(status)) ?
		    WEXITSTATUS(status) : -1;
		fleet->last_worker_exit_code = exit_code;
		/* Fleet-abort signal: a worker that died without ever committing
		 * a byte, and whose ssh child did not exit 0, is a respawn that
		 * failed to take hold. The streak resets in
		 * parallel_watchdog_sync_check on any sign of life. */
		if (lifetime_bytes == 0 && exit_code != 0)
			fleet->unproductive_deaths++;
		classify_worker_death(worker, reaped, status);
		pthread_mutex_destroy(&worker->mu);
		free(worker);
	}
	return n_reap;
}

/* Operator-facing flare for degraded episodes. Called once per reporter
 * slow-tick after the watchdog and respawn dispatch, so cooldown state and
 * born_slow_accepting are fresh. A "degraded episode" is any contiguous
 * stretch where we are backing off respawns (cooldown active) or accepting
 * slow-but-working workers (born-slow gated off). Edge-triggered: one notice
 * when it opens, a periodic reminder (escalating notice->warning) while it
 * lasts, a recovery notice when it closes. Best-effort framing throughout -
 * a degraded episode is the transfer slowing down and adapting, not failing.
 * On a clean transfer degraded is always 0 and this is a no-op. */
static void
reporter_flare(struct sftp_parallel *fleet)
{
	time_t now_s;
	int cooldown_active, accepting_slow, degraded;

	/* Quiet stays quiet: -q and -b both set print_flag to SFTP_QUIET.
	 * Errors (TRANSFER INCOMPLETE, failed paths) still surface via error(). */
	if (fleet->cfg.print_flag == SFTP_QUIET)
		return;

	now_s = monotime();
	/* booleans */
	cooldown_active = (fleet->respawn_resume_s != 0);
	accepting_slow  = (fleet->born_slow_accepting > 0);
	degraded        = cooldown_active || accepting_slow;

	if (!degraded) {
		if (fleet->flare_in_episode) {
			/* Falling edge: recovered. */
			logit("transfer recovered after %llds - no longer "
			    "backing off",
			    (long long)(now_s - fleet->flare_episode_start_s));
			fleet->flare_in_episode = 0;
		}
		return;
	}

	if (!fleet->flare_in_episode) {
		/* Rising edge: open an episode. No countdown - the cooldown
		 * level escalates/decays and isn't actionable; just the state. */
		fleet->flare_in_episode = 1;
		fleet->flare_episode_start_s = now_s;
		fleet->flare_last_reminder_s = now_s;
		fleet->flare_reminder_interval_s = FLARE_REMINDER_BASE_SEC;
		if (cooldown_active)
			logit("transfer backing off: the destination appears "
			    "saturated - pausing new connections; active workers "
			    "keep running and no data is lost");
		else
			logit("transfer backing off: no worker is reaching the "
			    "healthy rate - accepting %d slow worker(s) rather "
			    "than churning connections; transfer continues",
			    fleet->born_slow_accepting);
		return;
	}

	/* Sustained: reminder on a multiplicative back-off cadence (prompt
	 * first, then spacing out), escalating to warning wording once the
	 * episode has been prolonged. */
	if (now_s - fleet->flare_last_reminder_s >= fleet->flare_reminder_interval_s) {
		time_t since = now_s - fleet->flare_episode_start_s;
		uint64_t pending;
		fleet->flare_last_reminder_s = now_s;
		fleet->flare_reminder_interval_s *= 2;
		if (fleet->flare_reminder_interval_s > FLARE_REMINDER_CAP_SEC)
			fleet->flare_reminder_interval_s = FLARE_REMINDER_CAP_SEC;
		pthread_mutex_lock(&fleet->pending_mu);
		pending = fleet->pending;
		pthread_mutex_unlock(&fleet->pending_mu);
		if (since >= FLARE_WARN_SEC) {
			logit("warning: transfer degraded for %llds - %llu file(s) "
			    "still pending; continuing best-effort, no data lost",
			    (long long)since, (unsigned long long)pending);
		} else {
			logit("transfer still adapting (%llds) - %llu file(s) "
			    "pending", (long long)since,
			    (unsigned long long)pending);
		}
	}
}

/* Tail trend detector, implemented from here to tail_detector_tick. It
 * looks for one worker still grinding through a long unit after the rest
 * of the fleet has run out of work. This was happening a lot so the
 * effort is worth it. 
 *
 * Either of two signals arms it: the fleet aggregate rate declining by
 * TAIL_DECLINE_PCT across the sample ring, or the slowest holder's
 * remaining bytes over its own median rate projecting a long finish. Both
 * are gated on the structural conditions: walker done, queue empty, a
 * worker READY for work, and a holder lagging the busy-fleet median. The
 * signal also has to persist for TAIL_CONFIRM_SEC, because contention and
 * post-respawn ramps look like a straggler at first.
 *
 * A confirmed episode asks that holder to yield its unstarted remainder,
 * once per episode and subject to HPNTailRedistribute, and closes when any
 * condition clears. Boundaries are logged under HPN_PARALLEL_TRACE.
 * Constants and rationale: sftp-parallel-internal.h. */

/* Median over a worker's personal rate window (all valid samples).
 * Returns 0 when the worker lacks WORKER_RATE_MIN_SAMPLES of history -
 * callers treat 0 as "no evidence, contributes nothing either way".
 * The copy is linear rather than oldest-first because a median does not
 * depend on sample order, and indices 0 to count-1 are exactly the samples
 * written whether the ring has wrapped or not. */
static uint64_t
worker_window_median(const struct sftp_worker *worker)
{
	uint64_t samples[WORKER_RATE_RING];
	int count = worker->rate_ring_count, i;

	if (count < WORKER_RATE_MIN_SAMPLES)
		return 0;
	for (i = 0; i < count; i++)
		samples[i] = worker->rate_ring[i];
	sort_u64(samples, count);
	return samples[count / 2];
}

/* Median of the oldest or the newest quarter of the fleet rate ring. The
 * detector compares the two to decide whether the aggregate rate is
 * declining. Only ever called with a full ring, so idx, the next write
 * position, is also the oldest sample. */
static uint64_t
tail_quarter_median(const uint64_t *ring, int idx, int newest)
{
	uint64_t samples[TAIL_RING_QUARTER];
	int i;

	for (i = 0; i < TAIL_RING_QUARTER; i++) {
		int pos = newest ?
		    (idx - 1 - i + TAIL_RING_TICKS) % TAIL_RING_TICKS :
		    (idx + i) % TAIL_RING_TICKS;
		samples[i] = ring[pos];
	}
	sort_u64(samples, TAIL_RING_QUARTER);
	return samples[TAIL_RING_QUARTER / 2];
}

/* Ask the lagging endgame holder to yield its unstarted remainder so
 * another worker can pick it up. Fires at most once per episode, and only
 * when the holder's own projected remaining time is long enough to be
 * worth the handoff. Off when HPNTailRedistribute is off, which leaves the
 * detector telemetry only. */
static void
tail_fire_yield(struct sftp_parallel *fleet, struct sftp_worker *holder,
    uint64_t holder_med_tput, uint64_t holder_remain_time)
{
	if (!fleet->tail_redistribute || fleet->tail_yield_fired ||
	    holder == NULL || holder_remain_time <= TAIL_PROJECT_SEC)
		return;
	__atomic_store_n(&holder->yield_req, 1, __ATOMIC_RELAXED);
	fleet->tail_yield_fired = 1;
	if (getenv("HPN_PARALLEL_TRACE") != NULL)
		logit("HPN TAIL-YIELD worker=%d holder_med_tput=%llu holder_remain_time=%llus",
		    holder->id, (unsigned long long)holder_med_tput,
		    (unsigned long long)holder_remain_time);
	else
		debug("tail yield: worker %d asked to yield remainder",
		    holder->id);
}

/* Gather this tick's per-worker evidence and return whether the arm
 * condition holds. Takes workers_mu for the scan. Opens the episode, and
 * fires the one yield it allows, once the condition has held for
 * TAIL_CONFIRM_SEC. The caller checks the structural conditions first. */
static int
tail_arm_check(struct sftp_parallel *fleet, uint64_t now)
{
	int n_ready = 0, n_ready_hist = 0, lagging = 0;
	uint64_t ready_medians[SFTP_PARALLEL_MAX_WORKERS];
	uint64_t longest_remain_time = 0;
	uint64_t baseline = 0;
	uint64_t med_old, med_new;
	int trend, project;

	/* Yield target: the slowest lagging holder, with its own median and
	 * remaining time. Captured under workers_mu and used after the
	 * unlock. Nothing can free it in between. The reap runs on this
	 * thread, sftp_parallel_stop joins this thread before it frees any
	 * worker, and the one off-thread free, a respawn whose
	 * pthread_create failed, can only reach a worker too new to have the
	 * rate history this selection requires. */
	struct sftp_worker *yield_holder = NULL;
	uint64_t yield_med_tput = 0, yield_remain_time = 0;

	/* Per-worker evidence. Sample every BUSY worker's rate into its own
	 * window, then ask the only question redistribution cares about:
	 * would the READY workers, judged by the rates they have actually
	 * demonstrated, do the holder's remaining work materially faster? A
	 * worker without WORKER_RATE_MIN_SAMPLES of history counts on neither
	 * side, so a respawn still warming up can neither accuse nor be
	 * accused. */
	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = 0; i < fleet->num_workers; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		int avail = __atomic_load_n(&worker->avail,
		    __ATOMIC_RELAXED);
		uint64_t bytes_retired, bytes_moved;
		int exited, healthy;

		pthread_mutex_lock(&worker->mu);
		exited = worker->exited;
		healthy = (worker->health == WORKER_HEALTHY);
		bytes_retired = worker->bytes_total;
		pthread_mutex_unlock(&worker->mu);
		/* A worker that has left its loop keeps whatever avail it
		 * last had, so it can still read BUSY here until the reap on
		 * the next slow tick. Its samples and its median stopped
		 * being evidence when it exited. */
		if (exited)
			continue;
		bytes_moved = bytes_retired +
		    __atomic_load_n(&worker->live_bytes,
		    __ATOMIC_RELAXED);

		/* Window sampling: BUSY workers only. An idle worker keeps
		 * its last demonstrated samples. */
		if (avail == WORKER_AVAIL_BUSY) {
			if (worker->rate_prev_ms != 0 &&
			    now > worker->rate_prev_ms &&
			    bytes_moved >= worker->rate_prev_bytes) {
				uint64_t worker_rate = (bytes_moved -
				    worker->rate_prev_bytes) * 1000ULL /
				    (now - worker->rate_prev_ms);

				worker->rate_ring[worker->rate_ring_idx] =
				    worker_rate;
				worker->rate_ring_idx =
				    (worker->rate_ring_idx + 1) %
				    WORKER_RATE_RING;
				if (worker->rate_ring_count <
				    WORKER_RATE_RING)
					worker->rate_ring_count++;
			}
			worker->rate_prev_bytes = bytes_moved;
			worker->rate_prev_ms = now;
		} else {
			worker->rate_prev_ms = 0; /* re-baseline on next BUSY */
		}

		/* After the sampling block on purpose. A stalled worker can
		 * return to healthy, so keep measuring it and let its
		 * near-zero ticks land in its own window. It just gets no
		 * vote in the READY baseline while it is unhealthy. */
		if (!healthy)
			continue;
		if (avail == WORKER_AVAIL_READY) {
			uint64_t median = worker_window_median(worker);

			n_ready++;
			if (median > 0)
				ready_medians[n_ready_hist++] = median;
		}
	}
	/* Baseline = median of READY workers' demonstrated medians. */
	if (n_ready_hist > 0) {
		sort_u64(ready_medians, n_ready_hist);
		baseline = ready_medians[n_ready_hist / 2];
	}
	/* No baseline means no READY worker has demonstrated a rate yet, so
	 * there is nothing to judge a holder against. */
	if (baseline > 0) {
		for (int i = 0; i < fleet->num_workers; i++) {
			struct sftp_worker *worker = fleet->workers[i];
			int avail = __atomic_load_n(&worker->avail,
			    __ATOMIC_RELAXED);
			uint64_t holder_med_tput;
			int exited, healthy;

			if (avail != WORKER_AVAIL_BUSY)
				continue;
			pthread_mutex_lock(&worker->mu);
			exited = worker->exited;
			healthy = (worker->health == WORKER_HEALTHY);
			pthread_mutex_unlock(&worker->mu);
			/* Same stale-avail case as the sampling loop: a worker
			 * that has exited still reads BUSY, and accusing it
			 * spends the one yield this episode gets. */
			if (exited || !healthy)
				continue;
			holder_med_tput = worker_window_median(worker);
			if (holder_med_tput == 0)
				continue;	/* no evidence: cannot accuse */
			if (holder_med_tput * 100 <
			    baseline * TAIL_HOLDER_LAG_PCT) {
				uint64_t unit_size, unit_done;
				uint64_t remain_time = 0;

				lagging++;
				unit_size = __atomic_load_n(&worker->unit_size,
				    __ATOMIC_RELAXED);
				unit_done = __atomic_load_n(&worker->live_bytes,
				    __ATOMIC_RELAXED);
				if (unit_size > unit_done) {
					remain_time = (unit_size - unit_done) /
					    holder_med_tput;
					if (remain_time > longest_remain_time)
						longest_remain_time = remain_time;
				}
				/* Only consider a holder tail_fire_yield will
				 * accept. The episode gets exactly one call, so
				 * choosing a candidate it refuses forfeits the
				 * yield for the whole episode. */
				if (remain_time > TAIL_PROJECT_SEC &&
				    (yield_holder == NULL ||
				    holder_med_tput < yield_med_tput)) {
					yield_holder = worker;
					yield_med_tput = holder_med_tput;
					yield_remain_time = remain_time;
				}
			}
		}
	}
	pthread_mutex_unlock(&fleet->workers_mu);

	if (n_ready == 0 || lagging == 0)
		return 0;

	med_old = tail_quarter_median(fleet->tail_rate_ring,
	    fleet->tail_ring_idx, 0);
	med_new = tail_quarter_median(fleet->tail_rate_ring,
	    fleet->tail_ring_idx, 1);
	trend = (med_old > 0 &&
	    med_new < med_old * (100 - TAIL_DECLINE_PCT) / 100);
	project = (longest_remain_time > TAIL_PROJECT_SEC);

	if (!trend && !project)
		return 0;

	/* Persistence gate: contention reshuffles and post-respawn ramps look
	 * identical to a straggler for a few seconds, so only a condition
	 * that holds is actionable. The episode start backdates to when the
	 * lag began, so reported durations stay true. */
	if (fleet->tail_lag_start_ms == 0)
		fleet->tail_lag_start_ms = now;
	if (!fleet->tail_episode &&
	    now - fleet->tail_lag_start_ms >=
	    TAIL_CONFIRM_SEC * 1000) {
		if (getenv("HPN_PARALLEL_TRACE") != NULL)
			logit("HPN TAIL-DETECT t=%.3f "
			    "confirm=%.1fs trend=%d "
			    "remaining_time=%llus "
			    "agg_old=%llu agg_new=%llu "
			    "ready=%d ready_hist=%d "
			    "lagging=%d yield_med_tput=%llu "
			    "ready_baseline=%llu",
			    (double)now / 1e3,
			    (double)(now -
			    fleet->tail_lag_start_ms) / 1e3,
			    trend,
			    (unsigned long long)longest_remain_time,
			    (unsigned long long)med_old,
			    (unsigned long long)med_new,
			    n_ready, n_ready_hist, lagging,
			    (unsigned long long)yield_med_tput,
			    (unsigned long long)baseline);
		fleet->tail_episode = 1;
		fleet->tail_episode_ms = fleet->tail_lag_start_ms;
		tail_fire_yield(fleet, yield_holder,
		    yield_med_tput, yield_remain_time);
	}
	return 1;
}

static void
tail_detector_tick(struct sftp_parallel *fleet, uint64_t bytes_now)
{
	uint64_t now = monotime_ms();
	int would_arm = 0;
	int walker_done = 0;

	/* Per-tick rate sample into the ring. */
	if (fleet->tail_prev_ms != 0 && now > fleet->tail_prev_ms &&
	    bytes_now >= fleet->tail_prev_bytes) {
		fleet->tail_rate_ring[fleet->tail_ring_idx] =
		    (bytes_now - fleet->tail_prev_bytes) * 1000 /
		    (now - fleet->tail_prev_ms);
		fleet->tail_ring_idx = (fleet->tail_ring_idx + 1) % TAIL_RING_TICKS;
		if (fleet->tail_ring_count < TAIL_RING_TICKS)
			fleet->tail_ring_count++;
	}
	fleet->tail_prev_bytes = bytes_now;
	fleet->tail_prev_ms = now;

	if (fleet->tail_ring_count < TAIL_RING_TICKS)
		return;	/* window not full yet */

	/* Structural conjunction first (cheap, and required for an arm). */
	walker_done = (__atomic_load_n(&fleet->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE); /*boolean*/
	if (walker_done && sftp_workqueue_depth(fleet->q) == 0)
		would_arm = tail_arm_check(fleet, now);

	if (!would_arm)
		fleet->tail_lag_start_ms = 0;	/* condition broke: re-confirm */
	if (fleet->tail_episode && !would_arm) {
		if (getenv("HPN_PARALLEL_TRACE") != NULL)
			logit("HPN TAIL-EPISODE-END t=%.3f dur=%.1fs "
			    "pending=%llu",
			    (double)now / 1e3,
			    (double)(now - fleet->tail_episode_ms) / 1e3,
			    (unsigned long long)fleet->pending);
		fleet->tail_episode = 0;
		fleet->tail_yield_fired = 0;	/* re-arm for the next episode */
	}
}

/* ENV-VAR HPN_PARALLEL_TRACE per-tick fleet sample (2026-06-05 midstream-freeze
 * probe). One line: absolute time, work-queue depth, walker phase, then each
 * worker's phase + cumulative bytes + ssh child pid, plus the fleet total.
 * Per-worker and total bytes are cumulative, so consecutive samples give the
 * per-worker and fleet throughput series. The pid lets us correlate a worker
 * with its transport's HPN TCPSAMPLE lines (which carry getpid()). */
static void
reporter_emit_fleetsample(struct sftp_parallel *fleet)
{
	static int on = -1;
	char line[4096];
	size_t off;
	uint64_t total = 0;
	int i;

	if (on < 0)
		on = (getenv("HPN_PARALLEL_TRACE") != NULL);
	if (!on)
		return;

	off = (size_t)snprintf(line, sizeof(line),
	    "HPN FLEETSAMPLE t=%.3f qdepth=%zu walker=%s",
	    monotime_double(), sftp_workqueue_depth(fleet->q),
	    walker_phase_name(__atomic_load_n(&fleet->walker_phase,
	        __ATOMIC_RELAXED)));

	pthread_mutex_lock(&fleet->workers_mu);
	for (i = 0; i < fleet->num_workers && off < sizeof(line) - 64; i++) {
		struct sftp_worker *worker = fleet->workers[i];
		uint64_t wb;
		pthread_mutex_lock(&worker->mu);
		wb = worker->bytes_total +
		    __atomic_load_n(&worker->live_bytes, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&worker->mu);
		total += wb;
		off += (size_t)snprintf(line + off, sizeof(line) - off,
		    " w%d:%s:%llu:%ld", worker->id,
		    worker_phase_name(__atomic_load_n(&worker->phase,
		        __ATOMIC_RELAXED)),
		    (unsigned long long)wb, (long)worker->ssh_pid);
	}
	total += fleet->retired_bytes;
	pthread_mutex_unlock(&fleet->workers_mu);

	logit("%s total_bytes=%llu", line, (unsigned long long)total);
}

/* Leave the resume-check stretch: restore the transfer meter's label and
 * total (the stretch swapped them for the "resume check" sub-meter), clear
 * the frame flag, and restart the display ratchet - hash bytes are not
 * transfer bytes, so the published counter must not carry over. Idempotent. */
static void
resume_stretch_restore(struct sftp_parallel *fleet)
{
	if (!fleet->resume_stretch_on)
		return;
	fleet->resume_stretch_on = 0;
	hpn_meter_relabel(&fleet->meter, fleet, fleet->progress_label_saved);
	hpn_meter_retotal(&fleet->meter, fleet, fleet->progress_total_bytes);
	fleet->aggregate_progress_counter = 0;
	hpn_pm_set_phase(HPNS_F_RESUME, 0);
}

void *
parallel_reporter_thread(void *arg)
{
	struct sftp_parallel *fleet = arg;
	struct timespec sleep_ts = {
		.tv_sec = REPORTER_TICK_MS / 1000,
		.tv_nsec = (REPORTER_TICK_MS % 1000) * 1000000L,
	};
	int slow_tick_counter = 0;

	while (1) {
		nanosleep(&sleep_ts, NULL);
		if (fleet->stopped)
			break;

		/* Propagate caller's interrupt signal (e.g. SIGINT / Ctrl+C).
		 * sftp_parallel_abort is idempotent; calling it every tick while
		 * the flag stays set is harmless. Record the CAUSE first so
		 * the abort fallout is reported as an interrupt, not errors. */
		if (fleet->ext_interrupt_flag != NULL && *fleet->ext_interrupt_flag) {
			fleet->abort_user = 1;
			parallel_user_abort_flag = 1;
			sftp_parallel_abort(fleet);
		}

		/* Transport liveness (the cancel path): when the launching
		 * session dies (^C on a -R launcher), no signal crosses the
		 * ssh hop - the client sends none on death, sshd refuses
		 * session signals, and sshd never kills no-tty children on
		 * connection loss. The only observable is the session's
		 * plumbing dying: sshd-session's exit closes the read ends of
		 * BOTH our stdout and stderr together. Poll both (no I/O, no
		 * display dependency - works under -q with no meter): both
		 * dead means our session is gone, so cancel instead of
		 * orphaning a transfer the user just aborted. One dead pipe
		 * alone (stdout piped to a reader that exited) keeps stock
		 * pass-through behavior. */
		if (!fleet->abort_flag) {
			struct pollfd lfd[2];

			lfd[0].fd = STDOUT_FILENO;
			lfd[0].events = 0;
			lfd[1].fd = STDERR_FILENO;
			lfd[1].events = 0;
			if (poll(lfd, 2, 0) > 0 &&
			    (lfd[0].revents & (POLLERR | POLLHUP | POLLNVAL)) &&
			    (lfd[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
				logit("control session closed; "
				    "canceling transfer");
				fleet->abort_user = 1;
				sftp_parallel_abort(fleet);
			}
		}

		uint64_t bytes;
		off_t newpos;
		parallel_stats_snapshot(fleet, &bytes);
		if (fleet->verify_phase_active && fleet->verify_total_units > 0) {
			resume_stretch_restore(fleet);	/* safety: never both */
			/* Post-transfer verify phase: byte-granular meter. Counter
			 * = bytes of fully-verified files (verify_done_bytes) + every
			 * worker's in-flight count for the file it is hashing right
			 * now (fed each second by the server hash heartbeat / local
			 * read-back). This advances smoothly even when a single
			 * huge file is the whole phase, instead of the old file-count
			 * fraction that jumped 0->100% at completion. Snap to the
			 * exact total once all units are done so the bar lands at
			 * 100% (the last heartbeat may trail the final bytes). */
			uint64_t done_units = __atomic_load_n(
			    &fleet->verify_done_units, __ATOMIC_RELAXED);
			if (done_units >= fleet->verify_total_units) {
				newpos = fleet->verify_meter_total;
			} else {
				uint64_t hashed = __atomic_load_n(
				    &fleet->verify_done_bytes, __ATOMIC_RELAXED);
				/* workers_mu: a detached respawn thread can
				 * xreallocarray(fleet->workers) (and the reap loop can
				 * remove/free a worker) during the verify phase -
				 * a worker whose conn drops mid-hash is reaped and
				 * respawned. Iterating workers[]/worker->conn unlocked
				 * would race that realloc/free (UAF/OOB). Mirror
				 * the sibling fleet-sample/reap/CSV loops, which all
				 * hold this lock; the body is only a cheap atomic
				 * getter. */
				pthread_mutex_lock(&fleet->workers_mu);
				for (int wi = 0; wi < fleet->num_workers; wi++) {
					struct sftp_worker *worker = fleet->workers[wi];
					uint64_t d, t;

					if (worker == NULL || worker->conn == NULL)
						continue;
					sftp_conn_hash_work_live(worker->conn,
					    &d, &t);
					hashed += d;
				}
				pthread_mutex_unlock(&fleet->workers_mu);
				if (hashed > (uint64_t)fleet->verify_meter_total)
					hashed = (uint64_t)fleet->verify_meter_total;
				newpos = (off_t)hashed;
			}
		} else if (bytes == fleet->progress_bytes_baseline &&
		    fleet->progress_meter_started) {
			/* Resume-check stretch (-Z UX): no transfer byte has
			 * moved yet, but workers may be hashing existing
			 * partials (chunked resume). Render that as a
			 * "resume check" sub-meter - total from the conn
			 * hash-op markers, progress from the same inflight
			 * feed the verify meter uses - instead of a frozen
			 * 0% transfer bar. Markers self-clear on staleness,
			 * so a finished or abandoned hash drops out alone.
			 * Same workers_mu discipline as the sibling loops. */
			uint64_t rtotal = 0, rdone = 0;

			pthread_mutex_lock(&fleet->workers_mu);
			for (int wi = 0; wi < fleet->num_workers; wi++) {
				struct sftp_worker *worker = fleet->workers[wi];
				uint64_t d, t;

				if (worker == NULL || worker->conn == NULL)
					continue;
				sftp_conn_hash_work_live(worker->conn, &d, &t);
				rtotal += t;
				rdone += d;
			}
			pthread_mutex_unlock(&fleet->workers_mu);
			if (rtotal > 0) {
				if (!fleet->resume_stretch_on) {
					fleet->resume_stretch_on = 1;
					/* Save the transfer meter's label
					 * and total for the restore; the
					 * reporter owns the meter, so
					 * reading them here is safe. */
					strlcpy(fleet->progress_label_saved,
					    fleet->meter.label,
					    sizeof(fleet->progress_label_saved));
					fleet->progress_total_bytes =
					    fleet->meter.total;
					hpn_meter_relabel(&fleet->meter, fleet,
					    "resume check");
					fleet->aggregate_progress_counter = 0;
					hpn_pm_set_phase(
					    HPNS_F_RESUME, 1);
				}
				hpn_meter_retotal(&fleet->meter, fleet,
				    (off_t)rtotal);
				if (rdone > rtotal)
					rdone = rtotal;
				newpos = (off_t)rdone;
			} else {
				resume_stretch_restore(fleet);
				newpos = 0;
			}
		} else {
			resume_stretch_restore(fleet);
			newpos = bytes > fleet->progress_bytes_baseline ?
			    (off_t)(bytes - fleet->progress_bytes_baseline) : 0;
		}
		/* Monotonic publish. The raw aggregate steps BACKWARD when a
		 * worker dies or a unit is requeued mid-transfer: its live_bytes
		 * leave the sum until the redo re-transfers them. Publishing
		 * the dip makes the meter show a 0-rate tick and then absorb the
		 * whole recovery in one interval - an impossible rate spike
		 * (0 then multi-GB/s). Ratchet the DISPLAY counter instead: the
		 * meter holds through the redo and resumes at the true rate.
		 * Detectors are unaffected - they read the raw snapshot (bytes),
		 * not this counter. Meter restarts (new command, verify phase)
		 * reset the counter outside this tick, so the ratchet only
		 * applies within one meter's lifetime. */
		/* Publish only while a meter is running: the main thread
		 * resets the counter at meter boundaries (progress_start,
		 * verify start) with no lock, and a raciness-window publish
		 * would be pinned by the ratchet for the whole next meter
		 * instead of self-correcting on the following tick. */
		if (fleet->progress_meter_started &&
		    newpos > fleet->aggregate_progress_counter)
			fleet->aggregate_progress_counter = newpos;
		/* HPN status relay: keep the frame emitter's fleet telemetry
		 * fresh (stored unconditionally; only read when frame mode
		 * is armed). Same lock discipline as the sibling fleet
		 * loops. */
		{
			u_int fr_active = 0, fr_stalled = 0;

			pthread_mutex_lock(&fleet->workers_mu);
			for (int wi = 0; wi < fleet->num_workers; wi++) {
				struct sftp_worker *worker = fleet->workers[wi];

				if (worker == NULL || worker->exited)
					continue;
				if (worker->health == WORKER_STALLED)
					fr_stalled++;
				else if (worker->health != WORKER_DEAD)
					fr_active++;
			}
			pthread_mutex_unlock(&fleet->workers_mu);
			hpn_pm_set_workers(fr_active,
			    fr_stalled);
			hpn_pm_set_files(
			    (u_int)__atomic_load_n(&fleet->files_submitted,
			        __ATOMIC_RELAXED),
			    (u_int)__atomic_load_n(&fleet->files_total,
			        __ATOMIC_RELAXED));
		}

		/* Fold in what a walker posted (the total and file count
		 * from a drained enumeration). The reporter is the only
		 * thread that updates the meter; walkers only accumulate
		 * into the posted fields. Held while the resume-check
		 * stretch has the meter, so a post never lands in the
		 * stretch's hash-byte total. */
		if (fleet->progress_meter_started && !fleet->resume_stretch_on) {
			off_t addb = __atomic_exchange_n(
			    &fleet->posted_total_add, 0, __ATOMIC_RELAXED);
			u_int addf = __atomic_exchange_n(
			    &fleet->posted_files_add, 0, __ATOMIC_RELAXED);

			if (addb > 0 || addf > 0) {
				hpn_meter_add_total(&fleet->meter, fleet, addb, addf);
				if (fleet->progress_verb[0] != '\0' &&
				    fleet->meter.nfiles > 0) {
					char lbl[HPN_METER_LABEL_MAX];

					snprintf(lbl, sizeof(lbl),
					    "%s %u %s in parallel",
					    fleet->progress_verb,
					    fleet->meter.nfiles,
					    fleet->meter.nfiles == 1 ?
					    "file" : "files");
					hpn_meter_relabel(&fleet->meter, fleet, lbl);
				}
			}
		}
		if (__atomic_load_n(&fleet->meter_final_request,
		    __ATOMIC_ACQUIRE)) {
			/* progress_stop snapped the counter to the total and
			 * is waiting on this paint; force it past the alarm
			 * gate and acknowledge. */
			refresh_progress_meter(1);
			__atomic_store_n(&fleet->meter_final_request, 0,
			    __ATOMIC_RELEASE);
		} else if (fleet->progress_meter_started)
			refresh_progress_meter(0);

		/* Tail trend detector (phase B: telemetry only). */
		tail_detector_tick(fleet, bytes);

		/* Liveness checks on a slower cadence: cheaper, and watchdog
		 * timing does not need per-tick granularity. */
		if (++slow_tick_counter >= REPORTER_SLOW_TICKS) {
			slow_tick_counter = 0;

			reporter_emit_fleetsample(fleet);

			/* Watchdog classifies workers HEALTHY/STALLED/DEAD
			 * and SIGTERMs newly DEAD ones. We don't abort here;
			 * the reap loop below joins exited workers and spawns
			 * replacements. */
			(void)parallel_watchdog_check(fleet);

			/* SIGTERM any respawn wedged in its handshake past the
			 * stall deadline. The blocked spawn thread cannot time
			 * itself out, so the reporter does it: otherwise the
			 * stalled respawn pins pending_respawns and deadlocks the
			 * abort net (fatal at -j1). */
			parallel_respawn_sweep_stalled(fleet);

			/* Move any worker re-queue overflow back into fleet->q as it
			 * frees up. Workers park here (instead of blocking) when
			 * a re-queue hits a full queue; draining from the reporter
			 * is what keeps that non-blocking path live. */
			parallel_retry_overflow_drain(fleet);

			/* Track synchronous stalls (all workers at zero bytes
			 * while work is in flight) as a leading indicator of
			 * write-cache saturation from too many parallel writers.
			 * Observation-only for now; future use as a scale-down
			 * signal. */
			parallel_watchdog_sync_check(fleet);

			int n_to_respawn = reporter_reap_exited_workers(fleet);

			if (parallel_respawn_dispatch(fleet, n_to_respawn))
				break;

			/* Operator flare: episode-level notices for degraded
			 * stretches (cooldown / accepting slow workers). Runs
			 * after dispatch so cooldown + born_slow_accepting are
			 * fresh; no-op on a clean transfer. */
			reporter_flare(fleet);
		}
	}
	return NULL;
}
