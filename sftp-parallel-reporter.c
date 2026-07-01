/*
 * sftp-parallel-reporter.c - the reporter thread for the parallel SFTP
 * orchestrator: progress aggregation, worker reaping and death
 * classification, respawn triggering, flare/CSV/fleet-sample
 * observability.  Split from sftp-parallel.c; moves are verbatim.
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
#include "progressmeter.h"

#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"
#include "hpn-exit-codes.h"

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

void
parallel_stats_snapshot(struct sftp_parallel *p, uint64_t *bytes_out,
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
 * Classify and log how a reaped worker died, using the wait status plus
 * w->doomed (did WE kill it?).  Diagnostic only - it changes no control
 * flow; the caller respawns regardless.  Death modes:
 *
 *   - doomed                  : the watchdog terminated it (reason already
 *                               logged when it was doomed).
 *   - HPN transport exit code : the worker self-diagnosed and self-exited
 *                               (the "known cause" tier - see
 *                               hpn-exit-codes.h).
 *   - exit 255                : ssh transport error / dropped connection.
 *   - other exit code         : remote subsystem status, propagated.
 *   - SIGKILL (¬doomed)       : ambiguous - this reap path force-SIGKILLs,
 *                               so it most likely reflects OUR kill of a
 *                               child that had not yet exited, not a crash.
 *   - other signal            : a genuine crash (we only ever send SIGKILL).
 *
 * Read on the reporter thread, which also owns the doom state - so
 * w->doomed needs no lock here.
 */
static void
classify_worker_death(const struct sftp_worker *w, int have_status, int status)
{
	struct sftp_parallel *p = w->parent;
	const char *cause = NULL;
	uint64_t n = 0;
	int quiet = 0;

	/*
	 * One plain-language heartbeat per involuntary worker loss,
	 * numbered by a transfer-global ordinal so the running count the
	 * user sees adds up to the end-of-transfer respawn summary.
	 * (Previously only wedge/peer-stall printed - numbered by the
	 * dying worker's PRIVATE lineage count - so silent born-dead
	 * respawns made the first visible notice arrive pre-numbered and
	 * labeled with a worker id beyond the fleet size.)  Full forensic
	 * detail (worker id, exit code, doom reason) stays at debug.
	 *
	 * `quiet` causes (high-frequency churn the fleet absorbs on its
	 * own: startup deaths, dropped connections, slow-worker cycling)
	 * heartbeat at debug only - they still count toward the ordinal
	 * and the end-of-transfer summary, which remains the complete
	 * record.  Rare/meaningful causes (wedge, peer-stall brake,
	 * endgame stall, crashes) stay user-visible.
	 */
	if (w->doomed) {
		const char *r = w->doom_reason ? w->doom_reason : "doomed";

		if (strcmp(r, "born_dead") == 0) {
			cause = "worker unresponsive at startup";
			quiet = 1;
		}
		else if (strcmp(r, "endgame_straggler") == 0)
			cause = "worker stalled at the endgame";
		else if (strcmp(r, "tput_outlier") == 0 ||
		    strcmp(r, "born_slow") == 0) {
			cause = "worker persistently slow";
			quiet = 1;
		}
		else if (strcmp(r, "dead") == 0 ||
		    strcmp(r, "iso_stall") == 0 ||
		    strcmp(r, "isolation") == 0)
			cause = "worker stalled (no progress)";
		else if (strcmp(r, "child_gone") == 0) {
			cause = "worker connection lost";
			quiet = 1;
		}
		else
			cause = "worker terminated by watchdog";
		debug_ft("worker %d: reaped after orchestrator termination "
		    "(%s)", w->id, r);
	} else if (!have_status) {
		cause = "worker lost";
		debug_ft("worker %d: died (no wait status)", w->id);
	} else if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);

		if (code == HPN_EXIT_TCP_WEDGE) {
			if (p != NULL)
				p->wedge_terminations++;
			cause = "worker connection wedged";
			debug_ft("worker %d: self-terminated: TCP wedge",
			    w->id);
		} else if (code == HPN_EXIT_TCP_PEER_STALL) {
			if (p != NULL)
				p->peer_stall_terminations++;
			cause = "worker remote stopped draining";
			debug_ft("worker %d: self-terminated: peer stall",
			    w->id);
		} else if (HPN_EXIT_IS_TCP(code)) {
			cause = "worker transport self-check failed";
			debug_ft("worker %d: self-terminated: transport "
			    "(exit %d)", w->id, code);
		} else if (code == 255) {
			cause = "worker connection lost";
			quiet = 1;
			debug_ft("worker %d: ssh transport error / dropped "
			    "connection (exit 255)", w->id);
		} else if (code == 0) {
			cause = "worker exited unexpectedly";
			debug_ft("worker %d: exited cleanly (watchdog had not "
			    "doomed it)", w->id);
		} else {
			cause = "worker exited unexpectedly";
			debug_ft("worker %d: exited with status %d",
			    w->id, code);
		}
	} else if (WIFSIGNALED(status)) {
		cause = "worker terminated unexpectedly";
		debug_ft("worker %d: killed by signal %d", w->id,
		    WTERMSIG(status));
	} else {
		cause = "worker lost";
		debug_ft("worker %d: reaped (unrecognized wait status)",
		    w->id);
	}

	if (p != NULL)
		n = ++p->death_ordinal;
	/* During teardown the deaths are manufactured and nothing is
	 * reconnecting - keep it out of the user's face. */
	if (p == NULL || p->abort_flag || p->stopped)
		debug("%s (teardown)", cause);
	else if (quiet)
		debug("%s; reconnecting (respawn %llu)", cause,
		    (unsigned long long)n);
	else
		logit("%s; reconnecting (respawn %llu)", cause,
		    (unsigned long long)n);

	/*
	 * One-time heads-up once the cumulative reconnect count crosses a
	 * fleet-scaled threshold.  The per-respawn lines above show the churn
	 * happening; this names it as a path-reliability concern.  Keyed on the
	 * session-wide death_ordinal (survives per-worker respawn, unlike the
	 * old per-struct reconnect_count which reset every respawn and so never
	 * reached its threshold).  Fires ahead of the give-up thresholds
	 * (FLEET_ABORT_UNPRODUCTIVE_MULT / RESPAWN_MULTIPLIER); suppressed
	 * during teardown.  Reporter thread only - no lock needed.
	 */
	if (p != NULL && !p->abort_flag && !p->stopped &&
	    !p->churn_notice_emitted &&
	    n >= (uint64_t)p->cfg.num_streams * HPN_PATH_CHURN_NOTICE_MULT) {
		p->churn_notice_emitted = 1;
		logit("this transfer has required %llu worker reconnections; "
		    "the network path may be unreliable",
		    (unsigned long long)n);
	}
}

/*
 * Reap workers that have marked themselves exited (connection died,
 * fault-injected exit, or fatal protocol violation).  Every exit is
 * involuntary - the orchestrator always respawns.
 *
 * Two phases for clean locking: collect-under-lock, then join-and-free
 * outside the lock (pthread_join can take arbitrary time).
 *
 * Returns the count of reaped workers, which equals the number of
 * respawn slots the caller (reporter) needs to dispatch.
 */
static int
reporter_reap_exited_workers(struct sftp_parallel *p)
{
	struct sftp_worker *to_reap[SFTP_PARALLEL_MAX_WORKERS];
	int n_reap = 0;

	pthread_mutex_lock(&p->workers_mu);
	for (int i = p->num_workers - 1; i >= 0; i--) {
		struct sftp_worker *w = p->workers[i];
		int exited;
		uint64_t bt;
		pthread_mutex_lock(&w->mu);
		exited = w->exited;
		bt     = w->bytes_total;
		/* Capture bytes_total before the worker leaves the array
		 * so the aggregate stays monotonic.  live_bytes was reset
		 * to 0 at the worker's last completion so it is not
		 * double-counted.  Same for the wired/unit counters - they
		 * used to die with the struct, undercounting every
		 * post-respawn aggregate. */
		if (exited) {
			uint64_t cw = w->conn ?
			    sftp_conn_bytes_wired(w->conn) : 0;

			p->retired_bytes += bt;
			p->retired_wired += cw;
			p->retired_units_completed += w->units_completed;
			p->retired_units_failed   += w->units_failed;
			debug("reap-capture: worker %d conn=%p wired=%llu "
			    "bt=%llu retired_wired_now=%llu", w->id,
			    (void *)w->conn, (unsigned long long)cw,
			    (unsigned long long)bt,
			    (unsigned long long)p->retired_wired);
		}
		pthread_mutex_unlock(&w->mu);
		if (exited) {
			to_reap[n_reap++] = w;
			memmove(&p->workers[i],
			    &p->workers[i + 1],
			    (p->num_workers - i - 1) *
			    sizeof(*p->workers));
			p->num_workers--;
		}
	}
	pthread_mutex_unlock(&p->workers_mu);

	for (int i = 0; i < n_reap; i++) {
		struct sftp_worker *w = to_reap[i];
		pthread_join(w->tid, NULL);
		/* Worker thread has exited; no concurrent writer, so this read
		 * needs no lock.  Lifetime committed bytes feed the fleet-abort
		 * unproductive-death streak below. */
		uint64_t lifetime_bytes = w->bytes_total;
		if (w->conn) sftp_free(w->conn);
		if (w->fd_in >= 0) close(w->fd_in);
		if (w->fd_out >= 0) close(w->fd_out);
		if (w->ssh_pid > 0) {
			int s = 0;
			int reaped;
			/* Belt-and-suspenders: may already be dead from
			 * SIGTERM above.  A child that self-exited is already a
			 * zombie, so this SIGKILL is a no-op and waitpid still
			 * returns its real exit code. */
			(void)kill(w->ssh_pid, SIGKILL);
			reaped = (waitpid(w->ssh_pid, &s, 0) == w->ssh_pid);
			p->last_worker_exit_code =
			    (reaped && WIFEXITED(s)) ? WEXITSTATUS(s) : -1;
			/* Fleet-abort signal: a worker that died without ever
			 * committing a byte, and not as a clean end-of-queue
			 * exit, is a respawn that failed to take hold.  The
			 * streak resets in parallel_watchdog_sync_check on any sign
			 * of life (fleet progress or a heartbeat). */
			int clean = reaped && WIFEXITED(s) &&
			    WEXITSTATUS(s) == 0;
			if (lifetime_bytes == 0 && !clean)
				p->unproductive_deaths++;
			classify_worker_death(w, reaped, s);
		}
		pthread_mutex_destroy(&w->mu);
		free(w);
	}
	return n_reap;
}

/*
 * Operator-facing flare for degraded episodes.  Called once per reporter
 * slow-tick AFTER the watchdog and respawn dispatch, so cooldown state and
 * born_slow_accepting are fresh.  A "degraded episode" is any contiguous
 * stretch where we are backing off respawns (cooldown active) or accepting
 * slow-but-working workers (born-slow gated off).  Edge-triggered: one notice
 * when it opens, a periodic reminder (escalating notice->warning) while it
 * lasts, a recovery notice when it closes.  Best-effort framing throughout -
 * a degraded episode is the transfer slowing down and adapting, NOT failing.
 * On a clean transfer degraded is always 0 and this is a no-op.
 */
static void
reporter_flare(struct sftp_parallel *p)
{
	time_t now_s;
	int cooldown_active, accepting_slow, degraded;

	/* Quiet stays quiet: -q and -b both set print_flag to SFTP_QUIET.
	 * Errors (TRANSFER INCOMPLETE, failed paths) still surface via error(). */
	if (p->cfg.print_flag == SFTP_QUIET)
		return;

	now_s = monotime();
	cooldown_active = (p->respawn_resume_s != 0);
	accepting_slow  = (p->born_slow_accepting > 0);
	degraded        = cooldown_active || accepting_slow;

	if (!degraded) {
		if (p->flare_in_episode) {
			/* Falling edge: recovered. */
			logit("transfer recovered after %llds - resumed full "
			    "concurrency",
			    (long long)(now_s - p->flare_episode_start_s));
			p->flare_in_episode = 0;
		}
		return;
	}

	if (!p->flare_in_episode) {
		/* Rising edge: open an episode.  No countdown - the cooldown
		 * level escalates/decays and isn't actionable; just the state. */
		p->flare_in_episode = 1;
		p->flare_episode_start_s = now_s;
		p->flare_last_reminder_s = now_s;
		p->flare_reminder_interval_s = FLARE_REMINDER_BASE_SEC;
		if (cooldown_active)
			logit("transfer backing off: the destination appears "
			    "saturated - pausing new connections; active workers "
			    "keep running and no data is lost");
		else
			logit("transfer backing off: no worker is reaching the "
			    "healthy rate - accepting %d slow worker(s) rather "
			    "than churning connections; transfer continues",
			    p->born_slow_accepting);
		return;
	}

	/* Sustained: reminder on a multiplicative back-off cadence (prompt
	 * first, then spacing out), escalating to warning wording once the
	 * episode has been prolonged. */
	if (now_s - p->flare_last_reminder_s >= p->flare_reminder_interval_s) {
		time_t since = now_s - p->flare_episode_start_s;
		uint64_t pending;
		p->flare_last_reminder_s = now_s;
		p->flare_reminder_interval_s *= 2;
		if (p->flare_reminder_interval_s > FLARE_REMINDER_CAP_SEC)
			p->flare_reminder_interval_s = FLARE_REMINDER_CAP_SEC;
		pthread_mutex_lock(&p->pending_mu);
		pending = p->pending;
		pthread_mutex_unlock(&p->pending_mu);
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

/*
 * Tail trend detector - phase B of the tail-elimination design
 * (2026-06-12): TELEMETRY ONLY.  Samples the fleet aggregate rate once
 * per reporter tick into a small ring; a would-arm EPISODE opens when
 * the decline/projection signals AND the structural conjunction hold
 * (queue empty, walker done, READY capacity, holder lagging the
 * busy-fleet median), and closes when any condition clears.  Episode
 * boundaries are logged under HPN_BUNDLE_TIMING for tuning; nothing is
 * actuated.  Constants and rationale: sftp-parallel-internal.h.
 */
/* Median over a worker's personal rate window (all valid samples).
 * Returns 0 when the worker lacks WORKER_RATE_MIN_SAMPLES of history -
 * callers treat 0 as "no evidence, contributes nothing either way". */
static uint64_t
worker_window_median(const struct sftp_worker *w)
{
	uint64_t q[WORKER_RATE_RING];
	int n = w->rate_ring_count, i, j;

	if (n < WORKER_RATE_MIN_SAMPLES)
		return 0;
	for (i = 0; i < n; i++)
		q[i] = w->rate_ring[i];
	for (i = 1; i < n; i++) {
		uint64_t v = q[i];
		for (j = i; j > 0 && q[j - 1] > v; j--)
			q[j] = q[j - 1];
		q[j] = v;
	}
	return q[n / 2];
}

static uint64_t
tail_quarter_median(const uint64_t *ring, int count, int idx, int newest)
{
	uint64_t q[TAIL_RING_QUARTER];
	int i, j, n = TAIL_RING_QUARTER;

	/* Copy the oldest or newest quarter of the (full) ring. */
	for (i = 0; i < n; i++) {
		int pos = newest ?
		    (idx - 1 - i + 2 * TAIL_RING_TICKS) % TAIL_RING_TICKS :
		    (idx + i + TAIL_RING_TICKS - count + 2 * TAIL_RING_TICKS)
		    % TAIL_RING_TICKS;
		q[i] = ring[pos];
	}
	/* Insertion sort; n is 6. */
	for (i = 1; i < n; i++) {
		uint64_t v = q[i];
		for (j = i; j > 0 && q[j - 1] > v; j--)
			q[j] = q[j - 1];
		q[j] = v;
	}
	return q[n / 2];
}

/*
 * Phase C (HPNTailRedistribute): a confirmed episode asks the slowest
 * lagging holder to cooperatively yield its unstarted remainder for
 * redistribution.  One yield per episode latch; fires only when the
 * holder's own projected remaining tail is long enough to be worth the
 * handoff.  No-op unless the env gate armed it at parallel start.
 */
static void
tail_fire_yield(struct sftp_parallel *p, struct sftp_worker *tgt,
    uint64_t tgt_med, uint64_t tgt_proj)
{
	if (!p->tail_redistribute || p->tail_yield_fired || tgt == NULL ||
	    tgt_proj <= TAIL_PROJECT_SEC)
		return;
	__atomic_store_n(&tgt->yield_req, 1, __ATOMIC_RELAXED);
	p->tail_yield_fired = 1;
	if (getenv("HPN_BUNDLE_TIMING") != NULL)
		logit("HPN TAIL-YIELD worker=%d holder_med=%llu proj=%llus",
		    tgt->id, (unsigned long long)tgt_med,
		    (unsigned long long)tgt_proj);
	else
		debug("tail yield: worker %d asked to yield remainder",
		    tgt->id);
}

static void
tail_detector_tick(struct sftp_parallel *p, uint64_t bytes_now)
{
	uint64_t now = monotime_ns();
	uint64_t rate = 0;
	int would_arm = 0;

	/* Per-tick rate sample into the ring. */
	if (p->tail_prev_ns != 0 && now > p->tail_prev_ns &&
	    bytes_now >= p->tail_prev_bytes) {
		rate = (bytes_now - p->tail_prev_bytes) * 1000000000ULL /
		    (now - p->tail_prev_ns);
		p->tail_rate_ring[p->tail_ring_idx] = rate;
		p->tail_ring_idx = (p->tail_ring_idx + 1) % TAIL_RING_TICKS;
		if (p->tail_ring_count < TAIL_RING_TICKS)
			p->tail_ring_count++;
	}
	p->tail_prev_bytes = bytes_now;
	p->tail_prev_ns = now;

	if (p->tail_ring_count < TAIL_RING_TICKS)
		return;	/* window not full yet */

	/* Structural conjunction first (cheap, and required for an arm). */
	int walker_done = (__atomic_load_n(&p->walker_phase,
	    __ATOMIC_RELAXED) == SFTP_WKP_DONE);
	if (!walker_done || sftp_workqueue_depth(p->q) != 0)
		goto resolve;

	{
		int n_ready = 0, n_ready_hist = 0, lagging = 0;
		uint64_t ready_medians[SFTP_PARALLEL_MAX_WORKERS];
		uint64_t worst_proj_sec = 0;
		uint64_t baseline = 0, worst_holder_med = 0;
		/* Phase C yield target: the SLOWEST lagging holder (and its
		 * own projection).  Captured under workers_mu; safe to use
		 * after unlock because reaping runs on this same thread. */
		struct sftp_worker *yield_tgt = NULL;
		uint64_t yield_tgt_med = 0, yield_tgt_proj = 0;

		/*
		 * Per-worker evidence (predicate rework): sample every BUSY
		 * worker's personal rate into its window, then ask the only
		 * question redistribution cares about - would the READY
		 * workers, judged by their own demonstrated window medians,
		 * do the holder's remaining work materially faster?  Workers
		 * without WORKER_RATE_MIN_SAMPLES of history contribute
		 * nothing on either side (a respawn's warmup can neither
		 * accuse nor be accused - the measured source of the old
		 * predicate's false positives).
		 */
		pthread_mutex_lock(&p->workers_mu);
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			int av = __atomic_load_n(&w->avail, __ATOMIC_RELAXED);

			pthread_mutex_lock(&w->mu);
			int healthy = (w->health == WORKER_HEALTHY);
			uint64_t bt = w->bytes_total;
			pthread_mutex_unlock(&w->mu);
			uint64_t cur = bt + __atomic_load_n(&w->live_bytes,
			    __ATOMIC_RELAXED);

			/* Window sampling: BUSY workers only; idle workers
			 * keep their last demonstrated samples. */
			if (av == WORKER_AVAIL_BUSY) {
				if (w->rate_prev_ns != 0 &&
				    now > w->rate_prev_ns &&
				    cur >= w->rate_prev_bytes) {
					uint64_t r = (cur - w->rate_prev_bytes)
					    * 1000000000ULL /
					    (now - w->rate_prev_ns);
					w->rate_ring[w->rate_ring_idx] = r;
					w->rate_ring_idx =
					    (w->rate_ring_idx + 1) %
					    WORKER_RATE_RING;
					if (w->rate_ring_count <
					    WORKER_RATE_RING)
						w->rate_ring_count++;
				}
				w->rate_prev_bytes = cur;
				w->rate_prev_ns = now;
			} else {
				w->rate_prev_ns = 0; /* re-baseline on next BUSY */
			}

			if (!healthy)
				continue;
			if (av == WORKER_AVAIL_READY) {
				uint64_t m = worker_window_median(w);
				n_ready++;
				if (m > 0)
					ready_medians[n_ready_hist++] = m;
			}
		}
		/* Baseline = median of READY workers' demonstrated medians. */
		if (n_ready_hist > 0) {
			for (int i = 1; i < n_ready_hist; i++) {
				uint64_t v = ready_medians[i];
				int j;
				for (j = i; j > 0 && ready_medians[j-1] > v;
				    j--)
					ready_medians[j] = ready_medians[j-1];
				ready_medians[j] = v;
			}
			baseline = ready_medians[n_ready_hist / 2];
		}
		for (int i = 0; i < p->num_workers && baseline > 0; i++) {
			struct sftp_worker *w = p->workers[i];
			int av = __atomic_load_n(&w->avail, __ATOMIC_RELAXED);

			if (av != WORKER_AVAIL_BUSY)
				continue;
			pthread_mutex_lock(&w->mu);
			int healthy = (w->health == WORKER_HEALTHY);
			pthread_mutex_unlock(&w->mu);
			if (!healthy)
				continue;
			uint64_t hmed = worker_window_median(w);
			if (hmed == 0)
				continue;	/* no evidence: cannot accuse */
			if (hmed * 100 < baseline * TAIL_HOLDER_LAG_PCT) {
				uint64_t proj = 0;

				lagging++;
				if (hmed > worst_holder_med ||
				    worst_holder_med == 0)
					worst_holder_med = hmed;
				uint64_t usz = __atomic_load_n(&w->unit_size,
				    __ATOMIC_RELAXED);
				uint64_t done = __atomic_load_n(&w->live_bytes,
				    __ATOMIC_RELAXED);
				if (usz > done && hmed > 0) {
					proj = (usz - done) / hmed;
					if (proj > worst_proj_sec)
						worst_proj_sec = proj;
				}
				if (yield_tgt == NULL || hmed < yield_tgt_med) {
					yield_tgt = w;
					yield_tgt_med = hmed;
					yield_tgt_proj = proj;
				}
			}
		}
		pthread_mutex_unlock(&p->workers_mu);

		if (n_ready > 0 && lagging > 0) {
			uint64_t med_old = tail_quarter_median(
			    p->tail_rate_ring, p->tail_ring_count,
			    p->tail_ring_idx, 0);
			uint64_t med_new = tail_quarter_median(
			    p->tail_rate_ring, p->tail_ring_count,
			    p->tail_ring_idx, 1);
			int trend = (med_old > 0 && med_new <
			    med_old * (100 - TAIL_DECLINE_PCT) / 100);
			int project = (worst_proj_sec > TAIL_PROJECT_SEC);

			if (trend || project) {
				would_arm = 1;
				/*
				 * Persistence gate: contention reshuffles
				 * and post-respawn ramps look identical to
				 * a straggler for a few seconds; only a
				 * condition that HOLDS is actionable.  The
				 * episode start backdates to when the lag
				 * began, so reported durations stay true.
				 */
				if (p->tail_lag_start_ns == 0)
					p->tail_lag_start_ns = now;
				if (!p->tail_episode &&
				    now - p->tail_lag_start_ns >=
				    TAIL_CONFIRM_SEC * 1000000000ULL) {
					if (getenv("HPN_BUNDLE_TIMING") != NULL)
						logit("HPN TAIL-DETECT t=%.3f "
						    "confirm=%.1fs trend=%d "
						    "proj=%llus "
						    "agg_old=%llu agg_new=%llu "
						    "ready=%d ready_hist=%d "
						    "lagging=%d holder_med=%llu "
						    "ready_baseline=%llu",
						    (double)now / 1e9,
						    (double)(now -
						    p->tail_lag_start_ns) / 1e9,
						    trend,
						    (unsigned long long)worst_proj_sec,
						    (unsigned long long)med_old,
						    (unsigned long long)med_new,
						    n_ready, n_ready_hist, lagging,
						    (unsigned long long)worst_holder_med,
						    (unsigned long long)baseline);
					p->tail_episode = 1;
					p->tail_episode_ns = p->tail_lag_start_ns;
					tail_fire_yield(p, yield_tgt,
					    yield_tgt_med, yield_tgt_proj);
				}
			}
		}
	}

 resolve:
	if (!would_arm)
		p->tail_lag_start_ns = 0;	/* condition broke: re-confirm */
	if (p->tail_episode && !would_arm) {
		if (getenv("HPN_BUNDLE_TIMING") != NULL)
			logit("HPN TAIL-EPISODE-END t=%.3f dur=%.1fs "
			    "pending=%llu",
			    (double)now / 1e9,
			    (double)(now - p->tail_episode_ns) / 1e9,
			    (unsigned long long)p->pending);
		p->tail_episode = 0;
		p->tail_yield_fired = 0;	/* re-arm for the next episode */
	}
}

/*
 * ENV-VAR HPN_BUNDLE_TIMING per-tick fleet sample (2026-06-05 midstream-freeze
 * probe).  One line: absolute time, work-queue depth, walker phase, then each
 * worker's phase + cumulative bytes + ssh child pid, plus the fleet total.
 * Per-worker and total bytes are cumulative, so consecutive samples give the
 * per-worker and fleet throughput series.  The pid lets us correlate a worker
 * with its transport's HPN TCPSAMPLE lines (which carry getpid()).
 */
static void
reporter_emit_fleetsample(struct sftp_parallel *p)
{
	static int on = -1;
	char line[4096];
	size_t off;
	uint64_t total = 0;
	int i;

	if (on < 0)
		on = (getenv("HPN_BUNDLE_TIMING") != NULL);
	if (!on)
		return;

	off = (size_t)snprintf(line, sizeof(line),
	    "HPN FLEETSAMPLE t=%.3f qdepth=%zu walker=%s",
	    monotime_double(), sftp_workqueue_depth(p->q),
	    walker_phase_name(__atomic_load_n(&p->walker_phase,
	        __ATOMIC_RELAXED)));

	pthread_mutex_lock(&p->workers_mu);
	for (i = 0; i < p->num_workers && off < sizeof(line) - 64; i++) {
		struct sftp_worker *w = p->workers[i];
		uint64_t wb;
		pthread_mutex_lock(&w->mu);
		wb = w->bytes_total +
		    __atomic_load_n(&w->live_bytes, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&w->mu);
		total += wb;
		off += (size_t)snprintf(line + off, sizeof(line) - off,
		    " w%d:%s:%llu:%ld", w->id,
		    worker_phase_name(__atomic_load_n(&w->phase,
		        __ATOMIC_RELAXED)),
		    (unsigned long long)wb, (long)w->ssh_pid);
	}
	total += p->retired_bytes;
	pthread_mutex_unlock(&p->workers_mu);

	logit("%s total_bytes=%llu", line, (unsigned long long)total);
}

void *
parallel_reporter_thread(void *arg)
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
		 * the flag stays set is harmless.  Record the CAUSE first so
		 * the abort fallout is reported as an interrupt, not errors. */
		if (p->ext_interrupt_flag != NULL && *p->ext_interrupt_flag) {
			p->abort_user = 1;
			parallel_user_abort_flag = 1;
			sftp_parallel_abort(p);
		}

		uint64_t bytes;
		parallel_stats_snapshot(p, &bytes, NULL, NULL);
		p->aggregate_bytes_for_meter = bytes;
		if (p->verify_phase_active && p->verify_total_units > 0) {
			/* Post-transfer verify phase: byte-granular meter.  Counter
			 * = bytes of fully-verified files (verify_done_bytes) + every
			 * worker's in-flight count for the file it is hashing right
			 * now (fed each second by the server hash heartbeat / local
			 * read-back).  This advances smoothly even when a single
			 * huge file is the whole phase, instead of the old file-count
			 * fraction that jumped 0->100% at completion.  Snap to the
			 * exact total once all units are done so the bar lands at
			 * 100% (the last heartbeat may trail the final bytes). */
			uint64_t done_units = __atomic_load_n(
			    &p->verify_done_units, __ATOMIC_RELAXED);
			if (done_units >= p->verify_total_units) {
				p->aggregate_progress_counter =
				    p->verify_meter_total;
			} else {
				uint64_t hashed = __atomic_load_n(
				    &p->verify_done_bytes, __ATOMIC_RELAXED);
				for (int wi = 0; wi < p->num_workers; wi++) {
					struct sftp_worker *w = p->workers[wi];
					if (w != NULL && w->conn != NULL)
						hashed +=
						    sftp_conn_verify_inflight_get(
						        w->conn);
				}
				if (hashed > (uint64_t)p->verify_meter_total)
					hashed = (uint64_t)p->verify_meter_total;
				p->aggregate_progress_counter = (off_t)hashed;
			}
		} else {
			p->aggregate_progress_counter =
			    (off_t)(bytes - p->progress_bytes_baseline);
		}
		if (p->progress_meter_started)
			refresh_progress_meter(0);

		/* Tail trend detector (phase B: telemetry only). */
		tail_detector_tick(p, bytes);

		/* Liveness checks on a slower cadence (every 5 ticks ≈ 1s):
		 * cheaper and watchdog timing doesn't need 200ms granularity. */
		if (++slow_tick_counter >= 5) {
			slow_tick_counter = 0;

			reporter_emit_fleetsample(p);

			/* Watchdog classifies workers HEALTHY/STALLED/DEAD
			 * and SIGTERMs newly DEAD ones. We don't abort here;
			 * the reap loop below joins exited workers and spawns
			 * replacements. */
			(void)parallel_watchdog_check(p);

			/* SIGTERM any respawn wedged in its handshake past the
			 * stall deadline.  The blocked spawn thread cannot time
			 * itself out, so the reporter does it: otherwise the
			 * stalled respawn pins pending_respawns and deadlocks the
			 * abort net (fatal at -j1). */
			parallel_respawn_sweep_stalled(p);

			/* Move any worker re-queue overflow back into p->q as it
			 * frees up.  Workers park here (instead of blocking) when
			 * a re-queue hits a full queue; draining from the reporter
			 * is what keeps that non-blocking path live. */
			parallel_retry_overflow_drain(p);

			/* Track synchronous stalls (all workers at zero bytes
			 * while work is in flight) as a leading indicator of
			 * write-cache saturation from too many parallel writers.
			 * Observation-only for now; future use as a scale-down
			 * signal. */
			parallel_watchdog_sync_check(p);

			int n_to_respawn = reporter_reap_exited_workers(p);

			if (parallel_respawn_dispatch(p, n_to_respawn))
				break;

			/* Operator flare: episode-level notices for degraded
			 * stretches (cooldown / accepting slow workers).  Runs
			 * after dispatch so cooldown + born_slow_accepting are
			 * fresh; no-op on a clean transfer. */
			reporter_flare(p);
		}
	}
	return NULL;
}
