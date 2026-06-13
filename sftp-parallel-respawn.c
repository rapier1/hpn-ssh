/*
 * sftp-parallel-respawn.c - worker spawn / respawn lifecycle for the
 * parallel SFTP orchestrator: ssh child launch and teardown, the
 * in-flight-spawn kill registry, the deferred respawn thread, and
 * respawn dispatch.  Split from sftp-parallel.c; moves are verbatim.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
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
#include "sftp-client-internal.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"

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
		 * Optional diagnostic aid: when -W <dir> was supplied to
		 * hpnsftp (cfg->worker_log_dir non-NULL), redirect each
		 * worker's SSH child stderr to
		 * <dir>/hpnssh-worker-<pid>.stderr so the user can send us
		 * a clear per-worker log when reporting failures.
		 *
		 * In normal operation (-W not set) we INHERIT stderr - so
		 * SSH connection errors, host-key warnings, server banners
		 * and the like reach the user's terminal where they're
		 * actually useful, instead of vanishing into a file the
		 * user never reads.
		 *
		 * Hardening: O_EXCL | O_NOFOLLOW defeats the classic
		 * world-writable-directory symlink-race / preexisting-file
		 * attack - a co-tenant who predicts our child PID can't
		 * pre-create the path as either a symlink to a sensitive
		 * file (→ DoS via O_TRUNC equivalent) or as a file they own
		 * (→ info leak via redirected stderr).  On any failure
		 * (including O_EXCL collision) we fall through to inherited
		 * stderr, which is the safe default.
		 */
		if (cfg->worker_log_dir != NULL) {
			char path[PATH_MAX];
			int fd;
			snprintf(path, sizeof(path),
			    "%s/hpnssh-worker-%d.stderr",
			    cfg->worker_log_dir, (int)getpid());
			fd = open(path,
			    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
			    0644);
			if (fd >= 0) {
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}

		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);

		/*
		 * ENV-VAR HPN_PARALLEL_WORKER: marks this hpnssh child as a
		 * parallel-streams worker so it arms the TCP-health monitor
		 * (clientloop.c) and may self-terminate on a confirmed wedge.
		 * Internal orchestrator->worker signal only; never required
		 * for normal operation.
		 */
		(void)setenv("HPN_PARALLEL_WORKER", "1", 1);

		/* Build argv for an independent (non-mux) SSH connection. */
		char *argv[40];
		int argc = 0;
		argv[argc++] = (char *)ssh_bin;
		argv[argc++] = "-oBatchMode=yes";
		argv[argc++] = "-oControlMaster=no";
		argv[argc++] = "-oControlPath=none";
		argv[argc++] = "-oStrictHostKeyChecking=accept-new";
		/* Worker verbosity = max(user's hpnsftp -v count,
		 *                        worker_log_dir ? 1 : 0).
		 *
		 * Passing through the user's own -v count keeps worker
		 * verbosity consistent with what they asked for at the
		 * hpnsftp layer (previously hpnsftp -v added -v to the
		 * control-master SSH but not to the workers - asymmetric).
		 *
		 * When -W is set, force at least -v so the captured stderr
		 * files actually contain something useful: ssh is silent on
		 * a successful handshake, and an empty log file is a
		 * usability footgun.  We take the MAX of the two so a user
		 * who explicitly asked for -vv (or higher) gets that level
		 * - we never decrease their requested verbosity.
		 *
		 * SSH itself accepts at most -vvv (three -v's).  Cap there
		 * to avoid wasted argv slots. */
		{
			int v = cfg->verbose_level;
			if (cfg->worker_log_dir != NULL && v < 1)
				v = 1;
			if (v > 3) v = 3;
			for (int i = 0; i < v; i++)
				argv[argc++] = "-v";
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

void
parallel_respawn_teardown_ssh(struct sftp_worker *w)
{
	if (w->fd_in >= 0)  { close(w->fd_in);  w->fd_in = -1; }
	if (w->fd_out >= 0) { close(w->fd_out); w->fd_out = -1; }
	if (w->ssh_pid > 0) {
		int status;
		(void)waitpid(w->ssh_pid, &status, 0);
		w->ssh_pid = -1;
	}
}

/* Register/deregister an in-flight spawn's ssh child so abort/stop can
 * SIGTERM it out of a blocking connect instead of waiting it out. */
static void
spawning_pid_register(struct sftp_parallel *p, pid_t pid)
{
	pthread_mutex_lock(&p->workers_mu);
	if (p->n_spawning < SFTP_PARALLEL_MAX_WORKERS)
		p->spawning_pids[p->n_spawning++] = pid;
	pthread_mutex_unlock(&p->workers_mu);
}

static void
spawning_pid_deregister(struct sftp_parallel *p, pid_t pid)
{
	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->n_spawning; i++) {
		if (p->spawning_pids[i] == pid) {
			p->spawning_pids[i] =
			    p->spawning_pids[--p->n_spawning];
			break;
		}
	}
	pthread_mutex_unlock(&p->workers_mu);
}

static struct sftp_worker *
spawn_one_worker(struct sftp_parallel *p)
{
	int registered = 0;

	/* A dying/dead fleet takes no recruits - and a spawn that starts
	 * after abort/stop would block the teardown drain on its connect. */
	if (p->abort_flag || p->stopped)
		return NULL;

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
	/* From here until sftp_init returns we may block for a full connect
	 * timeout inside the child.  Register the child so abort/stop can
	 * SIGTERM it (the pipe EOF fails sftp_init within ms), and re-check
	 * the flags AFTER registering: a teardown that swept the registry
	 * just before our registration is caught here and we self-kill. */
	spawning_pid_register(p, w->ssh_pid);
	registered = 1;
	if (p->abort_flag || p->stopped) {
		(void)kill(w->ssh_pid, SIGTERM);
		goto fail;
	}
	w->conn = sftp_init(w->fd_in, w->fd_out, buflen, nreq,
	    p->cfg.limit_kbps);
	spawning_pid_deregister(p, w->ssh_pid);
	registered = 0;
	if (w->conn == NULL) {
		/* Quiet when the teardown killed our child out of the
		 * connect; loud for a genuine init failure. */
		if (p->abort_flag || p->stopped)
			debug_ft("sftp_init abandoned (abort)");
		else
			error_ft("sftp_init failed");
		goto fail;
	}
	sftp_set_live_counter(w->conn, &w->live_bytes);
	__atomic_store_n(&w->yield_req, 0, __ATOMIC_RELAXED);
	sftp_set_yield_flag(w->conn, &w->yield_req);

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

	if (pthread_create(&w->tid, NULL, parallel_worker_thread, w) != 0) {
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
	if (registered)
		spawning_pid_deregister(p, w->ssh_pid);
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
		/* ENV-VAR SFTP_RESPAWN_DELAY_MS - developer-only: respawn-
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

	/* The orchestrator may have been told to abort/stop while we slept
	 * (user interrupt, fleet abort, session teardown).  Bail WITHOUT
	 * spawning: a replacement would join a dead fleet.  This check is
	 * also what makes the detached-thread lifetime safe - stop() drains
	 * pending_respawns before freeing p, and that drain returns promptly
	 * only because we exit here instead of attempting a connection. */
	if (p->abort_flag || p->stopped) {
		pthread_mutex_lock(&p->workers_mu);
		p->pending_respawns--;
		pthread_mutex_unlock(&p->workers_mu);
		return NULL;
	}

	struct sftp_worker *w = spawn_one_worker(p);
	if (w == NULL) {
		/* Under an abort the failure is manufactured (we killed the
		 * spawn ourselves) - expected fallout, not news. */
		if (p->abort_flag || p->stopped)
			debug_ft("worker respawn abandoned (abort)");
		else
			error_ft("worker respawn failed");
	} else {
		uint64_t now = monotime_ns();
		pthread_mutex_lock(&w->mu);
		w->reconnect_count++;
		if (w->first_reconnect_ns == 0)
			w->first_reconnect_ns = now;
		w->last_reconnect_ns = now;
		pthread_mutex_unlock(&w->mu);
		if (w->reconnect_count == HPN_WORKER_CHURN_NOTICE)
			logit("worker %d has reconnected %llu times; this "
			    "path may be unreliable", w->id,
			    (unsigned long long)w->reconnect_count);
		debug_ft("worker %d respawned (reconnect_count=%llu)",
		    w->id, (unsigned long long)w->reconnect_count);
	}
	pthread_mutex_lock(&p->workers_mu);
	p->pending_respawns--;
	pthread_mutex_unlock(&p->workers_mu);
	return NULL;
}

/*
 * Drive worker respawn dispatch for the reporter's slow tick.  Takes
 * the count of non-voluntary worker exits seen on this tick and:
 *
 *   - absorbs them into respawn_owed (the persistent backlog)
 *   - samples the systemic peer-stall window and decays the cooldown level
 *   - on a systemic peer-stall burst or epoch-ceiling churn, enters/escalates
 *     a cooldown that pauses RESPAWNS ONLY (live workers keep running)
 *   - launches respawn threads up to the available slots (a single probe when
 *     the fleet is empty)
 *   - aborts ONLY as a genuine dead-end: all workers gone, units pending, not
 *     in cooldown, and a respawn could not even be launched
 *
 * Returns 1 if the reporter should break out of its main loop; 0 otherwise.
 *
 * Cooldown policy (escalating + decaying, best-effort, no count cap):
 *   Two entry triggers, one action.  PRIMARY: a systemic peer-stall burst -
 *   >= max(PEER_STALL_SYSTEMIC_MIN, PEER_STALL_SYSTEMIC_FRAC_PCT% of
 *   num_streams) peer-stall worker deaths within the PEER_STALL_WINDOW
 *   (~10 s) - means the backend is saturated fleet-wide.  BACKSTOP: the cause-
 *   agnostic epoch ceiling (RESPAWN_MULTIPLIER x num_streams respawns).
 *   Either pauses respawns for the current cooldown level (BASE, doubling per
 *   burst to CAP); sustained healthy throughput halves the level per DECAY_SEC
 *   and ends an active pause early.  There is NO cooldown-count abort: under a
 *   transient backend stall we back off and retry indefinitely, surfacing the
 *   condition rather than dropping data.  Pausing respawns shrinks the fleet
 *   to its functional subset - that IS the concurrency-shedding back-pressure
 *   on the saturated backend.
 *
 * Localized vs systemic:
 *   Below the systemic threshold a peer-stall death is localized: chunk 1 has
 *   already re-queued the unit (front of the FIFO) and any worker steals it -
 *   no cooldown.  Only a fleet-wide burst trips the back-off.
 *
 * Per-worker scope (deliberate, retained from 2026-05-30):
 *   The gate is session-wide, not per-worker.  Per-worker observability
 *   (first/last_reconnect_ns in the stats CSV) attributes churn post-hoc.  If
 *   one bad worker is ever shown to starve the budget, add a per-worker
 *   sliding-window thrash detector (time-windowed, not lifetime-capped) - do
 *   not add until the data shows it matters.  A respawn-EFFECTIVENESS trigger
 *   ("last K probes each re-stalled within T") is the truer signal than
 *   fleet-fraction and is the next candidate; deferred for now.
 */
int
parallel_respawn_dispatch(struct sftp_parallel *p, int n_to_respawn)
{
	time_t now_s = monotime();	/* misc.c, CLOCK_MONOTONIC seconds */

	pthread_mutex_lock(&p->workers_mu);
	int cur_workers  = p->num_workers;
	int respawn_ceil = p->cfg.num_streams * RESPAWN_MULTIPLIER;
	/* Scan-idle-first (HPN_RESPAWN_SCAN_IDLE): count READY healthy
	 * workers so the spawn decision below can defer fleet restoration
	 * while existing idle capacity covers the queued demand.  One pass
	 * over a small array, only when the gate is armed. */
	int n_ready_healthy = 0;
	if (p->respawn_scan_idle) {
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = p->workers[i];
			int av = __atomic_load_n(&w->avail,
			    __ATOMIC_RELAXED);

			pthread_mutex_lock(&w->mu);
			int healthy = (w->health == WORKER_HEALTHY);
			pthread_mutex_unlock(&w->mu);
			if (av == WORKER_AVAIL_READY && healthy &&
			    !w->doomed && !w->exited)
				n_ready_healthy++;
		}
	}
	pthread_mutex_unlock(&p->workers_mu);

	pthread_mutex_lock(&p->pending_mu);
	uint64_t pending = p->pending;
	pthread_mutex_unlock(&p->pending_mu);

	/* Absorb this tick's involuntary deaths into the backlog.
	 * respawn_owed carries across cooldowns and pthread_create failures,
	 * so the worker pool drains back up to num_streams once spawning
	 * resumes. */
	if (n_to_respawn > 0)
		p->respawn_owed += n_to_respawn;

	if (p->respawn_cooldown_dur_s == 0)
		p->respawn_cooldown_dur_s = RESPAWN_COOLDOWN_BASE_SEC; /* lazy */

	/*
	 * Systemic peer-stall detector: push this tick's delta of peer-stall
	 * worker deaths into a rolling window (mirrors the sync_stall window);
	 * a window sum at/above the systemic threshold means the backend is
	 * saturated fleet-wide.  The same reporter thread increments
	 * peer_stall_terminations (in the reap just above) and reads it here,
	 * so no extra lock is needed.
	 */
	int ps_delta = p->peer_stall_terminations - p->peer_stall_prev_sample;
	if (ps_delta < 0)
		ps_delta = 0;
	p->peer_stall_prev_sample = p->peer_stall_terminations;
	p->peer_stall_window[p->peer_stall_window_pos % PEER_STALL_WINDOW] =
	    ps_delta;
	p->peer_stall_window_pos++;
	int ps_sum = 0;
	for (int i = 0; i < PEER_STALL_WINDOW; i++)
		ps_sum += p->peer_stall_window[i];
	int systemic_min =
	    (p->cfg.num_streams * PEER_STALL_SYSTEMIC_FRAC_PCT + 99) / 100;
	if (systemic_min < PEER_STALL_SYSTEMIC_MIN)
		systemic_min = PEER_STALL_SYSTEMIC_MIN;
	int systemic = (ps_sum >= systemic_min);

	/*
	 * Path-health streak drives both the cooldown-level decay and the
	 * early exit from an active pause.  "Healthy" = the freshest raw max
	 * throughput is at or above the configured floor (default 2000 kbps).
	 */
	int healthy = (p->cfg.tput_path_healthy_kbps > 0) &&
	    (p->tput_last_raw_max_kbps >= p->cfg.tput_path_healthy_kbps);
	if (healthy) {
		if (p->respawn_healthy_since_s == 0) {
			p->respawn_healthy_since_s = now_s;
			p->respawn_decay_anchor_s  = now_s;
		}
		while (p->respawn_cooldown_dur_s > RESPAWN_COOLDOWN_BASE_SEC &&
		    now_s - p->respawn_decay_anchor_s >=
		    RESPAWN_COOLDOWN_DECAY_SEC) {
			p->respawn_cooldown_dur_s /= 2;
			if (p->respawn_cooldown_dur_s < RESPAWN_COOLDOWN_BASE_SEC)
				p->respawn_cooldown_dur_s =
				    RESPAWN_COOLDOWN_BASE_SEC;
			p->respawn_decay_anchor_s += RESPAWN_COOLDOWN_DECAY_SEC;
		}
	} else {
		p->respawn_healthy_since_s = 0;
	}

	/* Cooldown expiry, or early exit once the backend has recovered. */
	int in_cooldown = 0;
	if (p->respawn_resume_s != 0) {
		if (now_s >= p->respawn_resume_s) {
			debug_ft("respawn cooldown ended, resuming "
			    "(epoch reset, owed=%d)", p->respawn_owed);
			p->respawn_resume_s = 0;
			p->respawn_epoch_count = 0;
		} else if (healthy && p->respawn_healthy_since_s != 0 &&
		    now_s - p->respawn_healthy_since_s >=
		    RESPAWN_COOLDOWN_DECAY_SEC) {
			/* debug-level: the operator-facing recovery line is the
			 * reporter_flare falling-edge notice. */
			debug_ft("respawn cooldown ended early: path healthy "
			    "(%llukbps) for %ds - resuming respawns",
			    (unsigned long long)p->tput_last_raw_max_kbps,
			    RESPAWN_COOLDOWN_DECAY_SEC);
			p->respawn_resume_s = 0;
			p->respawn_epoch_count = 0;
		} else {
			in_cooldown = 1;
		}
	}

	/*
	 * Cooldown entry.  Two triggers, one action: a systemic peer-stall
	 * burst (primary) or the cause-agnostic epoch ceiling (backstop).
	 * Pause respawns for the current escalating level, then double it
	 * (capped) for the next burst.  No count cap, no abort - best-effort.
	 */
	if (!in_cooldown && p->respawn_owed > 0 &&
	    (systemic || p->respawn_epoch_count >= respawn_ceil)) {
		p->respawn_resume_s = now_s + p->respawn_cooldown_dur_s;
		p->respawn_decay_anchor_s = now_s;	/* freeze decay while paused */
		p->respawn_healthy_since_s = 0;		/* require fresh sustained
							 * health to exit early */
		p->respawn_epoch_count = 0;
		in_cooldown = 1;
		/* debug-level: the operator-facing notice is the reporter_flare
		 * rising-edge line; this keeps the per-entry detail for traces. */
		debug_ft("respawn cooldown: %s - pausing respawns for %llds "
		    "(healthy workers continue)",
		    systemic ? "systemic peer stall" : "epoch-ceiling churn",
		    (long long)p->respawn_cooldown_dur_s);
		p->respawn_cooldown_dur_s *= 2;
		if (p->respawn_cooldown_dur_s > RESPAWN_COOLDOWN_CAP_SEC)
			p->respawn_cooldown_dur_s = RESPAWN_COOLDOWN_CAP_SEC;
	}

	int target = p->cfg.num_streams;
	int slots  = target - cur_workers;
	int to_spawn;
	if (in_cooldown || p->abort_flag || p->stopped) {
		to_spawn = 0;
	} else if (cur_workers == 0) {
		/* Fleet empty: launch a SINGLE probe rather than num_streams
		 * fresh connections, so we don't slam a possibly-still-
		 * saturated backend.  A healthy probe refills normally on the
		 * following ticks; a re-stall escalates the cooldown. */
		to_spawn = (p->respawn_owed > 0 || pending > 0) ? 1 : 0;
	} else {
		to_spawn = (p->respawn_owed > 0 && slots > 0)
		    ? ((p->respawn_owed < slots) ? p->respawn_owed : slots)
		    : 0;
		/*
		 * Scan-idle-first (ENV-VAR HPN_RESPAWN_SCAN_IDLE=1): a
		 * respawn is a NEW connection into a possibly penalty-
		 * counting server - the born-dead candidate that feeds
		 * freeze storms.  If READY healthy workers already cover
		 * everything waiting in the queue, restoring fleet size
		 * buys nothing now: defer.  respawn_owed persists, so the
		 * moment queued demand outgrows the idle pool the deferred
		 * respawns fire on a later tick.  With no idle capacity
		 * (j == active writers) the gate never engages.
		 *
		 * PROGRESS GUARD (the fix for the measured regression): only
		 * defer while the fleet is actually MOVING BYTES.  qdepth==0
		 * with idle workers means "capacity covers demand" ONLY if
		 * work is flowing; during a freeze it instead means the lone
		 * remaining unit is wedged on a stalled worker and the fleet
		 * is short-handed - deferring there prolonged the freeze
		 * (measured: 65 defers across one stall).  noprogress_consec_
		 * ticks (maintained by parallel_watchdog_sync_check, which
		 * runs earlier this same tick) is 0 while the fleet advances
		 * and climbs the instant it stalls.  Stalled => do NOT defer;
		 * let the owed respawn fire.
		 */
		if (to_spawn > 0 && n_ready_healthy > 0 &&
		    p->noprogress_consec_ticks == 0 &&
		    sftp_workqueue_depth(p->q) <= (size_t)n_ready_healthy) {
			p->respawn_defers++;
			if (getenv("HPN_BUNDLE_TIMING") != NULL)
				logit("HPN RESPAWN-DEFER owed=%d ready=%d "
				    "qdepth=%zu", p->respawn_owed,
				    n_ready_healthy,
				    sftp_workqueue_depth(p->q));
			else
				debug_ft("respawn deferred: %d ready healthy "
				    "worker(s) cover the queue (owed=%d)",
				    n_ready_healthy, p->respawn_owed);
			to_spawn = 0;
		}
	}
	if (to_spawn > 0) {
		debug_ft("initiating respawn for %d worker(s) (current=%d "
		    "target=%d owed=%d epoch=%d/%d cooldown_level=%llds%s)",
		    to_spawn, cur_workers, target, p->respawn_owed,
		    p->respawn_epoch_count + to_spawn, respawn_ceil,
		    (long long)p->respawn_cooldown_dur_s,
		    cur_workers == 0 ? " probe" : "");
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
			 * leaves owed in place so we retry next tick.  A probe
			 * (owed may be 0) doesn't underflow the backlog. */
			if (p->respawn_owed > 0)
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

	/*
	 * Genuine dead-end abort: every worker gone, units still pending, NOT
	 * in a cooldown pause, and no respawn is in flight - i.e. a probe
	 * could not even be launched (pthread_create failing).  A backend
	 * stall is deliberately NOT this case: there we are in cooldown (or
	 * have a probe pending), so we wait and retry indefinitely rather than
	 * dropping the transfer.
	 */
	pthread_mutex_lock(&p->workers_mu);
	int all_gone = (p->num_workers == 0 && p->pending_respawns == 0);
	pthread_mutex_unlock(&p->workers_mu);
	if (all_gone && !in_cooldown && !p->abort_flag && pending > 0) {
		error_ft("all workers gone with %llu unit(s) pending and no "
		    "respawn could be launched -- aborting transfer",
		    (unsigned long long)pending);
		sftp_parallel_abort(p);
		return 1;
	}
	return 0;
}

void *
parallel_respawn_spawn_thread(void *arg)
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
