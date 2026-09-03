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

/* sftp-parallel-respawn.c - worker spawn / respawn lifecycle for the
 * parallel SFTP orchestrator: ssh child launch and teardown, the
 * in-flight-spawn kill registry, the deferred respawn thread, and
 * respawn dispatch. */

#include "includes.h"

#include <sys/types.h>
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
#include "sftp-common.h"		/* Attrib, needed by sftp-client.h */
#include "sftp-client.h"
#include "sftp-client-internal.h"
#include "sftp-parallel.h"
#include "sftp-parallel-internal.h"

/* A respawn whose connect+handshake has not completed in this many seconds is
 * wedged. ConnectTimeout bounds only the TCP connect, not the post-connect
 * kex/auth, so a server that accepts the socket then stalls the handshake
 * blocks spawn_one_worker in sftp_init indefinitely, pinning pending_respawns
 * above 0, which suppresses the dead-end abort net and deadlocks the transfer
 * (fatal at -j1). Generous: a healthy spawn finishes in well under a second
 * even with PQ kex, and a false kill merely costs one retried respawn. */
#define HPN_RESPAWN_STALL_SEC 30

/* Cooldown before a replacement attempts its SFTP handshake. Without it
 * the respawn fires within ~7 ms of the dying worker's kill, the server's
 * sftp-server has not finished tearing down the prior session, and the new
 * connection's SSH_FXP_INIT gets a malformed reply (type 0, "Invalid
 * packet back from SSH2_FXP_INIT"). */
#define RESPAWN_COOLDOWN_SEC 2

/*
 * Fork an ssh child for one worker, wired to a pair of pipes, and exec it
 * with an independent (non-multiplexed) connection. On success returns 0
 * with the parent's ends of the pipes in *fd_in_out and *fd_out_out and the
 * child's pid in *pid_out. On failure returns -1 with nothing left open.
 *
 * The child half runs between fork and exec, where POSIX permits only
 * async-signal-safe calls. setenv and snprintf below already break that:
 * both can reach malloc, so a child that forked while another thread held
 * the allocator lock would block forever, showing up as a spawn that never
 * completes. Do not add more of them, and do not add logging.
 */
static int
spawn_worker_ssh(const struct sftp_parallel_config *cfg,
    int *fd_in_out, int *fd_out_out, pid_t *pid_out)
{
	int p2c[2] = { -1, -1 }, c2p[2] = { -1, -1 };
	char user_host[512];

	const char *ssh_bin = cfg->ssh_binary ? cfg->ssh_binary : "hpnssh";

	if (cfg->user && cfg->user[0]) {
		if (snprintf(user_host, sizeof(user_host), "%s@%s",
		    cfg->user, cfg->host) >= (int)sizeof(user_host)) {
			error_ft("user@host too long (%zu byte limit)",
			    sizeof(user_host) - 1);
			return -1;
		}
	} else if (strlcpy(user_host, cfg->host, sizeof(user_host)) >=
	    sizeof(user_host)) {
		error_ft("host too long (%zu byte limit)",
		    sizeof(user_host) - 1);
		return -1;
	}

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
		/* Without these the child would exec ssh talking to the
		 * terminal instead of our pipes, and the parent would block
		 * in sftp_init forever waiting for a reply that can never
		 * arrive. Exit instead: the pipe EOF fails sftp_init in
		 * milliseconds and the spawn is retried. */
		if (dup2(p2c[0], STDIN_FILENO) == -1 ||
		    dup2(c2p[1], STDOUT_FILENO) == -1)
			_exit(126);

		/*
		 * With -W <dir>, send each worker's ssh stderr to
		 * <dir>/hpnssh-worker-<pid>.stderr so a user can hand us a
		 * per-worker log. Without it we inherit stderr, so connection
		 * errors, host-key warnings and banners reach the terminal
		 * rather than a file nobody reads.
		 *
		 * O_EXCL and O_NOFOLLOW defeat the world-writable-directory
		 * symlink race. A co-tenant who predicts our child PID cannot
		 * pre-create the path, either as a symlink to a sensitive file
		 * or as a file they own to read our stderr. On any failure,
		 * including an O_EXCL collision, we inherit instead.
		 */
		if (cfg->worker_log_dir != NULL) {
			char path[PATH_MAX];
			int fd;

			/* A truncated path could drop the pid and collide
			 * with another worker's file. No logging here: we
			 * are between fork and exec, so inherit instead. */
			if (snprintf(path, sizeof(path),
			    "%s/hpnssh-worker-%d.stderr",
			    cfg->worker_log_dir, (int)getpid()) <
			    (int)sizeof(path)) {
				fd = open(path,
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
				    0644);
				if (fd >= 0) {
					/* Deliberately unchecked: inheriting
					 * stderr is the documented fallback,
					 * so a failure here needs no action
					 * beyond closing fd. */
					(void)dup2(fd, STDERR_FILENO);
					close(fd);
				}
			}
		}

		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);

		/*
		 * ENV-VAR HPN_PARALLEL_WORKER: marks this hpnssh child as a
		 * parallel-streams worker so it arms the TCP-health monitor
		 * (clientloop.c) and may self-terminate on a confirmed wedge.
		 * Internal orchestrator->worker signal only; never required
		 * for normal operation. Technically this setenv doesn't
		 * meet standards because of the malloc called by setenv.
		 * However, this is a pretty common pattern and has minimal
		 * risks associated.
		 */
		(void)setenv("HPN_PARALLEL_WORKER", "1", 1);

		/* Build argv for an independent (non-mux) SSH connection.
		 * Generous: about 15 slots for what we build below, the rest
		 * for -o passthroughs. argv_max reserves the tail so the two
		 * cannot drift apart. */
		char *argv[80];
		int argc = 0;
		int argv_max = (int)(sizeof(argv) / sizeof(*argv)) - 8;
		argv[argc++] = (char *)ssh_bin;
		argv[argc++] = "-oBatchMode=yes";
		argv[argc++] = "-oControlMaster=no";
		argv[argc++] = "-oControlPath=none";
		argv[argc++] = "-oStrictHostKeyChecking=accept-new";
		/* Worker verbosity is max(the user's -v count, 1 if -W is
		 * set). Passing their count through keeps the workers
		 * consistent with the hpnsftp layer, and -W forces at least
		 * one -v because ssh is silent on a successful handshake and
		 * an empty log file is a footgun. Taking the max means we
		 * never lower what they asked for. ssh accepts at most -vvv,
		 * so cap there rather than waste argv slots. */
		{
			int verbosity = cfg->verbose_level;

			if (cfg->worker_log_dir != NULL && verbosity < 1)
				verbosity = 1;
			if (verbosity > 3)
				verbosity = 3;
			for (int i = 0; i < verbosity; i++)
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
		if (cfg->extra_argv) {
			for (int i = 0;
			    cfg->extra_argv[i] != NULL && argc < argv_max;
			    i++) {
				argv[argc++] = "-o";
				argv[argc++] = cfg->extra_argv[i];
			}
		}
		/*
		 * Remote subsystem / server-command selection, mirroring the
		 * main connection (sftp.c): a spec containing '/' is a path to
		 * a server command run directly (no -s); otherwise it is a
		 * subsystem name requested with -s (default "sftp").
		 * cfg->sftp_server carries the user's -s argument (NULL when
		 * unset; always NULL from scp, which has no -s subsystem).
		 */
		if (cfg->sftp_server != NULL &&
		    strchr(cfg->sftp_server, '/') != NULL) {
			argv[argc++] = user_host;
			argv[argc++] = (char *)cfg->sftp_server;
		} else {
			argv[argc++] = "-s";
			argv[argc++] = user_host;
			argv[argc++] = (char *)(cfg->sftp_server != NULL ?
			    cfg->sftp_server : "sftp");
		}
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

/*
 * Close a worker's pipes and reap its ssh child.
 *
 * The blocking waitpid has no escape, so the caller must already have
 * killed the child or be certain it will exit on the pipe EOF the closes
 * below produce. sftp_parallel_stop, the only caller, SIGKILLs every ssh
 * child and joins every worker thread first. Being the only caller is also
 * what makes the unsynchronised writes below safe, so a second one needs
 * both properties, not just the kill.
 */
void
parallel_respawn_teardown_ssh(struct sftp_worker *worker)
{
	if (worker->fd_in >= 0)  { close(worker->fd_in);  worker->fd_in = -1; }
	if (worker->fd_out >= 0) { close(worker->fd_out); worker->fd_out = -1; }
	if (worker->ssh_pid > 0) {
		/* NULL status: nothing here cares how the child died. */
		(void)waitpid(worker->ssh_pid, NULL, 0);
		worker->ssh_pid = -1;
	}
}

/* Register/deregister an in-flight spawn's ssh child so abort/stop can kill
 * it out of a blocking connect instead of waiting it out. Register returns 0
 * when the table is full, which its caller treats as a failed spawn. */
static int
spawning_pid_register(struct sftp_parallel *fleet, pid_t pid)
{
	int registered = 0;
	pthread_mutex_lock(&fleet->workers_mu);
	if (fleet->n_spawning < SFTP_PARALLEL_MAX_WORKERS) {
		fleet->spawning_since[fleet->n_spawning] = monotime();
		fleet->spawning_pids[fleet->n_spawning] = pid;
		fleet->n_spawning++;
		registered = 1;
	}
	pthread_mutex_unlock(&fleet->workers_mu);
	return registered;
}

static void
spawning_pid_deregister(struct sftp_parallel *fleet, pid_t pid)
{
	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = 0; i < fleet->n_spawning; i++) {
		if (fleet->spawning_pids[i] == pid) {
			int last = --fleet->n_spawning;
			fleet->spawning_pids[i] = fleet->spawning_pids[last];
			fleet->spawning_since[i] = fleet->spawning_since[last];
			break;
		}
	}
	pthread_mutex_unlock(&fleet->workers_mu);
}

/* SIGTERM any in-flight spawn stalled past HPN_RESPAWN_STALL_SEC: the child's
 * exit fails sftp_init on the pipe EOF, which deregisters the pid and resolves
 * the respawn (pending_respawns--), letting the normal reap/retry/abort
 * recovery proceed. Called every reporter tick (the blocked spawn thread
 * cannot time itself out). */
void
parallel_respawn_sweep_stalled(struct sftp_parallel *fleet)
{
	time_t now = monotime();

	pthread_mutex_lock(&fleet->workers_mu);
	for (int i = 0; i < fleet->n_spawning; i++) {
		if (fleet->spawning_pids[i] <= 0 ||
		    now - fleet->spawning_since[i] < HPN_RESPAWN_STALL_SEC)
			continue;
		debug2_ft("respawn pid %ld stalled %lds in handshake; SIGKILL to "
		    "free the respawn slot", (long)fleet->spawning_pids[i],
		    (long)(now - fleet->spawning_since[i]));
		(void)kill(fleet->spawning_pids[i], SIGKILL);
		/* Re-arm so we don't SIGKILL-storm before the spawn thread
		 * deregisters on the EOF; the child dies in milliseconds. */
		fleet->spawning_since[i] = now;
	}
	pthread_mutex_unlock(&fleet->workers_mu);
}

/*
 * Spawn one worker: SSH child via the master's socket, sftp_init,
 * attach to fleet->workers[] under workers_mu, then start the worker
 * thread. Returns the worker on success, NULL on failure with all
 * resources cleaned up. Used during initial bring-up and by the
 * reporter's respawn dispatch when a worker has died.
 */
static struct sftp_worker *
spawn_one_worker(struct sftp_parallel *fleet)
{
	int registered = 0;

	/* A dying/dead fleet takes no recruits, and a spawn that starts
	 * after abort/stop would block the teardown drain on its connect. */
	if (fleet->abort_flag || fleet->stopped)
		return NULL;

	struct sftp_worker *worker = xcalloc(1, sizeof(*worker));
	worker->parent = fleet;
	worker->fd_in = worker->fd_out = -1;
	worker->ssh_pid = -1;
	pthread_mutex_init(&worker->mu, NULL);

	u_int buflen = fleet->cfg.transfer_buflen ?
	    fleet->cfg.transfer_buflen : DEFAULT_TRANSFER_BUFLEN;
	u_int nreq = fleet->cfg.num_requests ?
	    fleet->cfg.num_requests : DEFAULT_NUM_REQUESTS;

	if (spawn_worker_ssh(&fleet->cfg,
	    &worker->fd_in, &worker->fd_out, &worker->ssh_pid) != 0) {
		error_ft("ssh spawn failed");
		goto fail;
	}
	/* From here until sftp_init returns we may block for a full connect
	 * timeout inside the child. Register the child so abort/stop can
	 * SIGTERM it (the pipe EOF fails sftp_init within ms), and re-check
	 * the flags after registering: a teardown that swept the registry
	 * just before our registration is caught here and we self-kill. */
	if (!spawning_pid_register(fleet, worker->ssh_pid)) {
		/* Registry full (SFTP_PARALLEL_MAX_WORKERS spawns already in
		 * flight, which is pathological, e.g. a spawn storm). An
		 * unregistered child cannot be found by abort/stop's SIGKILL
		 * sweep, so proceeding would pin teardown for a full connect
		 * timeout. Reap it now and fail the spawn. respawn_owed persists,
		 * so the dispatch retries once an in-flight slot frees. */
		error_ft("spawn registry full; abandoning spawn");
		goto fail;
	}
	registered = 1;
	if (fleet->abort_flag || fleet->stopped)
		goto fail;
	worker->conn = sftp_init(worker->fd_in, worker->fd_out, buflen, nreq,
	    fleet->cfg.limit_kbps);
	spawning_pid_deregister(fleet, worker->ssh_pid);
	registered = 0;
	if (worker->conn == NULL) {
		/* Quiet when the teardown killed our child out of the
		 * connect; loud for a genuine init failure. */
		if (fleet->abort_flag || fleet->stopped)
			debug_ft("sftp_init abandoned (abort)");
		else
			error_ft("sftp_init failed");
		goto fail;
	}
	sftp_set_live_counter(worker->conn, &worker->live_bytes);
	__atomic_store_n(&worker->yield_req, 0, __ATOMIC_RELAXED);
	sftp_set_yield_flag(worker->conn, &worker->yield_req);
	/* Propagate verify transfer to this worker conn: the main conn gets
	 * it at sftp_init time, but worker conns are created here and must be
	 * told explicitly. Without it the upload's inline source-hash
	 * accumulator never arms (verify falls back to a second full read). */
	sftp_conn_set_verify_transfer(worker->conn, fleet->cfg.verify_transfer);

	/* Insert into workers array under lock. */
	pthread_mutex_lock(&fleet->workers_mu);
	if (fleet->num_workers >= SFTP_PARALLEL_MAX_WORKERS) {
		pthread_mutex_unlock(&fleet->workers_mu);
		error_ft("worker array full; abandoning spawn");
		goto fail;
	}
	if (fleet->num_workers >= fleet->workers_cap) {
		int newcap = fleet->workers_cap ? fleet->workers_cap * 2 : 8;
		if (newcap > SFTP_PARALLEL_MAX_WORKERS)
			newcap = SFTP_PARALLEL_MAX_WORKERS;
		fleet->workers = xreallocarray(fleet->workers, newcap,
		    sizeof(*fleet->workers));
		fleet->workers_cap = newcap;
	}
	worker->id = fleet->next_worker_id++;
	fleet->workers[fleet->num_workers++] = worker;
	pthread_mutex_unlock(&fleet->workers_mu);

	if (pthread_create(&worker->tid, NULL, parallel_worker_thread, worker) != 0) {
		error_ft("pthread_create failed");
		/* Roll back insertion. */
		pthread_mutex_lock(&fleet->workers_mu);
		for (int i = 0; i < fleet->num_workers; i++) {
			if (fleet->workers[i] == worker) {
				memmove(&fleet->workers[i], &fleet->workers[i + 1],
				    (fleet->num_workers - i - 1) *
				    sizeof(*fleet->workers));
				fleet->num_workers--;
				break;
			}
		}
		pthread_mutex_unlock(&fleet->workers_mu);
		goto fail;
	}
	worker->started = 1;
	return worker;

 fail:
	if (registered)
		spawning_pid_deregister(fleet, worker->ssh_pid);
	if (worker->conn)
		sftp_free(worker->conn);
	if (worker->fd_in >= 0)
		close(worker->fd_in);
	if (worker->fd_out >= 0)
		close(worker->fd_out);
	if (worker->ssh_pid > 0) {
		/* Unconditional: by now the child is deregistered, so the
		 * stall sweep cannot reach it and this wait has no escape.
		 * A no-op on a child that has already exited. */
		(void)kill(worker->ssh_pid, SIGKILL);
		(void)waitpid(worker->ssh_pid, NULL, 0);
	}
	pthread_mutex_destroy(&worker->mu);
	free(worker);
	return NULL;
}

/* Spawns one replacement worker, called from a detached thread so
 * the SSH handshake doesn't block the reporter's progress ticks. */
static void *
respawn_worker_thread(void *arg)
{
	struct sftp_parallel *fleet = arg;
	struct timespec cooldown = { .tv_sec = RESPAWN_COOLDOWN_SEC,
	    .tv_nsec = 0 };
	struct timespec remaining;

	/* Finish the whole cooldown. Respawn threads mask no signals, so a
	 * running progress meter's alarm would otherwise cut the sleep short
	 * and reintroduce the FXP_INIT race this delay exists to avoid. */
	while (nanosleep(&cooldown, &remaining) == -1 && errno == EINTR)
		cooldown = remaining;

	/* The orchestrator may have been told to abort/stop while we slept
	 * (user interrupt, fleet abort, session teardown). Bail WITHOUT
	 * spawning: a replacement would join a dead fleet. This check is
	 * also what makes the detached-thread lifetime safe: stop() drains
	 * pending_respawns before freeing fleet, and that drain returns promptly
	 * only because we exit here instead of attempting a connection. */
	if (fleet->abort_flag || fleet->stopped) {
		pthread_mutex_lock(&fleet->workers_mu);
		fleet->pending_respawns--;
		pthread_mutex_unlock(&fleet->workers_mu);
		return NULL;
	}

	/*
	 * Once spawn_one_worker returns, worker is owned by the fleet (already
	 * inserted into fleet->workers[] and running its thread), so the reporter
	 * reap can pthread_join + destroy + free it at any moment. Do not
	 * dereference worker here. A success only needs the NULL check.
	 */
	struct sftp_worker *worker = spawn_one_worker(fleet);
	if (worker == NULL) {
		/* Under an abort the failure is manufactured (we killed the
		 * spawn ourselves). Expected fallout, not news. */
		if (fleet->abort_flag || fleet->stopped)
			debug_ft("worker respawn abandoned (abort)");
		else
			error_ft("worker respawn failed");
	}
	pthread_mutex_lock(&fleet->workers_mu);
	fleet->pending_respawns--;
	pthread_mutex_unlock(&fleet->workers_mu);
	return NULL;
}

/*
 * Drive worker respawn dispatch for the reporter's slow tick. Takes the
 * count of non-voluntary worker exits seen this tick, absorbs them into the
 * persistent backlog, and launches replacements up to the available slots,
 * or a single probe when the fleet is empty. Returns 1 if the reporter
 * should break out of its main loop, 0 otherwise.
 *
 * Cooldown policy, escalating and decaying, with no count cap. Two triggers
 * share one action. The primary is a systemic peer-stall burst, at least
 * max(PEER_STALL_SYSTEMIC_MIN, PEER_STALL_SYSTEMIC_FRAC_PCT% of num_streams)
 * peer-stall deaths inside PEER_STALL_WINDOW, which says the backend is
 * saturated fleet-wide. The backstop is the cause-agnostic epoch ceiling,
 * RESPAWN_MULTIPLIER x num_streams respawns.
 *
 * Either pauses respawns, not live workers, for the current level, starting
 * at BASE and doubling per burst to CAP. Sustained healthy throughput halves
 * the level every DECAY_SEC and ends a pause early. There is no
 * cooldown-count abort: under a transient stall we back off and retry
 * indefinitely rather than drop data, and the shrunken fleet is itself the
 * back-pressure on the saturated backend.
 *
 * Below the systemic threshold a peer-stall death is localized. Chunk 1 has
 * already re-queued the unit at the front of the FIFO and any worker steals
 * it, so only a fleet-wide burst trips the back-off.
 *
 * The gate is session-wide rather than per-worker, deliberately. One bad
 * worker starving the budget has not been observed.
 */
int
parallel_respawn_dispatch(struct sftp_parallel *fleet, int n_to_respawn)
{
	time_t now_s = monotime();	/* misc.c, CLOCK_MONOTONIC seconds */

	/* Snapshot the fleet. pending_respawns is decremented by
	 * detached respawn threads, so it is taken here with num_workers
	 * rather than read later: the probe gate below needs the two to
	 * agree, and a stale read there would let a second probe launch. */
	pthread_mutex_lock(&fleet->workers_mu);
	int cur_workers  = fleet->num_workers;
	int in_flight    = fleet->pending_respawns;
	int respawn_ceil = fleet->cfg.num_streams * RESPAWN_MULTIPLIER;
	pthread_mutex_unlock(&fleet->workers_mu);

	/* Snapshot the pending unit count. */
	pthread_mutex_lock(&fleet->pending_mu);
	uint64_t pending = fleet->pending;
	pthread_mutex_unlock(&fleet->pending_mu);

	/* Absorb this tick's involuntary deaths into the backlog.
	 * respawn_owed carries across cooldowns and pthread_create failures,
	 * so the worker pool drains back up to num_streams once spawning
	 * resumes. */
	if (n_to_respawn > 0)
		fleet->respawn_owed += n_to_respawn;

	if (fleet->respawn_cooldown_dur_s == 0)
		fleet->respawn_cooldown_dur_s = RESPAWN_COOLDOWN_BASE_SEC; /* lazy */

	/*
	 * Systemic peer-stall detector: push this tick's delta of peer-stall
	 * worker deaths into a rolling window (mirrors the sync_stall window);
	 * a window sum at/above the systemic threshold means the backend is
	 * saturated fleet-wide. The same reporter thread increments
	 * peer_stall_terminations (in the reap just above) and reads it here,
	 * so no extra lock is needed.
	 */
	int ps_delta = fleet->peer_stall_terminations - fleet->peer_stall_prev_sample;
	if (ps_delta < 0)
		ps_delta = 0;
	fleet->peer_stall_prev_sample = fleet->peer_stall_terminations;
	fleet->peer_stall_window[fleet->peer_stall_window_pos % PEER_STALL_WINDOW] =
	    ps_delta;
	fleet->peer_stall_window_pos++;
	int ps_sum = 0;
	for (int i = 0; i < PEER_STALL_WINDOW; i++)
		ps_sum += fleet->peer_stall_window[i];
	int systemic_min =
	    (fleet->cfg.num_streams * PEER_STALL_SYSTEMIC_FRAC_PCT + 99) / 100;
	if (systemic_min < PEER_STALL_SYSTEMIC_MIN)
		systemic_min = PEER_STALL_SYSTEMIC_MIN;
	int systemic = (ps_sum >= systemic_min);

	/*
	 * Path-health streak drives both the cooldown-level decay and the
	 * early exit from an active pause. "Healthy" = the freshest raw max
	 * throughput is at or above the configured floor (default 2 MiB/s).
	 */
	int healthy = (fleet->cfg.tput_path_healthy_bytes_s > 0) &&
	    (fleet->tput_last_raw_max_bytes_s >= fleet->cfg.tput_path_healthy_bytes_s);
	if (healthy) {
		if (fleet->respawn_healthy_since_s == 0) {
			fleet->respawn_healthy_since_s = now_s;
			fleet->respawn_decay_anchor_s  = now_s;
		}
		while (fleet->respawn_cooldown_dur_s > RESPAWN_COOLDOWN_BASE_SEC &&
		    now_s - fleet->respawn_decay_anchor_s >=
		    RESPAWN_COOLDOWN_DECAY_SEC) {
			fleet->respawn_cooldown_dur_s /= 2;
			if (fleet->respawn_cooldown_dur_s < RESPAWN_COOLDOWN_BASE_SEC)
				fleet->respawn_cooldown_dur_s =
				    RESPAWN_COOLDOWN_BASE_SEC;
			fleet->respawn_decay_anchor_s += RESPAWN_COOLDOWN_DECAY_SEC;
		}
	} else {
		fleet->respawn_healthy_since_s = 0;
	}

	/* Cooldown expiry, or early exit once the backend has recovered. */
	int in_cooldown = 0;
	if (fleet->respawn_resume_s != 0) {
		if (now_s >= fleet->respawn_resume_s) {
			debug_ft("respawn cooldown ended, resuming "
			    "(epoch reset, owed=%d)", fleet->respawn_owed);
			fleet->respawn_resume_s = 0;
			fleet->respawn_epoch_count = 0;
		} else if (healthy && fleet->respawn_healthy_since_s != 0 &&
		    now_s - fleet->respawn_healthy_since_s >=
		    RESPAWN_COOLDOWN_DECAY_SEC) {
			/* debug-level: the operator-facing recovery line is the
			 * reporter_flare falling-edge notice. */
			char rate[FMT_SCALED_STRSIZE];

			fmt_scaled((long long)
			    fleet->tput_last_raw_max_bytes_s, rate);
			debug_ft("respawn cooldown ended early: path healthy "
			    "(%sB/s) for %ds - resuming respawns", rate,
			    RESPAWN_COOLDOWN_DECAY_SEC);
			fleet->respawn_resume_s = 0;
			fleet->respawn_epoch_count = 0;
		} else {
			in_cooldown = 1;
		}
	}

	/*
	 * Cooldown entry. Two triggers, one action: a systemic peer-stall
	 * burst (primary) or the cause-agnostic epoch ceiling (backstop).
	 * Pause respawns for the current escalating level, then double it
	 * (capped) for the next burst. No count cap, no abort, best-effort.
	 */
	if (!in_cooldown && fleet->respawn_owed > 0 &&
	    (systemic || fleet->respawn_epoch_count >= respawn_ceil)) {
		fleet->respawn_resume_s = now_s + fleet->respawn_cooldown_dur_s;
		fleet->respawn_decay_anchor_s = now_s;	/* freeze decay while paused */
		/* Require fresh sustained health to exit the pause early. */
		fleet->respawn_healthy_since_s = 0;
		fleet->respawn_epoch_count = 0;
		in_cooldown = 1;
		/* debug-level: the operator-facing notice is the reporter_flare
		 * rising-edge line; this keeps the per-entry detail for traces. */
		debug_ft("respawn cooldown: %s - pausing respawns for %llds "
		    "(healthy workers continue)",
		    systemic ? "systemic peer stall" : "epoch-ceiling churn",
		    (long long)fleet->respawn_cooldown_dur_s);
		fleet->respawn_cooldown_dur_s *= 2;
		if (fleet->respawn_cooldown_dur_s > RESPAWN_COOLDOWN_CAP_SEC)
			fleet->respawn_cooldown_dur_s = RESPAWN_COOLDOWN_CAP_SEC;
	}

	/* Decide how many workers to launch this tick. */
	int target = fleet->cfg.num_streams;
	int slots  = target - cur_workers;
	int to_spawn;
	if (in_cooldown || fleet->abort_flag || fleet->stopped) {
		to_spawn = 0;
	} else if (cur_workers == 0) {
		/* Fleet empty: launch a single probe rather than num_streams
		 * fresh connections, so we don't slam a possibly-still-
		 * saturated backend. A healthy probe refills normally on the
		 * following ticks; a re-stall escalates the cooldown.
		 *
		 * Gate on pending_respawns == 0: the probe's respawn thread
		 * sleeps ~2s (the FXP_INIT-race cooldown) before it connects,
		 * longer than the reporter tick (~1s), so without this guard the
		 * next tick(s) still see cur_workers == 0 and launch additional
		 * probes, the exact connection storm the single-probe design
		 * exists to avoid. One probe in flight is enough. */
		to_spawn = 0;
		if (in_flight == 0 &&
		    (fleet->respawn_owed > 0 || pending > 0))
			to_spawn = 1;
	} else if (fleet->respawn_owed > 0 && slots > 0) {
		/* Never more than the free slots, however deep the backlog. */
		to_spawn = MINIMUM(fleet->respawn_owed, slots);
	} else {
		to_spawn = 0;
	}
	if (to_spawn > 0) {
		debug_ft("initiating respawn for %d worker(s) (current=%d "
		    "target=%d owed=%d epoch=%d/%d cooldown_level=%llds%s)",
		    to_spawn, cur_workers, target, fleet->respawn_owed,
		    fleet->respawn_epoch_count + to_spawn, respawn_ceil,
		    (long long)fleet->respawn_cooldown_dur_s,
		    cur_workers == 0 ? " probe" : "");
	}
	/* Launch them, one detached thread each. */
	for (int i = 0; i < to_spawn; i++) {
		if (fleet->abort_flag || fleet->stopped)
			break;
		pthread_mutex_lock(&fleet->workers_mu);
		fleet->pending_respawns++;
		fleet->total_respawns++;
		fleet->respawn_epoch_count++;
		pthread_mutex_unlock(&fleet->workers_mu);
		pthread_t rtid;
		if (pthread_create(&rtid, NULL,
		    respawn_worker_thread, fleet) == 0) {
			(void)pthread_detach(rtid);
			/* Drain backlog only on success; a failed create
			 * leaves owed in place so we retry next tick. A probe
			 * (owed may be 0) doesn't underflow the backlog. */
			if (fleet->respawn_owed > 0)
				fleet->respawn_owed--;	/* lock not needed */
		} else {
			error_ft("respawn thread create failed");
			pthread_mutex_lock(&fleet->workers_mu);
			fleet->pending_respawns--;
			fleet->total_respawns--;
			fleet->respawn_epoch_count--;
			pthread_mutex_unlock(&fleet->workers_mu);
		}
	}

	/*
	 * Genuine dead-end abort: every worker gone, units still pending, not
	 * in a cooldown pause, and no respawn is in flight, i.e. a probe
	 * could not even be launched (pthread_create failing). A backend
	 * stall is deliberately NOT this case: there we are in cooldown (or
	 * have a probe pending), so we wait and retry indefinitely rather than
	 * dropping the transfer.
	 */
	/* Re-snapshot rather than reusing the values above: the spawn loop
	 * may have raised pending_respawns. */
	pthread_mutex_lock(&fleet->workers_mu);
	int all_gone = (fleet->num_workers == 0 && fleet->pending_respawns == 0);
	pthread_mutex_unlock(&fleet->workers_mu);
	if (all_gone && !in_cooldown && !fleet->abort_flag && pending > 0) {
		error_ft("all workers gone with %llu unit(s) pending and no "
		    "respawn could be launched -- aborting transfer",
		    (unsigned long long)pending);
		sftp_parallel_abort(fleet);
		return 1;
	}
	return 0;
}

/*
 * Launch one worker of the initial fleet, on its own thread so the SSH
 * handshakes overlap. Waits on ctx->auth_cv until fewer than max_in_flight
 * authentications are outstanding, spawns its worker, then releases the
 * slot and signals the next thread in.
 *
 * ctx->succeeded is written here without a lock and read by the launcher in
 * sftp_parallel_start. That is safe only because the read happens after
 * pthread_join, which orders the two. Do not move the read before the join.
 */
void *
parallel_respawn_spawn_thread(void *arg)
{
	struct spawn_ctx *ctx = arg;

	/* wait for an auth slot to open */
	pthread_mutex_lock(ctx->auth_mu);
	while (*ctx->auth_in_flight >= ctx->max_in_flight)
		pthread_cond_wait(ctx->auth_cv, ctx->auth_mu);
	++*ctx->auth_in_flight;
	int started = ++*ctx->started;
	pthread_mutex_unlock(ctx->auth_mu);

	/* print the connection message to the user */
	if (ctx->fleet->cfg.print_flag != SFTP_QUIET) {
		if (started % ctx->max_in_flight == 0 || started == ctx->total)
			fprintf(stderr, "Connecting workers %d of %d\n",
			    started, ctx->total);
	}

	/* spawn the worker and update the success field */
	ctx->succeeded = 0;
	if (spawn_one_worker(ctx->fleet) != NULL)
		ctx->succeeded = 1;

	/* release our current auth slot and wake up the next waiter */
	pthread_mutex_lock(ctx->auth_mu);
	--*ctx->auth_in_flight;
	pthread_cond_signal(ctx->auth_cv);
	pthread_mutex_unlock(ctx->auth_mu);

	return NULL;
}
