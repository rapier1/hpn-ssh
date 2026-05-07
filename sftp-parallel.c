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
#define MAX_RETRIES             3
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

/* Watchdog thresholds. STALL: warn if a worker has had work available but
 * completed nothing for this long. DEAD: escalate to abort. Generous values
 * because legitimate single-file transfers can run for minutes. */
#define STALL_THRESHOLD_SEC     60
#define DEAD_THRESHOLD_SEC      300
#define RESPAWN_MULTIPLIER      2  /* abort when total respawns exceeds
				    * this * num_streams; each worker slot
				    * gets one retry before concluding the
				    * problem is systemic */

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
};

struct sftp_work_unit {
	enum sftp_op op;
	char    *src_path;
	char    *dst_path;
	off_t    size;
	mode_t   mode;
	int      attempt;
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
	enum worker_health health;             /* set by reporter, read for log */

	int                started;
	int                exited;             /* set by worker on self-exit;
						* read by reporter for reaping */
	int                exited_voluntary;   /* set when exiting via EXIT_WORKER
						* sentinel; suppresses replacement
						* spawn in the reap loop */
	int                doomed;            /* set by watchdog before SIGTERM;
						* prevents double-kill */
};

struct sftp_parallel {
	struct sftp_parallel_config cfg;
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
	int                         total_respawns;  /* lifetime respawn count;
						       * abort when this exceeds
						       * 2 * cfg.num_streams */
	int                         protocol_violations; /* under workers_mu;
						       * abort if any non-zero;
						       * exposed via stats for
						       * post-mortem inspection */

	pthread_t                   reporter_tid;
	int                         reporter_started;

	/* Pending counter for sftp_parallel_wait. */
	pthread_mutex_t             pending_mu;
	pthread_cond_t              pending_cv;
	uint64_t                    pending;

	/* Set by sftp_parallel_abort, read by workers between units. */
	volatile sig_atomic_t       abort_flag;

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
	if (pipe(c2p) < 0) {
		close(p2c[0]); close(p2c[1]);
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		close(p2c[0]); close(p2c[1]);
		close(c2p[0]); close(c2p[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(p2c[0], STDIN_FILENO);
		dup2(c2p[1], STDOUT_FILENO);
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

static void
free_unit(struct sftp_work_unit *u)
{
	if (u == NULL) return;
	free(u->src_path);
	free(u->dst_path);
	free(u);
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

/* Handle the result of executing a single work unit (retry or completion). */
static void
worker_process_result(struct sftp_worker *w, struct sftp_work_unit *u, int rc)
{
	struct sftp_parallel *p = w->parent;

	if (rc == 0) {
		worker_record_completion(w, u->size, 1);
		free_unit(u);
		pending_dec(p);
	} else if (++u->attempt < MAX_RETRIES) {
		/* Re-queue without freeing. Keeps pending counter consistent. */
		if (sftp_workqueue_push(p->q, u) != 0) {
			worker_record_completion(w, 0, 0);
			free_unit(u);
			pending_dec(p);
		}
	} else {
		error_f("worker %d: unit failed after %d attempts: %s",
		    w->id, u->attempt,
		    u->src_path ? u->src_path : "(null)");
		worker_record_completion(w, 0, 0);
		free_unit(u);
		pending_dec(p);
	}
}

static void *
worker_thread(void *arg)
{
	struct sftp_worker *w = arg;
	struct sftp_parallel *p = w->parent;

	/* Mask SIGALRM so progressmeter timer ticks deliver only to the
	 * main thread / reporter (which holds it unmasked). */
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	while (1) {
		if (p->abort_flag)
			break;
		void *item = NULL;
		if (sftp_workqueue_pop(p->q, &item) != 0)
			break;	/* shutdown && empty */
		struct sftp_work_unit *u0 = item;
		if (u0 == NULL)
			continue;

		/* Self-exit sentinel from sftp_parallel_remove_worker. The
		 * first worker to pop this exits its loop; the reporter
		 * thread reaps it. Mark voluntary so the reap loop does
		 * not spawn a replacement. */
		if (u0->op == SFTP_OP_EXIT_WORKER) {
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
		if (u0->op == SFTP_OP_UPLOAD) {
			struct sftp_work_unit *batch[UPLOAD_BATCH_SIZE];
			struct sftp_work_unit *leftover = NULL;
			int bn = 0;

			batch[bn++] = u0;
			while (bn < UPLOAD_BATCH_SIZE && !p->abort_flag) {
				void *nxt = NULL;
				if (sftp_workqueue_trypop(p->q, &nxt) != 0)
					break; /* queue empty or shutdown */
				struct sftp_work_unit *nu = nxt;
				if (nu->op == SFTP_OP_UPLOAD) {
					batch[bn++] = nu;
				} else {
					/* Non-upload: stop collecting, handle after batch. */
					leftover = nu;
					break;
				}
			}

			/*logit("sftp-parallel: worker %d batch_size=%d "
			    "(queue_depth=%zu)", w->id, bn,
			    sftp_workqueue_depth(p->q)); */

			if (bn == 1) {
				/* Single file — skip batch overhead. */
				worker_record_start(w);
				int rc = execute_unit(w, batch[0]);
				worker_process_result(w, batch[0], rc);
			} else {
				/*
				 * True batch: build entry array, run pipelined
				 * open/write/close, then record per-file results.
				 */
				struct sftp_upload_batch_entry entries[UPLOAD_BATCH_SIZE];
				for (int i = 0; i < bn; i++) {
					entries[i].local_path  = batch[i]->src_path;
					entries[i].remote_path = batch[i]->dst_path;
					entries[i].result      = 0;
					worker_record_start(w);
				}

				sftp_upload_batch(w->conn, entries, bn,
				    p->cfg.preserve_flag,
				    p->cfg.fsync_flag,
				    p->cfg.inplace_flag);

				for (int i = 0; i < bn; i++) {
					int rc = entries[i].result;
					if (rc == 0) {
						worker_record_completion(w,
						    batch[i]->size, 1);
						free_unit(batch[i]);
						pending_dec(p);
					} else if (++batch[i]->attempt < MAX_RETRIES) {
						/*
						 * Re-queue without recording completion:
						 * pending stays up, live_bytes reset inline.
						 */
						__atomic_store_n(&w->live_bytes, 0,
						    __ATOMIC_RELAXED);
						if (sftp_workqueue_push(p->q,
						    batch[i]) != 0) {
							worker_record_completion(w, 0, 0);
							free_unit(batch[i]);
							pending_dec(p);
						}
					} else {
						error_f("worker %d: batch unit failed "
						    "after %d attempts: %s",
						    w->id, batch[i]->attempt,
						    batch[i]->src_path ?
						    batch[i]->src_path : "(null)");
						worker_record_completion(w, 0, 0);
						free_unit(batch[i]);
						pending_dec(p);
					}
				}
			}

			/* Process the leftover non-upload unit (if any). */
			if (leftover != NULL) {
				if (leftover->op == SFTP_OP_EXIT_WORKER) {
					free_unit(leftover);
					pthread_mutex_lock(&w->mu);
					w->exited_voluntary = 1;
					pthread_mutex_unlock(&w->mu);
					break;
				}
				worker_record_start(w);
				int rc = execute_unit(w, leftover);
				worker_process_result(w, leftover, rc);
			}
		} else {
			/* Download, mkdir, or other non-upload unit. */
			worker_record_start(w);
			int rc = execute_unit(w, u0);
			worker_process_result(w, u0, rc);
		}

		/* Protocol violation (ID mismatch, unexpected packet type):
		 * possible MITM attack or serious server corruption. Do not
		 * retry — increment the orchestrator violation counter and
		 * abort the entire transfer. A fresh connection to a MITM
		 * would repeat the same violation. Unit cleanup already
		 * handled above by worker_process_result / batch result loop. */
		if (sftp_conn_is_protocol_violation(w->conn)) {
			error_f("worker %d: protocol violation — possible MITM "
			    "attack or server protocol corruption; "
			    "aborting transfer", w->id);
			pthread_mutex_lock(&p->workers_mu);
			p->protocol_violations++;
			pthread_mutex_unlock(&p->workers_mu);
			sftp_parallel_abort(p);
			break;
		}

		/* Connection died during the transfer — this worker cannot
		 * continue.  The unit was already re-queued or failed above;
		 * exit cleanly so the orchestrator can detect us as dead. */
		if (sftp_conn_is_dead(w->conn))
			break;
	}
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
 * Watchdog: classify each worker as HEALTHY/STALLED/DEAD based on (a) its
 * ssh child's existence and (b) elapsed time since last completion when
 * the queue had work to feed it. Returns nonzero if any worker has
 * transitioned to DEAD, signaling the reporter to abort the orchestrator.
 */
static int
watchdog_check_workers(struct sftp_parallel *p)
{
	int any_dead = 0;
	uint64_t now = monotonic_ns();
	int queue_has_work = (sftp_workqueue_depth(p->q) > 0);

	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = p->workers[i];
		enum worker_health prev, next;

		pthread_mutex_lock(&w->mu);
		prev = w->health;
		uint64_t since_completion_ns = w->last_completion_ns ?
		    (now - w->last_completion_ns) : 0;
		uint64_t in_flight = w->units_started - w->units_completed -
		    w->units_failed;
		pthread_mutex_unlock(&w->mu);

		next = WORKER_HEALTHY;

		/* SSH child gone is the strongest signal — detectable
		 * immediately via kill(0). The worker thread will notice
		 * on its next I/O (pipe EOF), but the probe lets the
		 * watchdog classify and act without waiting. */
		if (w->ssh_pid > 0 && kill(w->ssh_pid, 0) != 0 &&
		    errno == ESRCH) {
			next = WORKER_DEAD;
		} else if (queue_has_work && in_flight > 0 &&
		    since_completion_ns > 0) {
			uint64_t s = since_completion_ns / 1000000000ULL;
			if (s > DEAD_THRESHOLD_SEC)
				next = WORKER_DEAD;
			else if (s > STALL_THRESHOLD_SEC)
				next = WORKER_STALLED;
		}

		if (next != prev) {
			pthread_mutex_lock(&w->mu);
			w->health = next;
			pthread_mutex_unlock(&w->mu);
			if (next == WORKER_STALLED) {
				logit_f("worker %d stalled: no progress in "
				    "%llu sec while queue has work",
				    w->id,
				    (unsigned long long)
				    (since_completion_ns / 1000000000ULL));
			} else if (next == WORKER_DEAD) {
				error_f("worker %d declared dead: "
				    "ssh_pid=%ld since_completion=%llus",
				    w->id, (long)w->ssh_pid,
				    (unsigned long long)
				    (since_completion_ns / 1000000000ULL));
			}
		}

		/* Doom dead workers: SIGTERM the SSH child so any blocking
		 * I/O in the worker thread unblocks immediately. Guard with
		 * doomed to prevent double-SIGTERM on successive ticks. */
		if (next == WORKER_DEAD) {
			int already_doomed;
			pthread_mutex_lock(&w->mu);
			already_doomed = w->doomed || w->exited;
			if (!already_doomed)
				w->doomed = 1;
			pthread_mutex_unlock(&w->mu);
			if (!already_doomed) {
				if (w->ssh_pid > 0)
					(void)kill(w->ssh_pid, SIGTERM);
				logit_f("worker %d: sent SIGTERM to ssh child "
				    "(pid %ld)", w->id, (long)w->ssh_pid);
			}
			any_dead = 1;
		}
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
	struct sftp_worker *w = spawn_one_worker(p);
	if (w == NULL)
		error_f("worker respawn failed");
	else {
		pthread_mutex_lock(&w->mu);
		w->reconnect_count++;
		pthread_mutex_unlock(&w->mu);
	}
	pthread_mutex_lock(&p->workers_mu);
	p->pending_respawns--;
	pthread_mutex_unlock(&p->workers_mu);
	return NULL;
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

			/* Watchdog classifies workers HEALTHY/STALLED/DEAD
			 * and SIGTERMs newly DEAD ones. We don't abort here;
			 * the reap loop below joins exited workers and spawns
			 * replacements. */
			(void)watchdog_check_workers(p);

			/* Reap workers that have exited (either via
			 * SFTP_OP_EXIT_WORKER sentinel or because their
			 * connection died). Collect under workers_mu, then
			 * join and free outside the lock. */
			struct sftp_worker *to_reap[SFTP_PARALLEL_MAX_WORKERS];
			int to_reap_voluntary[SFTP_PARALLEL_MAX_WORKERS];
			int n_reap = 0;
			pthread_mutex_lock(&p->workers_mu);
			for (int i = p->num_workers - 1; i >= 0; i--) {
				struct sftp_worker *w = p->workers[i];
				int exited, voluntary;
				pthread_mutex_lock(&w->mu);
				exited    = w->exited;
				voluntary = w->exited_voluntary;
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
					/* Belt-and-suspenders: may already
					 * be dead from SIGTERM above. */
					(void)kill(w->ssh_pid, SIGKILL);
					(void)waitpid(w->ssh_pid, &s, 0);
				}
				pthread_mutex_destroy(&w->mu);
				free(w);
			}

			/* Spawn replacements for non-voluntary exits
			 * (connection died or watchdog-SIGTERMed). Run each
			 * in a detached thread so the SSH handshake doesn't
			 * block the reporter's progress ticks.
			 *
			 * Hard ceiling: abort if total lifetime respawns
			 * exceeds 2 * num_streams. Each worker slot gets one
			 * retry; beyond that the problem is systemic (sustained
			 * failure, attack) and continuing only delays the
			 * inevitable MAX_RETRIES drain. */
			pthread_mutex_lock(&p->workers_mu);
			int cur_workers  = p->num_workers;
			int respawn_ceil = p->cfg.num_streams * RESPAWN_MULTIPLIER;
			int over_ceil    = (p->total_respawns >= respawn_ceil);
			pthread_mutex_unlock(&p->workers_mu);

			if (over_ceil && n_to_respawn > 0) {
				error_f("respawn ceiling reached (%d of %d "
				    "allowed) — persistent connection failure, "
				    "aborting transfer", respawn_ceil,
				    respawn_ceil);
				sftp_parallel_abort(p);
				break;
			}

			int target   = p->cfg.num_streams;
			int slots    = target - cur_workers;
			int to_spawn = (n_to_respawn < slots) ?
			    n_to_respawn : slots;
			for (int i = 0; i < to_spawn; i++) {
				if (p->abort_flag || p->stopped)
					break;
				pthread_mutex_lock(&p->workers_mu);
				p->pending_respawns++;
				p->total_respawns++;
				pthread_mutex_unlock(&p->workers_mu);
				pthread_t rtid;
				if (pthread_create(&rtid, NULL,
				    respawn_worker_thread, p) == 0) {
					(void)pthread_detach(rtid);
				} else {
					error_f("respawn thread create failed");
					pthread_mutex_lock(&p->workers_mu);
					p->pending_respawns--;
					p->total_respawns--;
					pthread_mutex_unlock(&p->workers_mu);
				}
			}

			/* If every worker is gone and no respawn is in
			 * flight, all recovery attempts have failed; abort
			 * rather than letting sftp_parallel_wait hang. */
			pthread_mutex_lock(&p->workers_mu);
			int all_gone = (p->num_workers == 0 &&
			    p->pending_respawns == 0);
			pthread_mutex_unlock(&p->workers_mu);
			if (all_gone && !p->abort_flag) {
				pthread_mutex_lock(&p->pending_mu);
				int stuck = (p->pending > 0);
				pthread_mutex_unlock(&p->pending_mu);
				if (stuck) {
					error_f("all workers gone with %llu "
					    "unit(s) pending -- aborting "
					    "transfer",
					    (unsigned long long)p->pending);
					sftp_parallel_abort(p);
					break;
				}
			}
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

	unsigned int buflen = p->cfg.transfer_buflen ?
	    p->cfg.transfer_buflen : DEFAULT_TRANSFER_BUFLEN;
	unsigned int nreq = p->cfg.num_requests ?
	    p->cfg.num_requests : DEFAULT_NUM_REQUESTS;

	if (spawn_worker_ssh(&p->cfg,
	    &w->fd_in, &w->fd_out, &w->ssh_pid) != 0) {
		error_f("ssh spawn failed");
		goto fail;
	}
	w->conn = sftp_init(w->fd_in, w->fd_out, buflen, nreq,
	    p->cfg.limit_kbps);
	if (w->conn == NULL) {
		error_f("sftp_init failed");
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
		error_f("pthread_create failed");
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
	pthread_mutex_init(&p->pending_mu, NULL);
	pthread_cond_init(&p->pending_cv, NULL);
	pthread_mutex_init(&p->workers_mu, NULL);

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
				error_f("spawn thread %d failed", i);
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
				error_f("worker %d setup failed", i);
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
	pthread_mutex_lock(&p->pending_mu);
	p->pending++;
	pthread_mutex_unlock(&p->pending_mu);
	if (sftp_workqueue_push(p->q, u) != 0) {
		pthread_mutex_lock(&p->pending_mu);
		if (p->pending > 0) p->pending--;
		pthread_mutex_unlock(&p->pending_mu);
		free_unit(u);
		return -1;
	}
	return 0;
}

int
sftp_parallel_submit_upload(struct sftp_parallel *p,
    const char *local_path, const char *remote_path, off_t size, mode_t mode)
{
	return submit(p,
	    make_unit(SFTP_OP_UPLOAD, local_path, remote_path, size, mode));
}

int
sftp_parallel_submit_download(struct sftp_parallel *p,
    const char *remote_path, const char *local_path, off_t size, mode_t mode)
{
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
	pthread_mutex_lock(&p->pending_mu);
	pthread_cond_broadcast(&p->pending_cv);
	pthread_mutex_unlock(&p->pending_mu);
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

static int
parallel_upload_walk(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int depth)
{
	int created = 0, ret = 0;
	DIR *dirp;
	struct dirent *dp;
	char *new_src = NULL, *new_dst = NULL;
	struct stat sb;
	Attrib a, dirattrib;
	uint32_t saved_perm;
	int preserve_flag = p->cfg.preserve_flag;
	int follow_link_flag = p->cfg.follow_link_flag;

	if (depth >= PARALLEL_MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		return -1;
	}
	if (stat(src, &sb) == -1) {
		error("stat local \"%s\": %s", src, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		error("\"%s\" is not a directory", src);
		return -1;
	}

	stat_to_attrib(&sb, &a);
	a.flags &= ~SSH2_FILEXFER_ATTR_SIZE;
	a.flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
	a.perm &= 01777;
	if (!preserve_flag)
		a.flags &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	saved_perm = a.perm;
	a.perm |= (S_IWUSR|S_IXUSR);
	if (sftp_mkdir(conn, dst, &a, 0) == 0) {
		created = 1;
	} else {
		if (sftp_stat(conn, dst, 0, &dirattrib) != 0)
			return -1;
		if (!S_ISDIR(dirattrib.perm)) {
			error("\"%s\" exists but is not a directory", dst);
			return -1;
		}
	}
	a.perm = saved_perm;

	if ((dirp = opendir(src)) == NULL) {
		error("local opendir \"%s\": %s", src, strerror(errno));
		return -1;
	}
	while (((dp = readdir(dirp)) != NULL) && !p->abort_flag) {
		const char *filename = dp->d_name;
		if (dp->d_ino == 0)
			continue;
		if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
			continue;
		free(new_dst); free(new_src);
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);

		if (lstat(new_src, &sb) == -1) {
			logit("local lstat \"%s\": %s", filename,
			    strerror(errno));
			ret = -1;
			continue;
		}
		if (S_ISLNK(sb.st_mode)) {
			if (!follow_link_flag) {
				logit("%s: not a regular file", filename);
				continue;
			}
			if (stat(new_src, &sb) == -1) {
				logit("local stat \"%s\": %s", filename,
				    strerror(errno));
				ret = -1;
				continue;
			}
		}
		if (S_ISDIR(sb.st_mode)) {
			if (parallel_upload_walk(p, conn, new_src, new_dst,
			    depth + 1) == -1)
				ret = -1;
		} else if (S_ISREG(sb.st_mode)) {
			if (sftp_parallel_submit_upload(p, new_src, new_dst,
			    sb.st_size, sb.st_mode) != 0) {
				error("submit \"%s\" -> \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} else {
			logit("%s: not a regular file", filename);
		}
	}
	free(new_dst);
	free(new_src);

	if (created || preserve_flag)
		sftp_setstat(conn, dst, &a);

	(void)closedir(dirp);
	return ret;
}

int
sftp_parallel_upload_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag)
{
	if (p == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Entering %s\n", src);
	return parallel_upload_walk(p, conn, src, dst, 0);
}

static int
parallel_download_walk(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int depth, Attrib *dirattrib)
{
	int i, ret = 0;
	SFTP_DIRENT **dir_entries;
	char *new_src = NULL, *new_dst = NULL;
	mode_t mode = 0777, tmpmode = mode;
	Attrib *a, ldirattrib, lsym;
	int preserve_flag = p->cfg.preserve_flag;
	int follow_link_flag = p->cfg.follow_link_flag;

	if (depth >= PARALLEL_MAX_DIR_DEPTH) {
		error("Maximum directory depth exceeded: %d levels", depth);
		return -1;
	}
	if (dirattrib == NULL) {
		if (sftp_stat(conn, src, 1, &ldirattrib) != 0) {
			error("stat remote \"%s\" directory failed", src);
			return -1;
		}
		dirattrib = &ldirattrib;
	}
	if (!S_ISDIR(dirattrib->perm)) {
		error("\"%s\" is not a directory", src);
		return -1;
	}
	if (dirattrib->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		mode = dirattrib->perm & 01777;
		tmpmode = mode | (S_IWUSR|S_IXUSR);
	}
	if (mkdir(dst, tmpmode) == -1 && errno != EEXIST) {
		error("mkdir %s: %s", dst, strerror(errno));
		return -1;
	}
	if (sftp_readdir(conn, src, &dir_entries) == -1) {
		error("remote readdir \"%s\" failed", src);
		return -1;
	}

	for (i = 0; dir_entries[i] != NULL && !p->abort_flag; i++) {
		const char *filename = dir_entries[i]->filename;
		free(new_dst); free(new_src);
		new_dst = sftp_path_append(dst, filename);
		new_src = sftp_path_append(src, filename);
		a = &dir_entries[i]->a;

		if (S_ISLNK(a->perm)) {
			if (!follow_link_flag) {
				logit("download \"%s\": not a regular file",
				    new_src);
				continue;
			}
			if (sftp_stat(conn, new_src, 1, &lsym) != 0) {
				logit("remote stat \"%s\" failed", new_src);
				ret = -1;
				continue;
			}
			a = &lsym;
		}

		if (S_ISDIR(a->perm)) {
			if (strcmp(filename, ".") == 0 ||
			    strcmp(filename, "..") == 0)
				continue;
			if (parallel_download_walk(p, conn, new_src, new_dst,
			    depth + 1, a) == -1)
				ret = -1;
		} else if (S_ISREG(a->perm)) {
			off_t fsize = (a->flags & SSH2_FILEXFER_ATTR_SIZE) ?
			    (off_t)a->size : 0;
			mode_t fmode = (a->flags &
			    SSH2_FILEXFER_ATTR_PERMISSIONS) ?
			    (a->perm & 07777) : 0644;
			if (sftp_parallel_submit_download(p, new_src, new_dst,
			    fsize, fmode) != 0) {
				error("submit download \"%s\" -> \"%s\" failed",
				    new_src, new_dst);
				ret = -1;
			}
		} else {
			logit("download \"%s\": not a regular file", new_src);
		}
	}
	free(new_dst);
	free(new_src);

	if (preserve_flag &&
	    (dirattrib->flags & SSH2_FILEXFER_ATTR_ACMODTIME)) {
		struct timeval tv[2];
		tv[0].tv_sec = dirattrib->atime;
		tv[1].tv_sec = dirattrib->mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (utimes(dst, tv) == -1)
			error("local set times on \"%s\": %s",
			    dst, strerror(errno));
	}
	if (mode != tmpmode && chmod(dst, mode) == -1)
		error("local chmod directory \"%s\": %s",
		    dst, strerror(errno));

	sftp_free_dirents(dir_entries);
	return ret;
}

int
sftp_parallel_download_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag)
{
	if (p == NULL || conn == NULL || src == NULL || dst == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (print_flag && print_flag != SFTP_PROGRESS_ONLY)
		mprintf("Retrieving %s\n", src);
	return parallel_download_walk(p, conn, src, dst, 0, NULL);
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
	if (p->q) {
		out->queue_depth = sftp_workqueue_depth(p->q);
		out->queue_high_watermark = sftp_workqueue_high_watermark(p->q);
		/* queue capacity isn't directly queryable; derive from
		 * the formula used at construction. Slightly indirect but
		 * stable. */
		out->queue_capacity = WORK_QUEUE_DEPTH(p->cfg.num_streams);
	}
}

int
sftp_parallel_get_worker_stats(struct sftp_parallel *p,
    struct sftp_parallel_worker_stats *out, int max)
{
	if (p == NULL || out == NULL || max <= 0)
		return 0;
	int copied = 0;
	pthread_mutex_lock(&p->workers_mu);
	for (int i = 0; i < p->num_workers && copied < max; i++) {
		struct sftp_worker *w = p->workers[i];
		pthread_mutex_lock(&w->mu);
		out[copied].id                  = w->id;
		out[copied].health              = (int)w->health;
		out[copied].bytes_total         = w->bytes_total;
		out[copied].units_started       = w->units_started;
		out[copied].units_completed     = w->units_completed;
		out[copied].units_failed        = w->units_failed;
		out[copied].reconnect_count     = w->reconnect_count;
		out[copied].last_completion_ns  = w->last_completion_ns;
		pthread_mutex_unlock(&w->mu);
		copied++;
	}
	pthread_mutex_unlock(&p->workers_mu);
	return copied;
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
