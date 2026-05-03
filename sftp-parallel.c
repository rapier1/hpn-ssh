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
 * Phase 1 failure-handling note (known limitation, to be addressed later):
 *
 * sftp-client.c's I/O helpers call fatal() on EOF or read errors. That code
 * was written assuming a single connection, where exiting on a broken pipe
 * is correct. In our multi-worker context it means *any* worker's connection
 * death takes down the entire orchestrator process. Phase 1 accepts this:
 * we add visibility (stall logging, master-liveness polling) but do not
 * recover from worker connection loss.
 *
 * Future work (Phase 2+): replace fatal() in sftp-client.c's I/O paths with
 * error returns, or move workers to fork() rather than pthread() for
 * automatic isolation. Both enable dynamically adding/removing workers and
 * resuming transfers after a worker dies. The watchdog hooks below
 * (last_completion_ns, kill(0) probes, sftp_cm_alive polling) are designed
 * with that future in mind — when we get true recovery, they tell us *which*
 * worker to replace.
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
#include "sftp-controlmaster.h"
#include "sftp-workqueue.h"
#include "sftp-parallel.h"

extern int showprogress;

#define WORK_QUEUE_DEPTH(N)     ((size_t)((N) * 4 + 8))
#define MAX_RETRIES             3
#define REPORTER_TICK_MS        200
#define DEFAULT_TRANSFER_BUFLEN 32768
#define DEFAULT_NUM_REQUESTS    1024

/* Watchdog thresholds. STALL: warn if a worker has had work available but
 * completed nothing for this long. DEAD: escalate to abort. Generous values
 * because legitimate single-file transfers can run for minutes. */
#define STALL_THRESHOLD_SEC     60
#define DEAD_THRESHOLD_SEC      300

enum worker_health {
	WORKER_HEALTHY = 0,
	WORKER_STALLED,
	WORKER_DEAD,
};

enum sftp_op {
	SFTP_OP_UPLOAD,
	SFTP_OP_DOWNLOAD,
	SFTP_OP_MKDIR,
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
	uint64_t           units_started;     /* dispatched, may be in flight */
	uint64_t           units_completed;
	uint64_t           units_failed;
	uint64_t           reconnect_count;
	uint64_t           last_completion_ns; /* monotonic ns of last finish */
	enum worker_health health;             /* set by reporter, read for log */

	int                started;
};

struct sftp_parallel {
	struct sftp_parallel_config cfg;
	struct sftp_controlmaster  *cm;
	struct sftp_workqueue      *q;
	struct sftp_worker         *workers;
	int                         num_workers;

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
	off_t                       aggregate_progress_counter; /* meter ctr */
	char                        progress_label[128];        /* stable storage
								   * for the meter
								   * label string */

	int                         started;
	int                         stopped;
};

/* ---------- Worker SSH connection setup ---------- */

static int
spawn_worker_ssh(const char *ssh_binary, const char *cm_socket,
    const char *host, int *fd_in_out, int *fd_out_out, pid_t *pid_out)
{
	int p2c[2] = { -1, -1 }, c2p[2] = { -1, -1 };

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
		execlp(ssh_binary, ssh_binary,
		    "-S", cm_socket, "-s", host, "sftp", (char *)NULL);
		_exit(127);
	}
	close(p2c[0]);
	close(c2p[1]);
	*fd_in_out = c2p[0];
	*fd_out_out = p2c[1];
	*pid_out = pid;
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
		    p->cfg.preserve_flag, /*print_flag=*/0,
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
	}
	return rc;
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
		struct sftp_work_unit *u = item;
		if (u == NULL)
			continue;

		worker_record_start(w);
		int rc = execute_unit(w, u);
		if (rc == 0) {
			worker_record_completion(w, u->size, 1);
			free_unit(u);
			pending_dec(p);
		} else if (++u->attempt < MAX_RETRIES) {
			/* Re-queue without freeing. Keeps pending counter
			 * consistent — we don't decrement here. */
			if (sftp_workqueue_push(p->q, u) != 0) {
				/* Queue shutdown — drop unit. */
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
	return NULL;
}

/* ---------- Reporter thread ---------- */

static void
snapshot_workers(struct sftp_parallel *p, uint64_t *bytes_out,
    uint64_t *completed_out, uint64_t *failed_out)
{
	uint64_t b = 0, c = 0, f = 0;
	for (int i = 0; i < p->num_workers; i++) {
		pthread_mutex_lock(&p->workers[i].mu);
		b += p->workers[i].bytes_total;
		c += p->workers[i].units_completed;
		f += p->workers[i].units_failed;
		pthread_mutex_unlock(&p->workers[i].mu);
	}
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

	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = &p->workers[i];
		enum worker_health prev, next;

		pthread_mutex_lock(&w->mu);
		prev = w->health;
		uint64_t since_completion_ns = w->last_completion_ns ?
		    (now - w->last_completion_ns) : 0;
		uint64_t in_flight = w->units_started - w->units_completed -
		    w->units_failed;
		pthread_mutex_unlock(&w->mu);

		next = WORKER_HEALTHY;

		/* (3a-supporting) ssh child gone is the strongest signal.
		 * In the current Phase-1 fatal-on-error design, the worker
		 * thread's read() will have already triggered fatal() before
		 * we get here — but probing kill(pid, 0) is cheap and gives
		 * us correct telemetry for the future fork-or-error-return
		 * recovery code. */
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
		if (next == WORKER_DEAD)
			any_dead = 1;
	}
	return any_dead;
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
		p->aggregate_progress_counter = (off_t)bytes;
		if (p->progress_meter_started)
			refresh_progress_meter(0);

		/* Liveness checks on a slower cadence (every 5 ticks ≈ 1s):
		 * cheaper and watchdog timing doesn't need 200ms granularity. */
		if (++slow_tick_counter >= 5) {
			slow_tick_counter = 0;
			if (!sftp_cm_alive(p->cm)) {
				error_f("ControlMaster died — aborting "
				    "parallel transfer");
				sftp_parallel_abort(p);
				break;
			}
			if (watchdog_check_workers(p)) {
				/* Phase 1: any DEAD worker → abort the
				 * whole orchestrator. Phase 2 will replace
				 * the failed worker instead. */
				error_f("worker died — aborting parallel "
				    "transfer (Phase 1 limitation)");
				sftp_parallel_abort(p);
				break;
			}
		}
	}
	return NULL;
}

/* ---------- Public API ---------- */

struct sftp_parallel *
sftp_parallel_start(const struct sftp_parallel_config *cfg)
{
	if (cfg == NULL || cfg->host == NULL || cfg->num_streams < 1) {
		errno = EINVAL;
		return NULL;
	}

	struct sftp_parallel *p = xcalloc(1, sizeof(*p));
	p->cfg = *cfg;
	p->num_workers = cfg->num_streams;
	pthread_mutex_init(&p->pending_mu, NULL);
	pthread_cond_init(&p->pending_cv, NULL);

	/* 1. ControlMaster */
	struct sftp_cm_config cmcfg = {
		.host        = cfg->host,
		.port        = cfg->port,
		.ssh_binary  = cfg->ssh_binary,
		.identity    = cfg->identity,
		.known_hosts = cfg->known_hosts,
		.config_file = cfg->config_file,
		.verbose     = cfg->verbose,
		.timeout_sec = cfg->cm_timeout_sec,
		.extra_argv  = cfg->extra_argv,
	};
	if ((p->cm = sftp_cm_start(&cmcfg)) == NULL) {
		error_f("ControlMaster setup failed");
		goto fail;
	}

	/* 2. Workqueue */
	p->q = sftp_workqueue_new(WORK_QUEUE_DEPTH(p->num_workers));
	if (p->q == NULL) {
		error_f("workqueue allocation failed");
		goto fail;
	}

	/* 3. Workers — each gets its own SSH child via the master's socket */
	p->workers = xcalloc(p->num_workers, sizeof(*p->workers));
	const char *ssh_bin = cfg->ssh_binary ? cfg->ssh_binary : "hpnssh";
	const char *cm_sock = sftp_cm_socket(p->cm);
	unsigned int buflen = cfg->transfer_buflen ?
	    cfg->transfer_buflen : DEFAULT_TRANSFER_BUFLEN;
	unsigned int nreq = cfg->num_requests ?
	    cfg->num_requests : DEFAULT_NUM_REQUESTS;

	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = &p->workers[i];
		w->id = i;
		w->parent = p;
		w->fd_in = w->fd_out = -1;
		w->ssh_pid = -1;
		pthread_mutex_init(&w->mu, NULL);
		if (spawn_worker_ssh(ssh_bin, cm_sock, cfg->host,
		    &w->fd_in, &w->fd_out, &w->ssh_pid) != 0) {
			error_f("worker %d: ssh spawn failed", i);
			goto fail;
		}
		w->conn = sftp_init(w->fd_in, w->fd_out, buflen, nreq,
		    cfg->limit_kbps);
		if (w->conn == NULL) {
			error_f("worker %d: sftp_init failed", i);
			goto fail;
		}
	}

	/* 4. Suppress per-file progress in workers; orchestrate aggregate
	 * progress here when requested. */
	p->saved_showprogress = showprogress;
	showprogress = 0;
	if (cfg->print_flag != SFTP_QUIET) {
		/* For now, leave aggregate progress meter as a step-6
		 * concern. Reporter still ticks for telemetry but does not
		 * call refresh_progress_meter unless we set it up. */
	}

	/* 5. Worker threads */
	for (int i = 0; i < p->num_workers; i++) {
		struct sftp_worker *w = &p->workers[i];
		if (pthread_create(&w->tid, NULL, worker_thread, w) != 0) {
			error_f("worker %d: pthread_create failed", i);
			goto fail;
		}
		w->started = 1;
	}

	/* 6. Reporter */
	if (pthread_create(&p->reporter_tid, NULL, reporter_thread, p) == 0)
		p->reporter_started = 1;
	/* Reporter is best-effort; failing to start it isn't fatal. */

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
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = &p->workers[i];
			if (w->started)
				pthread_join(w->tid, NULL);
		}
	}
	if (p->reporter_started)
		pthread_join(p->reporter_tid, NULL);

	if (p->workers) {
		for (int i = 0; i < p->num_workers; i++) {
			struct sftp_worker *w = &p->workers[i];
			if (w->conn) {
				sftp_free(w->conn);
				w->conn = NULL;
			}
			teardown_worker_ssh(w);
			pthread_mutex_destroy(&w->mu);
		}
		free(p->workers);
		p->workers = NULL;
	}

	if (p->cm) {
		sftp_cm_stop(p->cm);
		p->cm = NULL;
	}
	if (p->q) {
		sftp_workqueue_free(p->q);
		p->q = NULL;
	}

	/* Restore the user's progress preference. */
	showprogress = p->saved_showprogress;

	pthread_mutex_destroy(&p->pending_mu);
	pthread_cond_destroy(&p->pending_cv);
	free(p);
}

void
sftp_parallel_progress_start(struct sftp_parallel *p, const char *label)
{
	if (p == NULL || p->progress_meter_started)
		return;
	if (label == NULL)
		label = "transfer";
	strlcpy(p->progress_label, label, sizeof(p->progress_label));
	p->aggregate_progress_counter = 0;
	/* total=0 -> indeterminate progress (rate without ETA). The
	 * aggregate total isn't known until the producer finishes
	 * submitting, which may be concurrent with transfer. Phase 2 may
	 * compute a running total during submission and pass it here. */
	start_progress_meter(p->progress_label, 0,
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
