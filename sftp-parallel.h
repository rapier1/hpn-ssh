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
 * Parallel-streams orchestrator for the sftp client.
 *
 * Topology (Pattern B): one ControlMaster amortizes auth, then N independent
 * worker SSH connections each open their own SFTP subsystem. A producer
 * thread (typically the caller) submits work units; N worker threads pop
 * units and execute them via the standard sftp_upload / sftp_download /
 * sftp_mkdir APIs. Each worker owns its own struct sftp_conn — no shared
 * cipher state, no shared TCP socket. A reporter thread aggregates per-worker
 * progress counters and drives a single global progress meter.
 *
 * Step 5 (architecture). The CLI wiring (-P N) lands in step 6.
 */

#ifndef _SFTP_PARALLEL_H
#define _SFTP_PARALLEL_H

#include <sys/types.h>
#include <stdint.h>

#include "sftp.h"		/* SFTP_QUIET / SFTP_PROGRESS_ONLY */

struct sftp_parallel;
struct sftp_conn;	/* opaque; defined in sftp-client.c */

struct sftp_parallel_config {
	int          num_streams;       /* N — must be >= 1 */

	/* ControlMaster passthrough */
	const char  *host;              /* required */
	const char  *port;
	const char  *ssh_binary;        /* /path/to/hpnssh / NULL = "hpnssh" */
	const char  *identity;
	const char  *known_hosts;
	const char  *config_file;
	int          verbose;
	int          cm_timeout_sec;    /* 0 = default */
	char *const *extra_argv;        /* additional -o KEY=VALUE; may be NULL */

	/* Per-worker sftp_init parameters */
	unsigned int transfer_buflen;   /* 0 = default */
	unsigned int num_requests;      /* 0 = default */
	uint64_t     limit_kbps;        /* 0 = no bandwidth limit */

	/* Transfer flags applied to every submitted unit */
	int          preserve_flag;
	int          resume_flag;
	int          fsync_flag;
	int          inplace_flag;
	int          follow_link_flag;

	/* Reporting: SFTP_QUIET / SFTP_PROGRESS_ONLY / SFTP_PRINT */
	int          print_flag;
};

/*
 * Initialise the orchestrator: spawn ControlMaster, spawn N worker SSH
 * connections, start the worker and reporter threads. Returns NULL on
 * failure (caller should warn and fall back to single-stream mode).
 */
struct sftp_parallel *sftp_parallel_start(const struct sftp_parallel_config *cfg);

/*
 * Submit a work unit. These calls copy the path strings; the caller retains
 * ownership of its own buffers. Returns 0 on success, -1 if the orchestrator
 * is in shutdown / abort state.
 */
int sftp_parallel_submit_upload(struct sftp_parallel *p,
    const char *local_path, const char *remote_path, off_t size, mode_t mode);
int sftp_parallel_submit_download(struct sftp_parallel *p,
    const char *remote_path, const char *local_path, off_t size, mode_t mode);
int sftp_parallel_submit_mkdir(struct sftp_parallel *p,
    const char *remote_path, mode_t mode);

/*
 * Recursive walkers (Approach B): traverse the source tree on the control
 * connection (`conn`), creating destination directories synchronously along
 * the way, and submitting regular files to the orchestrator's worker pool.
 * The walker returns once the tree has been fully visited and all files
 * submitted; the caller is responsible for sftp_parallel_wait().
 *
 * preserve_flag and follow_link_flag are taken from the orchestrator's
 * stored config.
 */
int sftp_parallel_upload_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag);

int sftp_parallel_download_dir(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *src, const char *dst, int print_flag);

/*
 * Block until all submitted units have been completed (or failed past
 * retry limits). After this returns, no in-flight work remains. May be
 * called multiple times; subsequent submits are valid until stop().
 */
void sftp_parallel_wait(struct sftp_parallel *p);

/*
 * Asynchronous abort. Sets a flag that workers check between units; in-flight
 * units are allowed to finish. Safe to call from a signal handler.
 */
void sftp_parallel_abort(struct sftp_parallel *p);

/*
 * Drive a single global progress_meter for the duration of an aggregate
 * batch (e.g. a put/get command's worth of submissions). Call _start
 * before submitting; the orchestrator's reporter thread will update the
 * meter's counter from snapshotted worker bytes_total. Call _stop after
 * sftp_parallel_wait returns.
 *
 * Calling _start while a meter is already active is a no-op. Calling
 * _stop without a started meter is a no-op. label is copied internally.
 */
void sftp_parallel_progress_start(struct sftp_parallel *p, const char *label);
void sftp_parallel_progress_stop(struct sftp_parallel *p);

/*
 * Tear down: signal workers to exit, join all threads, close worker SSH
 * subprocesses, stop the ControlMaster, free everything. Idempotent.
 */
void sftp_parallel_stop(struct sftp_parallel *p);

/* Observability — safe to call any time after start(). */
uint64_t sftp_parallel_bytes_total(struct sftp_parallel *p);
uint64_t sftp_parallel_units_completed(struct sftp_parallel *p);
uint64_t sftp_parallel_units_failed(struct sftp_parallel *p);

#endif /* _SFTP_PARALLEL_H */
