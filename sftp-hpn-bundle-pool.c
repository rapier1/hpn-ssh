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
 * sftp-hpn-bundle-pool.c - HPN-SSH bundle writer pool (see the header for the
 * design overview).  Used by both the server-side upload extract and the
 * client-side download extract; the producer (parser callbacks) buffers each
 * complete file and enqueues it, and these writer threads do the open/write/
 * close so the per-file MDS round-trips overlap.  Parent dirs are pre-created
 * serially on the producer thread, so the writers only touch independent files.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "log.h"		/* error_f */
#include "defines.h"		/* HPN_BUNDLE_SIZE_* */
#include "sftp-hpn-bundle-pool.h"

struct bundle_write_pool {
	pthread_t      *threads;
	int             n_threads;
	int             max_depth;	/* backpressure: queued-job count cap */
	uint64_t        max_bytes;	/* backpressure: buffered-byte budget */
	pthread_mutex_t mu;
	pthread_cond_t  not_empty;
	pthread_cond_t  not_full;
	struct bundle_write_job *head, *tail;
	int             depth;
	int             shutdown;	/* no more jobs will be enqueued */
	int             error;		/* a writer thread hit an error */
	int             preserve;
	int             do_fsync;
	uint64_t        cur_bytes;	/* held buffer bytes (queued + in-write) */
	uint64_t        peak_bytes;	/* high-water of cur_bytes (dev metric) */
};

/* Writer-thread count for the bundle extract pool - the fixed compile-time
 * HPN_BUNDLE_WRITER_THREADS_DEFAULT (the measured knee).  The pool is on/off
 * only (HPNWriterPool); the count is not user-tunable. */
int
bundle_writer_threads(void)
{
	return HPN_BUNDLE_WRITER_THREADS_DEFAULT;
}

/* Backpressure cap on queued jobs (the count backstop; the byte budget is the
 * primary bound).  Derived as max(threads*4, 16); not user-tunable. */
static int
bundle_writer_queue_depth(int n_threads)
{
	int n = n_threads * 4;
	return n < 16 ? 16 : n;
}

/* The pool's buffered-byte budget (backpressure) - the fixed compile-time
 * HPN_BUNDLE_WRITER_BUDGET_DEFAULT (16 MiB).  Bounds the pool's RAM regardless
 * of the file-size mix, and sets how many of the biggest eligible files fit in
 * flight.  Not user-tunable; the pool is on/off only via HPNWriterPool. */
uint64_t
bundle_writer_budget(void)
{
	return HPN_BUNDLE_WRITER_BUDGET_DEFAULT;
}

/* Write one complete file (open/write/perms/truncate/fsync/close).  Mirrors the
 * serial entry_cb+data_cb+entry_end_cb path exactly, so serial and pooled
 * extract produce identical results.  Returns 0 on success, -1 on error. */
static int
bundle_write_one(struct bundle_write_pool *pool, struct bundle_write_job *job)
{
	int    fd, rc = 0;
	mode_t perm = pool->preserve ? (job->mode & 07777) : 0644;
	size_t off  = 0;

	/* open WITHOUT O_TRUNC; ftruncate below sets the authoritative size
	 * (the bundle-truncation fix, same as the serial path). */
	fd = open(job->full_path, O_WRONLY | O_CREAT, perm);
	if (fd < 0) {
		error_f("hpn-bundle: open \"%s\": %s",
		    job->full_path, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	if (job->len > 0)
		(void)posix_fallocate(fd, 0, (off_t)job->len);
#endif
	while (off < job->len) {
		ssize_t n = write(fd, job->data + off, job->len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			error_f("hpn-bundle: write \"%s\": %s",
			    job->full_path, strerror(errno));
			rc = -1;
			break;
		}
		off += (size_t)n;
	}
	if (rc == 0 && pool->preserve) {
		struct timespec ts[2];
		(void)fchmod(fd, (mode_t)(job->mode & 07777));
		ts[0].tv_sec = job->mtime; ts[0].tv_nsec = 0;
		ts[1].tv_sec = job->mtime; ts[1].tv_nsec = 0;
		(void)futimens(fd, ts);
	}
	if (rc == 0 && ftruncate(fd, (off_t)job->len) != 0) {
		error_f("hpn-bundle: ftruncate \"%s\": %s",
		    job->full_path, strerror(errno));
		rc = -1;
	}
	if (rc == 0 && pool->do_fsync && fsync(fd) != 0) {
		error_f("hpn-bundle: fsync \"%s\": %s",
		    job->full_path, strerror(errno));
		rc = -1;
	}
	if (close(fd) != 0) {
		error_f("hpn-bundle: close \"%s\": %s",
		    job->full_path, strerror(errno));
		rc = -1;
	}
	return rc;
}

static void *
bundle_write_pool_thread(void *arg)
{
	struct bundle_write_pool *pool = arg;

	for (;;) {
		struct bundle_write_job *job;
		uint64_t                 jlen;

		pthread_mutex_lock(&pool->mu);
		while (pool->head == NULL && !pool->shutdown)
			pthread_cond_wait(&pool->not_empty, &pool->mu);
		if (pool->head == NULL) {	/* shutdown and drained */
			pthread_mutex_unlock(&pool->mu);
			break;
		}
		job = pool->head;
		pool->head = job->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		pool->depth--;
		pthread_cond_signal(&pool->not_full);
		pthread_mutex_unlock(&pool->mu);

		jlen = (uint64_t)job->len;
		if (bundle_write_one(pool, job) != 0) {
			pthread_mutex_lock(&pool->mu);
			pool->error = 1;
			pthread_mutex_unlock(&pool->mu);
		}
		free(job->full_path);
		free(job->data);
		free(job);
		pthread_mutex_lock(&pool->mu);
		pool->cur_bytes -= jlen;	/* buffer released */
		pthread_cond_signal(&pool->not_full); /* wake byte-blocked producer */
		pthread_mutex_unlock(&pool->mu);
	}
	return NULL;
}

/* Enqueue a job, blocking while the queue is at the depth cap (backpressure).
 * Returns -1 if a writer thread has already failed (caller drops the job). */
int
bundle_pool_enqueue(struct bundle_write_pool *pool, struct bundle_write_job *job)
{
	pthread_mutex_lock(&pool->mu);
	/* Backpressure: block while admitting this file would exceed the byte
	 * budget (the cur_bytes > 0 guard admits a lone file bigger than the
	 * whole budget so it can't deadlock), OR the count backstop is hit. */
	while (((pool->cur_bytes > 0 &&
	    pool->cur_bytes + (uint64_t)job->len > pool->max_bytes) ||
	    pool->depth >= pool->max_depth) && !pool->error)
		pthread_cond_wait(&pool->not_full, &pool->mu);
	if (pool->error) {
		pthread_mutex_unlock(&pool->mu);
		return -1;
	}
	job->next = NULL;
	if (pool->tail != NULL)
		pool->tail->next = job;
	else
		pool->head = job;
	pool->tail = job;
	pool->depth++;
	pool->cur_bytes += (uint64_t)job->len;
	if (pool->cur_bytes > pool->peak_bytes)
		pool->peak_bytes = pool->cur_bytes;
	pthread_cond_signal(&pool->not_empty);
	pthread_mutex_unlock(&pool->mu);
	return 0;
}

struct bundle_write_pool *
bundle_write_pool_new(int n_threads, int preserve, int do_fsync,
    uint64_t budget)
{
	struct bundle_write_pool *pool;
	int i;

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL)
		return NULL;
	pool->n_threads = n_threads;
	pool->max_depth = bundle_writer_queue_depth(n_threads);
	pool->max_bytes = budget;
	pool->preserve  = preserve;
	pool->do_fsync  = do_fsync;
	pthread_mutex_init(&pool->mu, NULL);
	pthread_cond_init(&pool->not_empty, NULL);
	pthread_cond_init(&pool->not_full, NULL);
	pool->threads = calloc((size_t)n_threads, sizeof(pthread_t));
	if (pool->threads == NULL)
		goto fail;
	for (i = 0; i < n_threads; i++) {
		if (pthread_create(&pool->threads[i], NULL,
		    bundle_write_pool_thread, pool) != 0) {
			/* Join whatever started, then fail -> serial fallback. */
			pthread_mutex_lock(&pool->mu);
			pool->shutdown = 1;
			pthread_cond_broadcast(&pool->not_empty);
			pthread_mutex_unlock(&pool->mu);
			while (--i >= 0)
				pthread_join(pool->threads[i], NULL);
			free(pool->threads);
			goto fail;
		}
	}
	return pool;
 fail:
	pthread_mutex_destroy(&pool->mu);
	pthread_cond_destroy(&pool->not_empty);
	pthread_cond_destroy(&pool->not_full);
	free(pool);
	return NULL;
}

/* Log the pool's final geometry + peak buffered memory at -vvv, for tuning
 * writer-pool sizing without instrumenting a live server. */
static void
bundle_pool_emit_stats(const struct bundle_write_pool *pool)
{
	debug3("hpn-bundle writer pool: threads=%d depth=%d peak_bytes=%llu",
	    pool->n_threads, pool->max_depth,
	    (unsigned long long)pool->peak_bytes);
}

/* Shut down, join all threads, free any leftover jobs, then destroy + free the
 * pool.  Returns the error flag (nonzero = some file failed). */
int
bundle_write_pool_finish(struct bundle_write_pool *pool)
{
	struct bundle_write_job *job, *next;
	int i, err;

	if (pool == NULL)
		return 0;
	pthread_mutex_lock(&pool->mu);
	pool->shutdown = 1;
	pthread_cond_broadcast(&pool->not_empty);
	pthread_mutex_unlock(&pool->mu);
	for (i = 0; i < pool->n_threads; i++)
		pthread_join(pool->threads[i], NULL);
	for (job = pool->head; job != NULL; job = next) {	/* defensive */
		next = job->next;
		free(job->full_path);
		free(job->data);
		free(job);
	}
	err = pool->error;
	bundle_pool_emit_stats(pool);
	pthread_mutex_destroy(&pool->mu);
	pthread_cond_destroy(&pool->not_empty);
	pthread_cond_destroy(&pool->not_full);
	free(pool->threads);
	free(pool);
	return err;
}
