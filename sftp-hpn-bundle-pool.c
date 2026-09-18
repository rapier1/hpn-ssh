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

/* sftp-hpn-bundle-pool.c - the bundle writer pool, shared by the server
 * upload extract and the client download extract. The parser callbacks
 * buffer each complete file and enqueue it, and the writer threads do
 * the open, write and close, so the per-file metadata round-trips (the
 * Lustre MDS) overlap. Parent directories are created on the producer
 * thread, so the writers only touch independent files. Design notes are
 * in the header. */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "sftp-hpn-bundle-pool.h"

/* One writer pool. The first group is fixed at construction. Everything
 * from mu down is shared with the writer threads and touched only with
 * mu held while any writer thread is alive. */
struct bundle_write_pool {
	pthread_t      *threads;
	int             n_threads;
	int             max_depth;	/* backpressure: queued-job count cap */
	uint64_t        max_bytes;	/* backpressure: buffered-byte budget */
	int             preserve;	/* apply each job's mode and mtime */
	int             do_fsync;	/* fsync each file before close */

	pthread_mutex_t mu;
	pthread_cond_t  not_empty;	/* a job was queued, or shutdown */
	pthread_cond_t  not_full;	/* a job left the queue or finished */
	struct bundle_write_job *head;	/* FIFO of queued jobs */
	struct bundle_write_job *tail;
	int             depth;		/* jobs queued */
	uint64_t        cur_bytes;	/* bytes held, queued and in write */
	uint64_t        peak_bytes;	/* high-water mark, logged at finish */
	int             shutdown;	/* no more jobs will be enqueued */
	int             error;		/* a writer failed, sticky */
};

/* Writer-thread count for the pool, the compile-time default from the
 * header, which is the knee measured in the pool benchmarks. The pool is
 * on or off via HPNWriterPool, the count is not tunable. */
int
bundle_writer_threads(void)
{
	return HPN_BUNDLE_WRITER_THREADS_DEFAULT;
}

/* Cap on queued jobs, the count backstop behind the byte budget. Four
 * per thread, at least 16. */
static int
bundle_writer_queue_depth(int n_threads)
{
	int n = n_threads * 4;

	if (n < 16)
		return 16;
	return n;
}

/* The pool's buffered-byte budget, the compile-time default from the
 * header. Bounds the pool's memory regardless of the file-size mix and
 * sets how many of the biggest eligible files can be in flight. Not
 * tunable. */
uint64_t
bundle_writer_budget(void)
{
	return HPN_BUNDLE_WRITER_BUDGET_DEFAULT;
}

/* Write one complete file: open, write, size, mode and mtime, fsync,
 * close. Mirrors the inline path in the server's entry callbacks, so
 * serial and pooled extracts produce the same files. Returns 0 on
 * success, -1 on error. */
static int
bundle_write_one(struct bundle_write_pool *pool, struct bundle_write_job *job)
{
	struct timespec ts[2];
	ssize_t written;
	size_t off = 0;
	mode_t perm;
	int fd, rc = 0;

	perm = 0644;
	if (pool->preserve)
		perm = job->mode;

	/* No O_TRUNC, the ftruncate below sets the size. See the comment in
	 * bundle_upload_entry_cb in sftp-hpn-bundle-server.c. */
	fd = open(job->full_path, O_WRONLY | O_CREAT, perm);
	if (fd < 0) {
		error_f("hpn-bundle: open \"%s\": %s",
		    job->full_path, strerror(errno));
		return -1;
	}
#ifdef HAVE_POSIX_FALLOCATE
	/* Preallocate the extents. Failure is harmless. */
	if (job->len > 0)
		(void)posix_fallocate(fd, 0, (off_t)job->len);
#endif
	/* Write the file. */
	while (off < job->len) {
		written = write(fd, job->data + off, job->len - off);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			error_f("hpn-bundle: write \"%s\": %s",
			    job->full_path, strerror(errno));
			rc = -1;
			break;
		}
		off += (size_t)written;
	}
	if (rc == 0 && ftruncate(fd, (off_t)job->len) != 0) {
		error_f("hpn-bundle: ftruncate \"%s\": %s",
		    job->full_path, strerror(errno));
		rc = -1;
	}
	if (rc == 0 && pool->preserve) {
		/* open's perm is subject to umask and ignored on an existing
		 * file, so force the bits here, after the ftruncate. */
		(void)fchmod(fd, job->mode);
		ts[0].tv_sec = job->mtime;
		ts[0].tv_nsec = 0;
		ts[1].tv_sec = job->mtime;
		ts[1].tv_nsec = 0;
		(void)futimens(fd, ts);
	}
	/* Sync the file if fsync enabled. */
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

/* Writer thread body. Takes jobs off the queue until shutdown drains
 * it. Each job is written, freed, and its bytes returned to the budget.
 * A failed write sets the sticky error and the thread keeps going, so
 * the queue still drains and finish can join. */
static void *
bundle_write_pool_thread(void *arg)
{
	struct bundle_write_pool *pool = arg;
	struct bundle_write_job *job;
	uint64_t job_len;
	int failed;

	for (;;) {
		pthread_mutex_lock(&pool->mu);
		while (pool->head == NULL && !pool->shutdown)
			pthread_cond_wait(&pool->not_empty, &pool->mu);
		if (pool->head == NULL) {
			/* Shutdown and the queue is drained. */
			pthread_mutex_unlock(&pool->mu);
			break;
		}
		job = pool->head;
		pool->head = job->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		pool->depth--;
		/* A producer blocked on the count cap can enqueue the next
		 * job while this one is being written. This signal means a
		 * queue slot is free. */
		pthread_cond_signal(&pool->not_full);
		pthread_mutex_unlock(&pool->mu);

		failed = bundle_write_one(pool, job) != 0;
		job_len = (uint64_t)job->len;
		free(job->full_path);
		free(job->data);
		free(job);

		pthread_mutex_lock(&pool->mu);
		if (failed)
			pool->error = 1;
		/* The buffer is gone, return its bytes to the budget and wake
		 * a producer blocked on it. This signal means bytes are free.
		 * Same condition variable as above, different trigger. */
		pool->cur_bytes -= job_len;
		pthread_cond_signal(&pool->not_full);
		pthread_mutex_unlock(&pool->mu);
	}
	return NULL;
}

/* Whether admitting a job of len bytes must wait. The cur_bytes > 0
 * guard admits a lone file larger than the whole budget when nothing
 * else is queued, otherwise it could never be admitted and the producer
 * would wait forever. Called with mu held. This only exists to simplify
 * the while loop in bundle_pool_enqueue. */
static int
bundle_pool_full(const struct bundle_write_pool *pool, size_t len)
{
	if (pool->depth >= pool->max_depth)
		return 1;
	if (pool->cur_bytes > 0 && pool->cur_bytes + len > pool->max_bytes)
		return 1;
	return 0;
}

/* Enqueue one complete file, taking ownership of the job. Blocks while
 * admitting it would exceed the byte budget or the queue is at the count
 * cap. Returns -1 once a writer has failed, and the job then stays with
 * the caller. */
int
bundle_pool_enqueue(struct bundle_write_pool *pool,
    struct bundle_write_job *job)
{
	pthread_mutex_lock(&pool->mu);
	/* Wait for the pool to open up. */
	while (bundle_pool_full(pool, job->len) && !pool->error)
		pthread_cond_wait(&pool->not_full, &pool->mu);
	if (pool->error) {
		pthread_mutex_unlock(&pool->mu);
		return -1;
	}

	/* Append the job at the tail of the queue. */
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

/* Create the pool and start its writer threads. On any failure whatever
 * started is joined, everything is freed and NULL is returned, and the
 * caller writes inline. */
struct bundle_write_pool *
bundle_write_pool_new(int n_threads, int preserve, int do_fsync,
    uint64_t budget)
{
	struct bundle_write_pool *pool;
	int i, rc;

	if ((pool = calloc(1, sizeof(*pool))) == NULL)
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
		rc = pthread_create(&pool->threads[i], NULL,
		    bundle_write_pool_thread, pool);
		if (rc != 0) {
			error_f("hpn-bundle: pthread_create: %s", strerror(rc));
			/* Shut down and join the threads that did start. */
			pthread_mutex_lock(&pool->mu);
			pool->shutdown = 1;
			pthread_cond_broadcast(&pool->not_empty);
			pthread_mutex_unlock(&pool->mu);
			while (--i >= 0)
				pthread_join(pool->threads[i], NULL);
			goto fail;
		}
	}
	return pool;
 fail:
	pthread_mutex_destroy(&pool->mu);
	pthread_cond_destroy(&pool->not_empty);
	pthread_cond_destroy(&pool->not_full);
	free(pool->threads);
	free(pool);
	return NULL;
}

/* Shut the pool down: mark it, wake and join every writer, log the peak
 * buffered bytes, destroy the synchronization objects and free it.
 * Returns nonzero if any writer failed. Safe on NULL. */
int
bundle_write_pool_finish(struct bundle_write_pool *pool)
{
	int i, err;

	if (pool == NULL)
		return 0;
	pthread_mutex_lock(&pool->mu);
	pool->shutdown = 1;
	pthread_cond_broadcast(&pool->not_empty);
	pthread_mutex_unlock(&pool->mu);
	/* Writers exit only once the queue is empty, so after the joins
	 * there are no jobs left to free. */
	for (i = 0; i < pool->n_threads; i++)
		pthread_join(pool->threads[i], NULL);
	err = pool->error;
	/* Peak buffered bytes at -vvv, for sizing the pool without
	 * instrumenting a live server. */
	debug3("hpn-bundle: writer pool threads=%d depth=%d peak_bytes=%llu",
	    pool->n_threads, pool->max_depth,
	    (unsigned long long)pool->peak_bytes);
	pthread_mutex_destroy(&pool->mu);
	pthread_cond_destroy(&pool->not_empty);
	pthread_cond_destroy(&pool->not_full);
	free(pool->threads);
	free(pool);
	return err;
}
