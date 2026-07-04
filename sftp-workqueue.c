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

#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "sftp-workqueue.h"

struct sftp_workqueue {
	void           **ring;        /* circular buffer of capacity slots */
	size_t           capacity;
	size_t           head;        /* next slot to pop */
	size_t           tail;        /* next slot to push */
	size_t           count;       /* items in queue */
	size_t           high_water;  /* peak count */
	int              shutdown;    /* nonzero once shutdown signaled */
	pthread_mutex_t  mu;
	pthread_cond_t   not_empty;
	pthread_cond_t   not_full;
	/* Activity kick channel (sftp_workqueue_kick/wait_activity): wakes
	 * workers whose only available work is externally gated (writer-cap
	 * slots) without the queue ever going empty.  kick_seq orders kicks
	 * so a waiter never sleeps through one that fired just before it
	 * parked. */
	pthread_cond_t   kick_cv;
	uint64_t         kick_seq;
};

struct sftp_workqueue *
sftp_workqueue_new(size_t capacity)
{
	struct sftp_workqueue *q;

	if (capacity == 0)
		return NULL;
	if ((q = calloc(1, sizeof(*q))) == NULL)
		return NULL;
	if ((q->ring = calloc(capacity, sizeof(void *))) == NULL) {
		free(q);
		return NULL;
	}
	q->capacity = capacity;
	if (pthread_mutex_init(&q->mu, NULL) != 0)
		goto fail_ring;
	if (pthread_cond_init(&q->not_empty, NULL) != 0)
		goto fail_mu;
	if (pthread_cond_init(&q->not_full, NULL) != 0)
		goto fail_ne;
	if (pthread_cond_init(&q->kick_cv, NULL) != 0) {
		pthread_cond_destroy(&q->not_full);
		goto fail_ne;
	}
	return q;

 fail_ne:
	pthread_cond_destroy(&q->not_empty);
 fail_mu:
	pthread_mutex_destroy(&q->mu);
 fail_ring:
	free(q->ring);
	free(q);
	return NULL;
}

void
sftp_workqueue_free(struct sftp_workqueue *q)
{
	if (q == NULL)
		return;
	pthread_cond_destroy(&q->kick_cv);
	pthread_cond_destroy(&q->not_full);
	pthread_cond_destroy(&q->not_empty);
	pthread_mutex_destroy(&q->mu);
	free(q->ring);
	free(q);
}

int
sftp_workqueue_push(struct sftp_workqueue *q, void *item)
{
	pthread_mutex_lock(&q->mu);
	while (q->count == q->capacity && !q->shutdown)
		pthread_cond_wait(&q->not_full, &q->mu);
	if (q->shutdown) {
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	q->ring[q->tail] = item;
	q->tail = (q->tail + 1) % q->capacity;
	q->count++;
	if (q->count > q->high_water)
		q->high_water = q->count;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mu);
	return 0;
}

/*
 * Non-blocking push (tail).  0 = queued, 1 = full (item NOT queued), -1 =
 * shutdown.  Used on the worker re-queue path so a worker never blocks on a
 * full queue it is itself the consumer of (self-deadlock; fatal at -j1).
 */
int
sftp_workqueue_trypush(struct sftp_workqueue *q, void *item)
{
	pthread_mutex_lock(&q->mu);
	if (q->shutdown) {
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	if (q->count == q->capacity) {
		pthread_mutex_unlock(&q->mu);
		return 1;
	}
	q->ring[q->tail] = item;
	q->tail = (q->tail + 1) % q->capacity;
	q->count++;
	if (q->count > q->high_water)
		q->high_water = q->count;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mu);
	return 0;
}

/* Non-blocking push_front (head).  Same return contract as trypush. */
int
sftp_workqueue_trypush_front(struct sftp_workqueue *q, void *item)
{
	pthread_mutex_lock(&q->mu);
	if (q->shutdown) {
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	if (q->count == q->capacity) {
		pthread_mutex_unlock(&q->mu);
		return 1;
	}
	q->head = (q->head + q->capacity - 1) % q->capacity;
	q->ring[q->head] = item;
	q->count++;
	if (q->count > q->high_water)
		q->high_water = q->count;
	pthread_cond_signal(&q->not_empty);
	pthread_mutex_unlock(&q->mu);
	return 0;
}

int
sftp_workqueue_pop(struct sftp_workqueue *q, void **itemp)
{
	pthread_mutex_lock(&q->mu);
	while (q->count == 0 && !q->shutdown)
		pthread_cond_wait(&q->not_empty, &q->mu);
	if (q->count == 0) {
		/* shutdown && empty */
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	*itemp = q->ring[q->head];
	q->ring[q->head] = NULL;
	q->head = (q->head + 1) % q->capacity;
	q->count--;
	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->mu);
	return 0;
}

int
sftp_workqueue_trypop(struct sftp_workqueue *q, void **itemp)
{
	pthread_mutex_lock(&q->mu);
	if (q->count == 0 || q->shutdown) {
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	*itemp = q->ring[q->head];
	q->ring[q->head] = NULL;
	q->head = (q->head + 1) % q->capacity;
	q->count--;
	pthread_cond_signal(&q->not_full);
	pthread_mutex_unlock(&q->mu);
	return 0;
}

/*
 * Like trypop but works on a SHUT-DOWN queue: pops while items remain,
 * -1 only when empty.  For the owner's final drain - after an abort the
 * undispatched items are still in the ring (trypop refuses them once
 * shutdown is set) and would otherwise leak with their payloads.
 */
int
sftp_workqueue_drain(struct sftp_workqueue *q, void **itemp)
{
	pthread_mutex_lock(&q->mu);
	if (q->count == 0) {
		pthread_mutex_unlock(&q->mu);
		return -1;
	}
	*itemp = q->ring[q->head];
	q->ring[q->head] = NULL;
	q->head = (q->head + 1) % q->capacity;
	q->count--;
	pthread_mutex_unlock(&q->mu);
	return 0;
}

void
sftp_workqueue_shutdown(struct sftp_workqueue *q)
{
	pthread_mutex_lock(&q->mu);
	q->shutdown = 1;
	pthread_cond_broadcast(&q->not_empty);
	pthread_cond_broadcast(&q->not_full);
	q->kick_seq++;
	pthread_cond_broadcast(&q->kick_cv);
	pthread_mutex_unlock(&q->mu);
}

void
sftp_workqueue_kick(struct sftp_workqueue *q)
{
	pthread_mutex_lock(&q->mu);
	q->kick_seq++;
	pthread_cond_broadcast(&q->kick_cv);
	pthread_mutex_unlock(&q->mu);
}

void
sftp_workqueue_wait_activity(struct sftp_workqueue *q, int timeout_ms)
{
	struct timespec deadline;
	uint64_t seen;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec  += timeout_ms / 1000;
	deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}
	pthread_mutex_lock(&q->mu);
	seen = q->kick_seq;
	while (q->kick_seq == seen && !q->shutdown) {
		if (pthread_cond_timedwait(&q->kick_cv, &q->mu,
		    &deadline) == ETIMEDOUT)
			break;
	}
	pthread_mutex_unlock(&q->mu);
}

size_t
sftp_workqueue_depth(struct sftp_workqueue *q)
{
	size_t n;
	pthread_mutex_lock(&q->mu);
	n = q->count;
	pthread_mutex_unlock(&q->mu);
	return n;
}

size_t
sftp_workqueue_high_watermark(struct sftp_workqueue *q)
{
	size_t n;
	pthread_mutex_lock(&q->mu);
	n = q->high_water;
	pthread_mutex_unlock(&q->mu);
	return n;
}
