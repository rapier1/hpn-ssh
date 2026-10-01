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

/* sftp-hpn-workqueue.c - a fixed ring of item pointers under one mutex,
 * with a "not empty" condition for poppers and a "not full" condition for
 * blocking pushers. A separate kick channel wakes workers whose next work
 * is gated outside the queue, so they do not have to wait for a push.
 * What the queue is for is in sftp-hpn-workqueue.h. */

#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>

#include "sftp-hpn-workqueue.h"

/* The queue: a ring of item pointers and the locking around it. The
 * kick channel at the end is separate from the ring's own conditions. */
struct sftp_hpn_workqueue {
	void           **ring;        /* circular buffer of capacity slots */
	int              capacity;
	int              head;        /* next slot to pop */
	int              tail;        /* next slot to push */
	int              count;       /* items in queue */
	int              shutdown;    /* nonzero once shutdown signaled */
	pthread_mutex_t  mu;
	pthread_cond_t   not_empty;
	pthread_cond_t   not_full;
	/* Activity kick channel (sftp_hpn_workqueue_kick and wait_activity).
	 * It wakes workers whose only available work is gated outside the
	 * queue, by writer-cap slots, when the queue never goes empty.
	 * kick_seq lets a waiter tell whether a kick fired after it took its
	 * sequence number. */
	pthread_cond_t   kick_cv;
	uint64_t         kick_seq;
};

/* Create an empty queue holding up to capacity items. Returns NULL if
 * capacity is not positive or anything fails to allocate. */
struct sftp_hpn_workqueue *
sftp_hpn_workqueue_new(int capacity)
{
	struct sftp_hpn_workqueue *queue;

	if (capacity <= 0)
		return NULL;
	if ((queue = calloc(1, sizeof(*queue))) == NULL)
		return NULL;
	if ((queue->ring = calloc(capacity, sizeof(void *))) == NULL) {
		free(queue);
		return NULL;
	}
	queue->capacity = capacity;
	if (pthread_mutex_init(&queue->mu, NULL) != 0)
		goto fail_ring;
	if (pthread_cond_init(&queue->not_empty, NULL) != 0)
		goto fail_mu;
	if (pthread_cond_init(&queue->not_full, NULL) != 0)
		goto fail_ne;
	if (pthread_cond_init(&queue->kick_cv, NULL) != 0)
		goto fail_nf;
	return queue;

 fail_nf:
	pthread_cond_destroy(&queue->not_full);
 fail_ne:
	pthread_cond_destroy(&queue->not_empty);
 fail_mu:
	pthread_mutex_destroy(&queue->mu);
 fail_ring:
	free(queue->ring);
	free(queue);
	return NULL;
}

/* Free the queue. Items still in it are not freed, since the caller owns
 * them, and no thread may still be waiting on it. Safe on NULL. */
void
sftp_hpn_workqueue_free(struct sftp_hpn_workqueue *queue)
{
	if (queue == NULL)
		return;
	pthread_cond_destroy(&queue->kick_cv);
	pthread_cond_destroy(&queue->not_full);
	pthread_cond_destroy(&queue->not_empty);
	pthread_mutex_destroy(&queue->mu);
	free(queue->ring);
	free(queue);
}

/* Store an item at the tail, or at the head so it is popped next. The
 * mutex is held and the queue is not full. */
static void
queue_put(struct sftp_hpn_workqueue *queue, void *item, int at_head)
{
	if (at_head) {
		queue->head = (queue->head + queue->capacity - 1) %
		    queue->capacity;
		queue->ring[queue->head] = item;
	} else {
		queue->ring[queue->tail] = item;
		queue->tail = (queue->tail + 1) % queue->capacity;
	}
	queue->count++;
	pthread_cond_signal(&queue->not_empty);
}

/* Take the head item. The mutex is held and the queue is not empty. */
static void *
queue_take(struct sftp_hpn_workqueue *queue)
{
	void *item = queue->ring[queue->head];

	queue->ring[queue->head] = NULL;
	queue->head = (queue->head + 1) % queue->capacity;
	queue->count--;
	pthread_cond_signal(&queue->not_full);
	return item;
}

/* The non-blocking pushes, at the tail or the head. */
static int
queue_trypush(struct sftp_hpn_workqueue *queue, void *item, int at_head)
{
	int rc = 0;

	pthread_mutex_lock(&queue->mu);
	if (queue->shutdown)
		rc = -1;
	else if (queue->count == queue->capacity)
		rc = 1;
	else
		queue_put(queue, item, at_head);
	pthread_mutex_unlock(&queue->mu);
	return rc;
}

/* Wake every wait_activity() caller. The mutex is held. */
static void
queue_kick(struct sftp_hpn_workqueue *queue)
{
	queue->kick_seq++;
	pthread_cond_broadcast(&queue->kick_cv);
}

/* Store an item at the tail, waiting while the queue is full. Returns 0
 * once it is queued, or -1 if the queue is shut down before there is
 * room. */
int
sftp_hpn_workqueue_push(struct sftp_hpn_workqueue *queue, void *item)
{
	pthread_mutex_lock(&queue->mu);
	while (queue->count == queue->capacity && !queue->shutdown)
		pthread_cond_wait(&queue->not_full, &queue->mu);
	if (queue->shutdown) {
		pthread_mutex_unlock(&queue->mu);
		return -1;
	}
	queue_put(queue, item, 0);
	pthread_mutex_unlock(&queue->mu);
	return 0;
}

/* Push at the tail without waiting. Returns 0 if queued, 1 if the queue is
 * full and the item was not queued, or -1 if it is shut down. Workers
 * re-queue through this so they never block on a full queue they also
 * consume from, which would deadlock, fatally at -j1. */
int
sftp_hpn_workqueue_trypush(struct sftp_hpn_workqueue *queue, void *item)
{
	return queue_trypush(queue, item, 0);
}

/* Push at the head without waiting, so the item is popped next. Returns
 * the same as trypush. */
int
sftp_hpn_workqueue_trypush_front(struct sftp_hpn_workqueue *queue, void *item)
{
	return queue_trypush(queue, item, 1);
}

/* Take the head item, waiting while the queue is empty. Items queued
 * before a shutdown are still handed out, so the workers finish them.
 * Returns -1 once the queue is shut down and empty. */
int
sftp_hpn_workqueue_pop(struct sftp_hpn_workqueue *queue, void **itemp)
{
	pthread_mutex_lock(&queue->mu);
	while (queue->count == 0 && !queue->shutdown)
		pthread_cond_wait(&queue->not_empty, &queue->mu);
	if (queue->count == 0) {
		/* shutdown && empty */
		pthread_mutex_unlock(&queue->mu);
		return -1;
	}
	*itemp = queue_take(queue);
	pthread_mutex_unlock(&queue->mu);
	return 0;
}

/* Take the head item without waiting. Returns -1 if the queue is empty
 * or shut down. Unlike pop, it refuses items left in a shut-down queue. */
int
sftp_hpn_workqueue_trypop(struct sftp_hpn_workqueue *queue, void **itemp)
{
	pthread_mutex_lock(&queue->mu);
	if (queue->count == 0 || queue->shutdown) {
		pthread_mutex_unlock(&queue->mu);
		return -1;
	}
	*itemp = queue_take(queue);
	pthread_mutex_unlock(&queue->mu);
	return 0;
}

/* Take the head item without waiting, even from a shut-down queue.
 * Returns -1 only when empty. The owner drains with this after an abort,
 * when undispatched items are still in the ring. trypop refuses them once
 * the queue is shut down, and they would otherwise leak with their
 * payloads. */
int
sftp_hpn_workqueue_drain(struct sftp_hpn_workqueue *queue, void **itemp)
{
	pthread_mutex_lock(&queue->mu);
	if (queue->count == 0) {
		pthread_mutex_unlock(&queue->mu);
		return -1;
	}
	*itemp = queue_take(queue);
	pthread_mutex_unlock(&queue->mu);
	return 0;
}

/* Shut the queue down and wake every thread blocked on it. Pushes fail
 * from here on, and pop hands out what is left before returning -1. */
void
sftp_hpn_workqueue_shutdown(struct sftp_hpn_workqueue *queue)
{
	pthread_mutex_lock(&queue->mu);
	queue->shutdown = 1;
	pthread_cond_broadcast(&queue->not_empty);
	pthread_cond_broadcast(&queue->not_full);
	queue_kick(queue);
	pthread_mutex_unlock(&queue->mu);
}

/* Wake the workers waiting in wait_activity(), for work that opened up
 * outside the queue. */
void
sftp_hpn_workqueue_kick(struct sftp_hpn_workqueue *queue)
{
	pthread_mutex_lock(&queue->mu);
	queue_kick(queue);
	pthread_mutex_unlock(&queue->mu);
}

/* Wait up to timeout_ms for a kick or a shutdown. The sequence number is
 * taken under the lock, so a kick cannot slip in between taking it and
 * starting the wait. */
void
sftp_hpn_workqueue_wait_activity(struct sftp_hpn_workqueue *queue, int timeout_ms)
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
	pthread_mutex_lock(&queue->mu);
	seen = queue->kick_seq;
	while (queue->kick_seq == seen && !queue->shutdown) {
		if (pthread_cond_timedwait(&queue->kick_cv, &queue->mu,
		    &deadline) == ETIMEDOUT)
			break;
	}
	pthread_mutex_unlock(&queue->mu);
}

/* The number of items queued right now. */
int
sftp_hpn_workqueue_depth(struct sftp_hpn_workqueue *queue)
{
	int depth;

	pthread_mutex_lock(&queue->mu);
	depth = queue->count;
	pthread_mutex_unlock(&queue->mu);
	return depth;
}
