/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <errno.h>
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

void
sftp_workqueue_shutdown(struct sftp_workqueue *q)
{
	pthread_mutex_lock(&q->mu);
	q->shutdown = 1;
	pthread_cond_broadcast(&q->not_empty);
	pthread_cond_broadcast(&q->not_full);
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
