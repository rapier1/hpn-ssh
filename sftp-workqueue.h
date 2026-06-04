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
 * Bounded multi-producer, multi-consumer work queue for the parallel-streams
 * sftp client. Carries opaque void* items; the caller owns the memory the
 * pointers refer to.
 *
 * Used by sftp-parallel.c: one producer pushes work units; N workers pop and
 * execute them. The queue is intentionally typeless so it can be compiled
 * and tested in isolation from the rest of the sftp client.
 */

#ifndef _SFTP_WORKQUEUE_H
#define _SFTP_WORKQUEUE_H

#include <stddef.h>

struct sftp_workqueue;

/*
 * Create a bounded queue with the given capacity (must be > 0). Returns
 * NULL on allocation failure.
 */
struct sftp_workqueue *sftp_workqueue_new(size_t capacity);

/*
 * Free the queue. The caller must have drained it; items still inside are
 * not freed by this function (the queue does not own item memory).
 */
void sftp_workqueue_free(struct sftp_workqueue *q);

/*
 * Push an item. Blocks if the queue is full. Returns 0 on success, -1 if
 * shutdown was signaled before the push could complete.
 */
int sftp_workqueue_push(struct sftp_workqueue *q, void *item);

/*
 * Like sftp_workqueue_push but inserts at the head (LIFO): the item is the
 * next one popped. Used for transient unit re-queues so a failed byte-range
 * jumps ahead of fresh work and its file completes promptly. Blocks if full;
 * returns 0 on success, -1 if shutdown was signaled before the push.
 */
int sftp_workqueue_push_front(struct sftp_workqueue *q, void *item);

/*
 * Pop an item. Blocks if the queue is empty. On success sets *itemp and
 * returns 0. Returns -1 if shutdown was signaled and the queue is empty
 * (drains residual items before returning -1).
 */
int sftp_workqueue_pop(struct sftp_workqueue *q, void **itemp);

/*
 * Non-blocking pop. On success sets *itemp and returns 0. Returns -1
 * immediately if the queue is empty or shutdown (does not drain).
 * Used by workers to collect a batch of items without blocking.
 */
int sftp_workqueue_trypop(struct sftp_workqueue *q, void **itemp);

/*
 * Signal shutdown. Wakes every thread currently blocked in push or pop.
 * Subsequent push calls fail immediately; pop calls drain remaining items
 * then fail. Idempotent.
 */
void sftp_workqueue_shutdown(struct sftp_workqueue *q);

/* Current number of items in the queue. Snapshot - may be stale by the
 * time the caller reads it, which is fine for telemetry. */
size_t sftp_workqueue_depth(struct sftp_workqueue *q);

/* Largest depth the queue has held since creation. Used by adaptive
 * tuning to detect "queue saturated" conditions. */
size_t sftp_workqueue_high_watermark(struct sftp_workqueue *q);

#endif /* _SFTP_WORKQUEUE_H */
