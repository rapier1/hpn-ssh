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

/* sftp-hpn-workqueue.h - a bounded multi-producer, multi-consumer work
 * queue for parallel hpnsftp. It carries opaque void * items, and the
 * caller owns the memory they point to.
 *
 * The parallel orchestrator (sftp-parallel*.c) pushes work units, and its
 * worker threads pop and run them. The queue knows nothing about the
 * items, so it can be built and unit-tested apart from the rest of the
 * sftp client. */

#ifndef _SFTP_HPN_WORKQUEUE_H
#define _SFTP_HPN_WORKQUEUE_H

struct sftp_hpn_workqueue;

/* Create a queue that holds up to the given number of items, which must be
 * positive. Returns NULL on failure. */
struct sftp_hpn_workqueue *sftp_hpn_workqueue_new(int);

/* Free the queue. Items still in it are not freed, because the queue does
 * not own them, so the caller drains it first. */
void sftp_hpn_workqueue_free(struct sftp_hpn_workqueue *);

/* Push an item, blocking while the queue is full. Returns 0, or -1 if the
 * queue is shut down first. */
int sftp_hpn_workqueue_push(struct sftp_hpn_workqueue *, void *);

/* Pushes that never wait. trypush adds at the tail. trypush_front adds at
 * the head, so the item is popped next. Re-queued units use it, so a
 * failed byte range runs ahead of fresh work and its file finishes
 * promptly. Both return 0 if queued, 1 if the queue is full and the item
 * was not queued, or -1 if it is shut down. A worker re-queueing onto the
 * queue it also drains must use these. A blocking push there would stop
 * that worker consuming, so nothing would drain the queue, and at -j1
 * that worker is the only consumer. */
int sftp_hpn_workqueue_trypush(struct sftp_hpn_workqueue *, void *);
int sftp_hpn_workqueue_trypush_front(struct sftp_hpn_workqueue *, void *);

/* Pop an item through the pointer given, blocking while the queue is
 * empty. Returns 0, or -1 once the queue is shut down and empty. Items
 * left at shutdown are still handed out first. */
int sftp_hpn_workqueue_pop(struct sftp_hpn_workqueue *, void **);

/* Pop an item through the pointer given, without waiting. Returns 0, or -1
 * if the queue is empty or shut down. Workers use it to gather a batch. */
int sftp_hpn_workqueue_trypop(struct sftp_hpn_workqueue *, void **);

/* Pop an item through the pointer given, even from a shut-down queue,
 * which trypop refuses. Returns -1 only when empty. The owner's final
 * drain uses it, so undispatched items do not leak. */
int sftp_hpn_workqueue_drain(struct sftp_hpn_workqueue *, void **);

/* Shut the queue down and wake every thread blocked in it. Later pushes
 * fail, and pop hands out what is left and then fails. Calling it again is
 * harmless. */
void sftp_hpn_workqueue_shutdown(struct sftp_hpn_workqueue *);

/* Wake the threads waiting in sftp_hpn_workqueue_wait_activity(). Called
 * when something outside the queue that gates queued work changes, such
 * as a per-file writer-cap slot freeing. The queue may stay non-empty the
 * whole time, so the not-empty condition cannot be the wait point. */
void sftp_hpn_workqueue_kick(struct sftp_hpn_workqueue *);

/* Wait for the next kick, a shutdown, or the given timeout in milliseconds,
 * whichever comes first. A push does not end the wait. Workers whose queued
 * work is all capped use it in place of a pop and re-queue spin: the kick
 * wakes them when a slot frees, and the timeout bounds how stale they can
 * get. */
void sftp_hpn_workqueue_wait_activity(struct sftp_hpn_workqueue *, int);

/* The number of items queued. It can be stale by the time the caller
 * reads it, which is fine for the telemetry and the gating that use it. */
int sftp_hpn_workqueue_depth(struct sftp_hpn_workqueue *);

#endif /* _SFTP_HPN_WORKQUEUE_H */
