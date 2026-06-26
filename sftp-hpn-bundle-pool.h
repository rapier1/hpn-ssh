/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the BSD 2-Clause License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the BSD 2-Clause License for more
 * details.
 *
 * You should have received a copy of the BSD 2-Clause License along with this
 * library; if not, see https://opensource.org/license/bsd-2-clause.
 *
 */

/*
 * sftp-hpn-bundle-pool.h - HPN-SSH bundle writer pool.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 *
 * A bounded producer/consumer pool that writes complete files to local storage
 * from N worker threads, overlapping the open/write/close (and, on a networked
 * filesystem, the MDS round-trips) that a serial extractor would serialize.
 * Shared by BOTH bundle-extract directions:
 *
 *   upload   - the server extracts a client-sent bundle (sftp-hpn-bundle-server.c)
 *   download - the client extracts a server-sent bundle (sftp-hpn-bundle-client.c)
 *
 * The producer (the codec's parser callbacks, on the main thread) buffers each
 * complete file and enqueues it; the writer threads do the actual file writes.
 * Files are independent, so there is no ordering constraint.  Backpressure is
 * bounded two ways: a buffered-byte budget (the primary bound on RAM) and a
 * queued-job count cap (a backstop).  Default off (threads == 1 -> the caller's
 * serial path); never required for normal operation.
 *
 * Error model: all-or-nothing, matching the codec.  A single failed write sets
 * the pool's sticky error; enqueue then returns -1 and finish() reports it, so
 * the caller abandons the bundle and the orchestrator retries via single-file.
 *
 * Threading: the pool owns its worker threads internally.  The producer side is
 * single-threaded (one parser/callback chain per worker process); only one
 * thread calls enqueue()/finish() on a given pool.
 */

#ifndef _SFTP_HPN_BUNDLE_POOL_H
#define _SFTP_HPN_BUNDLE_POOL_H

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

/*
 * Static pool tunables - fixed at compile time; the pool is on/off only
 * (HPNWriterPool / HPN_BUNDLE_FLAG_NO_POOL), the values are not user-tunable.
 *   THREADS - writer threads per pool; 4 is the measured knee on Lustre at -j8
 *             (1->4 is ~3x, 4->8 ~+5%, 8->16 flat).
 *   BUDGET  - buffered-byte backpressure bound per pool; 16 MiB clears the
 *             big-file concurrency penalty and bounds RAM to ~budget * J.
 */
#define HPN_BUNDLE_WRITER_THREADS_DEFAULT   4
#define HPN_BUNDLE_WRITER_BUDGET_DEFAULT    (16 * 1024 * 1024)

/* Opaque pool handle; defined in sftp-hpn-bundle-pool.c. */
struct bundle_write_pool;

/*
 * One complete file handed to the pool.  The pool takes ownership of both
 * full_path and data and frees them after the write (the producer transfers
 * them and clears its own pointers).  data may be NULL when len == 0.
 */
struct bundle_write_job {
	char    *full_path;	/* composed destination path (job owns) */
	mode_t   mode;		/* POSIX permission bits */
	time_t   mtime;		/* modification time (preserve mode) */
	u_char  *data;		/* file contents (job owns); NULL when len == 0 */
	size_t   len;		/* data length */
	struct bundle_write_job *next;
};

/* Writer-thread count for the extract pool - the fixed
 * HPN_BUNDLE_WRITER_THREADS_DEFAULT. */
int bundle_writer_threads(void);

/* The pool's buffered-byte budget - the fixed HPN_BUNDLE_WRITER_BUDGET_DEFAULT.
 * Bounds the pool's RAM and how many of the biggest eligible files fit in
 * flight. */
uint64_t bundle_writer_budget(void);

/*
 * Create a pool of n_threads writer threads.  preserve applies mode+mtime;
 * do_fsync fsyncs each file; budget is the buffered-byte backpressure bound.
 * Returns NULL on failure (the caller falls back to its serial path).
 */
struct bundle_write_pool *bundle_write_pool_new(int n_threads, int preserve,
    int do_fsync, uint64_t budget);

/*
 * Enqueue one complete file (takes ownership of job).  Blocks while the byte
 * budget or the count cap is exceeded (backpressure).  Returns -1 if a writer
 * thread has already failed - the caller drops the job and abandons the bundle.
 */
int bundle_pool_enqueue(struct bundle_write_pool *pool,
    struct bundle_write_job *job);

/*
 * Shut the pool down, join all threads, free any leftover jobs, destroy and
 * free the pool.  Returns the sticky error flag (nonzero = a file failed).
 * Safe on NULL.
 */
int bundle_write_pool_finish(struct bundle_write_pool *pool);

#endif /* _SFTP_HPN_BUNDLE_POOL_H */
