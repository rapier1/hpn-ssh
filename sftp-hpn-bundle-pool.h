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

/* sftp-hpn-bundle-pool.h - the bundle writer pool.
 *
 * A bounded producer and consumer pool that writes complete files from a
 * few worker threads, overlapping the open, write and close that a
 * serial extractor would do one file at a time. On a networked
 * filesystem that overlaps the metadata round-trips (the Lustre MDS).
 * Both extract directions use it: the server extracting a client-sent
 * bundle (sftp-hpn-bundle-server.c) and the client extracting a
 * server-sent one (sftp-hpn-bundle-client.c).
 *
 * The producer is the codec's parser callbacks on the main thread. It
 * buffers each complete file and enqueues it, and the writer threads do
 * the writes. Files are independent, so there is no ordering. The pool
 * is bounded two ways, a buffered-byte budget as the primary bound on
 * memory and a queued-job count cap as a backstop. It is on by default
 * (HPNWriterPool) and never required.
 *
 * Errors are all or nothing, matching the codec. One failed write sets
 * the pool's sticky error, enqueue then returns -1 and finish reports
 * it, so the caller abandons the bundle and the client falls back to
 * per-file transfer.
 *
 * The pool owns its worker threads. Only one thread calls enqueue and
 * finish on a given pool. */

#ifndef _SFTP_HPN_BUNDLE_POOL_H
#define _SFTP_HPN_BUNDLE_POOL_H

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

/* Compile-time pool sizing. The pool is on or off (HPNWriterPool on the
 * server, HPN_BUNDLE_FLAG_NO_POOL from the client), the values are not
 * tunable. Four threads is the measured knee on Lustre at -j8: one to
 * four gained about 3x, four to eight about 5 percent, eight to sixteen
 * nothing. 16 MiB clears the big-file concurrency penalty and bounds
 * memory to about the budget times the stream count. */
#define HPN_BUNDLE_WRITER_THREADS_DEFAULT   4
#define HPN_BUNDLE_WRITER_BUDGET_DEFAULT    (16 * 1024 * 1024)

/* Opaque pool handle, defined in sftp-hpn-bundle-pool.c. */
struct bundle_write_pool;

/* One complete file handed to the pool. On a successful enqueue the pool
 * owns full_path and data and frees them after the write. */
struct bundle_write_job {
	char    *full_path;	/* composed destination path */
	mode_t   mode;		/* permission bits */
	time_t   mtime;		/* applied when the pool preserves */
	u_char  *data;		/* file contents, NULL when len is 0 */
	size_t   len;		/* data length */
	struct bundle_write_job *next;
};

/* The fixed writer-thread count and byte budget above. */
int bundle_writer_threads(void);
uint64_t bundle_writer_budget(void);

/* Create a pool of n_threads writers. preserve applies each job's mode
 * and mtime, do_fsync fsyncs each file, budget is the buffered-byte
 * bound. Returns NULL on failure and the caller then writes inline. */
struct bundle_write_pool *bundle_write_pool_new(int n_threads, int preserve,
    int do_fsync, uint64_t budget);

/* Enqueue one complete file. Blocks while the byte budget or the count
 * cap is exceeded. Returns 0 and takes ownership of the job, or -1 once
 * a writer has failed, in which case the job stays with the caller. */
int bundle_pool_enqueue(struct bundle_write_pool *pool,
    struct bundle_write_job *job);

/* Shut the pool down, join all threads, destroy and free the pool.
 * Returns nonzero if any writer failed. Safe on NULL. */
int bundle_write_pool_finish(struct bundle_write_pool *pool);

#endif /* _SFTP_HPN_BUNDLE_POOL_H */
