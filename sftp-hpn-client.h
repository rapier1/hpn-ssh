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

/* sftp-hpn-client.h - HPN-SSH extensions to the SFTP client.
 *
 * This file is part of HPN-SSH, not of upstream OpenSSH. It declares the
 * client-side HPN state and interfaces that sftp-client.c would otherwise
 * carry: the extension bits the server advertises, the per-connection
 * state (struct sftp_hpn_conn, reached from struct sftp_conn through one
 * pointer, its only HPN member), the serial bundle accumulator, the
 * deferred directory attributes, the sink and driver interfaces of the
 * shared upload and download walks, and the read-ahead tuning constants.
 * The implementations are in sftp-hpn-client.c, except the inline source
 * hash, which is in sftp-hpn-verify.c. */

#ifndef _SFTP_HPN_CLIENT_H
#define _SFTP_HPN_CLIENT_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>

#include "sftp-common.h"

struct bwlimit;		/* misc.h; kept opaque here */
struct sftp_conn;
struct stat;

/* HPN's SFTP extension bits (server-advertised in SSH2_FXP_VERSION), split
 * out of the SFTP_EXT_* block in sftp-client.c so struct sftp_conn's upstream
 * define block carries only stock OpenSSH extensions. sftp-client.c sets
 * them and sftp-hpn-client.c tests them, both through this header. */
#define SFTP_EXT_HPN_CHECK_FILE		0x00000400
#define SFTP_EXT_HPN_FS_INFO		0x00000800
#define SFTP_EXT_HPN_BUNDLE		0x00001000
#define SFTP_EXT_HPN_BUNDLE_FETCH	0x00002000
#define SFTP_EXT_HASH_RANGE		0x00004000
#define SFTP_EXT_HPN_FILE_LAYOUT	0x00008000
#define SFTP_EXT_HPN_DTREE_OPEN		0x00010000
#define SFTP_EXT_HPN_DTREE_READ		0x00020000

/* Length of the pacing rate ring, the estimator's memory in seconds.
 * sftp-hpn-client.c indexes the ring with it. */
#define PACE_RING	10

/* Wedge detection threshold in seconds. A STATUS read that blocks longer
 * than this is evidence the path is wedged: the caller signals
 * sftp_conn_rdahead_backpressure_signal and the controller halves the
 * depth, as TCP halves cwnd on a timeout. 10 s is above the 3 to 8 s
 * STATUS latencies Lustre OST contention produces and well below the
 * wedges observed in testing, which all blocked for over 90 s. Without
 * the signal the grow-only controller settles high and never recovers
 * when conditions degrade mid-transfer.
 *
 * This layer is application-level congestion control on top of TCP's,
 * because the client cannot see the transport socket's TCP_INFO across
 * the hpnssh subprocess boundary. */
#define RDAHEAD_BP_THRESHOLD_SEC  10.0

/* Persistent degradation thresholds. When repeated backpressure events
 * have forced the controller to its floor and it is not recovering, the
 * connection is marked dead so the orchestrator replaces it with a fresh
 * TCP session. Either threshold suffices: BP_COUNT consecutive
 * backpressure events while at the floor, or FLOOR_SEC of wall time at
 * the floor in this run. The values are conservative, to give a broken
 * connection a way out without thrashing on transient slowdowns. Five
 * backpressure events at the floor is well past what a healthy path
 * produces, and 60 s there without recovery means the floor-doubling time
 * probe found no headroom either. The reap feeds the orchestrator's
 * existing respawn machinery, with its cooldowns and budgets. It adds a
 * trigger, not a respawn path. See parallel_respawn_dispatch in
 * sftp-parallel-respawn.c for why that gate is session-wide. */
#define RDAHEAD_REAP_BP_COUNT   5
#define RDAHEAD_REAP_FLOOR_SEC  60.0

/* Adaptive SFTP read-ahead controller.
 *
 * The stock client keeps a fixed pipeline of num_requests (-R, default
 * 1024) outstanding 128 KB requests, about 128 MB in flight per
 * connection. The receive side must buffer all of it, so on a fat pipe
 * with N parallel workers the process RSS and the kernel SO_RCVBUF grow
 * into the gigabytes, far past what throughput needs.
 *
 * This controller instead probes for the smallest depth that saturates
 * the path. Over a sliding window of one depth's worth of completed
 * requests it measures application-layer throughput, doubles the depth
 * while throughput keeps rising (growing by one would take thousands of
 * RTTs to fill a fat pipe), and settles at the last depth that still
 * gained once throughput plateaus, the BDP knee. A deeper pipe that
 * reduces throughput falls back to that last good depth the same way.
 * -R stays a hard ceiling. The state is per connection, so each parallel
 * worker tunes itself, and application-layer only: no TCP_INFO
 * dependency, so it is portable to every OS we support. */
struct sftp_rdahead {
	uint32_t cur;         /* current target depth, requests in flight */
	uint32_t floor;       /* never probe below this */
	uint32_t cap;         /* never exceed this, the -R value */
	/* The depth to fall back to, the last one that still gained. */
	uint32_t last_rising;
	uint32_t win_reqs;    /* completed requests in the current window */
	uint64_t win_bytes;   /* bytes accumulated in the current window */
	double   win_start;   /* monotime_double() at window open */
	/* Smoothed rate of the last window in bytes/s. 0 means no baseline. */
	double   last_rate;
	/* Set at the knee or at the -R ceiling. Stops the probing. */
	int      settled;

	/* Persistent degradation tracking. Backpressure events that arrive
	 * while cur is already at the floor accumulate here, and when the
	 * controller cannot lift cur above the floor for long enough, the
	 * connection is marked dead so the orchestrator's respawn machinery
	 * replaces it with a fresh TCP session (RDAHEAD_REAP_*). Both reset
	 * when cur grows above the floor again, from a window completion or
	 * from the floor time probe. */
	int      consecutive_bp_at_floor;
	/* monotime_double() of the first backpressure signal in the current
	 * run at the floor, or 0 while there is no such run. */
	double   time_first_at_floor;
};

/* One file parked for the classic post-transfer verify phase.
 * sftp_conn_verify_park adds one per transferred file and
 * sftp_conn_verify_run_phase verifies them all. Both paths are owned. */
struct sftp_verify_pending_entry {
	char *local_path;
	char *remote_path;
	/* Bytes, filled at phase start for the meter. */
	off_t size;
	int   local_is_target;		/* 0 = upload, 1 = download */
	/* Source hash teed while the upload read the file, when the tee
	 * covered every byte; the phase then skips the local read. */
	int      have_src_hash;
	uint64_t src_hash;
};

/* Adaptive upload pacing state. WRITE acks arrive at the receiver's
 * sustained drain rate, about one RTT late. Sending at slightly above that
 * rate keeps the destination's page cache below its dirty limit, which
 * otherwise turns a single-stream high-RTT upload into a stall and
 * recover cycle. sftp_conn_pace_ack holds the control law. One per
 * connection, so each parallel worker paces itself. */
struct sftp_hpn_pace {
	int      enabled;		/* on unless -X Pacing=no */
	int      active;		/* grace passed, limiter engaged */
	uint64_t acks;			/* WRITE acks seen, for the grace */
	uint64_t first_ack_ms;		/* monotime_ms of the first ack */
	uint64_t bucket_bytes;		/* acked bytes in the current bucket */
	uint64_t bucket_start_ms;	/* monotime_ms the bucket opened */
	/* Per-second delivered rates in bytes. The ceiling is 125% of their
	 * mean, so stalled seconds pull it toward the sink's sustained rate.
	 * Slow-start samples are left out. */
	uint64_t rate_ring[PACE_RING];
	u_int    ring_idx;
	uint64_t last_arm_ms;		/* monotime_ms of the last arm */
	uint64_t bw_rate_bits;		/* rate programmed into bw, bits/s */
	/* The last ceiling armed while rising, reclaimed after a famine. */
	uint64_t reclaim_bytes;
	struct bwlimit *bw;		/* -l token bucket, NULL until active */
};

/* Serial-path bundling settings, from HPNUseBundle, HPNBundleSize and
 * HPNWriterPool in ssh_config through sftp_conn_set_bundle_config. They
 * mirror the parallel planner's, so both modes obey the same knobs. */
struct sftp_hpn_bundle_cfg {
	int      use;			/* HPNUseBundle, default on */
	int      writer_pool;		/* HPNWriterPool, default on */
	uint64_t size;			/* HPNBundleSize bytes, 0 = default */
	/* Set after the server refused a bundle. The session then sends
	 * files individually. */
	int      server_cant;
};

/* HPN per-connection state, reached from struct sftp_conn through one
 * pointer, its only HPN member. */
struct sftp_hpn_conn {
	/* Set on an unrecoverable I/O error. send and receive refuse to run.
	 * A plain int, touched only by the thread that owns the connection. */
	int              dead;

	/* Set while a dtree-read batch is arriving. A reply is matched to
	 * its request by wire order, so a second request sent inside that
	 * window would interleave the two replies and desynchronise both
	 * readers, the "reply id mismatch" failure. send_msg refuses to send
	 * while this is set, so the mistake fails at once at the call site.
	 * Per connection: a crossload walk may send on the destination while
	 * the source connection is busy, and the pipelined helpers that track
	 * their own request ids (mkdir, setstat, bundle-fetch) do not set
	 * it. */
	int              reply_stream_active;

	/* Set on a protocol violation, such as a reply id mismatch or an
	 * unexpected packet type. Unlike dead, this means a possible attack
	 * or a corrupt server, so the parallel orchestrator aborts the whole
	 * transfer instead of retrying. */
	int              protocol_violation;

	/* Sticky: the server answered PERMISSION_DENIED. Set by get_status
	 * and get_handle, read by the parallel worker's retry decision, since
	 * a refusal is permanent. Survives the CLOSE that follows a failure
	 * and is cleared at each unit or batch status read. */
	int              saw_perm_denied;

	/* The refusal above carried the server's request-policy tag
	 * (HPN_POLICY_DENIED_TAG), so it was a -P or -p denial rather than a
	 * filesystem error, and the bundle path aborts the whole transfer.
	 * Cleared at each bundle attempt. */
	int              saw_policy_denied;

	/* The last SSH2_FXP_STATUS code from get_status or get_handle, for
	 * classifying permanent failures. */
	u_int            last_status;

	/* The server's per-user worker cap from hpn-max-workers@hpnssh.org:
	 * -1 not advertised (a stock server), 0 advertised with no cap, else
	 * the cap. */
	int              hpn_max_workers_cap;

	/* Progress hook for the parallel orchestrator, added to atomically per
	 * completed request. NULL until installed, by the orchestrator for
	 * its workers or by the verify repair for its meter. */
	volatile uint64_t *live_counter;

	/* Yield hook for the orchestrator's tail redistribution. When the
	 * reporter finds this worker holding the last of the work, it sets
	 * the flag. The range loops then stop issuing requests, drain what is
	 * in flight and return with what was acked, so the caller requeues
	 * only the untouched remainder. A voluntary wind-down, never a kill.
	 * NULL outside parallel mode. */
	volatile int *yield_flag;

	/* Monotonic-ms deadline before which the watchdog's inactivity
	 * heuristics leave this worker alone; the SSH-child-gone check still
	 * fires. sftp_conn_watchdog_pause sets it before a long operation
	 * that moves no bytes (a verify hash, an fsync, a bundle extract),
	 * sftp_conn_watchdog_resume or expiry clears it. Atomic load and
	 * store: written by the owning thread, read by the watchdog. */
	volatile uint64_t watchdog_pause_until_ms;

	/* -V, latched at sftp_init. Turns on the inline source hash and the
	 * post-transfer verify. */
	int              verify_transfer_enabled;

	/* Auto-repair for the single-connection verify phase, from the
	 * -X VerifyRepair token with attempts capped at 3. The parallel
	 * fleet keeps its own copy. sftp_hpn_verify_repair reads these. */
	int              verify_repair_enabled;
	int              verify_repair_attempts;

	/* The single-connection verify phase. sftp_upload and sftp_download
	 * park each transferred file here, sftp_conn_verify_run_phase
	 * verifies them all once the command's transfers finish, and
	 * sftp_conn_drain_verify_failures hands the mismatched remote paths
	 * to the caller for the summary and exit code. Plain arrays, since
	 * this connection is single threaded. Empty on worker connections,
	 * whose files the orchestrator verifies. */
	struct sftp_verify_pending_entry *verify_pending;
	int              verify_pending_count;
	int              verify_pending_cap;
	char           **verify_failed_paths;
	int              verify_failed_count;

	/* SFTP payload bytes that crossed the wire on this connection: WRITE
	 * payload sent and DATA payload received, without SSH framing. A
	 * unit's byte count can exceed it, since chunked resume skips data
	 * the remote already has. The orchestrator reports both at the end
	 * as resolved versus wired. Atomic add, any thread. */
	volatile uint64_t bytes_wired_payload;

	/* Hash work accounting for the -Z resume check, -V verify and
	 * auto-repair, in work bytes: checking one byte costs two, one per
	 * side, and both sides feed one monotone counter, done = leg_base +
	 * leg progress. Every progress write refreshes the stamp. The
	 * watchdog takes a fresh stamp as proof of hashing, and the reporter
	 * takes one older than HASH_WORK_STALE_MS as an op that is gone, so
	 * an engine need not mark its exit; the unit-completion sites do.
	 * Atomic, any thread. */
	volatile uint64_t hash_work_done;
	volatile uint64_t hash_work_total;
	volatile uint64_t hash_work_leg_base;
	volatile uint64_t hash_work_stamp_ms;

	/* Serial meter bridge. When set, every progress write also stores
	 * meter_base + done here, so a meter advances while the single thread
	 * is inside an engine. meter_base carries the completed prior ops of
	 * a multi-file verify. Only serial call sites set it. */
	volatile off_t  *hash_meter_ctr;
	volatile uint64_t hash_meter_base;

	/* HPNLustreStripeCount from ssh_config: -1 auto (the -j count, when
	 * the destination is Lustre with fewer stripes), 0 off (never call
	 * hpn-file-layout), else the stripe count to ask for under the same
	 * condition. Read for each directory the walk creates, until
	 * layout_set_declined ends the calls. */
	int              lustre_stripe_count;

	/* Set after the first non-success reply to hpn-file-layout, so later
	 * directories skip the round trip and the log gets one line, not one
	 * per directory. Lives as long as the connection. */
	int              layout_set_declined;

	/* Read-ahead controller. Sizes the in-flight window to the path's
	 * BDP instead of a flat num_requests. */
	struct sftp_rdahead rd;

#ifdef HPN_FAULT_INJECTION
	/* Test scaffolding for hpn-fault-inject.c, armed from the
	 * HPN_FAULT_* variables its header documents. Thresholds are byte
	 * counts, 0 for off. */
	uint64_t fault_after_bytes;		/* die after this many sent */
	uint64_t fault_pv_after_bytes;		/* protocol violation after */
	uint64_t fault_bytes_sent;		/* sent so far */
	uint64_t fault_throttle_after_bytes;	/* throttle sends after */
	int      fault_throttling;		/* holds a throttle slot */
	uint64_t fault_recv_throttle_after_bytes; /* throttle receives after */
	uint64_t fault_bytes_recvd;		/* received so far */
	int      fault_recv_throttling;		/* holds a receive slot */
#endif

	/* Inline source hash for verify transfer. An upload hashes the source
	 * as it reads it, and the result is taken into the file's parked
	 * verify entry or range slot, so the verify step need not read the
	 * source again. state is the streaming XXH3 handle, void so this
	 * header stays free of xxhash, NULL when idle. valid is set on a
	 * clean finish, failed when an update errored, which discards the
	 * result. */
	void     *verify_src_state;
	uint64_t  verify_src_bytes;
	uint64_t  verify_src_hash;
	int       verify_src_valid;
	int       verify_src_failed;

	struct sftp_hpn_pace pace;		/* adaptive upload pacing */
	struct sftp_hpn_bundle_cfg bundle_cfg;	/* serial bundling settings */
};

/* Serial-path bundle accumulator. The serial walks collect bundle-eligible
 * small files here and ship each batch on the session connection, as one
 * hpn-bundle stream for an upload or one hpn-bundle-fetch request for a
 * download. Implemented in sftp-hpn-client.c, with the eligibility policy
 * shared with the parallel planner through sftp-hpn-bundle.h. */
struct sftp_hpn_bundle_acc {
	char **src_paths;	/* upload: local; download: remote */
	char **dst_paths;	/* upload: remote; download: local */
	/* Per-member file bytes, for the log and the meter. */
	off_t *sizes;
	int nmembers;
	int members_alloc;
	/* Framed bytes so far: header, path and payload per member, the
	 * same accounting as the parallel producer. */
	uint64_t bytes;
	uint64_t path_bytes;	/* download only: fetch-request path cost */
	uint64_t target;	/* flush threshold (HPNBundleSize) */
	int is_download;	/* selects the fetch request over the stream */
	/* 0 when this walk cannot bundle: bundling is off, the server refused
	 * a bundle earlier, the walk is a resume, or the server lacks the
	 * direction's extension. Every file then goes individually. */
	int enabled;
};

/* Deferred directory attributes for the recursive transfer walks, one
 * implementation for serial and parallel. A directory is created with the
 * owner write and execute bits forced on and its final attrs are queued
 * here, then applied only after all file content has landed: at the end
 * of sftp_upload_dir, sftp_download_dir and sftp_crossload_dir for serial,
 * and of sftp_parallel_wait for parallel. Stock OpenSSH sets a
 * directory's final mode after its files are written; bundling delivers a
 * directory's files at a later flush, and bundles span directories, so
 * the end of the transfer is the first point every directory is known to
 * be complete. sftp_hpn_dirattrs_apply orders the list deepest first.
 *
 * The accepted costs: one entry per directory for the whole transfer, and
 * an interrupted transfer leaves directories with the widened mode until
 * a re-run completes. Files need no deferral, since they are written
 * through an open fd and fchmod'd last. */
struct sftp_hpn_dirattr {
	char   *path;
	Attrib  attrs;		/* remote: the final attrs for setstat */
	mode_t  mode;		/* local: final mode, (mode_t)-1 for no chmod */
	int     is_local;	/* 0 remote setstat, 1 local chmod and utimes */
	int     set_times;	/* local: the source sent ACMODTIME */
	time_t  atime, mtime;	/* local: the times to set when set_times */
};

/* The deferred entries of one transfer, applied and freed by the owner. */
struct sftp_hpn_dirattr_list {
	struct sftp_hpn_dirattr *entries;
	int nentries;
	int entries_alloc;
};

/* Per-mode callbacks for the download walks, sftp_tree_download_consume
 * and sftp_readdir_download_consume. The pattern, and how a callback
 * recovers its context, is described on struct sftp_upload_sink below.
 * Downloads create local directories one at a time, so make_dir both
 * creates and defers attrs, and they add two optional callbacks and the
 * streams_files flag. */
struct sftp_tree_dl_sink {
	/* Create local directory dst for a directory entry and defer its
	 * attrs. src, the remote path, is for messages. 0, or -1 after
	 * recording the failure. */
	int  (*make_dir)(struct sftp_tree_dl_sink *sink, const char *src,
	         const char *dst, const Attrib *attrs);
	/* Transfer regular file src to dst. 0 or -1. */
	int  (*xfer_file)(struct sftp_tree_dl_sink *sink, const char *src,
	         const char *dst, Attrib *attrs);
	/* Record a per-entry failure. reason is a static string. */
	void (*fail)(struct sftp_tree_dl_sink *sink, const char *path,
	         const char *reason);
	/* True when the walk should stop: interrupt or fleet abort. */
	int  (*aborting)(struct sftp_tree_dl_sink *sink);
	/* Optional. Print a one-line notice: a batch of the file list is
	 * being fetched, or an interrupt is waiting for one to drain. Serial
	 * prints above the meter. NULL keeps a sink's output unchanged. */
	void (*notice)(struct sftp_tree_dl_sink *sink, const char *text);
	/* Optional. Take the total bytes and file count once the walk ends,
	 * so an aggregate meter can show a percentage and ETA. Only the
	 * parallel sink has one. The readdir fallback never calls it. */
	void (*set_total)(struct sftp_tree_dl_sink *sink, off_t total_bytes,
	    size_t nfiles);
	/* Set when xfer_file may run while a batch is still arriving, so
	 * transfer overlaps discovery and the driver keeps no queue. Legal
	 * only when xfer_file sends nothing on the connection carrying the
	 * reply; reply_stream_active makes a violation fatal at once. Only
	 * parallel qualifies, since submitting just enqueues work. Serial
	 * and crossload transfer on that connection and keep the per-batch
	 * queue. */
	int streams_files;
};

/* Per-mode callbacks for the shared upload driver, sftp_upload_walk_consume.
 * The driver does what serial and parallel uploads share: walk the local
 * directory, batch-create the subdirectories on the control connection,
 * recurse. What differs by mode goes through these callbacks: how a file
 * is transferred (serial bundles it or calls sftp_upload, parallel submits
 * it to the fleet) and the per-directory bookkeeping (progress, Lustre
 * layout, worker phases, the deferred-attrs list, failures, aborts). A mode
 * flag would not do, because the two implementations live in different
 * files and call file-local functions the driver cannot see.
 *
 * Each mode embeds this struct as the first member of its own context
 * (serial_ul_sink, parallel_ul_sink), which also holds its connection,
 * accumulator or fleet, and flags. The driver holds only the base pointer;
 * a callback casts it back to the full context, which is safe because the
 * two share an address. struct sftp_tree_dl_sink is the download twin. */
struct sftp_upload_sink {
	/* Once per directory, after its attrs are known and before it is
	 * enumerated. Serial prints "Entering src"; parallel applies the
	 * Lustre layout to dst and enters the enumerate phase. */
	void (*enter_dir)(struct sftp_upload_sink *sink, const char *src,
	         const char *dst);
	/* Transfer regular local file src to dst. src_sb is its stat. 0 or
	 * -1. */
	int  (*xfer_file)(struct sftp_upload_sink *sink, const char *src,
	         const char *dst, const struct stat *src_sb);
	/* Before the pipelined mkdir batch. Parallel enters the mkdir phase. */
	void (*before_mkdir)(struct sftp_upload_sink *sink);
	/* Defer this directory's final remote attrs. The driver applies the
	 * created-or-preserve gate, so a call here means they are wanted. */
	void (*defer_dir)(struct sftp_upload_sink *sink, const char *dst,
	         const Attrib *attrs);
	/* Record a per-entry failure. reason is a short message the sink
	 * must use at once, since it may be strerror's buffer. */
	void (*fail)(struct sftp_upload_sink *sink, const char *path,
	         const char *reason);
	/* True when the walk should stop: interrupt or fleet abort. */
	int  (*aborting)(struct sftp_upload_sink *sink);
};

/* Directory handling shared by the serial and parallel walks. The
 * definitions in sftp-hpn-client.c carry the detail. */
void sftp_hpn_dir_attrs_from_stat(const struct stat *sb, int preserve_flag,
    Attrib *out);
int  sftp_hpn_ensure_remote_dir(struct sftp_conn *conn, const char *dst,
    const Attrib *attrs, int *created);
int  sftp_hpn_ensure_local_dir(const char *dst, const Attrib *dirattrib,
    mode_t *mode_out, mode_t *tmpmode_out);
void sftp_hpn_dirattrs_defer_remote(struct sftp_hpn_dirattr_list *dl,
    const char *path, const Attrib *attrs);
void sftp_hpn_dirattrs_defer_local(struct sftp_hpn_dirattr_list *dl,
    const char *path, mode_t mode, mode_t tmpmode, const Attrib *dirattrib);
void sftp_hpn_dirattrs_apply(struct sftp_conn *conn,
    struct sftp_hpn_dirattr_list *dl);
void sftp_hpn_dirattrs_free(struct sftp_hpn_dirattr_list *dl);

/* The shared walk drivers. Each replays a tree through the sink it is
 * given and returns 0, or -1 if any entry failed. The download drivers
 * take the root's attrs in dirattrib, or NULL to stat it; the readdir
 * fallback serves servers without the tree walk. The upload driver
 * expects dst to exist and recurses with each child's created flag. */
int  sftp_tree_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, Attrib *dirattrib, int follow_link_flag,
    struct sftp_tree_dl_sink *sink);
int  sftp_readdir_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, Attrib *dirattrib,
    int follow_link_flag, struct sftp_tree_dl_sink *sink);
int  sftp_upload_walk_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, int created, int preserve_flag,
    int follow_link_flag, struct sftp_upload_sink *sink);

/* Serial bundle accumulator, see struct sftp_hpn_bundle_acc. */
void sftp_hpn_bundle_acc_init(struct sftp_hpn_bundle_acc *acc,
    struct sftp_conn *conn, int resume, int is_download);
int  sftp_hpn_bundle_acc_eligible(const struct sftp_hpn_bundle_acc *acc,
    uint64_t size);
int  sftp_hpn_bundle_acc_add(struct sftp_hpn_bundle_acc *acc,
    const char *src, const char *dst, off_t size);
int  sftp_hpn_bundle_acc_flush(struct sftp_conn *conn,
    struct sftp_hpn_bundle_acc *acc, int preserve_flag, int print_flag,
    int verify, int fsync_flag, int inplace_flag);
void sftp_hpn_bundle_acc_free(struct sftp_hpn_bundle_acc *acc);

/* Allocate a zeroed sftp_hpn_conn with its option defaults set. Dies
 * rather than return NULL. */
struct sftp_hpn_conn *sftp_hpn_conn_init(void);

/* Free an sftp_hpn_conn. NULL is fine. */
void sftp_hpn_conn_free(struct sftp_hpn_conn *);

/* The -X Pacing= switch, applied to each new connection. The
 * per-connection pacing entry points are in sftp-client-internal.h. */
void sftp_hpn_pace_set_enabled(int on);

/* Ask the server to set a Lustre layout on the directory at path:
 * stripe_count stripes, with files below small_threshold kept on one.
 * Returns HPN_FILE_LAYOUT_OK, _NOT_FS, _PERM or _FAIL and reports what was
 * applied through applied_out and layout_kind_out. The caller,
 * sftp-lustre-client.c, gates on sftp_conn_has_file_layout and
 * sftp_conn_layout_set_declined and latches the latter after a refusal.
 * Experimental, and shaped so other parallel filesystems could use it. */
int  sftp_hpn_set_file_layout(struct sftp_conn *conn, const char *path,
    uint32_t stripe_count, uint32_t small_threshold, uint32_t *applied_out,
    uint32_t *layout_kind_out);

#endif /* _SFTP_HPN_CLIENT_H */
