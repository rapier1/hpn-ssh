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

/* sftp-hpn-client.h - HPN-SSH extensions to the SFTP client connection.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * All HPN-specific per-connection state is isolated here so that
 * sftp-client.c carries a minimal diff against upstream.
 *
 * Upstream merge note: struct sftp_conn gains exactly ONE HPN line -
 *   struct sftp_hpn_conn *hpn;
 * All HPN per-connection state (dead flag, live counter, verify/hash/rdahead/
 * watchdog state, last_status, saw_perm/policy_denied, worker cap) lives on
 * struct sftp_hpn_conn and is reached via conn->hpn->... or the sftp_conn_hpn()
 * bridge.  sftp-client.c also gains the include, sftp_hpn_conn_init/free calls
 * in sftp_init/sftp_free, and send_msg/get_msg/get_handle un-static'd.
 */

#ifndef _SFTP_CLIENT_HPN_H
#define _SFTP_CLIENT_HPN_H

#include <stdint.h>

/*
 * HPN's SFTP extension bits (server-advertised in SSH2_FXP_VERSION), split out
 * of the SFTP_EXT_* block in sftp-client.c so struct sftp_conn's upstream
 * define block carries only stock OpenSSH extensions.  sftp-client.c (the
 * `exts |=` setters) and sftp-hpn-client.c (the has_*() predicates) both see
 * these through this header.
 */
#define SFTP_EXT_HPN_CHECK_FILE		0x00000400
#define SFTP_EXT_HPN_FS_INFO		0x00000800
#define SFTP_EXT_HPN_BUNDLE		0x00001000
#define SFTP_EXT_HPN_BUNDLE_FETCH	0x00002000
#define SFTP_EXT_HASH_RANGE		0x00004000
#define SFTP_EXT_HPN_FILE_LAYOUT	0x00008000
#define SFTP_EXT_HPN_DISCOVER_TREE	0x00010000

/*
 * Uncomment to enable fault injection (SFTP_FAULT_INJECT / SFTP_FAULT_PROTOCOL
 * environment variables).  Leave commented out for production builds.
 */
/* #define HPN_FAULT_INJECTION */

/*
 * Adaptive SFTP read-ahead controller (HPN).
 *
 * The stock client keeps a fixed pipeline of num_requests (-R, default 1024)
 * outstanding 128 KB requests - ~128 MB in flight per connection.  The
 * receive side must buffer all of it, so on a fat pipe with N parallel
 * workers process RSS and the kernel SO_RCVBUF balloon into the GB range,
 * far past what throughput actually needs.
 *
 * This controller instead probes for the SMALLEST depth that saturates the
 * path.  Over a sliding window of one depth's worth of completed requests it
 * measures app-layer throughput, then multiplicatively grows the depth (x2)
 * while throughput keeps rising (an RTT-bound ramp - growing by 1 would take
 * thousands of RTTs to fill a fat pipe), and settles at the last depth that
 * still gained once throughput plateaus (the BDP knee); a deeper pipe that
 * reduces throughput (overshoot) likewise falls back to that last-good depth.
 * -R stays a hard ceiling.  Per-connection, so each parallel worker tunes
 * itself.  App-layer only - no TCP_INFO dependency, portable across every OS
 * we support.
 */
struct sftp_rdahead {
	uint32_t cur;         /* current target depth (requests in flight) */
	uint32_t floor;       /* never probe below this */
	uint32_t cap;         /* never exceed this (= num_requests / -R) */
	uint32_t last_rising; /* largest depth that still improved throughput */
	uint32_t win_reqs;    /* completed requests in the current window */
	uint64_t win_bytes;   /* bytes accumulated in the current window */
	double   win_start;   /* monotime_double() at window open */
	double   last_rate;   /* smoothed throughput of previous window (bytes/s) */
	int      settled;     /* 1 once the knee is found - stop probing */
	int      enabled;     /* 0 => legacy fixed depth (HPN_RDAHEAD=fixed) */

	/* Part D - persistent-degradation tracking.  Backpressure events
	 * occurring while already at floor accumulate here.  When the
	 * controller can't keep cur above floor for an extended period,
	 * the connection is marked dead so the orchestrator's existing
	 * respawn machinery can replace it with a fresh TCP session.
	 * Reset when cur grows above floor again (either via normal
	 * window completion or the Part C time-probe). */
	uint32_t consecutive_bp_at_floor; /* backpressure events while cur==floor */
	double   time_first_at_floor;     /* monotime_double() when cur first hit
	                                   * floor in the current degradation run;
	                                   * 0 if cur > floor */
};

/* One file parked for the classic post-transfer verify phase. */
struct sftp_verify_pending_entry {
	char *local_path;
	char *remote_path;
	off_t size;			/* bytes; sized at phase start for the meter */
	int   local_is_target;		/* 0 = upload, 1 = download */
};

struct bwlimit;		/* misc.h; kept opaque here */

/*
 * HPN per-connection state.  Embedded in struct sftp_conn as a single
 * pointer so the upstream struct definition gains exactly one line.
 */
struct sftp_hpn_conn {
	/* Set when an unrecoverable I/O error occurs; prevents further
	 * send/recv on this connection. */
	int              dead;

	/* Set when a protocol-level violation is detected (ID mismatch,
	 * unexpected packet type). Distinct from dead: this indicates
	 * possible MITM attack or serious server corruption, not a simple
	 * connection drop.  In parallel mode the orchestrator aborts the
	 * entire transfer rather than retrying. */
	int              protocol_violation;

	/* HPN: sticky "server refused with PERMISSION_DENIED" signal, set by
	 * get_status/get_handle and read by the parallel worker's retry
	 * deciders to set u->no_retry (a refusal is permanent).  Survives the
	 * post-failure CLOSE; reset at each unit/batch status-read boundary.
	 * Migrated here from struct sftp_conn. */
	int              saw_perm_denied;

	/* HPN: the refusal above was tagged by the server as a -P/-p
	 * request-policy denial (HPN_POLICY_DENIED_TAG), not a filesystem
	 * error, letting the bundle path abort the whole transfer.  Reset at
	 * each bundle attempt.  Migrated here from struct sftp_conn. */
	int              saw_policy_denied;

	/* HPN: most recent SSH2_FXP_STATUS code seen by get_status/get_handle;
	 * lets callers classify permanent failures.  Migrated from
	 * struct sftp_conn. */
	u_int            last_status;

	/* HPN: operator's per-user parallel-worker cap advertised by the server
	 * in SSH2_FXP_VERSION (hpn-max-workers@hpnssh.org).  -1 = not advertised
	 * (stock/non-HPN server); 0 = advertised with no cap; N>0 = the cap.
	 * Migrated from struct sftp_conn. */
	int              hpn_max_workers_cap;

	/* Incremental progress hook for the parallel orchestrator.
	 * Updated atomically per chunk during transfer; NULL in normal
	 * (non-parallel) mode. */
	volatile uint64_t *live_counter;

	/* Cooperative-yield hook for the parallel orchestrator's tail
	 * redistribution (phase C).  When the detector confirms this
	 * worker is the lagging endgame holder, the reporter sets the
	 * flag; the range transfer loops stop issuing NEW requests/writes,
	 * drain what is already in flight, and return with acked_out at
	 * the yield line so the caller requeues only the untouched
	 * remainder.  Voluntary wind-down only - never a kill; NULL in
	 * normal (non-parallel) mode. */
	volatile int *yield_flag;

	/* Watchdog pause: monotonic-ms deadline before which the parallel
	 * orchestrator's inactivity-based heuristics (born-dead, silence,
	 * isolation, throughput-outlier, born-slow) suppress for this
	 * worker.  The SSH-child-gone check still fires regardless.  Set by
	 * sftp_hpn_watchdog_pause() before a long non-byte-transfer
	 * operation (verify-hash, fsync after large write, bundle
	 * accumulate/extract, etc.), cleared by sftp_hpn_watchdog_resume()
	 * or auto-expires.  Atomic load/store; safe from any thread. */
	volatile uint64_t watchdog_pause_until_ms;

	/* HPNVerifyTransfer state, propagated from ssh_config at sftp_init
	 * time.  Gates the inline source-hash tee (so the post-transfer verify
	 * has a source hash) and the post-transfer integrity check itself. */
	int              verify_transfer_enabled;

	/* Auto-repair (#6) settings for the single-conn (classic) verify phase,
	 * resolved once in sftp.c from -X VerifyRepair / HPN_NO_VERIFY_REPAIR /
	 * HPN_VERIFY_REPAIR_ATTEMPTS - the conn-side analogue of the
	 * orchestrator's p->verify_repair_{enabled,attempts}.  The shared core
	 * (sftp_hpn_verify_repair) reads these on this path. */
	int              verify_repair_enabled;
	int              verify_repair_attempts;

	/* Classic post-transfer verify phase: the single-conn analogue of the
	 * -j orchestrator's verify phase.  sftp_upload/sftp_download PARK each
	 * transferred file (verify_pending); after the command's transfers
	 * finish, sftp_conn_verify_run_phase() verifies them all and appends any
	 * mismatch's remote path to verify_failed_paths, which
	 * sftp_conn_drain_verify_failures() then hands to sftp.c for the run
	 * summary + exit code.  Plain arrays (main conn is single-threaded, no
	 * mutex) - deliberately not hpn_strlist, which lives in the parallel
	 * module that scp does not link.  Both empty on worker conns: the
	 * orchestrator phase verifies those. */
	struct sftp_verify_pending_entry *verify_pending;
	size_t           verify_pending_count;
	size_t           verify_pending_cap;
	char           **verify_failed_paths;
	size_t           verify_failed_count;

	/* Cumulative SFTP payload bytes that actually crossed the wire on
	 * this connection: incremented after each successful SSH2_FXP_WRITE
	 * send (uploads) and SSH2_FXP_DATA payload receive (downloads).
	 * Excludes SSH framing and cipher overhead and is uncorrelated with
	 * the worker's "work units completed" byte count, which counts the
	 * full unit size even when chunked-resume verified the data already
	 * matched on the remote (zero wire bytes).  Read by the parallel
	 * orchestrator at session end to report "X resolved, Y wired" so the
	 * throughput line reflects what actually moved, not what was visited.
	 * Atomic add; safe from any thread. */
	volatile uint64_t bytes_wired_payload;

	/*
	 * Unified hash-work accounting (HPN; project_hash_work_meter_design).
	 * Every hash phase - -Z resume check, -V verify, auto-repair - meters
	 * in WORK-BYTES: checking one byte of overlap costs 2 (one local, one
	 * remote), so a two-leg op's total is 2x its span and BOTH legs feed
	 * the same monotone counter (done = leg_base + leg progress).  The
	 * stamp is refreshed by every progress write: the watchdog's kill
	 * classifiers treat a fresh stamp as "provably hashing", and the
	 * reporter treats a stale one (~3s) as op-gone - engines do NOT need
	 * exit-point discipline; the explicit end lives at unit-completion
	 * sites.  Atomic; any thread.
	 */
	volatile uint64_t hash_work_done;
	volatile uint64_t hash_work_total;
	volatile uint64_t hash_work_leg_base;
	volatile uint64_t hash_work_stamp_ms;

	/* Serial meter bridge: when registered, every progress write also
	 * lands meter_base + done at this location, so a meter counter
	 * advances while the single thread is blocked in an engine.
	 * meter_base carries completed prior ops (multi-file serial verify).
	 * Registered/cleared only by serial call sites (parallel workers run
	 * with showprogress off and never set it). */
	volatile off_t  *hash_meter_ctr;
	volatile uint64_t hash_meter_base;

	/* HPNLustreStripeCount resolved from ssh_config at sftp_init time.
	 *   -1  : auto (use -j N as the desired count when destination is
	 *         on Lustre and currently has stripe_count < N)
	 *    0  : feature disabled - never call hpn-file-layout
	 *   >0  : explicit override; ask for this stripe count when the
	 *         destination is Lustre and currently has stripe_count <
	 *         this value
	 * Read by the dir-layout decision site once per transfer (top-level
	 * destination dir). */
	int              lustre_stripe_count;

	/* Latched after the first non-success reply to hpn-file-layout on
	 * this connection.  Subsequent dir-layout calls skip the wire round
	 * trip entirely so a single declined / unsupported reply doesn't
	 * generate per-directory log spam.  Resets when a new conn is built
	 * (a new sftp invocation). */
	int              layout_set_declined;

	/* Adaptive read-ahead controller - sizes the in-flight request
	 * window to the path BDP instead of a flat num_requests. */
	struct sftp_rdahead rd;

#ifdef HPN_FAULT_INJECTION
	/* SFTP_FAULT_INJECT=bytes[:max_kills]   - simulates connection death.
	 * SFTP_FAULT_PROTOCOL=bytes[:max_kills] - simulates protocol violation. */
	/* FAULT-INJ: test-scaffolding state (sftp-fault-inject.c); inert
	 * in normal builds. */
	uint64_t fault_after_bytes;    /* die after N bytes sent (0=off) */
	uint64_t fault_pv_after_bytes; /* protocol violation after N bytes (0=off) */
	uint64_t fault_bytes_sent;     /* bytes sent so far on this connection */
	uint64_t fault_throttle_after_bytes; /* throttle after N bytes (0=off) */
	int      fault_throttling;     /* this conn holds a throttle slot */
	uint64_t fault_recv_throttle_after_bytes; /* recv-throttle after N
						    * bytes received (0=off) */
	uint64_t fault_bytes_recvd;    /* bytes received so far on this conn */
	int      fault_recv_throttling; /* this conn holds a recv-throttle slot */
#endif

	/* HPNVerifyTransfer (1b): inline source-hash accumulator.  When the
	 * upload computes the source XXH3 as it reads (post-transfer verify
	 * enabled, whole-file upload), the result lands here so the verify
	 * step consumes it instead of re-reading the source.  state is the
	 * streaming XXH3 handle (void* to keep this header xxhash-free; NULL
	 * when inactive); valid is set once finished cleanly. */
	void     *verify_src_state;
	uint64_t  verify_src_bytes;
	uint64_t  verify_src_hash;
	int       verify_src_valid;
	int       verify_src_failed;

	/* Adaptive upload pacing: ack-rate-driven issue ceiling.  WRITE
	 * status returns arrive at the receiver's true sustained drain rate
	 * (~1 RTT delayed); pacing sends to slightly above that rate keeps
	 * the destination's page cache out of the dirty-limit cliff that
	 * otherwise collapses single-stream high-RTT uploads into a
	 * stall/recover duty cycle.  See sftp_hpn_pace_ack() for the
	 * control law; state is per-connection (per-worker in parallel
	 * mode).  bw is the reused -l token bucket (struct bwlimit),
	 * allocated on first activation. */
	struct {
		int      enabled;      /* -X Pacing=no clears (default on) */
		int      active;       /* grace passed; limiter engaged */
		uint64_t acks;         /* WRITE acks seen (startup grace) */
		uint64_t first_ack_ms; /* monotime_ms of first ack */
		uint64_t bucket_bytes; /* acked bytes in current bucket */
		uint64_t bucket_start_ms; /* monotime_ms the bucket opened */
		/* Sliding window of per-second delivered rates (bytes/sec);
		 * the ceiling is HEADROOM x the MEAN of these, so stall
		 * seconds pull the estimate toward the sink's sustained
		 * rate.  Samples during slow-start are excised. */
		uint64_t rate_ring[10];
		u_int    ring_idx;
		uint64_t last_arm_ms;  /* monotime_ms of last actuator arm */
		uint64_t bw_rate_bits; /* programmed actuator rate, bits/s */
		uint64_t reclaim_bytes; /* last ceiling armed while rising;
		                         * post-famine reclaim target */
		struct bwlimit *bw;    /* actuator; NULL until activated */
	} pace;

	/* Serial-path bundling configuration (HPNUseBundle, HPNBundleSize,
	 * HPNWriterPool - resolved from ssh_config by the client program
	 * via sftp_conn_set_bundle_config).  Mirrors the parallel
	 * planner's pcfg fields so both modes obey the same knobs.
	 * server_cant latches after a SERVER_CANT bundle result: the
	 * session stops offering bundles and drives files individually. */
	struct {
		int      use;         /* HPNUseBundle; default 1 */
		int      writer_pool; /* HPNWriterPool; default 1 */
		uint64_t size;        /* HPNBundleSize bytes; 0 = default */
		int      server_cant; /* latched: server refused a bundle */
	} bundle_cfg;
};

/*
 * Serial-path bundle accumulator: the recursive upload walk in
 * sftp-client.c collects bundle-eligible small files here and ships
 * each batch as one hpn-bundle stream on the session connection.
 * Implementation in sftp-hpn-client.c; eligibility policy shared with
 * the parallel planner via sftp-hpn-bundle.h.
 */
struct sftp_hpn_bundle_acc {
	char **src_paths;	/* upload: local; download: remote */
	char **dst_paths;	/* upload: remote; download: local */
	long long *sizes;	/* per-member bytes, for TransferLog */
	int n, cap;
	uint64_t bytes;		/* accumulated FRAMED bytes (header+path+
				 * payload per member, matching the
				 * parallel producer's accounting) */
	uint64_t path_bytes;	/* download only: fetch-request path cost */
	uint64_t target;	/* flush threshold (HPNBundleSize) */
	int is_download;
	int enabled;
};

/*
 * Shared directory handling for the recursive transfer walks (serial
 * AND parallel-producer; one implementation - the hand-copied versions
 * measurably diverged).  ensure_* creates the destination directory
 * (remote for uploads, local for downloads).
 *
 * Directory ATTRIBUTE application (setstat / utimes+chmod) is DEFERRED
 * to restore stock OpenSSH's perms-AFTER-data ordering, which small-file
 * bundling broke.  Stock applies a directory's final mode after its
 * files are uploaded, so a restrictive mode (e.g. 0555) is set only
 * once the directory no longer needs writing into.  Bundling accumulates
 * files and writes them LATER at bundle flush, so an inline setstat ran
 * perms-BEFORE-data and could lose files under -p into a read-only
 * directory.  The walk records each directory here and the owner applies
 * the list only after all file content has landed:
 *   serial:   end of sftp_upload_dir / sftp_download_dir.
 *   parallel: end of sftp_parallel_wait, after every unit has drained.
 *
 * Applied at END OF TRANSFER, not per-directory: bundles span directory
 * boundaries, so a directory's files are not guaranteed written when the
 * walk leaves it - only after the final flush.  Tradeoffs (accepted,
 * bounded, never data-loss): the list costs one entry per directory for
 * the whole transfer (memory on pathological million-dir trees), and an
 * interrupted transfer leaves directories with the temporary writable
 * perms until a re-run completes.  Files need no such deferral - they
 * are written through an open fd and fchmod'd last, so the parent-dir
 * write check at create time is the only ordering hazard.  See
 * hpn-serial-bundling-design.md section 9 for the full rationale and the
 * per-bundle-completion mitigation if the tradeoffs ever bite.
 */
struct sftp_hpn_dirattr {
	char   *path;
	Attrib  a;          /* desired final attrs (remote) */
	mode_t  mode;       /* desired final mode (local) */
	int     is_local;   /* 0: remote setstat; 1: local utimes+chmod */
	int     set_times;  /* local: dirattrib had ACMODTIME */
	int64_t atime, mtime;
};

struct sftp_hpn_dirattr_list {
	struct sftp_hpn_dirattr *v;
	int n, cap;
};

struct sftp_conn;
int  sftp_hpn_ensure_remote_dir(struct sftp_conn *conn, const char *dst,
    Attrib *a, int *created);
int  sftp_hpn_ensure_local_dir(const char *dst, Attrib *dirattrib,
    mode_t *mode_out, mode_t *tmpmode_out);
void sftp_hpn_dirattrs_defer_remote(struct sftp_hpn_dirattr_list *dl,
    const char *path, const Attrib *a);
void sftp_hpn_dirattrs_defer_local(struct sftp_hpn_dirattr_list *dl,
    const char *path, mode_t mode, mode_t tmpmode, const Attrib *dirattrib);
void sftp_hpn_dirattrs_apply(struct sftp_conn *conn,
    struct sftp_hpn_dirattr_list *dl);
void sftp_hpn_dirattrs_free(struct sftp_hpn_dirattr_list *dl);

/*
 * struct sftp_tree_dl_sink is the per-mode callback set for the download walk.
 * It uses the same callback-table pattern documented on struct
 * sftp_upload_sink below. That comment explains why the driver cannot branch
 * on a mode flag and how a callback recovers its context. The download
 * differences are:
 *
 *   - It drives downloads. Both sftp_tree_download_consume (one streamed
 *     discover-tree enumeration) and sftp_readdir_download_consume (the
 *     recursive readdir fallback) use it.
 *   - Local directories are created one at a time with a cheap mkdir, so a
 *     single make_dir callback both creates the directory and defers its
 *     attrs. There is no batch-create or before_mkdir step like upload has.
 *   - The plug-in points are make_dir, xfer_file (download or bundle-fetch
 *     versus submit to the fleet), fail, and aborting.
 */
struct sftp_tree_dl_sink {
	/* Create the local directory dst for a dir entry (remote path src,
	 * attrs a) and defer its attributes; src is for progress output only.
	 * Returns 0, or -1 (having recorded failure). */
	int  (*make_dir)(struct sftp_tree_dl_sink *sink, const char *src,
	         const char *dst, Attrib *a);
	/* Transfer regular file src -> dst (attrs a).  Returns 0 or -1. */
	int  (*xfer_file)(struct sftp_tree_dl_sink *sink, const char *src,
	         const char *dst, Attrib *a);
	/* Record a per-entry failure (reason is a short static string). */
	void (*fail)(struct sftp_tree_dl_sink *sink, const char *path,
	         const char *reason);
	/* True when the walk should stop (interrupt / fleet abort). */
	int  (*aborting)(struct sftp_tree_dl_sink *sink);
};

/*
 * Enumerate the remote subtree at src via hpn-discover-tree and replay each
 * entry through sink as it streams in: create dst and every discovered
 * directory inline, transfer every regular file, skip symlinks/non-regular
 * entries, surface ERROR records.  dirattrib is the root's attrs (NULL ->
 * stat it).  defer_file_xfer selects when files move: 0 transfers each file
 * inline as its record arrives (parallel workers, on their own connections);
 * 1 queues files and transfers them after the stream drains (serial download
 * and crossload, whose transfers share the discover-tree stream's
 * connection).  Returns 0, or -1 if any entry failed.
 */
int  sftp_tree_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, Attrib *dirattrib, int follow_link_flag,
    int defer_file_xfer, struct sftp_tree_dl_sink *sink);

/*
 * Fallback recursive readdir download driver, used when the server lacks
 * hpn-discover-tree.  Enumerates src one directory at a time via sftp_readdir
 * and replays each entry through the same sink as sftp_tree_download_consume.
 * Recursive (calls itself per subdirectory); max_depth caps the recursion and
 * follow_link_flag mirrors the walks' dormant -L handling.  Returns 0, or -1
 * if any entry failed.
 */
int  sftp_readdir_download_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, Attrib *dirattrib,
    int follow_link_flag, struct sftp_tree_dl_sink *sink);

struct stat;

/*
 * struct sftp_upload_sink is the small set of per-mode callbacks the shared
 * upload driver calls out to.
 *
 * sftp_upload_walk_consume() below does everything the serial and parallel
 * uploads do the same way. It walks the local directory, collects
 * subdirectories, batch-creates them on the control connection, and recurses.
 * A few steps differ by mode. A file is transferred differently (serial
 * bundles it or calls sftp_upload, parallel submits it to the worker fleet),
 * and the per-directory bookkeeping differs (progress print, Lustre layout,
 * worker phases, which deferred-attrs list to use, how to record a failure,
 * how to detect an abort).
 *
 * The driver cannot just branch on a mode flag. The serial and parallel
 * implementations live in different files and call file-local functions the
 * driver cannot see. So each mode hands those steps to the driver as the
 * callbacks in this struct.
 *
 * A mode embeds this struct as the first member of its own context struct
 * (serial_ul_sink or parallel_ul_sink). That context also carries the mode's
 * data, such as the connection, bundle accumulator, worker set, and flags.
 * The driver only ever holds a struct sftp_upload_sink pointer. Each callback
 * casts that pointer back to the full context struct to reach its own data.
 * The cast is safe because base is the first member, so the two share an
 * address. sftp_tree_dl_sink is the download twin.
 */
struct sftp_upload_sink {
	/* Once per directory, after its attrs are known and before its
	 * contents are enumerated: serial prints "Entering src"; parallel
	 * applies the Lustre layout to dst and enters the enumerate phase. */
	void (*enter_dir)(struct sftp_upload_sink *sink, const char *src,
	         const char *dst);
	/* Transfer a regular local file src -> dst (local stat sb).  0 or -1. */
	int  (*xfer_file)(struct sftp_upload_sink *sink, const char *src,
	         const char *dst, const struct stat *sb);
	/* Before the pipelined mkdir batch (parallel enters the mkdir phase). */
	void (*before_mkdir)(struct sftp_upload_sink *sink);
	/* Defer this directory's final remote attrs (gated created||preserve). */
	void (*defer_dir)(struct sftp_upload_sink *sink, const char *dst,
	         const Attrib *a, int created);
	/* Record a per-entry failure (reason a short static string). */
	void (*fail)(struct sftp_upload_sink *sink, const char *path,
	         const char *reason);
	/* True when the walk should stop (interrupt / fleet abort). */
	int  (*aborting)(struct sftp_upload_sink *sink);
};

/*
 * Enumerate the local subtree at src, hand files to sink, batch-create the
 * discovered subdirectories on the control connection, and recurse (each
 * child gets its mkdir "created" flag).  dst must already exist (the caller
 * creates the root; each level creates its children).  Returns 0, or -1 if
 * any entry failed.
 */
int  sftp_upload_walk_consume(struct sftp_conn *conn, const char *src,
    const char *dst, int depth, int max_depth, int created, int preserve_flag,
    int follow_link_flag, struct sftp_upload_sink *sink);

void sftp_hpn_bundle_acc_init(struct sftp_hpn_bundle_acc *acc,
    struct sftp_conn *conn, int resume, int is_download);
int sftp_hpn_bundle_acc_eligible(struct sftp_hpn_bundle_acc *acc,
    uint64_t size);
int sftp_hpn_bundle_acc_add(struct sftp_hpn_bundle_acc *acc,
    const char *src, const char *dst, long long size);
int sftp_hpn_bundle_acc_flush(struct sftp_conn *conn,
    struct sftp_hpn_bundle_acc *acc, int preserve_flag, int print_flag,
    int verify, int fsync_flag, int inplace_flag);
void sftp_hpn_bundle_acc_free(struct sftp_hpn_bundle_acc *acc);

/*
 * HPNVerifyTransfer (1b) inline source-hash accumulator (sftp-hpn-verify.c).
 * arm:     begin a streaming XXH3 over the source bytes.
 * feed:    add bytes as the source is read so the hash reflects the
 *          on-disk source.
 * finish:  digest + mark valid; frees the streaming state.
 * dispose: abort with no result (partial/failed transfer); frees the state.
 * take:    consume the result iff it covers expect_bytes; 0 + *hash_out on
 *          success, -1 otherwise (caller re-reads the source).
 * All are no-ops when not armed / hpn==NULL.
 */
void sftp_hpn_src_arm(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_feed(struct sftp_hpn_conn *hpn, const u_char *buf, size_t len);
void sftp_hpn_src_finish(struct sftp_hpn_conn *hpn);
void sftp_hpn_src_dispose(struct sftp_hpn_conn *hpn);
int  sftp_hpn_src_take(struct sftp_hpn_conn *hpn, uint64_t expect_bytes,
	uint64_t *hash_out);

/*
 * Account `n` payload bytes that just left this connection on a
 * SSH2_FXP_WRITE (upload) or arrived on a SSH2_FXP_DATA (download).
 * Safe with hpn==NULL (no-op) and n==0 (no-op).  Atomic; safe from any
 * thread.  Read back via sftp_conn_bytes_wired() (sftp-client-internal.h).
 */
static inline void
sftp_hpn_bytes_wired_add(struct sftp_hpn_conn *hpn, uint64_t n)
{
	if (hpn == NULL || n == 0)
		return;
	__atomic_fetch_add(&hpn->bytes_wired_payload, n, __ATOMIC_RELAXED);
}

/* Allocate and initialise a zeroed sftp_hpn_conn. Never returns NULL. */
/* Allocate and initialise a zeroed sftp_hpn_conn. Never returns NULL. */
struct sftp_hpn_conn *sftp_hpn_conn_init(void);

/* Free an sftp_hpn_conn.  Safe to call with NULL. */
void sftp_hpn_conn_free(struct sftp_hpn_conn *);

/* Adaptive upload pacing (see the pace member above).  set_enabled is the
 * -X Pacing= switch, consulted at conn init; ack feeds one WRITE status of
 * len payload bytes to the estimator; bwlimit returns the token bucket the
 * outbound path should apply - the TIGHTER of the adaptive ceiling and the
 * user's explicit -l (min composition) - or NULL for no limit. */
void sftp_hpn_pace_set_enabled(int on);
void sftp_hpn_pace_ack(struct sftp_hpn_conn *hpn, size_t len,
    u_int num_requests);
struct bwlimit *sftp_hpn_pace_bwlimit(struct sftp_hpn_conn *hpn,
    struct bwlimit *user_bw, uint64_t user_rate);

/*
 * Internal helpers called by the thin public-API wrappers in sftp-client.c.
 * These operate on struct sftp_hpn_conn directly so sftp-hpn-client.c has
 * no dependency on the opaque struct sftp_conn.
 */
int  sftp_hpn_is_dead(struct sftp_hpn_conn *);
int  sftp_hpn_is_protocol_violation(struct sftp_hpn_conn *);
void sftp_hpn_set_protocol_violation(struct sftp_hpn_conn *);
void sftp_hpn_set_live_counter(struct sftp_hpn_conn *, volatile uint64_t *);
void sftp_hpn_set_yield_flag(struct sftp_hpn_conn *, volatile int *);

/*
 * Adaptive read-ahead (HPN).  init() seeds the controller from the
 * connection's num_requests (the -R cap); account() feeds it bytes as each
 * request completes and re-sizes the window at window boundaries; depth()
 * returns the current target in-flight depth, or 0 when adaptation is
 * disabled (HPN_RDAHEAD=fixed) so the caller falls back to its fixed
 * num_requests pipeline.
 */
void     sftp_hpn_rdahead_init(struct sftp_hpn_conn *, uint32_t cap);
void     sftp_hpn_rdahead_account(struct sftp_hpn_conn *, size_t nbytes);
uint32_t sftp_hpn_rdahead_depth(struct sftp_hpn_conn *);
/* Higher-level call-site helpers (collapse the repeated cap / ramp logic):
 * _cap = depth-or-fallback for the upload outstanding-cap sites; _window =
 * account + (adaptive depth or legacy +1 ramp) for the download ramp sites. */
uint32_t sftp_hpn_rdahead_cap(struct sftp_hpn_conn *, uint32_t fallback);
uint32_t sftp_hpn_rdahead_window(struct sftp_hpn_conn *, size_t nbytes,
             uint32_t cur, uint32_t cap);

/*
 * Wedge-detection threshold (seconds).  A STATUS read that blocks longer
 * than this is treated as evidence the path is wedged: the caller invokes
 * sftp_hpn_rdahead_backpressure_signal() and the controller multiplicatively
 * decreases `cur` (analogous to TCP cwnd /= 2 on RTO).
 *
 * 10 s catches every wedge the 2026-05-30 campaign captured (all blocked
 * > 90 s) while being above the 3–8 s STATUS latencies legitimately
 * produced by Lustre OST contention.  Without this signal the grow-only
 * controller settles high and never recovers when conditions degrade
 * mid-transfer; see [[bundle-inflight-backpressure]] in project memory.
 *
 * NB: this whole layer is application-level congestion control on top of
 * TCP's, because the SFTP client can't see the SSH transport socket's
 * TCP_INFO from across the hpnssh-subprocess boundary.  See
 * [[hpn-code-organization-vision]] and [[post-18-10-tcp-info-self-monitor]]
 * for the architectural direction (TCP_INFO integration) that would
 * eventually subsume this.
 *
 * Used by: do_upload_body, sftp_upload_range, bundle_drain_n.
 */
#define SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC  10.0

/* Backpressure signal: invoke when a STATUS read blocked longer than
 * SFTP_HPN_RDAHEAD_BP_THRESHOLD_SEC.  Halves the in-flight depth
 * (clamped to floor) and clears `settled` so re-probing resumes.  No-op
 * when the controller is disabled.  Threshold detection is the caller's
 * responsibility. */
void     sftp_hpn_rdahead_backpressure_signal(struct sftp_hpn_conn *);

/*
 * Part D - persistent-degradation reap thresholds.  When the controller
 * has been forced to floor by repeated backpressure events (TCP wedge,
 * sustained server slowdown, etc.) and isn't recovering, mark the
 * connection dead so the orchestrator can replace it with a fresh TCP
 * session.  Either threshold suffices:
 *
 *   _BP_COUNT      consecutive backpressure events while cur==floor
 *   _SEC           total wallclock time spent at floor in this run
 *
 * Chosen values are deliberately conservative - the goal is to give a
 * truly-broken connection a way out without thrashing legitimate
 * transient slowdowns.  5 events of Part B firing at floor is well past
 * what any healthy path produces; 60 s at floor without recovery means
 * the floor-doubling probes (Part C) haven't found any headroom either.
 *
 * The reap signal itself feeds the existing orchestrator respawn
 * machinery (cooldowns, total_respawns, BORN_SLOW budgets) - Part D
 * adds a trigger, not a parallel respawn path.  See the design
 * discussion at reporter_dispatch_respawns in sftp-parallel.c for why
 * thrash protection stays session-wide for now.
 */
#define SFTP_HPN_RDAHEAD_REAP_BP_COUNT       5
#define SFTP_HPN_RDAHEAD_REAP_TIME_AT_FLOOR_SEC  60.0

/*
 * Mark a connection as dead due to a non-recoverable error, log the
 * cause at ERROR level for diagnostic visibility, but do NOT terminate
 * the process. Used by the SFTP RPC layer to replace fatal() in code
 * paths that may run inside a parallel-streams worker, where a true
 * fatal() would crash the entire orchestrator process and take down
 * all other workers.
 *
 * After this is called, sftp_hpn_is_dead() returns true; subsequent
 * RPC calls on this connection short-circuit to error returns. Callers
 * must propagate the failure via their own return value, OR rely on
 * the worker thread's per-unit conn->dead post-check to abandon the
 * unit and exit so the watchdog can respawn.
 *
 * Format string matches fatal() for mechanical conversion.
 */
void sftp_hpn_conn_die(struct sftp_hpn_conn *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));



/* ── hpn-file-layout@hpnssh.org client helper (EXPERIMENTAL) ─────────────
 *
 * Ask the server to set a Lustre stripe count on `path` (must be an
 * existing directory).  Subsequent file creations in that directory
 * inherit the layout - including files unpacked from a bundle stream.
 *
 * Returns one of HPN_FILE_LAYOUT_OK / _NOT_FS / _PERM / _FAIL.  The caller
 * is responsible for:
 *   - gating on sftp_conn_has_file_layout(conn) before calling
 *   - gating on sftp_conn_layout_set_declined(conn) - a previous
 *     non-success reply latches that flag and subsequent calls should
 *     skip the wire round trip
 *   - latching the flag via sftp_conn_set_layout_set_declined(conn, 1)
 *     on any non-OK reply so future calls short-circuit
 *
 * `*applied_out`, if non-NULL, is set to the stripe count the server
 * reported applying (may be silently clamped by Lustre below the
 * requested value if the filesystem has fewer OSTs).
 */
int sftp_hpn_set_file_layout(struct sftp_conn *conn, const char *path,
    u_int32_t stripe_count, u_int32_t small_threshold, u_int32_t *applied_out,
    u_int32_t *layout_kind_out);

/*
 * Watchdog pause: tell the parallel orchestrator's worker-fault watchdog
 * that this worker is about to spend up to `seconds` doing legitimate
 * non-byte-transfer work (typically a verify-hash phase, but the primitive
 * is generic - any code path that knows it will be quiet on the SFTP wire
 * for an extended interval can use it).  The watchdog suppresses its
 * inactivity-based kills (born-dead, silence, isolation escalation,
 * throughput-outlier, born-slow) until the deadline expires or
 * sftp_hpn_watchdog_resume() is called.  The SSH-child-gone check continues
 * to fire regardless - pause cannot save a worker whose ssh transport has
 * physically exited.
 *
 * Multiple calls extend the pause to the LATER of the existing deadline
 * and the new deadline; a shorter pause can never shrink a longer one
 * already in flight.  Auto-expires at the deadline if resume is never
 * called, bounding any "forgot to clear it" mistake to the declared
 * duration.  Safe to call from any thread.  No-op when hpn is NULL.
 *
 * Pass HPN_HEARTBEAT_REFRESH_SEC (from sftp-hpn-server.h) for the initial
 * grace window when entering a hash extension call; the server emits
 * heartbeats during long hashes and each one refreshes the pause for
 * another HPN_HEARTBEAT_REFRESH_SEC - so the watchdog tracks actual
 * server progress rather than a size-derived prediction that fell apart
 * under parallel-worker disk contention.
 */
void sftp_hpn_watchdog_pause(struct sftp_hpn_conn *hpn, unsigned int seconds);
void sftp_hpn_watchdog_resume(struct sftp_hpn_conn *hpn);

/*
 * Compute XXH3_64bits over bytes [offset, offset+length) of the open fd.
 * Seeks before reading; the fd's position after return is undefined (the
 * caller is expected to lseek again before any subsequent read/write).
 * Returns 0 on success and writes the hash to *hash_out; -1 on any I/O
 * or hash-state error.
 */




#include "sftp-hpn-verify.h"

#endif /* _SFTP_CLIENT_HPN_H */
