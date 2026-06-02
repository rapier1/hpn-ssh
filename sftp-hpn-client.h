/* sftp-hpn-client.h - HPN-SSH extensions to the SFTP client connection.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * All HPN-specific per-connection state is isolated here so that
 * sftp-client.c carries a minimal diff against upstream.
 *
 * Upstream merge note: sftp-client.c gains only:
 *   #include "sftp-hpn-client.h"
 *   struct sftp_hpn_conn *hpn;   (one field in struct sftp_conn)
 *   sftp_hpn_conn_init/free calls in sftp_init/sftp_free
 *   conn->hpn->dead  replacements for conn->dead
 *   conn->hpn->live_counter  replacements for conn->live_counter
 *   sftp_hpn_check_fault() call and fd-close in send_msg (TEST/DEBUG)
 */

#ifndef _SFTP_CLIENT_HPN_H
#define _SFTP_CLIENT_HPN_H

#include <stdint.h>

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

	/* Incremental progress hook for the parallel orchestrator.
	 * Updated atomically per chunk during transfer; NULL in normal
	 * (non-parallel) mode. */
	volatile uint64_t *live_counter;

	/* Watchdog pause: monotonic-ns deadline before which the parallel
	 * orchestrator's inactivity-based heuristics (born-dead, silence,
	 * isolation, throughput-outlier, born-slow) suppress for this
	 * worker.  The SSH-child-gone check still fires regardless.  Set by
	 * sftp_hpn_watchdog_pause() before a long non-byte-transfer
	 * operation (verify-hash, fsync after large write, bundle
	 * accumulate/extract, etc.), cleared by sftp_hpn_watchdog_resume()
	 * or auto-expires.  Atomic load/store; safe from any thread. */
	volatile uint64_t watchdog_pause_until_ns;

	/* HPNVerifyTransfer state, propagated from ssh_config at sftp_init
	 * time so the resume-decision hash callers can ask the server for
	 * the real XXH3 (HPN_CHECK_FILE_STRICT) instead of accepting the
	 * sparse-skip sentinel.  See [[verify-nomenclature-collision]] -
	 * HPNVerifyTransfer here also gates the resume-decision-flow
	 * trust optimisation, not just the post-transfer integrity check. */
	int              verify_transfer_enabled;

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

	/* Server-advertised HPNMaxBundleSize, parsed from the
	 * hpn-bundle-max-size@hpnssh.org extension in SSH_FXP_VERSION.
	 * 0 = absent (no cap advertised; client uses its own values and
	 * relies on the server's defensive bundle_per_cap rejection if
	 * any).  Non-zero values let the worker init clamp bundle_target_bytes
	 * proactively so the client never generates a bundle the server
	 * would reject mid-stream. */
	uint64_t         server_max_bundle_size;

	/* Adaptive read-ahead controller - sizes the in-flight request
	 * window to the path BDP instead of a flat num_requests. */
	struct sftp_rdahead rd;

#ifdef HPN_FAULT_INJECTION
	/* SFTP_FAULT_INJECT=bytes[:max_kills]   - simulates connection death.
	 * SFTP_FAULT_PROTOCOL=bytes[:max_kills] - simulates protocol violation. */
	uint64_t fault_after_bytes;    /* die after N bytes sent (0=off) */
	uint64_t fault_pv_after_bytes; /* protocol violation after N bytes (0=off) */
	uint64_t fault_bytes_sent;     /* bytes sent so far on this connection */
#endif
};

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

/*
 * Internal helpers called by the thin public-API wrappers in sftp-client.c.
 * These operate on struct sftp_hpn_conn directly so sftp-hpn-client.c has
 * no dependency on the opaque struct sftp_conn.
 */
int  sftp_hpn_is_dead(struct sftp_hpn_conn *);
int  sftp_hpn_is_protocol_violation(struct sftp_hpn_conn *);
void sftp_hpn_set_protocol_violation(struct sftp_hpn_conn *);
void sftp_hpn_set_live_counter(struct sftp_hpn_conn *, volatile uint64_t *);

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

#ifdef HPN_FAULT_INJECTION
/*
 * Called by send_msg after each successful write.  Tracks bytes sent and
 * fires the fault injection trigger when the threshold is reached.
 * Returns 0 normally; returns -1 and sets hpn->dead when a fault fires.
 * The caller is responsible for closing the file descriptors.
 */
int sftp_hpn_check_fault(struct sftp_hpn_conn *, size_t bytes);
#endif /* HPN_FAULT_INJECTION */

/* ── Chunked resume: sftp-hash-range@hpnssh.org client helpers ──────────────
 *
 * The chunked-resume code in sftp_upload / sftp_download builds a chunk
 * layout for a same-size source/destination pair, hashes each chunk locally,
 * asks the server to hash the same chunks via sftp-hash-range, then issues
 * a contiguous-run re-transfer for each set of mismatched chunks.  These two
 * helpers expose the wire-level hash query and the local-side XXH3 of a
 * range so the decision-flow code stays free of protocol details.
 *
 * `struct sftp_hash_range` is the parameter type for batched range queries;
 * the same struct describes both sides (client request, server response is
 * a parallel hashes[] array).
 */
struct sftp_hash_range {
	u_int64_t	off;
	u_int64_t	len;
};

struct sftp_conn;

/*
 * Ask the server to XXH3 each (off, len) range of `path` and write the N
 * resulting hashes into `hashes_out` (caller-allocated, n entries).
 *
 * All-or-nothing semantics: returns 0 only when the server returned all N
 * hashes successfully.  Returns -1 on any failure (server STATUS reply,
 * transport error, parse error, server lacks the extension); emits a
 * user-visible `logit_f` so the operator knows the chunked path bailed out
 * before the caller falls back to whole-file hashing or full re-transfer.
 *
 * Caller must verify `sftp_conn_has_hash_range(conn)` before calling; if
 * the extension is not advertised, this returns -1 immediately with a
 * debug log (the upstream lacks-extension case is not loud - it's expected).
 */
int sftp_hpn_hash_remote_ranges(struct sftp_conn *conn, const char *path,
    const struct sftp_hash_range *ranges, u_int n, u_int64_t *hashes_out);

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
    u_int32_t stripe_count, u_int32_t *applied_out);

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
int sftp_hpn_xxhash_local_range(int fd, u_int64_t offset, u_int64_t length,
    u_int64_t *hash_out);

/*
 * Attempt a chunked-resume upload when remote and local sizes match.
 *
 * Called from sftp_upload's size-match branch BEFORE the existing whole-file
 * hash gate.  Builds a chunk layout for [0, file_size), hashes each chunk
 * locally and remotely, then re-transfers each contiguous run of mismatched
 * chunks via sftp_upload_range.  This is the cost-saving half of the
 * sparse-hole gate: instead of trucating the whole file when sizes match
 * but content differs (which is what the existing path does), we transfer
 * only the chunks that actually need it.
 *
 * Decline conditions (fall through to existing full-file gate):
 *   - server does not advertise sftp-hash-range@hpnssh.org
 *   - file is below CHUNK_HASH_MIN_FILE_SIZE (overhead not worth it)
 *   - chunk count would exceed MAX_RANGES_PER_REQUEST
 *   - local hashing failed (I/O error on the source)
 *
 * Returns:
 *    1  all chunks matched - file is already identical, caller should
 *       skip (return 1 from sftp_upload).
 *    0  one or more chunks mismatched - they have been re-transferred
 *       successfully, caller should treat the upload as complete
 *       (return 0 from sftp_upload).
 *   -1  declined or any failure during the chunked path; caller should
 *       fall through to the existing whole-file hash gate.  User-visible
 *       warnings are emitted by the helpers (via logit_f) for server
 *       failures; quiet (debug) for "extension not available" and other
 *       declined-by-policy paths.
 *
 * The fd's position after return is undefined; caller re-seeks as needed.
 */
int sftp_hpn_try_chunked_resume_upload(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size);

/*
 * Symmetric download-side helper to sftp_hpn_try_chunked_resume_upload.
 *
 * Called from sftp_download's size-match branch BEFORE the existing whole-
 * file hash gate.  Hashes each chunk of `local_fd` (the partially-downloaded
 * destination) and of `remote_path` (the authoritative source), then for
 * each contiguous run of mismatched chunks calls sftp_download_range to
 * re-fetch only those bytes.  Same three-value return semantics as the
 * upload sibling; same decline conditions; same user-visible logit on
 * success and on server-side hash failure.
 *
 * Returns:
 *    1  all chunks matched - local file already identical to remote, caller
 *       should treat the resume as skip (sets skip_ret=1, goto resume_fail).
 *    0  one or more chunks mismatched and were re-fetched successfully,
 *       caller should treat the download as complete (sets skip_ret=0,
 *       goto resume_fail).
 *   -1  declined or failure; caller should fall through to the existing
 *       whole-file hash gate.
 *
 * The fd's position after return is undefined.
 */
int sftp_hpn_try_chunked_resume_download(struct sftp_conn *conn, int local_fd,
    const char *local_path, const char *remote_path, off_t file_size);

#endif /* _SFTP_CLIENT_HPN_H */
