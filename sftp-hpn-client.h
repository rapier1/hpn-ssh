/* sftp-hpn-client.h — HPN-SSH extensions to the SFTP client connection.
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
 * outstanding 128 KB requests — ~128 MB in flight per connection.  The
 * receive side must buffer all of it, so on a fat pipe with N parallel
 * workers process RSS and the kernel SO_RCVBUF balloon into the GB range,
 * far past what throughput actually needs.
 *
 * This controller instead probes for the SMALLEST depth that saturates the
 * path.  Over a sliding window of one depth's worth of completed requests it
 * measures app-layer throughput, then multiplicatively grows the depth (x2)
 * while throughput keeps rising (an RTT-bound ramp — growing by 1 would take
 * thousands of RTTs to fill a fat pipe), and settles at the last depth that
 * still gained once throughput plateaus (the BDP knee); a deeper pipe that
 * reduces throughput (overshoot) likewise falls back to that last-good depth.
 * -R stays a hard ceiling.  Per-connection, so each parallel worker tunes
 * itself.  App-layer only — no TCP_INFO dependency, portable across every OS
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
	int      settled;     /* 1 once the knee is found — stop probing */
	int      enabled;     /* 0 => legacy fixed depth (HPN_RDAHEAD=fixed) */
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

	/* Adaptive read-ahead controller — sizes the in-flight request
	 * window to the path BDP instead of a flat num_requests. */
	struct sftp_rdahead rd;

#ifdef HPN_FAULT_INJECTION
	/* SFTP_FAULT_INJECT=bytes[:max_kills]   — simulates connection death.
	 * SFTP_FAULT_PROTOCOL=bytes[:max_kills] — simulates protocol violation. */
	uint64_t fault_after_bytes;    /* die after N bytes sent (0=off) */
	uint64_t fault_pv_after_bytes; /* protocol violation after N bytes (0=off) */
	uint64_t fault_bytes_sent;     /* bytes sent so far on this connection */
#endif
};

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

#endif /* _SFTP_CLIENT_HPN_H */
