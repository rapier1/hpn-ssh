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
