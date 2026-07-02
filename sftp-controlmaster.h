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

/*
 * ControlMaster lifecycle helper for the parallel-streams sftp client.
 *
 * Spawns and tears down an "hpnssh -M -N -S <socket>" sentinel process used
 * to amortize authentication across worker connections. Workers do NOT data-
 * plane through this socket (we use Pattern B: each worker opens its own TCP
 * connection); the master exists to seed agent/credential state once, so
 * subsequent worker auths are cheap.
 *
 * No threading inside this module. The orchestrator owns the threading and
 * calls these functions from a single thread.
 */

#ifndef _SFTP_CONTROLMASTER_H
#define _SFTP_CONTROLMASTER_H

struct sftp_controlmaster;

struct sftp_cm_config {
	const char  *host;        /* required: user@host or host */
	const char  *port;        /* "22" / "3940" / NULL = default */
	const char  *ssh_binary;  /* /path/to/hpnssh / NULL = "hpnssh" */
	const char  *identity;    /* -i path / NULL = ssh defaults */
	const char  *known_hosts; /* UserKnownHostsFile= / NULL = default */
	const char  *config_file; /* -F path / NULL = ~/.ssh/config */
	int          verbose;     /* nonzero = pass -v to master */
	int          timeout_sec; /* wait for auth, 0 = 30 default */
	char *const *extra_argv;  /* additional -o KEY=VALUE flags,
				   * NULL-terminated; may be NULL */
};

/*
 * Spawn a ControlMaster. Blocks until the master is authenticated and its
 * control socket is responding to "ssh -O check", or until auth fails /
 * timeout elapses. Returns NULL on failure (callers should warn and fall
 * back to single-stream mode). Errors are logged via the project's log_*
 * facilities.
 */
struct sftp_controlmaster *sftp_cm_start(const struct sftp_cm_config *cfg);

/* Path to the master's control socket. Caller does not free. */
const char *sftp_cm_socket(struct sftp_controlmaster *cm);

/* 1 if master process appears to be running, 0 otherwise. */
int sftp_cm_alive(struct sftp_controlmaster *cm);

/*
 * Tear down the master: send "ssh -O exit", wait for it to die, escalate
 * to SIGTERM/SIGKILL if needed, unlink socket, rmdir its private temp dir,
 * free the struct. Idempotent.
 */
void sftp_cm_stop(struct sftp_controlmaster *cm);

#endif /* _SFTP_CONTROLMASTER_H */
