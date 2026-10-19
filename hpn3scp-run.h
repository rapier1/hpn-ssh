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

/* hpn3scp-run.h - running the commands that hpnscp and hpn3scp start.
 *
 * hpn_run_status() runs the ssh that starts hpnscp on the source host and
 * passes the status frames it sends to the caller's hooks. hpnscp -R and
 * hpn3scp both launch through it. hpn_run_capture() and hpn_run_feed()
 * run the short commands of hpn3scp's host-key broker and shared login. */

#ifndef HPN3SCP_RUN_H
#define HPN3SCP_RUN_H

#include <sys/types.h>	/* for pid_t, size_t, and u_char */

/* Defined in misc.h and hpn-status-frame.h. Only pointers are needed
 * here, so callers need not include either. */
struct arglist;
struct hpns_hello;
struct hpns_progress;
struct hpns_end;
struct hpns_filefail;
struct hpns_filedone;

/* The caller's side of a status run. Any hook may be NULL, and every
 * hook gets ctx. The decoded-frame hooks get the validated struct. */
struct hpn_run_hooks {
	/* Unused today. A launcher that implements HPNS_CAP_PULL needs it,
	 * to read the source's caps before it sends any request. */
	void (*on_hello)(const struct hpns_hello *, void *ctx);
	void (*on_progress)(const struct hpns_progress *, void *ctx);
	void (*on_end)(const struct hpns_end *, void *ctx);
	/* Once per failed file, before on_end. The path is borrowed for the
	 * call only, so the hook copies or encodes it before returning. */
	void (*on_file_fail)(const struct hpns_filefail *, void *ctx);
	/* Once per file with its final transfer-log status, from a source
	 * armed with the "log" value. The path is borrowed as for
	 * on_file_fail. */
	void (*on_filedone)(const struct hpns_filedone *, void *ctx);
	/* About once a second on a quiet poll, and when a signal wakes the
	 * run, so a live meter can repaint */
	void (*on_tick)(void *ctx);
	/* once, when the run gives up on frames and passes output through */
	void (*on_degrade)(void *ctx);
	/* For every complete frame, decoded or not, as a sign that the source
	 * is still sending */
	void (*on_frame)(void *ctx);
	/* When about five seconds of PROGRESS frames in a row fail to decode,
	 * so the consumer can warn that progress cannot be read. A decoded
	 * PROGRESS restarts the count. */
	void (*on_mismatch)(void *ctx);
	/* where raw output goes after a degrade, or -1 to drop it */
	int		 passthrough_fd;
	/* Bytes written to the child's stdin, which is then closed. NULL
	 * leaves stdin as the child inherits it. */
	const u_char	*stdin_data;
	size_t		 stdin_len;	/* the length of stdin_data */
	void		*ctx;		/* passed to every hook */
};

/* What a status run saw, so a launcher can tell a source that read its
 * argument list from one that did not. */
struct hpn_run_result {
	int	got_hello;	/* a HELLO or PROGRESS frame arrived */
	int	exited;		/* the child exited, not killed by a signal */
	int	exit_status;	/* its exit status, when exited */
};

/* Fork and exec args->list[0] with a piped stdout, and pass its HPNS frames
 * to hooks. When hooks->stdin_data is set, it is written to the child's
 * stdin, which is then closed. A source that sends no frame within five
 * seconds, or whose stream fails to parse, has its output passed through
 * instead. If pidp is not NULL, it receives the child's pid after the fork
 * and -1 after the reap, so the caller's own signal handler can kill the
 * child. If res is not NULL, it reports whether a HELLO arrived and how
 * the child ended. Returns 0 if the child exited 0, and -1 otherwise. */
int	hpn_run_status(struct arglist *args, pid_t *pidp,
	    const struct hpn_run_hooks *hooks, struct hpn_run_result *res);

/* Fork and exec args->list[0] and collect its stdout, and its stderr too
 * when with_stderr is set, into buf, NUL-terminated. Output past buflen - 1
 * bytes is read and dropped, and sets *truncated when it is not NULL.
 * Returns 0 if the child exited 0 within timeout_ms, and -1 if it did not,
 * if reading failed, or if the timeout passed, which also sends it SIGTERM.
 * For short commands, not transfers. */
int	hpn_run_capture(struct arglist *args, char *buf, size_t buflen,
	    int timeout_ms, int *truncated, int with_stderr);

/* Fork and exec args->list[0], write input to its stdin, close it, and
 * reap the child. Returns 0 if all of input was written and the child
 * exited 0, and -1 otherwise. There is no timeout, so a person can answer
 * a login prompt. */
int	hpn_run_feed(struct arglist *args, const char *input);

#endif /* HPN3SCP_RUN_H */
