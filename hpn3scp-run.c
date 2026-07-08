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
 * hpn3scp-run.c - shared status-relay transfer runner (see hpn3scp-run.h).
 * Extracted from scp.c's do_local_cmd_status().
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "hpn-status-frame.h"
#include "hpn3scp-run.h"
#include "log.h"
#include "misc.h"

/* dispatch context threaded through the frame parser callback */
struct run_dispatch {
	const struct hpn_run_hooks *h;
	int got_hello;
};

/* decode one frame and hand it to the matching hook (numbers only; unknown
 * frame types are ignored for forward compatibility) */
static void
run_frame(u_char type, const u_char *payload, uint16_t plen, void *ctx)
{
	struct run_dispatch *d = ctx;
	struct hpns_hello he;
	struct hpns_progress pr;
	struct hpns_end e;

	switch (type) {
	case HPNS_T_HELLO:
		if (hpns_decode_hello(payload, plen, &he) == 0) {
			d->got_hello = 1;
			if (d->h->on_hello != NULL)
				d->h->on_hello(&he, d->h->ctx);
		}
		break;
	case HPNS_T_PROGRESS:
		if (hpns_decode_progress(payload, plen, &pr) == 0) {
			d->got_hello = 1;	/* implied */
			if (d->h->on_progress != NULL)
				d->h->on_progress(&pr, d->h->ctx);
		}
		break;
	case HPNS_T_END:
		if (hpns_decode_end(payload, plen, &e) == 0 &&
		    d->h->on_end != NULL)
			d->h->on_end(&e, d->h->ctx);
		break;
	default:
		break;
	}
}

int
hpn_run_status(struct arglist *a, pid_t *pidp, const struct hpn_run_hooks *h)
{
	struct hpns_parser ps;
	struct run_dispatch d;
	struct pollfd pfd;
	u_char rb[4096];
	double t0;
	size_t left;
	ssize_t n;
	int pfds[2], status, passthrough = 0;
	pid_t pid;

	if (a->num == 0)
		fatal_f("no arguments");

	if (pipe(pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		if (dup2(pfds[1], STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(1);
		}
		close(pfds[0]);
		close(pfds[1]);
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}
	close(pfds[1]);
	if (pidp != NULL)
		*pidp = pid;

	memset(&ps, 0, sizeof(ps));
	memset(&d, 0, sizeof(d));
	d.h = h;
	t0 = monotime_double();

	for (;;) {
		pfd.fd = pfds[0];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 1000) == -1) {
			if (errno == EINTR) {
				/* signal wake (e.g. meter SIGALRM): let the
				 * caller repaint if it wants */
				if (h->on_tick != NULL)
					h->on_tick(h->ctx);
				continue;
			}
			fatal_f("poll: %s", strerror(errno));
		}
		if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
			/* quiet second: if the peer never spoke frames, give
			 * up on status and pass its output through as-is */
			if (!passthrough && !d.got_hello &&
			    monotime_double() - t0 > 5.0) {
				if (h->on_degrade != NULL)
					h->on_degrade(h->ctx);
				passthrough = 1;
			}
			if (h->on_tick != NULL)
				h->on_tick(h->ctx);
			continue;
		}
		n = read(pfds[0], rb, sizeof(rb));
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}
		if (n == 0)
			break;			/* EOF: child is done */
		if (passthrough) {
			if (h->passthrough_fd >= 0)
				(void)atomicio(vwrite, h->passthrough_fd,
				    rb, (size_t)n);
			continue;
		}
		if (hpns_parser_feed(&ps, rb, (size_t)n, run_frame, &d,
		    &left) != 0) {
			/* garbled stream: hand the buffered prefix + tail to
			 * the passthrough sink, then pass all later bytes
			 * through verbatim.  The transfer is unaffected. */
			if (h->on_degrade != NULL)
				h->on_degrade(h->ctx);
			if (h->passthrough_fd >= 0) {
				if (ps.have > 0)
					(void)atomicio(vwrite,
					    h->passthrough_fd, ps.buf, ps.have);
				if (left > 0)
					(void)atomicio(vwrite,
					    h->passthrough_fd,
					    rb + ((size_t)n - left), left);
			}
			ps.have = 0;
			passthrough = 1;
			continue;
		}
	}
	close(pfds[0]);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal_f("waitpid: %s", strerror(errno));
	if (pidp != NULL)
		*pidp = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);
	return (0);
}

int
hpn_run_capture(struct arglist *a, char *buf, size_t buflen, int timeout_ms)
{
	struct pollfd pfd;
	double deadline, rem;
	size_t off = 0;
	ssize_t r;
	int pfds[2], status, killed = 0;
	pid_t pid;

	if (buflen == 0)
		return (-1);
	buf[0] = '\0';
	if (a->num == 0)
		fatal_f("no arguments");

	if (pipe(pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		if (dup2(pfds[1], STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(1);
		}
		close(pfds[0]);
		close(pfds[1]);
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}
	close(pfds[1]);

	deadline = monotime_double() + timeout_ms / 1000.0;
	for (;;) {
		rem = deadline - monotime_double();
		if (rem <= 0.0) {
			if (!killed) {
				kill(pid, SIGTERM);
				killed = 1;
			}
			break;			/* timed out */
		}
		pfd.fd = pfds[0];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, (int)(rem * 1000)) == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		if (off >= buflen - 1)
			break;			/* full: stop reading */
		r = read(pfds[0], buf + off, buflen - 1 - off);
		if (r == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}
		if (r == 0)
			break;			/* EOF */
		off += (size_t)r;
	}
	buf[off] = '\0';
	close(pfds[0]);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			break;

	if (killed)
		return (-1);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);
	return (0);
}

int
hpn_run_feed(struct arglist *a, const char *input)
{
	int pfds[2], status;
	pid_t pid;
	size_t len;

	if (a->num == 0)
		fatal_f("no arguments");
	len = strlen(input);

	if (pipe(pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		if (dup2(pfds[0], STDIN_FILENO) == -1) {
			perror("dup2");
			exit(1);
		}
		close(pfds[0]);
		close(pfds[1]);
		execvp(a->list[0], a->list);
		perror(a->list[0]);
		exit(1);
	}
	close(pfds[0]);
	/* SIGPIPE is ignored process-wide (hpn3scp main); a short write is
	 * caught by the child's nonzero exit below. */
	(void)atomicio(vwrite, pfds[1], (void *)input, len);
	close(pfds[1]);

	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			break;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);
	return (0);
}
