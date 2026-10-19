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

/* hpn3scp-run.c - running the commands that hpnscp and hpn3scp start.
 *
 * hpn_run_status() runs the ssh that starts hpnscp on the source host and
 * passes the status frames it sends on stdout to the caller's hooks.
 * hpnscp -R and hpn3scp both launch through it, by way of
 * hpn-launch-args.c. hpn_run_capture() and hpn_run_feed() run the short
 * commands of hpn3scp's host-key broker and shared login. One reads the
 * output under a timeout, and the other writes a payload to its stdin. */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "log.h"
#include "misc.h"
#include "hpn-status-frame.h"
#include "hpn3scp-run.h"

/* PROGRESS frames in a row that fail to decode before the consumer is
 * told progress cannot be read. A source sends about one a second. */
#define RUN_PROGRESS_MISS_LIMIT	5
/* poll timeout, which is also the caller's repaint tick */
#define RUN_TICK_MS		1000
/* seconds without a frame before a status run passes output through */
#define RUN_DEGRADE_SEC		5.0

/* The frame parser's context in hpn_run_status(): the caller's hooks,
 * whether a HELLO or PROGRESS frame has arrived, and how many PROGRESS
 * frames in a row have failed to decode */
struct run_dispatch {
	const struct hpn_run_hooks	*hooks;
	int				 got_hello;
	int				 progress_misses;
};

/* Decode one frame and pass it to the caller's hook for its type. The
 * hooks get decoded structs, never raw bytes. A frame whose payload does
 * not fit its type's layout is dropped, and an unknown type is ignored, so
 * frames from a newer source cannot break this side. A run of unreadable
 * PROGRESS frames reaches on_mismatch. Every frame, decoded or not, then
 * reaches on_frame as a sign the source is still sending. */
static void
run_frame(u_char type, const u_char *payload, uint16_t plen, void *ctx)
{
	struct run_dispatch *dispatch = ctx;
	const struct hpn_run_hooks *hooks = dispatch->hooks;
	struct hpns_hello hello;
	struct hpns_progress progress;
	struct hpns_end end;
	struct hpns_filefail filefail;
	struct hpns_filedone filedone;
	int r = 0;

	switch (type) {
	case HPNS_T_HELLO:
		if ((r = hpns_decode_hello(payload, plen, &hello)) == 0) {
			dispatch->got_hello = 1;
			if (hooks->on_hello != NULL)
				hooks->on_hello(&hello, hooks->ctx);
		}
		break;
	case HPNS_T_PROGRESS:
		if ((r = hpns_decode_progress(payload, plen, &progress)) != 0) {
			/* Tell the consumer when the misses reach the limit.
			 * A decoded frame restarts the count, so a later run
			 * of misses is reported again. */
			if (++dispatch->progress_misses ==
			    RUN_PROGRESS_MISS_LIMIT &&
			    hooks->on_mismatch != NULL)
				hooks->on_mismatch(hooks->ctx);
			break;
		}
		dispatch->progress_misses = 0;
		/* progress also shows the source speaks frames */
		dispatch->got_hello = 1;
		if (hooks->on_progress != NULL)
			hooks->on_progress(&progress, hooks->ctx);
		break;
	case HPNS_T_FILEFAIL:
		if ((r = hpns_decode_filefail(payload, plen, &filefail)) == 0 &&
		    hooks->on_file_fail != NULL)
			hooks->on_file_fail(&filefail, hooks->ctx);
		break;
	case HPNS_T_FILEDONE:
		if ((r = hpns_decode_filedone(payload, plen, &filedone)) == 0 &&
		    hooks->on_filedone != NULL)
			hooks->on_filedone(&filedone, hooks->ctx);
		break;
	case HPNS_T_END:
		if ((r = hpns_decode_end(payload, plen, &end)) == 0 &&
		    hooks->on_end != NULL)
			hooks->on_end(&end, hooks->ctx);
		break;
	default:
		break;
	}
	/* Any frame, readable or not, shows the source is still sending. It
	 * comes after the dispatch, so a PROGRESS that decodes has already
	 * ended the consumer's liveness mode. */
	if (hooks->on_frame != NULL)
		hooks->on_frame(hooks->ctx);
	/* a short payload means the source runs a different build */
	if (r != 0)
		debug_f("dropped a type %u frame: its %u-byte payload is "
		    "shorter than this build's layout", (u_int)type,
		    (u_int)plen);
}

/* In a forked child, put stdout_fd, stdin_fd, and stderr_fd, where not
 * -1, on the child's stdout, stdin, and stderr, then exec args. stderr_fd
 * may be stdout_fd, to merge the two. The caller has already closed the
 * parent's ends of the pipes. A failure exits 127, the status for a
 * command that could not run, so a launcher never mistakes it for an
 * older hpnscp's usage error. _exit() keeps the child from flushing the
 * parent's stdio buffers or running its atexit handlers. */
static void __attribute__((noreturn))
exec_child(struct arglist *args, int stdout_fd, int stdin_fd, int stderr_fd)
{
	if ((stdout_fd != -1 && dup2(stdout_fd, STDOUT_FILENO) == -1) ||
	    (stdin_fd != -1 && dup2(stdin_fd, STDIN_FILENO) == -1) ||
	    (stderr_fd != -1 && dup2(stderr_fd, STDERR_FILENO) == -1)) {
		perror("dup2");
		_exit(127);
	}
	/* the dup2 copies are the child's, so the originals go */
	if (stdout_fd != -1 && stdout_fd != STDOUT_FILENO)
		close(stdout_fd);
	if (stdin_fd != -1 && stdin_fd != STDIN_FILENO)
		close(stdin_fd);
	/* a merged stderr shares the stdout original, already closed */
	if (stderr_fd != -1 && stderr_fd != STDERR_FILENO &&
	    stderr_fd != stdout_fd)
		close(stderr_fd);
	execvp(args->list[0], args->list);
	perror(args->list[0]);
	_exit(127);
}

/* Run args with its stdout on a pipe, write the hooks' stdin payload as
 * the child reads it, and pass each HPNS frame to run_frame(). A quiet
 * poll ticks the caller. A source that sends no frame within
 * RUN_DEGRADE_SEC, or whose stream fails to parse, degrades to passing
 * its output through. The child is reaped before the return, which comes
 * from its exit status. */
int
hpn_run_status(struct arglist *args, pid_t *pidp,
    const struct hpn_run_hooks *hooks, struct hpn_run_result *res)
{
	struct hpns_parser parser;
	struct run_dispatch dispatch;
	struct pollfd pfd[2];
	u_char readbuf[4096];
	double start_time;
	size_t left, sent = 0;
	ssize_t n;
	int stdout_pfds[2], stdin_pfds[2] = { -1, -1 };
	int status, passthrough = 0, npfd, ready, sigpipe_saved = 0;
	sshsig_t old_sigpipe;
	pid_t pid;

	if (args->num == 0)
		fatal_f("no arguments");

	/* a pipe for the child's output, and one for its stdin when there
	 * is a payload to write */
	if (pipe(stdout_pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if (hooks->stdin_data != NULL && pipe(stdin_pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		/* the child closes the parent's ends of the pipes and execs */
		close(stdout_pfds[0]);
		if (stdin_pfds[1] != -1)
			close(stdin_pfds[1]);
		exec_child(args, stdout_pfds[1], stdin_pfds[0], -1);
	}
	/* the parent keeps only its own pipe ends */
	close(stdout_pfds[1]);
	/* the caller's signal handler can now find the child */
	if (pidp != NULL)
		*pidp = pid;
	if (stdin_pfds[0] != -1) {
		close(stdin_pfds[0]);
		/* The payload is written as the child reads it, alongside its
		 * output, so neither pipe can fill and stall the other. A
		 * child that exits without reading must not kill us with
		 * SIGPIPE, and scp's own SIGPIPE handler would. */
		set_nonblock(stdin_pfds[1]);
		old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);
		sigpipe_saved = 1;
		if (hooks->stdin_len == 0) {
			close(stdin_pfds[1]);
			stdin_pfds[1] = -1;
		}
	}

	/* a fresh parser, and the degrade timer starting now */
	memset(&parser, 0, sizeof(parser));
	memset(&dispatch, 0, sizeof(dispatch));
	dispatch.hooks = hooks;
	start_time = monotime_double();

	/* watch the child's output, and its stdin while the payload lasts */
	for (;;) {
		pfd[0].fd = stdout_pfds[0];
		pfd[0].events = POLLIN;
		npfd = 1;
		if (stdin_pfds[1] != -1) {
			pfd[1].fd = stdin_pfds[1];
			pfd[1].events = POLLOUT;
			npfd = 2;
		}
		if ((ready = poll(pfd, npfd, RUN_TICK_MS)) == -1) {
			if (errno == EINTR) {
				/* a signal, such as the meter's SIGALRM, woke
				 * us, so let the caller repaint */
				if (hooks->on_tick != NULL)
					hooks->on_tick(hooks->ctx);
				continue;
			}
			fatal_f("poll: %s", strerror(errno));
		}
		/* feed the payload, closing stdin once it is all sent or the
		 * child stops reading */
		if (npfd == 2 && pfd[1].revents != 0) {
			n = write(stdin_pfds[1], hooks->stdin_data + sent,
			    hooks->stdin_len - sent);
			if (n > 0)
				sent += (size_t)n;
			if ((n == -1 && errno != EAGAIN && errno != EINTR) ||
			    sent == hooks->stdin_len) {
				close(stdin_pfds[1]);
				stdin_pfds[1] = -1;
			}
		}
		/* only a quiet poll counts toward the degrade timer */
		if (ready == 0) {
			/* a source that never sent a frame gets its output
			 * passed through as is, without status */
			if (!passthrough && !dispatch.got_hello &&
			    monotime_double() - start_time > RUN_DEGRADE_SEC) {
				if (hooks->on_degrade != NULL)
					hooks->on_degrade(hooks->ctx);
				passthrough = 1;
			}
			if (hooks->on_tick != NULL)
				hooks->on_tick(hooks->ctx);
			continue;
		}
		/* only stdin was ready */
		if (!(pfd[0].revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		/* read what the child wrote */
		n = read(stdout_pfds[0], readbuf, sizeof(readbuf));
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			/* the run's result still comes from the exit status */
			error_f("read: %s", strerror(errno));
			break;
		}
		if (n == 0)
			break;			/* EOF: child is done */
		/* after a degrade, raw bytes go to the sink or are dropped */
		if (passthrough) {
			if (hooks->passthrough_fd >= 0)
				(void)atomicio(vwrite, hooks->passthrough_fd,
				    readbuf, (size_t)n);
			continue;
		}
		/* each complete frame goes to run_frame() */
		if (hpns_parser_feed(&parser, readbuf, (size_t)n, run_frame,
		    &dispatch, &left) != 0) {
			/* A garbled stream: hand the buffered prefix and the
			 * unparsed tail to the passthrough sink, then pass
			 * every later byte through as is. The transfer is
			 * unaffected. */
			if (hooks->on_degrade != NULL)
				hooks->on_degrade(hooks->ctx);
			if (hooks->passthrough_fd >= 0) {
				if (parser.have > 0)
					(void)atomicio(vwrite,
					    hooks->passthrough_fd, parser.buf,
					    parser.have);
				if (left > 0)
					(void)atomicio(vwrite,
					    hooks->passthrough_fd,
					    readbuf + ((size_t)n - left), left);
			}
			parser.have = 0;
			passthrough = 1;
			continue;
		}
	}
	/* the child is done or gone, so close our pipe ends */
	close(stdout_pfds[0]);
	if (stdin_pfds[1] != -1)
		close(stdin_pfds[1]);
	/* SIG_DFL is a null pointer, so a flag, not the handler, records the
	 * save */
	if (sigpipe_saved)
		ssh_signal(SIGPIPE, old_sigpipe);

	/* reap the child, then clear the pid the caller's handler reads */
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal_f("waitpid: %s", strerror(errno));
	if (pidp != NULL)
		*pidp = -1;
	/* tell a launcher what the run saw */
	if (res != NULL) {
		memset(res, 0, sizeof(*res));
		res->got_hello = dispatch.got_hello;
		if (WIFEXITED(status)) {
			res->exited = 1;
			res->exit_status = WEXITSTATUS(status);
		}
	}

	/* success is the child's exit 0 */
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

/* Run args and collect its stdout into buf, NUL-terminated, then reap
 * it. With with_stderr set, its stderr is collected too, merged with
 * stdout. Output past buflen - 1 bytes is read and dropped, and sets
 * *truncated when it is not NULL. The run fails if the timeout passes or
 * reading fails, which also sends the child SIGTERM, or if the child does
 * not exit 0. */
int
hpn_run_capture(struct arglist *args, char *buf, size_t buflen,
    int timeout_ms, int *truncated, int with_stderr)
{
	struct pollfd pfd;
	double deadline, remaining;
	size_t off = 0;
	ssize_t n;
	char drain[4096];
	int stdout_pfds[2], status, failed = 0, full;
	pid_t pid;

	if (truncated != NULL)
		*truncated = 0;
	if (buflen == 0)
		return -1;
	buf[0] = '\0';
	if (args->num == 0)
		fatal_f("no arguments");

	if (pipe(stdout_pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		/* the child keeps only the write end, as its stdout */
		close(stdout_pfds[0]);
		exec_child(args, stdout_pfds[1], -1,
		    with_stderr ? stdout_pfds[1] : -1);
	}
	/* without our copy of the write end, EOF comes when the child exits */
	close(stdout_pfds[1]);

	deadline = monotime_double() + timeout_ms / 1000.0;
	/* read until EOF or the deadline */
	for (;;) {
		remaining = deadline - monotime_double();
		if (remaining <= 0.0) {
			/* the reap below has no deadline, so stop the child */
			kill(pid, SIGTERM);
			failed = 1;
			break;			/* timed out */
		}
		pfd.fd = stdout_pfds[0];
		pfd.events = POLLIN;
		if (poll(&pfd, 1, (int)(remaining * 1000)) == -1) {
			if (errno == EINTR)
				continue;
			error_f("poll: %s", strerror(errno));
			kill(pid, SIGTERM);
			failed = 1;
			break;
		}
		if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		/* Past a full buffer, read and drop the rest. Stopping would
		 * leave a child that already wrote it all to exit 0, and
		 * output cut at a line break would read as complete. */
		full = off >= buflen - 1;
		n = read(stdout_pfds[0], full ? drain : buf + off,
		    full ? sizeof(drain) : buflen - 1 - off);
		if (n == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			/* partial output is never returned as a success */
			error_f("read: %s", strerror(errno));
			kill(pid, SIGTERM);
			failed = 1;
			break;
		}
		if (n == 0)
			break;			/* EOF */
		if (!full)
			off += (size_t)n;
		else if (truncated != NULL)
			*truncated = 1;
	}
	buf[off] = '\0';
	close(stdout_pfds[0]);

	/* wait for the child to exit and get its status */
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal_f("waitpid: %s", strerror(errno));

	if (failed || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

/* Run args with input written to its stdin, then reap it. The run fails
 * unless all of input was written and the child exits 0. */
int
hpn_run_feed(struct arglist *args, const char *input)
{
	int stdin_pfds[2], status, failed = 0;
	sshsig_t old_sigpipe;
	pid_t pid;
	size_t len;

	if (args->num == 0)
		fatal_f("no arguments");
	len = strlen(input);

	if (pipe(stdin_pfds) == -1)
		fatal_f("pipe: %s", strerror(errno));
	if ((pid = fork()) == -1)
		fatal_f("fork: %s", strerror(errno));

	if (pid == 0) {
		/* the child keeps only the read end, as its stdin */
		close(stdin_pfds[1]);
		exec_child(args, -1, stdin_pfds[0], -1);
	}
	close(stdin_pfds[0]);
	/* A child that exits without reading must not kill us with SIGPIPE,
	 * and scp's own SIGPIPE handler would. A payload that did not all
	 * arrive fails the run, whatever the child's exit status. */
	old_sigpipe = ssh_signal(SIGPIPE, SIG_IGN);
	if (atomicio(vwrite, stdin_pfds[1], (void *)input, len) != len) {
		debug_f("write: %s", strerror(errno));
		failed = 1;
	}
	ssh_signal(SIGPIPE, old_sigpipe);
	/* closing our end gives the child EOF on the payload */
	close(stdin_pfds[1]);

	/* wait for the child to exit and get its status */
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			fatal_f("waitpid: %s", strerror(errno));

	if (failed || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}
