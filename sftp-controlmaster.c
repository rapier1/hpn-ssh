/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xmalloc.h"
#include "log.h"
#include "misc.h"

#include "sftp-controlmaster.h"

#define DEFAULT_TIMEOUT_SEC      30
#define POLL_INTERVAL_USEC       100000  /* 100 ms */
#define EXIT_GRACE_SEC           5
#define DEFAULT_SSH_BINARY       "hpnssh"
#define SOCKET_DIR_TEMPLATE      "/tmp/hpnssh-cm-XXXXXX"
#define SOCKET_NAME              "sock"

struct sftp_controlmaster {
	pid_t  pid;
	char  *socket_dir;   /* private mkdtemp directory, mode 0700 */
	char  *socket_path;  /* socket_dir + "/sock" */
	char  *host;         /* duplicated from config */
	char  *ssh_binary;   /* duplicated from config */
	char  *port;         /* duplicated from config; may be NULL */
	int    stopped;
};

/*
 * Build the master's argv. Returns a NULL-terminated array allocated with
 * xmalloc; caller frees with free_argv().
 */
static char **
build_master_argv(const struct sftp_cm_config *cfg, const char *socket_path)
{
	size_t cap = 32, n = 0;
	char **a = xcalloc(cap, sizeof(*a));

	#define PUSH(s) do { \
		if (n + 2 > cap) { \
			cap *= 2; \
			a = xreallocarray(a, cap, sizeof(*a)); \
		} \
		a[n++] = xstrdup(s); \
	} while (0)

	PUSH(cfg->ssh_binary ? cfg->ssh_binary : DEFAULT_SSH_BINARY);
	PUSH("-M");
	PUSH("-N");
	PUSH("-o"); PUSH("ControlPersist=yes");
	PUSH("-o"); PUSH("BatchMode=yes");
	PUSH("-S"); PUSH(socket_path);
	if (cfg->verbose)
		PUSH("-v");
	if (cfg->port) {
		PUSH("-p"); PUSH(cfg->port);
	}
	if (cfg->identity) {
		PUSH("-i"); PUSH(cfg->identity);
	}
	if (cfg->config_file) {
		PUSH("-F"); PUSH(cfg->config_file);
	}
	if (cfg->known_hosts) {
		char buf[1024];
		snprintf(buf, sizeof(buf), "UserKnownHostsFile=%s",
		    cfg->known_hosts);
		PUSH("-o"); PUSH(buf);
	}
	if (cfg->extra_argv) {
		for (size_t i = 0; cfg->extra_argv[i] != NULL; i++) {
			PUSH("-o"); PUSH(cfg->extra_argv[i]);
		}
	}
	PUSH(cfg->host);
	a[n] = NULL;
	#undef PUSH
	return a;
}

static void
free_argv(char **a)
{
	if (a == NULL)
		return;
	for (size_t i = 0; a[i] != NULL; i++)
		free(a[i]);
	free(a);
}

/*
 * Run "ssh -O check -S <socket> <host>" and return its exit status.
 * Returns 0 if the master answers cleanly (authenticated and listening),
 * nonzero otherwise.
 */
static int
run_check(const char *ssh_binary, const char *socket_path, const char *host)
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		/* child: silence stdout/stderr - we only care about exit code */
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execlp(ssh_binary, ssh_binary, "-O", "check",
		    "-S", socket_path, host, (char *)NULL);
		_exit(127);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

/*
 * Run "ssh -O exit -S <socket> <host>" and wait briefly for it to finish.
 * Best-effort; we follow up with signal escalation if needed.
 */
static void
run_exit(const char *ssh_binary, const char *socket_path, const char *host)
{
	pid_t pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execlp(ssh_binary, ssh_binary, "-O", "exit",
		    "-S", socket_path, host, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, NULL, 0);
}

/*
 * Wait for `pid` to exit, up to `seconds` seconds. Returns 1 if exited,
 * 0 if still alive after the timeout.
 */
static int
wait_pid_with_timeout(pid_t pid, int seconds)
{
	struct timespec deadline, now;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += seconds;

	while (1) {
		int status;
		pid_t r = waitpid(pid, &status, WNOHANG);
		if (r == pid)
			return 1;
		if (r < 0 && errno != EINTR)
			return 0;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		     now.tv_nsec >= deadline.tv_nsec))
			return 0;
		usleep(POLL_INTERVAL_USEC);
	}
}

struct sftp_controlmaster *
sftp_cm_start(const struct sftp_cm_config *cfg)
{
	if (cfg == NULL || cfg->host == NULL) {
		errno = EINVAL;
		return NULL;
	}

	struct sftp_controlmaster *cm = xcalloc(1, sizeof(*cm));
	cm->pid = -1;
	cm->host = xstrdup(cfg->host);
	cm->ssh_binary = xstrdup(cfg->ssh_binary ?
	    cfg->ssh_binary : DEFAULT_SSH_BINARY);
	if (cfg->port)
		cm->port = xstrdup(cfg->port);

	/* Per-process directory, mode 0700, atomic creation. mkdtemp ignores
	 * umask. Prevents same-host adversarial users from observing or
	 * tampering with our control socket. */
	char tmpl[sizeof(SOCKET_DIR_TEMPLATE) + 1];
	strlcpy(tmpl, SOCKET_DIR_TEMPLATE, sizeof(tmpl));
	if (mkdtemp(tmpl) == NULL) {
		error_f("mkdtemp: %s", strerror(errno));
		goto fail;
	}
	cm->socket_dir = xstrdup(tmpl);
	xasprintf(&cm->socket_path, "%s/%s", cm->socket_dir, SOCKET_NAME);

	/* Spawn master. */
	char **argv = build_master_argv(cfg, cm->socket_path);
	pid_t pid = fork();
	if (pid < 0) {
		error_f("fork: %s", strerror(errno));
		free_argv(argv);
		goto fail;
	}
	if (pid == 0) {
		/* child: become the master */
		execvp(argv[0], argv);
		_exit(127);
	}
	free_argv(argv);
	cm->pid = pid;

	/* Wait for master to authenticate. Poll socket existence first
	 * (cheap), then confirm with -O check (more expensive). */
	int timeout = cfg->timeout_sec > 0 ? cfg->timeout_sec : DEFAULT_TIMEOUT_SEC;
	struct timespec deadline, now;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += timeout;

	while (1) {
		/* Has master died early (auth failure)? */
		int status;
		pid_t r = waitpid(cm->pid, &status, WNOHANG);
		if (r == cm->pid) {
			cm->pid = -1;
			error_f("ControlMaster exited before auth completed "
			    "(status %d) - is pubkey/agent auth set up?",
			    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
			goto fail;
		}

		/* Socket up yet? */
		struct stat st;
		if (stat(cm->socket_path, &st) == 0 && S_ISSOCK(st.st_mode)) {
			/* Confirm master is actually responsive. */
			if (run_check(cm->ssh_binary, cm->socket_path,
			    cm->host) == 0)
				break; /* success */
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		     now.tv_nsec >= deadline.tv_nsec)) {
			error_f("ControlMaster did not authenticate within "
			    "%d seconds", timeout);
			goto fail;
		}
		usleep(POLL_INTERVAL_USEC);
	}

	debug_f("ControlMaster ready: pid=%ld socket=%s",
	    (long)cm->pid, cm->socket_path);
	return cm;

 fail:
	sftp_cm_stop(cm);
	return NULL;
}

const char *
sftp_cm_socket(struct sftp_controlmaster *cm)
{
	return (cm == NULL) ? NULL : cm->socket_path;
}

int
sftp_cm_alive(struct sftp_controlmaster *cm)
{
	if (cm == NULL || cm->pid <= 0 || cm->stopped)
		return 0;
	if (kill(cm->pid, 0) != 0)
		return 0;
	struct stat st;
	if (cm->socket_path == NULL ||
	    stat(cm->socket_path, &st) != 0 || !S_ISSOCK(st.st_mode))
		return 0;
	return 1;
}

void
sftp_cm_stop(struct sftp_controlmaster *cm)
{
	if (cm == NULL || cm->stopped)
		return;
	cm->stopped = 1;

	if (cm->pid > 0) {
		/* Polite first: ask master to exit via mux command. */
		if (cm->socket_path && cm->ssh_binary && cm->host) {
			struct stat st;
			if (stat(cm->socket_path, &st) == 0 &&
			    S_ISSOCK(st.st_mode))
				run_exit(cm->ssh_binary, cm->socket_path,
				    cm->host);
		}
		if (!wait_pid_with_timeout(cm->pid, EXIT_GRACE_SEC)) {
			kill(cm->pid, SIGTERM);
			if (!wait_pid_with_timeout(cm->pid, EXIT_GRACE_SEC))
				kill(cm->pid, SIGKILL);
			(void)waitpid(cm->pid, NULL, 0);
		}
		cm->pid = -1;
	}

	if (cm->socket_path) {
		(void)unlink(cm->socket_path);
		free(cm->socket_path);
		cm->socket_path = NULL;
	}
	if (cm->socket_dir) {
		(void)rmdir(cm->socket_dir);
		free(cm->socket_dir);
		cm->socket_dir = NULL;
	}
	free(cm->host);
	free(cm->ssh_binary);
	free(cm->port);
	free(cm);
}
