/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

/*
 * sftp-parallel-config.c — bridge between ssh_config and the
 * parallel-streams orchestrator config.
 *
 * Reads the user's ssh_config files using the same machinery as
 * hpnssh (two-pass parsing with Match-block resolution) and copies
 * relevant HPN options into a `struct sftp_parallel_config`.
 *
 * Today this maps a single keyword:
 *   HPNUseBundle yes|no  ->  pcfg->use_bundle
 *
 * Future ssh_config-promoted options (BundleSize,
 * ParallelStreamsAuthConcurrent, etc.) plug in here as the inventory
 * in benchmark/env-vars-reference.md is promoted from env vars.
 *
 * Both hpnsftp and (future) hpnscp call sftp_parallel_apply_ssh_config()
 * to populate pcfg before invoking sftp_parallel_start().  This keeps
 * the readconf.o dependency contained in one small object file rather
 * than pulling it into the much larger sftp-parallel.o.
 */

#include "includes.h"

#include <sys/types.h>

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "pathnames.h"
#include "ssh.h"
#include "readconf.h"
#include "sftp-parallel.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "xmalloc.h"

/*
 * Mirror of ssh.c's process_config_files(), trimmed to what we need:
 * read user and system ssh_config (or the explicit -F file) into the
 * supplied Options struct.  Sets *want_final_pass=1 if any parsed
 * directive depended on the final-pass resolution (Match blocks).
 *
 * Returns 0 on success or -1 if the explicit user config file was
 * provided but couldn't be opened (matches ssh.c's fatal() behaviour
 * loosely — we return an error instead of exiting, since the caller
 * may want to fall back to defaults).
 */
static int
process_config_files(const char *user_config_file, struct passwd *pw,
    const char *host, const char *host_name, int final_pass,
    int *want_final_pass, Options *options)
{
	char buf[PATH_MAX];
	int r;

	if (user_config_file != NULL) {
		if (strcasecmp(user_config_file, "none") == 0)
			return 0;
		if (!read_config_file(user_config_file, pw, host, host_name,
		    /* remote_command */ NULL, options,
		    SSHCONF_USERCONF |
		    (final_pass ? SSHCONF_FINAL : 0),
		    want_final_pass))
			return -1;
		return 0;
	}

	/* User's ssh_config (best-effort; many systems lack it). */
	if (pw != NULL && pw->pw_dir != NULL) {
		r = snprintf(buf, sizeof(buf), "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		if (r > 0 && (size_t)r < sizeof(buf))
			(void)read_config_file(buf, pw, host, host_name,
			    /* remote_command */ NULL, options,
			    SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (final_pass ? SSHCONF_FINAL : 0),
			    want_final_pass);
	}

	/* System-wide config. */
	(void)read_config_file(_PATH_HOST_CONFIG_FILE, pw, host, host_name,
	    /* remote_command */ NULL, options,
	    final_pass ? SSHCONF_FINAL : 0, want_final_pass);

	return 0;
}

int
sftp_parallel_apply_ssh_config(struct sftp_parallel_config *pcfg,
    const char *host, const char *user_config_file)
{
	Options options;
	struct passwd *pw;
	int want_final_pass = 0;
	const char *host_name;

	if (pcfg == NULL || host == NULL || *host == '\0')
		return -1;

	/* Sensible defaults if anything below fails. */
	pcfg->use_bundle  = 1;
	pcfg->max_retries = 3;
	pcfg->bundle_size = 0;  /* 0 = let worker use compile-time default */
	pcfg->max_auth_concurrent = 0;  /* 0 = auto */

	initialize_options(&options);
	options.host_arg = xstrdup(host);

	pw = getpwuid(getuid());
	if (pw == NULL) {
		debug_f("getpwuid failed; skipping ssh_config parse");
		free_options(&options);
		return -1;
	}

	/* Pass 1: read config without Match-resolution, find out whether
	 * a second pass is needed. */
	if (process_config_files(user_config_file, pw, host, host,
	    /* final_pass */ 0, &want_final_pass, &options) < 0) {
		error_f("could not read user ssh_config \"%s\"",
		    user_config_file ? user_config_file : "(default)");
		free_options(&options);
		return -1;
	}

	/* Pass 2: if any Match block referenced final-pass data, re-read
	 * with the resolved hostname. */
	if (want_final_pass) {
		host_name = options.hostname ? options.hostname : host;
		(void)process_config_files(user_config_file, pw, host,
		    host_name, /* final_pass */ 1, NULL, &options);
	}

	fill_default_options(&options);

	/* Map the resolved Options into pcfg.  Future ssh_config-promoted
	 * options append additional assignments here. */
	pcfg->use_bundle  = (options.hpn_use_bundle != 0);
	pcfg->max_retries = options.hpn_max_retries;
	pcfg->bundle_size = (options.hpn_bundle_size > 0)
	    ? (uint64_t)options.hpn_bundle_size : 0;
	pcfg->max_auth_concurrent = options.hpn_max_auth_concurrent;

	debug_f("ssh_config: host=\"%s\" HPNUseBundle=%s HPNMaxRetries=%d "
	    "HPNBundleSize=%llu HPNMaxAuthConcurrent=%d",
	    host, pcfg->use_bundle ? "yes" : "no", pcfg->max_retries,
	    (unsigned long long)pcfg->bundle_size,
	    pcfg->max_auth_concurrent);

	free_options(&options);
	return 0;
}
