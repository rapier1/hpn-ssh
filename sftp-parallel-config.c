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
 * sftp-parallel-config.c - bridge between ssh_config and the
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
 * to populate pcfg before invoking sftp_parallel_start(). This keeps
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
 * supplied Options struct. Sets *want_final_pass=1 if any parsed
 * directive depended on the final-pass resolution (Match blocks).
 *
 * Returns 0 on success or -1 if the explicit user config file was
 * provided but couldn't be opened (matches ssh.c's fatal() behaviour
 * loosely - we return an error instead of exiting, since the caller
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

/*
 * Read ssh_config for `host` into *options (two-pass Match resolution).
 * initialize_options() is done here; the caller must always free_options()
 * afterward, including on a -1 return.
 *
 * `extra_argv` is the array of command-line `-o KEY=VALUE` strings
 * collected by sftp.c's argv parser (parallel_extra_o), NULL-terminated;
 * each entry is applied via process_config_line() AFTER the config files
 * are read but BEFORE fill_default_options(), matching the order ssh.c
 * uses so command-line overrides win over config values. May be NULL.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
resolve_ssh_config(const char *host, const char *user_config_file,
    char *const *extra_argv, Options *options)
{
	struct passwd *pw;
	int want_final_pass = 0;
	const char *host_name;

	initialize_options(options);
	options->host_arg = xstrdup(host);

	pw = getpwuid(getuid());
	if (pw == NULL) {
		debug_f("getpwuid failed; skipping ssh_config parse");
		return -1;
	}

	/* Pass 1: read config without Match-resolution, find out whether
	 * a second pass is needed. */
	if (process_config_files(user_config_file, pw, host, host,
	    /* final_pass */ 0, &want_final_pass, options) < 0) {
		error_f("could not read user ssh_config \"%s\"",
		    user_config_file ? user_config_file : "(default)");
		return -1;
	}

	/* Pass 2: if any Match block referenced final-pass data, re-read
	 * with the resolved hostname. */
	if (want_final_pass) {
		host_name = options->hostname ? options->hostname : host;
		(void)process_config_files(user_config_file, pw, host,
		    host_name, /* final_pass */ 1, NULL, options);
	}

	/*
	 * Apply -o overrides from the command line so they trump config
	 * values, matching how ssh.c handles -o. Without this, options
	 * like `-o HPNLustreStripeCount=0` silently fail to override the
	 * config defaults.
	 */
	if (extra_argv != NULL) {
		for (int i = 0; extra_argv[i] != NULL; i++) {
			char *line = xstrdup(extra_argv[i]);
			if (process_config_line(options, pw,
			    host ? host : "", host ? host : "", "",
			    line, "command-line", 0, NULL,
			    SSHCONF_USERCONF) != 0) {
				error_f("bad -o option \"%s\"",
				    extra_argv[i]);
				free(line);
				return -1;
			}
			free(line);
		}
	}

	fill_default_options(options);
	return 0;
}

int
sftp_parallel_apply_ssh_config(struct sftp_parallel_config *pcfg,
    const char *host, const char *user_config_file,
    char *const *extra_argv)
{
	Options options;

	if (pcfg == NULL || host == NULL || *host == '\0')
		return -1;

	/* Sensible defaults if anything below fails. */
	pcfg->use_bundle  = 1;
	pcfg->writer_pool = 1;
	pcfg->tail_redistribute = 1;
	pcfg->max_retries = 3;
	pcfg->stall_abort_timeout = 60;
	pcfg->bundle_size = 0;  /* 0 = let worker use compile-time default */
	pcfg->max_auth_concurrent = 0;  /* 0 = auto */
	pcfg->verify_transfer = 0;  /* default off */

	if (resolve_ssh_config(host, user_config_file, extra_argv,
	    &options) < 0) {
		free_options(&options);
		return -1;
	}

	/* Map the resolved Options into pcfg. Future ssh_config-promoted
	 * options append additional assignments here. */
	pcfg->use_bundle  = (options.hpn_use_bundle != 0);
	pcfg->writer_pool = (options.hpn_writer_pool != 0);
	pcfg->tail_redistribute = (options.hpn_tail_redistribute != 0);
	pcfg->max_retries = options.hpn_max_retries;
	pcfg->stall_abort_timeout = options.hpn_stall_abort_timeout;
	pcfg->bundle_size = (options.hpn_bundle_size > 0)
	    ? (uint64_t)options.hpn_bundle_size : 0;
	pcfg->max_auth_concurrent = options.hpn_max_auth_concurrent;
	/* verify_transfer is NOT an ssh_config option; it is requested per
	 * transfer via -V (scp) / put-getv (sftp) and stays at the default 0
	 * here, toggled later by the caller. */

	debug_f("ssh_config: host=\"%s\" HPNUseBundle=%s HPNWriterPool=%s "
	    "HPNTailRedistribute=%s HPNMaxRetries=%d HPNStallAbortTimeout=%d "
	    "HPNBundleSize=%llu HPNMaxAuthConcurrent=%d",
	    host, pcfg->use_bundle ? "yes" : "no",
	    pcfg->writer_pool ? "yes" : "no",
	    pcfg->tail_redistribute ? "yes" : "no", pcfg->max_retries,
	    pcfg->stall_abort_timeout,
	    (unsigned long long)pcfg->bundle_size,
	    pcfg->max_auth_concurrent);

	free_options(&options);
	return 0;
}

int
sftp_resolve_hpn_lustre_stripe_count(const char *host,
    const char *user_config_file, char *const *extra_argv)
{
	Options options;
	int r = -1;	/* default: auto */

	if (host == NULL || *host == '\0')
		return -1;
	if (resolve_ssh_config(host, user_config_file, extra_argv,
	    &options) == 0)
		r = options.hpn_lustre_stripe_count;
	free_options(&options);
	return r;
}

/*
 * Adaptive throughput-outlier stall detection defaults, shared by hpnsftp
 * and hpnscp so the two stay in lockstep. On by default in parallel mode
 * with conservative WAN-bulk settings (the values were settled by testing;
 * the env-var overrides that once existed were removed in the 19.0 dev-knob
 * cull): path-health floor in bytes/s (0 disables the detector), the outlier
 * fraction of the fastest peer's EMA, the consecutive outlier ticks before
 * STALLED (DEAD at 2N), and the EMA smoothing factor.
 */
void
sftp_parallel_set_stall_defaults(struct sftp_parallel_config *pcfg)
{
	pcfg->tput_path_healthy_bytes_s = 2000 * 1024;	/* ~2 MiB/s floor */
	pcfg->tput_outlier_fraction  = 0.25;	/* outlier fraction */
	pcfg->tput_consec_required   = 5;	/* consecutive stalled ticks */
	pcfg->tput_ema_alpha         = 0.2;	/* EMA smoothing, ~5-tick constant */
}
