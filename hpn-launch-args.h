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

/* hpn-launch-args.h - passing hpnscp its arguments on a third-party source
 * without the source's shell.
 *
 * hpn3scp and hpnscp -R start the copy by running hpnscp on the source
 * host. Its arguments travel on the ssh session's stdin rather than on
 * the command line, so no user-supplied string passes through the
 * source's shell. The list is a u32 count followed by that many sshbuf
 * strings, at most HPN_LAUNCH_ARGS_MAX bytes in all.
 *
 * hpnscp reads the list only when HPN_ARGS_STDIN is set and it was
 * started with no arguments, so the variable never overrides arguments a
 * wrapper or forced command gave it. With HPN_ARGS_STDIN=1 the launcher
 * closes stdin after the list. With HPN_ARGS_STDIN=2 it holds stdin open
 * for the whole run as a lifeline, and hpnscp stops the copy on every
 * host when stdin closes, because the launcher cancelled or died. A
 * source too old to read the list gets the legacy command line instead,
 * with a warning, unless -X StrictArgs refuses it. */

#ifndef HPN_LAUNCH_ARGS_H
#define HPN_LAUNCH_ARGS_H

#include <sys/types.h> /* for pid_t */

/* the largest argument list accepted, in bytes */
#define HPN_LAUNCH_ARGS_MAX	(1024 * 1024)

/* the exit status when -X StrictArgs refuses a legacy source */
#define HPN_EXIT_STRICT_ARGS	58

/* hpn_launch_args_run()'s result when it refused to run the copy at all,
 * for an argument list over the cap or an argument the shell would act on
 * in the legacy mode. Nothing ran, so nothing moved. */
#define HPN_LAUNCH_REFUSED	(-2)

struct arglist;		/* from misc.h */
struct hpn_run_hooks;	/* from hpn3scp-run.h */

/* One third-party launch on a source host, as hpn3scp and hpnscp -R
 * describe it to hpn_launch_args_run(). The caller builds the two ssh
 * prefixes, each ending in the source host, and the program's own
 * arguments. */
struct hpn_launch {
	struct arglist	*ssh_stdin;	/* for stdin mode, without -n */
	struct arglist	*ssh_legacy;	/* for legacy mode, with -n */
	const char	*program;	/* the remote program word */
	int		 legacy_relay;	/* arm the relay in legacy mode too */
	const struct arglist *args;	/* the program's arguments */
	const char	*source_host;	/* named in messages */
	int		 shared_login;	/* a retry joins a login already made */
	/* in stdin mode, hold stdin open as the source's lifeline */
	int		 lifeline;
	/* the hooks for a relayed run, and for a legacy run without the
	 * relay */
	const struct hpn_run_hooks *hooks;
	const struct hpn_run_hooks *plain_hooks;
	pid_t		*pidp;		/* as for hpn_run_status() */
	void		(*warn)(const char *);	/* report a warning */
	void		(*fail)(const char *);	/* report a refusal */
};

/* A hpnscp -R copy as scp describes it: the source, the target, and the
 * scp options the source must repeat for the transfer it runs. */
struct hpn_scp_remote {
	const char	*ssh_program;	/* the ssh scp runs */
	const struct arglist *ssh_args;	/* scp's options for the hop */
	const char	*host;		/* the source */
	const char	*user;		/* or NULL */
	int		 port;		/* or -1 */
	const char	*src;		/* the path on the source */
	const char	*target_user;	/* or NULL */
	const char	*target_host;	/* the target */
	int		 target_port;	/* or -1 */
	const char	*target_path;	/* the path on the target */
	int		 verbose;	/* -v */
	int		 recursive;	/* -r */
	int		 preserve;	/* -p */
	int		 target_is_dir;	/* -d, the target is a directory */
	int		 streams;	/* -j */
	int		 family;	/* 4, 6, or 0 */
	int		 compress;	/* -C */
	int		 zstd_level;	/* or 0 */
	int		 verify;	/* -V */
	int		 resume;	/* -Z */
	int		 show_meter;	/* draw the relayed meter */
	pid_t		*pidp;		/* as for hpn_run_status() */
};

/* Source side. When the launcher armed stdin mode and hpnscp was started
 * with no arguments, replace argc and argv with the list read from stdin,
 * keeping argv[0]. Otherwise leave them alone. A bad or oversized list is
 * fatal. It unsets HPN_ARGS_STDIN, and in stdin mode it arms the relay,
 * so HELLO goes out on stdout. With the lifeline it then watches stdin. */
void	hpn_launch_args_stdin(int *, char ***);

/* Source side. After option parsing, expand the local source operands as
 * a shell would have, when the argument list came from stdin. Otherwise
 * do nothing. */
void	hpn_launch_args_glob(int *, char ***);

/* Launcher side. Consume the -X StrictArgs option, returning 1 when the
 * option was this one and 0 otherwise. A legacy source is then
 * refused. */
int	hpn_launch_args_option(const char *);

/* Launcher side. Run the program on the source with its arguments on
 * stdin, falling back to the legacy command line for a source that cannot
 * read them. Returns 0, HPN_EXIT_STRICT_ARGS when -X StrictArgs refuses a
 * legacy source, HPN_LAUNCH_REFUSED when it refused to run the copy, or
 * -1. */
int	hpn_launch_args_run(const struct hpn_launch *);

/* Launcher side, for scp -R. Run one source operand's copy on the source
 * through hpn_launch_args_run(), drawing the relayed meter and writing a
 * transfer log when this side wants them. Returns as
 * hpn_launch_args_run() does. */
int	hpn_launch_args_scp_remote(const struct hpn_scp_remote *);

#endif /* HPN_LAUNCH_ARGS_H */
