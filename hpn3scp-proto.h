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

/* hpn3scp-proto.h - the control protocol between hpn3scp and the front
 * end that drives it.
 *
 * hpn3scp writes one EVENT line per event on stdout, so the command line
 * and a future GUI drive the same engine. The wire is ASCII only. Every
 * string value is percent-encoded, and numbers are plain decimal written
 * without the locale, so the stream reads the same under any LC_*
 * setting.
 *
 * The contract for every front end: an event's fields are key=value
 * tokens. Parse them by key, ignore keys you do not know, and do not
 * depend on their order, because new keys may appear in any event. A
 * parser that reads fields by position will break on the next new key.
 * The protocol is experimental, so keys may still be renamed or dropped
 * as the GUI requires.
 *
 * Three kinds of value need care. A key the engine reports but does not
 * know yet carries "unknown" (PROTO_UNKNOWN) in place of a number, for
 * example eta=unknown, so never read a 0 or a large number as unknown. A
 * key whose setting the user did not give, such as a port, carries
 * "default" (PROTO_DEFAULT), and ssh's own default applies. A key that is
 * missing is one this engine does not report at all. */

#ifndef HPN3SCP_PROTO_H
#define HPN3SCP_PROTO_H

#include <sys/types.h>	/* for u_int */

#include <stdio.h>	/* for FILE */

/* The value of a key the engine reports but does not know yet */
#define PROTO_UNKNOWN	"unknown"
/* The value of a key whose setting was not given, so ssh's default applies */
#define PROTO_DEFAULT	"default"

/* Defined in hpn3scp.h and hpn-status-frame.h. Only pointers are needed
 * here, so callers need not include either. */
struct endpoint;
struct hpns_progress;
struct hpns_filefail;
struct hpns_filedone;

/* Send EVENT lines to a stream other than stdout, the default. */
void	proto_init(FILE *);

/* The output mode. Protocol mode, the default, writes EVENT lines for the
 * front end that drives hpn3scp. Human mode, chosen when stdout is a
 * terminal, renders for a person instead: errors and warnings as plain
 * text on stderr, phases only under -v, and progress through the local
 * meter, which hpn3scp.c drives after checking proto_human(). */
void	proto_set_human(int);
int	proto_human(void);

/* The events. Each emitter writes one EVENT line in protocol mode. */

/* A phase change, as name=, with the names phase_name() in hpn3scp.c
 * gives. */
void	proto_emit_phase(const char *);

/* The resolved event carries each endpoint as parts: src_user=,
 * src_host=, src_port=, and src_path=, with src_user= and src_port= set to
 * default when not given, and the same dst_ keys. src= and dst= are
 * display labels, [user@]host[:port]:path with an IPv6 host in brackets.
 * A front end should read the parts. */
void	proto_emit_resolved(const struct endpoint *,
	    const struct endpoint *, int);

/* Aggregate progress from a decoded PROGRESS frame, or from a final
 * snapshot the caller builds. verifying= and resuming= come from the
 * frame's phase flags. total, eta, and files_total are unknown until the
 * source reports them. */
void	proto_emit_progress(const struct hpns_progress *);

/* The source is still sending, though its progress cannot be read. Sent
 * at most once a second after the mismatch warning, in place of the
 * progress events. Human mode emits nothing, because the local meter
 * shows it. */
void	proto_emit_alive(void);

/* A warning or an error, as msg=. In human mode they go to stderr as
 * plain text instead. */
void	proto_emit_warning(const char *);
void	proto_emit_error(const char *);

/* One failed file, from a decoded FILEFAIL frame: kind=transfer or
 * kind=verify (unknown for a reason this engine does not know),
 * truncated=1 when the source clipped a long path, and the path, which is
 * percent-encoded so any bytes, UTF-8 included, cross safely. */
void	proto_emit_file_fail(const struct hpns_filefail *);

/* One file's final status, from a decoded FILEDONE frame, which a source
 * armed with the "log" value sends: status= as a word (unknown for a
 * status this engine does not know), truncated=, size=, and path=, as for
 * file_fail. */
void	proto_emit_file_status(const struct hpns_filedone *);

/* The last event. ok and exit_status give the result. The files,
 * verify_failed, and transfer_failed counts go out as numbers when
 * counts_known is set, which means the source sent its END frame, and as
 * unknown otherwise. */
void	proto_emit_done(int ok, int exit_status, int counts_known,
	    u_int files, u_int verify_failed, u_int transfer_failed);

#endif /* HPN3SCP_PROTO_H */
