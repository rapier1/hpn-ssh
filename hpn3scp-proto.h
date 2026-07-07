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
 * hpn3scp-proto.h - hpn3scp <-> front-end control protocol.
 *
 * Line-structured text on the engine's stdout (events out) and stdin
 * (decisions in), so a CLI and a future GUI drive one engine.  Two rules
 * make it charset/locale proof (hpn-launcher-design.md sec 8): the wire is
 * ASCII-only (every value percent-encoded), and all fields are integers or
 * validated strings formatted/parsed locale-independently (no %f/strtod,
 * explicit ASCII ctype - never the locale isalnum/isdigit).
 */

#ifndef HPN3SCP_PROTO_H
#define HPN3SCP_PROTO_H

#include <stdint.h>
#include <stdio.h>

/* Direct emit at a specific stream (defaults to stdout if never set). */
void	proto_init(FILE *out);

/* --- events out (engine -> front-end) --- */
void	proto_emit_phase(const char *name);
void	proto_emit_resolved(const char *src, const char *dst, int streams);
void	proto_emit_need_decision_hostkey(const char *fp, const char *sshfp,
	    const char *token);
void	proto_emit_need_decision_identity(const char *reason);
void	proto_emit_progress(uint64_t bytes, uint64_t total, uint64_t rate,
	    uint32_t eta, uint32_t files_done, uint32_t files_total,
	    uint16_t workers, uint16_t stalled);
void	proto_emit_warning(const char *msg);
void	proto_emit_error(const char *msg);
void	proto_emit_done(int ok, int exit_status);

/* --- decisions in (front-end -> engine) --- */
enum proto_decision_kind {
	PROTO_DEC_NONE,		/* blank / non-DECISION line: ignore */
	PROTO_DEC_ACCEPT_HOSTKEY,
	PROTO_DEC_USE_IDENTITY,
	PROTO_DEC_CANCEL,
	PROTO_DEC_UNKNOWN	/* DECISION with an unrecognized kind */
};

struct proto_decision {
	enum proto_decision_kind kind;
	char	token[128];	/* accept_hostkey: binds to the shown key */
	int	accept;		/* accept_hostkey: 1 = accept */
	char	path[1024];	/* use_identity: local key file */
};

/*
 * Read and parse one line from `in` into `d`.  Returns 0 on any line read
 * (including blank / unknown, reported via d->kind), -1 on EOF/error.
 */
int	proto_read_decision(FILE *in, struct proto_decision *d);

#endif /* HPN3SCP_PROTO_H */
