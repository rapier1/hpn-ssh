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

/* hpn3scp-proto.c - the hpn3scp control protocol: EVENT lines out to the
 * front end that drives hpn3scp.
 *
 * Every value on the wire is percent-encoded ASCII, so a front end never
 * receives raw bytes from a remote host. Each emitter has two renderings.
 * In protocol mode it writes one EVENT line to the protocol stream. In
 * human mode, chosen when stdout is a terminal, it writes plain text to
 * stderr, or nothing when the local meter already shows the information.
 * hpn3scp-proto.h describes the wire contract. */

#include "includes.h"

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "xmalloc.h"
#include "hpn-status-frame.h"
#include "hpn3scp.h"
#include "hpn3scp-proto.h"

/* The stream EVENT lines go to. proto_init() sets it, and event_stream()
 * falls back to stdout until then. */
static FILE *proto_out;

/* Set when stdout is a terminal. The emitters then write plain text to
 * stderr, or nothing, instead of EVENT lines. */
static int human_mode;

/* Send EVENT lines to out instead of stdout. */
void
proto_init(FILE *out)
{
	proto_out = out;
}

/* Choose the human rendering when on is nonzero, or EVENT lines when it is
 * zero. */
void
proto_set_human(int on)
{
	human_mode = on;
}

/* Whether the human rendering is on, so hpn3scp.c can drive its meter. */
int
proto_human(void)
{
	return human_mode;
}

/* The stream EVENT lines go to: the one proto_init() set, or stdout. */
static FILE *
event_stream(void)
{
	return proto_out != NULL ? proto_out : stdout;
}

/* Percent-encode a NUL-terminated string into an allocated buffer with
 * room for every byte as %XX, so a value is never truncated. The caller
 * frees the result. */
static char *
pct_encode(const char *in)
{
	size_t len = strlen(in);
	char *out;

	out = xcalloc(len + 1, 3);
	hpns_pct_encode(out, 3 * (len + 1), (const u_char *)in, len);
	return out;
}

/* Write " <name><suffix>=<value>" with the value percent-encoded. The
 * suffix lets the resolved event build src_host and the like. */
static void
emit_encoded_key(const char *name, const char *suffix, const char *value)
{
	char *encoded = pct_encode(value);

	fprintf(event_stream(), " %s%s=%s", name, suffix, encoded);
	free(encoded);
}

/* Write one EVENT line that carries a single percent-encoded value, as
 * EVENT <event> <key>=<value>. */
static void
emit_single_value(const char *event, const char *key, const char *value)
{
	fprintf(event_stream(), "EVENT %s", event);
	emit_encoded_key(key, "", value);
	fprintf(event_stream(), "\n");
	fflush(event_stream());
}

/* Emit a phase event, or log the phase under -v in human mode. The names
 * come from phase_name() in hpn3scp.c. */
void
proto_emit_phase(const char *name)
{
	if (human_mode) {
		debug("phase %s", name);
		return;
	}
	emit_single_value("phase", "name", name);
}

/* Format endpoint as [user@]host[:port]:path for a display label. An IPv6
 * host goes in brackets so its colons do not run into the port and path.
 * The label is never given to a shell. The caller frees it. */
static char *
endpoint_desc(const struct endpoint *endpoint)
{
	char *desc, portbuf[16] = "";
	const char *lbracket = "", *rbracket = "";

	if (strchr(endpoint->host, ':') != NULL) {
		lbracket = "[";
		rbracket = "]";
	}
	if (endpoint->port != -1)
		snprintf(portbuf, sizeof(portbuf), ":%d", endpoint->port);
	xasprintf(&desc, "%s%s%s%s%s%s:%s",
	    endpoint->user != NULL ? endpoint->user : "",
	    endpoint->user != NULL ? "@" : "",
	    lbracket, endpoint->host, rbracket, portbuf,
	    endpoint->path != NULL ? endpoint->path : "");
	return desc;
}

/* Write one endpoint's keys for the resolved event: the display label,
 * then the parts, with _user and _port set to default when they were not
 * given. */
static void
emit_endpoint_keys(const char *side, const struct endpoint *endpoint)
{
	char *desc = endpoint_desc(endpoint);

	emit_encoded_key(side, "", desc);
	free(desc);
	emit_encoded_key(side, "_user",
	    endpoint->user != NULL ? endpoint->user : PROTO_DEFAULT);
	emit_encoded_key(side, "_host", endpoint->host);
	if (endpoint->port != -1)
		fprintf(event_stream(), " %s_port=%d", side, endpoint->port);
	else
		fprintf(event_stream(), " %s_port=%s", side, PROTO_DEFAULT);
	emit_encoded_key(side, "_path",
	    endpoint->path != NULL ? endpoint->path : "");
}

/* Emit the resolved event with both endpoints and the stream count, or
 * log the two labels under -v in human mode. */
void
proto_emit_resolved(const struct endpoint *src, const struct endpoint *dst,
    int streams)
{
	char *src_desc, *dst_desc;

	if (human_mode) {
		src_desc = endpoint_desc(src);
		dst_desc = endpoint_desc(dst);
		debug("%s -> %s (%d streams)", src_desc, dst_desc, streams);
		free(src_desc);
		free(dst_desc);
		return;
	}
	fprintf(event_stream(), "EVENT resolved");
	emit_endpoint_keys("src", src);
	emit_endpoint_keys("dst", dst);
	fprintf(event_stream(), " streams=%d\n", streams);
	fflush(event_stream());
}

/* Write " <key>=<value>", or " <key>=unknown" when the value is not
 * known, so a front end never mistakes a placeholder for a real number. */
static void
emit_number_key(const char *key, uint64_t value, int known)
{
	if (known)
		fprintf(event_stream(), " %s=%" PRIu64, key, value);
	else
		fprintf(event_stream(), " %s=%s", key, PROTO_UNKNOWN);
}

/* Emit a progress event from a PROGRESS frame. Every field is a number,
 * so nothing needs encoding. The frame's known flags and HPNS_ETA_UNKNOWN
 * say which totals and ETA are real, and the rest go out as unknown. Human
 * mode emits nothing, because the local meter renders progress instead. */
void
proto_emit_progress(const struct hpns_progress *progress)
{
	if (human_mode)
		return;
	fprintf(event_stream(), "EVENT progress bytes=%" PRIu64,
	    progress->bytes_done);
	emit_number_key("total", progress->bytes_total,
	    progress->flags & HPNS_F_TOTAL_KNOWN);
	fprintf(event_stream(), " rate=%" PRIu64 " rate_inst=%" PRIu64,
	    progress->rate_bps, progress->rate_inst_bps);
	emit_number_key("eta", progress->eta_sec,
	    progress->eta_sec != HPNS_ETA_UNKNOWN);
	fprintf(event_stream(), " files_done=%" PRIu32, progress->files_done);
	emit_number_key("files_total", progress->files_total,
	    progress->flags & HPNS_F_FILES_KNOWN);
	fprintf(event_stream(), " workers=%u stalled=%u verifying=%d "
	    "resuming=%d\n", (unsigned)progress->workers_active,
	    (unsigned)progress->workers_stalled,
	    (progress->flags & HPNS_F_VERIFY) ? 1 : 0,
	    (progress->flags & HPNS_F_RESUME) ? 1 : 0);
	fflush(event_stream());
}

/* Emit a warning event, or print the warning on stderr in human mode. */
void
proto_emit_warning(const char *msg)
{
	if (human_mode) {
		fprintf(stderr, "hpn3scp: warning: %s\n", msg);
		return;
	}
	emit_single_value("warning", "msg", msg);
}

/* Emit an error event, or print the error on stderr in human mode. */
void
proto_emit_error(const char *msg)
{
	if (human_mode) {
		fprintf(stderr, "hpn3scp: %s\n", msg);
		return;
	}
	emit_single_value("error", "msg", msg);
}

/* Emit a file_fail event from a FILEFAIL frame. The kind byte is split
 * into the reason as a word and the truncated flag, so a front end never
 * decodes the frame's bit layout. The path is opaque bytes from the
 * source, so it is percent-encoded in full. Human mode emits nothing,
 * because the source's stderr already shows the detail. */
void
proto_emit_file_fail(const struct hpns_filefail *filefail)
{
	/* room for every byte of the longest path as %XX */
	char encoded[3 * HPNS_FILEFAIL_MAXPATH + 1];

	if (human_mode)
		return;
	hpns_pct_encode(encoded, sizeof(encoded), filefail->path,
	    filefail->path_len);
	fprintf(event_stream(), "EVENT file_fail kind=%s truncated=%d "
	    "path=%s\n", hpns_ff_kind_word(filefail->kind),
	    (filefail->kind & HPNS_FF_TRUNCATED) ? 1 : 0, encoded);
	fflush(event_stream());
}

/* Emit a file_status event from a FILEDONE frame: the status as a word,
 * the truncated flag, the size, and the percent-encoded path, as for
 * file_fail. Human mode emits nothing, because the transfer log and the
 * meter cover it. */
void
proto_emit_file_status(const struct hpns_filedone *filedone)
{
	/* room for every byte of the longest path as %XX */
	char encoded[3 * HPNS_FILEDONE_MAXPATH + 1];

	if (human_mode)
		return;
	hpns_pct_encode(encoded, sizeof(encoded), filedone->path,
	    filedone->path_len);
	fprintf(event_stream(), "EVENT file_status status=%s truncated=%d "
	    "size=%" PRIu64 " path=%s\n",
	    hpns_fd_status_word(filedone->status),
	    (filedone->status & HPNS_FD_TRUNCATED) ? 1 : 0, filedone->size,
	    encoded);
	fflush(event_stream());
}

/* Emit the done event, the last on the stream: the result, the exit
 * status, and the three counts, which are unknown when the source sent no
 * END frame. Human mode emits nothing, because the exit status and the
 * summary tell a person the result. */
void
proto_emit_done(int ok, int exit_status, int counts_known, u_int files,
    u_int verify_failed, u_int transfer_failed)
{
	if (human_mode)
		return;
	fprintf(event_stream(), "EVENT done ok=%d exit=%d", ok ? 1 : 0,
	    exit_status);
	/* Without the source's END frame the counts are not known, and a 0
	 * would read as "none", so they go out as unknown. */
	emit_number_key("files", files, counts_known);
	emit_number_key("verify_failed", verify_failed, counts_known);
	emit_number_key("transfer_failed", transfer_failed, counts_known);
	fprintf(event_stream(), "\n");
	fflush(event_stream());
}
