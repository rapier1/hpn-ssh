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

/* sftp-lustre-client.c - the client's Lustre layout policy for parallel
 * transfers (HPNLustreStripeCount).
 *
 * On an upload the client asks the server to set the destination
 * directory's layout through the hpn-file-layout extension. On a download
 * it sets the local destination's layout itself through sftp-lustre.c.
 * This file decides when and what to ask for. The layout ABI and the calls
 * that set and read layouts stay in sftp-lustre.c, so another filesystem
 * can get a policy module of its own without touching the transfer code.
 * The connection's stripe count setting, and the latch that stops asking
 * after a refusal, live here too. */

#include "includes.h"

#include <sys/types.h>

#include <libgen.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"	/* sftp_conn_hpn, count accessors */
#include "sftp-hpn-client.h"	/* struct sftp_hpn_conn, the layout request */
#include "sftp-hpn-server.h"	/* HPN_FILE_LAYOUT_* */
#include "sftp-lustre.h"	/* lustre_get_stripe, lustre_set_layout_path */
#include "sftp-parallel.h"
#include "sftp-lustre-client.h"

/* The tiered layout's small-file boundary when no stripe size is known.
 * The boundary is normally the filesystem's stripe size, since a file
 * smaller than one stripe gains nothing from striping. This fallback
 * covers a server that reports no stripe size and a local destination
 * whose layout cannot be read. 1 MiB is the common Lustre default stripe
 * size. */
#define LUSTRE_SMALL_THRESHOLD_FALLBACK  (1024 * 1024)   /* 1 MiB */

/* The tiered layout's small-file boundary for a stripe size: the size
 * itself, the fallback when it is 0 (unknown), or UINT32_MAX when it does
 * not fit the 32-bit boundary that the hpn-file-layout request and the
 * local setter carry. Lustre's own stripe size is 32 bits, but hpn-fs-info
 * sends it as 64, so only a server can report a larger one. Without the
 * clamp it would truncate, and a multiple of 2^32 would truncate to 0,
 * which turns the small-file tier off. */
static uint32_t
stripe_to_small_threshold(uint64_t stripe_size)
{
	if (stripe_size == 0)
		return LUSTRE_SMALL_THRESHOLD_FALLBACK;
	if (stripe_size > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)stripe_size;
}

/* Query and set the latch that records the server turning down
 * hpn-file-layout on this connection. maybe_apply_lustre_layout() sets it
 * after the first reply that is not OK, NOT_FS included, so later
 * directories skip the round trip. Safe when conn or conn->hpn is NULL. */
static int
sftp_conn_layout_set_declined(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->layout_set_declined;
}

static void
sftp_conn_set_layout_set_declined(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->layout_set_declined = 1;
}

/* Query and set the download side's latch: set after the first PERM or
 * FAIL from setting a local destination's layout, so later directories
 * skip the attempt. Separate from the upload latch, since one session can
 * go both ways. Safe when conn or conn->hpn is NULL. */
static int
sftp_conn_local_layout_declined(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->local_layout_declined;
}

static void
sftp_conn_set_local_layout_declined(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->local_layout_declined = 1;
}

/* The layout HPNLustreStripeCount asks for. Returns 0 when the setting is
 * off or the transfer is not parallel. Otherwise returns 1, with
 * *use_tiered set for the auto setting and *desired the stripe count, the
 * worker count under auto. */
static int
layout_request(struct sftp_parallel *fleet, struct sftp_conn *conn,
    int *use_tiered, int *desired)
{
	int configured;
	int n_workers;

	configured = sftp_conn_lustre_stripe_count(conn);
	if (configured == 0)
		return 0;  /* HPNLustreStripeCount=0 turns it off */
	n_workers = sftp_parallel_num_streams(fleet);
	if (n_workers < 2)
		return 0;  /* not in parallel mode */
	*use_tiered = (configured < 0);
	*desired = *use_tiered ? n_workers : configured;
	return 1;
}

/* Upload side of HPNLustreStripeCount. For a directory the upload creates,
 * or the parent of a single-file upload's destination, ask hpn-fs-info for
 * its filesystem. On Lustre, ask the server through hpn-file-layout to set
 * the directory's layout, which the files created in it then inherit,
 * those extracted from bundles included. By default the layout is tiered:
 * files below the stripe size on one OST, larger ones across as many OSTs
 * as there are workers. HPNLustreStripeCount=N asks for a plain stripe
 * across N OSTs instead.
 *
 * It does nothing unless the transfer is parallel (-j 2 or more), the
 * setting is not 0, and the server has both extensions. A destination that
 * is not Lustre changes nothing and logs nothing. Success logs at debug
 * level. Any other reply logs once, at INFO for PERM and FAIL and at debug
 * for NOT_FS, and latches the connection so later directories skip the
 * request. Returns NOT_LUSTRE when hpn-fs-info names another filesystem,
 * SETTLED after any reply to the request or for a directory already at N,
 * and UNKNOWN when it stops before asking or the query fails.
 * Experimental. */
enum lustre_layout_result
maybe_apply_lustre_layout(struct sftp_parallel *fleet, struct sftp_conn *conn,
    const char *dst)
{
	struct sftp_fs_info info;
	int desired;
	int use_tiered;
	uint32_t small_threshold = 0;
	uint32_t applied = 0;
	uint32_t layout_kind = HPN_FILE_LAYOUT_KIND_STRIPE;
	int status;

	if (fleet == NULL || conn == NULL || dst == NULL)
		return LUSTRE_LAYOUT_UNKNOWN;
	/* an earlier request was turned down */
	if (sftp_conn_layout_set_declined(conn))
		return LUSTRE_LAYOUT_UNKNOWN;
	if (!layout_request(fleet, conn, &use_tiered, &desired))
		return LUSTRE_LAYOUT_UNKNOWN;
	/* the server is too old or built without it */
	if (!sftp_conn_has_file_layout(conn))
		return LUSTRE_LAYOUT_UNKNOWN;

	sftp_parallel_set_walker_phase(fleet, SFTP_WKP_FSINFO);
	if (sftp_fs_info(conn, dst, &info) != 0)
		return LUSTRE_LAYOUT_UNKNOWN;  /* no hpn-fs-info, or it failed */
	if (strcmp(info.fs_type, "lustre") != 0)
		return LUSTRE_LAYOUT_NOT_LUSTRE;
	/* The tiered boundary is the filesystem's stripe size, since a file
	 * smaller than one stripe gains nothing from striping. 0 means no
	 * tiers. */
	small_threshold = use_tiered
	    ? stripe_to_small_threshold(info.stripe_size)
	    : 0;
	/* A plain stripe of N is authoritative, so it is set unless the
	 * directory already has exactly N. The test must let a request narrow
	 * a wider inherited layout, such as a stripe-8 project root, as well
	 * as widen one. A >= test once dropped every narrowing request. The
	 * tiered layout is always set: the stripe count cannot tell a tiered
	 * layout from a plain one, and setting it again is cheap and
	 * idempotent. */
	if (!use_tiered && info.stripe_count == (uint32_t)desired) {
		debug_f("Lustre auto-stripe: \"%s\" already at stripe_count=%u "
		    "(desired %d); no change", dst, info.stripe_count, desired);
		return LUSTRE_LAYOUT_SETTLED;
	}

	sftp_parallel_set_walker_phase(fleet, SFTP_WKP_LAYOUT);
	status = sftp_hpn_set_file_layout(conn, dst, (uint32_t)desired,
	    small_threshold, &applied, &layout_kind);
	/* one line per outcome, and any reply but OK stops later requests */
	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		/* Success is silent at default verbosity, like the rest of the
		 * auto-tuning, and -v shows it. PERM and FAIL stay loud. */
		debug("Lustre auto-stripe: \"%s\" -> %s "
		    "(stripe_count %u)", dst,
		    layout_kind == HPN_FILE_LAYOUT_KIND_TIERED ?
		    "tiered composite" : "plain stripe", applied);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug_f("Lustre auto-stripe: \"%s\" reports not on a "
		    "layout-capable filesystem despite fs-info=lustre; "
		    "skipping further calls on this connection", dst);
		sftp_conn_set_layout_set_declined(conn);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("Lustre auto-stripe: \"%s\": permission "
		    "denied; layout will not be set for the rest of this "
		    "session. Disable with HPNLustreStripeCount=0.", dst);
		sftp_conn_set_layout_set_declined(conn);
		break;
	default:
		logit("Lustre auto-stripe: \"%s\": layout set "
		    "failed (status %d); layout will not be set for the rest "
		    "of this session.", dst, status);
		sftp_conn_set_layout_set_declined(conn);
		break;
	}
	return LUSTRE_LAYOUT_SETTLED;
}

/* Download side of HPNLustreStripeCount: the same policy, applied
 * directly with lustre_set_layout_path, since the destination directory is
 * local and this process writes it. The tiered boundary comes from the
 * directory's own stripe geometry, or the fallback when it has none.
 *
 * It differs from the upload side in two ways, both deliberate. It runs no
 * fs-info query, since the setter's NOT_FS is the test. And NOT_FS, from an
 * ext4 or xfs destination, sets no latch, since one attempt per directory
 * costs little next to the mkdir. PERM and FAIL log once at INFO and set
 * the download side's own latch, so later directories skip the attempt. */
void
maybe_apply_lustre_layout_local(struct sftp_parallel *fleet,
    struct sftp_conn *conn, const char *dst)
{
	uint64_t stripe_size = 0;
	uint32_t stripe_count = 0;
	uint32_t small_threshold;
	uint32_t applied = 0;
	uint32_t layout_kind = HPN_FILE_LAYOUT_KIND_STRIPE;
	uint32_t status;
	int use_tiered;
	int desired;

	if (fleet == NULL || conn == NULL || dst == NULL)
		return;
	if (sftp_conn_local_layout_declined(conn))
		return;  /* an earlier attempt was refused */
	if (!layout_request(fleet, conn, &use_tiered, &desired))
		return;

	/* The directory's stripe geometry feeds the tiered boundary and the
	 * plain stripe's "already at N" test. A failed read leaves both 0, and
	 * the setter's NOT_FS then decides. */
	(void)lustre_get_stripe(dst, &stripe_size, &stripe_count);
	if (!use_tiered && stripe_count == (uint32_t)desired) {
		debug_f("Lustre auto-stripe (local): \"%s\" already at "
		    "stripe_count=%u (desired %d); no change",
		    dst, stripe_count, desired);
		return;
	}
	small_threshold = use_tiered
	    ? stripe_to_small_threshold(stripe_size)
	    : 0;

	status = lustre_set_layout_path(dst, (uint32_t)desired,
	    small_threshold, &applied, &layout_kind);
	/* one line per outcome, and PERM or FAIL stops later attempts */
	switch (status) {
	case HPN_FILE_LAYOUT_OK:
		/* Success is silent at default verbosity, as on the upload
		 * side. */
		debug("Lustre auto-stripe (local): \"%s\" -> %s "
		    "(stripe_count %u)", dst,
		    layout_kind == HPN_FILE_LAYOUT_KIND_TIERED ?
		    "tiered composite" : "plain stripe", applied);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug_f("Lustre auto-stripe (local): \"%s\" not on a "
		    "layout-capable filesystem; skipping", dst);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("Lustre auto-stripe (local): \"%s\": permission "
		    "denied; layout will not be set for the rest of this "
		    "session. Disable with HPNLustreStripeCount=0.", dst);
		sftp_conn_set_local_layout_declined(conn);
		break;
	default:
		logit("Lustre auto-stripe (local): \"%s\": layout set "
		    "failed (status %u); layout will not be set for the rest "
		    "of this session.", dst, status);
		sftp_conn_set_local_layout_declined(conn);
		break;
	}
}

/* True when parent, on the side local names, is the last parent
 * maybe_apply_lustre_layout_parent() got an answer for. Safe when conn or
 * conn->hpn is NULL. */
static int
layout_parent_remembered(struct sftp_conn *conn, const char *parent,
    int local)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	return hpn != NULL && hpn->layout_parent != NULL &&
	    hpn->layout_parent_local == local &&
	    strcmp(hpn->layout_parent, parent) == 0;
}

/* Remember parent and its side as the last parent that got an answer,
 * replacing the one before. Safe when conn or conn->hpn is NULL. */
static void
layout_parent_remember(struct sftp_conn *conn, const char *parent, int local)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	free(hpn->layout_parent);
	hpn->layout_parent = xstrdup(parent);
	hpn->layout_parent_local = local;
}

/* Drop the remembered parent, so the next
 * maybe_apply_lustre_layout_parent() call asks again. Declared in
 * sftp-client-internal.h, and sftp.c calls it at the start of each get and
 * put. Safe when conn or conn->hpn is NULL. */
void
sftp_conn_forget_layout_parent(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return;
	free(hpn->layout_parent);
	hpn->layout_parent = NULL;
}

/* Apply the layout to the parent directory of path, for a single-file -j
 * transfer that does not go through the walker. local is 1 when the
 * destination is local (a download) and 0 when it is remote (an upload). */
void
maybe_apply_lustre_layout_parent(struct sftp_parallel *fleet,
    struct sftp_conn *conn, const char *path, int local)
{
	char *copy;
	char *parent;

	if (path == NULL)
		return;
	/* POSIX lets dirname write into its argument, so it gets a copy */
	copy = xstrdup(path);
	parent = dirname(copy);
	/* an earlier file of this command already settled this parent */
	if (layout_parent_remembered(conn, parent, local)) {
		free(copy);
		return;
	}
	/* The twins check the setting, the worker count, and their latches.
	 * The local twin's early returns hold for the whole command, so any
	 * call settles its parent. On the upload side UNKNOWN is not
	 * remembered, so a failed query is tried again. */
	if (local) {
		maybe_apply_lustre_layout_local(fleet, conn, parent);
		layout_parent_remember(conn, parent, local);
	} else if (maybe_apply_lustre_layout(fleet, conn, parent) !=
	    LUSTRE_LAYOUT_UNKNOWN)
		layout_parent_remember(conn, parent, local);
	free(copy);
}

/* Set and read the connection's HPNLustreStripeCount, declared in
 * sftp-client-internal.h with the other accessors that reach the HPN state
 * through sftp_conn_hpn(). Without HPN state the count reads 0, which turns
 * the layout policy off. */
void
sftp_conn_set_lustre_stripe_count(struct sftp_conn *conn, int value)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn != NULL)
		hpn->lustre_stripe_count = value;
}

int
sftp_conn_lustre_stripe_count(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *hpn = sftp_conn_hpn(conn);

	if (hpn == NULL)
		return 0;
	return hpn->lustre_stripe_count;
}
