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
 * sftp-lustre-client.c - client-side Lustre layout policy for the
 * parallel-streams orchestrator (HPNLustreStripeCount), extracted verbatim
 * from sftp-parallel-walk.c.  The upload path asks the SERVER to set the
 * destination directory's default layout via the hpn-file-layout wire
 * extension; the download path applies it LOCALLY through the sftp-lustre.c
 * mechanism wrappers.  Policy only - the layout ABI and the setstripe/
 * getstripe mechanics stay in sftp-lustre.c so other filesystems can grow
 * their own policy modules without touching the transfer code.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include "log.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
#include "sftp-client-internal.h"  /* sftp_conn_{lustre_stripe_count,layout_set_declined} */
#include "sftp-hpn-client.h"        /* sftp_hpn_set_file_layout */
#include "sftp-hpn-server.h"        /* HPN_FILE_LAYOUT_* */
#include "sftp-lustre.h"            /* local layout apply (download parity) */
#include "sftp-parallel.h"
#include "sftp-lustre-client.h"

/*
 * Fallback small/large boundary for the tiered auto layout (see
 * maybe_apply_lustre_layout).  The threshold is normally derived from the
 * destination filesystem's actual OST stripe size (a file smaller than one
 * stripe gains nothing from striping); this constant is used only when the
 * server does not report a stripe size (old server, or a query miss).  1 MiB
 * matches the common Lustre default stripe size.
 */
#define LUSTRE_SMALL_THRESHOLD_FALLBACK  (1u * 1024u * 1024u)   /* 1 MiB */

/*
 * Resolve the tiered small-file threshold from a 64-bit stripe size.  The
 * threshold is carried in a u32 (the hpn-file-layout wire field and the local
 * lustre setter), so a stripe >= 4 GiB - or an exact multiple of 2^32 - would
 * truncate to a bogus value (e.g. 0, which disables the small-file tier).
 * Clamp to UINT32_MAX; a 4 GiB "small file" boundary is already well past any
 * sane ceiling.  A zero stripe (server reported none) falls back to 1 MiB.
 */
static uint32_t
stripe_to_small_threshold(uint64_t stripe_size)
{
	if (stripe_size == 0)
		return LUSTRE_SMALL_THRESHOLD_FALLBACK;
	if (stripe_size > UINT32_MAX)
		return UINT32_MAX;
	return (uint32_t)stripe_size;
}

/*
 * HPNLustreStripeCount (EXPERIMENTAL): one-shot helper run at the top of
 * the upload walker.  Queries the destination directory's filesystem via
 * hpn-fs-info; if it's Lustre, asks the server to set the directory's default
 * layout via hpn-file-layout.  Default/auto requests a tiered composite layout
 * (small files on a single OST below the stripe-size threshold - one OST object,
 * no over-striping, no MDT data - large files striped across n_workers OSTs);
 * an explicit HPNLustreStripeCount=N requests a plain N-wide stripe instead.
 * Subsequent files created in the directory (including those extracted from
 * bundles) inherit the layout.
 *
 * Silent on every non-Lustre destination - operators of non-Lustre sites
 * see nothing change.  On Lustre destinations the actual stripe-set
 * action emits one INFO line per directory modified.  Server-side
 * failure (EPERM, controlled OST pools) emits one WARN line and latches
 * conn->hpn->layout_set_declined so subsequent calls short-circuit.
 *
 * Called only when parallel mode is engaged (-j N with N >= 2); skipped
 * on single-stream transfers.
 */
void
maybe_apply_lustre_layout(struct sftp_parallel *p, struct sftp_conn *conn,
    const char *dst)
{
	struct sftp_fs_info info;
	int desired;
	int configured;
	int n_workers;
	int use_tiered;
	uint32_t small_threshold = 0;
	uint32_t applied = 0;
	uint32_t layout_kind = 0;
	int rc;

	if (p == NULL || conn == NULL || dst == NULL)
		return;
	if (sftp_conn_layout_set_declined(conn))
		return;  /* prior failure on this conn - short-circuit */

	configured = sftp_conn_lustre_stripe_count(conn);
	if (configured == 0)
		return;  /* HPNLustreStripeCount=0 → feature disabled */

	n_workers = sftp_parallel_num_streams(p);
	if (n_workers < 2)
		return;  /* not in parallel mode */

	if (!sftp_conn_has_file_layout(conn))
		return;  /* server is too old or built without it */

	/*
	 * Default/auto (HPNLustreStripeCount unset = -1): tiered composite -
	 * small files on a single OST, large files striped across n_workers OSTs.
	 * Explicit HPNLustreStripeCount=N: plain N-wide stripe.
	 */
	use_tiered = (configured < 0);
	desired    = use_tiered ? n_workers : configured;

	sftp_parallel_set_walker_phase(p, SFTP_WKP_FSINFO);
	if (sftp_fs_info(conn, dst, &info) != 0)
		return;  /* server lacks hpn-fs-info, or query failed */
	if (strcmp(info.fs_type, "lustre") != 0)
		return;  /* not a Lustre destination */
	/*
	 * Tiered small/large boundary: derive it from the filesystem's actual
	 * OST stripe size (a file smaller than one stripe gains nothing from
	 * striping).  Fall back to the 1 MiB constant when the server reports no
	 * size.  0 for the explicit plain-stripe path (no tiering).
	 */
	small_threshold = use_tiered
	    ? stripe_to_small_threshold(info.stripe_size)
	    : 0;
	/*
	 * Plain-stripe path: HPNLustreStripeCount=N is authoritative, so apply
	 * unless the dir is already at exactly N.  The guard must honour a
	 * request to NARROW a wider inherited default (e.g. an offset=-1
	 * stripe-8 project root) just as well as widen - a ">=" test silently
	 * dropped every narrowing request.  The tiered path always (re)applies:
	 * the current stripe_count can't distinguish a tiered composite from a
	 * plain layout, and re-setting the dir default is cheap and idempotent.
	 */
	if (!use_tiered && info.stripe_count == (uint32_t)desired) {
		debug_f("Lustre auto-stripe: \"%s\" already at stripe_count=%u "
		    "(desired %d); no change", dst, info.stripe_count, desired);
		return;
	}

	sftp_parallel_set_walker_phase(p, SFTP_WKP_LAYOUT);
	rc = sftp_hpn_set_file_layout(conn, dst, (u_int32_t)desired,
	    small_threshold, &applied, &layout_kind);
	switch (rc) {
	case HPN_FILE_LAYOUT_OK:
		/* Success is silent at default verbosity (like the rest of the
		 * auto-tuning); -v recovers it.  PERM/FAIL below stay loud. */
		debug("Lustre auto-stripe: \"%s\" -> %s "
		    "(stripe_count %u)", dst,
		    layout_kind ? "tiered composite" : "plain stripe", applied);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug_f("Lustre auto-stripe: \"%s\" reports not on a "
		    "layout-capable filesystem despite fs-info=lustre; "
		    "skipping further calls on this connection", dst);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("Lustre auto-stripe: \"%s\": permission "
		    "denied; layout will not be set for the rest of this "
		    "transfer.  Disable with HPNLustreStripeCount=0.", dst);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	default:
		logit("Lustre auto-stripe: \"%s\": layout set "
		    "failed (status %d); layout will not be set for the rest "
		    "of this transfer.", dst, rc);
		sftp_conn_set_layout_set_declined(conn, 1);
		break;
	}
}

/*
 * Local twin of maybe_apply_lustre_layout for DOWNLOADS.  The destination
 * directory is on a LOCAL filesystem and this process is the writer, so the
 * layout is applied directly (sftp-lustre.c path wrappers) instead of via
 * the hpn-file-layout wire extension.  The policy block mirrors the upload
 * side exactly: HPNLustreStripeCount 0=disabled, unset(<0)=tiered composite
 * sized to n_workers, explicit N=plain N-stripe with the exact-match skip
 * (narrowing honored, same as upload).  The tiered small/large boundary
 * comes from the local dir's existing stripe geometry when present, else
 * the 1 MiB fallback.
 *
 * Differences from the wire version, both deliberate:
 *  - No declined-latch: the latch exists to save wire round-trips on a
 *    server that refused; locally one open+xattr attempt per created
 *    directory is negligible next to the mkdir itself, and a NOT_FS
 *    (ext4/xfs dest) just returns quietly each time.
 *  - No fs-info gate: the setter's own NOT_FS result is the detection.
 */
void
maybe_apply_lustre_layout_local(struct sftp_parallel *p,
    struct sftp_conn *conn, const char *dst)
{
	uint64_t l_ssize = 0;
	uint32_t l_scount = 0;
	uint32_t small_threshold;
	uint32_t applied = 0;
	uint32_t rc;
	int configured;
	int n_workers;
	int use_tiered;
	int desired;

	if (p == NULL || conn == NULL || dst == NULL)
		return;
	configured = sftp_conn_lustre_stripe_count(conn);
	if (configured == 0)
		return;  /* HPNLustreStripeCount=0 -> feature disabled */
	n_workers = sftp_parallel_num_streams(p);
	if (n_workers < 2)
		return;  /* not in parallel mode */

	use_tiered = (configured < 0);
	desired    = use_tiered ? n_workers : configured;

	/* Local stripe geometry feeds the tiered boundary and the plain-path
	 * exact-match skip.  A failed read means "no default set, or not
	 * Lustre" - proceed and let the setter's NOT_FS decide. */
	(void)lustre_get_stripe(dst, &l_ssize, &l_scount);
	if (!use_tiered && l_scount == (uint32_t)desired) {
		debug_f("Lustre auto-stripe (local): \"%s\" already at "
		    "stripe_count=%u (desired %d); no change",
		    dst, l_scount, desired);
		return;
	}
	small_threshold = use_tiered
	    ? stripe_to_small_threshold(l_ssize)
	    : 0;

	rc = use_tiered
	    ? lustre_set_tiered_layout_path(dst, small_threshold,
	        (uint32_t)desired)
	    : lustre_set_stripe_path(dst, (uint32_t)desired, &applied);
	switch (rc) {
	case HPN_FILE_LAYOUT_OK:
		/* Success is silent at default verbosity, mirroring the wire
		 * variant above; PERM stays loud. */
		debug("Lustre auto-stripe (experimental): local \"%s\" -> %s "
		    "(stripe_count %u)", dst,
		    use_tiered ? "tiered composite" : "plain stripe",
		    use_tiered ? (uint32_t)desired : applied);
		break;
	case HPN_FILE_LAYOUT_NOT_FS:
		debug_f("Lustre auto-stripe (local): \"%s\" not on a "
		    "layout-capable filesystem; skipping", dst);
		break;
	case HPN_FILE_LAYOUT_PERM:
		logit("Lustre auto-stripe (experimental): local \"%s\": "
		    "permission denied; layout not set.  Disable with "
		    "HPNLustreStripeCount=0.", dst);
		break;
	default:
		debug_f("Lustre auto-stripe (local): \"%s\" layout set "
		    "failed (status %u)", dst, rc);
		break;
	}
}

/* ==========================================================================
 * Conn-side lustre/layout bridge wrappers (moved from sftp-client.c).
 *
 * Reach HPN per-connection state through sftp_conn_hpn(); behavior-identical
 * to the originals.  Declared in sftp-client-internal.h; call sites unchanged.
 * ========================================================================== */

void
sftp_conn_set_lustre_stripe_count(struct sftp_conn *conn, int value)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->lustre_stripe_count = value;
}

int
sftp_conn_lustre_stripe_count(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h == NULL)
		return 0;
	return h->lustre_stripe_count;
}

int
sftp_conn_layout_set_declined(struct sftp_conn *conn)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	return h != NULL && h->layout_set_declined;
}

void
sftp_conn_set_layout_set_declined(struct sftp_conn *conn, int v)
{
	struct sftp_hpn_conn *h = sftp_conn_hpn(conn);

	if (h != NULL)
		h->layout_set_declined = v ? 1 : 0;
}
