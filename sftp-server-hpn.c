/*
 * sftp-server-hpn.c — HPN-SSH server-side SFTP extensions.
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * Isolating HPN-specific extension handlers here keeps sftp-server.c's
 * diff against upstream small.
 *
 * Phase 3 — hpn-fs-info@hpnssh.org
 * ---------------------------------
 * Returns filesystem type and stripe geometry for a given path so that
 * the parallel client (sftp-parallel.c) can align byte-range transfers to
 * Lustre/GPFS stripe boundaries.
 *
 * Detection layers (each falls back to the next):
 *   1. statfs() f_type magic number → filesystem type string
 *   2. Lustre: llapi_file_get_stripe() if built with --with-lustre;
 *      otherwise invoke "lfs getstripe --yaml <path>" as subprocess
 *   3. GPFS:   gpfs_fcntl() if built with --with-gpfs;
 *              otherwise invoke "mmlsattr -L <path>" as subprocess
 *   4. Fallback: f_bsize from statvfs(), zeros for stripe fields
 *
 * Wire format (SSH_FXP_EXTENDED_REPLY):
 *   fs_type      string   "lustre"|"gpfs"|"xfs"|"ext4"|"nfs"|"unknown"|...
 *   stripe_size  uint64   bytes per stripe; 0 if not applicable
 *   stripe_count uint32   number of stripes/OSTs; 0 if not applicable
 *   block_size   uint64   optimal I/O block size (always present)
 *
 * Copyright (c) 2024-2026 Pittsburgh Supercomputing Center / HPN-SSH project.
 * See LICENCE for redistribution terms.
 */

#include "includes.h"

#include <sys/statvfs.h>
#include <sys/types.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-server-hpn.h"

/* Extension name advertised to clients */
#define HPN_EXT_FS_INFO "hpn-fs-info@hpnssh.org"

int
sftp_server_hpn_handles(const char *name)
{
	return strcmp(name, HPN_EXT_FS_INFO) == 0;
}

void
sftp_server_hpn_dispatch(u_int id, const char *name,
    struct sshbuf *iqueue, struct sshbuf *oqueue)
{
	/*
	 * Phase 3 — not yet implemented.
	 *
	 * When implemented this function will:
	 *   1. Parse the path argument from iqueue
	 *   2. Detect filesystem type via statfs() magic number
	 *   3. Query Lustre/GPFS stripe geometry if applicable
	 *   4. Send SSH_FXP_EXTENDED_REPLY with fs_type, stripe_size,
	 *      stripe_count, block_size
	 *
	 * For now, return SSH2_FX_OP_UNSUPPORTED so the client falls back
	 * to equal-size range splitting.
	 */
	(void)iqueue;
	(void)name;

	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_FXP_STATUS)) != 0 ||
	    (r = sshbuf_put_u32(msg, id)) != 0 ||
	    (r = sshbuf_put_u32(msg, SSH2_FX_OP_UNSUPPORTED)) != 0 ||
	    (r = sshbuf_put_cstring(msg, "not yet implemented")) != 0 ||
	    (r = sshbuf_put_cstring(msg, "")) != 0)
		fatal_fr(r, "compose");
	if ((r = sshbuf_put_stringb(oqueue, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
}
