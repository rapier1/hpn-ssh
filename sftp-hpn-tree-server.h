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

/* sftp-hpn-tree-server.h - server side of the chunked tree walk.
 *
 * Two extended requests. hpn-tree-open@hpnssh.org starts a walk of a
 * directory subtree and returns a handle. hpn-tree-read@hpnssh.org
 * returns the next batch of records from that walk. The walk state
 * lives in the handle between requests, so the client drains one batch,
 * transfers what it listed, and asks for the next. The standard CLOSE
 * frees the handle. The wire format and the record codec are in
 * sftp-hpn-tree.h. The two request handlers are called by the
 * dispatcher in sftp-hpn-server.c. */

#ifndef _SFTP_HPN_TREE_SERVER_H
#define _SFTP_HPN_TREE_SERVER_H

struct sshbuf;

/* Tree handles live in sftp-server.c's handle table as HANDLE_TREE. The
 * close hook in sftp-hpn-server.c tests for one with the predicate and
 * calls the close below instead of the fd path. */
int sftp_hpn_tree_is_handle(int handle);

/* Free a tree handle and its open directories. Returns the SSH2_FX_*
 * status for the caller to send. */
int sftp_hpn_tree_close(int handle);

/* The two extended-request handlers. tree-open replies with
 * SSH2_FXP_HANDLE, or SSH2_FXP_STATUS on failure. tree-read replies with
 * one or more SSH2_FXP_EXTENDED_REPLY messages, or SSH2_FXP_STATUS for a
 * bad handle. */
void sftp_hpn_tree_open(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);
void sftp_hpn_tree_read(u_int id, struct sshbuf *iqueue,
    struct sshbuf *oqueue);

#endif /* _SFTP_HPN_TREE_SERVER_H */
