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

/* sftp-server-internal.h - the sftp-server.c helpers the HPN server
 * modules reply through, so they use upstream's own code rather than
 * copies of it that could drift. send_msg queues on sftp-server.c's
 * oqueue, the same buffer the dispatch hands every HPN handler.
 *
 * Also declared here: the handle-table slots for the HPN handle kinds and
 * the HPN operator toggles, which sftp-server.c defines so the HPN
 * modules need nothing of the table internals or of argv.
 *
 * Upstream merge note: sftp-server.c gains the removal of `static` from
 * the four reply helpers and the include of this header; the HPN handle
 * slots and toggles are HPN additions to that file. */

#ifndef _SFTP_SERVER_INTERNAL_H
#define _SFTP_SERVER_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

struct sshbuf;

/* sftp-server.c's input and output queues. The HPN handlers read their
 * request from iqueue as upstream's handlers do, and send_msg queues on
 * oqueue. */
extern struct sshbuf *iqueue;
extern struct sshbuf *oqueue;

int	errno_to_portable(int unixerrno);
void	send_msg(struct sshbuf *m);
void	send_status(uint32_t id, uint32_t status);
void	send_handle(uint32_t id, int handle);

/* Handle-table slots for the HPN handle kinds; each carries only the
 * module's opaque state. is_ reports whether handle is live and of that
 * kind. */
int	handle_new_bundle(void *opaque);
void	*handle_get_bundle(int handle);
int	handle_is_bundle(int handle);
void	handle_free_bundle(int handle);
int	handle_new_tree(void *opaque);
void	*handle_get_tree(int handle);
int	handle_is_tree(int handle);
void	handle_free_tree(int handle);

/* The HPN operator toggles from sftp-server's argv. use_bundle is
 * sshd_config's HPNUseBundle, passed as -B: when off, sftp-server.c
 * leaves hpn-bundle and hpn-bundle-fetch out of SSH_FXP_VERSION and the
 * bundle handlers refuse the requests with SSH2_FX_OP_UNSUPPORTED if a
 * client tries anyway. writer_pool is -O, the bundle writer pool. */
int	sftp_server_hpn_use_bundle(void);
int	sftp_server_hpn_writer_pool(void);

#endif /* _SFTP_SERVER_INTERNAL_H */
