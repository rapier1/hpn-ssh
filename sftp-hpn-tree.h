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

/* The chunked directory tree walk: hpn-dtree-open@hpnssh.org and
 * hpn-dtree-read@hpnssh.org.
 *
 * The client asks the server to enumerate a directory subtree. The server
 * walks it locally, with no network round trip per directory, and returns
 * it in batches of records. dtree-open starts a walk and returns a handle,
 * each dtree-read returns the next batch, and the standard CLOSE ends the
 * walk. The client transfers what a batch listed before asking for the
 * next, so its memory holds one batch rather than the whole tree and data
 * starts moving after the first batch.
 *
 * The wire representation is a direction-neutral directory tree: the same
 * record set a future extension could consume to create directories. A
 * version byte in every reply message lets that extension change the
 * record format later, so no fields are reserved for it now.
 *
 * Shared contract only. The record codec is sftp-hpn-tree.c, the server
 * walk is sftp-hpn-tree-server.c, and the client walk is
 * sftp-hpn-client.c. */
#ifndef _SFTP_HPN_TREE_H
#define _SFTP_HPN_TREE_H

#include <sys/types.h>
#include <stdint.h>

#include "sftp-common.h"	/* Attrib, held by value below */

struct sshbuf;
struct sftp_conn;

/* Extension names, advertised in SSH2_FXP_VERSION and matched by the
 * client. The walk needs both. */
#define HPN_EXT_DTREE_OPEN		"hpn-dtree-open@hpnssh.org"
#define HPN_EXT_DTREE_READ		"hpn-dtree-read@hpnssh.org"

/* Reply codec version. Bump to extend the record format. */
#define HPN_DTREE_VERSION		1

/* Request flags (u32) for dtree-open. FOLLOW_SYMLINKS is the client's
 * follow_link_flag, which scp sets. The remaining bits are reserved. A
 * client sends them as 0 and the server ignores them. */
#define HPN_DTREE_FOLLOW_SYMLINKS	0x00000001u

/* Reply message kinds for dtree-read. DATA carries records. BATCH_END ends
 * a batch with more of the tree to come. END means the walk is complete. */
#define HPN_DTREE_CHUNK_DATA		0
#define HPN_DTREE_CHUNK_BATCH_END	1
#define HPN_DTREE_CHUNK_END		2

/* The most records one dtree-read may ask for. The server caps a larger
 * request at this, and the client always asks for exactly this. */
#define HPN_DTREE_MAX_BATCH		65536u

/* Record types. DIR, REG, SYMLINK, and OTHER mirror the client's per-entry
 * S_ISDIR, S_ISREG, and S_ISLNK dispatch. The server sends SYMLINK only
 * when the walk does not follow links, and the client skips it and OTHER,
 * as OpenSSH's sftp does. With HPN_DTREE_FOLLOW_SYMLINKS the server
 * reports the link's target instead. ERROR marks an entry the server could
 * not read or descend into, such as a permission failure, a dangling link
 * it was asked to follow, a directory cycle, or the depth cap. The client
 * reports it as a failure and the walk continues. */
#define HPN_DTREE_REC_DIR		0
#define HPN_DTREE_REC_REG		1
#define HPN_DTREE_REC_SYMLINK		2
#define HPN_DTREE_REC_OTHER		3
#define HPN_DTREE_REC_ERROR		4

/* Recursion cap for every HPN directory walk. The server walk and the
 * parallel walk both use this one value.
 *
 * It must equal upstream's MAX_DIR_DEPTH in sftp-client.c, which bounds the
 * readdir walk. A client picks its walk from what the server advertises, so
 * two different caps mean the same command reaches a different depth against
 * a stock server than an HPN one. Upstream defines its copy in a .c file, so
 * it cannot be included here. sftp-client.c sees both and fails the build if
 * they ever diverge. */
#define HPN_WALK_MAX_DEPTH		64

/* Directory separators for validating a path the peer sent. Mirrors
 * upstream's SFTP_DIRECTORY_CHARS in sftp-client.c, which the readdir walk
 * uses for the same purpose and which cannot be included from here because it
 * lives in a .c file. Cygwin's runtime resolves a backslash as a separator,
 * so a validator that only knows '/' there lets a peer walk out of the
 * transfer root. On POSIX a backslash is an ordinary filename byte and must
 * stay legal, which is why this is conditional rather than always both. */
#ifdef HAVE_CYGWIN
# define HPN_WALK_SEPARATORS		"/\\"
#else
# define HPN_WALK_SEPARATORS		"/"
#endif

/* Wire format.
 *
 * dtree-open  (SSH2_FXP_EXTENDED HPN_EXT_DTREE_OPEN)
 *     string  root-path
 *     uint32  flags                 (HPN_DTREE_FOLLOW_SYMLINKS | reserved-0)
 *   reply:  SSH2_FXP_HANDLE, or SSH2_FXP_STATUS when the root is missing,
 *           unreadable, or not a directory, or a walk is already open.
 *
 * dtree-read  (SSH2_FXP_EXTENDED HPN_EXT_DTREE_READ)
 *     string  handle
 *     uint32  max-records           (0, or more than HPN_DTREE_MAX_BATCH,
 *                                     means HPN_DTREE_MAX_BATCH)
 *   reply:  one or more SSH2_FXP_EXTENDED_REPLY with the same id, ending
 *           with a BATCH_END or END message:
 *     byte    version               (HPN_DTREE_VERSION)
 *     byte    kind                  (HPN_DTREE_CHUNK_*)
 *     uint32  record-count          (0 for BATCH_END and END)
 *     record[record-count]
 *   or SSH2_FXP_STATUS for a bad handle. The server splits a batch into
 *   DATA messages that each hold whole records and stay under
 *   SFTP_MAX_MSG_LENGTH. A DATA message always carries at least one
 *   record, so a read is at most max-records DATA messages plus the
 *   marker. A read after END replies END again.
 *
 * close  standard SSH2_FXP_CLOSE on the handle. One walk may be open per
 *        session.
 *
 * record (one entry of the listing):
 *     string  relative-path         (from root; '/'-separated; parents
 *                                     always precede their children; empty
 *                                     for an ERROR on the root itself)
 *     byte    rec-type              (HPN_DTREE_REC_*)
 *     ATTRS   attrib                (full Attrib; absent iff type==ERROR)
 *     uint32  status                (present iff type==ERROR: SSH2_FX_*)
 *
 * The client re-validates every relative-path except that empty one: no
 * absolute path, no "." or ".." component, no empty component, nothing at
 * or past PATH_MAX, and split on the same separator set readdir uses so a
 * Cygwin client rejects a backslash too. The server generates the paths
 * but the client does not trust the peer. See sftp_tree_relpath_ok. */

/* One decoded tree entry, as the client consumer sees it. */
struct sftp_tree_ent {
	char		*relpath;	/* relative to the walk root */
	u_char		 rectype;	/* HPN_DTREE_REC_* */
	struct Attrib	 attrs;		/* for every type but ERROR */
	u_int32_t	 status;	/* SSH2_FX_* code, for ERROR only */
};

/* The client's handle on one open walk, as hpn-dtree-open returned it.
 * sftp_tree_walk_close frees it. */
struct sftp_tree_walk {
	u_char	*handle;
	size_t	 handle_len;
};

/* Per-record callback, called by the client read as each entry arrives
 * off the wire, with the context the caller gave sftp_tree_walk_read. The
 * entry is borrowed for the duration of the call: its relpath is freed
 * once the callback returns, so a callback that needs to keep any field
 * copies it. Return zero to keep consuming. A non-zero return means the
 * callback wants no further records, typically on an interrupt. The read
 * then stops decoding and discards the rest of the batch unread, but
 * still reads it to the end marker so the exchange finishes in sync and
 * the connection stays usable. It is a "stop calling me", not an error,
 * and the read still returns 0. */
typedef int (*sftp_tree_record_cb)(void *, struct sftp_tree_ent *);

/* The record codec (sftp-hpn-tree.c), shared by the server's emitter and
 * the client's consumer. put appends one record to a buffer. get parses
 * one and allocates its relative path, which the caller frees, even when
 * a later field fails to parse. An HPN_DTREE_REC_ERROR record carries an
 * SSH2_FX_* status in place of attrs. Both return 0 or an SSH_ERR_*
 * code. */
int	sftp_tree_put_record(struct sshbuf *, const char *, u_char,
	    const struct Attrib *, u_int32_t);
int	sftp_tree_get_record(struct sshbuf *, char **, u_char *,
	    struct Attrib *, u_int32_t *);

/* Check a relative path the peer sent before it is joined to the walk
 * root. Returns 1 if it is safe, and 0 if it is empty, absolute, at or
 * past PATH_MAX, or has an empty, ".", or ".." component, splitting on
 * HPN_WALK_SEPARATORS. */
int	sftp_tree_relpath_ok(const char *);

/* The client side of the chunked walk (sftp-hpn-client.c). open sends
 * hpn-dtree-open for a root path with its request flags and keeps the
 * server's handle in the walk. read sends one hpn-dtree-read for up to the
 * given number of records and calls the callback once per record as the
 * reply arrives, under the sftp_tree_record_cb contract. It sets the done
 * flag once the walk has reached END. The reply is one or more messages on
 * the control connection, and read drains them all before returning, so
 * the callback must not send on that connection. close sends CLOSE for the
 * handle, unless the connection is dead, and frees it. Each returns 0, or
 * -1 on failure. */
int	sftp_tree_walk_open(struct sftp_conn *, const char *, uint32_t,
	    struct sftp_tree_walk *);
int	sftp_tree_walk_read(struct sftp_conn *, struct sftp_tree_walk *,
	    uint32_t, sftp_tree_record_cb, void *, int *);
int	sftp_tree_walk_close(struct sftp_conn *, struct sftp_tree_walk *);

#endif /* _SFTP_HPN_TREE_H */
