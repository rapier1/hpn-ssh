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
 * The chunked directory tree walk: hpn-dtree-open@hpnssh.org and
 * hpn-dtree-read@hpnssh.org.
 *
 * The client asks the server to enumerate a directory subtree. The server
 * walks it locally, with no network round trip per directory, and returns
 * it in batches of records. dtree-open starts a walk and returns a handle,
 * each dtree-read returns the next batch, and the standard CLOSE ends the
 * walk. The client transfers what a batch listed before asking for the
 * next, so its memory holds one batch rather than the whole tree and data
 * starts moving after the first batch. See hpn-chunked-tree-walk-design.md.
 *
 * The wire representation is a direction-neutral directory tree: the same
 * record set a future extension could consume to create directories. A
 * version byte in every reply message lets that future extend the record
 * format without paying bytes now.
 *
 * Shared contract only. The record codec is sftp-hpn-tree.c, the server
 * walk is sftp-hpn-tree-server.c and the client walk is sftp-hpn-client.c.
 */
#ifndef _SFTP_HPN_TREE_H
#define _SFTP_HPN_TREE_H

/* Forward decls only - sftp-common.h has no include guard, so pull it in
 * from the .c files, not here.  Every includer already includes sftp-common.h
 * FIRST, so struct Attrib is complete by the time this header is read (needed
 * for the by-value member in struct sftp_tree_ent below). */
struct sshbuf;
struct Attrib;
struct sftp_conn;

/* Extension names, advertised in SSH2_FXP_VERSION and matched by the
 * client. The walk needs both. */
#define HPN_EXT_DTREE_OPEN		"hpn-dtree-open@hpnssh.org"
#define HPN_EXT_DTREE_READ		"hpn-dtree-read@hpnssh.org"

/* Reply codec version. Bump to extend the record format. */
#define HPN_DTREE_VERSION		1

/* Request flags (u32) for dtree-open. FOLLOW_SYMLINKS is the client's
 * follow_link_flag, which scp sets. The remaining bits are reserved and
 * must be 0. */
#define HPN_DTREE_FOLLOW_SYMLINKS	0x00000001u

/* Reply message kinds for dtree-read. DATA carries records. BATCH_END ends
 * a batch with more of the tree to come. END means the walk is complete. */
#define HPN_DTREE_CHUNK_DATA		0
#define HPN_DTREE_CHUNK_BATCH_END	1
#define HPN_DTREE_CHUNK_END		2

/* The most records one dtree-read may ask for. The server caps a larger
 * request at this, and the client requests exactly this by default. */
#define HPN_DTREE_MAX_BATCH		65536u

/*
 * Record types.  DIR/REG/SYMLINK/OTHER mirror the client's per-entry
 * S_ISDIR/S_ISREG/S_ISLNK dispatch (symlinks are skipped, per OpenSSH).
 * ERROR is an inline marker for a subtree the server could not read
 * (e.g. EACCES): the walk skips it and continues rather than aborting.
 */
#define HPN_DTREE_REC_DIR		0
#define HPN_DTREE_REC_REG		1
#define HPN_DTREE_REC_SYMLINK		2
#define HPN_DTREE_REC_OTHER		3
#define HPN_DTREE_REC_ERROR		4

/*
 * Recursion cap for every HPN directory walk: the server walk and the
 * parallel walk both use this one value.
 *
 * It must equal upstream's MAX_DIR_DEPTH in sftp-client.c, which bounds the
 * readdir walk.  A client picks its walk from what the server advertises, so
 * two different caps mean the same command reaches a different depth against
 * a stock server than an HPN one.  Upstream defines its copy in a .c file so
 * it cannot be included here; sftp-client.c sees both and fails the build if
 * they ever diverge.
 */
#define HPN_WALK_MAX_DEPTH		64

/*
 * Directory separators for validating a path the peer sent.  Mirrors
 * upstream's SFTP_DIRECTORY_CHARS in sftp-client.c, which the readdir walk
 * uses for the same purpose and which cannot be included from here because it
 * lives in a .c file.  Cygwin's runtime resolves a backslash as a separator,
 * so a validator that only knows '/' there lets a peer walk out of the
 * transfer root.  On POSIX a backslash is an ordinary filename byte and must
 * stay legal, which is why this is conditional rather than always both.
 */
#ifdef HAVE_CYGWIN
# define HPN_WALK_SEPARATORS		"/\\"
#else
# define HPN_WALK_SEPARATORS		"/"
#endif

/*
 * Wire format.
 *
 * dtree-open  (SSH2_FXP_EXTENDED HPN_EXT_DTREE_OPEN)
 *     string  root-path
 *     uint32  flags                 (HPN_DTREE_FOLLOW_SYMLINKS | reserved-0)
 *   reply:  SSH2_FXP_HANDLE, or SSH2_FXP_STATUS when the root is missing,
 *           unreadable or not a directory, or a walk is already open.
 *
 * dtree-read  (SSH2_FXP_EXTENDED HPN_EXT_DTREE_READ)
 *     string  handle
 *     uint32  max-records           (0, or above HPN_DTREE_MAX_BATCH, = max)
 *   reply:  one or more SSH2_FXP_EXTENDED_REPLY with the same id:
 *     byte    version               (HPN_DTREE_VERSION)
 *     byte    kind                  (HPN_DTREE_CHUNK_*)
 *     uint32  record-count          (0 for BATCH_END and END)
 *     record[record-count]
 *   or SSH2_FXP_STATUS for a bad handle. A DATA message always carries at
 *   least one record, so a read is bounded by max-records messages. A read
 *   after END replies END again.
 *
 * close  standard SSH2_FXP_CLOSE on the handle. One walk may be open per
 *        session.
 *
 * record:
 *     string  relative-path         (from root; '/'-separated; parents
 *                                     always precede their children)
 *     byte    rec-type              (HPN_DTREE_REC_*)
 *     ATTRS   attrib                 (full Attrib; absent iff type==ERROR)
 *     uint32  status                 (present iff type==ERROR: SSH2_FX_*)
 *
 * The client re-validates every relative-path: no absolute path, no "."
 * or ".." component, no empty component, nothing at or past PATH_MAX, and
 * split on the same separator set readdir uses so a Cygwin client rejects a
 * backslash too. The server generates the paths but the client does not
 * trust the peer. See sftp_tree_relpath_ok.
 */

/*
 * Record codec (sftp-hpn-tree.c), shared by the server emitter and the
 * client consumer.  put appends one record to m; get parses one from m and
 * allocates *relpath (caller frees).  status is meaningful only for
 * HPN_DTREE_REC_ERROR records (SSH2_FX_*); attrs are present otherwise.
 */
int	sftp_tree_put_record(struct sshbuf *msg, const char *relpath,
	    u_char rectype, const struct Attrib *a, u_int32_t status);
int	sftp_tree_get_record(struct sshbuf *msg, char **relpath,
	    u_char *rectype, struct Attrib *a, u_int32_t *status);

/*
 * One decoded tree entry as the client consumer sees it.  relpath is
 * relative to the walk root; rectype is HPN_DTREE_REC_*; a holds the
 * attrs (all types except ERROR); status is the SSH2_FX_* code for an
 * ERROR entry.
 */
struct sftp_tree_ent {
	char		*relpath;
	u_char		 rectype;
	struct Attrib	 a;
	u_int32_t	 status;
};

/*
 * Per-record callback invoked by the client read as each entry arrives off
 * the wire. ent is borrowed for the duration of the call: ent->relpath is
 * freed once the callback returns, so a callback that needs to retain any
 * field copies it. Return zero to keep consuming. A non-zero return means
 * the callback wants no further records, typically an interrupt: the read
 * stops decoding and discards the rest of the batch unread, but still reads
 * it to the end marker so the exchange finishes in sync and the connection
 * stays usable. It is a "stop calling me", not an error, and the read still
 * returns 0.
 */
typedef int (*sftp_tree_record_cb)(void *ctx, struct sftp_tree_ent *ent);

/* Safety check on a received relative path (no absolute, no "..").  1 = ok. */
int	sftp_tree_relpath_ok(const char *rel);

/*
 * Client side of the chunked walk (sftp-hpn-client.c). open sends
 * hpn-dtree-open for root and keeps the server's handle in *walk. read sends
 * one hpn-dtree-read for up to max_records records and calls cb once per
 * record as the reply arrives, with the same callback contract as above: a
 * nonzero return stops decoding and the rest of the batch is read and
 * discarded. *done is set once the walk has reached END. The reply is one
 * or more messages on the control connection, and read drains them all
 * before returning, so cb must not send on that connection. close sends
 * CLOSE for the handle and frees it. Each returns 0, or -1 on failure.
 */
struct sftp_tree_walk {
	u_char	*handle;
	size_t	 handle_len;
};

int	sftp_tree_walk_open(struct sftp_conn *conn, const char *root,
	    uint32_t flags, struct sftp_tree_walk *walk);
int	sftp_tree_walk_read(struct sftp_conn *conn, struct sftp_tree_walk *walk,
	    uint32_t max_records, sftp_tree_record_cb cb, void *ctx, int *done);
int	sftp_tree_walk_close(struct sftp_conn *conn,
	    struct sftp_tree_walk *walk);

#endif /* _SFTP_HPN_TREE_H */
