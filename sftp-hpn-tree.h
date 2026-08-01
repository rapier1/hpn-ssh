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
 * hpn-discover-tree@hpnssh.org - server-side remote directory discovery.
 *
 * The client asks the server to enumerate a directory subtree; the server
 * walks it LOCALLY (opendir/readdir syscalls, no network per directory) and
 * PUSH-streams the result back as successive SSH2_FXP_EXTENDED_REPLY chunks
 * for the one request id, terminated by an END chunk - no per-chunk round
 * trip (mirrors the hpn-bundle-fetch streaming model).  This replaces the
 * N-directories x ~4-round-trip readdir walk on the download control
 * connection with a single request; see hpn-discover-tree-design.md.
 *
 * The wire representation is a direction-NEUTRAL directory tree: the same
 * record set a future hpn-make-tree could consume to CREATE directories.
 * A version byte in every reply chunk lets that future extend the record
 * format (e.g. symlink targets) without paying bytes now.
 *
 * Shared contract only.  Encode/decode helpers (sftp-hpn-tree.c) and the
 * server walk (sftp-hpn-server.c) arrive with their first users.
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

/* Extension name, advertised in SSH2_FXP_VERSION and matched by the client. */
#define HPN_EXT_DISCOVER_TREE		"hpn-discover-tree@hpnssh.org"

/* Reply-chunk codec version; bump to extend the record format. */
#define HPN_DTREE_VERSION		1

/*
 * Request flags (u32).  FOLLOW_SYMLINKS mirrors OpenSSH's follow_link_flag,
 * which is a hardcoded-0 stub upstream (sftp.c "XXX follow_link_flag"); we
 * carry the bit DORMANT so the extension is already shaped for it if -L is
 * ever wired.  Remaining bits reserved (must be 0).
 */
#define HPN_DTREE_FOLLOW_SYMLINKS	0x00000001u

/* Reply-chunk kinds. */
#define HPN_DTREE_CHUNK_DATA		0	/* carries record-count records */
#define HPN_DTREE_CHUNK_END		1	/* terminal; no records          */

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

/* Server-side recursion cap; mirrors the client's MAX_DIR_DEPTH. */
#define HPN_DTREE_MAX_DEPTH		64

/*
 * Wire format.
 *
 * Request  (SSH2_FXP_EXTENDED):
 *     string  "hpn-discover-tree@hpnssh.org"
 *     string  root-path
 *     uint32  flags                 (HPN_DTREE_FOLLOW_SYMLINKS | reserved-0)
 *
 * Reply    (one or more SSH2_FXP_EXTENDED_REPLY, same id, until END):
 *     byte    version               (HPN_DTREE_VERSION)
 *     byte    chunk-kind            (HPN_DTREE_CHUNK_DATA | _END)
 *     uint32  record-count          (0 for END)
 *     record[record-count]
 *
 * record:
 *     string  relative-path         (from root; '/'-separated; parents
 *                                     always precede their children)
 *     byte    rec-type              (HPN_DTREE_REC_*)
 *     ATTRS   attrib                 (full Attrib; absent iff type==ERROR)
 *     uint32  status                 (present iff type==ERROR: SSH2_FX_*)
 *
 * The client re-validates every relative-path (no absolute paths, no "."
 * / ".." components, no escape above root) exactly as readdir does today -
 * the server generates the paths but the client does not trust the peer.
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
 * relative to the discovery root; rectype is HPN_DTREE_REC_*; a holds the
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
 * Client fetch (sftp-hpn-client.c): send hpn-discover-tree for root and
 * drain the whole streamed reply into a freshly allocated array.  The
 * entire stream is drained before returning - the reply shares the control
 * connection, so no other request may be issued mid-stream.  Returns 0 and
 * sets *entsp / *nentsp (caller frees with sftp_hpn_tree_free), or -1 on a
 * protocol/transport failure.
 */
int	sftp_hpn_discover_tree(struct sftp_conn *conn, const char *root,
	    u_int32_t flags, struct sftp_tree_ent **entsp, size_t *nentsp);
void	sftp_hpn_tree_free(struct sftp_tree_ent *ents, size_t nents);

/* Safety check on a received relative path (no absolute, no "..").  1 = ok. */
int	sftp_tree_relpath_ok(const char *rel);

#endif /* _SFTP_HPN_TREE_H */
