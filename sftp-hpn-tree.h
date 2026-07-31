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

#endif /* _SFTP_HPN_TREE_H */
