/* $OpenBSD: version.h,v 1.109 2026/07/06 07:54:26 djm Exp $ */

#define SSH_VERSION	"OpenSSH_10.4"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "_hpn19.0.0"

/*
 * DEV-ONLY build identifier.  When built with `make GITVERSION=1` the
 * Makefile injects -DSSH_HPN_EXTRA="-g<8-char commit>[-dirty]" so a binary
 * self-reports its commit and whether the tree had uncommitted changes.
 * Default and release builds leave it empty: SSH_RELEASE is unchanged.
 * Never enabled for a release.
 */
#ifndef SSH_HPN_EXTRA
# define SSH_HPN_EXTRA ""
#endif

#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN SSH_HPN_EXTRA
