/* $OpenBSD: version.h,v 1.110 2026/08/10 23:27:30 djm Exp $ */

#define SSH_VERSION	"OpenSSH_10.5"

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
