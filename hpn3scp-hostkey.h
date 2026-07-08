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
 * hpn3scp-hostkey.h - target host-key trust broker (Stage 2).
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.  The
 * source (A) is asked to ssh-keyscan the target (C); every byte it returns
 * is untrusted input, so the line parser here is strict and is the fuzz
 * target (hpn-launcher-design.md sec 9/12).  Fingerprints are computed by
 * us from the parsed key, never taken from the source's text; SSHFP is the
 * independent DNS channel that turns blind TOFU into verification.
 *
 * Stage 2 status: fetch + parse + fingerprint + SSHFP classification are
 * built here.  The accept decision (ssh-style prompt), provisioning into the
 * source's ~/.ssh/known_hosts, and gating the launch are wired separately.
 */

#ifndef HPN3SCP_HOSTKEY_H
#define HPN3SCP_HOSTKEY_H

#include <sys/types.h>

struct sshkey;
struct launch_session;

/* SSHFP classification of a fetched key against C's DNS records */
enum sshfp_status {
	SSHFP_ABSENT,		/* no usable SSHFP records / lookup failed */
	SSHFP_MATCH,		/* matched, but NOT DNSSEC-authenticated */
	SSHFP_SECURE,		/* matched AND DNSSEC-authenticated */
	SSHFP_MISMATCH		/* records exist and disagree - treat hostile */
};

/* one target host key plus what we independently determined about it */
struct target_key {
	struct sshkey	*key;		/* parsed, validated (owned) */
	char		*fingerprint;	/* our SHA256:... (owned) */
	enum sshfp_status sshfp;
};

struct target_keyset {
	struct target_key *keys;
	size_t		 nkeys;
};

/*
 * Parse one ssh-keyscan output line into *keyp.  Returns 0 on a valid host
 * key (caller owns *keyp), 1 to skip the line (blank or comment), -1 to
 * reject it (a known_hosts marker such as @cert-authority, or a malformed
 * key - either is an abort signal).  Pure text -> sshkey: the remote-facing
 * parser and the fuzz target.
 */
int	hpn3scp_parse_keyscan_line(const char *line, struct sshkey **keyp);

/* our own SHA256 fingerprint string for key (caller frees) */
char	*hpn3scp_key_fp(const struct sshkey *key);

/* classify key against host's DNS SSHFP records */
enum sshfp_status hpn3scp_sshfp_check(const char *host,
	    const struct sshkey *key);
const char *hpn3scp_sshfp_str(enum sshfp_status s);

/*
 * Ask the source to ssh-keyscan the target, then parse + fingerprint +
 * SSHFP-classify every key into *set.  Returns 0 with >=1 key on success;
 * -1 on keyscan failure, a rejected line, or no keys.  Caller frees with
 * hpn3scp_free_keyset().
 */
int	hpn3scp_fetch_target_keys(struct launch_session *s,
	    struct target_keyset *set);
void	hpn3scp_free_keyset(struct target_keyset *set);

/* Does the source already trust the target (in its known_hosts)?  1 = yes. */
int	hpn3scp_source_knows_target(struct launch_session *s);

/*
 * Verification ladder for a freshly fetched keyset: a DNSSEC-secure SSHFP
 * match auto-accepts; a SSHFP MISMATCH aborts; otherwise an ssh-style
 * interactive prompt (yes/no/[fingerprint]) on a terminal, or fail-closed
 * when non-interactive.  Returns 0 to accept, -1 to reject/abort.
 */
int	hpn3scp_confirm_target(struct launch_session *s,
	    struct target_keyset *set);

/* Append the accepted keys to the source's ~/.ssh/known_hosts.  0 on success. */
int	hpn3scp_provision_target(struct launch_session *s,
	    struct target_keyset *set);

#endif /* HPN3SCP_HOSTKEY_H */
