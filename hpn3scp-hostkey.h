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

/* hpn3scp-hostkey.h - making sure the source host trusts the target's
 * host key before hpn3scp launches the copy.
 *
 * This is server verification, the check ssh makes that a server is the
 * host it claims to be. It is not host-based authentication, and nothing
 * here logs a user in. The copy always runs with StrictHostKeyChecking=yes,
 * so the source host's hpnssh makes the final check, and these functions
 * only add a verified key to its known_hosts.
 *
 * The source host scans the target, and everything that scan returns is
 * untrusted. The parser is strict and fuzzed, fingerprints are computed
 * here, and no line from the source host is ever written back. A key is
 * accepted only on evidence from another path: a DNSSEC-signed SSHFP
 * record, the launcher's own known_hosts, or the user's confirmation of
 * the one key the copy would negotiate. Evidence that contradicts a key
 * stops the run. */

#ifndef HPN3SCP_HOSTKEY_H
#define HPN3SCP_HOSTKEY_H

/* Defined in sshkey.h and hpn3scp.h. Only pointers are needed here. */
struct sshkey;
struct run_state;

/* What the target's SSHFP records in DNS say about a fetched key */
enum sshfp_status {
	SSHFP_ABSENT,		/* no records, or the lookup failed */
	SSHFP_MATCH,		/* matched, without DNSSEC */
	SSHFP_SECURE,		/* matched, with DNSSEC */
	SSHFP_MISMATCH		/* records exist and disagree: hostile */
};

/* One of the target's host keys, with what hpn3scp found out about it */
struct target_key {
	struct sshkey	*key;		/* parsed and checked, owned */
	char		*fingerprint;	/* computed here, owned */
	enum sshfp_status sshfp;	/* its SSHFP result */
	int		 accepted;	/* verified or confirmed */
};

/* Every key a keyscan returned for the target */
struct target_keyset {
	struct target_key *keys;
	int		 nkeys;
};

/* Parse one keyscan output line into *keyp. Returns 0 for a plain host
 * key, which the caller then owns, 1 to skip a blank or comment line, or
 * -1 to reject the line: a known_hosts marker, a certificate, or a
 * malformed key. A rejected line should fail the whole scan. This parses
 * the source host's untrusted text and is the fuzz target. */
int	hpn3scp_parse_keyscan_line(const char *, struct sshkey **);

/* hpn3scp's own SHA256 fingerprint of a key, which the caller frees */
char	*hpn3scp_key_fp(const struct sshkey *);

/* What the host's SSHFP records in DNS, looked up from the launcher, say
 * about a key */
enum sshfp_status hpn3scp_sshfp_check(const char *, const struct sshkey *);

/* Ask the source host to keyscan the target's port, then parse,
 * fingerprint, and SSHFP-check every key into *keyset. Returns 0 with at
 * least one key, 1 when nothing on the port responded, so the caller may
 * try another, or -1 when the output had a rejected line. The caller
 * frees the set with hpn3scp_free_keyset(). */
int	hpn3scp_fetch_target_keys(const struct run_state *,
	    struct target_keyset *);

/* Free a key set and leave it empty, so freeing it again is harmless */
void	hpn3scp_free_keyset(struct target_keyset *);

/* Whether a known_hosts file the source host's hpnssh uses already holds a
 * key for the target on its current port: 1 if so, else 0, which only
 * means the key is fetched and confirmed again. */
int	hpn3scp_source_knows_target(const struct run_state *);

/* Decide which fetched keys the source host may trust. An SSHFP mismatch,
 * or a different or revoked key in the launcher's known_hosts, aborts.
 * Keys that a DNSSEC-signed SSHFP record or the launcher's known_hosts
 * vouch for are accepted. Otherwise the user confirms the one key the copy
 * would negotiate on a terminal, and with no terminal the run stops.
 * Returns 0 with the accepted keys marked, or -1 with an error emitted. */
int	hpn3scp_confirm_target(const struct run_state *,
	    struct target_keyset *);

/* Append the accepted keys to the first known_hosts file the source
 * host's hpnssh uses, formatted and hashed as hpnssh would write them.
 * Returns 0, or -1. */
int	hpn3scp_provision_target(const struct run_state *,
	    struct target_keyset *);

#endif /* HPN3SCP_HOSTKEY_H */
