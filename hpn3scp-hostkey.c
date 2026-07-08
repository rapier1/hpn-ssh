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
 * hpn3scp-hostkey.c - target host-key trust broker (see hpn3scp-hostkey.h).
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"		/* before dns.h: its prototypes use struct sshkey */
#include "digest.h"		/* SSH_DIGEST_SHA256 (via SSH_FP_HASH_DEFAULT) */
#include "dns.h"
#include "hpn3scp.h"
#include "hpn3scp-hostkey.h"
#include "hpn3scp-proto.h"
#include "hpn3scp-run.h"
#include "log.h"
#include "misc.h"		/* read_passphrase, RP_ECHO, arglist */
#include "xmalloc.h"

int
hpn3scp_parse_keyscan_line(const char *line, struct sshkey **keyp)
{
	struct sshkey *k;
	char *dup, *cp, *host;

	*keyp = NULL;

	while (*line == ' ' || *line == '\t')
		line++;
	if (*line == '\0' || *line == '#')
		return 1;		/* blank or comment: skip */
	if (*line == '@')
		return -1;		/* known_hosts marker: reject */

	dup = xstrdup(line);
	cp = dup;
	host = strsep(&cp, " \t");	/* discard hostspec (keyscan of C) */
	if (host == NULL || cp == NULL) {
		free(dup);
		return -1;
	}
	while (*cp == ' ' || *cp == '\t')
		cp++;

	/* remaining "keytype base64 [comment]" -> strict sshkey_read */
	if ((k = sshkey_new(KEY_UNSPEC)) == NULL) {
		free(dup);
		return -1;
	}
	if (sshkey_read(k, &cp) != 0) {
		sshkey_free(k);
		free(dup);
		return -1;
	}
	free(dup);
	*keyp = k;
	return 0;
}

char *
hpn3scp_key_fp(const struct sshkey *key)
{
	return sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT);
}

enum sshfp_status
hpn3scp_sshfp_check(const char *host, const struct sshkey *key)
{
	int flags = 0;

	/* verify_host_key_dns does the DNS SSHFP lookup + comparison and sets
	 * DNS_VERIFY_* (SECURE = DNSSEC-authenticated).  It does not use the
	 * address argument, so NULL is fine. */
	if (verify_host_key_dns(host, NULL, (struct sshkey *)key, &flags) != 0)
		return SSHFP_ABSENT;		/* no records / not lookupable */
	if (!(flags & DNS_VERIFY_FOUND))
		return SSHFP_ABSENT;
	if (flags & DNS_VERIFY_FAILED)
		return SSHFP_MISMATCH;
	if (flags & DNS_VERIFY_MATCH)
		return (flags & DNS_VERIFY_SECURE) ? SSHFP_SECURE : SSHFP_MATCH;
	return SSHFP_MISMATCH;			/* found records, none matched */
}

const char *
hpn3scp_sshfp_str(enum sshfp_status s)
{
	switch (s) {
	case SSHFP_ABSENT:	return "absent";
	case SSHFP_MATCH:	return "match";
	case SSHFP_SECURE:	return "verified";
	case SSHFP_MISMATCH:	return "MISMATCH";
	}
	return "unknown";
}

int
hpn3scp_fetch_target_keys(struct launch_session *s, struct target_keyset *set)
{
	arglist a;
	char buf[16384], *line, *save;
	struct sshkey *key;
	struct target_key *tk;
	int rc, r;

	memset(set, 0, sizeof(*set));

	/* have the source keyscan the target: ssh A "ssh-keyscan -T 10 [-p P] C" */
	ssh_base_args(s, &a, 0, 0);
	addargs(&a, "ssh-keyscan");
	if (s->addr_family == 4)		/* the A->C keyscan hop */
		addargs(&a, "-4");
	else if (s->addr_family == 6)
		addargs(&a, "-6");
	addargs(&a, "-T");
	addargs(&a, "10");
	if (s->dst.port != -1) {
		addargs(&a, "-p");
		addargs(&a, "%d", s->dst.port);
	}
	addargs(&a, "%s", s->dst.host);
	rc = hpn_run_capture(&a, buf, sizeof(buf), 20000);
	freeargs(&a);
	if (rc != 0)
		return -1;			/* keyscan failed or timed out */

	for (line = strtok_r(buf, "\n", &save); line != NULL;
	    line = strtok_r(NULL, "\n", &save)) {
		r = hpn3scp_parse_keyscan_line(line, &key);
		if (r == 1)
			continue;		/* skip blank/comment */
		if (r == -1) {			/* marker/malformed: abort */
			hpn3scp_free_keyset(set);
			return -1;
		}
		set->keys = xreallocarray(set->keys, set->nkeys + 1,
		    sizeof(*set->keys));
		tk = &set->keys[set->nkeys++];
		tk->key = key;
		tk->fingerprint = hpn3scp_key_fp(key);
		tk->sshfp = hpn3scp_sshfp_check(s->dst.host, key);
	}

	if (set->nkeys == 0) {
		hpn3scp_free_keyset(set);
		return -1;			/* nothing usable came back */
	}
	return 0;
}

void
hpn3scp_free_keyset(struct target_keyset *set)
{
	size_t i;

	if (set == NULL)
		return;
	for (i = 0; i < set->nkeys; i++) {
		sshkey_free(set->keys[i].key);
		free(set->keys[i].fingerprint);
	}
	free(set->keys);
	memset(set, 0, sizeof(*set));
}

/* [host]:port for a non-default port, else host - the known_hosts hostspec */
static void
target_hostspec(struct launch_session *s, char *out, size_t len)
{
	if (s->dst.port != -1)
		snprintf(out, len, "[%s]:%d", s->dst.host, s->dst.port);
	else
		snprintf(out, len, "%s", s->dst.host);
}

int
hpn3scp_source_knows_target(struct launch_session *s)
{
	arglist a;
	char buf[4096], spec[512];
	int rc;

	target_hostspec(s, spec, sizeof(spec));
	ssh_base_args(s, &a, 0, 0);
	addargs(&a, "ssh-keygen");
	addargs(&a, "-F");
	addargs(&a, "'%s'", spec);	/* quote: [host]:port brackets are
					 * glob metacharacters to the remote shell */
	rc = hpn_run_capture(&a, buf, sizeof(buf), 15000);
	freeargs(&a);
	/* ssh-keygen -F exits 0 only when a matching host entry is found */
	return rc == 0 ? 1 : 0;
}

/*
 * yes / no / [any of the shown fingerprints], modeled on sshconnect.c's
 * confirm().  read_passphrase(RP_ECHO) reads the answer from the terminal;
 * the prompt/info was already written to stderr (stdout is the protocol).
 */
static int
prompt_confirm(const char *prompt, struct target_keyset *set)
{
	const char *msg, *again = "Please type 'yes', 'no', or the fingerprint: ";
	char *p, *cp;
	size_t i;
	int ret;

	for (msg = prompt;; msg = again) {
		cp = p = read_passphrase(msg, RP_ECHO);
		if (p == NULL)
			return 0;			/* no answer -> treat as no */
		p += strspn(p, " \t");
		p[strcspn(p, " \t\n")] = '\0';
		ret = -1;
		if (p[0] == '\0' || strcasecmp(p, "no") == 0)
			ret = 0;
		else if (strcasecmp(p, "yes") == 0)
			ret = 1;
		else {
			for (i = 0; i < set->nkeys; i++) {
				if (strcmp(p, set->keys[i].fingerprint) == 0) {
					ret = 1;
					break;
				}
			}
		}
		free(cp);
		if (ret != -1)
			return ret;
	}
}

int
hpn3scp_confirm_target(struct launch_session *s, struct target_keyset *set)
{
	size_t i, nsecure = 0;

	/* layer 2 first: a MISMATCH anywhere is hostile; a SECURE match wins */
	for (i = 0; i < set->nkeys; i++) {
		if (set->keys[i].sshfp == SSHFP_MISMATCH) {
			error("target %s: a host key MISMATCHES its DNSSEC SSHFP "
			    "record - possible man-in-the-middle; aborting",
			    s->dst.host);
			return -1;
		}
		if (set->keys[i].sshfp == SSHFP_SECURE)
			nsecure++;
	}
	if (nsecure > 0) {
		logit("target %s host key verified via DNSSEC SSHFP",
		    s->dst.host);
		return 0;
	}

	/* layer 3: interactive confirmation, or fail-closed (Q3) */
	if (!isatty(STDIN_FILENO)) {
		char *m;

		xasprintf(&m, "%s's host key is not verified (no DNSSEC "
		    "SSHFP) and no terminal is available to confirm it; run "
		    "interactively or pre-add the key to %s's known_hosts",
		    s->dst.host, s->src.host);
		proto_emit_error(m);
		free(m);
		return -1;
	}
	fprintf(stderr, "The authenticity of target host '%s' can't be "
	    "established.\n", s->dst.host);
	for (i = 0; i < set->nkeys; i++) {
		fprintf(stderr, "  %s key fingerprint is %s%s.\n",
		    sshkey_ssh_name(set->keys[i].key), set->keys[i].fingerprint,
		    set->keys[i].sshfp == SSHFP_MATCH ?
		    " (SSHFP match, not DNSSEC-authenticated)" : "");
	}
	fflush(stderr);
	if (prompt_confirm("Are you sure you want to continue connecting "
	    "(yes/no/[fingerprint])? ", set) != 1) {
		logit("target host key rejected");
		return -1;
	}
	return 0;
}

int
hpn3scp_provision_target(struct launch_session *s, struct target_keyset *set)
{
	arglist a;
	char spec[512], *payload, *b64, *tmp;
	size_t i;
	int rc;

	target_hostspec(s, spec, sizeof(spec));

	/* build "hostspec keytype base64\n" lines from OUR validated keys -
	 * never echoed remote text (constructed from the parsed sshkey) */
	payload = xstrdup("");
	for (i = 0; i < set->nkeys; i++) {
		b64 = NULL;
		if (sshkey_to_base64(set->keys[i].key, &b64) != 0) {
			free(payload);
			return -1;
		}
		xasprintf(&tmp, "%s%s %s %s\n", payload, spec,
		    sshkey_ssh_name(set->keys[i].key), b64);
		free(payload);
		free(b64);
		payload = tmp;
	}

	/* append on the source; cat reads our piped stdin literally, so the
	 * key material is never interpreted by the remote shell */
	ssh_base_args(s, &a, 0, 0);
	addargs(&a, "umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/known_hosts");
	rc = hpn_run_feed(&a, payload);
	freeargs(&a);
	free(payload);
	return rc;
}
