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

/* hpn3scp-hostkey.c - getting the target's host key into the source's
 * known_hosts, so the copy can check the target strictly.
 *
 * This is server verification: the check ssh makes that the target is
 * the host it claims to be, before any login. It is not host-based
 * authentication, where a client's host key logs a user in. Nothing here
 * authenticates a user or changes how anyone logs in.
 *
 * The flow has four steps. First, ssh-keygen -F on the source asks
 * whether it already knows the target. If it does not, ssh-keyscan on the
 * source fetches the target's keys, and every line it returns is
 * untrusted input for a strict parser. Then hpn3scp computes the
 * fingerprints itself from the parsed keys and checks them against the
 * target's SSHFP records in DNS, or asks the user to confirm one as ssh
 * does. Last, the accepted keys are appended to the source's known_hosts.
 * These commands run through the source's shell, so the host and user in
 * them are checked by valid_host() and valid_user() first. */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"		/* read_passphrase, RP_ECHO, arglist */
#include "ssh.h"		/* SSH_DEFAULT_PORT */
#include "sshkey.h"		/* before dns.h, whose prototypes use it */
#include "digest.h"		/* SSH_FP_HASH_DEFAULT is SSH_DIGEST_SHA256 */
#include "dns.h"
#include "hostfile.h"
#include "hostfile-internal.h"
#include "pathnames.h"
#include "sshbuf.h"
#include "xmalloc.h"
#include "hpn3scp.h"
#include "hpn3scp-proto.h"
#include "hpn3scp-run.h"
#include "hpn3scp-hostkey.h"

/* The known_hosts files, hashing, and host key algorithms that the
 * source host's hpnssh uses for the target on one port, from hpnssh -G,
 * so the trust check, the prompt, and provisioning share one lookup. The
 * user files are listed apart, because new keys go into the first. */
static struct {
	int	 looked_up;	/* a lookup ran for port */
	int	 port;		/* the target port it ran for */
	char	**user;		/* UserKnownHostsFile paths */
	int	 nuser;
	char	**global;	/* GlobalKnownHostsFile paths */
	int	 nglobal;
	int	 hash;		/* HashKnownHosts is yes */
	char	*hostkeyalgs;	/* HostKeyAlgorithms, preferred first */
} hostfiles;

/* Parse one keyscan line. Leading whitespace is skipped, then the host
 * field, and the rest goes to upstream's strict sshkey_read(). A
 * certificate is rejected, because the scan asks for none, so one can only
 * come from tampered output. Nothing from the line is ever printed. */
int
hpn3scp_parse_keyscan_line(const char *line, struct sshkey **keyp)
{
	struct sshkey *key = NULL;
	char *copy, *cursor, *hostspec;

	*keyp = NULL;

	while (*line == ' ' || *line == '\t')
		line++;
	if (*line == '\0' || *line == '#')
		return 1;		/* blank or comment: skip */
	if (*line == '@')
		return -1;		/* known_hosts marker: reject */

	copy = xstrdup(line);
	cursor = copy;
	/* the host field names the target and is not needed */
	hostspec = strsep(&cursor, " \t");
	if (hostspec == NULL || cursor == NULL)
		goto fail;
	while (*cursor == ' ' || *cursor == '\t')
		cursor++;

	/* the rest is "keytype base64 [comment]" */
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		goto fail;
	if (sshkey_read(key, &cursor) != 0)
		goto fail;
	/* only plain host keys, never certificates */
	/* TODO:  accepting certificates is future work */
	if (sshkey_is_cert(key))
		goto fail;
	free(copy);
	*keyp = key;
	return 0;

 fail:
	sshkey_free(key);
	free(copy);
	return -1;
}

/* Our own fingerprint of a parsed key, in ssh's default SHA256 form. It
 * is computed here, never taken from the source's text. */
char *
hpn3scp_key_fp(const struct sshkey *key)
{
	return sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT);
}

/* Classify a key against the target's SSHFP records in DNS, using
 * upstream's verify_host_key_dns(), which does the lookup and the
 * comparison. A match is SECURE only when DNSSEC authenticated it. As in
 * upstream ssh, that means the launcher's resolver reported the answer as
 * validated, so the result is only as sound as that resolver. */
enum sshfp_status
hpn3scp_sshfp_check(const char *host, const struct sshkey *key)
{
	int flags = 0;

	/* It ignores the address argument, so NULL is fine. The cast is only
	 * because its prototype is not const. */
	if (verify_host_key_dns(host, NULL, (struct sshkey *)key, &flags) != 0)
		return SSHFP_ABSENT;	/* no records, or no lookup */
	if (!(flags & DNS_VERIFY_FOUND))
		return SSHFP_ABSENT;
	if (flags & DNS_VERIFY_FAILED)
		return SSHFP_MISMATCH;
	if (!(flags & DNS_VERIFY_MATCH))
		return SSHFP_MISMATCH;	/* records found, none matched */
	if (flags & DNS_VERIFY_SECURE)
		return SSHFP_SECURE;
	return SSHFP_MATCH;
}

/* Run hpnssh-keyscan on the source against the target's port, then parse
 * each line strictly, fingerprint each key, and check it against SSHFP.
 * Any line the parser rejects fails the whole fetch, because the source's
 * output is untrusted and a partial set could hide a substituted key.
 * No response on the port returns 1, so the caller can try another. */
int
hpn3scp_fetch_target_keys(const struct launch_session *session,
    struct target_keyset *keyset)
{
	arglist args;
	char output[16384], *line, *save;
	struct sshkey *key;
	struct target_key *entry;
	int rc, r;

	memset(keyset, 0, sizeof(*keyset));

	ssh_base_args(session, &args, 0, 0);
	addargs(&args, "hpnssh-keyscan");
	/* the source to target keyscan hop */
	add_addr_family_arg(session, &args);
	addargs(&args, "-T");
	addargs(&args, "10");
	if (session->dst.port != -1) {
		addargs(&args, "-p");
		addargs(&args, "%d", session->dst.port);
	}
	/* -- so a host starting with '-' is never read as an option */
	addargs(&args, "--");
	addargs(&args, "%s", session->dst.host);
	/* Output that overflows the buffer makes the keyscan fail when its
	 * pipe closes, so a cut-off list is never parsed as complete. */
	rc = hpn_run_capture(&args, output, sizeof(output), 20000);
	freeargs(&args);
	/* keyscan exits 1 when nothing on the port responded */
	if (rc != 0)
		return 1;

	/* The output is keyscan's known_hosts-format text, held only in this
	 * buffer. Split it into lines, parse each one, and record each valid
	 * key with our own fingerprint and its SSHFP result. One rejected
	 * line fails the whole set. */
	for (line = strtok_r(output, "\n", &save); line != NULL;
	    line = strtok_r(NULL, "\n", &save)) {
		r = hpn3scp_parse_keyscan_line(line, &key);
		if (r == 1)
			continue;		/* blank or comment */
		if (r == -1)
			goto fail;	/* a marker or a malformed key */
		keyset->keys = xreallocarray(keyset->keys, keyset->nkeys + 1,
		    sizeof(*keyset->keys));
		entry = &keyset->keys[keyset->nkeys++];
		entry->key = key;
		entry->fingerprint = hpn3scp_key_fp(key);
		entry->sshfp = hpn3scp_sshfp_check(session->dst.host, key);
		entry->accepted = 0;
	}
	/* nothing usable came back */
	if (keyset->nkeys == 0) {
		hpn3scp_free_keyset(keyset);
		return 1;
	}
	return 0;

 fail:
	hpn3scp_free_keyset(keyset);
	return -1;
}

/* Free every key and fingerprint in the set, and leave it empty, so
 * freeing it again is harmless. */
void
hpn3scp_free_keyset(struct target_keyset *keyset)
{
	int i;

	if (keyset == NULL)
		return;
	for (i = 0; i < keyset->nkeys; i++) {
		sshkey_free(keyset->keys[i].key);
		free(keyset->keys[i].fingerprint);
	}
	free(keyset->keys);
	memset(keyset, 0, sizeof(*keyset));
}

/* Forget a previous lookup of the source host's known_hosts files. */
static void
free_hostfiles(void)
{
	int i;

	for (i = 0; i < hostfiles.nuser; i++)
		free(hostfiles.user[i]);
	for (i = 0; i < hostfiles.nglobal; i++)
		free(hostfiles.global[i]);
	free(hostfiles.user);
	free(hostfiles.global);
	free(hostfiles.hostkeyalgs);
	memset(&hostfiles, 0, sizeof(hostfiles));
}

/* Whether a path from the source host is safe to put back on its command
 * line in single quotes: absolute, with no quote, backslash, whitespace,
 * or control character to break out of them. */
static int
hostfile_path_ok(const char *path)
{
	const u_char *cursor = (const u_char *)path;

	if (*cursor != '/')
		return 0;
	for (; *cursor != '\0'; cursor++) {
		if (*cursor == '\'' || *cursor == '\\' || *cursor <= ' ' ||
		    *cursor == 0x7f)
			return 0;
	}
	return 1;
}

/* Add each space-separated path in list to *filesp. Returns 0, or -1 for
 * a path that is not safe to quote. */
static int
add_hostfile_paths(char *list, char ***filesp, int *countp)
{
	char *path;

	while ((path = strsep(&list, " ")) != NULL) {
		/* skip the empty fields between repeated spaces */
		if (*path == '\0')
			continue;
		/* refuse a path that could break out of its quotes */
		if (!hostfile_path_ok(path))
			return -1;
		*filesp = xreallocarray(*filesp, *countp + 1, sizeof(**filesp));
		(*filesp)[(*countp)++] = xstrdup(path);
	}
	return 0;
}

/* Ask the source host's hpnssh which known_hosts files it uses for the
 * target on its current port, whether it hashes new entries, and which
 * host key algorithms it prefers, from hpnssh -G. That honours the source
 * host's build and the user's config. The result is kept for the port.
 * Returns 0, or -1 when the lookup failed or gave no user file, and the
 * callers then use the defaults. */
static int
source_hostfiles(const struct launch_session *session)
{
	arglist args;
	char output[16384], *line, *save;
	int rc;

	/* a lookup for this port already ran, so reuse its result */
	if (hostfiles.looked_up && hostfiles.port == session->dst.port) {
		if (hostfiles.nuser == 0)
			return -1;
		return 0;
	}
	/* start a fresh lookup for this port */
	free_hostfiles();
	hostfiles.looked_up = 1;
	hostfiles.port = session->dst.port;

	/* hpnssh -G prints the config it would use for the target */
	ssh_base_args(session, &args, 0, 0);
	addargs(&args, "hpnssh");
	addargs(&args, "-G");
	add_addr_family_arg(session, &args);
	if (session->dst.port != -1) {
		addargs(&args, "-p");
		addargs(&args, "%d", session->dst.port);
	}
	/* -- so a host starting with '-' is never read as an option */
	addargs(&args, "--");
	addargs(&args, "%s", session->dst.host);
	rc = hpn_run_capture(&args, output, sizeof(output), 15000);
	freeargs(&args);
	/* a full buffer may end in a cut-off line, so it is not used */
	if (rc != 0 || strlen(output) >= sizeof(output) - 1)
		goto fail;

	/* Only four lines matter, and each is "keyword value...". The
	 * paths are untrusted text from the source host, so each is checked
	 * before it can reach that host's command line again. The algorithm
	 * list is only compared with key names here. */
	for (line = strtok_r(output, "\n", &save); line != NULL;
	    line = strtok_r(NULL, "\n", &save)) {
		if (strncmp(line, "userknownhostsfile ", 19) == 0) {
			if (add_hostfile_paths(line + 19, &hostfiles.user,
			    &hostfiles.nuser) != 0)
				goto fail;
		} else if (strncmp(line, "globalknownhostsfile ", 21) == 0) {
			if (add_hostfile_paths(line + 21, &hostfiles.global,
			    &hostfiles.nglobal) != 0)
				goto fail;
		} else if (strncmp(line, "hostkeyalgorithms ", 18) == 0) {
			free(hostfiles.hostkeyalgs);
			hostfiles.hostkeyalgs = xstrdup(line + 18);
		} else if (strcmp(line, "hashknownhosts yes") == 0)
			hostfiles.hash = 1;
	}
	/* new keys need a user file to go into */
	if (hostfiles.nuser == 0)
		goto fail;
	return 0;

 fail:
	debug("could not learn the known_hosts files %s uses; using the "
	    "defaults", session->src.host);
	free_hostfiles();
	hostfiles.looked_up = 1;
	hostfiles.port = session->dst.port;
	return -1;
}

/* The target's name in known_hosts: [host]:port, or the plain host for
 * port 22, as ssh records it. */
static void
target_hostspec(const struct launch_session *session, char *out, size_t len)
{
	if (session->dst.port != -1 && session->dst.port != SSH_DEFAULT_PORT)
		snprintf(out, len, "[%s]:%d", session->dst.host,
		    session->dst.port);
	else
		snprintf(out, len, "%s", session->dst.host);
}

/* Add one "hpnssh-keygen -F spec -f file" to args. Every lookup after the
 * first is joined with ||, so the command succeeds if any file has the
 * key. A NULL file means hpnssh-keygen's default file. */
static void
add_keygen_lookup(arglist *args, const char *spec, const char *file,
    int first)
{
	if (!first)
		addargs(args, "||");
	addargs(args, "hpnssh-keygen");
	addargs(args, "-F");
	addargs(args, "'%s'", spec);
	if (file != NULL) {
		addargs(args, "-f");
		addargs(args, "'%s'", file);
	}
}

/* Ask the source host whether any known_hosts file its hpnssh uses holds
 * a key for the target on session->dst.port, with hpnssh-keygen -F on
 * each file, the user files first and then the system files. Without the
 * file list, only hpnssh-keygen's default file is checked. Returns 1 if
 * a file holds a key, or 0 if none does or the check could not run, which
 * only means the key is fetched and confirmed again. */
int
hpn3scp_source_knows_target(const struct launch_session *session)
{
	arglist args;
	char output[4096], spec[512];
	int i, rc;

	target_hostspec(session, spec, sizeof(spec));
	ssh_base_args(session, &args, 0, 0);
	/* Quote the spec and the paths, because the brackets of [host]:port
	 * are glob characters to the source host's shell. The quotes cannot
	 * be broken out of, because resolve_endpoint() accepts no host with
	 * one and hostfile_path_ok() no path. */
	if (source_hostfiles(session) == 0) {
		for (i = 0; i < hostfiles.nuser; i++)
			add_keygen_lookup(&args, spec, hostfiles.user[i],
			    i == 0);
		for (i = 0; i < hostfiles.nglobal; i++)
			add_keygen_lookup(&args, spec, hostfiles.global[i], 0);
	} else
		add_keygen_lookup(&args, spec, NULL, 1);
	/* only the exit status matters, so the output is read and dropped */
	rc = hpn_run_capture(&args, output, sizeof(output), 15000);
	freeargs(&args);
	/* hpnssh-keygen -F exits 0 only when it finds a matching entry */
	return rc == 0;
}

/* The key the copy's hpnssh would negotiate with the target: the first
 * of the source host's HostKeyAlgorithms that matches a scanned key, by
 * upstream's sshkey_match_keyname_to_sigalgs(). Certificate algorithms
 * match no plain key, so they are passed over. Without the list, or with
 * no match, the first scanned key is used. That still works, because
 * unless the user set a full HostKeyAlgorithms list, ssh prefers the
 * algorithms it holds a known key for. Returns an index into keyset. */
static int
negotiated_key(const struct target_keyset *keyset)
{
	char *algs, *cursor, *alg;
	int i, found = -1;

	/* no list from -G, so fall back to the first key */
	if (hostfiles.hostkeyalgs == NULL)
		return 0;
	/* walk the algorithms in the source host's order of preference */
	algs = cursor = xstrdup(hostfiles.hostkeyalgs);
	while (found == -1 && (alg = strsep(&cursor, ",")) != NULL) {
		for (i = 0; i < keyset->nkeys; i++) {
			/* rsa-sha2-512 and the like all match an RSA key */
			if (sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(keyset->keys[i].key), alg)) {
				found = i;
				break;
			}
		}
	}
	free(algs);
	/* no algorithm matched a scanned key */
	if (found == -1)
		return 0;
	return found;
}

/* Ask the user to accept the target's key, as ssh's confirm() in
 * sshconnect.c does: yes or the key's fingerprint accepts, no or an empty
 * answer refuses, and anything else asks again. The answer comes from the
 * terminal through read_passphrase(), and the details were already
 * printed on stderr, because stdout carries the protocol. Returns 1 with
 * the key marked accepted, or 0. */
static int
prompt_confirm(const char *prompt, struct target_key *key)
{
	const char *msg, *again =
	    "Please type 'yes', 'no' or the fingerprint: ";
	char *answer, *line;
	int ret;

	for (msg = prompt;; msg = again) {
		line = answer = read_passphrase(msg, RP_ECHO);
		/* no terminal or no answer counts as no */
		if (answer == NULL)
			return 0;
		/* trim the whitespace around the answer */
		answer += strspn(answer, " \t");
		answer[strcspn(answer, " \t\n")] = '\0';
		ret = -1;
		if (answer[0] == '\0' || strcasecmp(answer, "no") == 0)
			ret = 0;
		else if (strcasecmp(answer, "yes") == 0 ||
		    strcmp(answer, key->fingerprint) == 0) {
			key->accepted = 1;
			ret = 1;
		}
		free(line);
		if (ret != -1)
			return ret;
	}
}

/* Check the scanned keys against the launcher's own known_hosts, the
 * files hpnssh reads by default on this host. A key the user already
 * trusts from here came over a different network path from the source
 * host's scan, so a match is real evidence and the key is marked
 * accepted. A different key of the same type, or a revoked key, means
 * one of the two paths is lying, so the run stops. A UserKnownHostsFile
 * set in this host's config is not read, which only means the user is
 * asked. Returns the number of keys accepted, or -1 with an error
 * emitted. */
static int
check_launcher_known_hosts(const struct launch_session *session,
    struct target_keyset *keyset)
{
	static const char *files[] = {
		_PATH_SSH_USER_HOSTFILE,
		_PATH_SSH_USER_HOSTFILE2,
		_PATH_SSH_SYSTEM_HOSTFILE,
		_PATH_SSH_SYSTEM_HOSTFILE2
	};
	struct hostkeys *hostkeys;
	HostStatus status;
	char spec[512], *path, *msg;
	int i, naccepted = 0;

	/* look the target up under the name its entry will have */
	target_hostspec(session, spec, sizeof(spec));
	/* load the target's entries from every default file on this host */
	hostkeys = init_hostkeys();
	for (i = 0; i < (int)(sizeof(files) / sizeof(*files)); i++) {
		path = tilde_expand_filename(files[i], getuid());
		load_hostkeys(hostkeys, spec, path, 0);
		free(path);
	}
	/* compare each scanned key with what this host already trusts */
	for (i = 0; i < keyset->nkeys; i++) {
		status = check_key_in_hostkeys(hostkeys, keyset->keys[i].key,
		    NULL);
		/* the two paths disagree about the target, so stop */
		if (status == HOST_CHANGED || status == HOST_REVOKED) {
			xasprintf(&msg, "this host's known_hosts holds a "
			    "different or revoked key for %s, so the source "
			    "may be facing an impostor", session->dst.host);
			proto_emit_error(msg);
			free(msg);
			free_hostkeys(hostkeys);
			return -1;
		}
		/* the same key reached this host over its own path */
		if (status == HOST_OK) {
			keyset->keys[i].accepted = 1;
			naccepted++;
		}
	}
	free_hostkeys(hostkeys);
	return naccepted;
}

/* Decide which of the fetched keys the source host may trust. The source
 * host's keyscan output is untrusted, so evidence comes from elsewhere.
 * A key that does not match the target's SSHFP record in DNS, or one the
 * launcher's known_hosts contradicts, aborts the run. Otherwise the keys
 * a DNSSEC-signed SSHFP record verifies, and the keys the launcher
 * already trusts, are accepted. Failing both, the user confirms the one
 * key the copy would negotiate on a terminal, and with no terminal the
 * run stops. Only the keys marked accepted are provisioned, so a verified
 * key cannot carry an unverified one in with it. Returns 0, or -1 with an
 * error emitted. */
int
hpn3scp_confirm_target(const struct launch_session *session,
    struct target_keyset *keyset)
{
	struct target_key *key;
	char *msg;
	int i, nsecure = 0, nlauncher;

	for (i = 0; i < keyset->nkeys; i++) {
		if (keyset->keys[i].sshfp == SSHFP_MISMATCH) {
			xasprintf(&msg, "a host key for %s does not match its "
			    "SSHFP record in DNS, so the source may be facing "
			    "an impostor", session->dst.host);
			proto_emit_error(msg);
			free(msg);
			return -1;
		}
		if (keyset->keys[i].sshfp == SSHFP_SECURE) {
			keyset->keys[i].accepted = 1;
			nsecure++;
		}
	}
	/* the launcher's own known_hosts came over a different path */
	if ((nlauncher = check_launcher_known_hosts(session, keyset)) == -1)
		return -1;
	if (nsecure > 0)
		logit("target %s host key verified via DNSSEC SSHFP",
		    session->dst.host);
	if (nlauncher > 0)
		logit("target %s host key matches the launcher's known_hosts",
		    session->dst.host);
	if (nsecure > 0 || nlauncher > 0)
		return 0;

	/* nothing verified the keys, so a person has to */
	if (!isatty(STDIN_FILENO)) {
		xasprintf(&msg, "%s's host key is not verified by DNSSEC "
		    "SSHFP or this host's known_hosts, and no terminal is "
		    "available to confirm it; run interactively or pre-add "
		    "the key to %s's known_hosts",
		    session->dst.host, session->src.host);
		proto_emit_error(msg);
		free(msg);
		return -1;
	}
	/* Show and offer only the key the copy will negotiate, as ssh's own
	 * prompt does, so a yes trusts one key. */
	key = &keyset->keys[negotiated_key(keyset)];
	fprintf(stderr, "The authenticity of target host '%s' can't be "
	    "established.\n", session->dst.host);
	fprintf(stderr, "%s key fingerprint is %s%s.\n",
	    sshkey_type(key->key), key->fingerprint,
	    key->sshfp == SSHFP_MATCH ?
	    " (SSHFP match, not DNSSEC-authenticated)" : "");
	fflush(stderr);
	if (prompt_confirm("Are you sure you want to continue connecting "
	    "(yes/no/[fingerprint])? ", key) != 1) {
		proto_emit_error("the target's host key was rejected");
		return -1;
	}
	return 0;
}

/* Append the accepted keys to the first known_hosts file the source
 * host's hpnssh uses, as hpnssh would add them itself: each line is built
 * by upstream's format_host_entry() and hashed when HashKnownHosts is
 * yes. Without the file list, ~/.ssh/known_hosts and no hashing are used.
 * Only the keys hpn3scp_confirm_target() accepted are written. The lines
 * come from the parsed keys, never from the source host's text. Returns
 * 0, or -1. */
int
hpn3scp_provision_target(const struct launch_session *session,
    struct target_keyset *keyset)
{
	arglist args;
	struct sshbuf *lines;
	char spec[512], *payload, *dir, *slash;
	int i, rc;

	target_hostspec(session, spec, sizeof(spec));
	/* a failed lookup leaves no user file and no hashing */
	(void)source_hostfiles(session);
	if ((lines = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	/* one line per accepted key, built and hashed by upstream */
	for (i = 0; i < keyset->nkeys; i++) {
		if (!keyset->keys[i].accepted)
			continue;
		if (format_host_entry(lines, spec, NULL, keyset->keys[i].key,
		    hostfiles.hash) != 1) {
			sshbuf_free(lines);
			return -1;
		}
	}
	/* hpn_run_feed() takes the lines as a string */
	payload = sshbuf_dup_string(lines);
	sshbuf_free(lines);
	if (payload == NULL)
		return -1;

	/* Append on the source host. cat reads our piped stdin literally, so
	 * the key material never reaches the shell there. */
	ssh_base_args(session, &args, 0, 0);
	if (hostfiles.nuser > 0) {
		/* the path passed hostfile_path_ok(), so the quotes hold */
		dir = xstrdup(hostfiles.user[0]);
		/* keep "/" itself for a file at the root */
		slash = strrchr(dir, '/');
		if (slash == dir)
			slash[1] = '\0';
		else
			*slash = '\0';
		addargs(&args, "umask 077; mkdir -p '%s' && cat >> '%s'", dir,
		    hostfiles.user[0]);
		free(dir);
	} else {
		/* no file list, so the default, with ~ left to the shell */
		addargs(&args,
		    "umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/known_hosts");
	}
	rc = hpn_run_feed(&args, payload);
	freeargs(&args);
	free(payload);
	return rc;
}
