/*
 * Seed-corpus generator for hpn3scp_keyscan_fuzz.  Emits realistic
 * ssh-keyscan output lines (valid keys in several hostspec forms), the
 * adversarial cases the parser must reject (known_hosts markers, garbage,
 * truncated base64), and the skip cases (comments, blanks) into
 * ./hpn3scp_keyscan_corpus/.  Run once before the fuzzer.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fixed-keys.h"

#define CORPUS "hpn3scp_keyscan_corpus"

static void
emit(const char *name, const char *content)
{
	char path[1024];
	FILE *f;

	snprintf(path, sizeof(path), CORPUS "/%s", name);
	if ((f = fopen(path, "w")) == NULL) {
		perror(path);
		exit(1);
	}
	fputs(content, f);
	fclose(f);
}

int
main(void)
{
	(void)mkdir(CORPUS, 0777);

	/* valid keyscan lines, assorted hostspec forms */
	emit("seed-rsa", "[target.example.org]:2222 " PUB_RSA "\n");
	emit("seed-ecdsa", "[target.example.org]:2222 " PUB_ECDSA "\n");
	emit("seed-ed25519", "target.example.org " PUB_ED25519 "\n");
	emit("seed-hashed-host",
	    "|1|kRjF3K2mB8vqZ1Yx|dGhpc2lzbm90YXJlYWxoYXNo " PUB_ED25519 "\n");
	emit("seed-tab-sep", "target.example.org\t" PUB_ED25519 "\n");
	emit("seed-multi",
	    "# target.example.org:2222 SSH-2.0-OpenSSH_10.4\n"
	    "[target.example.org]:2222 " PUB_RSA "\n"
	    "[target.example.org]:2222 " PUB_ECDSA "\n"
	    "[target.example.org]:2222 " PUB_ED25519 "\n");

	/* skip cases */
	emit("seed-comment", "# target.example.org:22 SSH-2.0-OpenSSH_10.4\n");
	emit("seed-blank", "\n\n  \n\t\n");

	/* reject cases */
	emit("seed-marker-ca",
	    "@cert-authority *.example.org " PUB_ED25519 "\n");
	emit("seed-marker-revoked",
	    "@revoked target.example.org " PUB_ED25519 "\n");
	emit("seed-garbage", "this is not a keyscan line at all\n");
	emit("seed-bad-b64",
	    "target.example.org ssh-ed25519 NOT!VALID!BASE64!\n");
	emit("seed-no-key", "target.example.org\n");
	emit("seed-truncated",
	    "target.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n");

	printf("wrote seeds to %s/\n", CORPUS);
	return 0;
}
