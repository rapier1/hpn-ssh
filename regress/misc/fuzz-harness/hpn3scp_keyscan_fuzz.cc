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
 * Fuzz the hpn3scp keyscan-line parser (hpn3scp-hostkey.h), the remote-
 * facing parser of the third-party launcher's host-key trust broker: the
 * launcher asks the SOURCE host to hpnssh-keyscan the target, and every byte
 * that comes back is controlled by a possibly-hostile source.  The parser
 * must never crash, over-read, or loop, must reject known_hosts markers
 * (@cert-authority/@revoked - an injection signal, keyscan never emits
 * them), certificate keys, and malformed keys, and must hand back a fully
 * parsed plain key only on return 0 (contract checked below).
 *
 * Input is split on newlines and fed line-by-line, mirroring the real
 * consumer (hpn3scp_fetch_target_keys splits the capture with strtok_r).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "hpn3scp.h"
#include "hpn3scp-hostkey.h"

/*
 * The linked objects reference functions from hpn3scp.c, which has main(),
 * and from progressmeter.c, which drags in the meter.  The parser path
 * never calls them; abort if anything does.
 */
void
ssh_base_args(const struct run_state *s, struct arglist *a, int with_n,
    int with_agent)
{
	(void)s; (void)a; (void)with_n; (void)with_agent;
	abort();
}

void
add_addr_family_arg(const struct run_state *s, struct arglist *a)
{
	(void)s; (void)a;
	abort();
}

int
pm_eprintf(const char *fmt, ...)
{
	(void)fmt;
	abort();
}
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sshkey *k;
	char *buf, *line, *save = NULL, *fp;
	int r;

	/* NUL-terminated, mutable copy for line splitting */
	buf = (char *)malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	for (line = strtok_r(buf, "\n", &save); line != NULL;
	    line = strtok_r(NULL, "\n", &save)) {
		k = NULL;
		r = hpn3scp_parse_keyscan_line(line, &k);
		switch (r) {
		case 0:
			/* contract: accepted line yields a parsed plain key */
			if (k == NULL || sshkey_is_cert(k))
				abort();
			/* exercise the fingerprint path the consumer runs */
			fp = hpn3scp_key_fp(k);
			free(fp);
			sshkey_free(k);
			break;
		case 1:		/* skipped (blank/comment) */
		case -1:	/* rejected (marker/malformed) */
			/* contract: no key may escape a non-accept */
			if (k != NULL)
				abort();
			break;
		default:
			abort();	/* no other returns exist */
		}
	}
	free(buf);
	return 0;
}
