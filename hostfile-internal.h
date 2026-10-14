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

/* hostfile-internal.h - the hostfile.c helper hpn3scp uses to build
 * known_hosts entries, so its lines are formatted, lowercased, and hashed
 * exactly as ssh writes them, rather than by a copy that could drift.
 *
 * Upstream merge note: hostfile.c gains the removal of `static` from
 * format_host_entry() and the include of this header. */

#ifndef _HOSTFILE_INTERNAL_H
#define _HOSTFILE_INTERNAL_H

struct sshbuf;
struct sshkey;

/* Append one known_hosts line for host and key to entry, hashing the host
 * name when store_hash is set, as ssh does under HashKnownHosts. With ip,
 * the address is recorded too. Returns 1 on success, or 0. */
int	format_host_entry(struct sshbuf *, const char *, const char *,
	    const struct sshkey *, int);

#endif /* _HOSTFILE_INTERNAL_H */
