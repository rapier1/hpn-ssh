/*
 * Copyright (c) 2026 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Mitchell Dorrell <mwd@psc.edu>
 *  Author: Chris Rapier  <rapier@psc.edu>
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

#ifndef CHACHA_POLY_LIBCRYPTO_MT_H
#define CHACHA_POLY_LIBCRYPTO_MT_H

#include <sys/types.h>
#include "chacha.h"
#include "poly1305.h"

#ifndef CHACHA_KEYLEN
#define CHACHA_KEYLEN	32 /* Only 256 bit keys used here */
#endif

struct chachapoly_ctx_mt; /* defined in cipher-chachapoly-libcrypto-mt.c */

struct chachapoly_ctx_mt *chachapoly_new_mt(u_int startseqnr, const u_char *key, u_int keylen)
                                            __attribute__((__bounded__(__buffer__, 2, 3)));

void   chachapoly_free_mt(struct chachapoly_ctx_mt *cpctx);

int    chachapoly_crypt_mt(struct chachapoly_ctx_mt *cpctx, u_int seqnr,
			   u_char *dest, const u_char *src, u_int len, u_int aadlen,
			   u_int authlen, int do_encrypt);

int    chachapoly_get_length_mt(struct chachapoly_ctx_mt *cpctx,
				u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
                                __attribute__((__bounded__(__buffer__, 4, 5)));

#endif /* CHACHA_POLY_LIBCRYPTO_MT_H */
