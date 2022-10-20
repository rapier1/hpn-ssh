/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly-libcrypto.c,v 1.1 2020/04/03 04:32:21 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <sys/wait.h>

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly-forks.h"
#include "cipher-pipes.h"
#include "poly1305-opt.h"
#include "ipc.h"

#define READ_END 0
#define WRITE_END 1

#define NUMWORKERS 2

#define LIKELY(x)   __builtin_expect((x),1)
#define UNLIKELY(x) __builtin_expect((x),0)

#define PUT_UINT(ADDR, VAL) ( *((u_int *) (ADDR)) = (VAL) )

/* #define WORKERPATH "ssh-worker-chacha20" */

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
	struct chachapolyf_ctx * cpf_ctx;
};

struct chachapolyf_ctx {
	u_int numworkers;
	int (* rpipes)[2];
	int (* wpipes)[2];
	struct smem ** smem;
	u_int nextseqnr;
	pid_t * pids;
	u_char sndbuf[4096];
	u_char rcvbuf[POLY1305_KEYLEN + AADLEN + KEYSTREAMLEN];
};

void
dumphex(const u_char * label, const u_char * data, size_t size) {
	if(size > 32) {
		dumphex(label,data,32);
		dumphex(label,data+32,size-32);
		return;
	}
	char * str = malloc(size * 2 + 1);
	for(u_int i=0; i<size; i++)
		sprintf(str + 2*i, "%02hhx", data[i]);
	debug_f("DEBUGX: %s: %s", label, str);
	free(str);
}

__attribute__((always_inline))
static inline int
pw(struct chachapolyf_ctx * ctx, u_int worker, const u_char * data,
    size_t size) {
/*	debug_f("DEBUGX: Writing %lu bytes to pipe %u.", size,
	    ctx->wpipes[worker][WRITE_END]);
	dumphex("bytes",data,size);*/
	return (write(ctx->wpipes[worker][WRITE_END], data, size*sizeof(u_char))
	    != (ssize_t) (size * sizeof(u_char)));
}
__attribute__((always_inline))
static inline int
pcw(struct chachapolyf_ctx * ctx, u_int worker, u_char data) {
/*	debug_f("DEBUGX: Writing a char to pipe %u: %c",
	    ctx->wpipes[worker][WRITE_END], data); */
	return (write(ctx->wpipes[worker][WRITE_END], &data, sizeof(u_char))
	    != sizeof(u_char));
}
__attribute__((always_inline))
static inline int
piw(struct chachapolyf_ctx * ctx, u_int worker, u_int data) {
/*	debug_f("DEBUGX: Writing an int to pipe %u: %u",
	    ctx->wpipes[worker][WRITE_END], data); */
	return (write(ctx->wpipes[worker][WRITE_END], &data, sizeof(u_int))
	    != sizeof(u_int));
}
__attribute__((always_inline))
static inline int
pr(struct chachapolyf_ctx * ctx, u_int worker, u_char * data, size_t size) {
/*	debug_f("DEBUGX: Reading %lu bytes from pipe %u...", size,
	    ctx->rpipes[worker][READ_END]); */
	int ret = -1;
	size_t count = 0;
	while(count < size) {
		ret = read(ctx->rpipes[worker][READ_END], data + count, size - count);
		if(ret == -1 || ret == 0) {
/*			debug_f("DEBUGX: err(%d)",ret); */
			return 1;
		} else {
			count += ret;
/*			dumphex("so far",data,count); */
		}
	}
/*	dumphex("complete",data,size); */
	return 0;
}

__attribute__((always_inline))
static inline int
pwm(struct chachapolyf_ctx * ctx, u_int worker, const u_char * data,
    size_t size) {
	return (smem_nwrite_msg(ctx->smem[worker], data, size, MAINSIG) != size);
}
__attribute__((always_inline))
static inline int
pcwm(struct chachapolyf_ctx * ctx, u_int worker, u_char data) {
	return (smem_nwrite_msg(ctx->smem[worker], &data, sizeof(u_char), MAINSIG)
	    != sizeof(u_char));
}
__attribute__((always_inline))
static inline int
piwm(struct chachapolyf_ctx * ctx, u_int worker, u_int data) {
	return (smem_nwrite_msg(ctx->smem[worker], &data, sizeof(u_int), MAINSIG)
	    != sizeof(u_int));
}
__attribute__((always_inline))
static inline int
prm(struct chachapolyf_ctx * ctx, u_int worker, u_char * data, size_t size) {
	return (smem_nread_msg(ctx->smem[worker], &data, size, MAINSIG) != size);
}


struct chachapoly_ctx *
chachapolyf_new(struct chachapoly_ctx * oldctx, const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *cp_ctx = chachapoly_new(key,keylen);
	if(cp_ctx == NULL)
		return NULL;

	if ((cp_ctx->cpf_ctx = calloc(1, sizeof(*(cp_ctx->cpf_ctx)))) == NULL) {
		chachapoly_free(cp_ctx);
		return NULL;
	}
	struct chachapolyf_ctx *ctx = cp_ctx->cpf_ctx;

	char * ssh_cipher_threads = getenv("SSH_CIPHER_THREADS");
	if (ssh_cipher_threads == NULL || strlen(ssh_cipher_threads) == 0)
		ctx->numworkers = NUMWORKERS;
	else {
		int envnumworkers = atoi(ssh_cipher_threads);
		if(envnumworkers > 0)
			ctx->numworkers = envnumworkers;
		else
			ctx->numworkers = NUMWORKERS;
	}

	if ((ctx->rpipes = malloc(ctx->numworkers * sizeof(int[2]))) == NULL)
		goto fail;
	if ((ctx->wpipes = malloc(ctx->numworkers * sizeof(int[2]))) == NULL)
		goto fail;
	if ((ctx->pids = malloc(ctx->numworkers * sizeof(pid_t))) == NULL)
		goto fail;
	if ((ctx->smem = malloc(ctx->numworkers * sizeof(struct smem *)))
	    == NULL)
		goto fail;

	if(allocCipherPipeSpace(ctx->numworkers * 2))
		goto fail;

	u_int nextseqnr=0;
	if (oldctx != NULL && oldctx->cpf_ctx != NULL) {
		nextseqnr=oldctx->cpf_ctx->nextseqnr;
	}

	char * helper = getenv("SSH_CCP_HELPER");
	if (helper == NULL || strlen(helper) == 0)
		helper = _PATH_SSH_CCP_HELPER;

	for(u_int i = 0; i < ctx->numworkers; i++) {
		if (pipe(ctx->wpipes[i]) != 0) {
			for (int j = i-1; j >= 0; j--) {
				close(ctx->wpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				close(ctx->rpipes[j][WRITE_END]);
			}
			goto fail;
		}
		if (pipe(ctx->rpipes[i]) != 0) {
			close(ctx->wpipes[i][READ_END]);
			close(ctx->wpipes[i][WRITE_END]);
			for (int j = i-1; j >= 0; j--) {
				close(ctx->wpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				close(ctx->rpipes[j][WRITE_END]);
			}
			goto fail;
		}
	}

	for (u_int i = 0; i < ctx->numworkers; i++) {
		ctx->pids[i] = fork();
		if (ctx->pids[i] == -1) {
			for (u_int j = 0; j < ctx->numworkers; j++) {
				/*pcw(ctx, j, 'q');*/
				close(ctx->wpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				close(ctx->rpipes[j][WRITE_END]);
				/*waitpid(ctx->pids[j], NULL, 0);*/
			}
			goto fail;
		}
		if (ctx->pids[i] != 0) {
			/* parent process */
			u_int workerseqnr = nextseqnr;
			while (workerseqnr % ctx->numworkers != i)
				workerseqnr++;
			if (pcw(ctx, i, 'b') ||
			    piw(ctx, i, ctx->numworkers) ||
			    piw(ctx, i, workerseqnr) ||
			    pw(ctx, i, key, keylen) ||
			    pcw(ctx, i, 'g')) {
				for (u_int j = 0; j < ctx->numworkers; j++) {
					/*pcw(ctx, j, 'q');*/
					close(ctx->wpipes[j][READ_END]);
					close(ctx->wpipes[j][WRITE_END]);
					close(ctx->rpipes[j][READ_END]);
					close(ctx->rpipes[j][WRITE_END]);
					/*waitpid(ctx->pids[j], NULL, 0);*/
				}
				goto fail;
			}
		} else {
			/* child process */
			if (dup2(ctx->rpipes[i][WRITE_END], STDOUT_FILENO)
			    == -1)
				exit(1);
			if (dup2(ctx->wpipes[i][READ_END], STDIN_FILENO) == -1)
				exit(1);
			for (u_int j = 0; j < ctx->numworkers; j++) {
				if (close(ctx->wpipes[j][WRITE_END]) == -1)
					exit(1);
				if (close(ctx->rpipes[j][READ_END]) == -1)
					exit(1);
				if (close(ctx->rpipes[j][WRITE_END]) == -1)
					exit(1);
				if (close(ctx->wpipes[j][READ_END]) == -1)
					exit(1);
			}
			if (closeCipherPipes())
				exit(1);
			execlp(helper, helper, (char *) NULL);
			exit(1);
		}
	}
	int ret = 0;
	for (u_int i = 0; i < ctx->numworkers; i++) {
		ret |= close(ctx->wpipes[i][READ_END]);
		ret |= close(ctx->rpipes[i][WRITE_END]);
	}
	if (ret) {
		for (u_int i = 0; i < ctx->numworkers; i++) {
			close(ctx->wpipes[i][WRITE_END]);
			close(ctx->rpipes[i][READ_END]);
		}
		goto fail;
	}
	for (u_int i = 0; i < ctx->numworkers; i++) {
		if (addCipherPipe(ctx->wpipes[i][WRITE_END]) ||
		    addCipherPipe(ctx->rpipes[i][READ_END])) {
			for (u_int j = 0; j < ctx->numworkers; j++) {
				delCipherPipe(ctx->wpipes[j][WRITE_END]);
				delCipherPipe(ctx->rpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
			}
			goto fail;
		}
	}

	/* Switch to shared memory mode */
	for (u_int i = 0; i < ctx->numworkers; i++) {
		ctx->smem[i] = smem_create();
		if (ctx->smem[i] == NULL) {
			for (u_int j = 0; j < ctx->numworkers; j++) {
				delCipherPipe(ctx->wpipes[j][WRITE_END]);
				delCipherPipe(ctx->rpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
			}
			for (u_int j = 0; j < i; j++)
				smem_free(ctx->smem[j]);
			goto fail;
		}
		smem_signal(ctx->smem[i], 1);
	}
	for (u_int i = 0; i < ctx->numworkers; i++) {
		if (pcw(ctx, i, 'm') ||
		    piw(ctx, i, smem_getpath(ctx->smem[i]))) {
			for (u_int j = 0; j < ctx->numworkers; j++) {
				delCipherPipe(ctx->wpipes[j][WRITE_END]);
				delCipherPipe(ctx->rpipes[j][READ_END]);
				close(ctx->wpipes[j][WRITE_END]);
				close(ctx->rpipes[j][READ_END]);
				smem_free(ctx->smem[j]);
			}
			goto fail;
		}
		smem_signal(ctx->smem[i], 0);
		pcwm(ctx, i, 'g');
		smem_signal(ctx->smem[i], 0);
	}

	return cp_ctx;
 fail:
	if (ctx->rpipes != NULL)
		free(ctx->rpipes);
	if (ctx->wpipes != NULL)
		free(ctx->wpipes);
	if (ctx->pids != NULL)
		free(ctx->pids);
	freezero(ctx, sizeof(*ctx));
	chachapoly_free(cp_ctx);
	return NULL;
}

void
chachapolyf_free(struct chachapoly_ctx *cpctx)
{
	if (cpctx == NULL)
		return;
	struct chachapolyf_ctx * cpfctx = cpctx->cpf_ctx;
	if (cpfctx != NULL) {
		for (u_int i = 0; i < cpfctx->numworkers; i++) {
/*				pcw(cpfctx, i, 'q');*/
			pcwm(cpfctx, i, 'q');
			smem_signal(cpfctx->smem[i], 0);
			delCipherPipe(cpfctx->wpipes[i][WRITE_END]);
			delCipherPipe(cpfctx->rpipes[i][READ_END]);
			close(cpfctx->wpipes[i][WRITE_END]);
			close(cpfctx->rpipes[i][READ_END]);
			waitpid(cpfctx->pids[i], NULL, 0);
			smem_free(cpfctx->smem[i]);
		}
		free(cpfctx->rpipes);
		free(cpfctx->wpipes);
		free(cpfctx->pids);
		free(cpfctx->smem);
		freezero(cpfctx, sizeof(*cpfctx));
	}
	chachapoly_free(cpctx);
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapolyf_crypt(struct chachapoly_ctx *cp_ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	if (UNLIKELY(cp_ctx->cpf_ctx == NULL)) {
/*		debug_f("FALLBACK"); */
		return chachapoly_crypt(cp_ctx, seqnr, dest, src, len, aadlen,
		    authlen, do_encrypt);
	}
	struct chachapolyf_ctx * ctx = cp_ctx->cpf_ctx;

	u_char * poly_key = ctx->smem[seqnr % ctx->numworkers]->data;
	u_char * xorStream = ctx->smem[seqnr % ctx->numworkers]->data +
	    POLY1305_KEYLEN;

	u_char expected_tag[POLY1305_TAGLEN];

	int r = SSH_ERR_INTERNAL_ERROR;
	if (UNLIKELY(ctx->nextseqnr != seqnr)) {
		ctx->sndbuf[0] = 's';
		ctx->sndbuf[5] = 'g';
		for (u_int i = 0; i < ctx->numworkers; i++) {
			PUT_UINT(&(ctx->sndbuf[1]), seqnr + i);
			if (UNLIKELY(pwm(ctx, (seqnr + i) % ctx->numworkers,
			    ctx->sndbuf, 6)))
				goto out;
			smem_signal(ctx->smem[(seqnr + i) % ctx->numworkers],
			    0);
		}
		ctx->nextseqnr = seqnr;
	}
	ctx->sndbuf[0]='p';
	PUT_UINT(&(ctx->sndbuf[1]), len);
//	fprintf(stderr,"Spinning %i\n", seqnr);
	smem_spinwait(ctx->smem[seqnr % ctx->numworkers], 1);

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		poly1305_auth_opt(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	u_int last4 = (len + AADLEN)/4 - 1;
	((uint32_t *) dest)[last4] =
	    ((uint32_t *) xorStream)[last4] ^ ((uint32_t *) src)[last4];
	typedef uint64_t bsize;
	bsize * destB      = (bsize *) &(dest[0]);
	bsize * srcB       = (bsize *) &(src[0]);
	bsize * xorStreamB = (bsize *) &(xorStream[0]);
	for (u_int i = 0; i < len/(sizeof(bsize)); i++)
		destB[i] = xorStreamB[i] ^ srcB[i];

/*
	for (u_int i = 0; i < len + AADLEN; i++)
		dest[i] = xorStream[i] ^ src[i];
*/	

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth_opt(dest + aadlen + len, dest, aadlen + len,
		     poly_key);
	}
	ctx->nextseqnr = seqnr + 1;
	pwm(ctx, seqnr % ctx->numworkers, "ng", 2);
	smem_signal(ctx->smem[seqnr % ctx->numworkers], 0);
	r = 0;
 out:
	if (ctx == NULL)
		fprintf(stderr,"CTX NULL!\n");
	explicit_bzero(expected_tag, sizeof(expected_tag));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapolyf_get_length(struct chachapoly_ctx *cp_ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	if(cp_ctx->cpf_ctx == NULL) {
/*		debug_f("FALLBACK"); */
		return chachapoly_get_length(cp_ctx, plenp, seqnr, cp, len);
	}
	struct chachapolyf_ctx * ctx = cp_ctx->cpf_ctx;

	u_char buf[4];
/*	u_char xorStream[4];*/
	u_char * xorStream = ctx->smem[seqnr % ctx->numworkers]->data +
	    POLY1305_KEYLEN;

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;

	if (ctx->nextseqnr != seqnr) {
		for (u_int i = 0; i < ctx->numworkers; i++) {
			if (pcwm(ctx, (seqnr + i) % ctx->numworkers, 's'))
				return SSH_ERR_LIBCRYPTO_ERROR;
			if (piwm(ctx, (seqnr + i) % ctx->numworkers, seqnr + i))
				return SSH_ERR_LIBCRYPTO_ERROR;
			if (pcwm(ctx, (seqnr + i) % ctx->numworkers, 'g'))
				return SSH_ERR_LIBCRYPTO_ERROR;
			smem_signal(ctx->smem[(seqnr + i) % ctx->numworkers],
			    0);
		}
		ctx->nextseqnr = seqnr;
	}
	smem_spinwait(ctx->smem[seqnr % ctx->numworkers], 1);
	for (u_int i = 0; i < sizeof(buf); i++)
		buf[i] = xorStream[i] ^ cp[i];
	*plenp = PEEK_U32(buf);
	explicit_bzero(buf, sizeof(buf));
	return 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
