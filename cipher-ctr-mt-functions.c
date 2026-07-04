/*
 * OpenSSH Multi-threaded AES-CTR Cipher Provider for OpenSSL 3
 *
 * Author: Benjamin Bennett <ben@psc.edu>
 * Author: Mike Tasota <tasota@gmail.com>
 * Author: Chris Rapier <rapier@psc.edu>
 * Copyright (c) 2008-2022 Pittsburgh Supercomputing Center. All rights reserved.
 *
 * Based on original OpenSSH AES-CTR cipher. Small portions remain unchanged,
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
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

#include "includes.h"

/* only for systems with OSSL 3 */
#ifdef WITH_OPENSSL3
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include "xmalloc.h"
#include <unistd.h>
#include "cipher-ctr-mt-functions.h"
#include "log.h"

/* for provider error struct */
#include "ossl3-provider-err.h"
#include "num.h"

/* note regarding threads and queues */
/* initially this cipher was written in a way that
 * the key stream was generated in a per cipher block
 * loop. For example, if the key stream queue length was
 * 16k and the cipher block size was 16 bytes it would
 * fill the queue 16 bytes at a time. Mitch Dorrell pointed
 * out that we could fill the queue in once call eliminating
 * loop and multiple calls to EVP_EncryptUpdate. Doing so
 * dramatically reduced CPU load in the threads and indicated
 * that we could also eliminate most of the threads and queues
 * as it would take far less time for a queue to enter KQ_FULL
 * state. As such, we've reduced the number of threads and queues from 2 and 8
 * (respectively) to 1 and 2. We've also elimnated the need to determine the
 * physical number of cores on the system. cjr 10/19/2022
 * Update 2026-07-03: the thread and queue counts are now fixed compile-time
 * constants (SSH_CIPHER_THREADS / NUMKQ = threads + 1).  Testing on loopback -
 * the maximum-throughput regime, since a networked path can only be slower -
 * confirmed one producer thread keeps the queues full at any rate ssh reaches,
 * so the runtime override (SSH_CIPHER_THREADS env var + get_thread_count) was
 * removed. */

/*-------------------- TUNABLES --------------------*/
/* SSH_CIPHER_THREADS (producer threads) and NUMKQ (keystream queues) are
 * compile-time constants defined in cipher-ctr-mt-functions.h. */
/*-------------------- END TUNABLES --------------------*/

/* globals */
/* how we increment the id the structs we create */
long unsigned int global_struct_id = 0;

/* keep a copy of the pointers created in thread_loop to free later */
struct aes_mt_ctx_ptrs *evp_ptrs = NULL;
/* evp_ptrs is a PROCESS-GLOBAL uthash mutated by every pregen thread
 * (HASH_ADD in thread_loop) and read/deleted from the join path.  Each cipher
 * context runs a single pregen thread, but a process has several contexts live
 * at once (send + receive, plus rekeys), so their HASH_ADDs into this shared
 * hash still run concurrently even at SSH_CIPHER_THREADS == 1.  The mutex is
 * therefore required; serialize all access (startup/join only, never the
 * per-block hot path). */
static pthread_mutex_t evp_ptrs_mu = PTHREAD_MUTEX_INITIALIZER;

/* private functions */

/*
 * Add num to counter 'ctr'
 */
static void
ssh_ctr_add(u_char *ctr, uint32_t num, u_int len)
{
	int i;
	uint16_t n;

	for (n = 0, i = len - 1; i >= 0 && (num || n); i--) {
		n = ctr[i] + (num & 0xff) + n;
		num >>= 8;
		ctr[i] = n & 0xff;
		n >>= 8;
	}
}

/*
 * Threads may be cancelled in a pthread_cond_wait, we must free the mutex
 */
static void
thread_loop_cleanup(void *x)
{
	pthread_mutex_unlock((pthread_mutex_t *)x);
}

#ifdef __APPLE__
/* Check if we should exit, we are doing both cancel and exit condition
 * since on OSX threads seem to occasionally fail to notice when they have
 * been cancelled. We want to have a backup to make sure that we won't hang
 * when the main process join()-s the cancelled thread.
 */
static void
thread_loop_check_exit(struct aes_mt_ctx_st *aes_mt_ctx)
{
	int exit_flag;

	pthread_rwlock_rdlock(&aes_mt_ctx->stop_lock);
	exit_flag = aes_mt_ctx->exit_flag;
	pthread_rwlock_unlock(&aes_mt_ctx->stop_lock);

	if (exit_flag)
		pthread_exit(NULL);
}
#else
# define thread_loop_check_exit(s)
#endif /* __APPLE__ */

/*
 * Helper function to terminate the helper threads
 */
static void
stop_and_join_pregen_threads(struct aes_mt_ctx_st *aes_mt_ctx)
{
	int i;

#ifdef __APPLE__
	/* notify threads that they should exit */
	pthread_rwlock_wrlock(&aes_mt_ctx->stop_lock);
	aes_mt_ctx->exit_flag = TRUE;
	pthread_rwlock_unlock(&aes_mt_ctx->stop_lock);
#endif /* __APPLE__ */

	/* Cancel pregen threads */
	for (i = 0; i < SSH_CIPHER_THREADS; i++) {
		debug_f ("Canceled %lu (%lu,%d)", aes_mt_ctx->tid[i], aes_mt_ctx->struct_id,
		       aes_mt_ctx->id[i]);
		pthread_cancel(aes_mt_ctx->tid[i]);
	}
	for (i = 0; i < SSH_CIPHER_THREADS; i++) {
		if (pthread_kill(aes_mt_ctx->tid[i], 0) != 0)
			debug3("AES-CTR MT pthread_join failure: Invalid thread id %lu in %s",
			       aes_mt_ctx->tid[i], __func__);
		else {
			debug_f ("Joining %lu (%lu, %d)", aes_mt_ctx->tid[i], aes_mt_ctx->struct_id,
				 aes_mt_ctx->id[i]);
			pthread_join(aes_mt_ctx->tid[i], NULL);
			/* this finds the entry in the hash that corresponding to the
			 * thread id. That's used to find the pointer to the cipher struct
			 * created in thread_loop. */
			struct aes_mt_ctx_ptrs *ptr;
			pthread_mutex_lock(&evp_ptrs_mu);
			HASH_FIND_INT(evp_ptrs, &aes_mt_ctx->tid[i], ptr);
			if (ptr != NULL)
				EVP_CIPHER_CTX_free(ptr->pointer);
			else {
				pthread_mutex_unlock(&evp_ptrs_mu);
				fatal_f ("Cannot find entry in hash table for thread id");
			}
			HASH_DEL(evp_ptrs, ptr);
			pthread_mutex_unlock(&evp_ptrs_mu);
			free(ptr);
                }
        }
	pthread_rwlock_destroy(&aes_mt_ctx->tid_lock);
}

/*
 * The life of a pregen thread:
 *    Find empty keystream queues and fill them using their counter.
 *    When done, update counter for the next fill.
 */
static void *
thread_loop(void *job)
{
	EVP_CIPHER_CTX * volatile evp_ctx;
	struct aes_mt_ctx_st *aes_mt_ctx = job;
	struct kq *q;
	struct aes_mt_ctx_ptrs *ptr;
	pthread_t first_tid;
	int outlen;
	u_char mynull[KQLEN * AES_BLOCK_SIZE];
	memset(&mynull, 0, KQLEN * AES_BLOCK_SIZE);

	/* get the thread id to see if this is the first one */
	pthread_rwlock_rdlock(&aes_mt_ctx->tid_lock);
	first_tid = aes_mt_ctx->tid[0];
	pthread_rwlock_unlock(&aes_mt_ctx->tid_lock);

	/* create the context for this thread */
	evp_ctx = EVP_CIPHER_CTX_new();
	if (evp_ctx == NULL)
		fatal_f("EVP_CIPHER_CTX_new failed");

	/* keep track of the pointer for the evp in this struct
	 * so we can free it later. So we place it in a hash indexed on the
	 * thread id, which is available to us in the free function.
	 * Note, the thread id isn't necessary unique across rekeys but
	 * that's okay as they are unique during a key. */
	ptr = xmalloc(sizeof *ptr); /*freed in stop & prejoin */
	ptr->tid = pthread_self(); /* index for hash */
	ptr->pointer = evp_ctx;
	pthread_mutex_lock(&evp_ptrs_mu);
	HASH_ADD_INT(evp_ptrs, tid, ptr);
	pthread_mutex_unlock(&evp_ptrs_mu);

	/* initialize the cipher ctx with the key provided
	 * determine which cipher to use based on the key size */
	const EVP_CIPHER *type;
	if (aes_mt_ctx->keylen == 256)
		type = EVP_aes_256_ctr();
	else if (aes_mt_ctx->keylen == 128)
		type = EVP_aes_128_ctr();
	else if (aes_mt_ctx->keylen == 192)
		type = EVP_aes_192_ctr();
	else
		fatal("Invalid key length of %d in AES CTR MT. Exiting", aes_mt_ctx->keylen);
	if (!EVP_EncryptInit_ex(evp_ctx, type, NULL, aes_mt_ctx->orig_key, NULL))
		fatal_f("EVP_EncryptInit_ex (key) failed");

	/*
	 * Handle the special case of startup, one thread must fill
	 * the first KQ then mark it as draining. Lock held throughout.
	 */
	if (pthread_equal(pthread_self(), first_tid)) {
		/* get the first element of the key queue struct */
		q = &aes_mt_ctx->q[0];
		pthread_mutex_lock(&q->lock);
		/* if we are in the INIT state then fill the queue */
		if (q->qstate == KQINIT) {
			/* set the initial counter */
			if (!EVP_EncryptInit_ex(evp_ctx, NULL, NULL, NULL, q->ctr))
				fatal_f("EVP_EncryptInit_ex (ctr) failed");
			/* encipher a block sized null string (mynull) with the key. This
			 * returns the keystream because xoring the keystream
			 * against null returns the keystream. Store that in the appropriate queue */
			if (!EVP_EncryptUpdate(evp_ctx, q->keys[0], &outlen, mynull, KQLEN * AES_BLOCK_SIZE))
				fatal_f("EVP_EncryptUpdate failed");
			/* Update the aes counter */
			ssh_ctr_add(q->ctr, KQLEN * NUMKQ, AES_BLOCK_SIZE);
			/* since this is the first thread set it to draining */
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
		}
		pthread_mutex_unlock(&q->lock);
	}

	/*
	 * Normal case is to find empty queues and fill them, skipping over
	 * queues already filled by other threads and stopping to wait for
	 * a draining queue to become empty.
	 *
	 * Multiple threads may be waiting on a draining queue and awoken
	 * when empty. The first thread to wake will mark it as filling,
	 * others will move on to fill, skip, or wait on the next queue.
	 * We init qidx here because if we do it at the top of the function
	 * we get a warning about it possibly being clobbered. The exact reason
	 * doesn't make a lot of sense but it has to happen after the
	 * first pthread_rwlock_rdlock(). Might have something to do with
	 * incorrect compiler optimizations.
	 */
	int qidx;
	for (qidx = 1;; qidx = (qidx + 1) % NUMKQ) {
		/* Check if I was cancelled, also checked in cond_wait */
		pthread_testcancel();

		/* Check if we should exit as well */
		thread_loop_check_exit(aes_mt_ctx);

		/* Lock queue and block if its draining */
		q = &aes_mt_ctx->q[qidx];
		pthread_mutex_lock(&q->lock);
		pthread_cleanup_push(thread_loop_cleanup, &q->lock);
		while (q->qstate == KQDRAINING || q->qstate == KQINIT) {
			thread_loop_check_exit(aes_mt_ctx);
			pthread_cond_wait(&q->cond, &q->lock);
		}
		pthread_cleanup_pop(0);

		/* If filling or full, somebody else got it, skip */
		if (q->qstate != KQEMPTY) {
			pthread_mutex_unlock(&q->lock);
			continue;
		}

		/*
		 * Empty, let's fill it.
		 * Queue lock is relinquished while we do this so others
		 * can see that it's being filled.
		 */
		q->qstate = KQFILLING;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);

		/* set the initial counter */
		if (!EVP_EncryptInit_ex(evp_ctx, NULL, NULL, NULL, q->ctr))
			fatal_f("EVP_EncryptInit_ex (ctr) failed");

		/* see corresponding block above for useful comments */
		if (!EVP_EncryptUpdate(evp_ctx, q->keys[0], &outlen, mynull, KQLEN * AES_BLOCK_SIZE))
			fatal_f("EVP_EncryptUpdate failed");

		/* Re-lock, mark full and signal consumer */
		pthread_mutex_lock(&q->lock);
		ssh_ctr_add(q->ctr, KQLEN * NUMKQ, AES_BLOCK_SIZE);
		q->qstate = KQFULL;
		pthread_cond_broadcast(&q->cond);
		pthread_mutex_unlock(&q->lock);
	}

	return NULL;
}


/* Our version of the EVP functions
 * these are public as they are used by the provider */

/* instantiate the cipher context.
 * in this we create the EVP ctx and the AES ctx, setup the AES ctx
 * initialize the EVP and then attach the AES ctx to the EVP ctx.
 * The *only* difference between aes_mt_newctx_256|192|128 is the
 * keylength of the cipher used in EVP_CipherInit
 * parameters: provider context
 * returns: EVP context
 */
/* honestly the way this works makes me think that there has to be
 * a better way of doing this however, I've yet to find one that doesn't
 * involve more madness. I think that's mostly becase I don't understand
 * how params work properly. I feel like I should be able to use them
 * to specify the key length but until then... */
/* Note: newctx returns the EVP_CIPHER_CTX, not the aes_mt_ctx_st directly.
 * The aes_mt_ctx_st is attached as app_data and retrieved with
 * EVP_CIPHER_CTX_get_app_data() in the other callbacks. The key length
 * comes in through the provider keylen param (set_ctx_params, in bytes),
 * is stored in aes_mt_ctx_st->keylen in bits, and selects the cipher in
 * the keyschedule below. Setting keylen through the params previously
 * looked broken only because get/set_ctx_params cast the context to the
 * wrong type; that was fixed 2026-06-29.*/
void *aes_mt_newctx_256(void *provctx)
{
	struct aes_mt_ctx_st *aes_mt_ctx = xmalloc(sizeof(*aes_mt_ctx));
	memset(aes_mt_ctx, 0, sizeof(*aes_mt_ctx));
	EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

	if ((aes_mt_ctx != NULL) && (evp_ctx != NULL)) {
		pthread_rwlock_init(&aes_mt_ctx->tid_lock, NULL);
#ifdef __APPLE__
		pthread_rwlock_init(&aes_mt_ctx->stop_lock, NULL);
		aes_mt_ctx->exit_flag = FALSE;
#endif /* __APPLE__ */

		aes_mt_ctx->state = HAVE_NONE;

		/* initialize the mutexs and conditions for each lock in our struct */
		for (int i = 0; i < NUMKQ; i++) {
			pthread_mutex_init(&aes_mt_ctx->q[i].lock, NULL);
			pthread_cond_init(&aes_mt_ctx->q[i].cond, NULL);
		}
		aes_mt_ctx->provctx = provctx;
		EVP_CipherInit(evp_ctx, EVP_aes_256_ctr(), NULL, NULL, 0);
		EVP_CIPHER_CTX_set_app_data(evp_ctx, aes_mt_ctx);
		return evp_ctx;
	}
	return NULL;
}

void *aes_mt_newctx_192(void *provctx)
{
	struct aes_mt_ctx_st *aes_mt_ctx = xmalloc(sizeof(*aes_mt_ctx));
	memset(aes_mt_ctx, 0, sizeof(*aes_mt_ctx));
	EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

	if ((aes_mt_ctx != NULL) && (evp_ctx != NULL)) {
		pthread_rwlock_init(&aes_mt_ctx->tid_lock, NULL);
#ifdef __APPLE__
		pthread_rwlock_init(&aes_mt_ctx->stop_lock, NULL);
		aes_mt_ctx->exit_flag = FALSE;
#endif /* __APPLE__ */

		aes_mt_ctx->state = HAVE_NONE;

		/* initialize the mutexs and conditions for each lock in our struct */
		for (int i = 0; i < NUMKQ; i++) {
			pthread_mutex_init(&aes_mt_ctx->q[i].lock, NULL);
			pthread_cond_init(&aes_mt_ctx->q[i].cond, NULL);
		}
		aes_mt_ctx->provctx = provctx;
		EVP_CipherInit(evp_ctx, EVP_aes_192_ctr(), NULL, NULL, 0);
		EVP_CIPHER_CTX_set_app_data(evp_ctx, aes_mt_ctx);
		return evp_ctx;
	}
	return NULL;
}

void *aes_mt_newctx_128(void *provctx)
{
	struct aes_mt_ctx_st *aes_mt_ctx = xmalloc(sizeof(*aes_mt_ctx));
	memset(aes_mt_ctx, 0, sizeof(*aes_mt_ctx));
	EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

	if ((aes_mt_ctx != NULL) && (evp_ctx != NULL)) {
		pthread_rwlock_init(&aes_mt_ctx->tid_lock, NULL);
#ifdef __APPLE__
		pthread_rwlock_init(&aes_mt_ctx->stop_lock, NULL);
		aes_mt_ctx->exit_flag = FALSE;
#endif /* __APPLE__ */

		aes_mt_ctx->state = HAVE_NONE;

		/* initialize the mutexs and conditions for each lock in our struct */
		for (int i = 0; i < NUMKQ; i++) {
			pthread_mutex_init(&aes_mt_ctx->q[i].lock, NULL);
			pthread_cond_init(&aes_mt_ctx->q[i].cond, NULL);
		}
		aes_mt_ctx->provctx = provctx;
		EVP_CipherInit(evp_ctx, EVP_aes_128_ctr(), NULL, NULL, 0);
		EVP_CIPHER_CTX_set_app_data(evp_ctx, aes_mt_ctx);
		return evp_ctx;
	}
	return NULL;
}

/* this function expects a void but we need the actual context
 * to get the app_data.
 */
void aes_mt_freectx(void *vevp_ctx)
{
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	struct aes_mt_ctx_st *aes_mt_ctx;

	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) != NULL) {
		stop_and_join_pregen_threads(aes_mt_ctx);

		memset(aes_mt_ctx, 0, sizeof(*aes_mt_ctx));
		free(aes_mt_ctx);
		EVP_CIPHER_CTX_set_app_data(evp_ctx, NULL);
	}
	EVP_CIPHER_CTX_free(evp_ctx);
}

/* this function takes the EVP context, gets the AES context
 * and starts the various threads we need */
int aes_mt_start_threads(void *vevp_ctx, const u_char *key,
			 size_t keylen, const u_char *iv,
			 size_t ivlen, const OSSL_PARAM *ossl_params)
{
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	struct aes_mt_ctx_st *aes_mt_ctx;


	/* get the initial state of aes_mt_ctx (our cipher stream struct) */
 	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) == NULL) {
		fatal("Missing AES MT context data!");
	}

	/* we are initializing but the current structure already
	 * has an IV and key so we want to kill the existing key data
	 * and start over. This is important when we need to rekey the data stream */
	if (aes_mt_ctx->state == (HAVE_KEY | HAVE_IV)) {
		/* tell the pregen threads to exit */
		stop_and_join_pregen_threads(aes_mt_ctx);

#ifdef __APPLE__
		/* reset the exit flag */
		aes_mt_ctx->exit_flag = FALSE;
#endif /* __APPLE__ */

		/* Start over getting key & iv */
		aes_mt_ctx->state = HAVE_NONE;
	}

	/* set the initial key for this key stream queue */
	if (key != NULL) {
		/* keylen is stored in bits here for the keyschedule selector
		 * below; the provider get/set_ctx_params convert to/from bytes */
		aes_mt_ctx->keylen = EVP_CIPHER_CTX_key_length(evp_ctx) * 8;
		aes_mt_ctx->orig_key = key;
		aes_mt_ctx->state |= HAVE_KEY;
	}

	/* set the IV */
	if (iv != NULL) {
		/* init the counter this is just a 16byte uchar */
		memcpy(aes_mt_ctx->aes_counter, iv, AES_BLOCK_SIZE);
		aes_mt_ctx->state |= HAVE_IV;
	}

	if (aes_mt_ctx->state == (HAVE_KEY | HAVE_IV)) {
		/* Clear queues */
		/* set the first key in the key queue to the current counter */
		memcpy(aes_mt_ctx->q[0].ctr, aes_mt_ctx->aes_counter, AES_BLOCK_SIZE);
		/* indicate that it needs to be initialized */
		aes_mt_ctx->q[0].qstate = KQINIT;
		/* for each of the remaining queues set the first counter to the
		 * counter and then add the size of the queue to the counter */
		for (int i = 1; i < NUMKQ; i++) {
			memcpy(aes_mt_ctx->q[i].ctr, aes_mt_ctx->aes_counter, AES_BLOCK_SIZE);
			ssh_ctr_add(aes_mt_ctx->q[i].ctr, i * KQLEN, AES_BLOCK_SIZE);
			aes_mt_ctx->q[i].qstate = KQEMPTY;
		}
		aes_mt_ctx->qidx = 0;
		aes_mt_ctx->ridx = 0;
		aes_mt_ctx->struct_id = global_struct_id++;

		/* Start threads. Make sure we have enough stack space (under alpine)
		* and aren't using more than we need (linux). This can be as low as
		* 512KB but that's a minimum. 1024KB gives us a little headroom if we
		* need it */
#define STACK_SIZE (1024 * 1024)
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setstacksize(&attr, STACK_SIZE);
		for (int i = 0; i < SSH_CIPHER_THREADS; i++) {
			pthread_rwlock_wrlock(&aes_mt_ctx->tid_lock);
			if (pthread_create(&aes_mt_ctx->tid[i], &attr, thread_loop, aes_mt_ctx) != 0)
				fatal ("AES-CTR MT Could not create thread in %s", __func__);
			else {
				aes_mt_ctx->id[i] = i;
				debug_f ("AES-CTR MT spawned a thread with id %lu (%lu, %d)",
					 aes_mt_ctx->tid[i], aes_mt_ctx->struct_id,
					 aes_mt_ctx->id[i]);
			}
			pthread_rwlock_unlock(&aes_mt_ctx->tid_lock);
		}
		pthread_attr_destroy(&attr);
		pthread_mutex_lock(&aes_mt_ctx->q[0].lock);
		/* wait for all of the threads to be initialized */
		while (aes_mt_ctx->q[0].qstate == KQINIT)
			pthread_cond_wait(&aes_mt_ctx->q[0].cond, &aes_mt_ctx->q[0].lock);
		pthread_mutex_unlock(&aes_mt_ctx->q[0].lock);
	}
	return 1;
}

/* this should correspond to ssh_aes_ctr
 * OSSL_CORE_MAKE_FUNC(int, cipher_cipher,
 *                     (void *cctx,
 *                     unsigned char *out, size_t *outl, size_t outsize,
 *                     const unsigned char *in, size_t inl))
 */

int aes_mt_do_cipher(void *vevp_ctx,
			    u_char *dest, size_t *destlen, size_t destsize,
			    const u_char *src, size_t len)
{
	typedef union {
#ifdef CIPHER_INT128_OK
		__uint128_t *u128;
#endif
		uint64_t *u64;
		uint32_t *u32;
		uint8_t *u8;
		const uint8_t *cu8;
		uintptr_t u;
	} ptrs_t;
	ptrs_t destp, srcp, bufp;
	uintptr_t align;
	struct aes_mt_ctx_st *aes_mt_ctx;
	struct kq *q, *oldq;
	int ridx;
	u_char *buf;
	EVP_CIPHER_CTX *evp_ctx = vevp_ctx;
	uint64_t src_a, key_a;
	
	/* CTR output length equals input length; report it per the OSSL
	 * update/cipher contract. Current callers on the EVP_Cipher path
	 * ignore the count, but the contract requires *destlen to be set. */
	if (destlen != NULL)
		*destlen = len;

	if (len == 0)
		return 1;

	if ((aes_mt_ctx = EVP_CIPHER_CTX_get_app_data(evp_ctx)) == NULL)
		return 0;

	q = &aes_mt_ctx->q[aes_mt_ctx->qidx];
	ridx = aes_mt_ctx->ridx;

	/* src already padded to block multiple */
	srcp.cu8 = src;
	destp.u8 = dest;
	do { /* do until len is 0 */
		buf = q->keys[ridx];
		bufp.u8 = buf;

		/* figure out the alignment on the fly */
#ifdef CIPHER_UNALIGNED_OK
		align = 0;
#else
		align = destp.u | srcp.u | bufp.u;
#endif

		/* XOR src against keystream (buf). Use memcpy to
		 * avoid strict aliasing UB when type-punning through
		 * wider integer types. The compiler optimizes these
		 * fixed-size memcpys into register loads. */
#ifdef CIPHER_INT128_OK
		if ((align & 0xf) == 0) {
			__uint128_t s128, k128, d128;
			memcpy(&s128, srcp.u8, sizeof(s128));
			memcpy(&k128, bufp.u8, sizeof(k128));
			d128 = s128 ^ k128;
			memcpy(destp.u8, &d128, sizeof(d128));
		} else
#endif
		if ((align & 0x7) == 0) {
			uint64_t dst_a;
			memcpy(&src_a, srcp.u8, sizeof(uint64_t));
			memcpy(&key_a, bufp.u8, sizeof(uint64_t));
			dst_a = src_a ^ key_a;
			memcpy(destp.u8, &dst_a, sizeof(uint64_t));
			memcpy(&src_a, srcp.u8 + 8, sizeof(uint64_t));
			memcpy(&key_a, bufp.u8 + 8, sizeof(uint64_t));
			dst_a = src_a ^ key_a;
			memcpy(destp.u8 + 8, &dst_a, sizeof(uint64_t));
		} else
		if ((align & 0x3) == 0) {
			destp.u32[0] = srcp.u32[0] ^ bufp.u32[0];
			destp.u32[1] = srcp.u32[1] ^ bufp.u32[1];
			destp.u32[2] = srcp.u32[2] ^ bufp.u32[2];
			destp.u32[3] = srcp.u32[3] ^ bufp.u32[3];
		} else {
			/*1 byte at a time*/
			size_t i;
			for (i = 0; i < AES_BLOCK_SIZE; ++i)
				dest[i] = src[i] ^ buf[i];
		}

		/* inc/decrement the pointers by the block size (16)*/
		destp.u += AES_BLOCK_SIZE;
		srcp.u += AES_BLOCK_SIZE;

		/* Increment read index, switch queues on rollover */
		if ((ridx = (ridx + 1) % KQLEN) == 0) {
			oldq = q;

			/* Mark next queue draining, may need to wait */
			aes_mt_ctx->qidx = (aes_mt_ctx->qidx + 1) % NUMKQ;
			q = &aes_mt_ctx->q[aes_mt_ctx->qidx];
			pthread_mutex_lock(&q->lock);
			while (q->qstate != KQFULL) {
				pthread_cond_wait(&q->cond, &q->lock);
			}
			q->qstate = KQDRAINING;
			pthread_cond_broadcast(&q->cond);
			pthread_mutex_unlock(&q->lock);

			/* Mark consumed queue empty and signal producers */
			pthread_mutex_lock(&oldq->lock);
			oldq->qstate = KQEMPTY;
			pthread_cond_broadcast(&oldq->cond);
			pthread_mutex_unlock(&oldq->lock);
		}
	} while (len -= AES_BLOCK_SIZE);
	aes_mt_ctx->ridx = ridx;
	return 1;
}

#endif /*WITH_OPENSSL3*/
