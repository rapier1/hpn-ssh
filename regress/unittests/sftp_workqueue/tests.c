/*
 * Unit tests for sftp-workqueue. Wired into the regress/unittests/
 * harness; built as test_sftp_workqueue and invoked from the unit target
 * of regress/Makefile. Provides its own main() and does not link against
 * test_helper because the workqueue's correctness contract is simple
 * enough that targeted assertions cover it.
 *
 * Exits 0 on success, nonzero on any failure with a diagnostic.
 *
 * Coverage: basic push/pop, FIFO ordering, MPMC stress, shutdown drain,
 * shutdown wakes blocked threads, high-watermark tracking, capacity bound.
 */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sftp-workqueue.h"

#define FAIL(fmt, ...) do { \
	fprintf(stderr, "FAIL %s:%d: " fmt "\n", \
	    __func__, __LINE__, ##__VA_ARGS__); \
	exit(1); \
} while (0)

#define OK(name) printf("ok  %s\n", name)

/* --- 1. basic single-thread push/pop FIFO ordering --- */
static void
test_basic_fifo(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(16);
	if (q == NULL) FAIL("new");
	for (intptr_t i = 1; i <= 8; i++)
		if (sftp_workqueue_push(q, (void *)i) != 0)
			FAIL("push %td", i);
	if (sftp_workqueue_depth(q) != 8) FAIL("depth %zu", sftp_workqueue_depth(q));
	for (intptr_t i = 1; i <= 8; i++) {
		void *p = NULL;
		if (sftp_workqueue_pop(q, &p) != 0)
			FAIL("pop %td", i);
		if ((intptr_t)p != i)
			FAIL("FIFO order: got %td want %td", (intptr_t)p, i);
	}
	if (sftp_workqueue_depth(q) != 0) FAIL("not empty");
	sftp_workqueue_shutdown(q);
	sftp_workqueue_free(q);
	OK("basic_fifo");
}

/* --- 2. shutdown drains residual then returns -1 --- */
static void
test_shutdown_drains(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(8);
	for (intptr_t i = 1; i <= 4; i++)
		sftp_workqueue_push(q, (void *)i);
	sftp_workqueue_shutdown(q);
	for (intptr_t i = 1; i <= 4; i++) {
		void *p = NULL;
		if (sftp_workqueue_pop(q, &p) != 0)
			FAIL("residual pop %td failed after shutdown", i);
		if ((intptr_t)p != i) FAIL("residual order");
	}
	void *p = NULL;
	if (sftp_workqueue_pop(q, &p) != -1)
		FAIL("pop after drain should fail");
	if (sftp_workqueue_push(q, (void *)1) != -1)
		FAIL("push after shutdown should fail");
	sftp_workqueue_free(q);
	OK("shutdown_drains");
}

/* --- 3. shutdown unblocks waiting threads --- */
static void *
blocked_pop(void *arg)
{
	struct sftp_workqueue *q = arg;
	void *p = NULL;
	int r = sftp_workqueue_pop(q, &p);
	return (void *)(intptr_t)r;
}

static void
test_shutdown_wakes_waiters(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(4);
	pthread_t t1, t2;
	pthread_create(&t1, NULL, blocked_pop, q);
	pthread_create(&t2, NULL, blocked_pop, q);
	usleep(50000); /* let them block */
	sftp_workqueue_shutdown(q);
	void *r1, *r2;
	pthread_join(t1, &r1);
	pthread_join(t2, &r2);
	if ((intptr_t)r1 != -1 || (intptr_t)r2 != -1)
		FAIL("blocked pop should return -1 on shutdown");
	sftp_workqueue_free(q);
	OK("shutdown_wakes_waiters");
}

/* --- 4. capacity bound: push blocks when full --- */
static void *
late_pop(void *arg)
{
	struct sftp_workqueue *q = arg;
	usleep(30000);
	void *p = NULL;
	sftp_workqueue_pop(q, &p);
	return NULL;
}

static void
test_capacity_blocks_push(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(2);
	pthread_t t;
	sftp_workqueue_push(q, (void *)1);
	sftp_workqueue_push(q, (void *)2);
	if (sftp_workqueue_depth(q) != 2) FAIL("not full");
	pthread_create(&t, NULL, late_pop, q);
	/* This push must block until late_pop frees a slot. */
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (sftp_workqueue_push(q, (void *)3) != 0) FAIL("push");
	clock_gettime(CLOCK_MONOTONIC, &t1);
	pthread_join(t, NULL);
	long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
	    (t1.tv_nsec - t0.tv_nsec) / 1000000;
	if (elapsed_ms < 20)
		FAIL("push didn't block (elapsed %ldms)", elapsed_ms);
	sftp_workqueue_shutdown(q);
	void *p;
	while (sftp_workqueue_pop(q, &p) == 0)
		;
	sftp_workqueue_free(q);
	OK("capacity_blocks_push");
}

/* --- 5. MPMC stress: 4 producers × 4 consumers × 10000 items each --- */
#define MPMC_PRODUCERS 4
#define MPMC_CONSUMERS 4
#define MPMC_PER_PRODUCER 10000

struct mpmc_args {
	struct sftp_workqueue *q;
	int id;
	uint64_t pushed;
	uint64_t popped;
	uint64_t sum;
};

static void *
mpmc_producer(void *arg)
{
	struct mpmc_args *a = arg;
	for (int i = 0; i < MPMC_PER_PRODUCER; i++) {
		intptr_t v = (intptr_t)(a->id * MPMC_PER_PRODUCER + i + 1);
		if (sftp_workqueue_push(a->q, (void *)v) != 0)
			FAIL("producer %d push", a->id);
		a->pushed++;
	}
	return NULL;
}

static void *
mpmc_consumer(void *arg)
{
	struct mpmc_args *a = arg;
	void *p;
	while (sftp_workqueue_pop(a->q, &p) == 0) {
		a->popped++;
		a->sum += (intptr_t)p;
	}
	return NULL;
}

static void
test_mpmc_stress(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(64);
	pthread_t prods[MPMC_PRODUCERS], cons[MPMC_CONSUMERS];
	struct mpmc_args pa[MPMC_PRODUCERS], ca[MPMC_CONSUMERS];

	for (int i = 0; i < MPMC_CONSUMERS; i++) {
		ca[i] = (struct mpmc_args){.q = q, .id = i};
		pthread_create(&cons[i], NULL, mpmc_consumer, &ca[i]);
	}
	for (int i = 0; i < MPMC_PRODUCERS; i++) {
		pa[i] = (struct mpmc_args){.q = q, .id = i};
		pthread_create(&prods[i], NULL, mpmc_producer, &pa[i]);
	}
	for (int i = 0; i < MPMC_PRODUCERS; i++)
		pthread_join(prods[i], NULL);
	sftp_workqueue_shutdown(q);
	for (int i = 0; i < MPMC_CONSUMERS; i++)
		pthread_join(cons[i], NULL);

	uint64_t expected_total = MPMC_PRODUCERS * MPMC_PER_PRODUCER;
	uint64_t actual_total = 0, actual_sum = 0;
	for (int i = 0; i < MPMC_CONSUMERS; i++) {
		actual_total += ca[i].popped;
		actual_sum += ca[i].sum;
	}
	uint64_t expected_sum = 0;
	for (int p = 0; p < MPMC_PRODUCERS; p++)
		for (int i = 0; i < MPMC_PER_PRODUCER; i++)
			expected_sum += (uint64_t)(p * MPMC_PER_PRODUCER + i + 1);

	if (actual_total != expected_total)
		FAIL("count: got %lu want %lu",
		    (unsigned long)actual_total, (unsigned long)expected_total);
	if (actual_sum != expected_sum)
		FAIL("sum: got %lu want %lu (items lost or duplicated)",
		    (unsigned long)actual_sum, (unsigned long)expected_sum);

	if (sftp_workqueue_high_watermark(q) > 64)
		FAIL("high watermark exceeded capacity");

	sftp_workqueue_free(q);
	OK("mpmc_stress");
}

/* --- 6. high watermark tracks correctly --- */
static void
test_high_watermark(void)
{
	struct sftp_workqueue *q = sftp_workqueue_new(8);
	if (sftp_workqueue_high_watermark(q) != 0) FAIL("hw not 0");
	for (intptr_t i = 1; i <= 5; i++) sftp_workqueue_push(q, (void *)i);
	if (sftp_workqueue_high_watermark(q) != 5) FAIL("hw not 5");
	void *p;
	for (int i = 0; i < 3; i++) sftp_workqueue_pop(q, &p);
	if (sftp_workqueue_high_watermark(q) != 5) FAIL("hw should not decrease");
	for (intptr_t i = 1; i <= 6; i++) sftp_workqueue_push(q, (void *)i);
	if (sftp_workqueue_high_watermark(q) != 8) FAIL("hw not 8");
	sftp_workqueue_shutdown(q);
	while (sftp_workqueue_pop(q, &p) == 0) ;
	sftp_workqueue_free(q);
	OK("high_watermark");
}

/* --- 7. invalid args --- */
static void
test_invalid(void)
{
	if (sftp_workqueue_new(0) != NULL) FAIL("zero capacity should fail");
	OK("invalid");
}

int
main(void)
{
	test_basic_fifo();
	test_shutdown_drains();
	test_shutdown_wakes_waiters();
	test_capacity_blocks_push();
	test_high_watermark();
	test_mpmc_stress();
	test_invalid();
	printf("\nall workqueue tests passed\n");
	return 0;
}
