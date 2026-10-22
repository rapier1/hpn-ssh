/*
 * Unit tests for sftp-hpn-workqueue. Wired into the regress/unittests/
 * harness; built as test_sftp_workqueue and invoked from the unit target
 * of regress/Makefile. Provides its own main() and does not link against
 * test_helper because the workqueue's correctness contract is simple
 * enough that targeted assertions cover it.
 *
 * Exits 0 on success, nonzero on any failure with a diagnostic.
 *
 * Coverage: basic push/pop, FIFO ordering, MPMC stress, shutdown drain,
 * shutdown wakes blocked threads, capacity bound, invalid capacity, the
 * non-blocking pushes and pop, drain after shutdown, and the kick and
 * timeout that end wait_activity.
 */

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sftp-hpn-workqueue.h"

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
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(16);
	if (q == NULL) FAIL("new");
	for (intptr_t i = 1; i <= 8; i++)
		if (sftp_hpn_workqueue_push(q, (void *)i) != 0)
			FAIL("push %td", i);
	if (sftp_hpn_workqueue_depth(q) != 8) FAIL("depth %d", sftp_hpn_workqueue_depth(q));
	for (intptr_t i = 1; i <= 8; i++) {
		void *p = NULL;
		if (sftp_hpn_workqueue_pop(q, &p) != 0)
			FAIL("pop %td", i);
		if ((intptr_t)p != i)
			FAIL("FIFO order: got %td want %td", (intptr_t)p, i);
	}
	if (sftp_hpn_workqueue_depth(q) != 0) FAIL("not empty");
	sftp_hpn_workqueue_shutdown(q);
	sftp_hpn_workqueue_free(q);
	OK("basic_fifo");
}

/* --- 2. shutdown drains residual then returns -1 --- */
static void
test_shutdown_drains(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(8);
	for (intptr_t i = 1; i <= 4; i++)
		sftp_hpn_workqueue_push(q, (void *)i);
	sftp_hpn_workqueue_shutdown(q);
	for (intptr_t i = 1; i <= 4; i++) {
		void *p = NULL;
		if (sftp_hpn_workqueue_pop(q, &p) != 0)
			FAIL("residual pop %td failed after shutdown", i);
		if ((intptr_t)p != i) FAIL("residual order");
	}
	void *p = NULL;
	if (sftp_hpn_workqueue_pop(q, &p) != -1)
		FAIL("pop after drain should fail");
	if (sftp_hpn_workqueue_push(q, (void *)1) != -1)
		FAIL("push after shutdown should fail");
	sftp_hpn_workqueue_free(q);
	OK("shutdown_drains");
}

/* --- 3. shutdown unblocks waiting threads --- */
static void *
blocked_pop(void *arg)
{
	struct sftp_hpn_workqueue *q = arg;
	void *p = NULL;
	int r = sftp_hpn_workqueue_pop(q, &p);
	return (void *)(intptr_t)r;
}

static void
test_shutdown_wakes_waiters(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(4);
	pthread_t t1, t2;
	pthread_create(&t1, NULL, blocked_pop, q);
	pthread_create(&t2, NULL, blocked_pop, q);
	usleep(50000); /* let them block */
	sftp_hpn_workqueue_shutdown(q);
	void *r1, *r2;
	pthread_join(t1, &r1);
	pthread_join(t2, &r2);
	if ((intptr_t)r1 != -1 || (intptr_t)r2 != -1)
		FAIL("blocked pop should return -1 on shutdown");
	sftp_hpn_workqueue_free(q);
	OK("shutdown_wakes_waiters");
}

/* --- 4. capacity bound: push blocks when full --- */
static void *
late_pop(void *arg)
{
	struct sftp_hpn_workqueue *q = arg;
	usleep(30000);
	void *p = NULL;
	sftp_hpn_workqueue_pop(q, &p);
	return NULL;
}

static void
test_capacity_blocks_push(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(2);
	pthread_t t;
	sftp_hpn_workqueue_push(q, (void *)1);
	sftp_hpn_workqueue_push(q, (void *)2);
	if (sftp_hpn_workqueue_depth(q) != 2) FAIL("not full");
	pthread_create(&t, NULL, late_pop, q);
	/* This push must block until late_pop frees a slot. */
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (sftp_hpn_workqueue_push(q, (void *)3) != 0) FAIL("push");
	clock_gettime(CLOCK_MONOTONIC, &t1);
	pthread_join(t, NULL);
	long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
	    (t1.tv_nsec - t0.tv_nsec) / 1000000;
	if (elapsed_ms < 20)
		FAIL("push didn't block (elapsed %ldms)", elapsed_ms);
	sftp_hpn_workqueue_shutdown(q);
	void *p;
	while (sftp_hpn_workqueue_pop(q, &p) == 0)
		;
	sftp_hpn_workqueue_free(q);
	OK("capacity_blocks_push");
}

/* --- 5. MPMC stress: 4 producers x 4 consumers x 10000 items each --- */
#define MPMC_PRODUCERS 4
#define MPMC_CONSUMERS 4
#define MPMC_PER_PRODUCER 10000

struct mpmc_args {
	struct sftp_hpn_workqueue *q;
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
		if (sftp_hpn_workqueue_push(a->q, (void *)v) != 0)
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
	while (sftp_hpn_workqueue_pop(a->q, &p) == 0) {
		a->popped++;
		a->sum += (intptr_t)p;
	}
	return NULL;
}

static void
test_mpmc_stress(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(64);
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
	sftp_hpn_workqueue_shutdown(q);
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

	sftp_hpn_workqueue_free(q);
	OK("mpmc_stress");
}

/* --- 6. invalid args --- */
static void
test_invalid(void)
{
	if (sftp_hpn_workqueue_new(0) != NULL) FAIL("zero capacity should fail");
	OK("invalid");
}

/* --- 7. non-blocking pushes: trypush adds at the tail, trypush_front
 * at the head, both return 1 when full and -1 after shutdown --- */
static void
test_trypush(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(3);
	void *p = NULL;

	if (sftp_hpn_workqueue_trypush(q, (void *)1) != 0) FAIL("trypush 1");
	if (sftp_hpn_workqueue_trypush(q, (void *)2) != 0) FAIL("trypush 2");
	/* The head is slot 0 here, so this also wraps to the last slot. */
	if (sftp_hpn_workqueue_trypush_front(q, (void *)3) != 0)
		FAIL("trypush_front 3");
	if (sftp_hpn_workqueue_trypush(q, (void *)4) != 1)
		FAIL("trypush on a full queue should return 1");
	if (sftp_hpn_workqueue_trypush_front(q, (void *)5) != 1)
		FAIL("trypush_front on a full queue should return 1");
	if (sftp_hpn_workqueue_depth(q) != 3)
		FAIL("depth %d after pushes onto a full queue",
		    sftp_hpn_workqueue_depth(q));
	/* The item pushed at the head comes out first. */
	intptr_t order[] = { 3, 1, 2 };
	for (int i = 0; i < 3; i++) {
		if (sftp_hpn_workqueue_pop(q, &p) != 0) FAIL("pop %d", i);
		if ((intptr_t)p != order[i])
			FAIL("order: got %td want %td", (intptr_t)p, order[i]);
	}
	sftp_hpn_workqueue_shutdown(q);
	if (sftp_hpn_workqueue_trypush(q, (void *)6) != -1)
		FAIL("trypush after shutdown should return -1");
	if (sftp_hpn_workqueue_trypush_front(q, (void *)7) != -1)
		FAIL("trypush_front after shutdown should return -1");
	sftp_hpn_workqueue_free(q);
	OK("trypush");
}

/* --- 8. trypop never waits and refuses a shut-down queue, while drain
 * still hands out what is left --- */
static void
test_trypop_drain(void)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(4);
	void *p = NULL;

	if (sftp_hpn_workqueue_trypop(q, &p) != -1)
		FAIL("trypop on an empty queue should return -1");
	sftp_hpn_workqueue_push(q, (void *)1);
	sftp_hpn_workqueue_push(q, (void *)2);
	sftp_hpn_workqueue_push(q, (void *)3);
	if (sftp_hpn_workqueue_trypop(q, &p) != 0 || (intptr_t)p != 1)
		FAIL("trypop should return the head item");
	sftp_hpn_workqueue_shutdown(q);
	if (sftp_hpn_workqueue_trypop(q, &p) != -1)
		FAIL("trypop after shutdown should return -1");
	if (sftp_hpn_workqueue_depth(q) != 2)
		FAIL("trypop took an item from a shut-down queue");
	for (intptr_t want = 2; want <= 3; want++) {
		if (sftp_hpn_workqueue_drain(q, &p) != 0)
			FAIL("drain %td after shutdown", want);
		if ((intptr_t)p != want)
			FAIL("drain order: got %td want %td", (intptr_t)p, want);
	}
	if (sftp_hpn_workqueue_drain(q, &p) != -1)
		FAIL("drain on an empty queue should return -1");
	sftp_hpn_workqueue_free(q);
	OK("trypop_drain");
}

/* --- 9. wait_activity ends on a kick, a shutdown or its timeout, but
 * not on a push --- */
enum delayed_op { OP_NONE, OP_PUSH, OP_KICK, OP_SHUTDOWN };

struct delayed_args {
	struct sftp_hpn_workqueue *q;
	enum delayed_op op;
};

static void *
delayed(void *arg)
{
	struct delayed_args *a = arg;

	usleep(30000);
	switch (a->op) {
	case OP_PUSH:
		sftp_hpn_workqueue_push(a->q, (void *)1);
		break;
	case OP_KICK:
		sftp_hpn_workqueue_kick(a->q);
		break;
	case OP_SHUTDOWN:
		sftp_hpn_workqueue_shutdown(a->q);
		break;
	case OP_NONE:
		break;
	}
	return NULL;
}

/* Run op on another thread 30ms in, wait up to timeout_ms on a fresh
 * queue, and return how long the wait took in milliseconds. */
static long
timed_wait(enum delayed_op op, int timeout_ms)
{
	struct sftp_hpn_workqueue *q = sftp_hpn_workqueue_new(4);
	struct delayed_args a = { .q = q, .op = op };
	struct timespec t0, t1;
	pthread_t t;
	void *p;

	pthread_create(&t, NULL, delayed, &a);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	sftp_hpn_workqueue_wait_activity(q, timeout_ms);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	pthread_join(t, NULL);
	sftp_hpn_workqueue_shutdown(q);
	while (sftp_hpn_workqueue_drain(q, &p) == 0)
		;
	sftp_hpn_workqueue_free(q);
	return (t1.tv_sec - t0.tv_sec) * 1000 +
	    (t1.tv_nsec - t0.tv_nsec) / 1000000;
}

static void
test_wait_activity(void)
{
	long ms;

	/* The bounds are loose so a loaded machine does not fail them. */
	if ((ms = timed_wait(OP_NONE, 50)) < 40)
		FAIL("wait returned before its timeout (%ldms)", ms);
	if ((ms = timed_wait(OP_PUSH, 300)) < 250)
		FAIL("a push ended the wait (%ldms)", ms);
	if ((ms = timed_wait(OP_KICK, 5000)) >= 2500)
		FAIL("a kick did not end the wait (%ldms)", ms);
	if ((ms = timed_wait(OP_SHUTDOWN, 5000)) >= 2500)
		FAIL("a shutdown did not end the wait (%ldms)", ms);
	OK("wait_activity");
}

int
main(void)
{
	test_basic_fifo();
	test_shutdown_drains();
	test_shutdown_wakes_waiters();
	test_capacity_blocks_push();
	test_mpmc_stress();
	test_invalid();
	test_trypush();
	test_trypop_drain();
	test_wait_activity();
	printf("\nall workqueue tests passed\n");
	return 0;
}
