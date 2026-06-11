/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Concurrency test for TODO #42: the lock-free bounded MPSC queue
 * (nats_mpsc) that replaces the single gen_lock_t serializing every
 * worker's ack-IPC / RPC-IPC enqueue.
 *
 * The headline test is a message-conservation stress test: P producer
 * threads each enqueue M uniquely-tagged elements concurrently while one
 * consumer thread drains; at the end EVERY (producer, seq) element must
 * have been received EXACTLY once, with its payload canary intact -- no
 * loss, no duplication, no torn write.  Built with both AddressSanitizer
 * and (via the suite's check-tsan target) ThreadSanitizer, so a data race
 * or memory error in the lock-free path trips the sanitizer.
 *
 * Plus single-threaded FIFO / full / empty / drop-accounting checks.
 *
 * Build:
 *   gcc -g -O0 -DTEST_SHIM -I. -I../../.. -fsanitize=address -pthread \
 *       -o test_mpsc test_mpsc.c test_shim.c ../nats_mpsc.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#include "../nats_mpsc.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ---- payload: self-describing so torn writes are detectable ---------- */

typedef struct {
	uint32_t producer;
	uint32_t seq;
	uint64_t canary;   /* must equal mix(producer, seq) */
} elem_t;

static uint64_t mix(uint32_t p, uint32_t s)
{
	uint64_t x = ((uint64_t)p << 32) ^ s;
	x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
	x ^= x >> 33;
	return x;
}

/* ---- single-threaded behaviour -------------------------------------- */

static void test_single_threaded(void)
{
	nats_mpsc_t *q = nats_mpsc_create(4, sizeof(elem_t));
	elem_t e, out;
	int i;

	ASSERT(q != NULL, "create a cap-4 queue");
	ASSERT(nats_mpsc_capacity(q) == 4, "capacity reported");
	ASSERT(nats_mpsc_dequeue(q, &out) == 0, "empty queue dequeues nothing");
	ASSERT(nats_mpsc_depth(q) == 0, "empty depth is 0");

	/* fill to capacity */
	for (i = 0; i < 4; i++) {
		e.producer = 7; e.seq = (uint32_t)i; e.canary = mix(7, i);
		ASSERT(nats_mpsc_enqueue(q, &e) == 0, "enqueue up to capacity");
	}
	ASSERT(nats_mpsc_depth(q) == 4, "depth equals capacity when full");

	/* one more must be dropped */
	e.producer = 7; e.seq = 99; e.canary = mix(7, 99);
	ASSERT(nats_mpsc_enqueue(q, &e) == -1, "enqueue past capacity drops");
	ASSERT(nats_mpsc_dropped_total(q) == 1, "drop counted");

	/* FIFO order out */
	for (i = 0; i < 4; i++) {
		ASSERT(nats_mpsc_dequeue(q, &out) == 1, "dequeue a buffered element");
		ASSERT(out.producer == 7 && out.seq == (uint32_t)i &&
			out.canary == mix(7, i), "FIFO order + intact payload");
	}
	ASSERT(nats_mpsc_dequeue(q, &out) == 0, "drained queue is empty again");

	/* wrap-around: reuse the freed cells many times */
	{
		int ok = 1;
		for (i = 0; i < 1000; i++) {
			e.producer = 1; e.seq = (uint32_t)i; e.canary = mix(1, i);
			if (nats_mpsc_enqueue(q, &e) != 0) { ok = 0; break; }
			if (nats_mpsc_dequeue(q, &out) != 1) { ok = 0; break; }
			if (out.seq != (uint32_t)i || out.canary != mix(1, i)) { ok = 0; break; }
		}
		ASSERT(ok, "1000x enqueue/dequeue wrap-around preserves payload");
	}

	ASSERT(nats_mpsc_enqueued_total(q) == 4 + 1000, "enqueued_total accurate");
	ASSERT(nats_mpsc_drained_total(q) == 4 + 1000, "drained_total accurate");

	nats_mpsc_destroy(q);
}

/* ---- concurrent conservation stress test ---------------------------- */

#define NPROD     4u
#define PER_PROD  100000u
#define CAP       256u   /* deliberately small vs. the offered load */

static nats_mpsc_t *g_q;

static void *producer_main(void *arg)
{
	uint32_t p = (uint32_t)(uintptr_t)arg;
	uint32_t s;
	for (s = 0; s < PER_PROD; s++) {
		elem_t e;
		e.producer = p; e.seq = s; e.canary = mix(p, s);
		/* retry on full so the conservation count is exact (no drops) */
		while (nats_mpsc_enqueue(g_q, &e) != 0)
			sched_yield();
	}
	return NULL;
}

static void test_concurrent(void)
{
	static uint8_t seen[NPROD][PER_PROD];   /* received-count per element */
	pthread_t prod[NPROD];
	uint64_t total = (uint64_t)NPROD * PER_PROD;
	uint64_t got = 0;
	int dup = 0, bad = 0, i;

	memset(seen, 0, sizeof(seen));
	g_q = nats_mpsc_create(CAP, sizeof(elem_t));
	ASSERT(g_q != NULL, "create the stress queue");

	for (i = 0; i < (int)NPROD; i++)
		pthread_create(&prod[i], NULL, producer_main,
			(void *)(uintptr_t)i);

	/* single consumer: this thread */
	while (got < total) {
		elem_t out;
		if (nats_mpsc_dequeue(g_q, &out) == 1) {
			if (out.producer >= NPROD || out.seq >= PER_PROD) {
				bad++;
			} else if (out.canary != mix(out.producer, out.seq)) {
				bad++;   /* torn / corrupted payload */
			} else if (seen[out.producer][out.seq]++) {
				dup++;   /* duplicate delivery */
			}
			got++;
		} else {
			sched_yield();
		}
	}

	for (i = 0; i < (int)NPROD; i++)
		pthread_join(prod[i], NULL);

	ASSERT(got == total, "consumed exactly NPROD*PER_PROD elements");
	ASSERT(dup == 0, "no element delivered more than once");
	ASSERT(bad == 0, "no corrupted/torn payload");

	/* completeness: every element present exactly once */
	{
		uint64_t missing = 0;
		uint32_t p, s;
		for (p = 0; p < NPROD; p++)
			for (s = 0; s < PER_PROD; s++)
				if (seen[p][s] != 1) missing++;
		ASSERT(missing == 0, "every produced element received exactly once");
	}

	ASSERT(nats_mpsc_enqueued_total(g_q) == total,
		"enqueued_total matches offered load");
	ASSERT(nats_mpsc_drained_total(g_q) == total,
		"drained_total matches consumed load");

	nats_mpsc_destroy(g_q);
}

int main(void)
{
	test_single_threaded();
	test_concurrent();

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
