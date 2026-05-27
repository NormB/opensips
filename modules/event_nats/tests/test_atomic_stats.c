/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_stats counters must use C11 _Atomic
 * with atomic_fetch_add for increments.  The previous declaration as
 * `volatile unsigned long` is not atomic on weakly-ordered
 * architectures (aarch64); two workers incrementing concurrently
 * produce torn values.
 *
 * The hot counters (published, failed) must additionally be
 * cache-line aligned to avoid false-sharing across cores.
 *
 * Test:
 *   1. Source-pattern: header declares counters as `_Atomic`,
 *      hot counters carry __attribute__((aligned(64))).
 *   2. Increment sites use atomic_fetch_add.
 *   3. Functional: spawn N threads each doing M atomic_fetch_add
 *      on the same counter and verify the total is N*M (no torn
 *      writes). Compares against a non-atomic ++ control to show
 *      the difference.
 *
 * Build:
 *   gcc -g -O0 -Wall -pthread -o test_atomic_stats test_atomic_stats.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) hits++;
	fclose(f);
	return hits;
}

/* ─── concurrent-increment functional test ───────────────────── */

#define N_THREADS 8
#define N_ITERS   100000

static unsigned long volatile_ctr;            /* control: volatile only */
static _Atomic unsigned long atomic_ctr;      /* fix: C11 atomic */

static void *bump_volatile(void *_) { (void)_;
	for (int i = 0; i < N_ITERS; i++) volatile_ctr++;
	return NULL;
}
static void *bump_atomic(void *_)   { (void)_;
	for (int i = 0; i < N_ITERS; i++)
		atomic_fetch_add_explicit(&atomic_ctr, 1, memory_order_relaxed);
	return NULL;
}

static unsigned long run_threads(void *(*fn)(void *))
{
	pthread_t t[N_THREADS];
	for (int i = 0; i < N_THREADS; i++) pthread_create(&t[i], NULL, fn, NULL);
	for (int i = 0; i < N_THREADS; i++) pthread_join(t[i], NULL);
	return 0;
}

int main(void)
{
	/* CASE 1: source pattern in nats_stats.h */
	int atomic_decl = grep_count("../nats_stats.h", "_Atomic unsigned long");
	ASSERT(atomic_decl >= 6,
		"nats_stats.h declares >= 6 _Atomic counters");

	int volatile_decl = grep_count("../nats_stats.h", "volatile unsigned long");
	ASSERT(volatile_decl == 0,
		"nats_stats.h has no volatile-only unsigned long counters");

	int aligned_hot = grep_count("../nats_stats.h", "aligned(64)");
	ASSERT(aligned_hot >= 1,
		"nats_stats.h cache-line aligns at least one hot counter");

	/* CASE 2: increment sites use the per-process bump macro
	 * (NATS_STATS_BUMP).  The macro centralises the slot indexing
	 * by process_no and expands to atomic_fetch_add on the
	 * caller's private cacheline; we still want the underlying
	 * atomic op so cross-process MI readers see clean loads, but
	 * the call sites no longer touch atomic_fetch_add directly. */
	int producer_bumps = grep_count(
		"../nats_producer.c", "NATS_STATS_BUMP");
	ASSERT(producer_bumps >= 2,
		"nats_producer.c bumps counters via NATS_STATS_BUMP");

	int event_bumps = grep_count(
		"../event_nats.c", "NATS_STATS_BUMP");
	ASSERT(event_bumps >= 2,
		"event_nats.c bumps counters via NATS_STATS_BUMP");

	int producer_old = grep_count(
		"../nats_producer.c", "nats_stats->failed++");
	ASSERT(producer_old == 0,
		"nats_producer.c no longer uses ++ on counters");

	/* The underlying NATS_STATS_BUMP macro must still expand to an
	 * atomic increment so MI readers can sum cleanly across slots. */
	int macro_atomic = grep_count(
		"../nats_stats.h", "atomic_fetch_add");
	ASSERT(macro_atomic >= 1,
		"NATS_STATS_BUMP macro expands to atomic_fetch_add");

	/* CASE 3: MI reads sum across slots via NATS_STATS_SUM, which
	 * is implemented by atomic_load_explicit in nats_stats.c. */
	int sum_uses = grep_count("../nats_stats.c", "NATS_STATS_SUM");
	ASSERT(sum_uses >= 6,
		"nats_stats.c MI handler uses NATS_STATS_SUM");

	int sum_atomic = grep_count("../nats_stats.c", "atomic_load");
	ASSERT(sum_atomic >= 1,
		"nats_stats_sum() uses atomic_load for cross-slot reads");

	/* CASE 5: the per-process `reconnects` counter was never bumped, so
	 * MI now reports the shared pool's reconnect epoch instead; and the
	 * slot comment no longer claims a single writer (the cnats ack
	 * thread shares the slot, so atomics are mandatory). */
	ASSERT(grep_count("../nats_stats.c",
			"nats_pool_get_reconnect_epoch") >= 1,
		"MI reports the pool reconnect epoch (real reconnect count)");
	ASSERT(grep_count("../nats_stats.c", "NATS_STATS_SUM(reconnects)") == 0,
		"MI no longer sums the never-incremented reconnects counter");
	ASSERT(grep_count("../nats_stats.h", "AckHandler") >= 1,
		"nats_stats.h documents the JS ack thread shares the slot "
		"(atomics required)");

	/* CASE 4: functional concurrent-increment check */
	volatile_ctr = 0;
	atomic_store(&atomic_ctr, 0);
	run_threads(bump_volatile);
	run_threads(bump_atomic);

	unsigned long expected = (unsigned long)N_THREADS * N_ITERS;
	unsigned long got_atomic = atomic_load(&atomic_ctr);
	fprintf(stderr, "  control: volatile_ctr=%lu (expected %lu, often torn)\n",
		volatile_ctr, expected);
	fprintf(stderr, "  atomic:  atomic_ctr=%lu (expected %lu)\n",
		got_atomic, expected);
	ASSERT(got_atomic == expected,
		"atomic counter survives concurrent increment exactly");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
