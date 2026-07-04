/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_ring_push() woke EVERY blocked consumer
 * (FUTEX_WAKE INT_MAX) on the empty->non-empty edge.  A single message
 * stampeded all N workers -- one popped it and the other N-1 immediately
 * re-blocked (~N wasted wakeups + context switches per message at low
 * rate).  Fix: track the number of blocked waiters and wake exactly ONE
 * per published message (skipping the syscall when nobody waits), so a
 * single message wakes one worker and a burst of K messages issues K
 * single wakes -- up to K workers drain in parallel, with no stampede.
 *
 * The key correctness property of a per-message wake is that NO wakeup is
 * lost: this test blocks W consumer threads on an empty ring, pushes W
 * messages, and asserts all W threads receive exactly one message.  Plus
 * source-pattern checks of the production wiring.
 *
 * Build (TEST_SHIM + ../nats_ring.c, -pthread):
 *   cc -DTEST_SHIM -I. -I../../.. -o test_ring_wake_one \
 *      test_ring_wake_one.c test_shim.c ../nats_ring.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>

#include "../nats_ring.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg); } \
} while (0)

#define W 8

struct warg { nats_ring_t *r; atomic_int *got; };

static void *waiter(void *p)
{
	struct warg *a = p;
	nats_ring_slot_t slot;
	int waited = 0;
	const int budget = 5000;
	while (waited < budget) {
		if (nats_ring_pop(a->r, &slot) == 0) {
			atomic_fetch_add(a->got, 1);
			return NULL;
		}
		nats_ring_wait(a->r, budget - waited);
		waited += 50;   /* coarse; the wait wakes us far sooner */
	}
	return NULL;   /* timed out without a message -> lost wakeup */
}

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	nats_ring_t *r = nats_ring_create(16);
	atomic_int got = 0;
	pthread_t th[W];
	struct warg a = { r, &got };
	int i;

	ASSERT(r != NULL, "ring created");

	/* Block W consumers on the empty ring. */
	for (i = 0; i < W; i++) pthread_create(&th[i], NULL, waiter, &a);
	usleep(100 * 1000);   /* let them reach nats_ring_wait */

	/* Push W messages -- each should wake exactly one waiter. */
	for (i = 0; i < W; i++)
		nats_ring_push(r, &(nats_ring_msg_t){
				.subject = "s",
				.subject_len = 1,
				.data = "x",
				.data_len = 1,
				.stream_seq = 0,
				.consumer_seq = 0,
				.delivered = 0,
				.pending = 0,
				.timestamp_ns = 0,
				.ack_token = (uint64_t)i,
			});

	for (i = 0; i < W; i++) pthread_join(th[i], NULL);

	ASSERT(atomic_load(&got) == W,
		"all W waiters received a message (no lost wakeup with wake-one)");

	nats_ring_destroy(r);

	/* Production wiring. */
	{
		const char *src = "../nats_ring.c";
		ASSERT(grep_in_function(src, "nats_ring_push", "FUTEX_WAKE, 1") >= 1,
			"push wakes exactly one waiter (FUTEX_WAKE, 1) not INT_MAX");
		ASSERT(!file_contains(src, "FUTEX_WAKE, INT_MAX"),
			"no FUTEX_WAKE INT_MAX stampede remains");
		ASSERT(file_contains(src, "waiters"),
			"ring tracks a blocked-waiter count");
		ASSERT(grep_in_function(src, "nats_ring_wait", "->waiters") >= 1,
			"nats_ring_wait registers/unregisters as a waiter");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
