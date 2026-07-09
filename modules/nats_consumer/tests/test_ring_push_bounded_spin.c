/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the unbounded PRODUCER spin in nats_ring_push().
 *
 * Bug: before reusing a slot, the producer waits for the previous
 * consumer to have published consumed_gen == (head - capacity), spinning
 * with cpu_relax().  If the consumer (a SIP worker) dies AFTER advancing
 * tail but BEFORE the consumed_gen release-store, that slot's consumed_gen
 * never reaches the expected value while the ring still looks non-full --
 * so the producer (the consumer process) spins forever, pinning a CPU at
 * 100% and starving ack/RPC IPC drains (the pop side already had a bounded
 * spin; the push side did not).
 *
 * Fix: nats_ring_push caps how long it will spin on a single un-consumed
 * slot (NATS_RING_PUSH_SPIN_MAX) and bails out with -1 ("full") so the
 * caller backs off instead of livelocking.  A merely-preempted consumer
 * that resumes within the cap is still observed on the fast path.
 *
 * This reaches into the ring internals (by #including the .c) to forge the
 * "consumer reserved+advanced tail then died" state and uses a SIGALRM
 * watchdog to turn a hang into a failure.
 *
 * Build:
 *   cc -DTEST_SHIM -I. -I../../.. -o test_ring_push_bounded_spin \
 *      test_ring_push_bounded_spin.c test_shim.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

#include "test_shim.h"
#include "../nats_ring.c"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_timed_out;

static void on_alarm(int sig)
{
	(void)sig;
	g_timed_out = 1;
	siglongjmp(g_jmp, 1);
}

/* ── case 1: stalled consumer must not spin the producer forever ─── */

static void test_stalled_consumer_bails(void)
{
	nats_ring_t *r = nats_ring_create(4);
	int rc = 0;

	ASSERT(r != NULL, "ring created");
	if (!r) return;

	/*
	 * Forge "consumer popped slot 0 (gen 0) then died before the
	 * consumed_gen store, and advanced tail to 4": head=tail=capacity so
	 * the ring is NOT full (depth 0), but the next push targets slot 0
	 * and requires consumed_gen[0] == (head - capacity) == 0.  After
	 * create, consumed_gen is the UINT64_MAX sentinel, which never equals
	 * 0 -- exactly the transient the push loop waits on, except here it
	 * never resolves.
	 */
	atomic_store_explicit(&r->head, (uint64_t)4, memory_order_relaxed);
	atomic_store_explicit(&r->tail, (uint64_t)4, memory_order_relaxed);
	ASSERT(nats_ring_depth(r) == 0, "ring looks non-full (head == tail)");
	ASSERT(r->slots[0].consumed_gen != 0,
		"slot 0 is reserved-but-unconsumed (consumed_gen != head-capacity)");

	signal(SIGALRM, on_alarm);
	g_timed_out = 0;
	if (sigsetjmp(g_jmp, 1) == 0) {
		alarm(3);                  /* generous: the fix returns in <1ms */
		rc = nats_ring_push(r, &(nats_ring_msg_t){
				.subject = "s",
				.subject_len = 1,
				.data = "x",
				.data_len = 1,
				.stream_seq = 0,
				.consumer_seq = 0,
				.delivered = 0,
				.pending = 0,
				.timestamp_ns = 0,
				.ack_token = 7,
			});
		alarm(0);
	}

	ASSERT(!g_timed_out,
		"nats_ring_push returns within the watchdog window "
		"(old code would spin forever on the un-consumed slot)");
	ASSERT(g_timed_out || rc == -1,
		"stalled-consumer push bails out reporting full (-1)");

	nats_ring_destroy(r);
}

/* ── case 2: fast path unchanged -- a free slot still accepts a push ── */

static void test_free_slot_still_pushes(void)
{
	nats_ring_t      *r = nats_ring_create(4);
	nats_ring_slot_t  out;
	volatile int rc;	/* survives the SIGALRM longjmp (-Wclobbered) */

	ASSERT(r != NULL, "ring created");
	if (!r) return;

	signal(SIGALRM, on_alarm);
	g_timed_out = 0;
	if (sigsetjmp(g_jmp, 1) == 0) {
		alarm(3);
		rc = nats_ring_push(r, &(nats_ring_msg_t){
				.subject = "subj",
				.subject_len = 4,
				.data = "body",
				.data_len = 4,
				.stream_seq = 1,
				.consumer_seq = 2,
				.delivered = 3,
				.pending = 4,
				.timestamp_ns = 5,
				.ack_token = 0x99ULL,
			});
		alarm(0);
	}
	ASSERT(!g_timed_out && rc == 0, "push to a free slot succeeds (fast path)");

	rc = nats_ring_pop(r, &out);
	ASSERT(rc == 0 && out.ack_token == 0x99ULL, "pushed message pops back");

	nats_ring_destroy(r);
}

/* ── case 3: the source carries both bounds ──────────────────────── */

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[1024];
	int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

static void test_source_has_bounds(void)
{
	const char *src = "../nats_ring.c";
	ASSERT(file_contains(src, "NATS_RING_PUSH_SPIN_MAX"),
		"nats_ring.c defines a bounded push spin cap");
}

int main(void)
{
	test_stalled_consumer_bails();
	test_free_slot_still_pushes();
	test_source_has_bounds();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
