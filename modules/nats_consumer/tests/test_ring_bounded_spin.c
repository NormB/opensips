/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * test_ring_bounded_spin.c -- regression test for the unbounded pop spin
 * in nats_ring_pop().
 *
 * Bug: the single-consumer pop spins on `ready_gen != tail` with
 * cpu_relax().  If the single producer (the consumer process) dies or is
 * preempted for a long time AFTER bumping head (reserving a slot) but
 * BEFORE the release-store that publishes ready_gen, the ring looks
 * non-empty (head > tail) yet the slot at `tail & mask` never becomes
 * ready.  The popper then spins forever, pinning a CPU and never letting
 * the worker re-arm its wait.
 *
 * Fix: nats_ring_pop now caps the number of times it will spin waiting
 * for a single un-published slot (NATS_RING_POP_SPIN_MAX) and bails out
 * to the "empty" (-1) return instead of looping indefinitely.  The fast
 * path (slot already published) is unchanged, and a tail that advances
 * resets the counter so legitimate concurrent progress is never
 * penalised.
 *
 * This test reaches into the ring internals (by #including the .c so the
 * otherwise-opaque struct is visible) to deterministically construct the
 * "producer reserved a slot then died" state: head=1, tail=0, and slot 0
 * left with its pre-seed sentinel ready_gen (UINT64_MAX != 0).  With the
 * old code nats_ring_pop would never return; a SIGALRM watchdog turns
 * that hang into a test failure.  With the fix it returns -1 promptly.
 *
 * Build (self-contained, links test_shim.c for the allocator):
 *   cc -DTEST_SHIM -I. -I../../.. -o test_ring_bounded_spin \
 *      test_ring_bounded_spin.c test_shim.c -lpthread
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

/* Pull the implementation in directly so we can touch the opaque
 * struct nats_ring and forge a stalled-producer state. */
#include "../nats_ring.c"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* SIGALRM watchdog: if pop hangs (old, unbounded behaviour) the alarm
 * longjmps us out and we record a failure instead of wedging the suite. */
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_timed_out;

static void on_alarm(int sig)
{
	(void)sig;
	g_timed_out = 1;
	siglongjmp(g_jmp, 1);
}

/* ── case 1: stalled producer must not spin forever ──────────────── */

static void test_stalled_producer_bails(void)
{
	nats_ring_t     *r = nats_ring_create(4);
	nats_ring_slot_t out;
	int rc = 0;

	ASSERT(r != NULL, "ring created");
	if (!r) return;

	/*
	 * Forge "producer reserved slot 0 then died": advance head past
	 * tail WITHOUT publishing slot 0.  After nats_ring_create the
	 * slots are pre-seeded with ready_gen = UINT64_MAX, so
	 * slots[0].ready_gen (UINT64_MAX) != tail (0): the exact transient
	 * the pop loop waits on -- except here it never resolves.
	 */
	atomic_store_explicit(&r->head, (uint64_t)1, memory_order_relaxed);
	atomic_store_explicit(&r->tail, (uint64_t)0, memory_order_relaxed);
	ASSERT(r->slots[0].ready_gen != 0,
		"slot 0 is reserved-but-unpublished (ready_gen != tail)");
	ASSERT(nats_ring_depth(r) == 1, "ring looks non-empty (head > tail)");

	signal(SIGALRM, on_alarm);
	g_timed_out = 0;
	if (sigsetjmp(g_jmp, 1) == 0) {
		alarm(3);                 /* generous: the fix returns in <1ms */
		rc = nats_ring_pop(r, &out);
		alarm(0);
	}

	ASSERT(!g_timed_out,
		"nats_ring_pop returns within the watchdog window "
		"(old code would spin forever on the un-published slot)");
	ASSERT(g_timed_out || rc == -1,
		"stalled-producer pop bails out reporting empty (-1)");

	nats_ring_destroy(r);
}

/* ── case 2: fast path unchanged -- a published slot still pops ───── */

static void test_published_slot_still_pops(void)
{
	nats_ring_t     *r = nats_ring_create(4);
	nats_ring_slot_t out;
	int rc;

	ASSERT(r != NULL, "ring created");
	if (!r) return;

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
			.ack_token = 0x1234ULL,
		});
	ASSERT(rc == 0, "push of a real message succeeds");

	signal(SIGALRM, on_alarm);
	g_timed_out = 0;
	if (sigsetjmp(g_jmp, 1) == 0) {
		alarm(3);
		rc = nats_ring_pop(r, &out);
		alarm(0);
	}
	ASSERT(!g_timed_out, "published-slot pop returns promptly");
	ASSERT(!g_timed_out && rc == 0, "published slot pops successfully (fast path intact)");
	ASSERT(!g_timed_out && out.ack_token == 0x1234ULL, "popped the right slot");

	/* And the now-empty ring pops -1 immediately (no spin). */
	g_timed_out = 0;
	if (sigsetjmp(g_jmp, 1) == 0) {
		alarm(3);
		rc = nats_ring_pop(r, &out);
		alarm(0);
	}
	ASSERT(!g_timed_out && rc == -1, "empty ring pops -1 with no spin");

	nats_ring_destroy(r);
}

/* ── case 3: the source actually carries the bound ───────────────── */

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

static void test_source_has_bound(void)
{
	const char *src = "../nats_ring.c";
	ASSERT(file_contains(src, "NATS_RING_POP_SPIN_MAX"),
		"nats_ring.c defines a bounded pop spin cap");
}

int main(void)
{
	test_stalled_producer_bails();
	test_published_slot_still_pops();
	test_source_has_bound();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
