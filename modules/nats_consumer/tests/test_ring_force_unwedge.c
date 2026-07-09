/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 *
 * [P2.2] Ring force-unwedge.  A worker that dies between its tail-CAS
 * and the consumed_gen release orphans one slot; once the producer
 * wraps to that slot it bounded-spins, bails "full", and -- before
 * this change -- the handle was dead forever (every future push waits
 * on a consumed_gen store that will never come).
 *
 * The producer (the consumer process -- single producer per ring) now
 * tracks how long the SAME generation has kept push blocked; past
 * NATS_RING_FORCE_UNWEDGE_US it force-stores the missing consumed_gen
 * (CAS from the observed stale value), WARNs, counts it, and delivery
 * resumes.  Un-popped messages are un-acked, so JetStream redelivers.
 *
 * Two guards make the force safe against a SLOW (not dead) worker:
 *   - the pop release is now a CAS from the deterministic prior value
 *     (t - capacity, or the UINT64_MAX seed for the first lap), so a
 *     resurrected worker's late release cannot REGRESS a consumed_gen
 *     the force (and later laps) moved past,
 *   - pop re-checks ready_gen == t after copying the payload
 *     (_ring_pop_still_owned): if the slot was recycled under a
 *     stalled copy, the torn payload is dropped, never delivered.
 *
 * Drives the PRODUCTION TU (#include "../nats_ring.c") with the forge
 * pattern of test_ring_push_bounded_spin.c; the unwedge threshold is
 * compiled down to 50ms so the test sleeps through it.
 *
 * Build: -DNATS_RING_FORCE_UNWEDGE_US=50000 (see Makefile).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>

#include "test_shim.h"
#include "../nats_ring.c"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int push_one(nats_ring_t *r, const char *tag)
{
	return nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = tag,
			.data_len = (uint32_t)strlen(tag),
			.stream_seq = 1,
			.consumer_seq = 1,
			.delivered = 1,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 0x42ULL,
		});
}

int main(void)
{
	nats_ring_t *r = nats_ring_create(4);
	nats_ring_slot_t out;

	ASSERT(r != NULL, "ring created (capacity 4)");
	if (!r) return 1;

	/*
	 * Forge "worker claimed slot 0 (gen 0) then died before the
	 * consumed_gen release, everything else drained": head = tail =
	 * capacity, consumed_gen[0] left at the UINT64_MAX seed.  The next
	 * push targets slot 0 and waits for consumed_gen[0] == 0 forever.
	 */
	atomic_store_explicit(&r->head, 4, memory_order_relaxed);
	atomic_store_explicit(&r->tail, 4, memory_order_relaxed);
	/* slots 1-3 were consumed cleanly; ONLY slot 0's release is missing */
	__atomic_store_n(&r->slots[1].consumed_gen, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&r->slots[2].consumed_gen, 2, __ATOMIC_RELEASE);
	__atomic_store_n(&r->slots[3].consumed_gen, 3, __ATOMIC_RELEASE);

	ASSERT(push_one(r, "wedged") == -1,
		"first push on the orphaned slot bails full (stall recorded)");
	ASSERT(nats_ring_forced_unwedges(r) == 0,
		"no force before the threshold");

	usleep(60 * 1000);   /* threshold is 50ms in this build */

	ASSERT(push_one(r, "recovered") == 0,
		"push succeeds after the threshold (slot force-unwedged)");
	ASSERT(nats_ring_forced_unwedges(r) == 1,
		"forced-unwedge counter bumped");

	/* The recovered message is deliverable and intact. */
	memset(&out, 0, sizeof(out));
	ASSERT(nats_ring_pop(r, &out) == 0, "republished message pops");
	ASSERT(out.data_len == 9 && memcmp(out.data, "recovered", 9) == 0,
		"payload intact after the unwedge");
	ASSERT(__atomic_load_n(&r->slots[0].consumed_gen, __ATOMIC_ACQUIRE)
			== 4,
		"pop released consumed_gen at its own generation (4)");

	/*
	 * The dead worker resurrects and issues its LATE release for
	 * generation 0.  Its pop would compute prior == UINT64_MAX (first
	 * lap) and CAS(UINT64_MAX -> 0) -- which must FAIL against the
	 * post-force value, never regress it.
	 */
	{
		uint64_t prev = UINT64_MAX;
		int won = __atomic_compare_exchange_n(
			&r->slots[0].consumed_gen, &prev, 0, 0,
			__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
		ASSERT(!won &&
		       __atomic_load_n(&r->slots[0].consumed_gen,
				__ATOMIC_ACQUIRE) == 4,
			"late release from the dead claim cannot regress "
			"consumed_gen");
	}

	/* Torn-copy guard: ownership check is ready_gen == t, nothing else. */
	{
		nats_ring_slot_t *s0 = &r->slots[0];
		uint64_t saved = __atomic_load_n(&s0->ready_gen,
			__ATOMIC_ACQUIRE);
		__atomic_store_n(&s0->ready_gen, 7, __ATOMIC_RELEASE);
		ASSERT(_ring_pop_still_owned(s0, 7) == 1,
			"still-owned: ready_gen matches the claimed generation");
		ASSERT(_ring_pop_still_owned(s0, 4) == 0,
			"recycled under a stalled copy: ownership check fails "
			"(torn payload dropped)");
		__atomic_store_n(&s0->ready_gen, saved, __ATOMIC_RELEASE);
	}

	/* Ring keeps working normally after the whole episode. */
	ASSERT(push_one(r, "steady") == 0 &&
	       nats_ring_pop(r, &out) == 0 &&
	       out.data_len == 6 && memcmp(out.data, "steady", 6) == 0,
		"ring healthy after recovery (push/pop round-trip)");

	nats_ring_destroy(r);
	printf("\n=== %s (fails=%d) ===\n",
		g_fails ? "FAILURES" : "ALL PASS", g_fails);
	return g_fails ? 1 : 0;
}
