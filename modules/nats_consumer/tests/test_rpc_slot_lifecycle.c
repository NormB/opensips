/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Depth/coverage test for the async-RPC slot allocator (nats_rpc_slot.c).
 * The other slot tests exercise the generation/reply protocol; this drives the
 * full allocator lifecycle and its edge/error paths, which were previously
 * uncovered:
 *   - init count clamp (0 -> 1), double-init, total_count
 *   - claim -> CLAIMED, publish -> INFLIGHT, inflight_count accounting
 *   - pool exhaustion: claim on a full pool returns NULL
 *   - publish on a non-CLAIMED slot returns -1
 *   - lookup by idx (hit) and out-of-range / FREE (NULL)
 *   - abandon (INFLIGHT -> ABANDONED) and free (-> FREE), then reuse
 *
 * Built with a 1-slot pool (-DNATS_RPC_SLOT_COUNT=1) so exhaustion is one claim
 * away; the count is also set via the runtime var to exercise the clamp.
 *
 * Build (Makefile): test_rpc_slot_lifecycle.c + shim + nats_rpc_slot.c,
 *                   -DNATS_RPC_SLOT_COUNT=1
 */

#include <stdio.h>
#include <stdatomic.h>
#include "../nats_rpc_slot.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);            } \
} while (0)

static int state_of(nats_rpc_slot_t *s)
{
	return atomic_load_explicit(&s->state, memory_order_acquire);
}

int main(void)
{
	nats_rpc_slot_t *a, *b;

	/* init clamps a non-positive count up to 1. */
	nats_rpc_slot_count = 0;
	CHECK(nats_rpc_slot_init() == 0, "init clamps count 0 -> ok");
	CHECK(nats_rpc_slot_total_count() == 1, "total_count == 1 (clamped)");

	/* double init is a no-op success (already initialised). */
	CHECK(nats_rpc_slot_init() == 0, "double init returns 0 (already init)");

	CHECK(nats_rpc_slot_inflight_count() == 0, "inflight starts at 0");

	/* claim -> CLAIMED. */
	a = nats_rpc_slot_claim();
	CHECK(a != NULL, "claim returns a slot");
	CHECK(a && state_of(a) == NATS_RPC_SLOT_CLAIMED, "claimed slot is CLAIMED");
	CHECK(nats_rpc_slot_inflight_count() == 1, "inflight == 1 after claim");

	/* pool is now full (1 slot) -> next claim returns NULL. */
	b = nats_rpc_slot_claim();
	CHECK(b == NULL, "claim on a full pool returns NULL");

	/* lookup by idx: hit + out-of-range. */
	CHECK(nats_rpc_slot_lookup(a->slot_idx) == a, "lookup(idx) finds the slot");
	CHECK(nats_rpc_slot_lookup(9999) == NULL, "lookup(out-of-range) is NULL");

	/* publish CLAIMED -> INFLIGHT; a second publish (not CLAIMED) fails. */
	CHECK(nats_rpc_slot_publish(a) == 0, "publish CLAIMED -> INFLIGHT");
	CHECK(a && state_of(a) == NATS_RPC_SLOT_INFLIGHT, "state is INFLIGHT");
	CHECK(nats_rpc_slot_publish(a) == -1, "publish on non-CLAIMED slot fails");

	/* abandon INFLIGHT -> ABANDONED. */
	CHECK(nats_rpc_slot_abandon(a) == NATS_RPC_SLOT_ABANDONED,
		"abandon INFLIGHT -> ABANDONED");

	/* free returns the slot to the pool. */
	nats_rpc_slot_free(a,
		atomic_load_explicit(&(a)->generation, memory_order_relaxed));
	CHECK(nats_rpc_slot_inflight_count() == 0, "inflight == 0 after free");
	CHECK(nats_rpc_slot_lookup(a->slot_idx) == NULL,
		"lookup on a freed (FREE) slot is NULL");

	/* the slot is reusable after free. */
	b = nats_rpc_slot_claim();
	CHECK(b == a, "the freed slot is re-claimed (reuse)");
	nats_rpc_slot_free(b,
		atomic_load_explicit(&(b)->generation, memory_order_relaxed));

	nats_rpc_slot_destroy();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
