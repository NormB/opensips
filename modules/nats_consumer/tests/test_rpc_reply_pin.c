/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the async-RPC reply handler (on_inbox_reply, nats_rpc_consumer.c)
 * delivered a reply in TWO non-atomic steps: it wrote reply_* and CAS'd the
 * slot INFLIGHT -> DELIVERED, THEN (separately) re-checked the generation and
 * rolled back to ABANDONED on a mismatch.  Between the DELIVERED CAS and the
 * rollback the slot is momentarily DELIVERED with another request's payload; a
 * worker that has re-claimed the same slot can poll in that window and consume
 * a reply that belongs to a DIFFERENT request -- a silent wrong-reply delivered
 * to a SIP transaction.
 *
 * Fix: pin the claim first.  CAS INFLIGHT -> DELIVERING, re-validate the
 * generation (roll back to INFLIGHT on mismatch), THEN write reply_* and store
 * DELIVERED.  A worker never consumes anything but DELIVERED, and while the slot
 * is DELIVERING the worker resume never abandons+frees it, so no reclaim (hence
 * no generation change) can happen under the pin.
 *
 * This drives the REAL slot API (../nats_rpc_slot.c under the SHM shim),
 * -DNATS_RPC_SLOT_COUNT=1 to force slot reuse.  deliver_reply() models
 * on_inbox_reply; a midpoint hook lets the test run a worker poll at the exact
 * instant the buggy protocol exposes the reply:
 *
 *   -DSIMULATE_PREFIX_BUG -> write+DELIVERED then re-check gen: the reclaiming
 *                            worker consumes the FOREIGN reply -> assertion FAILS.
 *   (default)             -> DELIVERING pin + gen re-check before publish: the
 *                            worker never sees a foreign reply -> ALL PASS.
 *
 * Build: TEST_SHIM + ../nats_rpc_slot.c, -DNATS_RPC_SLOT_COUNT=1.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

#include "../nats_rpc_slot.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* We stash the reply's identity (the generation it was minted for) in the
 * slot's reply_data_len field so a worker poll can read "which reply is this". */

/* Worker poll: returns the reply-id if the slot is DELIVERED, else -1.  A real
 * worker only ever consumes on DELIVERED (resume_nats_request_slot). */
static long worker_poll(nats_rpc_slot_t *s)
{
	int st = atomic_load_explicit(&s->state, memory_order_acquire);
	if (st == NATS_RPC_SLOT_DELIVERED)
		return (long)s->reply_data_len;   /* the delivered reply's id */
	return -1;
}

/* Captured: what a re-claiming worker observed at the delivery midpoint. */
static long        g_mid_observed = -1;
static nats_rpc_slot_t *g_mid_slot;

static void midpoint_worker_poll(void)
{
	g_mid_observed = worker_poll(g_mid_slot);
}

/*
 * Model of on_inbox_reply delivering the reply identified by @reply_id, which
 * was minted for the slot claim of generation @target_gen.  @mid runs at the
 * point where the buggy protocol has made the reply visible as DELIVERED.
 */
static void deliver_reply(nats_rpc_slot_t *s, long reply_id,
		uint32_t target_gen, void (*mid)(void))
{
#ifdef SIMULATE_PREFIX_BUG
	/* Pre-fix: write + publish DELIVERED, THEN re-check generation. */
	{
		int expected = NATS_RPC_SLOT_INFLIGHT;
		if (atomic_load_explicit(&s->state, memory_order_acquire) != expected)
			return;
		s->reply_data_len = (uint32_t)reply_id;             /* write reply */
		if (!atomic_compare_exchange_strong_explicit(&s->state, &expected,
				NATS_RPC_SLOT_DELIVERED, memory_order_release,
				memory_order_relaxed))
			return;
		if (mid) mid();                                     /* <-- bug window */
		if (atomic_load_explicit(&s->generation, memory_order_relaxed)
				!= target_gen) {
			int d = NATS_RPC_SLOT_DELIVERED;
			(void)atomic_compare_exchange_strong_explicit(&s->state, &d,
				NATS_RPC_SLOT_ABANDONED, memory_order_release,
				memory_order_relaxed);                      /* too late */
		}
	}
#else
	/* Fixed: pin -> gen re-check -> write -> DELIVERED. */
	{
		int expected = NATS_RPC_SLOT_INFLIGHT;
		if (!atomic_compare_exchange_strong_explicit(&s->state, &expected,
				NATS_RPC_SLOT_DELIVERING, memory_order_acq_rel,
				memory_order_relaxed))
			return;
		if (atomic_load_explicit(&s->generation, memory_order_relaxed)
				!= target_gen) {
			/* pinned a reclaimed (newer) claim -> undo, drop stale reply */
			atomic_store_explicit(&s->state, NATS_RPC_SLOT_INFLIGHT,
				memory_order_release);
			return;
		}
		s->reply_data_len = (uint32_t)reply_id;             /* write reply */
		if (mid) mid();                                     /* still DELIVERING */
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_DELIVERED,
			memory_order_release);
	}
#endif
}

int main(void)
{
	nats_rpc_slot_t *sa, *sb;
	uint32_t gen_a, gen_b;

	CHECK(nats_rpc_slot_init() == 0, "slot pool initialised");

	/* Worker A claims slot S (gen A), publishes. */
	sa = nats_rpc_slot_claim();
	CHECK(sa != NULL && nats_rpc_slot_publish(sa) == 0, "A claims + INFLIGHT");
	gen_a = atomic_load_explicit(&sa->generation, memory_order_relaxed);

	/* A times out -> abandon + free. */
	(void)nats_rpc_slot_abandon(sa);
	nats_rpc_slot_free(sa);

	/* Worker B re-claims the SAME slot (gen B = A+1), publishes. */
	sb = nats_rpc_slot_claim();
	CHECK(sb == sa, "B re-claims the very same slot (forced reuse)");
	CHECK(nats_rpc_slot_publish(sb) == 0, "B publishes (INFLIGHT)");
	gen_b = atomic_load_explicit(&sb->generation, memory_order_relaxed);
	CHECK(gen_b != gen_a, "generation advanced across the reuse");

	/* A's STALE reply (minted for gen A) now arrives while the slot is B's
	 * claim.  At the delivery midpoint, worker B polls the slot. */
	g_mid_slot = sb;
	g_mid_observed = -1;
	deliver_reply(sb, /*reply_id=*/(long)gen_a, /*target_gen=*/gen_a,
		midpoint_worker_poll);

	/* THE CONTRACT: worker B must never consume A's reply. */
	CHECK(g_mid_observed != (long)gen_a,
		"worker B never consumes worker A's reply at the delivery midpoint "
		"(no slot-reuse misdelivery)");
	/* And B's slot must not be left DELIVERED with a foreign payload. */
	CHECK(worker_poll(sb) != (long)gen_a,
		"the slot is not left DELIVERED carrying A's foreign reply");

	nats_rpc_slot_free(sb);
	nats_rpc_slot_destroy();

	/* ---- production wiring ---------------------------------------- */
	CHECK(1, "--- source wiring ---");
	{
		FILE *f = fopen("../nats_rpc_consumer.c", "r");
		char line[4096]; int pin = 0, deliv = 0;
		if (f) {
			while (fgets(line, sizeof(line), f)) {
				if (strstr(line, "NATS_RPC_SLOT_DELIVERING")) pin = 1;
				if (strstr(line, "NATS_RPC_SLOT_DELIVERED"))  deliv = 1;
			}
			fclose(f);
		}
		CHECK(pin, "on_inbox_reply pins the claim via NATS_RPC_SLOT_DELIVERING");
		CHECK(deliv, "on_inbox_reply still publishes DELIVERED");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
