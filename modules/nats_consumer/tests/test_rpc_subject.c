/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the consumer-process-routed async nats_request
 * reply-correlation generation guard.
 *
 * Bug: replies were correlated to their SHM slot by slot_idx ALONE
 * (reply subject "<prefix>.<slot_idx>").  A responder slower than the
 * request timeout could have its reply land after the worker timed out,
 * freed the slot, and another request re-claimed the SAME slot_idx --
 * delivering one call's reply payload to a different call (a cross-call
 * data leak).  The pre-fix INFLIGHT-state CAS did not catch this because
 * the re-claimed slot is also INFLIGHT.
 *
 * Fix: each claim bumps a per-slot generation; the reply subject is now
 * "<prefix>.<slot_idx>.<generation>", and on_inbox_reply drops a reply
 * whose generation no longer matches the slot's current claim.
 *
 * This test exercises the two pure pieces of that fix together:
 *   - nats_rpc_subject_build / _parse   (reply-subject grammar)
 *   - nats_rpc_slot generation bump on every claim
 * and asserts the exact guard on_inbox_reply applies.
 *
 * Build (see Makefile): links ../nats_rpc_subject.c + ../nats_rpc_slot.c
 * under -DTEST_SHIM.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

#include "../nats_rpc_subject.h"
#include "../nats_rpc_slot.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static void test_subject_grammar(void)
{
	char     buf[128];
	uint32_t slot, gen;
	int      n;

	/* round-trip */
	n = nats_rpc_subject_build(buf, sizeof(buf),
		"_INBOX.opensips.12345", 5, 7);
	ASSERT(n > 0, "build returns length");
	ASSERT(strcmp(buf, "_INBOX.opensips.12345.5.7") == 0,
		"build emits <prefix>.<slot>.<gen>");
	ASSERT(nats_rpc_subject_parse(buf, (int)strlen(buf), &slot, &gen) == 0,
		"parse accepts a well-formed subject");
	ASSERT(slot == 5 && gen == 7, "parse recovers slot and gen");

	/* large values */
	n = nats_rpc_subject_build(buf, sizeof(buf), "p", 2147483647u,
		4294967295u);
	ASSERT(n > 0 &&
		nats_rpc_subject_parse(buf, (int)strlen(buf), &slot, &gen) == 0 &&
		slot == 2147483647u && gen == 4294967295u,
		"parse handles INT32_MAX slot and UINT32_MAX gen");

	/* malformed inputs are rejected */
	ASSERT(nats_rpc_subject_parse("noslots", 7, &slot, &gen) < 0,
		"parse rejects subject with no dots");
	ASSERT(nats_rpc_subject_parse("_INBOX.5", 8, &slot, &gen) < 0,
		"parse rejects subject with only one dot");
	ASSERT(nats_rpc_subject_parse("a.b.7", 5, &slot, &gen) < 0,
		"parse rejects non-numeric slot");
	ASSERT(nats_rpc_subject_parse("a.5.x", 5, &slot, &gen) < 0,
		"parse rejects non-numeric gen");
	ASSERT(nats_rpc_subject_parse("a.5.", 4, &slot, &gen) < 0,
		"parse rejects empty gen segment");
	ASSERT(nats_rpc_subject_parse("a..7", 4, &slot, &gen) < 0,
		"parse rejects empty slot segment");

	/* build overflow */
	ASSERT(nats_rpc_subject_build(buf, 4, "longprefix", 1, 1) < 0,
		"build rejects buffer overflow");
}

/* Re-claim a specific slot index by cycling the round-robin allocator,
 * freeing every non-matching claim along the way.  Returns the slot or
 * NULL if not reached within a few full cycles. */
static nats_rpc_slot_t *reclaim_idx(uint32_t want)
{
	int k;
	for (k = 0; k < (int)nats_rpc_slot_total_count() * 3 + 4; k++) {
		nats_rpc_slot_t *c = nats_rpc_slot_claim();
		if (!c) return NULL;
		if (c->slot_idx == want) return c;
		nats_rpc_slot_free(c);
	}
	return NULL;
}

static void test_generation_guard(void)
{
	const char *prefix = "_INBOX.opensips.12345";
	char subj_old[128], subj_new[128];
	uint32_t idx, gen_old, gen_new, pslot, pgen;
	nats_rpc_slot_t *a, *b;

	ASSERT(nats_rpc_slot_init() == 0, "slot table init");

	/* claim A -- this is request #1 */
	a = nats_rpc_slot_claim();
	ASSERT(a != NULL, "claim A succeeds");
	idx     = a->slot_idx;
	gen_old = atomic_load_explicit(&a->generation, memory_order_relaxed);
	ASSERT(gen_old >= 1, "generation is set (>=1) on first claim");

	/* the consumer would publish request #1 with this reply subject */
	ASSERT(nats_rpc_subject_build(subj_old, sizeof(subj_old),
		prefix, idx, gen_old) > 0, "build reply subject for claim A");

	/* request #1 times out -> worker frees the slot */
	nats_rpc_slot_free(a);

	/* request #2 re-claims the SAME slot index */
	b = reclaim_idx(idx);
	ASSERT(b != NULL, "re-claimed the same slot index for request #2");
	gen_new = atomic_load_explicit(&b->generation, memory_order_relaxed);
	ASSERT(gen_new != gen_old,
		"re-claim of the same slot has a different generation");

	/* === the guard on_inbox_reply applies === */

	/* (1) the LATE reply for request #1 arrives carrying subj_old */
	ASSERT(nats_rpc_subject_parse(subj_old, (int)strlen(subj_old),
		&pslot, &pgen) == 0, "parse late reply subject");
	ASSERT(pslot == idx, "late reply maps to the same slot index");
	ASSERT(pgen == gen_old, "late reply carries request #1's generation");
	ASSERT(atomic_load_explicit(&b->generation, memory_order_relaxed) != pgen,
		"STALE reply rejected: slot generation != reply generation");

	/* (2) the genuine reply for request #2 carries the current gen */
	ASSERT(nats_rpc_subject_build(subj_new, sizeof(subj_new),
		prefix, idx, gen_new) > 0, "build reply subject for claim B");
	ASSERT(nats_rpc_subject_parse(subj_new, (int)strlen(subj_new),
		&pslot, &pgen) == 0, "parse genuine reply subject");
	ASSERT(atomic_load_explicit(&b->generation, memory_order_relaxed) == pgen,
		"FRESH reply accepted: slot generation == reply generation");

	nats_rpc_slot_free(b);
	nats_rpc_slot_destroy();
}

int main(void)
{
	test_subject_grammar();
	test_generation_guard();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
