/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * REV-26 (P10 follow-up): nats_json_index_add must increment num_documents only
 * for a GENUINELY-NEW doc-key, so the counter equals the true unique-key
 * cardinality.
 *
 * The bug: with enable_search_index=1 a node indexes its OWN write twice — once
 * inline in the registration worker (cachedb_nats_json.c) and once via the KV
 * watcher echo of that same Put — and the old nats_json_index_add incremented
 * num_documents UNCONDITIONALLY.  So a single live AoR read as 2, and the stat
 * drifted up under load (accurate only right after a fresh build/rebuild).
 * Membership and field entries were always correct; only the raw counter lied.
 *
 * The fix: gate the increment on a reverse-map membership check
 * (nats_rev_contains) — if the doc-key is already indexed (a node's own echo, or
 * a field-update), do NOT increment.  This test carries that logic over a simple
 * membership set:
 *   - first add of a key                 => +1
 *   - any re-add of a present key (echo) => +0   (the fix)
 *   - the writer UPDATE pattern           => remove_fields(-1) + add(+1) = net 0
 *   - count always == #distinct keys present (the true cardinality)
 *
 *   gcc -DCOUNTER_UNCONDITIONAL ... -> old +1-every-add => RED (drifts).
 *   gcc ...                         -> membership-gated => GREEN.
 *
 * Rule 6: the authoritative proof is the Tier-2 run_marker_watcher_joint_e2e.sh
 * tombstone line reading "num_documents 1->0" (a single live key, cleanly to 0).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_index_add_idempotent test_index_add_idempotent.c
 */
#include <stdio.h>
#include <string.h>

/* ─── carried model of the reverse-map membership set (g_rev) ─────────
 * The real map is a sharded SHM hash; membership semantics are identical. */
#define MAXK 32
static char  set_keys[MAXK][64];
static int   set_used[MAXK];
static int   num_documents;

static int rev_contains(const char *key)
{
	for (int i = 0; i < MAXK; i++)
		if (set_used[i] && strcmp(set_keys[i], key) == 0)
			return 1;
	return 0;
}
static void rev_put(const char *key)            /* insert-or-replace, like nats_rev_put */
{
	for (int i = 0; i < MAXK; i++)
		if (set_used[i] && strcmp(set_keys[i], key) == 0) return;  /* replace: present */
	for (int i = 0; i < MAXK; i++)
		if (!set_used[i]) { set_used[i] = 1; snprintf(set_keys[i], 64, "%s", key); return; }
}
static void rev_remove(const char *key)
{
	for (int i = 0; i < MAXK; i++)
		if (set_used[i] && strcmp(set_keys[i], key) == 0) { set_used[i] = 0; return; }
}
static int set_count(void)
{
	int n = 0;
	for (int i = 0; i < MAXK; i++) n += set_used[i] ? 1 : 0;
	return n;
}

/* ─── carried model of nats_json_index_add's counter logic ───────────── */
static void index_add(const char *key)
{
#ifdef COUNTER_UNCONDITIONAL
	rev_put(key);
	num_documents += 1;                 /* OLD bug: +1 every add */
#else
	int was_present = rev_contains(key);   /* check BEFORE the put */
	rev_put(key);
	if (!was_present)                      /* REV-26: only a genuinely-new key counts */
		num_documents += 1;
#endif
}
/* nats_json_index_remove / remove_fields: drop membership + decrement. */
static void index_remove(const char *key)
{
	if (rev_contains(key)) { rev_remove(key); num_documents -= 1; }
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
#define INVARIANT() CHECK(num_documents == set_count(), \
	"  invariant: num_documents == #distinct keys present")

int main(void)
{
#ifdef COUNTER_UNCONDITIONAL
	printf("== carried copy: COUNTER_UNCONDITIONAL (+1 every add = today's bug) ==\n");
#else
	printf("== carried copy: REV-26 membership-gated increment ==\n");
#endif

	printf("[REV-26] a node's own write is indexed twice (inline + watcher echo) => count ONCE:\n");
	index_add("usrloc.alice");                      /* inline write */
	CHECK(num_documents == 1, "first add of alice => 1");
	index_add("usrloc.alice");                      /* watcher echo of the SAME Put */
	CHECK(num_documents == 1, "echo re-add of alice => STILL 1 (idempotent)");
	index_add("usrloc.alice");                      /* periodic resync re-add */
	CHECK(num_documents == 1, "third re-add of alice => STILL 1");
	INVARIANT();

	printf("[REV-26] distinct keys each count once:\n");
	index_add("usrloc.bob");
	index_add("usrloc.bob");                        /* bob's echo */
	CHECK(num_documents == 2, "alice + bob (each echoed) => 2");
	INVARIANT();

	printf("[REV-26] a re-REGISTER UPDATE (remove_fields then add) nets zero:\n");
	index_remove("usrloc.alice");                   /* remove_fields(-1) */
	index_add("usrloc.alice");                      /* add(+1) over the same key */
	index_add("usrloc.alice");                      /* its echo */
	CHECK(num_documents == 2, "update alice => still 2 (no drift)");
	INVARIANT();

	printf("[REV-26] a single live key removed by the watcher MUST reach 0:\n");
	index_remove("usrloc.alice");
	index_remove("usrloc.bob");
	CHECK(num_documents == 0, "both removed => 0 (the P10 e2e's num_documents->0)");
	INVARIANT();

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
		fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
