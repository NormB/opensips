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
 * P10 / TTL-SOLUTION-SPEC §4 [TREV-2a], SPEC §12 [REV-26] observability.
 *
 * The in-SHM forward index tracks live document keys in g_idx->num_documents
 * (an _Atomic int).  Until P10 there was NO way to OBSERVE that count, so a
 * Tier-2 test could not assert "the index entry is gone" after a server-side
 * TTL expiry — it could only see the read-path filter omit the row, which is a
 * DIFFERENT subsystem (P4).  The joint reaper⊕watcher GATE requires proving the
 * index itself drops the entry.
 *
 * nats_json_index_count() exposes the live count, NULL-safe:
 *   - g_idx == NULL (index not initialized) => -1  (distinct from "empty"=0),
 *     never a NULL deref;
 *   - otherwise the exact atomic num_documents (no truncation at scale).
 *
 *   gcc -DCOUNT_CURRENT ... -> no accessor (count unobservable) => RED.
 *   gcc ...              -> the FIXED accessor                  => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 joint e2e
 * (run_marker_watcher_joint_e2e.sh) where the watcher drops the index entry on
 * a real MaxAge marker and this count reaches 0 with the reaper parked.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_index_count test_index_count.c
 */
#include <stdio.h>
#include <stdatomic.h>

/* ─── minimal carried copy of the index struct (cachedb_nats_json.h) ───
 * Only num_documents matters here; the real struct also holds buckets/locks. */
struct nats_json_index { _Atomic int num_documents; };
static struct nats_json_index *g_idx;   /* the real module global, mocked */

/* ─── carried copy of the production accessor (cachedb_nats_json_index.c) ── */
static int nats_json_index_count(void)
{
#ifdef COUNT_CURRENT
	return -2;   /* today: no accessor exists — count is UNOBSERVABLE */
#else
	if (!g_idx)
		return -1;   /* index not initialized — distinct from empty(0) */
	return atomic_load_explicit(&g_idx->num_documents, memory_order_relaxed);
#endif
}

/* test helpers that mimic add/remove deltas on the real index */
static void idx_set(int n)  { atomic_store_explicit(&g_idx->num_documents, n, memory_order_relaxed); }
static void idx_add(void)   { atomic_fetch_add_explicit(&g_idx->num_documents, 1, memory_order_relaxed); }
static void idx_sub(void)   { atomic_fetch_sub_explicit(&g_idx->num_documents, 1, memory_order_relaxed); }

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef COUNT_CURRENT
	printf("== carried copy: COUNT_CURRENT (no accessor — unobservable) ==\n");
#else
	printf("== carried copy: FIXED index-count accessor ==\n");
#endif

	printf("[REV-26] uninitialized index MUST be NULL-safe (no deref/crash):\n");
	g_idx = NULL;
	CHECK(nats_json_index_count() == -1, "g_idx==NULL => -1 (not initialized)");

	struct nats_json_index idx = { 0 };
	g_idx = &idx;

	printf("[TREV-2a] the accessor MUST track the live document count:\n");
	idx_set(0);
	CHECK(nats_json_index_count() == 0, "empty index => 0 (distinct from -1)");
	idx_add();
	CHECK(nats_json_index_count() == 1, "after one add => 1");
	idx_set(0); idx_add(); idx_add(); idx_add();
	CHECK(nats_json_index_count() == 3, "three adds => 3");

	printf("[TREV-2a] a marker-driven removal MUST be observable as a decrement:\n");
	idx_set(1);
	CHECK(nats_json_index_count() == 1, "one live row baseline => 1");
	idx_sub();                                  /* watcher drops the entry */
	CHECK(nats_json_index_count() == 0, "after the watcher removes it => 0 (index entry GONE)");

	printf("[REV-26] scale: no truncation of a large count:\n");
	idx_set(1000000);
	CHECK(nats_json_index_count() == 1000000, "1,000,000 docs => exact");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
		fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
