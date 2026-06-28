/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 [R1 / TTL-SOLUTION-SPEC.md §4 TREV-2a]: watcher index action for a watched
 * KV entry.  cnats 3.12 surfaces a server-side MaxAge TTL-expiry as an
 * EMPTY-VALUE kvOp_Put (NOT a Delete/Purge op).  The watcher's index maintenance
 * must treat that empty-value Put as a REMOVAL -- otherwise, the moment
 * per-message TTL is enabled and a key auto-expires server-side, the forward
 * index keeps pointing at a vanished key (split-brain: lookup-by-field returns a
 * phantom).
 *
 *   gcc -DWATCH_CURRENT ... -> today: empty-value Put => SKIP (neither add nor
 *                              remove) => the phantom-index bug => RED.
 *   gcc ...                 -> the FIXED classifier (empty Put => REMOVE) => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (let a key TTL-expire on a
 * real >=2.11 server, assert the in-SHM index entry is dropped and a re-REGISTER
 * succeeds first-attempt) -- run_usrloc_ttl_marker_watcher_e2e.sh (Stage 3c).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_watch_marker test_ttl_watch_marker.c
 */
#include <stdio.h>

/* carried copy of the cnats kvOperation values (nats.h) */
enum { kvOp_Unknown = 0, kvOp_Put = 1, kvOp_Delete = 2, kvOp_Purge = 3 };

/* ─── carried copy of the production classifier (cachedb_nats_watch.c) ─── */
enum watch_idx_action { WATCH_IDX_SKIP = 0, WATCH_IDX_ADD = 1, WATCH_IDX_REMOVE = 2 };

static enum watch_idx_action _watch_index_action(int op, int val_len, char val0)
{
	if (op == kvOp_Delete || op == kvOp_Purge)
		return WATCH_IDX_REMOVE;
	if (op == kvOp_Put) {
#ifndef WATCH_CURRENT
		if (val_len <= 0)
			return WATCH_IDX_REMOVE;   /* [R1] empty-value Put = MaxAge tombstone */
#endif
		if (val_len > 0 && val0 == '{')
			return WATCH_IDX_ADD;      /* JSON doc; prefix checked at call site */
	}
	return WATCH_IDX_SKIP;
}

static int fails = 0;
static const char *NM[] = { "SKIP", "ADD", "REMOVE" };
static void expect(const char *what, enum watch_idx_action got, enum watch_idx_action want)
{
	if (got == want) { printf("  ok:   %-44s => %s\n", what, NM[got]); }
	else { printf("  FAIL: %-44s => %s (want %s)\n", what, NM[got], NM[want]); fails++; }
}

int main(void)
{
	printf("[R1] watcher index action over KV entry ops:\n");

	/* the load-bearing case: an empty-value Put is a server MaxAge tombstone */
	expect("Put, empty value (MaxAge marker)", _watch_index_action(kvOp_Put, 0, 0), WATCH_IDX_REMOVE);

	/* normal live row: a JSON document is indexed */
	expect("Put, JSON '{...}'",               _watch_index_action(kvOp_Put, 42, '{'), WATCH_IDX_ADD);

	/* a non-JSON value is not indexed (and is not a tombstone) */
	expect("Put, non-JSON value",             _watch_index_action(kvOp_Put, 5, 'x'), WATCH_IDX_SKIP);

	/* explicit delete / purge ops remove */
	expect("Delete op",                       _watch_index_action(kvOp_Delete, 0, 0), WATCH_IDX_REMOVE);
	expect("Purge op",                        _watch_index_action(kvOp_Purge, 0, 0), WATCH_IDX_REMOVE);

	/* unknown / other ops are ignored */
	expect("Unknown op",                      _watch_index_action(kvOp_Unknown, 10, '{'), WATCH_IDX_SKIP);

	if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
	printf("\n=== ALL PASS (fails=0) ===\n");
	return 0;
}
