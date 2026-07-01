/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the KV watcher's _raise_kv_change_event (cachedb_nats_watch.c)
 * emitted the E_NATS_KV_CHANGE event with the RAW kvOperation.  A server-side
 * MaxAge/TTL expiry (and the module's own delete markers) surface via cnats
 * (<=3.12) as a kvOp_Put with an EMPTY value.  The in-SHM index correctly maps
 * that empty-value Put to a REMOVE (_watch_index_action), but the EVI event was
 * raised as operation="put" -- so a presence-tracking script saw a phantom
 * "put" for a key that had actually vanished (index and EVI disagreeing on the
 * same event).
 *
 * Fix: classify an empty-value Put as a delete for the raised event, matching
 * the index's REMOVE semantics.
 *
 * Models the op-classification:
 *   -DSIMULATE_RAW_OP_BUG -> emit the raw op -> empty-value Put stays "put".
 *   (default)             -> empty-value Put becomes delete.
 * plus a source-wiring assertion.
 *
 * Build: gcc -g -O0 -Wall -o test_watch_evi_expire_op test_watch_evi_expire_op.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Mirror the cnats kvOperation values we care about. */
enum { KVOP_PUT = 1, KVOP_DELETE = 2, KVOP_PURGE = 3 };

/* Model of the effective op the EVI event should carry. */
static int eff_evi_op(int op, int val_len)
{
#ifdef SIMULATE_RAW_OP_BUG
	(void)val_len;
	return op;                                  /* raw op: empty Put stays put */
#else
	if (op == KVOP_PUT && val_len == 0)
		return KVOP_DELETE;                     /* MaxAge tombstone -> delete */
	return op;
#endif
}

int main(void)
{
	ASSERT(eff_evi_op(KVOP_PUT, 42) == KVOP_PUT,
		"a real value Put stays a put");
	ASSERT(eff_evi_op(KVOP_PUT, 0) == KVOP_DELETE,
		"an empty-value Put (TTL expiry/tombstone) is raised as a delete");
	ASSERT(eff_evi_op(KVOP_DELETE, 0) == KVOP_DELETE,
		"an explicit delete stays a delete");
	ASSERT(eff_evi_op(KVOP_PURGE, 0) == KVOP_PURGE,
		"a purge stays a purge");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../cachedb_nats_watch.c";
		ASSERT(file_contains(src, "eff_op") &&
		       file_contains(src, "eff_op = kvOp_Delete"),
			"_raise_kv_change_event remaps an empty-value Put to kvOp_Delete");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
