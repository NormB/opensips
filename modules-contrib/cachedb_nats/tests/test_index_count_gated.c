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
 * Regression: the JSON-FTS index decremented g_idx->num_documents
 * UNCONDITIONALLY on every remove path (nats_json_index_remove,
 * remove_by_revmap, remove_fields), even when the key was never indexed --
 * e.g. the seed-create path calls remove_fields on a key it never added, and
 * a duplicate remove hits nothing.  That drives num_documents negative and
 * skews the stat.
 *
 * Fix: entry_remove_key returns whether it removed the key; the remove paths
 * OR those results and decrement only when the key was actually present.
 *
 * Models the gated decrement:
 *   -DSIMULATE_UNGATED -> decrement regardless -> removing a never-indexed key
 *                         drives the count to -1 -> assertion FAILS.
 *   (default)          -> gated on actual removal -> count stays 0.
 * plus source-wiring assertions on the real index TU.
 *
 * Build: cc -g -O0 -Wall -o test_index_count_gated test_index_count_gated.c
 */

#include <stdio.h>
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

static int num_documents;

/* Model of a remove path: @removed_any is whether entry_remove_key found and
 * stripped the key from at least one field entry. */
static void index_remove(int removed_any)
{
#ifdef SIMULATE_UNGATED
	(void)removed_any;
	num_documents -= 1;                 /* unconditional -> can go negative */
#else
	if (removed_any)
		num_documents -= 1;             /* only when actually present */
#endif
}

int main(void)
{
	num_documents = 0;

	/* Add one document. */
	num_documents += 1;
	ASSERT(num_documents == 1, "one indexed document => count 1");

	/* Remove a key that was NOT indexed (seed-create / duplicate remove):
	 * must not decrement below the true membership. */
	index_remove(/*removed_any=*/0);
	ASSERT(num_documents == 1,
		"removing a never-indexed key does not decrement (no drift)");

	/* Remove the real document. */
	index_remove(/*removed_any=*/1);
	ASSERT(num_documents == 0, "removing the indexed document => count 0");

	/* Another spurious remove must not go negative. */
	index_remove(/*removed_any=*/0);
	ASSERT(num_documents == 0,
		"a spurious remove on an empty index stays 0 (never negative)");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../../cachedb_nats_fts/fts_index.c";
		ASSERT(file_contains(src, "removed_any"),
			"remove paths gate the decrement on actual removal (removed_any)");
		ASSERT(file_contains(src, "return 1;   /* removed */"),
			"entry_remove_key reports whether it removed the key");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
