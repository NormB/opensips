/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 [§2.0 invariant]: EVERY usrloc-row write goes through nats_kv_write_row_cas()
 * (which re-asserts Nats-TTL), so no kvStore_UpdateString may remain on the
 * usrloc row path -- otherwise that writer silently strips the TTL and
 * re-creates #1994 (the registration update AND the reaper survivor-write are
 * the two load-bearing cases).  The ONLY allowed kvStore_UpdateString on the row
 * path is the legacy fallback INSIDE the helper (gated on TTL being unavailable).
 *
 * Source-pattern guard (the CI grep guard from the plan).  Run from tests/.
 *
 * Build: gcc -g -O0 -Wall -o test_ttl_write_invariant test_ttl_write_invariant.c
 */
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define ASSERT(cond, msg) do { if (cond) printf("  ok:   %s\n", msg); \
	else { printf("  FAIL: %s\n", msg); fails++; } } while (0)

/* count occurrences of @needle within function @fn in source @path */
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int in = 0, depth = 0, n = 0;
	if (!f) { printf("  (cannot open %s)\n", path); return -1; }
	while (fgets(line, sizeof line, f)) {
		if (!in) {
			if (strstr(line, fn)) { in = 1; depth = 0; }
		}
		if (in) {
			const char *p;
			if (strstr(line, needle)) n++;
			for (p = line; *p; p++) {
				if (*p == '{') depth++;
				else if (*p == '}') { depth--; if (depth <= 0) { in = 0; break; } }
			}
		}
	}
	fclose(f);
	return n;
}

int main(void)
{
	printf("[§2.0] usrloc-row-write invariant -- no kvStore_UpdateString off the helper:\n");

	/* the two writers must NOT call kvStore_UpdateString directly */
	ASSERT(grep_in_function("../cachedb_nats_json.c",
		"_update_apply_and_cas", "nats_dl.kvStore_UpdateString") == 0,
		"registration write (_update_apply_and_cas) has no direct kvStore_UpdateString");
	ASSERT(grep_in_function("../cachedb_nats.c",
		"_nats_cdb_reaper_tick", "nats_dl.kvStore_UpdateString") == 0,
		"reaper survivor-write has no direct kvStore_UpdateString");

	/* both writers route through the helper */
	ASSERT(grep_in_function("../cachedb_nats_json.c",
		"_update_apply_and_cas", "nats_kv_write_row_cas") >= 1,
		"registration write routes through nats_kv_write_row_cas");
	ASSERT(grep_in_function("../cachedb_nats.c",
		"_nats_cdb_reaper_tick", "nats_kv_write_row_cas") >= 1,
		"reaper survivor-write routes through nats_kv_write_row_cas");

	/* the helper delegates to the single CAS publish (nats_kv_put_row);
	 * since P1.5 (reaper-only) NO kvStore_UpdateString remains anywhere
	 * on the row path -- the legacy fallback is gone too */
	ASSERT(grep_in_function("../cachedb_nats_ttl_put.c",
		"nats_kv_write_row_cas", "nats_kv_put_row") >= 1,
		"helper delegates to the nats_kv_put_row CAS publish");
	ASSERT(grep_in_function("../cachedb_nats_ttl_put.c",
		"nats_kv_write_row_cas", "nats_dl.kvStore_UpdateString") == 0 &&
	       grep_in_function("../cachedb_nats_ttl_put.c",
		"nats_kv_put_row", "nats_dl.kvStore_UpdateString") == 0,
		"no kvStore_UpdateString remains in the row-write helper");

	if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
	printf("\n=== ALL PASS (fails=0) ===\n");
	return 0;
}
