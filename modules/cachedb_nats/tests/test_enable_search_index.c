/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Item 3 wiring test: cachedb_nats exposes an `enable_search_index`
 * modparam (default 1) that lets operators disable the in-memory
 * JSON-FTS index for PK-only workloads (notably usrloc).  When
 * disabled:
 *
 *   - mod_init must skip nats_json_index_init.
 *   - child_init must skip nats_json_index_build and the watcher.
 *   - nats_cache_query and nats_cache_update must reject non-PK
 *     filters with an explicit error message rather than crashing
 *     on a NULL g_idx.
 *
 * This test is structural -- it greps the production source for the
 * required declarations and gate sites.
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
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	ASSERT(file_contains("../cachedb_nats.c",
		"\"enable_search_index\""),
		"enable_search_index modparam declared");
	ASSERT(file_contains("../cachedb_nats.c",
		"int   nats_enable_search_index = 1"),
		"nats_enable_search_index global defined with default 1");

	ASSERT(file_contains("../cachedb_nats.c",
		"if (nats_enable_search_index) {"),
		"mod_init gates nats_json_index_init on the flag");
	ASSERT(file_contains("../cachedb_nats.c",
		"if (nats_enable_search_index && rank == 1 &&"),
		"child_init gates index_build / watcher on the flag");

	ASSERT(file_contains("../cachedb_nats_json.c",
		"non-PK filter rejected because the "),
		"query and update reject non-PK filters when index disabled");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
