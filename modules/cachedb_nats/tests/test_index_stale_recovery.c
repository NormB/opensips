/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_cache_query at the result-fetch
 * loop (cachedb_nats_json.c around the kvStore_Get call inside the
 * "Fetch full JSON documents" stage) used to silently `continue` on
 * any non-NATS_OK status from kvStore_Get. In a multi-instance
 * deployment where another node has deleted the key between our
 * index build and our fetch, this means the in-memory index says
 * "hit" but the KV store says "miss" — the row vanishes from the
 * caller's result set with no log warning and no operator signal.
 *
 * The fix: on NATS_NOT_FOUND specifically, evict the stale index
 * entry via nats_json_index_remove() and bump the index_miss_kv
 * counter so operators can monitor staleness rate via the
 * nats_cdb_stats MI command. Other failures (network) keep the
 * existing skip behaviour but log louder.
 *
 * This test is structural — it greps the production source for the
 * required call shape inside nats_cache_query rather than running
 * the function (which would need a live NATS broker).
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_index_stale_recovery test_index_stale_recovery.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Same body-scan helper as test_disconnected_fastfail. */
static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	int seen_marker = 0;
	int in_body = 0;
	char marker[256];
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen_marker = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			if (strchr(line, ';')) { seen_marker = 0; continue; }
			if (strchr(line, '{')) { in_body = 1; continue; }
			continue;
		}
		if (strstr(line, marker)) {
			seen_marker = 1;
			if (strchr(line, ';')) seen_marker = 0;
			else if (strchr(line, '{')) {
				in_body = 1;
				seen_marker = 0;
			}
		}
	}
	fclose(f);
	return hits;
}

int main(void)
{
	const char *path = "../cachedb_nats_json.c";
	int n;

	/* (a) the query function must distinguish NATS_NOT_FOUND from other
	 *     non-OK statuses on the result-fetch path */
	/* the result-fetch loop now lives in the _query_fetch_rows helper
	 * extracted from nats_cache_query (NATS_TODO #60 decomposition) */
	n = grep_in_function(path, "_query_fetch_rows", "NATS_NOT_FOUND");
	ASSERT(n >= 1,
		"nats_cache_query distinguishes NATS_NOT_FOUND in fetch loop");

	/* (b) on stale-index detection, the entry is evicted from the index */
	n = grep_in_function(path, "_query_fetch_rows", "nats_json_index_remove");
	ASSERT(n >= 1,
		"nats_cache_query evicts stale index entries on KV miss");

	/* (c) the index_miss_kv counter is bumped so operators can monitor */
	n = grep_in_function(path, "_query_fetch_rows", "index_miss_kv");
	ASSERT(n >= 1,
		"nats_cache_query bumps index_miss_kv counter on stale hit");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
