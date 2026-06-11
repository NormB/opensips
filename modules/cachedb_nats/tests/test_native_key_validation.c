/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: only the scalar dbase ops validated their KV key.  The
 * native script wrappers (w_nats_kv_*), the map ops, and raw KV PURGE
 * forwarded SIP-derived tokens to NATS unvalidated, which allowed:
 *   - map-key ':' injection: a subkey containing the ':' map separator
 *     aliases another logical map's fields (build_map_key composes
 *     "key:subkey"); and
 *   - a wildcard ('*' / '>') reaching kvStore_Purge -> a destructive
 *     mass delete of every matching key.
 *
 * Fix: route every native/map/raw key through validate_kv_key(), which
 * rejects control chars, whitespace, wildcards and ':'.  (validate_kv_key
 * is exposed from cachedb_nats_dbase.h and used by both translation units.)
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_native_key_validation test_native_key_validation.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
	char line[2048];
	int hits = 0, seen_marker = 0, in_body = 0;
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
			else if (strchr(line, '{')) { in_body = 1; seen_marker = 0; }
		}
	}
	fclose(f);
	return hits;
}

int main(void)
{
	const char *native = "../cachedb_nats_native.c";
	const char *needle = "validate_kv_key";

	const char *fns[] = {
		"build_map_key",        /* composition choke point: map_set/map_remove */
		"nats_cache_map_get",   /* builds its own "key:" prefix */
		"raw_kv_purge",         /* must reject wildcards (mass delete) */
		"w_nats_kv_get", "w_nats_kv_put", "w_nats_kv_update",
		"w_nats_kv_delete", "w_nats_kv_revision", "w_nats_kv_history",
	};
	for (size_t i = 0; i < sizeof(fns)/sizeof(fns[0]); i++) {
		int n = grep_in_function(native, fns[i], needle);
		char msg[160];
		snprintf(msg, sizeof(msg), "%s validates its KV key(s)", fns[i]);
		ASSERT(n >= 1, msg);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
