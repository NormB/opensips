/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the disconnected fast-fail + stale-KV-handle refresh
 * (nats_con_refresh_kv) was applied only to the scalar dbase ops
 * (get/set/remove/counter).  The query, update, raw and map ops obtained
 * ncon->kv and called kvStore_* WITHOUT refreshing, so:
 *   - a broker outage blocked the SIP worker for the full JetStream
 *     timeout on every REGISTER routed through query/update, and
 *   - after a reconnect those paths kept using the pre-reconnect
 *     ncon->kv, which nats_pool_get_kv() destroys on the first
 *     post-reconnect call -> a dangling handle and a
 *     "free(): invalid pointer" crash in cnats's I/O thread.
 *
 * The fix:
 *   - the con->data ops (nats_cache_query / _update / _raw_query_impl /
 *     _map_get / _map_set / _map_remove) call nats_con_refresh_kv(ncon)
 *     before touching ncon->kv, which both fast-fails when disconnected
 *     and refreshes the handle after a reconnect; and
 *   - the w_nats_kv_* script wrappers (which fetch a fresh handle via
 *     nats_pool_get_kv) gate on nats_pool_is_connected() first.
 *
 * Like test_disconnected_fastfail.c, this is a source-pattern test: it
 * confirms the guarding call is present in each function body.  Run from
 * the tests/ directory (reads ../cachedb_nats_*.c).
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_allops_fastfail test_allops_fastfail.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Count occurrences of @needle inside the function body named @fn_name.
 * Skips the forward declaration; a function body ends at a '}' in
 * column 0.  (Same helper shape as test_disconnected_fastfail.c.) */
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
	const char *json   = "../cachedb_nats_json.c";
	const char *native = "../cachedb_nats_native.c";

	/* Group A: con->data ops must refresh (fast-fail + rebind handle). */
	struct { const char *file; const char *fn; } refresh_ops[] = {
		{ json,   "nats_cache_query"          },
		{ json,   "nats_cache_update"         },
		{ native, "nats_cache_raw_query_impl" },
		{ native, "nats_cache_map_get"        },
		{ native, "nats_cache_map_set"        },
		{ native, "nats_cache_map_remove"     },
	};
	for (size_t i = 0; i < sizeof(refresh_ops)/sizeof(refresh_ops[0]); i++) {
		int n = grep_in_function(refresh_ops[i].file, refresh_ops[i].fn,
			"nats_con_refresh_kv");
		char msg[160];
		snprintf(msg, sizeof(msg),
			"%s calls nats_con_refresh_kv before using ncon->kv",
			refresh_ops[i].fn);
		ASSERT(n >= 1, msg);
	}

	/* Group B: w_nats_kv_* wrappers must gate on connectivity. */
	const char *kv_wrappers[] = {
		"w_nats_kv_get", "w_nats_kv_put", "w_nats_kv_update",
		"w_nats_kv_delete", "w_nats_kv_revision", "w_nats_kv_history",
	};
	for (size_t i = 0; i < sizeof(kv_wrappers)/sizeof(kv_wrappers[0]); i++) {
		int n = grep_in_function(native, kv_wrappers[i],
			"nats_pool_is_connected");
		char msg[160];
		snprintf(msg, sizeof(msg),
			"%s gates on nats_pool_is_connected", kv_wrappers[i]);
		ASSERT(n >= 1, msg);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
