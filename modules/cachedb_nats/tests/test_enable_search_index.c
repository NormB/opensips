/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * FTS-split wiring test (P1.2): the former enable_search_index modparam
 * is GONE — loading the optional cachedb_nats_fts module is the enable
 * switch.  cachedb_nats binds it at mod_init (cdbn_fts_bind) and:
 *   - query/update reject non-PK filters when the module is absent;
 *   - the write path / watcher feed the index only through the binds
 *     (cdbn_fts_on-guarded);
 *   - the index + intern lifecycles live in the FTS module's
 *     mod_init/destroy, not in cachedb_nats.
 *
 * Source-pattern test; run from the tests/ directory.
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
	const char *CN = "../cachedb_nats.c";
	const char *JS = "../cachedb_nats_json.c";
	const char *W  = "../cachedb_nats_watch.c";
	const char *FM = "../../cachedb_nats_fts/cachedb_nats_fts.c";

	/* the modparam is gone; the binds replace it */
	ASSERT(!file_contains(CN, "\"enable_search_index\""),
		"enable_search_index modparam removed");
	ASSERT(file_contains(CN, "find_export(\"cdbn_fts_bind\""),
		"cachedb_nats binds the FTS module at mod_init");

	/* PK-only rejection when absent */
	ASSERT(file_contains(JS, "cachedb_nats_fts) is not loaded"),
		"query/update reject non-PK filters without the module");

	/* binds-guarded feeds */
	ASSERT(file_contains(W, "if (cdbn_fts_on)"),
		"watcher index feed is binds-guarded");
	ASSERT(file_contains(CN, "cdbn_fts.build(kv, fts_json_prefix)"),
		"child_init initial build goes through the binds");

	/* index + intern lifecycle belongs to the FTS module */
	ASSERT(file_contains(FM, "nats_json_index_init()"),
		"FTS module mod_init owns index init");
	ASSERT(file_contains(FM, "nats_intern_destroy()"),
		"FTS module destroy owns the intern table");
	ASSERT(!file_contains(CN, "nats_json_index_init"),
		"cachedb_nats no longer inits the index itself");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
