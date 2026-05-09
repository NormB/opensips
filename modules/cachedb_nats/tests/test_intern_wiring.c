/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Structural wiring test for the doc-key intern table introduced
 * to cut HP_MALLOC contention on the watcher's _entry_add_key
 * hot path.  See cachedb_nats_intern.h and PERF_NOTES.md
 * "HP_MALLOC contention hypothesis -> watcher-local arena" for
 * the design.
 *
 * This test is structural -- it greps the production source for
 * the required declarations + call sites.  The behavioural
 * coverage is in the sip_e2e suite (cases 030, 120, 140 all
 * exercise the intern path because they drive REGISTER/index
 * traffic).
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
	char line[4096];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	/* Headers exposing the API */
	ASSERT(file_contains("../cachedb_nats_intern.h",
		"int  nats_intern_init"),
		"nats_intern_init prototype declared");
	ASSERT(file_contains("../cachedb_nats_intern.h",
		"void nats_intern_destroy"),
		"nats_intern_destroy prototype declared");
	ASSERT(file_contains("../cachedb_nats_intern.h",
		"char *nats_intern_acquire"),
		"nats_intern_acquire prototype declared");
	ASSERT(file_contains("../cachedb_nats_intern.h",
		"void nats_intern_release"),
		"nats_intern_release prototype declared");

	/* Implementation file present */
	ASSERT(file_contains("../cachedb_nats_intern.c",
		"NATS_INTERN_BUCKETS"),
		"intern .c defines NATS_INTERN_BUCKETS");
	ASSERT(file_contains("../cachedb_nats_intern.c",
		"NATS_INTERN_SHARDS"),
		"intern .c defines NATS_INTERN_SHARDS");
	ASSERT(file_contains("../cachedb_nats_intern.c",
		"refcount"),
		"intern entries are refcounted");
	ASSERT(file_contains("../cachedb_nats_intern.c",
		"lock_set_alloc"),
		"intern uses gen_lock_set for sharded locking");

	/* Callers in cachedb_nats_json.c -- the optimization is
	 * pointless if _entry_add_key still strdups instead of
	 * interning. */
	ASSERT(file_contains("../cachedb_nats_json.c",
		"nats_intern_acquire"),
		"_entry_add_key acquires from intern table");
	ASSERT(file_contains("../cachedb_nats_json.c",
		"nats_intern_release"),
		"key release path goes through intern table");

	/* Init / destroy hooks in mod_init / destroy.  Without these
	 * the table is NULL when index code calls into it -- everything
	 * gracefully fails but no one gets the alloc savings. */
	ASSERT(file_contains("../cachedb_nats.c",
		"nats_intern_init"),
		"mod_init initialises the intern table");
	ASSERT(file_contains("../cachedb_nats.c",
		"nats_intern_destroy"),
		"destroy() tears the intern table down");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
