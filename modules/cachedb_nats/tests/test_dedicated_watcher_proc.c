/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Item 4 wiring test: cachedb_nats can move the KV watcher out of
 * the rank-1 SIP worker (where it lives as a pthread) into a
 * dedicated OpenSIPS child process.
 *
 *   dedicated_watcher_proc (int, default 0)
 *     When 1 (and enable_search_index is also 1), the module
 *     declares a proc_export_t that the OpenSIPS core forks at
 *     startup, and the rank-1 SIP worker skips the
 *     pthread_create() in nats_watch_start().  The dedicated
 *     process owns the watcher's NATS connection, the kvWatcher,
 *     and the SHM-index update path.
 *
 *   When 0 (default): legacy rank-1 pthread behaviour, unchanged.
 *
 *   When enable_search_index=0: dedicated process is NOT declared
 *     and NOT forked, regardless of dedicated_watcher_proc -- the
 *     watcher has nothing to update.
 *
 * This test is structural -- it greps the production source for the
 * required declarations, the proc_export_t entry, the watcher_proc
 * entry function, and the gate sites in mod_init / nats_watch_start.
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
	/* Modparam declaration + default storage in cachedb_nats.c */
	ASSERT(file_contains("../cachedb_nats.c",
		"\"dedicated_watcher_proc\""),
		"dedicated_watcher_proc modparam declared");
	ASSERT(file_contains("../cachedb_nats.c",
		"int   nats_dedicated_watcher_proc = 0"),
		"nats_dedicated_watcher_proc global defined with default 0");

	/* proc_export_t entry pointing at the dedicated proc main */
	ASSERT(file_contains("../cachedb_nats.c",
		"proc_export_t"),
		"proc_export_t declared in cachedb_nats.c");
	ASSERT(file_contains("../cachedb_nats.c",
		"NATS Watcher"),
		"proc name string \"NATS Watcher\" present");
	ASSERT(file_contains("../cachedb_nats.c",
		"nats_watcher_proc_main"),
		"dedicated proc main referenced from cachedb_nats.c");

	/* mod_init wires exports.procs only when both knobs are on */
	ASSERT(file_contains("../cachedb_nats.c",
		"if (nats_enable_search_index && nats_dedicated_watcher_proc)"),
		"mod_init gates exports.procs on both flags");
	ASSERT(file_contains("../cachedb_nats.c",
		"exports.procs ="),
		"mod_init assigns exports.procs at runtime");

	/* The dedicated proc main lives in cachedb_nats_watch.c */
	ASSERT(file_contains("../cachedb_nats_watch.c",
		"void nats_watcher_proc_main"),
		"nats_watcher_proc_main defined in cachedb_nats_watch.c");

	/* Header export so cachedb_nats.c can see the symbol */
	ASSERT(file_contains("../cachedb_nats_watch.h",
		"nats_watcher_proc_main"),
		"nats_watcher_proc_main declared in cachedb_nats_watch.h");

	/* The rank-1 pthread spawn must be skipped when the dedicated
	 * process is in use -- otherwise we'd run the watcher twice. */
	ASSERT(file_contains("../cachedb_nats.c",
		"!nats_dedicated_watcher_proc"),
		"child_init skips rank-1 pthread when dedicated proc on");

	/* destroy() must skip nats_watch_stop() when the dedicated
	 * proc owns the watcher -- the pthread state is in another
	 * process and pthread_join() from main would deadlock. */
	ASSERT(file_contains("../cachedb_nats.c",
		"if (!nats_dedicated_watcher_proc)"),
		"destroy() skips watch_stop in dedicated mode");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
