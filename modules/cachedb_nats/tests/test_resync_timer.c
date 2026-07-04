/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the periodic index-resync timer handler early-returned
 * on !nats_pool_is_connected().  That flag is process-local and only set
 * after a process calls nats_pool_get(); the timer runs in OpenSIPS's
 * timer process, which never connects on its own, so the flag was always
 * 0 and EVERY tick was silently skipped -- the periodic rebuild never ran.
 *
 * Fix: drop the dead gate and call nats_pool_get_kv() directly, which
 * lazily establishes the connection on first use (and returns NULL,
 * skipping just that tick, if the broker is genuinely down).
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_resync_timer test_resync_timer.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	const char *src = "../cachedb_nats_watch.c";   /* [P2.7] body moved */

	ASSERT(grep_in_function(src, "nats_cdb_periodic_resync",
		"nats_pool_is_connected") == 0,
		"resync handler no longer gates on the process-local _connected flag");
	ASSERT(grep_in_function(src, "nats_cdb_periodic_resync",
		"nats_pool_get_kv") >= 1,
		"resync handler lazily connects via nats_pool_get_kv");
	ASSERT(grep_in_function(src, "nats_cdb_periodic_resync",
		"cdbn_fts.rebuild") >= 1,
		"resync handler still rebuilds the index");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
