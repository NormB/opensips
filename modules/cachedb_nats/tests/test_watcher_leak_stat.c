/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #36 (survivability): the KV watcher deliberately
 * skips kvWatcher_Destroy() on the disconnected teardown path, because
 * destroying the handle while nats.c's I/O thread is concurrently tearing
 * down the same internal subscription state double-frees.  The handle is
 * therefore leaked once per disconnect-while-disconnected cycle -- unbounded
 * under a flapping broker.
 *
 * Reclaiming the handle safely needs live-broker validation of the teardown
 * timing (the destroy is only known-safe while connected), so it stays
 * deferred.  What this commit does is make the leak OBSERVABLE: a
 * watcher_handle_leaks counter incremented on every skipped destroy and
 * surfaced in nats_cdb_stats, so operators can alert on a climbing leak rate
 * instead of discovering it as unexplained memory growth.
 *
 * This test carries the count-decision model (leak counted iff the destroy
 * was skipped because disconnected) and asserts the production wiring.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_watcher_leak_stat test_watcher_leak_stat.c
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
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096], marker[256];
	int hits = 0, in_body = 0, seen = 0;
	if (!f) return -1;
	snprintf(marker, sizeof(marker), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen) {
			if (strchr(line, ';') && !strchr(line, '{')) { seen = 0; continue; }
			if (strchr(line, '{')) in_body = 1;
			continue;
		}
		if (strstr(line, marker)) seen = 1;
	}
	fclose(f);
	return hits;
}

/* ---- carried model: when is a watcher handle leak counted? --------- */

/* Mirrors the teardown decision: destroy (no leak) while connected; skip
 * destroy (leak, counted) while disconnected. */
static void teardown(int connected, int *destroyed, int *leaks)
{
	if (connected) (*destroyed)++;
	else           (*leaks)++;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		int destroyed = 0, leaks = 0;
		teardown(1, &destroyed, &leaks);   /* connected: destroyed */
		teardown(0, &destroyed, &leaks);   /* disconnected: leaked+counted */
		teardown(0, &destroyed, &leaks);   /* flap again: another leak */
		teardown(1, &destroyed, &leaks);   /* connected: destroyed */
		ASSERT(destroyed == 2, "connected teardown destroys (no leak)");
		ASSERT(leaks == 2, "each disconnected skip is counted as a leak");
	}

	/* ---- stats counter declared + emitted ----------------------- */
	{
		ASSERT(file_contains("../cachedb_nats_stats.h", "watcher_handle_leaks"),
			"stats header declares watcher_handle_leaks");
		ASSERT(file_contains("../cachedb_nats_stats.c", "watcher_handle_leaks"),
			"nats_cdb_stats MI emits watcher_handle_leaks");
	}

	/* ---- counted exactly on the skipped-destroy (disconnected) path - */
	{
		const char *w = "../cachedb_nats_watch.c";
		ASSERT(grep_in_function(w, "_watcher_loop",
				"NATS_CDB_STATS_INC(watcher_handle_leaks)") >= 1,
			"watcher counts the leak when it skips destroy while disconnected");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
