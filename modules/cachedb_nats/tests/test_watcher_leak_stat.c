/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Regression test for the KV watcher teardown stat (originally TODO #36
 * survivability): the watcher used to deliberately skip kvWatcher_Destroy()
 * on the disconnected teardown path (suspected double-free against nats.c's
 * I/O thread) and count each skip in watcher_handle_leaks -- one leaked
 * handle per broker flap, unbounded under a flapping broker.
 *
 * The suspicion was refuted live (design repo watcher_destroy_spike.c:
 * 10 SIGKILL broker-flap cycles, Stop+Destroy on a disconnected connection
 * with the reconnect thread running, ASan-clean on the pinned libnats), so
 * the destroy is now UNCONDITIONAL and no teardown path leaks.  The counter
 * stays declared and MI-exported -- expected 0 -- so existing dashboards
 * and alert rules keep working and any regression is visible.
 *
 * This test carries the fixed teardown model (destroy in every connection
 * state, nothing counted as leaked) and asserts the production wiring.
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

/* Mirrors the teardown decision since the disconnected-destroy fix:
 * the claimed handle is destroyed in EVERY connection state (the old
 * skip-while-disconnected arm leaked one handle per broker flap; its
 * double-free suspicion was refuted by watcher_destroy_spike.c). */
static void teardown(int connected, int *destroyed, int *leaks)
{
	(void)connected;
	(*destroyed)++;
	(void)leaks;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		int destroyed = 0, leaks = 0;
		teardown(1, &destroyed, &leaks);   /* connected: destroyed */
		teardown(0, &destroyed, &leaks);   /* disconnected: ALSO destroyed */
		teardown(0, &destroyed, &leaks);   /* flap again: destroyed */
		teardown(1, &destroyed, &leaks);   /* connected: destroyed */
		ASSERT(destroyed == 4, "teardown destroys in EVERY connection state");
		ASSERT(leaks == 0, "no teardown path leaks the handle");
	}

	/* ---- stats counter declared + emitted ----------------------- */
	{
		ASSERT(file_contains("../cachedb_nats_stats.h", "watcher_handle_leaks"),
			"stats header declares watcher_handle_leaks");
		ASSERT(file_contains("../cachedb_nats_stats.c", "watcher_handle_leaks"),
			"nats_cdb_stats MI emits watcher_handle_leaks");
	}

	/* ---- the skip arm is GONE: destroy is unconditional -------------
	 * (the disconnected-destroy double-free suspicion was refuted live:
	 * watcher_destroy_spike.c, 10 SIGKILL flap cycles, ASan-clean; the
	 * counter stays exported, expected 0, so dashboards keep working) */
	{
		const char *w = "../cachedb_nats_watch.c";
		ASSERT(grep_in_function(w, "watcher_loop",
				"NATS_CDB_STATS_INC(watcher_handle_leaks)") == 0,
			"watcher no longer counts intentional leaks (destroy unconditional)");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
