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
 * Regression: the KV watcher (cachedb_nats_watch.c) rebuilt the FTS index from
 * a full KV snapshot and THEN created the UpdatesOnly watcher.  UpdatesOnly
 * delivers only mutations after the subscribe point, so any Put/Delete that
 * landed in the (snapshot, subscribe) window -- e.g. a sibling instance
 * registering an AoR during the O(N) rebuild -- was never delivered and stayed
 * missing from the index until the next reconnect (the read-path self-heal can
 * evict a stale entry but cannot resurrect a never-indexed key).
 *
 * Fix: subscribe FIRST, then rebuild.  The watcher's pending queue captures
 * mutations from subscribe-time, and the consume loop applies them after the
 * index swap; the snapshot/live overlap is idempotent (entry_add_key dedups,
 * removes are membership-gated).
 *
 * This asserts the ordering in the production source: kvStore_WatchMulti must
 * appear BEFORE the binds index rebuild in the watcher loop.
 *
 * Build: cc -g -O0 -Wall -o test_watcher_subscribe_order test_watcher_subscribe_order.c
 */

#include <stdio.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* 1-based line of the first line containing @needle, or 0 if absent. */
static int first_line_of(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int n = 0;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f)) {
		n++;
		if (strstr(line, needle)) { fclose(f); return n; }
	}
	fclose(f);
	return 0;
}

int main(void)
{
	const char *src = "../cachedb_nats_watch.c";
	int watch_line   = first_line_of(src, "kvStore_WatchMulti(&w");
	int rebuild_line = first_line_of(src, "cdbn_fts.rebuild(kv");

	ASSERT(watch_line > 0, "found kvStore_WatchMulti call in the watcher");
	ASSERT(rebuild_line > 0, "found the binds index-rebuild call in the watcher");
	ASSERT(watch_line > 0 && rebuild_line > 0 && watch_line < rebuild_line,
		"watcher subscribes (kvStore_WatchMulti) BEFORE it rebuilds the "
		"snapshot (cdbn_fts.rebuild) -- no (snapshot,subscribe) gap");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
