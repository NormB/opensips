/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 2 wiring test: cachedb_nats exposes two operator knobs for
 * index resync coordination across multi-instance / multi-DC
 * deployments.
 *
 *   index_resync_on_reconnect (int, default 1)
 *     Controls whether the KV-watcher thread issues a full
 *     nats_json_index_rebuild() after each reconnect. With Phase
 *     1.4 self-healing on stale-index hits, operators may prefer
 *     to skip the O(N) rebuild and accept slight staleness.
 *
 *   index_resync_interval_secs (int, default 0 = off)
 *     Optional periodic full rebuild on a timer. Belt-and-braces
 *     for high-churn deployments where indexes can drift faster
 *     than the self-heal pace.
 *
 * Both are declared as INT_PARAM and have non-NULL default storage
 * locations in cachedb_nats.c. The watcher reads them at the
 * appropriate point in its event loop.
 *
 * This test is structural — it greps the production source for the
 * required declarations and call sites. Build:
 *   gcc -g -O0 -Wall -o test_resync_modparams test_resync_modparams.c
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
	/* Modparam declarations live in cachedb_nats.c */
	ASSERT(file_contains("../cachedb_nats.c",
		"\"index_resync_on_reconnect\""),
		"index_resync_on_reconnect modparam declared");
	ASSERT(file_contains("../cachedb_nats.c",
		"\"index_resync_interval_secs\""),
		"index_resync_interval_secs modparam declared");

	/* Watcher honors index_resync_on_reconnect on epoch change */
	ASSERT(file_contains("../cachedb_nats_watch.c",
		"index_resync_on_reconnect"),
		"watcher consults index_resync_on_reconnect on epoch change");

	/* Timer registered when interval > 0 */
	ASSERT(file_contains("../cachedb_nats.c",
		"register_timer"),
		"periodic resync timer registered in mod_init");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
