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
 * Wiring test: cachedb_nats exposes two operator knobs for index
 * resync coordination across multi-instance / multi-DC deployments.
 *
 *   index_resync_on_reconnect (int, default 1)
 *     Controls whether the KV-watcher thread issues a full
 *     nats_json_index_rebuild() after each reconnect. With
 *     stale-entry self-healing on index hits, operators may prefer
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

	/* [P3.3] The periodic resync no longer rides the shared core timer
	 * process: it is hosted by the dedicated reaper process, gated on
	 * the same interval modparam. */
	ASSERT(!file_contains("../cachedb_nats.c", "register_timer"),
		"no shared-core-timer registration remains in mod_init");
	ASSERT(file_contains("../cachedb_nats_expiry.c",
		"index_resync_interval_secs"),
		"the reaper proc consults index_resync_interval_secs");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
