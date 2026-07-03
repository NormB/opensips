/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #29 (survivability): the KV watcher subscribes
 * with UpdatesOnly, so writes made by sibling instances WHILE this process
 * is disconnected never enter the in-memory search index.  Convergence
 * relied on a post-reconnect full rebuild gated by index_resync_on_reconnect
 * -- which defaulted to 0, so by default the index silently diverged after
 * any outage during which writes occurred.
 *
 * Fix (chosen approach): default index_resync_on_reconnect to 1, so every
 * reconnect rebuilds the index in full and converges.  Operators with
 * large-index / hot-reconnect topologies can still set it to 0 and rely on
 * the periodic resync timer (#28) + query-time stale-entry self-heal.
 *
 * This test carries the convergence model (resync=1 captures missed writes;
 * resync=0 does not, on the reconnect path) and asserts the production
 * default + that the in-tree comments agree on it.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_index_converge test_index_converge.c
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

/* ---- carried model: does the index converge after a missed-write outage? */

/* The watcher uses UpdatesOnly, so live deltas during an outage are lost.
 * The index converges iff a full rebuild runs on reconnect. */
static int index_converges(int resync_on_reconnect, int writes_during_outage)
{
	int index_has_writes = 0;        /* started consistent */
	/* ...outage: sibling instances perform `writes_during_outage` writes;
	 * UpdatesOnly means we receive none of them live... */
	/* ...reconnect: */
	if (resync_on_reconnect)
		index_has_writes = 1;        /* full rebuild reloads everything */
	/* else: only the periodic timer / lazy self-heal will catch up later */
	if (writes_during_outage == 0)
		return 1;                    /* nothing to miss */
	return index_has_writes;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		ASSERT(index_converges(1, 5) == 1,
			"resync=1 converges the index after missed writes");
		ASSERT(index_converges(0, 5) == 0,
			"resync=0 does NOT converge on the reconnect path alone");
		ASSERT(index_converges(0, 0) == 1,
			"no missed writes -> already converged regardless");
	}

	/* ---- production default is now 1 ---------------------------- */
	{
		const char *c = "../cachedb_nats.c";
		ASSERT(file_contains(c, "int index_resync_on_reconnect = 1;"),
			"index_resync_on_reconnect defaults to 1");
		ASSERT(!file_contains(c, "int index_resync_on_reconnect = 0;"),
			"the old 0 default is gone");
		/* the doc comment must agree (no stale 'default 0') */
		ASSERT(file_contains(c, "index_resync_on_reconnect (default 1)"),
			"cachedb_nats.c doc comment says default 1");
		ASSERT(!file_contains(c, "index_resync_on_reconnect (default 0)"),
			"stale 'default 0' doc comment removed");
	}

	/* ---- watcher still honours the flag (opt-out path intact) ---- */
	{
		const char *w = "../cachedb_nats_watch.c";
		ASSERT(file_contains(w, "if (cdbn_fts_on && index_resync_on_reconnect)"),
			"watcher rebuilds on reconnect when the flag is set "
			"(and the FTS module is bound, P1.2)");
		ASSERT(file_contains(w, "cdbn_fts.rebuild"),
			"watcher calls the full index rebuild via the binds");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
