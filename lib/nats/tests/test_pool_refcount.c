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
 * Regression test: nats_pool_destroy() was called only from event_nats's
 * mod_destroy.  That is the wrong owner for a library shared by three
 * modules: it tears down the connection while cachedb_nats / nats_consumer
 * may still be using it, and when event_nats is NOT loaded the pool is
 * never destroyed at all.  Separately, jsCtx_Destroy ran BEFORE any wait
 * for in-flight async publishes (so pending JetStream acks were
 * abandoned), and event_nats freed its stats table BEFORE the pool, so a
 * late cnats ack callback could bump freed stats memory.
 *
 * Fix:
 *   - reference-count registrations: nats_pool_register() bumps a counter,
 *     nats_pool_unregister() decrements it and only tears the pool down on
 *     the LAST unregister; every module unregisters in mod_destroy;
 *   - js_PublishAsyncComplete() before jsCtx_Destroy() (bounded wait);
 *   - event_nats clears the pub-ack callback and destroys its stats AFTER
 *     unregistering the pool.
 *
 * The refcount decision is modelled here; production wiring is checked by
 * source pattern.
 *   -DSIMULATE_PREFIX_BUG -> first unregister tears the pool down even
 *                            though other modules still hold it -> FAIL.
 *   (default)             -> teardown only on the last unregister -> PASS.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_pool_refcount test_pool_refcount.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ── refcount model ──────────────────────────────────────────────── */

static int g_count;
static int g_torn_down;

static void sim_register(void)  { g_count++; }
static void sim_unregister(void)
{
#ifdef SIMULATE_PREFIX_BUG
	/* pre-fix: event_nats's mod_destroy tears down unconditionally,
	 * regardless of whether other modules still hold the pool. */
	g_torn_down++;
#else
	if (--g_count <= 0) { g_count = 0; g_torn_down++; }
#endif
}

/* ── source-pattern helper ───────────────────────────────────────── */

static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f);
	return hits;
}

/* Order check: does @first appear before @second in @fn's body? */
static int order_in_function(const char *path, const char *fn,
	const char *first, const char *second)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048]; int seen=0, in=0, saw_first=0, ok=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) {
			if (line[0]=='}') break;
			if (strstr(line, first))  saw_first = 1;
			if (strstr(line, second) && saw_first) { ok = 1; break; }
			continue;
		}
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f);
	return ok;
}

int main(void)
{
	/* Three modules register and later unregister. */
	sim_register(); sim_register(); sim_register();

	sim_unregister();
	ASSERT(g_torn_down == 0,
		"first unregister of 3 does NOT tear the pool down");
	sim_unregister();
	ASSERT(g_torn_down == 0, "second unregister still does not tear down");
	sim_unregister();
	ASSERT(g_torn_down == 1, "last unregister tears the pool down exactly once");

	/* ── production wiring ──────────────────────────────────────── */
	const char *pool = "../nats_pool.c";

	ASSERT(grep_in_function(pool, "nats_pool_register", "_register_count") >= 1,
		"nats_pool_register bumps the registration refcount");
	ASSERT(grep_in_function(pool, "nats_pool_unregister", "_register_count") >= 1,
		"nats_pool_unregister decrements the refcount and tears down at 0");
	ASSERT(order_in_function(pool, "nats_pool_destroy",
		"js_PublishAsyncComplete", "jsCtx_Destroy"),
		"nats_pool_destroy waits for async publishes before jsCtx_Destroy");

	const char *en = "../../../modules/event_nats/event_nats.c";
	ASSERT(order_in_function(en, "mod_destroy",
		"nats_pool_unregister", "nats_stats_destroy"),
		"event_nats mod_destroy destroys stats AFTER unregistering the pool");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
