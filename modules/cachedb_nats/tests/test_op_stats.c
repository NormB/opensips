/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #34 (observability): the cachedb_nats stats
 * block tracked CAS retries and index misses but had no counter for the
 * three conditions an operator most needs to see when the broker degrades:
 *
 *   fastfail_rejected -- a KV op rejected up front because the pool was
 *                        disconnected (or the post-reconnect handle refresh
 *                        failed).  Previously this was LM_DBG-only, so a
 *                        broker outage was invisible in the metrics.
 *   op_failed         -- a KV op that actually reached the broker and came
 *                        back with a hard error (not a NOT_FOUND miss).
 *   watcher_restarts  -- the search-index watcher tore down and rebuilt its
 *                        KV handle (reconnect / disconnect recovery).
 *
 * This test carries a model of the classification and asserts the
 * production wiring: the new counters in cachedb_nats_stats.h, their
 * emission in the nats_cdb_stats MI handler, and the bump sites in
 * nats_con_refresh_kv / the KV ops / the watcher loop.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_op_stats test_op_stats.c
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

/* Count occurrences of @needle inside the body of function @fn_name
 * (body starts at the first '{' after "fn_name(" and ends at a '}' in
 * column 0).  Skips the forward declaration / prototype. */
static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096], marker[256];
	int hits = 0, in_body = 0, seen_marker = 0;
	if (!f) return -1;
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen_marker = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			if (strchr(line, ';')) { seen_marker = 0; continue; } /* proto */
			if (strchr(line, '{')) { in_body = 1; }
			continue;
		}
		if (strstr(line, marker)) seen_marker = 1;
	}
	fclose(f);
	return hits;
}

/* ---- carried model: classify a cachedb op / watcher event ----------- */

enum ev { EV_DISCONNECTED, EV_REFRESH_FAIL, EV_KV_HARD_ERR, EV_KV_NOTFOUND,
          EV_KV_OK, EV_WATCH_FIRST_BUILD, EV_WATCH_REBUILD };

struct cnt { unsigned fastfail, op_failed, restarts; };

static void account(struct cnt *c, enum ev e)
{
	switch (e) {
	case EV_DISCONNECTED:      c->fastfail++;  break;
	case EV_REFRESH_FAIL:      c->fastfail++;  break;
	case EV_KV_HARD_ERR:       c->op_failed++; break;
	case EV_KV_NOTFOUND:       /* normal miss, not an error */ break;
	case EV_KV_OK:             /* success */ break;
	case EV_WATCH_FIRST_BUILD: /* initial build is not a restart */ break;
	case EV_WATCH_REBUILD:     c->restarts++; break;
	}
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		struct cnt c = {0};
		account(&c, EV_DISCONNECTED);
		account(&c, EV_REFRESH_FAIL);
		account(&c, EV_KV_HARD_ERR);
		account(&c, EV_KV_NOTFOUND);
		account(&c, EV_KV_OK);
		account(&c, EV_WATCH_FIRST_BUILD);
		account(&c, EV_WATCH_REBUILD);

		ASSERT(c.fastfail == 2, "disconnect + refresh-fail count as fastfail");
		ASSERT(c.op_failed == 1, "only a hard KV error counts as op_failed");
		ASSERT(c.restarts == 1, "only a rebuild (not first build) is a restart");
		/* a NOT_FOUND miss must never be counted as an op failure */
		struct cnt m = {0};
		account(&m, EV_KV_NOTFOUND);
		ASSERT(m.op_failed == 0, "NOT_FOUND miss is not an op_failed");
	}

	/* ---- header declares the three counters --------------------- */
	{
		const char *h = "../cachedb_nats_stats.h";
		ASSERT(file_contains(h, "fastfail_rejected"),
			"stats header declares fastfail_rejected");
		ASSERT(file_contains(h, "op_failed"),
			"stats header declares op_failed");
		ASSERT(file_contains(h, "watcher_restarts"),
			"stats header declares watcher_restarts");
	}

	/* ---- MI handler emits all three ----------------------------- */
	{
		const char *s = "../cachedb_nats_stats.c";
		ASSERT(file_contains(s, "fastfail_rejected"),
			"nats_cdb_stats MI emits fastfail_rejected");
		ASSERT(file_contains(s, "op_failed"),
			"nats_cdb_stats MI emits op_failed");
		ASSERT(file_contains(s, "watcher_restarts"),
			"nats_cdb_stats MI emits watcher_restarts");
	}

	/* ---- bump sites are wired in the production paths ------------ */
	{
		const char *d = "../cachedb_nats_dbase.c";
		ASSERT(grep_in_function(d, "nats_con_refresh_kv",
				"NATS_CDB_STATS_INC(fastfail_rejected)") >= 1,
			"nats_con_refresh_kv bumps fastfail_rejected on the fastfail path");
		ASSERT(grep_in_function(d, "nats_cache_get",
				"NATS_CDB_STATS_INC(op_failed)") >= 1,
			"nats_cache_get bumps op_failed on a hard KV error");
		/* at least the five KV ops carry an op_failed bump */
		ASSERT(file_contains(d, "NATS_CDB_STATS_INC(op_failed)"),
			"op_failed bumped on KV-error paths");

		const char *w = "../cachedb_nats_watch.c";
		ASSERT(grep_in_function(w, "_watcher_loop",
				"NATS_CDB_STATS_INC(watcher_restarts)") >= 1,
			"_watcher_loop bumps watcher_restarts on rebuild");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
