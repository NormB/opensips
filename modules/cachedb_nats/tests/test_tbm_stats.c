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
 * [TTL-BELOW-MARKER observability, Tier-2] The kv_ttl_below_marker
 * canary verdict used to live only in the reaper process (per-process
 * latch + log lines): an operator could not tell from MI whether the
 * broker's below-marker TTL support was requested, probed, verified,
 * or downgraded.  The verdict now rides the existing per-process shm
 * stats table as reaper-slot gauges (single writer -> cross-slot SUM
 * yields the plain value), surfaced by nats_cdb_stats:
 *
 *   tbm_requested        modparam (0/1), emitted straight from config
 *   tbm_probe_state      0 = unprobed, 1 = unsupported, 2 = supported
 *                        (pool state -1/0/1 stored +1, gauge)
 *   tbm_canary_verdict   0 = none yet, 1 = honored, 2 = broken (gauge)
 *   tbm_canary_last      epoch of the last verdict (gauge)
 *   tbm_canary_failures  count of SURVIVED (broken) verdicts (counter)
 *
 * Locks: field declarations (stats.h), MI emission (stats.c), and the
 * canary/probe write sites (expiry.c) -- plus a carried model of the
 * verdict transitions.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_tbm_stats
 *            test_tbm_stats.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, label) do { \
	if (cond) fprintf(stderr, "  ok: %s\n", (label)); \
	else { fprintf(stderr, "  FAIL: %s\n", (label)); g_fails++; } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ── carried model: verdict state machine ────────────────────────── */

struct tbm_model {
	long probe_state, verdict, last;
	long failures;
};

static void model_probe(struct tbm_model *m, int pool_state)
{	/* pool -1/0/1 -> gauge 0/1/2 */
	m->probe_state = pool_state + 1;
}

static void model_verdict(struct tbm_model *m, int honored, long now)
{
	m->verdict = honored ? 1 : 2;
	m->last = now;
	if (!honored)
		m->failures++;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		struct tbm_model m; memset(&m, 0, sizeof(m));
		ASSERT(m.verdict == 0, "no verdict before the first canary");
		model_probe(&m, 1);
		ASSERT(m.probe_state == 2, "pool state 1 (supported) -> gauge 2");
		model_verdict(&m, 1, 1000);
		ASSERT(m.verdict == 1 && m.last == 1000 && m.failures == 0,
			"honored: verdict 1, stamped, no failure");
		model_verdict(&m, 0, 2000);
		ASSERT(m.verdict == 2 && m.last == 2000 && m.failures == 1,
			"broken: verdict 2, stamped, failure counted");
		model_verdict(&m, 1, 3000);
		ASSERT(m.verdict == 1 && m.failures == 1,
			"later honored verdict recovers, failure count keeps history");
		model_probe(&m, 0);
		ASSERT(m.probe_state == 1, "pool state 0 (unsupported) -> gauge 1");
	}

	/* ---- stats fields declared ---------------------------------- */
	{
		const char *h = "../cachedb_nats_stats.h";
		ASSERT(file_contains(h, "tbm_probe_state"),
			"stats header declares tbm_probe_state");
		ASSERT(file_contains(h, "tbm_canary_verdict"),
			"stats header declares tbm_canary_verdict");
		ASSERT(file_contains(h, "tbm_canary_last"),
			"stats header declares tbm_canary_last");
		ASSERT(file_contains(h, "tbm_canary_failures"),
			"stats header declares tbm_canary_failures");
	}

	/* ---- MI emission -------------------------------------------- */
	{
		const char *c = "../cachedb_nats_stats.c";
		ASSERT(file_contains(c, "\"tbm_requested\""),
			"nats_cdb_stats emits tbm_requested");
		ASSERT(file_contains(c, "\"tbm_probe_state\""),
			"nats_cdb_stats emits tbm_probe_state");
		ASSERT(file_contains(c, "\"tbm_canary_verdict\""),
			"nats_cdb_stats emits tbm_canary_verdict");
		ASSERT(file_contains(c, "\"tbm_canary_last\""),
			"nats_cdb_stats emits tbm_canary_last");
		ASSERT(file_contains(c, "\"tbm_canary_failures\""),
			"nats_cdb_stats emits tbm_canary_failures");
	}

	/* ---- canary/probe write sites -------------------------------- */
	{
		const char *e = "../cachedb_nats_expiry.c";
		ASSERT(file_contains(e, "NATS_CDB_STATS_SET(tbm_probe_state"),
			"probe state stored as a gauge after bind");
		ASSERT(file_contains(e, "NATS_CDB_STATS_SET(tbm_canary_verdict"),
			"canary verdict stored as a gauge");
		ASSERT(file_contains(e, "NATS_CDB_STATS_SET(tbm_canary_last"),
			"canary verdict is timestamped");
		ASSERT(file_contains(e, "NATS_CDB_STATS_INC(tbm_canary_failures"),
			"SURVIVED verdict counts a failure");
	}

	if (g_fails == 0) { fprintf(stderr, "=== ALL PASS ===\n"); return 0; }
	fprintf(stderr, "=== FAILS=%d ===\n", g_fails);
	return 1;
}
