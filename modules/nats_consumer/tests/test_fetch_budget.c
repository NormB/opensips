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
 * Regression test: the consumer process's main loop fetched from every
 * bound subscription serially, each with a blocking Fetch of up to the
 * full fetch_timeout (default 1000ms), and only THEN drained acks and
 * async-RPC publishes.  With N (mostly idle) handles, that sweep blocked
 * for up to N * fetch_timeout before servicing acks/RPCs -- head-of-line
 * blocking that inflates ack latency past ack_wait (broker redelivery) and
 * times out async RPCs.
 *
 * Fix: budget the per-fetch wait by the number of handles so the WHOLE
 * sweep stays bounded at ~one fetch_timeout (fetch_budget_ms), and drain
 * the RPC publish IPC between fetches.
 *
 * This carries a copy of fetch_budget_ms and models the worst-case sweep.
 *   -DSIMULATE_PREFIX_BUG -> every fetch uses the full timeout: the sweep
 *                            is N * fetch_timeout -> the "bounded" assert
 *                            FAILS.
 *   (default)             -> budgeted: sweep ~= fetch_timeout -> ALL PASS.
 * Plus source-pattern checks that production wires it in.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_fetch_budget test_fetch_budget.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

#define NATS_FETCH_MIN_BUDGET_MS  5

/* Carried copy of nats_consumer_proc.c::fetch_budget_ms. */
static int fetch_budget_ms(int configured, int num_subs)
{
#ifdef SIMULATE_PREFIX_BUG
	(void)num_subs;
	return configured;       /* pre-fix: every fetch waits the full timeout */
#else
	int b;
	if (num_subs <= 1)
		return 0;
	b = configured / num_subs;
	if (b < NATS_FETCH_MIN_BUDGET_MS) b = NATS_FETCH_MIN_BUDGET_MS;
	if (b > configured) b = configured;
	return b;
#endif
}

/* Effective per-fetch wait (mirror of pull_one_batch's cap). */
static int eff_fetch(int configured, int budget)
{
	return (budget > 0 && budget < configured) ? budget : configured;
}

/* Worst-case sweep time = sum of per-fetch waits over all idle handles. */
static long sweep_ms(int configured, int num_subs)
{
	int budget = fetch_budget_ms(configured, num_subs);
	return (long)num_subs * eff_fetch(configured, budget);
}

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

int main(void)
{
	const int T = 1000;   /* configured fetch_timeout_ms */

	/* Single handle: full idle wait, sweep == one timeout. */
	ASSERT(sweep_ms(T, 1) == T, "single handle sweeps for one fetch_timeout");

	/* Ten idle handles: the WHOLE sweep must stay ~one timeout, not 10x.
	 * Under the pre-fix code each fetch waits the full timeout (10*T). */
	ASSERT(sweep_ms(T, 10) <= T,
		"ten idle handles sweep within one fetch_timeout (no N*T blocking)");

	/* Even at extreme fan-out the sweep is bounded by N*floor, not N*T. */
	ASSERT(sweep_ms(T, 1000) <= 1000 * NATS_FETCH_MIN_BUDGET_MS,
		"1000 handles sweep bounded by the per-fetch floor, not N*timeout");

	/* Production wiring. */
	const char *src = "../nats_consumer_proc.c";
	ASSERT(grep_in_function(src, "pull_one_batch", "budget_ms") >= 1,
		"pull_one_batch honours a per-fetch budget");
	ASSERT(grep_in_function(src, "nats_consumer_proc_main", "fetch_budget_ms") >= 1,
		"main loop budgets the fetch sweep");
	ASSERT(grep_in_function(src, "nats_consumer_proc_main",
		"pump_worker_ipc") >= 2,
		"main loop pumps the worker IPC between fetches (not only after)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
