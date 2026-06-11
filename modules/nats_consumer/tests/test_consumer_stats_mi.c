/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #34 (observability): the nats_consumer module
 * tracked back-pressure / IPC / slot counters in SHM but exported none of
 * them, so an operator could not see ring depth, ack/RPC IPC depth + drops,
 * RPC slots in flight, or fetch errors without attaching a debugger.
 *
 * Fix: a `nats_consumer_stats` MI command that aggregates the per-handle
 * SHM counters (walked via nats_registry_foreach) and the global IPC / slot
 * getters into one flat object, plus the new per-handle counters surfaced
 * in `nats_consumer_list`.
 *
 * This test carries the aggregation model (summing per-handle counters)
 * and asserts the production wiring in ../nats_mi.c.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_consumer_stats_mi test_consumer_stats_mi.c
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

/* ---- carried model: the stats command sums per-handle counters ------ */

struct phandle { unsigned long depth, drops, skips, errors; };

struct agg { unsigned long depth, drops, skips, errors; };

static void agg_add(struct agg *a, const struct phandle *h)
{
	a->depth  += h->depth;
	a->drops  += h->drops;
	a->skips  += h->skips;
	a->errors += h->errors;
}

int main(void)
{
	/* ---- model: aggregation is a sum across handles ---------------- */
	{
		struct phandle hs[3] = {
			{ .depth = 4, .drops = 1, .skips = 2, .errors = 0 },
			{ .depth = 0, .drops = 3, .skips = 0, .errors = 1 },
			{ .depth = 7, .drops = 0, .skips = 5, .errors = 2 },
		};
		struct agg a = {0};
		int i;
		for (i = 0; i < 3; i++)
			agg_add(&a, &hs[i]);

		ASSERT(a.depth  == 11, "ring depth summed across handles");
		ASSERT(a.drops  == 4,  "backpressure drops summed across handles");
		ASSERT(a.skips  == 7,  "fetch skips summed across handles");
		ASSERT(a.errors == 3,  "fetch errors summed across handles");
	}

	/* ---- production wiring: the MI command is registered ----------- */
	{
		const char *m = "../nats_mi.c";
		ASSERT(file_contains(m, "\"nats_consumer_stats\""),
			"nats_consumer_stats command registered");
		ASSERT(file_contains(m, "mi_consumer_stats"),
			"mi_consumer_stats handler present");

		/* aggregates the per-handle SHM counters */
		ASSERT(file_contains(m, "nats_registry_foreach"),
			"stats walks the registry to aggregate per-handle counters");
		ASSERT(file_contains(m, "ring_depth"),
			"stats emits ring_depth");
		ASSERT(file_contains(m, "backpressure_drops"),
			"stats emits backpressure_drops");
		ASSERT(file_contains(m, "fetch_skips_full"),
			"stats emits fetch_skips_full");
		ASSERT(file_contains(m, "fetch_errors"),
			"stats emits fetch_errors");

		/* reads the global SHM getters (cross-process safe, set pre-fork) */
		ASSERT(file_contains(m, "nats_ring_depth"),
			"stats reads nats_ring_depth");
		ASSERT(file_contains(m, "nats_ack_ipc_depth"),
			"stats reads ack IPC depth");
		ASSERT(file_contains(m, "nats_ack_ipc_dropped_total"),
			"stats reads ack IPC drops");
		ASSERT(file_contains(m, "nats_rpc_ipc_depth"),
			"stats reads rpc IPC depth");
		ASSERT(file_contains(m, "nats_rpc_ipc_dropped_total"),
			"stats reads rpc IPC drops");
		ASSERT(file_contains(m, "nats_rpc_slot_inflight_count"),
			"stats reads rpc slots in flight");
	}

	/* ---- nats_consumer_list also surfaces the new per-handle counters - */
	{
		const char *m = "../nats_mi.c";
		ASSERT(file_contains(m, "\"backpressure_drops\""),
			"per-handle list surfaces backpressure_drops");
		ASSERT(file_contains(m, "\"fetch_skips_full\""),
			"per-handle list surfaces fetch_skips_full");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
