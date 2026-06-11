/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #34 (observability): the consumer process used
 * a single per-sub counter, total_dropped_backpressure, for two very
 * different events:
 *
 *   1. a PRE-FETCH SKIP -- the ring is already full so the Fetch is not
 *      even issued.  No message is touched; the un-fetched messages remain
 *      owned by the broker and are delivered cleanly on the next pull.
 *      This is pure flow control, NOT a drop.
 *
 *   2. a genuine per-message DEFER -- a message WAS fetched but could not
 *      be handed to the worker ring (msg-ref table exhausted, or ring full
 *      on push).  Not acked => the broker redelivers after ack_wait.
 *
 * Conflating (1) into a "dropped" counter makes the metric read as data
 * loss when it is actually back-pressure working as intended, and hides
 * the real defer rate.  The oversize case (Term) is a third thing again
 * and is already counted via the per-handle `terms` counter.
 *
 * Fix: split into three SHM per-handle counters so the attendant MI
 * process can read them:
 *   fetch_skips_full    -- (1), no message lost
 *   backpressure_drops  -- (2), fetched-but-deferred
 *   fetch_errors        -- Fetch returned a hard error
 * and stop double-classifying the oversize Term as a backpressure drop.
 *
 * This test carries a model of the classification (proving skip != drop)
 * and asserts the production wiring in ../nats_consumer_proc.c and
 * ../nats_handle_registry.h.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_backpressure_stats test_backpressure_stats.c
 */

#include <stdio.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ---- carried model: classify each consumer-loop outcome ------------- */

enum outcome {
	OC_SKIP_FULL,   /* ring full before fetch: no message touched     */
	OC_DROP_DEFER,  /* fetched but not delivered: broker redelivers    */
	OC_TERM,        /* oversize: terminated, counted as a Term         */
	OC_DELIVERED,   /* pushed to the ring                              */
	OC_FETCH_ERR    /* Fetch returned a hard error                     */
};

/* The three counters a correct classifier must keep distinct. */
struct counters { unsigned skips, drops, terms, delivered, errors; };

static void account(struct counters *c, enum outcome o)
{
	switch (o) {
	case OC_SKIP_FULL:  c->skips++;     break;  /* NOT a drop */
	case OC_DROP_DEFER: c->drops++;     break;
	case OC_TERM:       c->terms++;     break;  /* NOT a drop */
	case OC_DELIVERED:  c->delivered++; break;
	case OC_FETCH_ERR:  c->errors++;    break;
	}
}

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

int main(void)
{
	/* ---- model: a pre-fetch skip must NOT be counted as a drop ----- */
	{
		struct counters c = {0};
		/* one of each event */
		account(&c, OC_SKIP_FULL);
		account(&c, OC_DROP_DEFER);
		account(&c, OC_TERM);
		account(&c, OC_DELIVERED);
		account(&c, OC_FETCH_ERR);

		ASSERT(c.skips == 1, "pre-fetch skip increments skips");
		ASSERT(c.drops == 1, "only the genuine defer increments drops");
		ASSERT(c.terms == 1, "oversize is a Term, not a drop");
		ASSERT(c.delivered == 1, "delivered counted separately");
		ASSERT(c.errors == 1, "fetch error counted separately");
		/* The bug was: skips + terms folded into drops -> drops==3. */
		ASSERT(c.drops != 3, "skip and term are NOT folded into drops");
	}

	/* ---- production wiring: the SHM per-handle counters exist ------- */
	{
		const char *h = "../nats_handle_registry.h";
		ASSERT(file_contains(h, "fetch_skips_full"),
			"registry handle declares fetch_skips_full");
		ASSERT(file_contains(h, "backpressure_drops"),
			"registry handle declares backpressure_drops");
		ASSERT(file_contains(h, "fetch_errors"),
			"registry handle declares fetch_errors");
	}

	/* ---- production wiring: proc bumps the right SHM counter ------- */
	{
		const char *p = "../nats_consumer_proc.c";
		ASSERT(file_contains(p, "&ss->h_ref->fetch_skips_full"),
			"pre-fetch skip bumps SHM fetch_skips_full");
		ASSERT(file_contains(p, "&ss->h_ref->backpressure_drops"),
			"genuine defer bumps SHM backpressure_drops");
		ASSERT(file_contains(p, "&ss->h_ref->fetch_errors"),
			"fetch error bumps SHM fetch_errors");

		/* The mislabeled counter and the dead process-local duplicates
		 * are gone. */
		ASSERT(!file_contains(p, "total_dropped_backpressure"),
			"mislabeled total_dropped_backpressure removed");
		ASSERT(!file_contains(p, "total_fetch_errors"),
			"dead process-local total_fetch_errors removed");
		ASSERT(!file_contains(p, "total_pulled"),
			"dead process-local total_pulled removed");
		ASSERT(!file_contains(p, "total_pushed"),
			"dead process-local total_pushed removed");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
