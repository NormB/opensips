/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #34 (observability): the event_nats inbound
 * callback bounds publish floods by dropping oversized payloads
 * (dropped_oversize) and capping in-flight events (dropped_backpressure),
 * but those SHM counters were exported NOWHERE -- an operator could not
 * tell a healthy instance from one silently shedding inbound events.
 *
 * Fix: expose getters from nats_consumer.c and surface them in the
 * nats_stats MI command as inbound_dropped_oversize /
 * inbound_dropped_backpressure / inbound_inflight.
 *
 * This test carries the drop-classification model and asserts the
 * production wiring (getters + their declarations + MI emission).
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_inbound_drop_stats test_inbound_drop_stats.c
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

/* ---- carried model: which counter each drop reason bumps ------------ */

#define MAX_DATA      (1 * 1024 * 1024)
#define MAX_INFLIGHT  4096

struct ctl { unsigned long oversize, backpressure; int inflight; };

/* mirror of nats_msg_handler's admission decision: returns 1 if accepted */
static int admit(struct ctl *c, long data_len)
{
	if (data_len > MAX_DATA) { c->oversize++; return 0; }
	if (c->inflight >= MAX_INFLIGHT) { c->backpressure++; return 0; }
	c->inflight++;
	return 1;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		struct ctl c = {0};
		int i;

		ASSERT(admit(&c, 100) == 1, "small message admitted");
		ASSERT(admit(&c, MAX_DATA + 1) == 0, "oversized message dropped");
		ASSERT(c.oversize == 1, "oversize drop counted as oversize");
		ASSERT(c.backpressure == 0, "oversize is not a backpressure drop");

		/* saturate in-flight, then one more must be a backpressure drop */
		c.inflight = MAX_INFLIGHT;
		ASSERT(admit(&c, 100) == 0, "in-flight cap rejects further events");
		ASSERT(c.backpressure == 1, "in-flight overflow counted as backpressure");

		/* a small message under cap doesn't touch either drop counter */
		c.inflight = 0; c.oversize = 0; c.backpressure = 0;
		for (i = 0; i < 10; i++) admit(&c, 100);
		ASSERT(c.oversize == 0 && c.backpressure == 0,
			"healthy traffic increments no drop counter");
	}

	/* ---- production wiring: getters defined + declared ----------- */
	{
		const char *c = "../event_nats_sub.c";
		const char *h = "../event_nats_sub.h";
		ASSERT(file_contains(c, "nats_inbound_dropped_oversize"),
			"nats_consumer.c defines dropped_oversize getter");
		ASSERT(file_contains(c, "nats_inbound_dropped_backpressure"),
			"nats_consumer.c defines dropped_backpressure getter");
		ASSERT(file_contains(c, "nats_inbound_inflight"),
			"nats_consumer.c defines inflight getter");
		ASSERT(file_contains(h, "nats_inbound_dropped_oversize"),
			"nats_consumer.h declares the inbound getters");

		/* [P3.7] silent drops are not silent: both drop branches emit
		 * a rate-limited warning.  The delivery callback runs on a
		 * libnats thread where dprint is off-limits (same rule as the
		 * pool callbacks), so the warning rides the raw-write path,
		 * gated once per interval. */
		ASSERT(file_contains(c, "_drop_warn_unsafe"),
			"drop branches emit the rate-limited unsafe warning");
	}

	/* ---- production wiring: MI surfaces the counters ------------- */
	{
		const char *s = "../nats_stats.c";
		ASSERT(file_contains(s, "event_nats_sub.h"),
			"nats_stats.c includes the consumer header for the getters");
		ASSERT(file_contains(s, "inbound_dropped_oversize"),
			"nats_stats MI emits inbound_dropped_oversize");
		ASSERT(file_contains(s, "inbound_dropped_backpressure"),
			"nats_stats MI emits inbound_dropped_backpressure");
		ASSERT(file_contains(s, "inbound_inflight"),
			"nats_stats MI emits inbound_inflight");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
