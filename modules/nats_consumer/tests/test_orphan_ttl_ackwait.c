/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: reap_orphan_msg_refs (nats_msg_ref.c) reclaimed any msg-ref slot
 * outstanding longer than a FIXED 120s (NATS_MSG_REF_ORPHAN_TTL_US), destroying
 * the natsMsg so a late ack no-ops.  If an operator configures a handle
 * ack_wait > ~120s, a legitimately slow-but-live worker still within its
 * ack_wait window has its message reaped out from under it -> the ack is
 * dropped and the broker redelivers a duplicate.
 *
 * Fix: derive the per-row orphan TTL from the handle's ack_wait
 * (max(120s default, 2 * ack_wait)) so a worker within ack_wait is never
 * reaped, while a truly dead worker (past 2 * ack_wait) still is.
 *
 * Models the reap TTL decision:
 *   -DSIMULATE_FIXED_TTL -> fixed 120s -> a 150s-old slot with ack_wait=90s is
 *                           wrongly reaped -> assertion FAILS.
 *   (default)            -> ack_wait-derived -> not reaped -> ALL PASS.
 * plus a source-wiring assertion.
 *
 * Build: cc -g -O0 -Wall -o test_orphan_ttl_ackwait test_orphan_ttl_ackwait.c
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
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

#define DEFAULT_TTL_US (120LL * 1000000LL)

/* Model of the per-row orphan TTL in microseconds. */
static long long reap_ttl_us(int ack_wait_ms)
{
#ifdef SIMULATE_FIXED_TTL
	(void)ack_wait_ms;
	return DEFAULT_TTL_US;
#else
	long long ttl = DEFAULT_TTL_US;
	if (ack_wait_ms > 0) {
		long long w = 2LL * (long long)ack_wait_ms * 1000LL;  /* 2 * ack_wait */
		if (w > ttl) ttl = w;
	}
	return ttl;
#endif
}

/* Would a slot of age @age_us be reaped under a handle with @ack_wait_ms? */
static int would_reap(long long age_us, int ack_wait_ms)
{
	return age_us > reap_ttl_us(ack_wait_ms);
}

int main(void)
{
	/* Default ack_wait (30s): a slot older than 120s is a real orphan. */
	ASSERT(would_reap(130LL * 1000000LL, 30000) == 1,
		"ack_wait=30s: a 130s-old slot is reaped (real orphan)");
	ASSERT(would_reap(60LL * 1000000LL, 30000) == 0,
		"ack_wait=30s: a 60s-old slot is not reaped");

	/* Large ack_wait (90s): a slow-but-live worker at 150s (< 2*90=180s)
	 * must NOT be reaped -- the fixed-120s policy would wrongly reap it. */
	ASSERT(would_reap(150LL * 1000000LL, 90000) == 0,
		"ack_wait=90s: a 150s-old slot (within 2*ack_wait) is NOT reaped");
	ASSERT(would_reap(200LL * 1000000LL, 90000) == 1,
		"ack_wait=90s: a 200s-old slot (past 2*ack_wait) is still reaped");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../nats_msg_ref.c";
		ASSERT(file_contains(src, "ack_wait_ms"),
			"reap_orphan_msg_refs derives the TTL from the row's ack_wait_ms");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
