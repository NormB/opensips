/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Coverage for TODO #74: the ensure_subscription_for_handle() retry backoff
 * in reconcile_subs_cb had no unit test.  A handle whose broker-side
 * consumer was deleted would otherwise retry js_AddConsumer/js_PullSubscribe
 * every reconcile tick (~1 s), flooding logs and starving fresh handles, so
 * the reconcile path applies an exponential backoff (1,2,4,...,32 s) capped
 * at 60 s, keyed on a per-handle failure counter, and resets to 0 on success.
 *
 * This carries the pure ensure_backoff_seconds() schedule and asserts the
 * production cap + the reconcile gating on ensure_next_retry_at.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_ensure_backoff test_ensure_backoff.c
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
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ---- carried copy of the schedule under test ----------------------- */

#define ENSURE_BACKOFF_CAP_S 60u

static unsigned ensure_backoff_seconds(unsigned failures)
{
	unsigned shift;
	if (failures == 0)
		return 0;
	shift = failures - 1;
	if (shift >= 6)            /* 1<<6 = 64 > cap; saturate */
		return ENSURE_BACKOFF_CAP_S;
	return 1u << shift;
}

int main(void)
{
	/* ---- schedule ---------------------------------------------- */
	ASSERT(ensure_backoff_seconds(0) == 0,  "0 failures -> no wait");
	ASSERT(ensure_backoff_seconds(1) == 1,  "1st failure -> 1 s");
	ASSERT(ensure_backoff_seconds(2) == 2,  "2nd failure -> 2 s");
	ASSERT(ensure_backoff_seconds(3) == 4,  "3rd failure -> 4 s");
	ASSERT(ensure_backoff_seconds(4) == 8,  "4th failure -> 8 s");
	ASSERT(ensure_backoff_seconds(5) == 16, "5th failure -> 16 s");
	ASSERT(ensure_backoff_seconds(6) == 32, "6th failure -> 32 s");

	/* ---- saturation: monotonic, capped, never overflows -------- */
	{
		unsigned f, prev = 0;
		int monotonic = 1, capped = 1;
		for (f = 1; f <= 1000; f++) {
			unsigned w = ensure_backoff_seconds(f);
			if (w < prev) monotonic = 0;
			if (w > ENSURE_BACKOFF_CAP_S) capped = 0;
			prev = w;
		}
		ASSERT(monotonic, "backoff is non-decreasing");
		ASSERT(capped, "backoff never exceeds the 60 s cap");
		ASSERT(ensure_backoff_seconds(7) == ENSURE_BACKOFF_CAP_S,
			"7th failure saturates at the cap (64 > cap)");
		ASSERT(ensure_backoff_seconds(1000) == ENSURE_BACKOFF_CAP_S,
			"huge failure count stays at the cap (no 1<<shift overflow)");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *p = "../nats_consumer_proc.c";
		ASSERT(file_contains(p, "#define ENSURE_BACKOFF_CAP_S 60u"),
			"production caps the backoff at 60 s");
		ASSERT(file_contains(p, "ensure_backoff_seconds(h->ensure_failures)"),
			"reconcile computes the wait from the failure count");
		ASSERT(file_contains(p, "now < h->ensure_next_retry_at"),
			"reconcile skips a handle until its retry time arrives");
		ASSERT(file_contains(p, "h->ensure_failures = 0"),
			"a successful ensure resets the failure counter");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
