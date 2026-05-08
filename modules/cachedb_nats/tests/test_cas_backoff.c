/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 1.3 fix: nats_cache_update and nats_cache_add/sub used a
 * hot-spin CAS retry loop with no backoff. On heavy contention this
 * pegged the worker on the broker and let exhaustion silently drop
 * the write. Replace with bounded jittered exponential backoff.
 *
 * This file tests the pure deterministic upper-bound helper
 * _cas_backoff_max_us(attempt) used by both CAS loops:
 *   - returns 0 for attempt 0 (no delay before first retry)
 *   - exponential growth: 50, 100, 200, ... µs
 *   - capped at 5000 µs (5 ms ceiling)
 *   - never larger than the cap regardless of attempt count
 *
 * The actual sleep uses full-jitter (random in [0, max]) which is not
 * tested here because randomness; only the upper bound is asserted.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_cas_backoff \
 *     test_cas_backoff.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── carried copy of the helper under test ───────────────────────── */

#define NATS_CAS_BACKOFF_BASE_US   50UL
#define NATS_CAS_BACKOFF_CAP_US    5000UL

static unsigned long _cas_backoff_max_us(int attempt)
{
	unsigned long us;
	if (attempt <= 0)
		return 0;
	/* Clamp shift count well above the natural saturation of the cap so
	 * the cap is what bounds the value, not the shift; avoids UB when
	 * very large attempt counts arrive. */
	if (attempt > 16)
		attempt = 16;
	us = NATS_CAS_BACKOFF_BASE_US << (attempt - 1);
	if (us > NATS_CAS_BACKOFF_CAP_US)
		us = NATS_CAS_BACKOFF_CAP_US;
	return us;
}

/* ─── tests ───────────────────────────────────────────────────────── */

static int g_fails;

static void check_eq(const char *label, unsigned long got, unsigned long want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s\n  got:      %lu\n  expected: %lu\n",
			label, got, want);
		g_fails++;
		return;
	}
	fprintf(stderr, "  ok: %s -> %lu us\n", label, got);
}

static void check_le(const char *label, unsigned long got, unsigned long ceil)
{
	if (got > ceil) {
		fprintf(stderr, "FAIL: %s\n  got:      %lu\n  ceiling:  %lu\n",
			label, got, ceil);
		g_fails++;
		return;
	}
	fprintf(stderr, "  ok: %s -> %lu (<=%lu)\n", label, got, ceil);
}

int main(void)
{
	int i;

	/* attempt 0 = first try, no prior failure → no sleep */
	check_eq("attempt 0 returns 0", _cas_backoff_max_us(0), 0);

	/* exponential growth from BASE = 50 µs */
	check_eq("attempt 1 = base 50us",  _cas_backoff_max_us(1), 50);
	check_eq("attempt 2 = 100us",      _cas_backoff_max_us(2), 100);
	check_eq("attempt 3 = 200us",      _cas_backoff_max_us(3), 200);
	check_eq("attempt 4 = 400us",      _cas_backoff_max_us(4), 400);
	check_eq("attempt 5 = 800us",      _cas_backoff_max_us(5), 800);
	check_eq("attempt 6 = 1600us",     _cas_backoff_max_us(6), 1600);
	check_eq("attempt 7 = 3200us",     _cas_backoff_max_us(7), 3200);

	/* cap: attempt 8 would naively be 6400 but is clamped to 5000 */
	check_eq("attempt 8 capped at 5000us",
		_cas_backoff_max_us(8), 5000);
	check_eq("attempt 100 capped at 5000us",
		_cas_backoff_max_us(100), 5000);

	/* negative input clamped to 0 */
	check_eq("negative attempt -> 0",  _cas_backoff_max_us(-5), 0);

	/* across the full default budget (10 retries), the worst-case total
	 * sleep is the sum of upper bounds.  Assert it stays under 50 ms. */
	{
		unsigned long total = 0;
		for (i = 1; i <= 10; i++)
			total += _cas_backoff_max_us(i);
		check_le("sum over 10 retries <= 50000 us", total, 50000);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
