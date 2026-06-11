/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the cachedb_nats counter ops read the current value
 * from a broker-supplied KV entry with strtoll/strtol and then either
 *   - added the delta with no overflow check (nats_cache_counter_op:
 *     `current += delta` on an int64 that may be near INT64_MAX -> signed
 *     overflow UB), or
 *   - cast the parsed value straight to `int` (get_counter:
 *     `(int)strtol(...)` -> silent 64->32 truncation).
 * Both return a wrapped/truncated value to the script.  Since counters
 * gate throttle / admission decisions, an attacker who can set the KV
 * value can wrap a counter to a small or negative number and bypass a
 * limit.
 *
 * Fix: counters are 32-bit from the script's API (int delta, int *out).
 * Range-check the parsed value to [INT_MIN, INT_MAX] (and detect strtoll
 * ERANGE), compute the sum in int64, and reject (not truncate) a result
 * that leaves the 32-bit range.
 *
 * This models the parse+check+add step the fix performs.
 *   -DSIMULATE_PREFIX_BUG -> no range/overflow checks: an over-range
 *                            value or an overflowing add returns a
 *                            wrapped/truncated result -> assertions FAIL.
 *   (default)             -> out-of-range / overflow rejected -> ALL PASS.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_counter_overflow \
 *       test_counter_overflow.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdint.h>

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* Models the counter read+add: parse @cur_str, add @delta, write the new
 * 32-bit value to *out.  Returns 0 on success, -1 if the value is out of
 * range or the add would overflow the 32-bit counter. */
static int counter_add(const char *cur_str, int delta, int *out)
{
	long long parsed;

	errno = 0;
	parsed = cur_str ? strtoll(cur_str, NULL, 10) : 0;

#ifdef SIMULATE_PREFIX_BUG
	{
		int64_t current = parsed;       /* no range check */
		current += delta;               /* may overflow (UB in prod) */
		*out = (int)current;            /* may truncate */
		return 0;
	}
#else
	if (errno == ERANGE || parsed < INT_MIN || parsed > INT_MAX)
		return -1;                      /* corrupt/hostile stored value */
	{
		int64_t next = (int64_t)parsed + (int64_t)delta;
		if (next < INT_MIN || next > INT_MAX)
			return -1;                  /* increment would overflow */
		*out = (int)next;
		return 0;
	}
#endif
}

int main(void)
{
	int out;

	/* Normal increments work. */
	CHECK(counter_add("5", 3, &out) == 0 && out == 8,
		"normal increment 5 + 3 = 8");
	CHECK(counter_add(NULL, 1, &out) == 0 && out == 1,
		"missing counter treated as 0, +1 = 1");

	/* Increment at the 32-bit ceiling must be REJECTED, not wrapped to a
	 * negative number (which would bypass a throttle limit). */
	{
		char ceil_s[32];
		snprintf(ceil_s, sizeof(ceil_s), "%d", INT_MAX);
		CHECK(counter_add(ceil_s, 1, &out) == -1,
			"increment past INT_MAX is rejected (not wrapped)");
	}

	/* A broker value far beyond 64-bit range (strtoll ERANGE). */
	CHECK(counter_add("999999999999999999999999", 1, &out) == -1,
		"value beyond int64 range is rejected");

	/* A broker value beyond 32-bit but within 64-bit must also be
	 * rejected rather than silently truncated to a small int. */
	CHECK(counter_add("4294967296", 0, &out) == -1,   /* 2^32 */
		"value beyond 32-bit range is rejected (not truncated)");

	/* Decrement below the floor is likewise rejected. */
	{
		char floor_s[32];
		snprintf(floor_s, sizeof(floor_s), "%d", INT_MIN);
		CHECK(counter_add(floor_s, -1, &out) == -1,
			"decrement past INT_MIN is rejected (not wrapped)");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
