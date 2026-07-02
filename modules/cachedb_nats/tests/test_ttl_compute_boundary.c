/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P5 / TTL-SOLUTION-SPEC.md §2.3 [TREV-12] + TTL-HISTORY-FIX-SPEC.md D3
 * [HREV-3]: TTL computation, units, boundary.
 *
 *   ttl_seconds = row_exp - now + slack   (slack = grace [+ linger, HREV-3])
 *   - ttl_seconds <= 0 (already expired / within slack): FLOOR to the server's
 *     1000 ms minimum so the row physically self-expires ~1 s after the write.
 *     The old "0 ms purge signal" contract is DELETED [RC-6]: no caller ever
 *     implemented the purge, so 0 silently meant "no TTL at all" and an
 *     expired-at-write row lingered until a reaper pass.
 *   - else jsPubOptions.MsgTTL = ttl_seconds * 1000 (ms), invariant MsgTTL %
 *     1000 == 0 (we only ever set whole seconds [TREV-12]).
 * Units across the three layers for one logical 30 s: stream config
 * SubjectDeleteMarkerTTL = ns; the publish option MsgTTL = ms; the wire header
 * is whole s — a transposition is caught by MsgTTL % 1000 == 0.
 *
 *   gcc -DTTLCALC_CURRENT ... -> unit-transposed: MsgTTL = ttl_seconds (forgets
 *                               *1000) and no floor => RED.
 *   gcc -DTTLFLOOR_CURRENT ...-> pre-HREV-3: ttl<=0 returns the 0 "purge
 *                               signal" (i.e. no TTL is set) => RED.
 *   gcc ...                  -> the FIXED computation => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_compute_boundary test_ttl_compute_boundary.c
 */
#include <stdio.h>
#include <stdint.h>

#define NS_PER_S 1000000000LL

/* ─── carried copies of the production helpers (cachedb_nats_ttl.c) ─ */
static int64_t _ttl_seconds(int64_t row_exp, int64_t now, int grace)
{
	return row_exp - now + (int64_t)grace;
}
/* MsgTTL in ms; whole seconds only; <=0 floors to the 1 s server minimum. */
static int64_t _ttl_msgttl_ms(int64_t ttl_seconds)
{
#ifdef TTLCALC_CURRENT
	return ttl_seconds;   /* unit transposition: seconds where ms is wanted */
#else
	int64_t ms;
	if (ttl_seconds <= 0)
#ifdef TTLFLOOR_CURRENT
		return 0;                                  /* pre-HREV-3 "purge signal" */
#else
		return 1000;                               /* HREV-3: floor to 1 s min */
#endif
	/* overflow-safe: cap before *1000 (real epochs never reach this). */
	if (ttl_seconds > 9223372036854775LL)
		ttl_seconds = 9223372036854775LL;
	ms = ttl_seconds * 1000;
	if (ms < 1000)
		ms = 1000;                                 /* clamp to the 1 s minimum */
	return ms;
#endif
}
/* SubjectDeleteMarkerTTL (stream config) in ns from whole seconds. */
static int64_t _ttl_marker_ns(int64_t seconds)
{
	return seconds * NS_PER_S;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
#define EQ(got, want, msg) do { int64_t _g=(got),_w=(want); \
	if (_g != _w) { printf("  FAIL: %s (got %lld want %lld)\n", msg,(long long)_g,(long long)_w); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef TTLCALC_CURRENT
	printf("== carried copy: TTLCALC_CURRENT (unit-transposed) ==\n");
#else
	printf("== carried copy: FIXED computation ==\n");
#endif

	printf("[§2.3] ttl_seconds = row_exp - now + grace:\n");
	EQ(_ttl_seconds(1000, 900, 5), 105, "1000-900+5 == 105");
	EQ(_ttl_seconds(900, 1000, 5), -95, "already-past => negative");
	EQ(_ttl_seconds(1000, 1000, 0), 0, "exactly now, no grace => 0");

	printf("[TREV-12] MsgTTL ms = whole-seconds * 1000 (invariant %% 1000 == 0):\n");
	EQ(_ttl_msgttl_ms(30), 30000, "30 s => 30000 ms");
	EQ(_ttl_msgttl_ms(1), 1000, "1 s => 1000 ms (the minimum)");
	CHECK(_ttl_msgttl_ms(30) % 1000 == 0, "30 s ms is a whole-second multiple");
	CHECK(_ttl_msgttl_ms(3617) % 1000 == 0, "arbitrary s ms still %1000==0");
	EQ(_ttl_msgttl_ms(3600), 3600000, "1 h => 3600000 ms");

	printf("[HREV-3] boundary: ttl<=0 => FLOOR to the 1 s server minimum "
	       "(an expired-at-write row self-expires, never written TTL-less):\n");
	EQ(_ttl_msgttl_ms(0), 1000, "0 s => 1000 ms (floored, not a no-TTL write)");
	EQ(_ttl_msgttl_ms(-5), 1000, "negative => 1000 ms (floored)");
	CHECK(_ttl_msgttl_ms(-5) % 1000 == 0, "floored value keeps %1000==0");

	printf("[§2.3] no overflow at large/post-2038 expiries:\n");
	EQ(_ttl_msgttl_ms(2147483647LL), 2147483647000LL, "INT32_MAX s => *1000 fits int64");
	CHECK(_ttl_msgttl_ms(2147483647LL) % 1000 == 0, "INT32_MAX s ms %1000==0");
	EQ(_ttl_msgttl_ms(5000000000LL), 5000000000000LL, "post-2038 s => no overflow");

	printf("[TREV-12] units: one logical 30 s across the layers:\n");
	EQ(_ttl_marker_ns(30), 30000000000LL, "config SubjectDeleteMarkerTTL = 30e9 ns");
	EQ(_ttl_msgttl_ms(30), 30000, "option MsgTTL = 30000 ms");
	/* wire = whole seconds = 30 (== ms/1000). */
	EQ(_ttl_msgttl_ms(30) / 1000, 30, "wire = ms/1000 = 30 s");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
