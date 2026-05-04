/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-6a regression test: persist serialization must preserve
 * uint64 precision for fields above 2^53.
 *
 * The bug: cJSON_AddNumberToObject takes a double argument, so
 * `(double)h->start_seq` for start_seq > 2^53 (~9e15) silently
 * rounds.  start_time_unix_ns (nanoseconds since epoch) is
 * ~1.7e18 in 2026 -- well above 2^53.
 *
 * The fix: serialize these fields as JSON strings, parse back
 * with strtoull / strtoll on rehydrate.
 *
 * Tests:
 *   1. Source pattern: serialize uses cJSON_AddStringToObject
 *      for start_seq and start_time_ns.
 *   2. Functional: demonstrate the precision loss in the
 *      double round-trip vs. the lossless string round-trip.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_persist_precision test_persist_precision.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) hits++;
	fclose(f);
	return hits;
}

/* simulate the OLD path: uint64 -> double -> uint64 */
static uint64_t round_trip_double(uint64_t v)
{
	double d = (double)v;
	return (uint64_t)d;
}

/* simulate the NEW path: uint64 -> "%llu" -> strtoull */
static uint64_t round_trip_string(uint64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
	return strtoull(buf, NULL, 10);
}

int main(void)
{
	/* CASE 1: source uses string serialization */
	int s = grep_count("../nats_persist.c",
		"cJSON_AddStringToObject(obj, \"start_seq\"");
	ASSERT(s >= 1, "nats_persist.c serializes start_seq as JSON string");

	int t = grep_count("../nats_persist.c",
		"cJSON_AddStringToObject(obj, \"start_time_ns\"");
	ASSERT(t >= 1, "nats_persist.c serializes start_time_ns as JSON string");

	/* CASE 2: precision boundary */
	uint64_t safe   = (1ULL << 53);          /* exactly 2^53 -- last lossless */
	uint64_t marg   = (1ULL << 53) + 1;      /* 2^53 + 1 -- first lossy */
	uint64_t big    = (1ULL << 60) + 12345;  /* well above 2^53 */
	/* nanosecond-precision timestamp -- includes the sub-second portion
	 * (123456789 ns) so the bottom bits are not all-zero, making the
	 * value pathological for double rounding. */
	uint64_t ns2026 = 1735689600ULL * 1000000000ULL + 123456789ULL;

	ASSERT(round_trip_double(safe) == safe,
		"double round-trip: 2^53 is lossless (control)");
	ASSERT(round_trip_double(marg) != marg,
		"double round-trip: 2^53+1 IS lossy (demonstrates the bug)");
	ASSERT(round_trip_double(big) != big,
		"double round-trip: 2^60+12345 IS lossy");
	ASSERT(round_trip_double(ns2026) != ns2026,
		"double round-trip: nanoseconds-since-epoch IS lossy");

	ASSERT(round_trip_string(safe)   == safe,   "string round-trip: 2^53 lossless");
	ASSERT(round_trip_string(marg)   == marg,   "string round-trip: 2^53+1 lossless");
	ASSERT(round_trip_string(big)    == big,    "string round-trip: 2^60+12345 lossless");
	ASSERT(round_trip_string(ns2026) == ns2026, "string round-trip: ns-epoch lossless");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
