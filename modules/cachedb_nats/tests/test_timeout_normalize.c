/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-4a regression test: w_nats_request must normalize the
 * caller-supplied timeout against a configurable default and clamp
 * it into a sane range.
 *
 * Pre-fix behavior:
 *   - upper clamp at 30000 ms (in-place mutation of *timeout_ms)
 *   - no lower clamp (0 or negative reach natsConnection_RequestString
 *     where behavior is implementation-defined)
 *   - no default (caller must pass an explicit value or get UB)
 *
 * Post-fix behavior:
 *   - timeout_ms <= 0  -> use nats_request_default_timeout_ms (500)
 *   - 0 < timeout_ms < 10  -> clamp to 10 (NATS RTT floor)
 *   - timeout_ms > 30000   -> clamp to 30000 (existing behavior)
 *   - 10..30000  -> pass through
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_timeout_normalize test_timeout_normalize.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirror the fix's clamp arithmetic.  The production code keeps
 * this inline in w_nats_request; we test the math here. */
static int normalize(int caller, int dflt, int min, int max)
{
	int t = caller;
	if (t <= 0) t = dflt;
	if (t < min) t = min;
	if (t > max) t = max;
	return t;
}

static int g_fails;
#define EXPECT(in, want, label) do { \
	int got = normalize((in), 500, 10, 30000); \
	if (got != (want)) { \
		fprintf(stderr, "FAIL: %s in=%d want=%d got=%d\n", \
			(label), (in), (want), got); \
		g_fails++; \
	} else { \
		fprintf(stderr, "  ok: %s (%d -> %d)\n", (label), (in), got); \
	} \
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

int main(void)
{
	/* boundary arithmetic */
	EXPECT(   0, 500, "zero -> default");
	EXPECT(  -1, 500, "negative -> default");
	EXPECT(-1000, 500, "very negative -> default");
	EXPECT(   1,  10, "1ms -> clamped to min 10");
	EXPECT(   9,  10, "9ms -> clamped to min 10");
	EXPECT(  10,  10, "exactly min");
	EXPECT( 100, 100, "in-range unchanged");
	EXPECT(2000,2000, "typical 2s unchanged");
	EXPECT(30000,30000,"exactly max");
	EXPECT(30001,30000,"over-max clamped");
	EXPECT(60000,30000,"way over-max clamped");

	/* source-pattern checks */
	int default_decl = grep_count(
		"../cachedb_nats.c",
		"int   nats_request_default_timeout_ms = 500;");
	if (!default_decl) g_fails++,
		fprintf(stderr, "FAIL: cachedb_nats.c default 500\n");
	else fprintf(stderr, "  ok: cachedb_nats.c default = 500\n");

	int param_export = grep_count(
		"../cachedb_nats.c",
		"\"nats_request_default_timeout_ms\"");
	if (!param_export) g_fails++,
		fprintf(stderr, "FAIL: cachedb_nats.c modparam export\n");
	else fprintf(stderr, "  ok: cachedb_nats.c exports modparam\n");

	int default_used = grep_count(
		"../cachedb_nats_native.c",
		"nats_request_default_timeout_ms");
	if (default_used < 1) g_fails++,
		fprintf(stderr, "FAIL: native.c uses default\n");
	else fprintf(stderr, "  ok: native.c references default\n");

	int min_clamp = grep_count(
		"../cachedb_nats_native.c",
		"NATS_REQUEST_MIN_TIMEOUT_MS");
	if (min_clamp < 1) g_fails++,
		fprintf(stderr, "FAIL: native.c declares min clamp\n");
	else fprintf(stderr, "  ok: native.c declares min clamp\n");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
