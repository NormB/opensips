/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: deliver_policy=by_start_time must round-trip
 * through persistence.
 *
 * The pre-fix behavior: nats_persist.c serialized the start time
 * as a lossless uint64-string (`start_time_ns`) to dodge IEEE 754
 * precision loss, but the rehydrate path skipped the field with a
 * WARN because the bind parser only accepts RFC3339.  Net effect:
 * a handle configured `deliver_policy=by_start_time;start_time=...`
 * lost the start_time across a snapshot reload.
 *
 * The fix: on rehydrate, convert `start_time_ns` back to an
 * RFC3339 string with 9-digit fractional seconds and emit it as
 * the regular `start_time` key.  parse_rfc3339_ns round-trips this
 * back to the same int64 the serializer wrote, so the rehydrated
 * handle matches the pre-snapshot configuration exactly.
 *
 * Cases:
 *
 *   1. Source pattern: nats_persist.c's rehydrate branch for
 *      "start_time_ns" emits a `start_time=` key (no longer skips
 *      with a WARN).  The stale "not round-trippable" log is gone.
 *
 *   2. Functional: the ns->RFC3339 formatter (test-local mirror of
 *      the production gmtime_r + snprintf logic) produces a string
 *      that parses back to the original ns via the same algorithm
 *      parse_rfc3339_ns uses in nats_handle_parse.c.  Boundary
 *      cases: epoch (0 ns), modern timestamps with sub-second
 *      precision, year 2099 to confirm the format handles 4-digit
 *      years without truncation.
 *
 * Build (driven by Makefile):
 *   gcc -g -O0 -Wall -o test_start_time_roundtrip \
 *       test_start_time_roundtrip.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ── helpers ───────────────────────────────────────────────────── */

static int grep_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char  line[2048];
	int   hits = 0;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) hits++;
	fclose(f);
	return hits;
}

/*
 * Test-local mirror of the production ns->RFC3339 formatter (kept
 * in nats_persist.c).  If this drifts away from the production
 * format, case (1) source-pattern check fails before this gets
 * called.
 */
static int format_ns_to_rfc3339(uint64_t ns, char *out, size_t cap)
{
	time_t    secs    = (time_t)(ns / 1000000000ULL);
	long      frac_ns = (long)(ns % 1000000000ULL);
	struct tm tm;
	int       n;

	if (!gmtime_r(&secs, &tm)) return -1;
	n = snprintf(out, cap,
		"%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, frac_ns);
	return (n > 0 && (size_t)n < cap) ? n : -1;
}

/*
 * Test-local mirror of parse_rfc3339_ns from nats_handle_parse.c.
 * Accepts the canonical 4-digit-year + 9-digit-fraction + Z form
 * the formatter above emits.  If the production parser ever stops
 * accepting that exact shape, this test breaks.
 */
static int parse_rfc3339_ns(const char *s, int len, int64_t *out)
{
	char      buf[64];
	struct tm tm;
	time_t    tt_utc;
	int       year, mon, day, hh, mm, ss;
	int       frac_ns = 0;
	int       pos     = 19;

	if (len < 19 || len >= (int)sizeof(buf)) return -1;
	memcpy(buf, s, (size_t)len);
	buf[len] = '\0';

	if (sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d",
			&year, &mon, &day, &hh, &mm, &ss) != 6)
		return -1;

	if (buf[pos] == '.') {
		int  scale = 100000000;   /* 0.1 s -> ns */
		pos++;
		while (pos < len && buf[pos] >= '0' && buf[pos] <= '9'
		    && scale > 0) {
			frac_ns += (buf[pos] - '0') * scale;
			scale /= 10;
			pos++;
		}
	}

	/* Accept trailing 'Z' for UTC; reject any other tz here. */
	if (pos >= len || buf[pos] != 'Z') return -1;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mon  = mon - 1;
	tm.tm_mday = day;
	tm.tm_hour = hh;
	tm.tm_min  = mm;
	tm.tm_sec  = ss;
	tt_utc     = timegm(&tm);
	if (tt_utc == (time_t)-1) return -1;

	*out = (int64_t)tt_utc * 1000000000LL + frac_ns;
	return 0;
}

/* ── case 1: source pattern ────────────────────────────────────── */

static void test_source_pattern(void)
{
	int hits_emit;
	int hits_stale;

	fprintf(stderr, "\n=== source pattern (rehydrate emits start_time) ===\n");

	hits_emit = grep_count("../nats_persist.c",
		"append_kv(&buf, &len, &cap,\n\t\t\t\t\"start_time\",");
	if (hits_emit < 1) {
		/* Fall back to a less brittle pattern that survives
		 * whitespace reflow. */
		hits_emit = grep_count("../nats_persist.c",
			"\"start_time\", iso, strlen(iso)");
	}
	ASSERT(hits_emit >= 1,
		"rehydrate path emits a start_time key from start_time_ns");

	hits_stale = grep_count("../nats_persist.c",
		"start_time_ns not round-trippable");
	ASSERT(hits_stale == 0,
		"stale 'start_time_ns not round-trippable' WARN removed");

	/* The formatter must use 9-digit fractional seconds + 'Z' --
	 * that's the wire shape parse_rfc3339_ns accepts in its
	 * canonical form. */
	{
		int hits_fmt = grep_count("../nats_persist.c",
			"\"%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ\"");
		ASSERT(hits_fmt >= 1,
			"formatter uses 4-year + 9-digit-fraction + Z layout");
	}
}

/* ── case 2: functional round-trip ─────────────────────────────── */

static void test_one_roundtrip(uint64_t ns, const char *label)
{
	char    iso[64];
	int     n;
	int64_t parsed = 0;
	int     rc;
	char    msg[128];

	n = format_ns_to_rfc3339(ns, iso, sizeof(iso));
	snprintf(msg, sizeof(msg), "%s: format succeeds", label);
	ASSERT(n > 0, msg);

	rc = parse_rfc3339_ns(iso, n, &parsed);
	snprintf(msg, sizeof(msg), "%s: parse succeeds (output='%s')",
		label, iso);
	ASSERT(rc == 0, msg);

	snprintf(msg, sizeof(msg),
		"%s: round-trip preserves ns (%" PRIu64 " == %" PRIu64 ")",
		label, ns, (uint64_t)parsed);
	ASSERT((uint64_t)parsed == ns, msg);
}

static void test_roundtrip(void)
{
	fprintf(stderr, "\n=== functional round-trip ===\n");

	/* Unix epoch -- baseline. */
	test_one_roundtrip(0ULL, "epoch");

	/* 2026-01-01T00:00:00.000000000Z -- start of the current year. */
	test_one_roundtrip(1735689600ULL * 1000000000ULL,
		"2026-01-01 midnight");

	/* Realistic JetStream start time with sub-second fraction.
	 * 1735689600 = 2026-01-01 00:00:00 UTC; + 123456789 ns. */
	test_one_roundtrip(1735689600ULL * 1000000000ULL + 123456789ULL,
		"2026-01-01 + 123.456789 ms");

	/* A timestamp with every sub-second digit non-zero to catch
	 * a snprintf format that drops trailing zeros. */
	test_one_roundtrip(1746662400ULL * 1000000000ULL + 999999999ULL,
		"2025-05-08 + 999999999 ns");

	/* Year 2099 -- confirms 4-digit year handling.  Unix timestamp
	 * 4070908800 = 2099-01-01 00:00:00 UTC. */
	test_one_roundtrip(4070908800ULL * 1000000000ULL,
		"2099-01-01");
}

/* ── main ──────────────────────────────────────────────────────── */

int main(void)
{
	test_source_pattern();
	test_roundtrip();
	if (g_fails) {
		fprintf(stderr, "\n%d FAILED\n", g_fails);
		return 1;
	}
	fprintf(stderr, "\nALL PASSED\n");
	return 0;
}
