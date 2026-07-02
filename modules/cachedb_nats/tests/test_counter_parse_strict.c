/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the counter ops (cachedb_nats_dbase.c) parsed the stored KV
 * value with bare strtoll(vs, NULL, 10).  A non-numeric value like "abc"
 * returns 0 with no errno, so the range check passed and the counter was
 * silently RESET to `delta` (increment path) or reported as 0 (get path)
 * instead of being rejected -- a corrupt/hostile broker value bypassing the
 * intended fail-closed behaviour.
 *
 * Fix: nats_counter_parse() strictly requires a pure (optionally signed,
 * whitespace-padded) base-10 integer in the 32-bit range; anything else
 * (no digits, trailing garbage, out of range) is rejected.  A NULL value
 * (counter absent) parses as 0 -- the create path.
 *
 * Models nats_counter_parse():
 *   -DSIMULATE_LOOSE_PARSE -> bare strtoll -> "abc" parses to 0 -> FAILS.
 *   (default)              -> strict parse -> "abc" rejected -> ALL PASS.
 * plus a source-wiring assertion.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_counter_parse_strict \
 *        test_counter_parse_strict.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

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

/* Model of nats_counter_parse(). Returns 0 (+*out) on a valid 32-bit int,
 * -1 on non-numeric/trailing-garbage/out-of-range.  NULL -> 0 (create path). */
static int counter_parse(const char *s, long long *out)
{
	if (!s) { *out = 0; return 0; }
#ifdef SIMULATE_LOOSE_PARSE
	{
		long long v;
		errno = 0;
		v = strtoll(s, NULL, 10);          /* "abc" -> 0, no error */
		if (errno == ERANGE || v < INT_MIN || v > INT_MAX) return -1;
		*out = v;
		return 0;
	}
#else
	{
		char *endp;
		long long v;
		errno = 0;
		v = strtoll(s, &endp, 10);
		if (endp == s) return -1;                          /* no digits */
		while (*endp == ' ' || *endp == '\t' ||
		       *endp == '\n' || *endp == '\r') endp++;
		if (*endp != '\0') return -1;                      /* trailing garbage */
		if (errno == ERANGE || v < INT_MIN || v > INT_MAX) return -1;
		*out = v;
		return 0;
	}
#endif
}

int main(void)
{
	long long v;

	ASSERT(counter_parse("42", &v) == 0 && v == 42, "a plain integer parses");
	ASSERT(counter_parse("  -7 ", &v) == 0 && v == -7,
		"a signed, whitespace-padded integer parses");
	ASSERT(counter_parse(NULL, &v) == 0 && v == 0,
		"an absent counter (NULL) parses as 0 (create path)");

	ASSERT(counter_parse("abc", &v) == -1,
		"a non-numeric value is REJECTED (not silently reset to 0)");
	ASSERT(counter_parse("12abc", &v) == -1,
		"trailing garbage after a number is rejected");
	ASSERT(counter_parse("", &v) == -1,
		"an empty (non-NULL) value is rejected");

	/* 2^40 is a valid int64 but out of the 32-bit counter range. */
	ASSERT(counter_parse("1099511627776", &v) == -1,
		"a value beyond 32-bit range is rejected");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../cachedb_nats_dbase.c";
		ASSERT(file_contains(src, "nats_counter_parse"),
			"the counter ops route the stored value through nats_counter_parse");
		ASSERT(file_contains(src, "endp == s"),
			"nats_counter_parse rejects a value with no digits");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
