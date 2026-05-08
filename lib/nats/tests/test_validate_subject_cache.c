/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Tier-2 #7 perf test: nats_validate_publish_subject caches its last
 * (pointer, length, result) tuple per thread to avoid re-scanning
 * identical script-supplied subject literals on every publish.
 *
 * This test asserts the cache does not regress correctness:
 *   - repeated validation of the same valid subject still returns 0
 *   - repeated validation of the same invalid subject still returns -1
 *   - alternating between two distinct subjects yields each correct result
 *   - the cache does not falsely persist results for different lengths
 *     of the same buffer (subject prefixes vs. full)
 *   - NULL input always rejects (cache must not produce a stale pass
 *     when a NULL is passed after a valid hit)
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. \
 *       -o test_validate_subject_cache test_validate_subject_cache.c \
 *       ../nats_validate.o
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nats_validate_publish_subject(const char *s, int len);

static int g_fails;
#define EXPECT(want, label) do { \
	if (got != (want)) { \
		fprintf(stderr, "FAIL: %s want=%d got=%d\n", \
			(label), (want), got); \
		g_fails++; \
	} else { \
		fprintf(stderr, "  ok: %s -> %d\n", (label), got); \
	} \
} while (0)

int main(void)
{
	const char *good = "call.123.event";
	const char *bad  = "call..bad";
	int got;
	int i;

	/* Repeated validation of valid subject must always return 0. */
	for (i = 0; i < 5; i++) {
		got = nats_validate_publish_subject(good, (int)strlen(good));
		EXPECT(0, "valid subject hit (cache or fresh)");
	}

	/* Repeated validation of invalid subject must always return -1. */
	for (i = 0; i < 5; i++) {
		got = nats_validate_publish_subject(bad, (int)strlen(bad));
		EXPECT(-1, "invalid subject hit (cache or fresh)");
	}

	/* Alternating between two subjects: cache miss on each switch
	 * must produce the correct result for the new input. */
	for (i = 0; i < 3; i++) {
		got = nats_validate_publish_subject(good, (int)strlen(good));
		EXPECT(0, "alternation: valid arm");
		got = nats_validate_publish_subject(bad, (int)strlen(bad));
		EXPECT(-1, "alternation: invalid arm");
	}

	/* Same buffer pointer, different length: cache must miss because
	 * len differs, and the prefix may have a different validation
	 * outcome. */
	got = nats_validate_publish_subject(good, (int)strlen(good));
	EXPECT(0, "full-length good baseline");
	got = nats_validate_publish_subject(good, 4); /* "call" — valid token */
	EXPECT(0, "prefix 'call' (len=4) revalidates as valid");
	got = nats_validate_publish_subject(good, 5); /* "call." — invalid */
	EXPECT(-1, "prefix 'call.' (len=5) revalidates as trailing-dot");

	/* NULL after a valid hit must not produce a stale pass. */
	got = nats_validate_publish_subject(good, (int)strlen(good));
	EXPECT(0, "valid baseline before NULL");
	got = nats_validate_publish_subject(NULL, 5);
	EXPECT(-1, "NULL after valid hit rejects");

	/* Zero-length after a valid hit. */
	got = nats_validate_publish_subject("ignored", 0);
	EXPECT(-1, "len<=0 after valid hit rejects");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
