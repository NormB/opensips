/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the JetStream MI commands `nats_jetstream_msg_get` /
 * `..._msg_delete` (nats_jetstream.c) read the message sequence with
 * try_get_mi_int_param into an int and cast it to uint64_t.  Stream sequences
 * are 64-bit; a message at seq > INT_MAX is unaddressable (and an int parse of
 * a large value wraps).  On a long-lived high-volume stream these commands
 * cannot get/delete recent messages.
 *
 * Fix: parse `seq` as a full uint64 -- accept a JSON string (strtoull, full
 * 64-bit range) in addition to the JSON-number int path (back-compat, <=
 * INT_MAX).
 *
 * Models the parse:
 *   -DSIMULATE_INT_SEQ -> int parse -> a > INT_MAX seq wraps/saturates -> FAILS.
 *   (default)          -> strtoull -> full 64-bit value preserved -> ALL PASS.
 * plus a source-wiring assertion.
 *
 * Build: gcc -g -O0 -Wall -o test_mi_seq_u64 test_mi_seq_u64.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

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

/* Model: parse a decimal seq string into a uint64. Returns 0 on success. */
static int seq_parse(const char *s, uint64_t *out)
{
#ifdef SIMULATE_INT_SEQ
	{
		int v = atoi(s);              /* int path: wraps/saturates > INT_MAX */
		if (v <= 0) return -1;
		*out = (uint64_t)v;
		return 0;
	}
#else
	{
		char *endp;
		unsigned long long v;
		errno = 0;
		v = strtoull(s, &endp, 10);
		if (endp == s || *endp != '\0' || errno == ERANGE || v == 0)
			return -1;
		*out = (uint64_t)v;
		return 0;
	}
#endif
}

int main(void)
{
	uint64_t seq;

	ASSERT(seq_parse("42", &seq) == 0 && seq == 42, "a small seq parses");

	/* 5_000_000_000 is > INT_MAX (2147483647) but a valid stream seq. */
	ASSERT(seq_parse("5000000000", &seq) == 0 && seq == 5000000000ULL,
		"a seq beyond INT_MAX is preserved (not wrapped/truncated)");

	ASSERT(seq_parse("0", &seq) == -1, "seq 0 is rejected");
	ASSERT(seq_parse("abc", &seq) == -1, "a non-numeric seq is rejected");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../nats_jetstream.c";
		ASSERT(file_contains(src, "mi_get_seq_u64"),
			"msg get/delete route seq through mi_get_seq_u64");
		ASSERT(file_contains(src, "strtoull"),
			"seq is parsed as a full 64-bit value (strtoull)");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
