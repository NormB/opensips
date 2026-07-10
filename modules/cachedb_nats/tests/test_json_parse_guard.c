/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Regression test: broker-supplied KV values reach cdb_json_to_dict()
 * (cachedb/cachedb_dict.c) which hands them to OpenSIPS's bundled
 * cJSON_Parse().  That parser recurses one C stack frame per nesting
 * level (lib/cJSON.c: parse_value -> parse_array/parse_object ->
 * parse_value) with NO depth limit, so a deeply nested document such as
 * "[[[[ ... ]]]]" published by anyone who can write to the broker drives
 * the SIP worker into stack exhaustion and a crash.
 *
 * The fix is a pure, iterative pre-validation guard,
 * json_parse_guard(data, len, max_depth, max_bytes), called at the two
 * cachedb_nats query call sites (cachedb_nats_json.c) BEFORE the data is
 * handed to cdb_json_to_dict().  It rejects:
 *   - NULL / non-positive / oversized (> max_bytes) input,
 *   - any raw embedded NUL (invalid JSON; would truncate the document),
 *   - object/array nesting deeper than max_depth.
 * Brace/bracket counting skips string literals so structural bytes
 * inside strings are not miscounted.
 *
 * This test carries a synced copy of the production guard (same pattern
 * as test_intern_unit.c / test_json_escape.c — self-contained, no
 * OpenSIPS link), and a `naive_recursive_parse()` that faithfully models
 * cJSON's per-level recursion to prove the guarded input is exactly the
 * input that would blow the stack.
 *
 * RED/GREEN demonstration:
 *   gcc -DSIMULATE_PREFIX_BUG ...  -> guard is a no-op (pre-fix); the
 *                                     "deep nesting rejected" assertions
 *                                     FAIL, proving the test has teeth.
 *   gcc ...                        -> real guard; ALL PASS.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_json_parse_guard \
 *       test_json_parse_guard.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Must match the production constants in cachedb_nats_json.c. */
#define NATS_JSON_MAX_DEPTH  64
#define NATS_JSON_MAX_BYTES  (1 * 1024 * 1024)

/* ─── synced copy of the production guard ─────────────────────────────
 * Keep in lock-step with cachedb_nats_json.c::json_parse_guard().     */

#ifdef SIMULATE_PREFIX_BUG
/* Models the pre-fix world: nothing pre-validates the broker data. */
static int json_parse_guard(const char *data, int data_len,
		int max_depth, int max_bytes)
{
	(void)data; (void)data_len; (void)max_depth; (void)max_bytes;
	return 0;
}
#else
static int json_parse_guard(const char *data, int data_len,
		int max_depth, int max_bytes)
{
	int i, depth = 0, in_string = 0;

	if (!data || data_len <= 0 || data_len > max_bytes)
		return -1;

	/* Any raw NUL is invalid JSON and would truncate the document at
	 * cJSON_Parse — reject outright (one cheap pass). */
	if (memchr(data, '\0', (size_t)data_len) != NULL)
		return -1;

	/* Bound object/array nesting, skipping string literals so that
	 * structural bytes inside strings are not counted. */
	for (i = 0; i < data_len; i++) {
		unsigned char c = (unsigned char)data[i];
		if (in_string) {
			if (c == '\\') { i++; continue; }   /* skip escaped byte */
			if (c == '"') in_string = 0;
			continue;
		}
		if (c == '"') { in_string = 1; continue; }
		if (c == '{' || c == '[') {
			if (++depth > max_depth) return -1;
		} else if (c == '}' || c == ']') {
			if (depth > 0) depth--;
		}
	}
	return 0;
}
#endif

/* ─── model of cJSON's recursion (parse_value -> parse_array -> ...) ───
 * Returns the maximum C-stack depth this document would drive cJSON to.
 * Capped so the test itself can never overflow; the cap stands in for
 * "the kernel stack limit" in the real crash.                          */

#define RECURSION_TRIP 100000

static int naive_recursive_parse(const char **p, const char *end, int depth)
{
	if (depth > RECURSION_TRIP)
		return depth;                 /* would have crashed by now */
	while (*p < end && (**p == ' ' || **p == '\t' || **p == '\n'))
		(*p)++;
	if (*p >= end)
		return depth;
	if (**p == '[' || **p == '{') {
		char close = (**p == '[') ? ']' : '}';
		int maxd = depth;
		(*p)++;
		while (*p < end && **p != close) {
			int d = naive_recursive_parse(p, end, depth + 1);
			if (d > maxd) maxd = d;
			if (*p < end && **p == ',') (*p)++;
			else break;
		}
		if (*p < end && **p == close) (*p)++;
		return maxd;
	}
	/* scalar: consume to delimiter */
	while (*p < end && **p != ',' && **p != ']' && **p != '}')
		(*p)++;
	return depth;
}

static int recursion_depth_of(const char *data, int len)
{
	const char *p = data;
	return naive_recursive_parse(&p, data + len, 0);
}

/* ─── helpers ─────────────────────────────────────────────────────── */

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* Build a string of `n` nested arrays: "[[[...]]]". */
static char *make_nested(int n)
{
	char *b = malloc((size_t)n * 2 + 1);
	int i;
	for (i = 0; i < n; i++)       b[i] = '[';
	for (i = 0; i < n; i++)       b[n + i] = ']';
	b[n * 2] = '\0';
	return b;
}

int main(void)
{
	int got;

	/* ── benign documents the guard must ACCEPT ───────────────────── */
	{
		const char *flat = "{\"aor\":\"sip:a@b\",\"expires\":\"60\"}";
		got = json_parse_guard(flat, (int)strlen(flat),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == 0, "flat usrloc-style object accepted");
	}
	{
		/* Nesting right at the limit must still pass. */
		char *atlimit = make_nested(NATS_JSON_MAX_DEPTH);
		got = json_parse_guard(atlimit, (int)strlen(atlimit),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == 0, "nesting exactly at max_depth accepted");
		free(atlimit);
	}
	{
		/* Braces *inside a string* must not count toward depth. */
		const char *s = "{\"k\":\"[[[[[[[[[[[[[[[[[[[[[[[[ not real ]]]]\"}";
		got = json_parse_guard(s, (int)strlen(s),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == 0, "brackets inside a JSON string are not counted");
	}

	/* ── the attack: deep nesting that crashes the recursive parser ── */
	{
		int deep_n = NATS_JSON_MAX_DEPTH + 5000;
		char *deep = make_nested(deep_n);

		/* First prove the input really is dangerous: the faithful
		 * recursion model is driven far past any safe frame budget. */
		int rd = recursion_depth_of(deep, (int)strlen(deep));
		CHECK(rd > NATS_JSON_MAX_DEPTH,
			"deep input drives the recursive parser past max_depth "
			"(would exhaust the real stack)");

		/* The guard must reject it BEFORE it reaches cJSON. */
		got = json_parse_guard(deep, (int)strlen(deep),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == -1, "deep nesting rejected by guard");
		free(deep);
	}
	{
		/* One past the limit must already be rejected. */
		char *over = make_nested(NATS_JSON_MAX_DEPTH + 1);
		got = json_parse_guard(over, (int)strlen(over),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == -1, "nesting one past max_depth rejected");
		free(over);
	}

	/* ── size cap ─────────────────────────────────────────────────── */
	{
		const char *s = "{\"a\":\"b\"}";
		got = json_parse_guard(s, (int)strlen(s), NATS_JSON_MAX_DEPTH, 4);
		CHECK(got == -1, "oversized document (> max_bytes) rejected");
	}

	/* ── embedded NUL ─────────────────────────────────────────────── */
	{
		const char buf[] = {'{','"','a','"',':','"','x','\0','y','"','}'};
		got = json_parse_guard(buf, (int)sizeof(buf),
				NATS_JSON_MAX_DEPTH, NATS_JSON_MAX_BYTES);
		CHECK(got == -1, "embedded NUL rejected (no silent truncation)");
	}

	/* ── degenerate inputs handled without crashing ───────────────── */
	{
		got = json_parse_guard(NULL, 5, NATS_JSON_MAX_DEPTH,
				NATS_JSON_MAX_BYTES);
		CHECK(got == -1, "NULL data rejected");
		got = json_parse_guard("{}", 0, NATS_JSON_MAX_DEPTH,
				NATS_JSON_MAX_BYTES);
		CHECK(got == -1, "zero length rejected");
		/* Unbalanced closers must not underflow depth or crash. */
		got = json_parse_guard("]]]]}", 5, NATS_JSON_MAX_DEPTH,
				NATS_JSON_MAX_BYTES);
		CHECK(got == 0, "unbalanced closers do not crash/underflow");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
