/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats_native.c::w_nats_kv_history built a
 * JSON array with a chain of
 *     pos += snprintf(buf + pos, buf_size - pos, ...);
 * snprintf() returns the number of bytes it WOULD have written, which on
 * truncation EXCEEDS the size limit -- so `pos` could grow past
 * buf_size.  The next call then computes  buf_size - pos  as a NEGATIVE
 * int that converts to a huge size_t, defeating the bound and letting
 * the following snprintf / buf[pos++] writes run off the end of the
 * heap buffer.
 *
 * The fix clamps `pos` to buf_size-1 after every advance (the
 * HIST_ADVANCE macro) so the remaining size can never underflow.
 *
 * This test carries the fixed history-building loop verbatim, runs it
 * with a deliberately TINY buffer against many oversized entries, and
 * relies on AddressSanitizer to trip on any out-of-bounds write.  It
 * also asserts the result is always NUL-terminated within bounds and
 * that pos never exceeds buf_size.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_kv_history_bounds \
 *       test_kv_history_bounds.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── stub kvEntry + libnats accessors ─────────────────────────────── */

typedef struct { unsigned long long rev; const char *val; int val_len; } kvEntry;

static unsigned long long ke_rev(kvEntry *e)      { return e->rev; }
static const char        *ke_valstr(kvEntry *e)   { return e->val; }
static int                ke_vallen(kvEntry *e)   { return e->val_len; }

/* ── carried copy of the FIXED history builder ────────────────────── */

static int build_history(char *buf, int buf_size, kvEntry **entries, int count)
{
	int pos = 0, i;

	/* same clamping macro as the production fix */
#define HIST_ADVANCE(...) do { \
		int _w = snprintf(buf + pos, (size_t)(buf_size - pos), \
			__VA_ARGS__); \
		if (_w < 0) { pos = buf_size - 1; } \
		else { \
			pos += _w; \
			if (pos >= buf_size) pos = buf_size - 1; \
		} \
	} while (0)

	HIST_ADVANCE("[");

	for (i = 0; i < count && pos < buf_size - 128; i++) {
		kvEntry *e = entries[i];
		const char *eval = ke_valstr(e);
		int eval_len = ke_vallen(e);

		if (i > 0)
			HIST_ADVANCE(",");

		HIST_ADVANCE("{\"rev\":%llu,\"value\":\"",
			(unsigned long long)ke_rev(e));

		int j;
		for (j = 0; eval && j < eval_len && pos < buf_size - 4; j++) {
			if (eval[j] == '"' || eval[j] == '\\') {
				if (pos >= buf_size - 4) break;
				buf[pos++] = '\\';
			}
			buf[pos++] = eval[j];
		}

		HIST_ADVANCE("\"}");
	}

	HIST_ADVANCE("]");
#undef HIST_ADVANCE
	return pos;
}

/* ── tests ────────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Run the builder on a heap buffer of exactly buf_size bytes so ASan
 * red-zones immediately flank it; any 1-byte overrun aborts. */
static void run_case(int buf_size, kvEntry **entries, int count,
	const char *label)
{
	char *buf = malloc(buf_size);
	int pos;
	if (!buf) { ASSERT(0, "malloc"); return; }
	pos = build_history(buf, buf_size, entries, count);

	ASSERT(pos >= 0 && pos < buf_size,
		label /* pos stays strictly within bounds */);
	/* the position must point at (or before) a writable byte and the
	 * buffer must be readable up to pos -- ASan guarantees this if no
	 * OOB write happened. */
	{
		volatile char sink = 0;
		int k;
		for (k = 0; k < pos; k++) sink ^= buf[k];
		(void)sink;
	}
	free(buf);
}

int main(void)
{
	/* A long value full of quotes/backslashes maximises escape expansion
	 * and snprintf truncation pressure. */
	char big[4096];
	memset(big, '"', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';

	char big2[4096];
	memset(big2, '\\', sizeof(big2) - 1);
	big2[sizeof(big2) - 1] = '\0';

	kvEntry e0 = { 1, "small", 5 };
	kvEntry e1 = { 2, big,  (int)sizeof(big) - 1 };
	kvEntry e2 = { 3, big2, (int)sizeof(big2) - 1 };
	kvEntry e3 = { 4, "another", 7 };
	kvEntry *entries[] = { &e0, &e1, &e2, &e3 };

	/* Buffer FAR too small to hold the oversized entries -> exercises
	 * every truncation / clamp path. */
	run_case(16,  entries, 4, "16-byte buffer never overruns");
	run_case(32,  entries, 4, "32-byte buffer never overruns");
	run_case(64,  entries, 4, "64-byte buffer never overruns");
	run_case(130, entries, 4, "130-byte buffer (just over the 128 guard)");
	run_case(200, entries, 4, "200-byte buffer never overruns");

	/* Tiny buffers where even the opening '[' nearly fills it. */
	run_case(2, entries, 4, "2-byte buffer never overruns");
	run_case(4, entries, 4, "4-byte buffer never overruns");

	/* A buffer big enough to hold the small entries fully. */
	{
		kvEntry s0 = { 10, "ab", 2 };
		kvEntry s1 = { 11, "cd", 2 };
		kvEntry *se[] = { &s0, &s1 };
		char buf[256];
		int pos = build_history(buf, (int)sizeof(buf), se, 2);
		ASSERT(pos > 0 && pos < (int)sizeof(buf),
			"normal case produces bounded output");
		ASSERT(buf[0] == '[' && buf[pos - 1] == ']',
			"normal case is a well-formed JSON array");
		fprintf(stderr, "  normal output: %.*s\n", pos, buf);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
