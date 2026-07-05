/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.5] _sink_emit_int(): the per-field snprintf("%lld") parsed a
 * format string for every integer emitted into a row document (expires,
 * cseq, last_mod, q, methods, row_exp ... a dozen per REGISTER); it is
 * now a plain divide-loop.  This is a characterization test against the
 * REAL ../cachedb_nats_json_ser.c: every edge value must serialize to
 * exactly what printf produces -- including INT64_MIN, whose naive
 * negation is UB.
 *
 * Also locks the pattern: no snprintf left inside _sink_emit_int.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "../cachedb_nats_json_internal.h"
#include "../../../lib/nats/nats_dl.h"

/* ── core seams (same shape as test_json_foreach.c) ─────────────── */
static int test_log_level = 0;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int dp_my_pid(void) { return 0; }
void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{ (void)level; (void)facility; (void)module; (void)func;
  (void)stderr_fmt; (void)syslog_fmt; (void)format; }
void *mem_block = NULL;
static void *blk_malloc(void *b, unsigned long n) { (void)b; return malloc(n); }
static void *blk_realloc(void *b, void *p, unsigned long n)
{ (void)b; return realloc(p, n); }
static void blk_free(void *b, void *p) { (void)b; free(p); }
void *(*gen_pkg_malloc)(void *blk, unsigned long size) = blk_malloc;
void *(*gen_pkg_realloc)(void *blk, void *p, unsigned long size) = blk_realloc;
void (*gen_pkg_free)(void *blk, void *p) = blk_free;

/* symbols the ser TU references but this test never reaches */
nats_dl_funcs_t nats_dl;
char *fts_json_prefix = "json_";
int   fts_json_prefix_len = 5;
int cdb_json_to_dict(const char *json, cdb_dict_t *out,
	void (*unescape)(char *inout))
{ (void)json; (void)out; (void)unescape; return -1; }

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

static int emits_exactly(int64_t v)
{
	json_sink_t s;
	char want[32], *got;
	int want_len, got_len, ok;

	want_len = snprintf(want, sizeof(want), "%" PRId64, v);
	if (_sink_init(&s, 8) < 0) return 0;
	if (_sink_emit_int(&s, v) < 0) return 0;
	got = _sink_take(&s, &got_len);
	if (!got) return 0;
	ok = (got_len == want_len && memcmp(got, want, want_len) == 0);
	if (!ok)
		fprintf(stderr, "  mismatch: v=%" PRId64 " want='%s' got='%.*s'\n",
			v, want, got_len, got);
	free(got);
	return ok;
}

static int file_function_contains(const char *path, const char *fn,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long n;
	const char *p, *end;
	int found = 0;
	if (!f) return 0;
	fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return 0; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return 0;
	}
	buf[n] = '\0';
	fclose(f);
	p = strstr(buf, fn);
	if (p) {
		end = strstr(p, "\n}\n");
		if (!end) end = buf + n;
		found = (memmem(p, (size_t)(end - p), needle, strlen(needle))
			!= NULL);
	}
	free(buf);
	return found;
}

int main(void)
{
	int64_t vals[] = {
		0, 1, -1, 9, 10, 99, 100, -100,
		1234567890, -1234567890,
		1783254616,               /* an epoch-second, the common case */
		INT64_MAX, INT64_MIN,
		INT64_MAX - 1, INT64_MIN + 1,
	};
	unsigned i;
	int all = 1;

	for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++)
		if (!emits_exactly(vals[i]))
			all = 0;
	CHECK(all, "every edge value serializes byte-identically to printf");

	CHECK(!file_function_contains("../cachedb_nats_json_ser.c",
			"int _sink_emit_int(", "snprintf"),
		"_sink_emit_int no longer parses a printf format per field");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
