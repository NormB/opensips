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
 * MAINTAINABILITY-PERF-SPEC.md P2.5: the ONE top-level JSON field
 * iterator behind the row-mutation paths.  The hand-rolled
 * cdbn_skip_ws/cdbn_parse_json_string/cdbn_skip_json_value walk skeleton used to
 * be copy-pasted through _apply_pairs_one_pass /
 * cdbn_row_finalize_metadata / cdbn_reap_project_survivors /
 * _sink_merge_subkeys; they all now walk through
 * cdbn_json_foreach_top_field(json, len, cb, ud).  This locks the
 * iterator against the PRODUCTION walker TU (#included directly):
 *
 *   - every top-level field visited exactly once, name span and RAW
 *     value span (nested objects/arrays as one span) handed to the cb,
 *   - names with escaped quotes/backslashes, values with embedded
 *     braces/commas inside strings, deep nesting,
 *   - cb abort (<0) stops the walk and surfaces -1,
 *   - malformed JSON (truncated value, missing colon, not an object,
 *     garbage) surfaces -1; empty object walks zero fields -> 0,
 *   - empty input / NULL guarded.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_json_foreach
 *            test_json_foreach.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cachedb_nats_json_walk.c"

/* ── core seams for the TU's other functions (unused here) ──────── */
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
int cdb_json_to_dict(const char *json, cdb_dict_t *out,
	void (*unescape)(char *inout))
{ (void)json; (void)out; (void)unescape; return -1; }

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* recording callback: append "name=value;" into a buffer */
struct rec {
	char buf[512];
	int  len;
	int  abort_after;   /* abort (<0) after visiting N fields; 0=never */
	int  visited;
};

static int rec_cb(const char *fname, int flen,
	const char *vstart, const char *vend, void *ud)
{
	struct rec *r = ud;

	r->visited++;
	r->len += snprintf(r->buf + r->len, sizeof(r->buf) - r->len,
		"%.*s=%.*s;", flen, fname, (int)(vend - vstart), vstart);
	if (r->abort_after && r->visited >= r->abort_after)
		return -1;
	return 0;
}

static int walk(const char *json, struct rec *r)
{
	memset(r, 0, sizeof(*r));
	return cdbn_json_foreach_top_field(json, (int)strlen(json), rec_cb, r);
}

int main(void)
{
	struct rec r;

	printf("[P2.5] plain object: every field once, raw value spans:\n");
	CHECK(walk("{\"a\":1,\"b\":\"x\",\"c\":null}", &r) == 0 &&
	      strcmp(r.buf, "a=1;b=\"x\";c=null;") == 0,
		"scalar fields visited in order with exact spans");

	printf("[P2.5] nested values are ONE span:\n");
	CHECK(walk("{\"o\":{\"i\":{\"j\":[1,2]}},\"z\":9}", &r) == 0 &&
	      strcmp(r.buf, "o={\"i\":{\"j\":[1,2]}};z=9;") == 0,
		"nested object handed through as a single raw span");

	printf("[P2.5] adversarial strings:\n");
	CHECK(walk("{\"k\\\"ey\":\"br{ce,}\",\"b\\\\\":\"\"}", &r) == 0 &&
	      strcmp(r.buf, "k\\\"ey=\"br{ce,}\";b\\\\=\"\";") == 0,
		"escaped quote in name; braces/commas inside value strings");

	printf("[P2.5] whitespace + empty object:\n");
	CHECK(walk("  { \"a\" :  1 , \"b\" : 2 }  ", &r) == 0 && r.visited == 2,
		"whitespace everywhere still walks both fields");
	CHECK(walk("{}", &r) == 0 && r.visited == 0,
		"empty object: zero fields, success");
	CHECK(walk("   { }  ", &r) == 0 && r.visited == 0,
		"empty object with whitespace");

	printf("[P2.5] cb abort stops the walk:\n");
	memset(&r, 0, sizeof(r));
	r.abort_after = 2;
	CHECK(cdbn_json_foreach_top_field("{\"a\":1,\"b\":2,\"c\":3}", 21,
			rec_cb, &r) == -1 && r.visited == 2,
		"abort after 2 fields: walk stops, -1 surfaced");

	printf("[P2.5] malformed inputs surface -1:\n");
	CHECK(walk("[1,2]", &r) == -1, "not an object");
	CHECK(walk("{\"a\":1", &r) == -1, "unterminated object");
	CHECK(walk("{\"a\" 1}", &r) == -1, "missing colon");
	CHECK(walk("{\"a\":}", &r) == -1, "missing value");
	CHECK(walk("{\"a\":\"unterminated}", &r) == -1,
		"unterminated string value");
	CHECK(walk("", &r) == -1, "empty input");
	CHECK(cdbn_json_foreach_top_field(NULL, 5, rec_cb, &r) == -1,
		"NULL json guarded");
	CHECK(cdbn_json_foreach_top_field("{}", 2, NULL, &r) == -1,
		"NULL callback guarded");

	printf("\n%s (%d failure%s)\n", g_fails ? "FAILED" : "PASSED",
		g_fails, g_fails == 1 ? "" : "s");
	return g_fails ? 1 : 0;
}
