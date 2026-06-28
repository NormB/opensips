/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P2.1 / SPEC.md §3.3 §3.2 §4.1 [REV-34 + REV-25 + REV-18]: compute the
 * row-level expiry sentinel `row_exp` from the merged contact set and emit it
 * (plus `schema_version`) as cachedb_nats-private top-level peers, WITHOUT
 * disturbing a non-usrloc document.
 *
 * Part A — _row_exp_min(exp[], n):
 *   - 0 is the "permanent / never auto-expire" sentinel.  expires==0 means a
 *     permanent contact; if ANY contact is permanent the whole row is
 *     permanent => row_exp == 0  (§3.3 / GATE "any expires==0 => 0").
 *   - an empty contact set (or NULL) yields 0 (nothing to expire).
 *   - otherwise row_exp == min(expires) over the contacts.
 *   - int64 THROUGHOUT [REV-34]: no int32 clamp, so post-2038 epochs survive.
 *   - only 0 is the sentinel; a negative (already-past) expiry is a real
 *     candidate value, NOT a permanent marker.
 *
 * Part B — _row_finalize_metadata(json,len): recompute row_exp+schema_version
 *   over the MERGED contacts (§4.1 step 3) and re-emit them as top-level peers
 *   [REV-18/D3], replacing any stale ones; a document with no top-level
 *   "contacts" object is returned byte-for-byte unchanged (other cachedb_nats
 *   consumers must never be reshaped).
 *
 * RED/GREEN from one file (carried-copy convention, matches the Tier-1 suite):
 *   gcc -DROWEXP_CURRENT ... -> a naive int32 min, no permanent sentinel; this
 *                               clamps/mis-drives both _row_exp_min AND the
 *                               row_exp emitted by _row_finalize_metadata
 *                               => RED.
 *   gcc ...                   -> the FIXED int64 sentinel-aware helper => GREEN.
 *
 * Rule 6 [PREV-4]: the GREEN copy here mirrors the production helpers in
 * cachedb_nats_json.c; the AUTHORITATIVE round-trip proof is the Tier-2
 * test_usrloc_roundtrip_int64_e2e.sh vs production [REV-30/PREV-19].
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_row_exp_compute test_row_exp_compute.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── carried copy: row_exp arithmetic (cachedb_nats_json.c) ─────── */

#ifdef ROWEXP_CURRENT
/* CURRENT (naive): int32 accumulation (clamps post-2038, violates REV-34) and
 * no permanent sentinel (empty => INT32_MAX, and a negative beats a 0). */
static int64_t _row_exp_min(const int64_t *exp, int n)
{
	int32_t m = INT32_MAX;
	int i;
	if (!exp || n <= 0)            /* NULL-guard is NOT the bug under test */
		return INT32_MAX;          /* ...but empty => INT32_MAX is (want 0) */
	for (i = 0; i < n; i++) {
		int32_t v = (int32_t)exp[i];   /* REV-34 clamp bug */
		if (v < m) m = v;
	}
	return (int64_t)m;
}
#else
/* FIXED: int64, 0 = permanent sentinel (any permanent contact => permanent
 * row), empty/NULL => 0, else the minimum (earliest) expiry. */
static int64_t _row_exp_min(const int64_t *exp, int n)
{
	int64_t m = 0;
	int i, seen = 0;
	if (!exp || n <= 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (exp[i] == 0)
			return 0;              /* permanent contact => permanent row */
		if (!seen || exp[i] < m) {
			m = exp[i];
			seen = 1;
		}
	}
	return seen ? m : 0;
}
#endif

/* ─── carried copy: JSON walkers (cachedb_nats_json_index.c) ─────── */

static const char *_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}
static const char *_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++; start = p;
	while (p < end && *p != '"') {
		if (*p == '\\') { p++; if (p >= end) return NULL; }
		p++;
	}
	if (p >= end) return NULL;
	*out = start; *out_len = (int)(p - start);
	return p + 1;
}
static const char *_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = _skip_ws(p, end);
	if (p >= end) return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') { p++; if (p >= end) return NULL; }
			p++;
		}
		return (p < end) ? p + 1 : NULL;
	case '{':
	case '[':
		depth = 1; p++;
		while (p < end && depth > 0) {
			if (*p == '{' || *p == '[') depth++;
			else if (*p == '}' || *p == ']') depth--;
			else if (*p == '"') {
				p++;
				while (p < end && *p != '"') {
					if (*p == '\\') { p++; if (p >= end) return NULL; }
					p++;
				}
				if (p >= end) return NULL;
			}
			p++;
		}
		return p;
	default:
		while (p < end && *p != ',' && *p != '}' && *p != ']'
				&& *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		return p;
	}
}

/* ─── carried copy: minimal json_sink_t (cachedb_nats_json_ser.c) ── */

typedef struct { char *buf; int len; int cap; int oom; } json_sink_t;
static int _sink_init(json_sink_t *s, int initial)
{
	s->buf = malloc(initial > 0 ? initial : 16);
	if (!s->buf) return -1;
	s->len = 0; s->cap = initial > 0 ? initial : 16; s->oom = 0;
	return 0;
}
static int _sink_grow(json_sink_t *s, int need)
{
	int ncap = s->cap;
	char *nb;
	while (ncap - s->len < need) ncap *= 2;
	nb = realloc(s->buf, ncap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb; s->cap = ncap;
	return 0;
}
static int _sink_write(json_sink_t *s, const char *p, int n)
{
	if (s->oom) return -1;
	if (s->cap - s->len < n && _sink_grow(s, n) < 0) return -1;
	memcpy(s->buf + s->len, p, n); s->len += n;
	return 0;
}
static int _sink_putc(json_sink_t *s, char c) { return _sink_write(s, &c, 1); }
static int _sink_emit_raw_string(json_sink_t *s, const char *p, int n)
{
	if (_sink_putc(s, '"') < 0) return -1;
	if (_sink_write(s, p, n) < 0) return -1;
	return _sink_putc(s, '"');
}
static int _sink_emit_int(json_sink_t *s, int64_t v)
{
	char tmp[32];
	int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
	return _sink_write(s, tmp, n);
}
static char *_sink_take(json_sink_t *s, int *out_len)
{
	if (s->oom) { free(s->buf); return NULL; }
	if (_sink_putc(s, '\0') < 0) return NULL;
	if (out_len) *out_len = s->len - 1;
	return s->buf;
}

/* ─── carried copy: injector helpers (cachedb_nats_json.c) ───────── */

static const char *_json_parse_int64(const char *p, const char *end, int64_t *out)
{
	int neg = 0;
	uint64_t mag = 0;
	if (p >= end) return NULL;
	if (*p == '-') { neg = 1; p++; }
	if (p >= end || *p < '0' || *p > '9') return NULL;
	for (; p < end && *p >= '0' && *p <= '9'; p++) {
		uint64_t d = (uint64_t)(*p - '0');
		uint64_t lim = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
		if (mag > (lim - d) / 10) return NULL;
		mag = mag * 10 + d;
	}
	*out = neg ? -(int64_t)mag : (int64_t)mag;
	return p;
}
static int _contact_expires(const char *vstart, const char *vend, int64_t *out)
{
	const char *p = _skip_ws(vstart, vend);
	if (p >= vend || *p != '{') return -1;
	p++;
	while (p < vend) {
		const char *name, *vs; int nlen;
		p = _skip_ws(p, vend);
		if (p >= vend) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, vend, &name, &nlen);
		if (!p) return -1;
		p = _skip_ws(p, vend);
		if (p >= vend || *p != ':') return -1;
		p++;
		p = _skip_ws(p, vend);
		vs = p;
		if (nlen == 7 && memcmp(name, "expires", 7) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, vend, &v)) { *out = v; return 0; }
		}
		p = _skip_json_value(p, vend);
		if (!p) return -1;
	}
	return -1;
}
static int _row_collect_expiries(const char *vstart, const char *vend,
	int64_t **out_arr, int *out_n)
{
	const char *p = _skip_ws(vstart, vend);
	int64_t *arr = NULL; int n = 0, cap = 0;
	*out_arr = NULL; *out_n = 0;
	if (p >= vend || *p != '{') return -1;
	p++;
	while (p < vend) {
		const char *name, *cvs; int nlen; int64_t e;
		p = _skip_ws(p, vend);
		if (p >= vend) { free(arr); return -1; }
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, vend, &name, &nlen);
		if (!p) { free(arr); return -1; }
		p = _skip_ws(p, vend);
		if (p >= vend || *p != ':') { free(arr); return -1; }
		p++;
		p = _skip_ws(p, vend);
		cvs = p;
		p = _skip_json_value(p, vend);
		if (!p) { free(arr); return -1; }
		if (_contact_expires(cvs, p, &e) == 0) {
			if (n == cap) {
				int ncap = cap ? cap * 2 : 8;
				int64_t *na = realloc(arr, ncap * sizeof(*na));
				if (!na) { free(arr); return -1; }
				arr = na; cap = ncap;
			}
			arr[n++] = e;
		}
	}
	*out_arr = arr; *out_n = n;
	return 0;
}
static char *_row_finalize_metadata(const char *json, int len, int *out_len)
{
	const char *p, *end, *c_vs = NULL, *c_ve = NULL;
	int64_t *exps = NULL; int n_exp = 0, first = 1;
	int64_t row_exp;
	json_sink_t s;
	if (!json || len <= 0) return NULL;
	end = json + len;
	p = _skip_ws(json, end);
	if (p >= end || *p != '{') return NULL;
	p++;
	while (p < end) {
		const char *name, *vs; int nlen;
		p = _skip_ws(p, end);
		if (p >= end) return NULL;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p) return NULL;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return NULL;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p) return NULL;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) { c_vs = vs; c_ve = p; }
	}
	if (!c_vs) {
		char *copy = malloc(len + 1);
		if (!copy) return NULL;
		memcpy(copy, json, len); copy[len] = '\0';
		if (out_len) *out_len = len;
		return copy;
	}
	if (_row_collect_expiries(c_vs, c_ve, &exps, &n_exp) < 0) return NULL;
	row_exp = _row_exp_min(exps, n_exp);
	free(exps);
	if (_sink_init(&s, len + 64) < 0) return NULL;
	if (_sink_putc(&s, '{') < 0) goto fail;
	p = _skip_ws(json, end); p++;
	while (p < end) {
		const char *name, *vs; int nlen;
		p = _skip_ws(p, end);
		if (p >= end) goto fail;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p) goto fail;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') goto fail;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p) goto fail;
		if ((nlen == 7 && memcmp(name, "row_exp", 7) == 0) ||
		    (nlen == 14 && memcmp(name, "schema_version", 14) == 0))
			continue;
		if (!first && _sink_putc(&s, ',') < 0) goto fail;
		first = 0;
		if (_sink_emit_raw_string(&s, name, nlen) < 0) goto fail;
		if (_sink_putc(&s, ':') < 0) goto fail;
		if (_sink_write(&s, vs, (int)(p - vs)) < 0) goto fail;
	}
	if (!first && _sink_putc(&s, ',') < 0) goto fail;
	if (_sink_write(&s, "\"row_exp\":", 10) < 0) goto fail;
	if (_sink_emit_int(&s, row_exp) < 0) goto fail;
	if (_sink_write(&s, ",\"schema_version\":1", 19) < 0) goto fail;
	if (_sink_putc(&s, '}') < 0) goto fail;
	return _sink_take(&s, out_len);
fail:
	free(s.buf);
	return NULL;
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

#define EXPECT(arr, want, msg) do { \
	int64_t _g = _row_exp_min((arr), (int)(sizeof(arr)/sizeof((arr)[0]))); \
	if (_g != (want)) { printf("  FAIL: %s (got %lld want %lld)\n", msg, \
		(long long)_g, (long long)(want)); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

/* Extract the int64 immediately after the first "row_exp": in @out. */
static int64_t _rowexp_of(const char *out)
{
	const char *m = strstr(out, "\"row_exp\":");
	if (!m) return INT64_MIN;
	m += strlen("\"row_exp\":");
	return (int64_t)strtoll(m, NULL, 10);
}
static int _count(const char *hay, const char *needle)
{
	int c = 0; const char *p = hay;
	while ((p = strstr(p, needle))) { c++; p += strlen(needle); }
	return c;
}
/* finalize a literal doc; returns malloc'd output (caller frees). */
static char *_fin(const char *doc)
{
	return _row_finalize_metadata(doc, (int)strlen(doc), NULL);
}

int main(void)
{
#ifdef ROWEXP_CURRENT
	printf("== carried copy: ROWEXP_CURRENT (naive int32, no sentinel) ==\n");
#else
	printf("== carried copy: FIXED behavior ==\n");
#endif

	printf("[A][REV-34] min over non-zero expiries:\n");
	{ int64_t a[] = {100, 50, 200};   EXPECT(a, 50,  "min{100,50,200} == 50"); }
	{ int64_t a[] = {200, 100, 50};   EXPECT(a, 50,  "order-independent: min{200,100,50} == 50"); }
	{ int64_t a[] = {42};             EXPECT(a, 42,  "single contact => its own expiry"); }

	printf("[A] any expires==0 (permanent) => row_exp==0:\n");
	{ int64_t a[] = {100, 0, 50};     EXPECT(a, 0,   "permanent contact present => 0"); }
	{ int64_t a[] = {0, 0};           EXPECT(a, 0,   "all permanent => 0"); }
	{ int64_t a[] = {-5, 0, 100};     EXPECT(a, 0,   "permanent beats a past expiry => 0"); }

	printf("[A] empty / NULL set => 0:\n");
	CHECK(_row_exp_min(NULL, 0) == 0, "NULL,0 => 0");
	CHECK(_row_exp_min(NULL, 5) == 0, "NULL,n => 0 (defensive)");
	{ int64_t a[] = {7}; CHECK(_row_exp_min(a, 0) == 0, "n==0 => 0 (empty contact set)"); }

	printf("[A][REV-34] int64: no int32 clamp (post-2038 epochs survive):\n");
	{ int64_t a[] = {5000000000LL, 4000000000LL}; EXPECT(a, 4000000000LL, "min of >2038 epochs preserved"); }
	{ int64_t a[] = {1LL << 40};      EXPECT(a, 1LL << 40, "single 2^40 expiry not truncated"); }
	{ int64_t a[] = {1LL << 40, 0};   EXPECT(a, 0,        "permanent still wins over a huge expiry"); }
	{ int64_t a[] = {INT64_MAX, 9000000000LL}; EXPECT(a, 9000000000LL, "INT64_MAX never the min here"); }

	printf("[A] adversarial: negatives are real candidates (only 0 is sentinel):\n");
	{ int64_t a[] = {-5, 100};        EXPECT(a, -5, "negative (past) expiry is the min => row due now"); }
	{ int64_t a[] = {-1};             EXPECT(a, -1, "lone negative preserved (not treated as permanent)"); }

	printf("[B][REV-18] finalize emits row_exp + schema_version peers:\n");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":100},\"c2\":{\"expires\":50}},\"aorhash\":7}");
	  CHECK(o != NULL, "finalize returns a document");
	  CHECK(o && _rowexp_of(o) == 50, "row_exp == min(100,50) == 50");
	  CHECK(o && strstr(o, "\"schema_version\":1") != NULL, "schema_version:1 emitted");
	  CHECK(o && strstr(o, "\"aorhash\":7") != NULL, "aorhash preserved");
	  CHECK(o && strstr(o, "\"contacts\":") != NULL, "contacts preserved");
	  free(o); }

	printf("[B] permanent contact => row_exp 0 in output:\n");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":0},\"c2\":{\"expires\":50}},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 0, "permanent member => row_exp 0"); free(o); }

	printf("[B][REV-34] int64 expiry survives the finalize emit:\n");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":5000000000}},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 5000000000LL, "row_exp 5e9 emitted intact (no int32 clamp)"); free(o); }

	printf("[B] stale private peers are replaced, not duplicated:\n");
	{ char *o = _fin("{\"contacts\":{\"c1\":{\"expires\":50}},\"row_exp\":999,\"schema_version\":1,\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 50, "stale row_exp:999 recomputed to 50");
	  CHECK(o && _count(o, "\"row_exp\"") == 1, "exactly one row_exp key");
	  CHECK(o && _count(o, "\"schema_version\"") == 1, "exactly one schema_version key");
	  free(o); }

	printf("[B] empty contacts object => row_exp 0:\n");
	{ char *o = _fin("{\"contacts\":{},\"aorhash\":7}");
	  CHECK(o && _rowexp_of(o) == 0, "no contacts => row_exp 0"); free(o); }

	printf("[B][REV-18] non-usrloc doc (no contacts) returned byte-for-byte:\n");
	{ const char *in = "{\"foo\":1,\"bar\":\"x\"}";
	  char *o = _fin(in);
	  CHECK(o && strcmp(o, in) == 0, "doc without contacts unchanged");
	  CHECK(o && strstr(o, "row_exp") == NULL, "no row_exp injected into non-usrloc doc");
	  free(o); }

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
