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
 * P9 / SPEC.md §4.3A [REV-1 / REV-16 / REV-3 / REV-26]: the reaper's survivor
 * projection.  Given a stored usrloc row JSON, drop every DUE contact and
 * recompute the row's expiry sentinel over the survivors, so the reaper can
 * CAS-write the survivor row (or, when nothing survives, learn it must instead
 * CAS-delete the whole key).
 *
 * cdbn_reap_project_survivors(json,len,now,grace,&n_survivors,&out_len):
 *   per-contact DUE decision (mirrors the P4 read filter, fail-closed):
 *     - expires == 0           -> permanent, KEEP (never reaped);
 *     - expires + grace <= now -> DUE, drop  (grace = nats_reap_grace = S);
 *     - absent/unparseable     -> fail-closed DUE, drop (never keep a binding
 *                                 we cannot prove is live) [REV-26];
 *     - else                   -> live, KEEP.
 *   row_exp is recomputed over the SURVIVORS only (min, 0 = permanent) [REV-34];
 *   a row with no top-level "contacts" is not a usrloc row -> returned unchanged
 *   with *n_survivors = -1 so the reaper skips it; a fully-due row returns valid
 *   JSON with an empty contacts {} and *n_survivors = 0 (caller CAS-deletes).
 *
 * RED/GREEN from one file (carried-copy convention, matches the Tier-1 suite):
 *   gcc -DREAP_PROJECT_CURRENT ... -> naive: fail-OPEN on an absent expires
 *                                     (keeps an unprovable binding), a strict
 *                                     '<' grace boundary, AND row_exp recomputed
 *                                     over ALL contacts incl. the dropped ones
 *                                     => RED.
 *   gcc ...                        -> the FIXED projection => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 run_reaper_e2e.sh (a short-expiry
 * binding physically removed from JetStream + rows_reaped incremented) vs the
 * production reaper host.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_project test_reap_project.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── carried copy: row_exp arithmetic (cachedb_nats_json_rowmeta.c) ── */
static int64_t _row_exp_min(const int64_t *exp, int n)
{
	int64_t m = 0;
	int i, seen = 0;
	if (!exp || n <= 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (exp[i] == 0)
			return 0;
		if (!seen || exp[i] < m) { m = exp[i]; seen = 1; }
	}
	return seen ? m : 0;
}

/* ─── carried copy: JSON walkers (cachedb_nats_json_index.c) ────────── */
static const char *cdbn_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
	return p;
}
static const char *cdbn_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++; start = p;
	while (p < end && *p != '"') { if (*p == '\\') { p++; if (p >= end) return NULL; } p++; }
	if (p >= end) return NULL;
	*out = start; *out_len = (int)(p - start);
	return p + 1;
}
static const char *cdbn_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = cdbn_skip_ws(p, end);
	if (p >= end) return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') { if (*p == '\\') { p++; if (p >= end) return NULL; } p++; }
		return (p < end) ? p + 1 : NULL;
	case '{':
	case '[':
		depth = 1; p++;
		while (p < end && depth > 0) {
			if (*p == '{' || *p == '[') depth++;
			else if (*p == '}' || *p == ']') depth--;
			else if (*p == '"') {
				p++;
				while (p < end && *p != '"') { if (*p == '\\') { p++; if (p >= end) return NULL; } p++; }
				if (p >= end) return NULL;
			}
			p++;
		}
		return p;
	default:
		while (p < end && *p != ',' && *p != '}' && *p != ']'
				&& *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
		return p;
	}
}

/* ─── carried copy: minimal json_sink_t (cachedb_nats_json_ser.c) ───── */
typedef struct { char *buf; int len; int cap; int oom; } json_sink_t;
static int cdbn_sink_init(json_sink_t *s, int initial)
{
	s->buf = malloc(initial > 0 ? initial : 16);
	if (!s->buf) return -1;
	s->len = 0; s->cap = initial > 0 ? initial : 16; s->oom = 0;
	return 0;
}
static int _sink_grow(json_sink_t *s, int need)
{
	int ncap = s->cap; char *nb;
	while (ncap - s->len < need) ncap *= 2;
	nb = realloc(s->buf, ncap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb; s->cap = ncap;
	return 0;
}
static int cdbn_sink_write(json_sink_t *s, const char *p, int n)
{
	if (s->oom) return -1;
	if (s->cap - s->len < n && _sink_grow(s, n) < 0) return -1;
	memcpy(s->buf + s->len, p, n); s->len += n;
	return 0;
}
static int cdbn_sink_putc(json_sink_t *s, char c) { return cdbn_sink_write(s, &c, 1); }
static int cdbn_sink_emit_raw_string(json_sink_t *s, const char *p, int n)
{
	if (cdbn_sink_putc(s, '"') < 0) return -1;
	if (cdbn_sink_write(s, p, n) < 0) return -1;
	return cdbn_sink_putc(s, '"');
}
static int cdbn_sink_emit_int(json_sink_t *s, int64_t v)
{
	char tmp[32];
	int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
	return cdbn_sink_write(s, tmp, n);
}
static char *cdbn_sink_take(json_sink_t *s, int *out_len)
{
	if (s->oom) { free(s->buf); return NULL; }
	if (cdbn_sink_putc(s, '\0') < 0) return NULL;
	if (out_len) *out_len = s->len - 1;
	return s->buf;
}

/* ─── carried copy: per-contact expiry parse (rowmeta) ──────────────── */
static const char *_json_parse_int64(const char *p, const char *end, int64_t *out)
{
	int neg = 0; uint64_t mag = 0;
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
/* returns 0 + *out if the contact object carries an integer "expires", else -1 */
static int cdbn_contact_expires(const char *vstart, const char *vend, int64_t *out)
{
	const char *p = cdbn_skip_ws(vstart, vend);
	if (p >= vend || *p != '{') return -1;
	p++;
	while (p < vend) {
		const char *name, *vs; int nlen;
		p = cdbn_skip_ws(p, vend);
		if (p >= vend) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, vend, &name, &nlen);
		if (!p) return -1;
		p = cdbn_skip_ws(p, vend);
		if (p >= vend || *p != ':') return -1;
		p++;
		p = cdbn_skip_ws(p, vend);
		vs = p;
		if (nlen == 7 && memcmp(name, "expires", 7) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, vend, &v)) { *out = v; return 0; }
		}
		p = cdbn_skip_json_value(p, vend);
		if (!p) return -1;
	}
	return -1;
}

/* ─── carried copy: generic top-level int64 field extractor + due-gate ── */
static int cdbn_contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out)
{
	const char *p = cdbn_skip_ws(vstart, vend);
	if (p >= vend || *p != '{') return -1;
	p++;
	while (p < vend) {
		const char *name, *vs; int nlen;
		p = cdbn_skip_ws(p, vend);
		if (p >= vend) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, vend, &name, &nlen);
		if (!p) return -1;
		p = cdbn_skip_ws(p, vend);
		if (p >= vend || *p != ':') return -1;
		p++;
		p = cdbn_skip_ws(p, vend);
		vs = p;
		if (nlen == flen && memcmp(name, fname, flen) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, vend, &v)) { *out = v; return 0; }
			return -1;
		}
		p = cdbn_skip_json_value(p, vend);
		if (!p) return -1;
	}
	return -1;
}
static int cdbn_reap_row_due(int64_t row_exp, long now, int grace)
{ return row_exp != 0 && (row_exp + (int64_t)grace) <= (int64_t)now; }
static int cdbn_reap_row_due_json(const char *json, int len, long now, int grace)
{
	int64_t row_exp;
	if (!json || len <= 0) return -1;
	if (cdbn_contact_field_int64(json, json + len, "row_exp", 7, &row_exp) != 0)
		return -1;
	return cdbn_reap_row_due(row_exp, now, grace);
}

/* ─── the unit under test: reaper survivor projection ───────────────── */

/* per-contact DUE decision (1 = drop). */
static int _reap_contact_due(int has_exp, int64_t expires, long now, int grace)
{
#ifdef REAP_PROJECT_CURRENT
	/* CURRENT (buggy): fail-OPEN on an absent expires (keeps an unprovable
	 * binding), and a strict '<' so the exact +grace boundary is wrongly kept. */
	if (!has_exp) return 0;
	return expires != 0 && (expires + (int64_t)grace) < (long)now;
#else
	if (!has_exp) return 1;                       /* fail-closed: unprovable => due */
	return expires != 0 && (expires + (int64_t)grace) <= (int64_t)now;
#endif
}

/* Emit a filtered "contacts" object holding only surviving contacts, verbatim. */
static int _emit_survivor_contacts(json_sink_t *s, const char *c_vs, const char *c_ve,
	long now, int grace)
{
	const char *p = cdbn_skip_ws(c_vs, c_ve);
	int first = 1;
	if (p >= c_ve || *p != '{') return -1;
	if (cdbn_sink_putc(s, '{') < 0) return -1;
	p++;
	while (p < c_ve) {
		const char *name, *cvs; int nlen; int64_t e; int has;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, c_ve, &name, &nlen);
		if (!p) return -1;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p != ':') return -1;
		p++;
		p = cdbn_skip_ws(p, c_ve);
		cvs = p;
		p = cdbn_skip_json_value(p, c_ve);
		if (!p) return -1;
		has = (cdbn_contact_expires(cvs, p, &e) == 0);
		if (_reap_contact_due(has, e, now, grace))
			continue;                              /* drop this contact */
		if (!first && cdbn_sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (cdbn_sink_emit_raw_string(s, name, nlen) < 0) return -1;
		if (cdbn_sink_putc(s, ':') < 0) return -1;
		if (cdbn_sink_write(s, cvs, (int)(p - cvs)) < 0) return -1;
	}
	return cdbn_sink_putc(s, '}');
}

static char *cdbn_reap_project_survivors(const char *json, int len, long now, int grace,
	int *n_survivors, int *out_len)
{
	const char *p, *end, *c_vs = NULL, *c_ve = NULL;
	int64_t *surv = NULL, *allc = NULL;
	int n_surv = 0, n_all_kept = 0, cap_s = 0, cap_a = 0;
	int64_t row_exp;
	int first = 1;
	json_sink_t s;

	if (n_survivors) *n_survivors = 0;
	if (!json || len <= 0) return NULL;
	end = json + len;
	p = cdbn_skip_ws(json, end);
	if (p >= end || *p != '{') return NULL;
	p++;
	/* pass 1: locate the contacts object */
	while (p < end) {
		const char *name, *vs; int nlen;
		p = cdbn_skip_ws(p, end);
		if (p >= end) return NULL;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) return NULL;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') return NULL;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) return NULL;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) { c_vs = vs; c_ve = p; }
	}
	if (!c_vs) {                                   /* not a usrloc row -> skip */
		char *copy = malloc(len + 1);
		if (!copy) return NULL;
		memcpy(copy, json, len); copy[len] = '\0';
		if (n_survivors) *n_survivors = -1;
		if (out_len) *out_len = len;
		return copy;
	}
	/* pass 2: classify each contact, collect survivor + (all-kept) expiries */
	{
		const char *q = cdbn_skip_ws(c_vs, c_ve);
		if (q >= c_ve || *q != '{') { free(surv); free(allc); return NULL; }
		q++;
		while (q < c_ve) {
			const char *name, *cvs; int nlen; int64_t e; int has, due;
			q = cdbn_skip_ws(q, c_ve);
			if (q >= c_ve) break;
			if (*q == '}') break;
			if (*q == ',') { q++; continue; }
			q = cdbn_parse_json_string(q, c_ve, &name, &nlen);
			if (!q) { free(surv); free(allc); return NULL; }
			q = cdbn_skip_ws(q, c_ve);
			if (q >= c_ve || *q != ':') { free(surv); free(allc); return NULL; }
			q++;
			q = cdbn_skip_ws(q, c_ve);
			cvs = q;
			q = cdbn_skip_json_value(q, c_ve);
			if (!q) { free(surv); free(allc); return NULL; }
			has = (cdbn_contact_expires(cvs, q, &e) == 0);
			due = _reap_contact_due(has, e, now, grace);
			/* "all kept" set: every contact's parseable expiry (CURRENT bug
			 * computes row_exp over THIS instead of survivors). */
			if (has) {
				if (n_all_kept == cap_a) {
					int nc = cap_a ? cap_a * 2 : 8;
					int64_t *na = realloc(allc, nc * sizeof(*na));
					if (!na) { free(surv); free(allc); return NULL; }
					allc = na; cap_a = nc;
				}
				allc[n_all_kept++] = e;
			}
			if (!due) {                            /* survivor */
				if (n_surv == cap_s) {
					int nc = cap_s ? cap_s * 2 : 8;
					int64_t *na = realloc(surv, nc * sizeof(*na));
					if (!na) { free(surv); free(allc); return NULL; }
					surv = na; cap_s = nc;
				}
				surv[n_surv++] = has ? e : 0;
			}
		}
	}
#ifdef REAP_PROJECT_CURRENT
	row_exp = _row_exp_min(allc, n_all_kept);      /* BUG: incl. dropped contacts */
#else
	row_exp = _row_exp_min(surv, n_surv);          /* survivors only */
#endif
	free(surv); free(allc);

	/* pass 3: copy through top-level fields, filtering contacts, re-emit peers */
	if (cdbn_sink_init(&s, len + 64) < 0) return NULL;
	if (cdbn_sink_putc(&s, '{') < 0) goto fail;
	p = cdbn_skip_ws(json, end); p++;
	while (p < end) {
		const char *name, *vs; int nlen;
		p = cdbn_skip_ws(p, end);
		if (p >= end) goto fail;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p) goto fail;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':') goto fail;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p) goto fail;
		if ((nlen == 7 && memcmp(name, "row_exp", 7) == 0) ||
		    (nlen == 14 && memcmp(name, "schema_version", 14) == 0))
			continue;
		if (!first && cdbn_sink_putc(&s, ',') < 0) goto fail;
		first = 0;
		if (cdbn_sink_emit_raw_string(&s, name, nlen) < 0) goto fail;
		if (cdbn_sink_putc(&s, ':') < 0) goto fail;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (_emit_survivor_contacts(&s, vs, p, now, grace) < 0) goto fail;
		} else {
			if (cdbn_sink_write(&s, vs, (int)(p - vs)) < 0) goto fail;
		}
	}
	if (!first && cdbn_sink_putc(&s, ',') < 0) goto fail;
	if (cdbn_sink_write(&s, "\"row_exp\":", 10) < 0) goto fail;
	if (cdbn_sink_emit_int(&s, row_exp) < 0) goto fail;
	if (cdbn_sink_write(&s, ",\"schema_version\":1", 19) < 0) goto fail;
	if (cdbn_sink_putc(&s, '}') < 0) goto fail;
	if (n_survivors) *n_survivors = n_surv;
	return cdbn_sink_take(&s, out_len);
fail:
	free(s.buf);
	return NULL;
}

/* ─── assertions ────────────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

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

int main(void)
{
	const long now = 1000;
	const int S = 5;
	int n;
	char *o;

#ifdef REAP_PROJECT_CURRENT
	printf("== carried copy: REAP_PROJECT_CURRENT (fail-open, '<' boundary, stale row_exp) ==\n");
#else
	printf("== carried copy: FIXED reaper survivor projection ==\n");
#endif

	printf("[REV-1] partial prune: one expired + one live -> survivor kept, row_exp recomputed:\n");
	{ const char *d = "{\"contacts\":{\"a\":{\"expires\":900},\"b\":{\"expires\":5000}},\"aorhash\":7}";
	o = cdbn_reap_project_survivors(d, (int)strlen(d), now, S, &n, NULL); }
	CHECK(o != NULL, "projection returns a document");
	CHECK(n == 1, "exactly 1 survivor (b live, a due at 900+5<=1000)");
	CHECK(o && strstr(o, "\"b\":") != NULL, "live contact b retained");
	CHECK(o && strstr(o, "\"a\":") == NULL, "due contact a dropped");
	CHECK(o && _rowexp_of(o) == 5000, "row_exp recomputed over SURVIVORS (5000), not 900");
	CHECK(o && strstr(o, "\"aorhash\":7") != NULL, "other top-level fields preserved");
	free(o);

	printf("[REV-1] grace boundary is inclusive (expires+S == now => due):\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":995}}}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":995}}}"), now, S, &n, NULL);
	CHECK(o && n == 0, "expires 995 + grace 5 == now 1000 => due (0 survivors)");
	CHECK(o && strstr(o, "\"a\":") == NULL, "boundary contact dropped");
	free(o);

	printf("[REV-1] within-skew contact NOT due (expires+S > now):\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":996}}}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":996}}}"), now, S, &n, NULL);
	CHECK(o && n == 1, "expires 996 + grace 5 > now => kept");
	CHECK(o && _rowexp_of(o) == 996, "row_exp == 996");
	free(o);

	printf("[REV-26] fail-closed: a contact with NO/!int expires is DUE (dropped):\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"callid\":\"x\"},\"b\":{\"expires\":5000}}}",
		(int)strlen("{\"contacts\":{\"a\":{\"callid\":\"x\"},\"b\":{\"expires\":5000}}}"),
		now, S, &n, NULL);
	CHECK(o && n == 1, "unprovable contact a dropped, b survives");
	CHECK(o && strstr(o, "\"a\":") == NULL, "absent-expires contact dropped (fail-closed)");
	free(o);

	printf("[REV-1] permanent (expires==0) is NEVER reaped:\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":0},\"b\":{\"expires\":900}}}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":0},\"b\":{\"expires\":900}}}"),
		now, S, &n, NULL);
	CHECK(o && n == 1, "permanent a kept, expired b dropped");
	CHECK(o && strstr(o, "\"a\":") != NULL, "permanent contact retained");
	CHECK(o && _rowexp_of(o) == 0, "any permanent survivor => row_exp 0");
	free(o);

	printf("[REV-16] fully-due row => 0 survivors + empty contacts (caller CAS-deletes):\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":900},\"b\":{\"expires\":800}},\"aorhash\":7}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":900},\"b\":{\"expires\":800}},\"aorhash\":7}"),
		now, S, &n, NULL);
	CHECK(o && n == 0, "all contacts due => 0 survivors");
	CHECK(o && strstr(o, "\"contacts\":{}") != NULL, "empty contacts object emitted");
	CHECK(o && _rowexp_of(o) == 0, "row_exp 0 over empty survivor set");
	free(o);

	printf("[REV-1] nothing due => all kept, row_exp = min(survivors):\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":5000},\"b\":{\"expires\":4000}}}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":5000},\"b\":{\"expires\":4000}}}"),
		now, S, &n, NULL);
	CHECK(o && n == 2, "both live => 2 survivors");
	CHECK(o && _rowexp_of(o) == 4000, "row_exp == min(5000,4000) == 4000");
	free(o);

	printf("[REV-18] stale private peers replaced, exactly one each:\n");
	o = cdbn_reap_project_survivors(
		"{\"contacts\":{\"a\":{\"expires\":5000}},\"row_exp\":111,\"schema_version\":1}",
		(int)strlen("{\"contacts\":{\"a\":{\"expires\":5000}},\"row_exp\":111,\"schema_version\":1}"),
		now, S, &n, NULL);
	CHECK(o && _rowexp_of(o) == 5000, "stale row_exp:111 recomputed to 5000");
	CHECK(o && _count(o, "\"row_exp\"") == 1, "exactly one row_exp key");
	CHECK(o && _count(o, "\"schema_version\"") == 1, "exactly one schema_version key");
	free(o);

	printf("[REV-18] non-usrloc doc (no contacts) untouched, n_survivors = -1:\n");
	o = cdbn_reap_project_survivors("{\"foo\":1}", (int)strlen("{\"foo\":1}"), now, S, &n, NULL);
	CHECK(o && n == -1, "no contacts => n_survivors -1 (reaper skips)");
	CHECK(o && strcmp(o, "{\"foo\":1}") == 0, "doc returned byte-for-byte");
	free(o);

	printf("[REV-1/25] reaper due-gate over the stored row_exp:\n");
	CHECK(cdbn_reap_row_due_json("{\"row_exp\":900}", 15, now, S) == 1, "row_exp 900 +5<=1000 => due (1)");
	CHECK(cdbn_reap_row_due_json("{\"row_exp\":996}", 15, now, S) == 0, "row_exp 996 +5>1000 => not due (0)");
	CHECK(cdbn_reap_row_due_json("{\"row_exp\":0}", 13, now, S) == 0, "row_exp 0 (permanent) => never due (0)");
	CHECK(cdbn_reap_row_due_json("{\"aorhash\":7}", 13, now, S) == -1, "absent row_exp => -1 (legacy, fail-closed project)");
	CHECK(cdbn_reap_row_due_json("{\"row_exp\":5000000000}", 22, now, S) == 0, "post-2038 row_exp not due (int64, no clamp)");

	printf("[adversarial] malformed JSON => NULL, no crash/leak:\n");
	CHECK(cdbn_reap_project_survivors("[1,2,3]", 7, now, S, &n, NULL) == NULL, "non-object top-level => NULL");
	CHECK(cdbn_reap_project_survivors("{\"contacts\":}", 13, now, S, &n, NULL) == NULL, "contacts value not an object => NULL");
	CHECK(cdbn_reap_project_survivors("", 0, now, S, &n, NULL) == NULL, "empty => NULL");
	CHECK(cdbn_reap_project_survivors(NULL, 5, now, S, &n, NULL) == NULL, "NULL => NULL");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
