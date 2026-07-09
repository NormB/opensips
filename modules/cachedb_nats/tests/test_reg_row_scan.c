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
 * Registration-observability MI [OBS]: cdbn_reg_row_scan() -- one pass over a
 * stored usrloc row producing the per-AoR summary the MI commands (and the
 * reaper's piggybacked gauges) are built from:
 *
 *   aor slice, stored/active/expired/permanent contact counts,
 *   soonest non-permanent expiry (INT64_MAX when nothing expires),
 *   max last_mod, and ua=/contact= substring hits (raw, escaped text).
 *
 * Fail-closed rules (mirror the read path): a contact whose `expires` is
 * absent or non-integer counts as EXPIRED (stored but never served) and
 * contributes nothing to soonest_exp; a contacts member that is not an
 * object counts the same way.  A doc without a top-level "contacts" object
 * is NOT a usrloc row (-1) -- the MI must count it as other_docs, never
 * guess.
 *
 *   gcc -DREGSCAN_CURRENT ... -> naive scan: counts every member as an
 *                                active contact, no fail-closed handling,
 *                                soonest ignores the permanent rule => RED.
 *   gcc ...                   -> the FIXED walker => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reg_row_scan test_reg_row_scan.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define REG_NO_EXPIRY INT64_MAX

/* ─── carried copies of the shared JSON walkers (json_index/rowmeta) ── */

static const char *cdbn_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}

static const char *cdbn_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"')
		return NULL;
	p++;
	start = p;
	while (p < end && *p != '"') {
		if (*p == '\\') {
			p++;
			if (p >= end)
				return NULL;
		}
		p++;
	}
	if (p >= end)
		return NULL;
	*out = start;
	*out_len = (int)(p - start);
	return p + 1;
}

static const char *cdbn_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = cdbn_skip_ws(p, end);
	if (p >= end)
		return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') { p++; if (p >= end) return NULL; }
			p++;
		}
		return (p < end) ? p + 1 : NULL;
	case '{': case '[':
		depth = 1;
		p++;
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

static const char *_json_parse_int64(const char *p, const char *end,
	int64_t *out)
{
	int neg = 0;
	uint64_t mag = 0;
	if (p >= end)
		return NULL;
	if (*p == '-') { neg = 1; p++; }
	if (p >= end || *p < '0' || *p > '9')
		return NULL;
	for (; p < end && *p >= '0' && *p <= '9'; p++) {
		uint64_t d = (uint64_t)(*p - '0');
		uint64_t lim = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
		if (mag > (lim - d) / 10)
			return NULL;
		mag = mag * 10 + d;
	}
	*out = neg ? -(int64_t)mag : (int64_t)mag;
	return p;
}

static int cdbn_reg_substr(const char *hay, int hlen, const char *nee, int nlen)
{
	int i;
	if (nlen <= 0 || nlen > hlen)
		return 0;
	for (i = 0; i + nlen <= hlen; i++)
		if (memcmp(hay + i, nee, nlen) == 0)
			return 1;
	return 0;
}

/* ─── carried copy of the walker under test (cachedb_nats_reg.c) ────── */

struct reg_row_info {
	const char *aor; int aor_len;
	int n_contacts, n_active, n_expired, n_perm;
	int64_t soonest_exp;
	int64_t last_mod;
	int ua_hit, ct_hit;
};

/* one contact object slice [cs,ce): classify + collect */
static void _reg_scan_contact(const char *cs, const char *ce,
	time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *o)
{
	const char *p = cdbn_skip_ws(cs, ce);
	int64_t expires = -1, lm = 0;
	int have_exp = 0;

	o->n_contacts++;
#ifdef REGSCAN_CURRENT
	(void)p; (void)now; (void)grace; (void)ua_nee; (void)ua_len;
	(void)ct_nee; (void)ct_len; (void)expires; (void)lm; (void)have_exp;
	o->n_active++;                              /* everything "active" */
	return;
#else
	if (p >= ce || *p != '{') {
		o->n_expired++;                         /* poison member: fail closed */
		return;
	}
	p++;
	while (p < ce) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, ce);
		if (p >= ce || *p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, ce, &name, &nlen);
		if (!p) { o->n_expired++; return; }     /* malformed: fail closed */
		p = cdbn_skip_ws(p, ce);
		if (p >= ce || *p != ':') { o->n_expired++; return; }
		p++;
		p = cdbn_skip_ws(p, ce);
		vs = p;
		if (nlen == 7 && memcmp(name, "expires", 7) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, ce, &v)) { expires = v; have_exp = 1; }
		} else if (nlen == 8 && memcmp(name, "last_mod", 8) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, ce, &v) && v > o->last_mod)
				o->last_mod = v;
			(void)lm;
		} else if ((nlen == 2 && memcmp(name, "ua", 2) == 0) ||
		           (nlen == 7 && memcmp(name, "contact", 7) == 0)) {
			const char *sv; int svl;
			if (*vs == '"' && cdbn_parse_json_string(vs, ce, &sv, &svl)) {
				if (nlen == 2 && ua_len &&
				    cdbn_reg_substr(sv, svl, ua_nee, ua_len))
					o->ua_hit = 1;
				if (nlen == 7 && ct_len &&
				    cdbn_reg_substr(sv, svl, ct_nee, ct_len))
					o->ct_hit = 1;
			}
		}
		p = cdbn_skip_json_value(p, ce);
		if (!p) { o->n_expired++; return; }
	}
	if (!have_exp) {
		o->n_expired++;                         /* no usable expiry: fail closed */
		return;
	}
	if (expires == 0) {
		o->n_perm++;
		return;                                 /* permanent: no soonest_exp */
	}
	if (expires + (int64_t)grace > (int64_t)now) {
		o->n_active++;
		if (expires < o->soonest_exp)
			o->soonest_exp = expires;
	} else {
		o->n_expired++;
		/* an already-expired contact still "dies next" for sorting? NO --
		 * it is already dead; soonest_exp ranks upcoming expiries only. */
	}
#endif
}

static int cdbn_reg_row_scan(const char *json, int len, time_t now, int grace,
	const char *ua_nee, int ua_len, const char *ct_nee, int ct_len,
	struct reg_row_info *o)
{
	const char *p, *end = json + len;
	const char *c_vs = NULL, *c_ve = NULL;

	memset(o, 0, sizeof(*o));
	o->soonest_exp = REG_NO_EXPIRY;

	p = cdbn_skip_ws(json, end);
	if (p >= end || *p != '{')
		return -1;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, end);
		if (p >= end)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, end, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, end);
		vs = p;
		p = cdbn_skip_json_value(p, end);
		if (!p)
			return -1;
		if (nlen == 3 && memcmp(name, "aor", 3) == 0 && *vs == '"') {
			cdbn_parse_json_string(vs, end, &o->aor, &o->aor_len);
		} else if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (*vs != '{')
				return -1;                     /* poison contacts: not a row */
			c_vs = vs; c_ve = p;
		}
	}
	if (!c_vs)
		return -1;                             /* not a usrloc row */

	/* walk the contacts object's members */
	p = cdbn_skip_ws(c_vs, c_ve);
	p++;                                       /* '{' */
	while (p < c_ve) {
		const char *name, *vs;
		int nlen;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = cdbn_parse_json_string(p, c_ve, &name, &nlen);
		if (!p)
			return -1;
		p = cdbn_skip_ws(p, c_ve);
		if (p >= c_ve || *p != ':')
			return -1;
		p++;
		p = cdbn_skip_ws(p, c_ve);
		vs = p;
		p = cdbn_skip_json_value(p, c_ve);
		if (!p)
			return -1;
		_reg_scan_contact(vs, p, now, grace,
			ua_nee, ua_len, ct_nee, ct_len, o);
	}
	return 0;
}

/* ─── harness ─────────────────────────────────────────────────────── */

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	struct reg_row_info o;
	const time_t NOW = 1000000;
	const int G = 5;

#ifdef REGSCAN_CURRENT
	printf("== carried copy: REGSCAN_CURRENT (naive scan) ==\n");
#else
	printf("== carried copy: FIXED row scan ==\n");
#endif

	printf("[OBS] typical mixed row: active + expired + permanent:\n");
	{
		const char *doc =
			"{\"aor\":\"alice@example.com\",\"aorhash\":7,\"contacts\":{"
			"\"k1\":{\"contact\":\"sip:a@10.0.0.1:5060\",\"expires\":1000100,"
			"\"ua\":\"Yealink T54W\",\"last_mod\":999990},"
			"\"k2\":{\"contact\":\"sip:a@10.0.0.2:5060\",\"expires\":999900,"
			"\"ua\":\"Zoiper 5\",\"last_mod\":999500},"
			"\"k3\":{\"contact\":\"sip:a@10.0.0.3:5060\",\"expires\":0,"
			"\"last_mod\":999999}"
			"},\"row_exp\":1000100,\"schema_version\":1}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0, "usrloc row recognized");
		CHECK(o.aor_len == 17 && memcmp(o.aor, "alice@example.com", 17) == 0,
			"aor slice extracted");
		CHECK(o.n_contacts == 3, "3 stored contacts");
		CHECK(o.n_active == 1, "1 active (k1: future expiry)");
		CHECK(o.n_expired == 1, "1 expired (k2: past expires+grace)");
		CHECK(o.n_perm == 1, "1 permanent (k3: expires=0)");
		CHECK(o.soonest_exp == 1000100,
			"soonest = the ACTIVE upcoming expiry (dead k2 does not rank)");
		CHECK(o.last_mod == 999999, "last_mod = max over contacts");
	}

	printf("[OBS] ua=/contact= substring hits over raw (escaped) values:\n");
	{
		const char *doc =
			"{\"aor\":\"b@x\",\"contacts\":{"
			"\"k1\":{\"expires\":1000100,\"ua\":\"evil\\\"quote agent\","
			"\"contact\":\"sip:b@host;transport=tcp\"}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"quote", 5, NULL, 0, &o) == 0 && o.ua_hit == 1,
			"ua needle matches across an escaped quote (raw text match)");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"Yealink", 7, NULL, 0, &o) == 0 && o.ua_hit == 0,
			"non-matching ua needle: no hit");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, "transport=tcp", 13, &o) == 0 && o.ct_hit == 1,
			"contact needle matches inside the URI ('=' in value)");
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, "callid", 6, &o) == 0 && o.ct_hit == 0,
			"needles never match OTHER fields (no cross-field bleed)");
	}

	printf("[OBS] fail-closed classification:\n");
	{
		const char *doc =
			"{\"aor\":\"c@x\",\"contacts\":{"
			"\"k1\":{\"ua\":\"noexp\"},"
			"\"k2\":{\"expires\":\"1000100\"},"
			"\"k3\":7,"
			"\"k4\":{\"expires\":1000100}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0, "row with poison members still scans");
		CHECK(o.n_contacts == 4, "all 4 stored members counted");
		CHECK(o.n_expired == 3,
			"missing expires, string expires, non-object member: ALL fail closed");
		CHECK(o.n_active == 1 && o.soonest_exp == 1000100,
			"the one well-formed contact classifies normally");
	}

	printf("[OBS] boundary + big values:\n");
	{
		const char *doc =
			"{\"aor\":\"d@x\",\"contacts\":{"
			"\"k1\":{\"expires\":999995},"
			"\"k2\":{\"expires\":5000000000}}}";
		/* k1: expires+grace == now exactly => expired (mirrors read filter) */
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0 &&
			o.n_expired == 1 && o.n_active == 1,
			"expires+grace==now boundary => expired");
		CHECK(o.soonest_exp == 5000000000LL, "post-2038 expiry survives (int64)");
	}

	printf("[OBS] empty / degenerate rows:\n");
	{
		const char *doc = "{\"aor\":\"e@x\",\"contacts\":{}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == 0 &&
			o.n_contacts == 0 && o.soonest_exp == REG_NO_EXPIRY,
			"empty contacts: zero counts, no-expiry sentinel");
	}
	{
		const char *doc = "{\"x\":1}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1,
			"doc without contacts => NOT a usrloc row (-1, counted as other)");
	}
	{
		const char *doc = "{\"aor\":\"f@x\",\"contacts\":[1,2]}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1,
			"contacts not an object => refused, never guessed");
	}
	{
		const char *doc = "not json at all";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			NULL, 0, NULL, 0, &o) == -1, "non-JSON => -1");
	}

	printf("[OBS] backslash torture (keys and values):\n");
	{
		const char *doc =
			"{\"aor\":\"g\\\\@x\",\"contacts\":{"
			"\"k\\\\1\":{\"expires\":1000100,\"ua\":\"back\\\\slash\"}}}";
		CHECK(cdbn_reg_row_scan(doc, (int)strlen(doc), NOW, G,
			"back\\\\slash", 11, NULL, 0, &o) == 0 &&
			o.n_active == 1 && o.ua_hit == 1,
			"escaped backslashes in key/value do not derail the walk");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
