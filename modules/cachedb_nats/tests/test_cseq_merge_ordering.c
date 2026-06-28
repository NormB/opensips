/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P2.2 / SPEC.md §4.1-step-2 [REV-8]: same-subkey merge ordering.
 *
 * On a collision for the SAME contact subkey, the merge MUST keep the higher
 * `cseq` (tie-broken by `last_mod`) and discard a stale write — even if its CAS
 * would otherwise succeed.  CAS alone protects the row across DIFFERENT contacts;
 * without a cseq check the same-contact path is blind last-writer-wins and can
 * roll a binding backward versus the SQL backend (e.g. a delayed/retransmitted
 * REGISTER with an older cseq overwriting the current binding).
 *
 * The decision engages ONLY when BOTH values carry a `cseq` (usrloc contacts).
 * For any other subkey (a non-usrloc cachedb_nats consumer, or a value that is
 * not a JSON object), _cseq_new_wins returns 1 → last-writer-wins, exactly the
 * generic merge's current behavior (so the existing merge tests are unaffected).
 *
 *   gcc -DCSEQ_CURRENT ... -> today: blind last-writer-wins (_cseq_new_wins
 *                             always 1) => RED (a stale write is NOT discarded).
 *   gcc ...               -> the FIXED ordering => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (an out-of-order REGISTER
 * must not roll a binding backward) vs the production _sink_merge_subkeys.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_cseq_merge_ordering test_cseq_merge_ordering.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── carried copy: JSON walkers + int64 parse + field extractor ──── */
static const char *_skip_ws(const char *p, const char *end)
{ while (p < end && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r')) p++; return p; }
static const char *_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++; start = p;
	while (p < end && *p != '"') { if (*p=='\\'){p++; if(p>=end)return NULL;} p++; }
	if (p >= end) return NULL;
	*out = start; *out_len = (int)(p - start); return p + 1;
}
static const char *_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = _skip_ws(p, end);
	if (p >= end) return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') { if (*p=='\\'){p++; if(p>=end)return NULL;} p++; }
		return (p < end) ? p + 1 : NULL;
	case '{': case '[':
		depth = 1; p++;
		while (p < end && depth > 0) {
			if (*p=='{'||*p=='[') depth++;
			else if (*p=='}'||*p==']') depth--;
			else if (*p=='"') { p++; while(p<end&&*p!='"'){if(*p=='\\'){p++;if(p>=end)return NULL;}p++;} if(p>=end)return NULL; }
			p++;
		}
		return p;
	default:
		while (p<end && *p!=','&&*p!='}'&&*p!=']'&&*p!=' '&&*p!='\t'&&*p!='\n'&&*p!='\r') p++;
		return p;
	}
}
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
	*out = neg ? -(int64_t)mag : (int64_t)mag; return p;
}
static int _contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out)
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
		if (nlen == flen && memcmp(name, fname, flen) == 0) {
			int64_t v; if (_json_parse_int64(vs, vend, &v)) { *out = v; return 0; }
		}
		p = _skip_json_value(p, vend);
		if (!p) return -1;
	}
	return -1;
}

/* ─── carried copy: the ordering decision (rowmeta TU) ──────────── */
static int _cseq_new_wins(const char *new_json, int new_len,
	const char *old_json, int old_len)
{
#ifdef CSEQ_CURRENT
	(void)new_json; (void)new_len; (void)old_json; (void)old_len;
	(void)_contact_field_int64;
	return 1;   /* today: blind last-writer-wins */
#else
	int64_t nc, oc, nlm = 0, olm = 0;
	/* engage only when BOTH carry a cseq; else last-writer-wins. */
	if (_contact_field_int64(new_json, new_json + new_len, "cseq", 4, &nc) != 0)
		return 1;
	if (_contact_field_int64(old_json, old_json + old_len, "cseq", 4, &oc) != 0)
		return 1;
	if (nc != oc)
		return nc > oc;
	/* tie on cseq → higher last_mod wins (absent treated as 0). */
	_contact_field_int64(new_json, new_json + new_len, "last_mod", 8, &nlm);
	_contact_field_int64(old_json, old_json + old_len, "last_mod", 8, &olm);
	return nlm > olm;
#endif
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
/* wins(new, old): does the new value supersede the old? */
static int wins(const char *n, const char *o)
{ return _cseq_new_wins(n, (int)strlen(n), o, (int)strlen(o)); }

int main(void)
{
#ifdef CSEQ_CURRENT
	printf("== carried copy: CSEQ_CURRENT (blind last-writer-wins) ==\n");
#else
	printf("== carried copy: FIXED cseq ordering ==\n");
#endif

	printf("[REV-8] higher cseq wins:\n");
	CHECK(wins("{\"cseq\":5,\"ua\":\"new\"}", "{\"cseq\":3,\"ua\":\"old\"}") == 1,
	      "new cseq 5 > old 3 => new wins (overwrite)");
	/* the load-bearing case: a STALE write (lower cseq) must be DISCARDED. */
	CHECK(wins("{\"cseq\":3,\"ua\":\"stale\"}", "{\"cseq\":5,\"ua\":\"cur\"}") == 0,
	      "new cseq 3 < old 5 => stale discarded (keep existing)");
	CHECK(wins("{\"cseq\":100}", "{\"cseq\":99}") == 1, "100 > 99 => new");
	CHECK(wins("{\"cseq\":99}", "{\"cseq\":100}") == 0, "99 < 100 => old");

	printf("[REV-8] tie on cseq => higher last_mod wins:\n");
	CHECK(wins("{\"cseq\":5,\"last_mod\":2000}", "{\"cseq\":5,\"last_mod\":1000}") == 1,
	      "equal cseq, newer last_mod => new wins");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1000}", "{\"cseq\":5,\"last_mod\":2000}") == 0,
	      "equal cseq, older last_mod => stale discarded");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1000}", "{\"cseq\":5,\"last_mod\":1000}") == 0,
	      "exact duplicate (cseq+last_mod equal) => discarded (not strictly newer)");
	CHECK(wins("{\"cseq\":5,\"last_mod\":5000000000}", "{\"cseq\":5,\"last_mod\":4000000000}") == 1,
	      "int64 last_mod tie-break (post-2038)");

	printf("[REV-8] last-writer-wins fallback when cseq is absent:\n");
	CHECK(wins("{\"ua\":\"x\"}", "{\"cseq\":5}") == 1, "new lacks cseq => overwrite (current behavior)");
	CHECK(wins("{\"cseq\":3}", "{\"ua\":\"x\"}") == 1, "old lacks cseq => overwrite");
	CHECK(wins("{\"ua\":\"a\"}", "{\"ua\":\"b\"}") == 1, "neither has cseq => overwrite (non-usrloc subkey)");
	CHECK(wins("\"a string\"", "{\"cseq\":5}") == 1, "new not an object => overwrite");
	CHECK(wins("{\"cseq\":5}", "42") == 1, "old not an object => overwrite");

	printf("[REV-8] adversarial: tie with one side missing last_mod:\n");
	CHECK(wins("{\"cseq\":5,\"last_mod\":1}", "{\"cseq\":5}") == 1, "new has last_mod 1, old missing(0) => new wins");
	CHECK(wins("{\"cseq\":5}", "{\"cseq\":5,\"last_mod\":1}") == 0, "new missing last_mod(0) < old 1 => discarded");
	CHECK(wins("{\"cseq\":-1}", "{\"cseq\":-2}") == 1, "signed cseq compare (-1 > -2)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
