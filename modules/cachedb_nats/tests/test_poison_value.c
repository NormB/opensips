/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P2.5 / SPEC.md §4.2 [REV-26]: fail-closed on a poison stored value.
 *
 * On read, the current code gates on `data && data_len > 0 && data[0] == '{'`
 * and treats EVERYTHING else as "no row" — so a non-empty value that is not a
 * JSON object (null / a bare string / a number / an array / garbage planted by
 * an old node, a co-writer, or an attacker) silently empties the AoR, i.e. a
 * silent deregistration.  [REV-26] makes that a hard integrity error: alarm +
 * `poison_values_rejected`, NOT a masked empty result.
 *
 * An EMPTY value (zero-length / all-whitespace) is a *legitimate* server-side
 * delete marker (TTL-SOLUTION §2.2/§4) and stays "absent", not poison.
 *
 * _value_classify(data,len) is the pure leaf:
 *   EMPTY  -> absent (delete marker)        -> res.count stays 0, no error
 *   OBJECT -> parse it
 *   POISON -> hard error: alarm + counter   -> never masked as empty
 *
 * RED/GREEN (carried-copy convention):
 *   gcc -DPOISON_CURRENT ... -> today's `data[0]=='{'` gate (non-object => EMPTY)
 *                               => RED (poison values misclassified as EMPTY).
 *   gcc ...                  -> the FIXED classifier => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 test_usrloc_poison_value_e2e.sh
 * (a planted non-object value => query hard-errors + counter, vs production).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_poison_value test_poison_value.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mirror of enum nats_val_class (cachedb_nats_json_internal.h) */
enum { VAL_EMPTY = 0, VAL_OBJECT = 1, VAL_POISON = 2 };

/* ─── carried copy of the production classifier (rowmeta TU) ─────── */
static int _value_classify(const char *data, int len)
{
#ifdef POISON_CURRENT
	/* today: data[0]=='{' is the only "object"; everything else (incl. a
	 * non-empty non-object) is treated as "no row" == EMPTY. */
	if (!data || len <= 0)
		return VAL_EMPTY;
	return (data[0] == '{') ? VAL_OBJECT : VAL_EMPTY;
#else
	const char *p, *end;
	if (!data || len <= 0)
		return VAL_EMPTY;
	p = data; end = data + len;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	if (p >= end)
		return VAL_EMPTY;             /* all whitespace == delete marker */
	return (*p == '{') ? VAL_OBJECT : VAL_POISON;
#endif
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
static const char *_name(int c)
{ return c == VAL_EMPTY ? "EMPTY" : c == VAL_OBJECT ? "OBJECT" : "POISON"; }

/* expectations are CONSTANT (FIXED semantics) so the CURRENT arm fails them. */
#define EXPECT(data, len, want, msg) do { \
	int _g = _value_classify((data), (len)); \
	if (_g != (want)) { printf("  FAIL: %s (got %s want %s)\n", msg, \
		_name(_g), _name(want)); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
#define EXPECTS(lit, want, msg) EXPECT((lit), (int)(sizeof(lit)-1), (want), (msg))

int main(void)
{
#ifdef POISON_CURRENT
	printf("== carried copy: POISON_CURRENT (data[0]=='{' gate) ==\n");
#else
	printf("== carried copy: FIXED classifier ==\n");
#endif

	printf("[REV-26] empty value == delete marker (absent, NOT poison):\n");
	EXPECT(NULL, 0, VAL_EMPTY, "NULL => EMPTY");
	EXPECTS("", VAL_EMPTY, "zero-length => EMPTY");
	EXPECTS("   ", VAL_EMPTY, "all-whitespace => EMPTY (marker)");
	EXPECTS("\t\n", VAL_EMPTY, "ws-only => EMPTY");

	printf("[REV-26] a JSON object parses normally:\n");
	EXPECTS("{}", VAL_OBJECT, "empty object => OBJECT");
	EXPECTS("{\"contacts\":{\"c1\":{\"expires\":9}}}", VAL_OBJECT, "real row => OBJECT");
	EXPECTS("  {\"x\":1}", VAL_OBJECT, "object with leading ws => OBJECT");

	printf("[REV-26] a non-empty non-object is POISON (hard error, not empty):\n");
	EXPECTS("null", VAL_POISON, "null => POISON");
	EXPECTS("\"a string\"", VAL_POISON, "bare string => POISON");
	EXPECTS("42", VAL_POISON, "bare number => POISON");
	EXPECTS("-1", VAL_POISON, "negative number => POISON");
	EXPECTS("true", VAL_POISON, "bool => POISON");
	EXPECTS("[1,2,3]", VAL_POISON, "array => POISON (not an object)");
	EXPECTS("garbage", VAL_POISON, "unparseable text => POISON");
	EXPECTS("}{", VAL_POISON, "starts with '}' => POISON");
	EXPECTS("x", VAL_POISON, "single non-{ char => POISON");
	EXPECTS("  null", VAL_POISON, "leading ws then non-object => POISON");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
