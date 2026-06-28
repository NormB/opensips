/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P2.3 / SPEC.md §3.1 §4.1-step-0 [REV-20]: reject-at-write any contact field
 * that carries an embedded NUL.  An OpenSIPS `str` is length-based, so a `0x00`
 * byte is reachable in fields like `ua`/`attr`.  Such a value CANNOT round-trip:
 * the reader is `cJSON_Parse` + `str.len = strlen(valuestring)`
 * (cachedb/cachedb_dict.c:565), so an interior NUL silently truncates the value
 * — corruption.  A raw NUL in the wire buffer is already caught by
 * `_json_parse_guard`, but the ESCAPED form `\u0000` slips through the guard,
 * is decoded by cJSON into a `0x00`, and then truncates on `strlen`.  v1 refuses
 * the save (no partial row, integrity counter ++) for EITHER form.
 *
 * _field_has_nul(s,len) is the byte-level detector: 1 if @s contains a raw
 * `0x00` OR the 6-byte JSON escape `\u0000` (decodes to NUL); else 0.  It is
 * fail-closed: a value embedding the literal escape sequence is conservatively
 * refused (a real SIP UA/attr never carries it; correctness over permissiveness).
 *
 * RED/GREEN from one file (carried-copy convention, matches the Tier-1 suite):
 *   gcc -DNULCHK_CURRENT ... -> today's behavior: NO reject (helper absent,
 *                               modelled as "always 0") => RED.
 *   gcc ...                  -> the FIXED detector => GREEN.
 *
 * Rule 6 [PREV-4 / REV-20/F20]: a carried Tier-1 copy cannot prove byte-exact
 * production behavior; the AUTHORITATIVE proof is the Tier-2
 * test_usrloc_nul_field_e2e.sh (NUL field => clean reject, vs production).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reject_nul_field test_reject_nul_field.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── carried copy of the production helper (cachedb_nats_json_rowmeta.c) ─── */

static int _field_has_nul(const char *s, int len)
{
#ifdef NULCHK_CURRENT
	(void)s; (void)len; return 0;   /* TODAY: write path does no NUL reject */
#else
	int i;
	if (!s || len <= 0)
		return 0;
	for (i = 0; i < len; i++) {
		if (s[i] == '\0')
			return 1;                       /* raw 0x00 byte */
		/* escaped JSON NUL: backslash 'u' '0' '0' '0' '0' (decodes to 0x00) */
		if (s[i] == '\\' && i + 5 < len &&
		    s[i+1] == 'u' &&
		    s[i+2] == '0' && s[i+3] == '0' &&
		    s[i+4] == '0' && s[i+5] == '0')
			return 1;
	}
	return 0;
#endif
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

/* len-explicit helper so embedded NULs are honoured (no strlen). */
#define HASNUL(lit) _field_has_nul((lit), (int)(sizeof(lit) - 1))

int main(void)
{
#ifdef NULCHK_CURRENT
	printf("== carried copy: NULCHK_CURRENT (today: no NUL reject) ==\n");
#else
	printf("== carried copy: FIXED behavior ==\n");
#endif

	printf("[REV-20] clean fields are accepted (no NUL):\n");
	CHECK(HASNUL("alice@example.com") == 0, "plain AoR-ish value accepted");
	CHECK(_field_has_nul("", 0) == 0, "empty value accepted");
	CHECK(_field_has_nul(NULL, 0) == 0, "NULL value accepted (defensive)");
	CHECK(HASNUL("Acme-UA/3.14 (x86_64)") == 0, "typical UA string accepted");
	CHECK(HASNUL("version0000build") == 0, "bare '0000' digits NOT a false positive");
	CHECK(HASNUL("u0000") == 0, "'u0000' without backslash accepted");

	printf("[REV-20] a raw 0x00 byte is rejected:\n");
	{ const char v[] = {'a','\0','b'};  CHECK(_field_has_nul(v, 3) == 1, "interior raw NUL rejected"); }
	{ const char v[] = {'\0','a','b'};  CHECK(_field_has_nul(v, 3) == 1, "leading raw NUL rejected"); }
	{ const char v[] = {'a','b','\0'};  CHECK(_field_has_nul(v, 3) == 1, "trailing raw NUL rejected"); }
	{ const char v[] = {'\0'};          CHECK(_field_has_nul(v, 1) == 1, "lone raw NUL rejected"); }

	printf("[REV-20] the escaped form \\u0000 is equally rejected:\n");
	CHECK(HASNUL("\\u0000") == 1, "bare \\u0000 rejected");
	CHECK(HASNUL("ua\\u0000evil") == 1, "interior \\u0000 rejected");
	CHECK(HASNUL("\\u0000tail") == 1, "leading \\u0000 rejected");
	CHECK(HASNUL("head\\u0000") == 1, "trailing \\u0000 rejected");

	printf("[REV-20] adversarial: non-NUL escapes must NOT be rejected:\n");
	CHECK(HASNUL("line\\none") == 0, "\\n (newline escape) accepted");
	CHECK(HASNUL("tab\\tend") == 0, "\\t accepted");
	CHECK(HASNUL("back\\\\slash") == 0, "\\\\ (escaped backslash) accepted");
	CHECK(HASNUL("char\\u0041A") == 0, "\\u0041 (letter 'A') accepted");
	CHECK(HASNUL("ctrl\\u0001x") == 0, "\\u0001 (SOH, not NUL) accepted");
	CHECK(HASNUL("max\\uffff") == 0, "\\uffff accepted");
	CHECK(HASNUL("trunc\\u00") == 0, "truncated \\u00 at end accepted (no match)");
	CHECK(HASNUL("trunc\\u000") == 0, "truncated \\u000 at end accepted (no match)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
