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
 * P1 / SPEC.md [REV-9 + REV-23 + REV-33]: the usrloc row-key encoder must be
 * injective, round-trippable, produce only NATS-KV-safe *and token-valid*
 * subjects, and the PK path must REJECT (not silently drop) AoRs that would
 * encode to an invalid subject.
 *
 * Guards beyond the existing test_kv_key_encode.c (=HH round-trip):
 *   1. [REV-23] backslash '\\' must be ESCAPED (was in the safe set -> violated
 *      the project's mandatory backslash-adversarial rule).
 *   2. [REV-23] '.' and '/' stay literal (valid multi-token subjects; keeps
 *      `nats kv` greppability) BUT a key with an EMPTY subject token
 *      (leading '.', trailing '.', or '..') is REJECTED by cdbn_kv_key_validate()
 *      before any kvStore_* call -- else JetStream rejects it and the REGISTER
 *      is silently lost (remote DoS / per-user poisoning).
 *   3. injectivity over an adversarial corpus; decode(encode(x)) == x for all
 *      byte strings incl. embedded NUL, '@', '=', empty.
 *
 * RED/GREEN from one file:
 *   gcc -DKEYENC_CURRENT ... -> carries TODAY's helpers ('\\' safe, no validator)
 *                               => RED (the [REV-23] assertions fail).
 *   gcc ...                   -> carries the FIXED helpers => GREEN.
 *
 * Carried-copy convention (matches the other Tier-1 tests). Rule 6 [PREV-4]:
 * the GREEN copy here mirrors cachedb_nats_json_ser.c; the AUTHORITATIVE
 * escape/validation proof is the Tier-2 key-poison e2e vs production [REV-20].
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_key_validate test_kv_key_validate.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── carried copy of the production helpers (cachedb_nats_json_ser.c) ─── */

static int _kv_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
#ifdef KEYENC_CURRENT
	case '-': case '_': case '/': case '\\': case '.':   /* TODAY: '\\' literal */
		return 1;
#else
	case '-': case '_': case '/': case '.':              /* FIXED: '\\' escaped */
		return 1;
#endif
	}
	return 0;
}

char *cdbn_kv_encode_key(const char *in, int in_len, int *out_len)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, w = 0;
	int cap = in_len * 3 + 1;
	char *out = malloc(cap);
	if (!out) return NULL;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c != '=' && _kv_char_safe(c)) {
			out[w++] = (char)c;
		} else {
			out[w++] = '=';
			out[w++] = hex[(c >> 4) & 0xF];
			out[w++] = hex[c & 0xF];
		}
	}
	out[w] = '\0';
	if (out_len) *out_len = w;
	return out;
}

/* [REV-23] Reject an encoded AoR key whose subject would have an empty token
 * (NATS rejects leading/trailing/double '.') or that is empty. 0=ok, -1=reject. */
static int cdbn_kv_key_validate(const char *enc, int len)
{
#ifdef KEYENC_CURRENT
	(void)enc; (void)len; return 0;   /* TODAY: PK path does no validation */
#else
	int i;
	if (len <= 0) return -1;
	if (enc[0] == '.' || enc[len-1] == '.') return -1;
	for (i = 1; i < len; i++)
		if (enc[i] == '.' && enc[i-1] == '.') return -1;
	return 0;
#endif
}

/* round-trip decoder for the =HH scheme */
static int _hexv(int c)
{
	if (c>='0'&&c<='9') return c-'0';
	if (c>='A'&&c<='F') return c-'A'+10;
	if (c>='a'&&c<='f') return c-'a'+10;
	return -1;
}
static char *_kv_decode_key(const char *in, int in_len, int *out_len)
{
	char *out = malloc(in_len + 1);
	int i = 0, w = 0;
	if (!out) return NULL;
	while (i < in_len) {
		if (in[i] == '=' && i + 2 < in_len) {
			int hi = _hexv((unsigned char)in[i+1]), lo = _hexv((unsigned char)in[i+2]);
			if (hi < 0 || lo < 0) { out[w++] = in[i++]; continue; }
			out[w++] = (char)((hi << 4) | lo); i += 3;
		} else out[w++] = in[i++];
	}
	out[w] = '\0';
	if (out_len) *out_len = w;
	return out;
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static int enc_has(const char *in, const char *needle)
{
	int el; char *e = cdbn_kv_encode_key(in, (int)strlen(in), &el);
	int r = e && strstr(e, needle) != NULL; free(e); return r;
}
static int roundtrips(const char *in, int len)
{
	int el, dl; char *e = cdbn_kv_encode_key(in, len, &el);
	char *d = e ? _kv_decode_key(e, el, &dl) : NULL;
	int ok = e && d && dl == len && memcmp(d, in, len) == 0;
	free(e); free(d); return ok;
}
static int validate_aor(const char *aor)
{
	int el; char *e = cdbn_kv_encode_key(aor, (int)strlen(aor), &el);
	int r = e ? cdbn_kv_key_validate(e, el) : -2; free(e); return r;
}

int main(void)
{
#ifdef KEYENC_CURRENT
	printf("== carried copy: KEYENC_CURRENT (today's behavior) ==\n");
#else
	printf("== carried copy: FIXED behavior ==\n");
#endif
	printf("[REV-23] backslash is escaped:\n");
	CHECK(enc_has("a\\b", "=5C"), "'\\\\' -> =5C (escaped, not literal)");
	CHECK(!_kv_char_safe('\\'), "_kv_char_safe('\\\\') == 0");

	printf("[REV-23] reserved/separator handling:\n");
	CHECK(enc_has("a@b", "=40"), "'@' -> =40");
	CHECK(enc_has("a=b", "=3D"), "'=' -> =3D (self-escape, injective)");
	CHECK(enc_has("a*b", "=2A") && enc_has("a>b", "=3E") && enc_has("a b", "=20"),
	      "'*','>',' ' escaped (no wildcard/space injection)");
	CHECK(!enc_has("alice.example.com", "=2E"), "'.' stays literal (greppable multi-token)");

	printf("[REV-23] PK-path token validation (reject empty tokens):\n");
	CHECK(validate_aor("sip:a..b@d") == -1,  "double-dot 'a..b' rejected");
	CHECK(validate_aor(".alice@d")   == -1,  "leading-dot rejected");
	CHECK(validate_aor("alice.")     == -1,  "trailing-dot rejected");
	CHECK(validate_aor("")           == -1,  "empty AoR rejected");
	CHECK(validate_aor("alice@example.com") == 0, "normal AoR accepted");
	CHECK(validate_aor("alice.smith@example.com") == 0, "dotted user/host accepted");

	printf("[REV-9] injectivity + round-trip (incl. NUL/empty):\n");
	const char *corpus[] = { "alice@example.com", "a..b", ".x", "x.", "a=b",
	                         "a/b\\c", "weird user", " unicode@domain", "" };
	int n = sizeof(corpus)/sizeof(corpus[0]), k, j;
	for (k = 0; k < n; k++)
		CHECK(roundtrips(corpus[k], (int)strlen(corpus[k])), corpus[k][0]?corpus[k]:"<empty>");
	{ const char nulstr[] = {'a','\0','b'}; CHECK(roundtrips(nulstr, 3), "embedded NUL round-trips"); }
	for (k = 0; k < n; k++) for (j = k+1; j < n; j++) {
		int al,bl; char *a=cdbn_kv_encode_key(corpus[k],(int)strlen(corpus[k]),&al);
		char *b=cdbn_kv_encode_key(corpus[j],(int)strlen(corpus[j]),&bl);
		if (a && b && al==bl && memcmp(a,b,al)==0) { printf("  FAIL: collision %s==%s\n",corpus[k],corpus[j]); fails++; }
		free(a); free(b);
	}
	CHECK(1, "no collisions across corpus");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
