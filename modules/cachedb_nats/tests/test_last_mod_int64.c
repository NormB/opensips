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
 * P2.4 / SPEC.md §3.1 [REV-15 / REV-30] (Option A): read `last_mod` as int64.
 *
 * The shared converter cdb_json_to_dict (cachedb/cachedb_dict.c:556-559) turns
 * every cJSON_Number into CDB_INT32 via cJSON's `valueint`, which cJSON CLAMPS
 * to INT_MAX/INT_MIN.  `last_mod` is a usrloc CDB_INT64 (read as i64 at
 * udomain.c:211), so a value > INT32_MAX silently narrows to 2147483647 on read
 * — the round-trip is not byte-exact.  Option A: cachedb_nats re-parses
 * `last_mod` as int64 from the raw row JSON and overwrites the clamped value.
 *
 * [REV-30] Only `last_mod` gets the int64 guarantee; `expires` is CDB_INT32 at
 * the usrloc boundary and re-clamps the instant usrloc consumes it, so its
 * Y2038 overflow is an accepted usrloc-wide limitation, not asserted here.
 *
 * This Tier-1 carries the int64 EXTRACTION leaf (the genuinely tricky part):
 * cdbn_contact_field_int64() pulls last_mod out of a contact object as int64, and
 * _lastmod_read() contrasts the Option-A int64 value with what the shared
 * int32-clamping converter would have produced.
 *   gcc -DLASTMOD_CURRENT ... -> model the shared cdb_json_to_dict clamp
 *                                (valueint -> INT_MAX) => RED for > INT32_MAX.
 *   gcc ...                   -> Option A int64 parse => GREEN.
 *
 * Rule 6 [PREV-19/REV-30]: the AUTHORITATIVE round-trip proof is the Tier-2
 * test_usrloc_roundtrip_int64_e2e.sh — it compares the bytes usrloc RECEIVES
 * (an MI/log dump of the parsed cdb_row_t after query()), NOT `nats kv get`
 * (which shows the raw stored int64 and would pass even while the read clamps).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_last_mod_int64 test_last_mod_int64.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── carried copy: JSON walkers (cachedb_nats_json_index.c) ─────── */
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
static const char *cdbn_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = cdbn_skip_ws(p, end);
	if (p >= end) return NULL;
	switch (*p) {
	case '"':
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') { p++; if (p >= end) return NULL; }
			p++;
		}
		return (p < end) ? p + 1 : NULL;
	case '{': case '[':
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

/* ─── carried copy: int64 parse + field extractor (rowmeta TU) ───── */
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
/* Find an integer-valued field @fname inside a contact object slice
 * [vstart,vend). 0 + *out on success; -1 if absent / not an integer. */
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
		}
		p = cdbn_skip_json_value(p, vend);
		if (!p) return -1;
	}
	return -1;
}

/* What the read path yields for last_mod: Option A (int64) vs today's clamp. */
#define LM_ABSENT INT64_MIN
static int64_t _lastmod_read(const char *contact)
{
	int64_t v;
	const char *end = contact + strlen(contact);
	if (cdbn_contact_field_int64(contact, end, "last_mod", 8, &v) != 0)
		return LM_ABSENT;
#ifdef LASTMOD_CURRENT
	/* model cdb_json_to_dict: CDB_INT32 = cJSON valueint, clamped to INT_MAX. */
	if (v > INT32_MAX) return INT32_MAX;
	if (v < INT32_MIN) return INT32_MIN;
	return v;
#else
	return v;   /* Option A: int64 preserved */
#endif
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define EXPECT(contact, want, msg) do { \
	int64_t _g = _lastmod_read(contact); \
	if (_g != (want)) { printf("  FAIL: %s (got %lld want %lld)\n", msg, \
		(long long)_g, (long long)(want)); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef LASTMOD_CURRENT
	printf("== carried copy: LASTMOD_CURRENT (shared int32 clamp) ==\n");
#else
	printf("== carried copy: FIXED (Option A int64) ==\n");
#endif

	printf("[REV-15] values within int32 round-trip either way:\n");
	EXPECT("{\"cseq\":1,\"last_mod\":1000,\"ua\":\"x\"}", 1000LL, "small last_mod preserved");
	EXPECT("{\"last_mod\":2147483647}", 2147483647LL, "INT32_MAX preserved (boundary)");
	EXPECT("{\"last_mod\":0}", 0LL, "zero preserved");
	EXPECT("{\"last_mod\":-2147483648}", -2147483648LL, "INT32_MIN preserved (boundary)");

	/* The assertions below are CONSTANT (always the true int64) so the
	 * int32-clamp arm genuinely FAILS them (RED). */
	printf("[REV-15/30] > INT32_MAX must survive (RED under the shared clamp):\n");
	EXPECT("{\"last_mod\":2147483648}", 2147483648LL, "INT32_MAX+1 preserved");
	EXPECT("{\"last_mod\":5000000000}", 5000000000LL, "5e9 (post-2038 ms epoch) preserved");
	EXPECT("{\"last_mod\":-5000000000}", -5000000000LL, "-5e9 preserved");

	printf("[REV-30] huge int64 last_mod preserved (RED under the shared clamp):\n");
	EXPECT("{\"last_mod\":1099511627776}", 1099511627776LL, "2^40 preserved");
	EXPECT("{\"last_mod\":9223372036854775807}", 9223372036854775807LL, "INT64_MAX preserved");

	printf("extraction correctness (field position, neighbours):\n");
	EXPECT("{\"ua\":\"a\",\"expires\":2000,\"last_mod\":5000000001,\"cseq\":7}",
	       5000000001LL,
	       "last_mod found among other fields (and > INT32_MAX preserved)");
	/* expires must NOT be confused with last_mod */
	EXPECT("{\"expires\":5000000000,\"last_mod\":42}", 42LL, "expires not mistaken for last_mod");

	printf("adversarial: missing / non-integer last_mod => absent sentinel:\n");
	EXPECT("{\"cseq\":1,\"ua\":\"x\"}", LM_ABSENT, "absent last_mod => sentinel");
	EXPECT("{\"last_mod\":\"123\"}", LM_ABSENT, "string last_mod => not an integer");
	EXPECT("{\"last_mod\":null}", LM_ABSENT, "null last_mod => not an integer");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
