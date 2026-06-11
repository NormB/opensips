/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #40: the map subject encoder.  Map ops emulate
 * hash-map semantics on flat NATS KV by composing a subject key
 *   enc(map_key) . enc(field)
 * where '.' is the structural separator.  To get exact server-side prefix
 * filtering ("enc(map_key).>") without cross-map aliasing, AND to let users
 * put any byte (including '.', ':', '=') in a map key/field, each component
 * is hex-escaped: every byte outside the NATS-subject-safe set
 * [0-9A-Za-z-_/\] is written as "=HH".  Crucially '.' and '=' are NOT in the
 * safe set, so an encoded component never contains a raw '.' (it is always a
 * single subject token) and the escape is unambiguous.
 *
 * This mirrors the proven =HH scheme of the PK key encoder
 * (test_kv_key_encode), but additionally escapes '.' (the map separator).
 *
 * The test carries a copy of the encode/decode helpers and proves
 * round-trip on the full byte range + the tricky edge cases (empty,
 * backslash, NUL, all-reserved, '=', high bytes), plus the structural
 * invariant (encoded output contains no raw '.'), then asserts the
 * production wiring.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_map_key_encode \
 *     test_map_key_encode.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ─── carried copy of the helpers under test ──────────────────── */

static int _map_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	/* NOTE: '.' and '=' are deliberately NOT safe here (separator and
	 * escape char); they are in the safe set of the PK key encoder. */
	case '-': case '_': case '/': case '\\':
		return 1;
	}
	return 0;
}

/* Encode in[0..in_len) into out as a NUL-terminated subject token.
 * Returns the encoded length (excluding NUL), or -1 if out is too small. */
static int nats_map_encode(const char *in, int in_len, char *out, int out_size)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, pos = 0;

	if (in_len < 0) return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (_map_char_safe(c)) {
			if (pos + 1 >= out_size) return -1;
			out[pos++] = (char)c;
		} else {
			if (pos + 3 >= out_size) return -1;
			out[pos++] = '=';
			out[pos++] = hex[c >> 4];
			out[pos++] = hex[c & 0x0f];
		}
	}
	if (pos >= out_size) return -1;
	out[pos] = '\0';
	return pos;
}

static int _hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* Decode in[0..in_len) into out.  Returns the decoded length, or -1 on a
 * malformed escape or overflow. */
static int nats_map_decode(const char *in, int in_len, char *out, int out_size)
{
	int i = 0, pos = 0;

	if (in_len < 0) return -1;
	while (i < in_len) {
		char c = in[i];
		if (c == '=') {
			int hi, lo;
			if (i + 2 >= in_len) return -1;          /* truncated escape */
			hi = _hexval(in[i + 1]);
			lo = _hexval(in[i + 2]);
			if (hi < 0 || lo < 0) return -1;         /* non-hex */
			if (pos + 1 >= out_size) return -1;
			out[pos++] = (char)((hi << 4) | lo);
			i += 3;
		} else {
			if (pos + 1 >= out_size) return -1;
			out[pos++] = c;
			i++;
		}
	}
	if (pos >= out_size) return -1;
	out[pos] = '\0';
	return pos;
}

/* ─── tests ────────────────────────────────────────────────────── */

static int has_raw_dot(const char *s, int n)
{
	int i;
	for (i = 0; i < n; i++) if (s[i] == '.') return 1;
	return 0;
}

static void roundtrip(const char *in, int in_len, const char *label)
{
	/* worst case is 3x expansion (every byte escaped) + NUL */
	char enc[1024], dec[512];
	int elen = nats_map_encode(in, in_len, enc, sizeof(enc));
	int dlen;
	char m[128];

	snprintf(m, sizeof(m), "%s: encode ok", label);
	ASSERT(elen >= 0, m);
	if (elen < 0) return;

	/* structural invariant: encoded component is one subject token */
	snprintf(m, sizeof(m), "%s: encoded has no raw '.'", label);
	ASSERT(!has_raw_dot(enc, elen), m);

	dlen = nats_map_decode(enc, elen, dec, sizeof(dec));
	snprintf(m, sizeof(m), "%s: decode ok", label);
	ASSERT(dlen == in_len, m);
	snprintf(m, sizeof(m), "%s: round-trips byte-exact", label);
	ASSERT(dlen == in_len && memcmp(dec, in, in_len) == 0, m);
}

int main(void)
{
	/* ---- round-trip the tricky cases --------------------------- */
	roundtrip("", 0, "empty");
	roundtrip("plainfield", 10, "plain");
	roundtrip("a.b.c", 5, "dots (separator char in data)");
	roundtrip("sub:field", 9, "colon (legacy sep in data)");
	roundtrip("100%=done", 9, "equals + percent");
	roundtrip("a\\b/c", 5, "backslash + slash (both safe, pass through)");
	roundtrip("user@host.com", 13, "SIP-ish at + dot");
	roundtrip("-_/\\", 4, "all-safe punctuation");
	roundtrip("*>? \t", 5, "wildcards + whitespace (must be escaped, not raw)");
	{
		/* embedded NUL + full high-byte range */
		char buf[3] = { 'a', '\0', 'z' };
		roundtrip(buf, 3, "embedded NUL");
	}
	{
		char all[256];
		int i;
		for (i = 0; i < 256; i++) all[i] = (char)i;
		roundtrip(all, 256, "every byte 0x00..0xff");
	}

	/* ---- structural: wildcards/whitespace never survive raw ----- */
	{
		char enc[64];
		int n = nats_map_encode("a*b>c d.e", 9, enc, sizeof(enc));
		ASSERT(n > 0, "mixed reserved encodes");
		ASSERT(!strchr(enc, '*') && !strchr(enc, '>') &&
		       !strchr(enc, ' ') && !strchr(enc, '.'),
			"no raw wildcard/space/dot in encoded subject token");
	}

	/* ---- decode rejects malformed escapes ----------------------- */
	{
		char out[16];
		ASSERT(nats_map_decode("=", 1, out, sizeof(out)) < 0,
			"truncated escape '=' rejected");
		ASSERT(nats_map_decode("=2", 2, out, sizeof(out)) < 0,
			"truncated escape '=2' rejected");
		ASSERT(nats_map_decode("=2G", 3, out, sizeof(out)) < 0,
			"non-hex escape '=2G' rejected");
		ASSERT(nats_map_decode("=2E", 3, out, sizeof(out)) == 1 && out[0] == '.',
			"valid escape '=2E' decodes to '.'");
	}

	/* ---- overflow guards ---------------------------------------- */
	{
		char tiny[2];
		ASSERT(nats_map_encode("...", 3, tiny, sizeof(tiny)) < 0,
			"encode reports overflow instead of truncating");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *n = "../cachedb_nats_native.c";
		ASSERT(file_contains(n, "nats_map_encode"),
			"native defines nats_map_encode");
		ASSERT(file_contains(n, "nats_map_decode"),
			"native defines nats_map_decode");
		ASSERT(file_contains(n, "#define NATS_MAP_SEP    '.'") ||
		       file_contains(n, "#define NATS_MAP_SEP '.'"),
			"map separator is now '.'");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
