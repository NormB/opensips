/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: NATS-KV subject tokens reject characters outside
 * [-./_=a-zA-Z0-9]. usrloc
 * AoRs in cluster_mode=full-sharing-cachedb routinely contain '@'
 * (user@host SIP convention), causing kvStore_Get to return
 * "Invalid Argument" and every REGISTER to fail.
 *
 * Encode unsafe bytes as `=HH` (two-hex-digit) so keys round-trip
 * deterministically and contain only NATS-KV-safe characters. '='
 * is itself NATS-safe and is also encoded (=3D) so the decode is
 * unambiguous.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_kv_key_encode \
 *     test_kv_key_encode.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── carried copy of the helpers under test ──────────────────── */

static int _kv_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	case '-': case '_': case '/': case '\\': case '.':
		return 1;
	}
	return 0;
}

/* Encode @in into NATS-KV-safe form with '=HH' escape for unsafe bytes.
 * Returns malloc'd null-terminated string of length *out_len, or NULL
 * on alloc failure. The literal '=' itself is escaped to '=3D' so the
 * decoder never has to disambiguate. */
static char *_kv_encode_key(const char *in, int in_len, int *out_len)
{
	int i, w = 0;
	int cap = in_len * 3 + 1;
	char *out = malloc(cap);
	static const char hex[] = "0123456789ABCDEF";
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
	*out_len = w;
	return out;
}

/* ─── tests ───────────────────────────────────────────────────── */

static int g_fails;
static void check(const char *label, const char *got, const char *expected)
{
	if (!got || strcmp(got, expected) != 0) {
		fprintf(stderr, "FAIL: %s\n  got:      \"%s\"\n  expected: \"%s\"\n",
			label, got ? got : "<NULL>", expected);
		g_fails++;
		return;
	}
	fprintf(stderr, "  ok: %s -> %s\n", label, got);
}

static int kv_key_valid(const char *s)
{
	while (*s) {
		unsigned char c = (unsigned char)*s++;
		if (!_kv_char_safe(c) && c != '=') return 0;
	}
	return 1;
}

int main(void)
{
	char *out;
	int n;

	/* A. usrloc AoR with '@' */
	out = _kv_encode_key("alice@example.com", 17, &n);
	check("A: SIP AoR @ encoded as =40",
		out, "alice=40example.com");
	if (out && !kv_key_valid(out)) {
		fprintf(stderr, "FAIL: A: encoded form not KV-safe: %s\n", out);
		g_fails++;
	}
	free(out);

	/* B. plain user (no encoding needed) */
	out = _kv_encode_key("alice", 5, &n);
	check("B: alphanumeric passthrough", out, "alice");
	free(out);

	/* C. dotted hostname stays as-is */
	out = _kv_encode_key("alice_at_example.com", 20, &n);
	check("C: '.' passes through", out, "alice_at_example.com");
	free(out);

	/* D. ':' (colon) is encoded — NATS-KV reserves it */
	out = _kv_encode_key("user:pw@host", 12, &n);
	check("D: ':' and '@' both encoded",
		out, "user=3Apw=40host");
	free(out);

	/* E. literal '=' is escaped to =3D */
	out = _kv_encode_key("a=b", 3, &n);
	check("E: literal '=' becomes =3D", out, "a=3Db");
	free(out);

	/* F. wildcards rejected by NATS-KV are encoded */
	out = _kv_encode_key("a*b>c", 5, &n);
	check("F: wildcards encoded", out, "a=2Ab=3Ec");
	free(out);

	/* G. high bytes (UTF-8) are encoded */
	{
		const char in[] = {'a', (char)0xC3, (char)0xA9, 'b', 0};
		out = _kv_encode_key(in, 4, &n);
		check("G: UTF-8 bytes encoded as =HH=HH",
			out, "a=C3=A9b");
		free(out);
	}

	/* H. empty input */
	out = _kv_encode_key("", 0, &n);
	check("H: empty input -> empty", out, "");
	free(out);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
