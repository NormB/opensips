/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-3b regression test: cachedb_nats_json.c::_json_set_field had
 * a JSON-injection bug -- field/value bytes were spliced into the
 * output document with hand-coded `"` quoting and no escaping.  An
 * input value containing `"` would close the value early and let the
 * tail bytes inject arbitrary JSON.
 *
 * The fix introduces a static helper `_json_escape(in, in_len, out,
 * out_sz)` that writes the escaped form (without surrounding quotes)
 * of an input string and returns the number of bytes written, or -1
 * on output overflow.  The encoder follows RFC 8259 section 7:
 *   - "  -> \"
 *   - \  -> \\
 *   - \b \f \n \r \t -> short forms
 *   - other control bytes (< 0x20) -> \uXXXX
 *   - everything else passes through verbatim (including high bytes)
 *
 * Build (test carries its own copy of the helper for isolation):
 *   gcc -g -O0 -fsanitize=address -Wall -o test_json_escape test_json_escape.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── copy of the helper under test ───────────────────────────── */

static int _json_escape(const char *in, int in_len, char *out, int out_sz)
{
	int i, w = 0;
	if (out_sz <= 0) return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		const char *esc = NULL;
		char short_buf[2];

		switch (c) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\b': esc = "\\b";  break;
		case '\f': esc = "\\f";  break;
		case '\n': esc = "\\n";  break;
		case '\r': esc = "\\r";  break;
		case '\t': esc = "\\t";  break;
		default:
			if (c < 0x20) {
				if (w + 6 > out_sz) return -1;
				w += snprintf(out + w, out_sz - w,
					"\\u%04x", c);
				continue;
			}
			short_buf[0] = (char)c;
			short_buf[1] = '\0';
			esc = short_buf;
		}
		{
			int n = (int)strlen(esc);
			if (w + n >= out_sz) return -1;
			memcpy(out + w, esc, n);
			w += n;
		}
	}
	if (w >= out_sz) return -1;
	out[w] = '\0';
	return w;
}

/* ─── tiny JSON validator: parse "..."contents..." and confirm it's
 *     a single well-formed RFC 8259 JSON string ─────────────────── */

static int looks_like_valid_json_string(const char *quoted, int qlen)
{
	int i;
	if (qlen < 2) return 0;
	if (quoted[0] != '"' || quoted[qlen - 1] != '"') return 0;
	for (i = 1; i < qlen - 1; i++) {
		unsigned char c = (unsigned char)quoted[i];
		if (c == '"') return 0;       /* unescaped quote -> invalid */
		if (c == '\\') {
			if (i + 1 >= qlen - 1) return 0;
			char n = quoted[i + 1];
			if (n == '"' || n == '\\' || n == '/' ||
			    n == 'b' || n == 'f' || n == 'n' ||
			    n == 'r' || n == 't') {
				i++;
			} else if (n == 'u') {
				if (i + 5 >= qlen - 1) return 0;
				i += 5;
			} else {
				return 0;
			}
		} else if (c < 0x20) {
			return 0;       /* unescaped control */
		}
	}
	return 1;
}

static int g_fails;
#define ESCAPED(in, expected, label) do { \
	char buf[256]; \
	int n = _json_escape((in), (int)strlen(in), buf, sizeof(buf)); \
	if (n < 0 || strcmp(buf, (expected)) != 0) { \
		fprintf(stderr, "FAIL: %s\n  in:       \"%s\"\n  got:      \"%s\"\n  expected: \"%s\"\n", \
			(label), (in), n >= 0 ? buf : "<overflow>", (expected)); \
		g_fails++; \
	} else { \
		fprintf(stderr, "  ok: %s -> \"%s\"\n", (label), buf); \
	} \
	{ \
		char quoted[260]; \
		snprintf(quoted, sizeof(quoted), "\"%s\"", buf); \
		if (!looks_like_valid_json_string(quoted, (int)strlen(quoted))) { \
			fprintf(stderr, "FAIL: %s: round-trip not valid JSON string: \"%s\"\n", \
				(label), quoted); \
			g_fails++; \
		} \
	} \
} while (0)

int main(void)
{
	/* simple */
	ESCAPED("hello",        "hello",        "plain ascii");
	ESCAPED("",             "",             "empty");
	ESCAPED("a/b",          "a/b",          "slash unescaped (allowed)");

	/* dangerous */
	ESCAPED("a\"b",         "a\\\"b",       "double quote");
	ESCAPED("a\\b",         "a\\\\b",       "backslash");
	ESCAPED("a\"b\"c",      "a\\\"b\\\"c",  "two quotes");

	/* injection attempt — value is closed and a key is appended */
	ESCAPED("\",\"injected\":\"yes",
		"\\\",\\\"injected\\\":\\\"yes",
		"injection attempt");

	/* control chars */
	ESCAPED("a\nb",         "a\\nb",        "newline");
	ESCAPED("a\rb",         "a\\rb",        "carriage return");
	ESCAPED("a\tb",         "a\\tb",        "tab");
	ESCAPED("a\bb",         "a\\bb",        "backspace");
	ESCAPED("a\fb",         "a\\fb",        "form feed");
	{
		const char in[] = {'a', 0x01, 'b', 0};
		ESCAPED(in, "a\\u0001b", "control 0x01 -> \\u0001");
	}

	/* high bytes (UTF-8 continuation) pass through */
	{
		const char in[] = {'a', (char)0xC3, (char)0xA9, 'b', 0}; /* "aéb" */
		const char ex[] = {'a', (char)0xC3, (char)0xA9, 'b', 0};
		ESCAPED(in, ex, "UTF-8 é passes through");
	}

	/* overflow */
	{
		char buf[3];
		int n = _json_escape("abcdef", 6, buf, sizeof(buf));
		if (n != -1) {
			fprintf(stderr, "FAIL: overflow not detected (n=%d)\n", n);
			g_fails++;
		} else {
			fprintf(stderr, "  ok: overflow returns -1\n");
		}
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
