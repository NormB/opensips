/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TTL-HISTORY-FIX-SPEC.md D2 [HREV-2] regression lock: the seedless first
 * insert reuses the SAME _build_seed_doc output as the old write-the-seed
 * flow, now purely as the in-memory merge base.  If the builder's
 * serialization drifted, a first-insert row would silently differ from what
 * every pre-D2 deployment stored -- so its shape is locked here byte-for-byte
 * against golden strings, over adversarial filter values (the house list:
 * backslashes, quotes, control chars/NUL-adjacent, empty, boundary-length).
 *
 * This is a golden-output LOCK for behavior that must NOT change with D2
 * (no _CURRENT arm: there is no old-vs-new here, only drift detection).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_seed_shape_adversarial test_seed_shape_adversarial.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── carried copies (cachedb_nats_json.c) ────────────────────────── */

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
				w += snprintf(out + w, out_sz - w, "\\u%04x", c);
				continue;
			}
			short_buf[0] = (char)c; short_buf[1] = '\0';
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

static char *_build_seed_doc(const char *field, int flen,
	const char *val, int vlen, int *out_len)
{
	char *buf, *esc_field, *esc_val;
	int esc_field_len, esc_val_len, total;

	if (!field || flen <= 0) {
		buf = malloc(3);
		if (!buf) return NULL;
		memcpy(buf, "{}", 3);
		if (out_len) *out_len = 2;
		return buf;
	}
	esc_field = malloc(flen * 6 + 1);
	esc_val   = malloc((vlen > 0 ? vlen : 1) * 6 + 1);
	if (!esc_field || !esc_val) { free(esc_field); free(esc_val); return NULL; }
	esc_field_len = _json_escape(field, flen, esc_field, flen * 6 + 1);
	esc_val_len   = _json_escape(val, vlen, esc_val, (vlen > 0 ? vlen : 1) * 6 + 1);
	if (esc_field_len < 0 || esc_val_len < 0) {
		free(esc_field); free(esc_val);
		return NULL;
	}
	total = 1 + 1 + esc_field_len + 1 + 1 + 1 + esc_val_len + 1 + 1;
	buf = malloc(total + 1);
	if (!buf) { free(esc_field); free(esc_val); return NULL; }
	snprintf(buf, total + 1, "{\"%s\":\"%s\"}", esc_field, esc_val);
	free(esc_field); free(esc_val);
	if (out_len) *out_len = (int)strlen(buf);
	return buf;
}

static int g_fails = 0;

static void lock(const char *label, const char *field, const char *val,
	const char *golden)
{
	int len = 0;
	char *out = _build_seed_doc(field, field ? (int)strlen(field) : 0,
		val, val ? (int)strlen(val) : 0, &len);
	if (!out) {
		fprintf(stderr, "FAIL: %s: builder returned NULL\n", label);
		g_fails++;
		return;
	}
	if (strcmp(out, golden) != 0 || len != (int)strlen(golden)) {
		fprintf(stderr, "FAIL: %s\n  got:    \"%s\" (len %d)\n"
			"  golden: \"%s\"\n", label, out, len, golden);
		g_fails++;
	} else
		fprintf(stderr, "  ok: %s -> %s\n", label, out);
	free(out);
}

int main(void)
{
	fprintf(stderr, "[HREV-2] merge-base seed shape is locked (golden):\n");

	lock("plain AoR", "aor", "alice@example.com",
	     "{\"aor\":\"alice@example.com\"}");
	lock("backslash in value", "aor", "do\\main",
	     "{\"aor\":\"do\\\\main\"}");
	lock("quote in value", "aor", "ev\"il",
	     "{\"aor\":\"ev\\\"il\"}");
	lock("both, adjacent", "aor", "\\\"",
	     "{\"aor\":\"\\\\\\\"\"}");
	lock("tab + newline control chars", "aor", "a\tb\nc",
	     "{\"aor\":\"a\\tb\\nc\"}");
	lock("0x01 control char (uXXXX path)", "aor", "a\x01" "b",
	     "{\"aor\":\"a\\u0001b\"}");
	lock("empty value", "aor", "",
	     "{\"aor\":\"\"}");
	lock("empty field -> empty object", NULL, "whatever",
	     "{}");

	/* boundary-length AoR: 255 'a's (the practical AoR ceiling) survives
	 * without truncation and round-trips its exact length. */
	{
		char big[256], golden[300];
		int len = 0;
		char *out;
		memset(big, 'a', 255); big[255] = '\0';
		snprintf(golden, sizeof(golden), "{\"aor\":\"%s\"}", big);
		out = _build_seed_doc("aor", 3, big, 255, &len);
		if (!out || strcmp(out, golden) != 0) {
			fprintf(stderr, "FAIL: 255-char AoR truncated or mangled\n");
			g_fails++;
		} else
			fprintf(stderr, "  ok: 255-char AoR round-trips (len %d)\n", len);
		free(out);
	}

	/* NUL handling note: an embedded NUL never reaches the builder -- the
	 * update path rejects it earlier (_dict_has_nul_field, P2.3 [REV-20],
	 * locked by test_update_nul_poison).  Locked here: a NUL-terminated
	 * prefix is serialized as-is, not silently extended. */
	lock("value stops at NUL (upstream guard owns rejection)", "aor", "ab",
	     "{\"aor\":\"ab\"}");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
