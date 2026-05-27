/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats_json.c::_apply_pairs_one_pass /
 * _sink_merge_subkeys re-escaped EXISTING JSON field/subkey NAMES when
 * copying them through on a KV-doc update.
 *
 * Those names come straight out of _parse_json_string(), which returns
 * the bytes STILL ESCAPED (it does not decode \" / \\ / \uXXXX).  The
 * buggy code fed them back through _sink_emit_string(), which escapes
 * again:  the source name  foo\"bar  (logical:  foo"bar )  became
 * foo\\\"bar  on every update -> the backslash count doubles on each
 * write -> data corruption.
 *
 * The fix copies already-escaped names through raw via a new helper
 * _sink_emit_raw_string() (open-quote + raw bytes + close-quote), so a
 * name round-trips byte-for-byte.  cdb_pair-supplied NAMES (which are
 * UN-escaped) still go through _sink_emit_string().
 *
 * This test carries byte-for-byte copies of the production helpers
 * (_json_escape, _json_escape_len, _sink_*, _parse_json_string) so it
 * runs standalone, then drives a copy-through of a parsed name with
 * both the buggy emitter and the fixed emitter and asserts:
 *   - fixed emitter: name survives unchanged (idempotent round-trip)
 *   - buggy emitter: name gets double-escaped (the regression)
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_json_name_passthrough \
 *       test_json_name_passthrough.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ─── copies of the production sink + helpers ─────────────────────── */

typedef struct {
	char *buf;
	int   len;
	int   cap;
	int   oom;
} json_sink_t;

static int _sink_init(json_sink_t *s, int cap)
{
	if (cap < 16) cap = 16;
	s->buf = malloc(cap);
	if (!s->buf) return -1;
	s->len = 0; s->cap = cap; s->oom = 0;
	s->buf[0] = '\0';
	return 0;
}

static int _sink_grow(json_sink_t *s, int extra)
{
	if (s->oom) return -1;
	if (s->len + extra <= s->cap) return 0;
	int ncap = s->cap * 2;
	while (ncap < s->len + extra) ncap *= 2;
	char *nb = realloc(s->buf, ncap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb; s->cap = ncap;
	return 0;
}

static int _sink_write(json_sink_t *s, const char *p, int n)
{
	if (s->oom || n <= 0) return s->oom ? -1 : 0;
	if (_sink_grow(s, n + 1) < 0) return -1;
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	s->buf[s->len] = '\0';
	return 0;
}

static int _sink_putc(json_sink_t *s, char c)
{
	return _sink_write(s, &c, 1);
}

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

static int _json_escape_len(const char *in, int in_len)
{
	int i, out = 0;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
		case '"': case '\\':
		case '\b': case '\f': case '\n':
		case '\r': case '\t':
			out += 2;
			break;
		default:
			out += (c < 0x20) ? 6 : 1;
		}
	}
	return out;
}

/* Model of the BUGGY pre-fix name-emit path: it escaped the name with
 * _json_escape and wrapped it in quotes.  We give _json_escape a
 * generous buffer here (the production sink off-by-one is a separate
 * issue, irrelevant to the NAME double-escape we are demonstrating) so
 * that the escaping itself succeeds and the double-escape is visible. */
static int _sink_emit_string(json_sink_t *s, const char *p, int n)
{
	char tmp[512];
	int written;
	if (s->oom) return -1;
	(void)_json_escape_len;
	written = _json_escape(p, n, tmp, (int)sizeof(tmp));
	if (written < 0) { s->oom = 1; return -1; }
	if (_sink_putc(s, '"') < 0) return -1;
	if (_sink_write(s, tmp, written) < 0) return -1;
	return _sink_putc(s, '"');
}

/* The raw emitter -- correct for ALREADY-escaped existing names. */
static int _sink_emit_raw_string(json_sink_t *s, const char *p, int n)
{
	if (s->oom) return -1;
	if (_sink_putc(s, '"') < 0) return -1;
	if (_sink_write(s, p, n) < 0) return -1;
	return _sink_putc(s, '"');
}

/* _parse_json_string: returns slice pointing into source, escapes NOT
 * decoded -- exact copy of the production parser's contract. */
static const char *_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++;
	start = p;
	while (p < end && *p != '"') {
		if (*p == '\\') { p++; if (p >= end) return NULL; }
		p++;
	}
	if (p >= end) return NULL;
	*out = start;
	*out_len = (int)(p - start);
	p++;
	return p;
}

/* ─── test harness ────────────────────────────────────────────────── */

static int g_fails;

/* Copy-through the single field name of a one-field object {"NAME":1}
 * using the given name emitter, return the rebuilt name as it would
 * appear inside the output document (escaped form between the quotes). */
static int passthrough_name(const char *doc, int emit_raw,
	char *out, size_t out_sz)
{
	const char *p = doc, *end = doc + strlen(doc);
	const char *fname; int flen;
	json_sink_t s;

	if (*p != '{') return -1;
	p++;
	p = _parse_json_string(p, end, &fname, &flen);
	if (!p) return -1;

	if (_sink_init(&s, 64) < 0) return -1;
	if (emit_raw) {
		if (_sink_emit_raw_string(&s, fname, flen) < 0)
			{ free(s.buf); return -1; }
	} else {
		if (_sink_emit_string(&s, fname, flen) < 0)
			{ free(s.buf); return -1; }
	}
	if ((size_t)s.len + 1 > out_sz) { free(s.buf); return -1; }
	memcpy(out, s.buf, s.len + 1);
	free(s.buf);
	return s.len;
}

#define CHECK(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static void round_trip_case(const char *doc, const char *expect_emitted_name)
{
	char raw_out[256], esc_out[256];
	int rraw = passthrough_name(doc, 1, raw_out, sizeof(raw_out));
	int resc = passthrough_name(doc, 0, esc_out, sizeof(esc_out));

	fprintf(stderr, "doc=%s\n  raw -> %s\n  esc -> %s\n  want=%s\n",
		doc, rraw >= 0 ? raw_out : "<err>",
		resc >= 0 ? esc_out : "<err>", expect_emitted_name);

	/* FIXED path: the existing (already-escaped) name copies through
	 * byte-for-byte -- the emitted bytes equal the source bytes. */
	CHECK(rraw >= 0 && strcmp(raw_out, expect_emitted_name) == 0,
		"raw emitter copies existing name through unchanged");

	/* BUGGY path: when the name actually contains an escape, the
	 * escaping emitter changes it -- this is the regression the fix
	 * removes.  (For names with no escapes both emitters agree.) */
	if (strchr(expect_emitted_name + 1, '\\')) {
		CHECK(resc >= 0 && strcmp(esc_out, expect_emitted_name) != 0,
			"escaping emitter double-escapes existing name (bug)");
	}
}

int main(void)
{
	/* Plain name -- both emitters must agree, raw is idempotent. */
	round_trip_case("{\"plain\":1}", "\"plain\"");

	/* Name containing an escaped quote: source bytes  a\"b  must come
	 * out as  "a\"b"  unchanged.  The buggy emitter would produce
	 * "a\\\"b" (backslash doubled). */
	round_trip_case("{\"a\\\"b\":1}", "\"a\\\"b\"");

	/* Name containing an escaped backslash: source bytes  a\\b  ->
	 * "a\\b" unchanged.  Buggy: "a\\\\b". */
	round_trip_case("{\"a\\\\b\":1}", "\"a\\\\b\"");

	/* Idempotency: applying the raw emitter to its own output again
	 * must be a fixed point (no creeping escape growth over updates). */
	{
		char first[256], second[256];
		int n1 = passthrough_name("{\"a\\\"b\":1}", 1,
			first, sizeof(first));
		/* feed first back as a one-field doc */
		char doc2[300];
		snprintf(doc2, sizeof(doc2), "{%s:1}", first);
		int n2 = passthrough_name(doc2, 1, second, sizeof(second));
		(void)n1; (void)n2;
		CHECK(n1 >= 0 && n2 >= 0 && strcmp(first, second) == 0,
			"raw emitter is a fixed point across repeated updates");
	}

	/* ─── source-structure assertions on the production .c ──────────
	 * The behavioural cases above prove the two emitters differ on
	 * escaped names; these prove the production copy-through sites
	 * actually use the RAW emitter (the fix) and that the raw helper
	 * exists. */
	{
		FILE *f = fopen("../cachedb_nats_json.c", "r");
		int have_raw_helper = 0, raw_uses = 0, line_no = 0;
		char line[2048];
		CHECK(f != NULL, "open cachedb_nats_json.c for source check");
		if (f) {
			while (fgets(line, sizeof(line), f)) {
				line_no++;
				if (strstr(line, "_sink_emit_raw_string(json_sink_t"))
					have_raw_helper = 1;
				/* count the copy-through call sites that emit a
				 * parsed (already-escaped) name via the raw helper */
				if (strstr(line, "_sink_emit_raw_string(") &&
				    !strstr(line, "json_sink_t"))
					raw_uses++;
			}
			fclose(f);
		}
		CHECK(have_raw_helper,
			"_sink_emit_raw_string helper defined in source");
		/* fname x3 (top set / subkey-merge / copy-through) +
		 * kfield x2 (subkey op / subkey copy-through) = 5 sites */
		CHECK(raw_uses >= 5,
			"existing-name copy-through sites use the raw emitter");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
