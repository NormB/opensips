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
 * Regression test for the cdbn_sink_emit_string / _json_escape out_sz
 * off-by-one in cachedb_nats_json.c.
 *
 * Bug: cdbn_sink_emit_string() called
 *     _json_escape(p, n, s->buf + s->len, esc_len)
 * but _json_escape reserves one byte of out_sz for a trailing NUL and
 * rejects an exact fit (`if (w >= out_sz) return -1`).  esc_len is the
 * EXACT escaped length, so _json_escape returned -1 for ANY non-empty
 * string -- tripping the sink's sticky `oom` flag and truncating the
 * serialized JSON.  Fix: pass esc_len + 1 (the sink already reserved
 * the byte; the NUL is overwritten by the closing quote).
 *
 * This test carries faithful copies of the production helpers and emits
 * strings two ways -- with out_sz = esc_len (buggy) and esc_len + 1
 * (fixed) -- proving the buggy form fails/oom's on non-empty input while
 * the fixed form produces correct, untruncated JSON.  A source-structure
 * assertion ties the production cdbn_sink_emit_string to the fixed argument.
 *
 * Self-contained; run from the tests/ directory (reads ../cachedb_nats_json.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ---- faithful copies of the production helpers ---- */
typedef struct { char *buf; int len; int cap; int oom; } json_sink_t;

static int cdbn_sink_init(json_sink_t *s, int initial)
{
	s->cap = initial > 16 ? initial : 16;
	s->len = 0; s->oom = 0;
	s->buf = malloc(s->cap);
	return s->buf ? 0 : -1;
}
static int _sink_grow(json_sink_t *s, int need)
{
	int newcap; char *nb;
	if (s->oom) return -1;
	if (s->len + need < s->cap) return 0;
	newcap = s->cap;
	while (newcap <= s->len + need) {
		if (newcap > INT_MAX / 2) { s->oom = 1; return -1; }
		newcap *= 2;
	}
	nb = realloc(s->buf, newcap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb; s->cap = newcap;
	return 0;
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
static int _json_escape_len(const char *in, int in_len)
{
	int i, out = 0;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
		case '"': case '\\': case '\b': case '\f':
		case '\n': case '\r': case '\t': out += 2; break;
		default: out += (c < 0x20) ? 6 : 1;
		}
	}
	return out;
}
/* emit with out_sz = esc_len + nul_reserve.  nul_reserve=0 reproduces
 * the bug; nul_reserve=1 is the fix. */
static int emit_string(json_sink_t *s, const char *p, int n, int nul_reserve)
{
	int esc_len, needed;
	if (s->oom) return -1;
	esc_len = _json_escape_len(p, n);
	needed = esc_len + 2;
	if (_sink_grow(s, needed + 1) < 0) return -1;
	s->buf[s->len++] = '"';
	if (esc_len > 0) {
		int written = _json_escape(p, n, s->buf + s->len, esc_len + nul_reserve);
		if (written < 0) { s->oom = 1; return -1; }
		s->len += written;
	}
	s->buf[s->len++] = '"';
	s->buf[s->len] = '\0';
	return 0;
}

static void emit_case(const char *in, int n, const char *want, int nul_reserve)
{
	json_sink_t s;
	char label[256];
	cdbn_sink_init(&s, 16);
	int rc = emit_string(&s, in, n, nul_reserve);
	snprintf(label, sizeof(label),
		"FIXED emit(\"%s\") -> rc=0, no oom, == %s", in, want);
	ASSERT(rc == 0 && !s.oom && strcmp(s.buf, want) == 0, label);
	if (strcmp(s.buf, want) != 0)
		fprintf(stderr, "        got: %s\n", s.buf);
	free(s.buf);
}

/* ---- source-structure: production uses the fixed out_sz ---- */
static char *extract_func_body(const char *path, const char *funcname)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t rd = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[rd] = '\0';
	char *p = buf, *body = NULL;
	size_t flen = strlen(funcname);
	while ((p = strstr(p, funcname)) != NULL) {
		char *q = p + flen;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '(') { p += flen; continue; }
		char *brace = q;
		while (*brace && *brace != '{' && *brace != ';') brace++;
		if (*brace != '{') { p += flen; continue; }
		int depth = 0; char *t = brace;
		for (; *t; t++) {
			if (*t == '{') depth++;
			else if (*t == '}') { depth--; if (depth == 0) { t++; break; } }
		}
		size_t blen = (size_t)(t - brace);
		body = malloc(blen + 1);
		if (body) { memcpy(body, brace, blen); body[blen] = '\0'; }
		break;
	}
	free(buf);
	return body;
}

int main(void)
{
	char tab[] = { 't', '\t', 'x', 0 };

	/* (1) FIXED form: correct, untruncated output, no oom */
	emit_case("hello", 5, "\"hello\"", 1);
	emit_case("he\"llo", 6, "\"he\\\"llo\"", 1);
	emit_case(tab, 3, "\"t\\tx\"", 1);
	emit_case("", 0, "\"\"", 1);   /* empty: skips _json_escape entirely */

	/* (2) BUGGY form: out_sz == esc_len makes _json_escape reject any
	 * non-empty string -> sticky oom + truncated output. */
	{
		json_sink_t s; cdbn_sink_init(&s, 16);
		int rc = emit_string(&s, "hello", 5, 0 /* buggy */);
		ASSERT(rc == -1 && s.oom,
			"BUGGY emit(\"hello\") fails and sets oom (the original bug)");
		free(s.buf);
	}

	/* (3) source: production passes esc_len + 1, not bare esc_len */
	{
		char *b = extract_func_body("../cachedb_nats_json_ser.c",
			"cdbn_sink_emit_string");
		ASSERT(b != NULL, "found production cdbn_sink_emit_string body");
		if (b) {
			ASSERT(strstr(b, "s->buf + s->len, esc_len + 1") != NULL,
				"production _json_escape call reserves the NUL byte "
				"(esc_len + 1)");
			ASSERT(strstr(b, "s->buf + s->len, esc_len)") == NULL,
				"production no longer passes the bare (off-by-one) esc_len");
			free(b);
		}
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
