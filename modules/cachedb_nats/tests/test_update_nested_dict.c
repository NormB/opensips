/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats_json.c::nats_cache_update silently dropped
 * every non-string pair. usrloc's cdb_flush_urecord passes contacts as
 * CDB_DICT pairs, so contacts vanished. Top-level integers (e.g. aorhash)
 * vanished. CDB_NULL pairs vanished. Pair->subkey was ignored entirely,
 * meaning every contact-update would replace the whole "contacts" map.
 * Pair->unset was ignored, meaning contact deletes were silent no-ops.
 *
 * The fix introduces a small pure helper, _json_apply_pair(), that takes
 * a JSON document plus the projected primitives of one cdb_pair_t (field,
 * optional subkey, type-tagged value, unset flag) and returns the
 * mutated document. nats_cache_update() walks its pairs list and calls
 * this helper once per pair. This file carries a copy of the helper for
 * isolated unit testing, matching the convention used by test_json_escape.c.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -Wextra \
 *     -o test_update_nested_dict test_update_nested_dict.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/* ─── carried copy of the production helpers under test ──────────── */

static const char *_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}

static const char *_parse_json_string(const char *p, const char *end,
	const char **out_s, int *out_len)
{
	const char *start;
	if (p >= end || *p != '"') return NULL;
	p++;
	start = p;
	while (p < end && *p != '"') {
		if (*p == '\\' && p + 1 < end) p += 2;
		else p++;
	}
	if (p >= end) return NULL;
	*out_s = start;
	*out_len = (int)(p - start);
	return p + 1;
}

static const char *_skip_json_value(const char *p, const char *end)
{
	int depth;
	p = _skip_ws(p, end);
	if (p >= end) return NULL;
	if (*p == '"') {
		const char *s; int n;
		return _parse_json_string(p, end, &s, &n);
	}
	if (*p == '{' || *p == '[') {
		char open = *p, close = (open == '{') ? '}' : ']';
		depth = 1; p++;
		while (p < end && depth > 0) {
			if (*p == '"') {
				const char *s; int n;
				p = _parse_json_string(p, end, &s, &n);
				if (!p) return NULL;
				continue;
			}
			if (*p == open) depth++;
			else if (*p == close) depth--;
			p++;
		}
		return p;
	}
	while (p < end && *p != ',' && *p != '}' && *p != ']' &&
	       *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
		p++;
	return p;
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

/* Locate the value range of a top-level field in a JSON object.
 * Returns 0 if found and writes vstart/vend to the value bounds; 1 if
 * the field does not exist (and insert_pos is set to the position just
 * before the closing brace, plus needs_comma indicates whether a leading
 * ',' is needed); -1 on parse error.
 */
static int _find_field(const char *json, int json_len,
	const char *field, int flen,
	const char **vstart, const char **vend,
	const char **insert_pos, int *needs_comma)
{
	const char *p = json, *end = json + json_len;
	const char *jfield;
	int jflen;
	int saw_field = 0;

	p = _skip_ws(p, end);
	if (p >= end || *p != '{') return -1;
	p++;
	while (p < end) {
		p = _skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') {
			*insert_pos = p;
			*needs_comma = saw_field;
			return 1;
		}
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &jfield, &jflen);
		if (!p) return -1;
		saw_field = 1;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = _skip_ws(p, end);
		if (jflen == flen && memcmp(jfield, field, flen) == 0) {
			*vstart = p;
			p = _skip_json_value(p, end);
			if (!p) return -1;
			*vend = p;
			return 0;
		}
		p = _skip_json_value(p, end);
		if (!p) return -1;
	}
	return -1;
}

/* Render a leaf value into a malloc'd JSON literal token (no surrounding
 * key/colon). Returns NULL on alloc failure or invalid type. */
static char *_render_leaf(char val_type,
	const char *val_str, int val_len, int64_t val_int, int *out_len)
{
	char *buf;
	int n;

	switch (val_type) {
	case 'N':
		buf = malloc(5);
		if (!buf) return NULL;
		memcpy(buf, "null", 5);
		*out_len = 4;
		return buf;
	case 'I':
	case 'L': {
		char tmp[32];
		n = snprintf(tmp, sizeof(tmp), "%lld", (long long)val_int);
		if (n < 0 || n >= (int)sizeof(tmp)) return NULL;
		buf = malloc(n + 1);
		if (!buf) return NULL;
		memcpy(buf, tmp, n + 1);
		*out_len = n;
		return buf;
	}
	case 'S': {
		int cap = val_len * 6 + 3;   /* worst case escape + 2 quotes */
		buf = malloc(cap);
		if (!buf) return NULL;
		buf[0] = '"';
		n = _json_escape(val_str, val_len, buf + 1, cap - 2);
		if (n < 0) { free(buf); return NULL; }
		buf[1 + n] = '"';
		buf[2 + n] = '\0';
		*out_len = n + 2;
		return buf;
	}
	case 'O': {
		buf = malloc(val_len + 1);
		if (!buf) return NULL;
		memcpy(buf, val_str, val_len);
		buf[val_len] = '\0';
		*out_len = val_len;
		return buf;
	}
	}
	return NULL;
}

/* Splice [json..pre) + middle + [post..end) into a new malloc'd buffer. */
static char *_splice(const char *json, int json_len,
	int pre_off, int post_off,
	const char *middle, int middle_len, int *out_len)
{
	int suffix = json_len - post_off;
	int new_len = pre_off + middle_len + suffix;
	char *out = malloc(new_len + 1);
	if (!out) return NULL;
	memcpy(out, json, pre_off);
	memcpy(out + pre_off, middle, middle_len);
	memcpy(out + pre_off + middle_len, json + post_off, suffix);
	out[new_len] = '\0';
	*out_len = new_len;
	return out;
}

/* Build "<field>":<rendered> as a malloc'd token. */
static char *_kv_token(const char *field, int flen,
	const char *rendered, int rendered_len, int *out_len)
{
	int cap = flen * 6 + 4 + rendered_len;
	int n;
	char *buf = malloc(cap);
	if (!buf) return NULL;
	buf[0] = '"';
	n = _json_escape(field, flen, buf + 1, cap - 3 - rendered_len);
	if (n < 0) { free(buf); return NULL; }
	buf[1 + n]     = '"';
	buf[1 + n + 1] = ':';
	memcpy(buf + 1 + n + 2, rendered, rendered_len);
	buf[1 + n + 2 + rendered_len] = '\0';
	*out_len = 1 + n + 2 + rendered_len;
	return buf;
}

/* Set or unset a top-level field of @json to @rendered.  When unset==1,
 * @rendered is ignored and the field is removed (along with one neighboring
 * comma). Returns malloc'd output. */
static char *_object_set(const char *json, int json_len,
	const char *field, int flen,
	const char *rendered, int rendered_len,
	int unset, int *out_len)
{
	const char *vstart = NULL, *vend = NULL, *ipos = NULL;
	int needs_comma = 0;
	int rc = _find_field(json, json_len, field, flen,
		&vstart, &vend, &ipos, &needs_comma);
	if (rc < 0) return NULL;

	if (unset) {
		if (rc == 1) {
			char *out = malloc(json_len + 1);
			if (!out) return NULL;
			memcpy(out, json, json_len);
			out[json_len] = '\0';
			*out_len = json_len;
			return out;
		}
		{
			int kstart = (int)(vstart - json);
			int kend   = (int)(vend - json);
			while (kstart > 0) {
				char c = json[kstart - 1];
				if (c == ' ' || c == '\t' || c == ':' || c == '\n' || c == '\r') {
					kstart--; continue;
				}
				if (c == '"') { kstart--; break; }
				break;
			}
			while (kstart > 0 && json[kstart - 1] != '"') kstart--;
			if (kstart > 0) kstart--;
			if (kstart > 0 && json[kstart - 1] == ',') kstart--;
			else {
				while (kend < json_len && (json[kend] == ' ' || json[kend] == '\t'
				    || json[kend] == '\n' || json[kend] == '\r'))
					kend++;
				if (kend < json_len && json[kend] == ',') kend++;
			}
			return _splice(json, json_len, kstart, kend, "", 0, out_len);
		}
	}

	if (rc == 0) {
		return _splice(json, json_len,
			(int)(vstart - json), (int)(vend - json),
			rendered, rendered_len, out_len);
	}
	{
		char *kv;
		int kvlen;
		kv = _kv_token(field, flen, rendered, rendered_len, &kvlen);
		if (!kv) return NULL;
		{
			int ipos_off = (int)(ipos - json);
			char *with_comma = NULL;
			char *out;
			int wc_len = 0;
			if (needs_comma) {
				with_comma = malloc(1 + kvlen + 1);
				if (!with_comma) { free(kv); return NULL; }
				with_comma[0] = ',';
				memcpy(with_comma + 1, kv, kvlen);
				with_comma[1 + kvlen] = '\0';
				wc_len = 1 + kvlen;
			}
			out = _splice(json, json_len, ipos_off, ipos_off,
				needs_comma ? with_comma : kv,
				needs_comma ? wc_len : kvlen, out_len);
			free(kv);
			free(with_comma);
			return out;
		}
	}
}

/**
 * _json_apply_pair() — apply one cdb_pair_t-style update to a JSON object.
 *
 * @field/@flen           outer field name.
 * @subkey/@sklen         optional sub-key under @field. If non-zero length,
 *                        @field is treated as a JSON object and the subkey
 *                        is what gets set/unset.
 * @unset                 1 = remove (sub)key; the value args are ignored.
 * @val_type              one of 'S' string, 'I' int32, 'L' int64,
 *                        'N' null, 'O' raw JSON value (object/array/etc).
 * @val_str/@val_len      payload for 'S' (escaped+quoted) and 'O' (verbatim).
 * @val_int               payload for 'I' and 'L'.
 *
 * Returns malloc'd new document, or NULL on error. Caller must free().
 * The original @json buffer is never modified.
 */
static char *_json_apply_pair(const char *json, int json_len,
	const char *field, int flen,
	const char *subkey, int sklen,
	int unset,
	char val_type,
	const char *val_str, int val_len,
	int64_t val_int)
{
	if (!json || json_len <= 0 || !field || flen <= 0) return NULL;

	if (sklen <= 0 || !subkey) {
		if (unset)
			return _object_set(json, json_len, field, flen,
				NULL, 0, 1, &(int){0}); /* dummy */
		{
			char *rendered;
			int rlen;
			char *out;
			int olen;
			rendered = _render_leaf(val_type, val_str, val_len,
				val_int, &rlen);
			if (!rendered) return NULL;
			out = _object_set(json, json_len, field, flen,
				rendered, rlen, 0, &olen);
			free(rendered);
			(void)olen;
			return out;
		}
	}

	/* subkey path: field is treated as a JSON object */
	{
		const char *vstart = NULL, *vend = NULL, *ipos = NULL;
		int needs_comma = 0;
		int rc = _find_field(json, json_len, field, flen,
			&vstart, &vend, &ipos, &needs_comma);
		const char *inner;
		int inner_len;
		char inner_buf[3] = "{}";
		char *new_inner;
		int new_inner_len;
		char *out;
		int olen;

		if (rc < 0) return NULL;
		if (rc == 0) {
			const char *p = _skip_ws(vstart, vend);
			if (p >= vend || *p != '{') return NULL;
			inner = vstart;
			inner_len = (int)(vend - vstart);
		} else {
			inner = inner_buf;
			inner_len = 2;
		}

		if (unset) {
			new_inner = _object_set(inner, inner_len,
				subkey, sklen, NULL, 0, 1, &new_inner_len);
		} else {
			char *rendered;
			int rlen;
			rendered = _render_leaf(val_type, val_str, val_len,
				val_int, &rlen);
			if (!rendered) return NULL;
			new_inner = _object_set(inner, inner_len,
				subkey, sklen, rendered, rlen, 0, &new_inner_len);
			free(rendered);
		}
		if (!new_inner) return NULL;

		if (rc == 0) {
			out = _splice(json, json_len,
				(int)(vstart - json), (int)(vend - json),
				new_inner, new_inner_len, &olen);
			free(new_inner);
			(void)olen;
			return out;
		}
		{
			char *kv;
			int kvlen;
			kv = _kv_token(field, flen, new_inner, new_inner_len, &kvlen);
			free(new_inner);
			if (!kv) return NULL;
			{
				int ipos_off = (int)(ipos - json);
				char *with_comma = NULL;
				int wc_len = 0;
				if (needs_comma) {
					with_comma = malloc(1 + kvlen + 1);
					if (!with_comma) { free(kv); return NULL; }
					with_comma[0] = ',';
					memcpy(with_comma + 1, kv, kvlen);
					wc_len = 1 + kvlen;
				}
				out = _splice(json, json_len, ipos_off, ipos_off,
					needs_comma ? with_comma : kv,
					needs_comma ? wc_len : kvlen, &olen);
				free(kv);
				free(with_comma);
				(void)olen;
				return out;
			}
		}
	}
}

/* ─── tests ───────────────────────────────────────────────────────── */

static int g_fails;

static void check(const char *label, const char *got, const char *expected)
{
	if (!got) {
		fprintf(stderr, "FAIL: %s\n  got:      <NULL>\n  expected: \"%s\"\n",
			label, expected);
		g_fails++;
		return;
	}
	if (strcmp(got, expected) != 0) {
		fprintf(stderr, "FAIL: %s\n  got:      \"%s\"\n  expected: \"%s\"\n",
			label, got, expected);
		g_fails++;
		return;
	}
	fprintf(stderr, "  ok: %s -> %s\n", label, got);
}

int main(void)
{
	char *out;

	#define _SLEN(s) ((s) ? (int)strlen((s) ? (s) : "") : 0)
#define APPLY(j, f, sk, u, t, vs, vi)                                  \
	_json_apply_pair((j), (int)strlen(j),                              \
		(f), (int)strlen(f),                                           \
		(sk), _SLEN(sk),                                               \
		(u), (t), (vs), _SLEN(vs), (vi))

	/* A. existing string-field behaviour: regression check */
	out = APPLY("{\"aor\":\"alice\"}", "aor", NULL, 0, 'S', "bob", 0);
	check("A: replace string field", out, "{\"aor\":\"bob\"}");
	free(out);

	/* B. integer field set */
	out = APPLY("{\"aor\":\"alice@x\"}", "aorhash", NULL, 0, 'I', NULL, 12345);
	check("B: append int field",
		out, "{\"aor\":\"alice@x\",\"aorhash\":12345}");
	free(out);

	/* C. int64 field set */
	out = APPLY("{}", "last_mod", NULL, 0, 'L', NULL, 1746630000123LL);
	check("C: append int64 field",
		out, "{\"last_mod\":1746630000123}");
	free(out);

	/* D. null field set */
	out = APPLY("{\"aor\":\"a\"}", "path", NULL, 0, 'N', NULL, 0);
	check("D: append null field",
		out, "{\"aor\":\"a\",\"path\":null}");
	free(out);

	/* E. nested-dict via subkey (the core fix) — create both layers */
	out = APPLY("{\"aor\":\"alice@x\"}", "contacts", "ct1", 0,
		'O', "{\"contact\":\"sip:alice@1.2.3.4\",\"expires\":60}", 0);
	check("E: nested object created via subkey", out,
		"{\"aor\":\"alice@x\",\"contacts\":{\"ct1\":{\"contact\":\"sip:alice@1.2.3.4\",\"expires\":60}}}");
	free(out);

	/* F. add second contact under existing "contacts" object */
	out = APPLY("{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"expires\":60}}}",
		"contacts", "ct2", 0, 'O', "{\"expires\":120}", 0);
	check("F: add second subkey to existing object", out,
		"{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"expires\":60},\"ct2\":{\"expires\":120}}}");
	free(out);

	/* G. unset subkey: delete contact from "contacts" object */
	out = APPLY("{\"aor\":\"a\",\"contacts\":{\"ct1\":{\"x\":1},\"ct2\":{\"y\":2}}}",
		"contacts", "ct1", 1, 'N', NULL, 0);
	check("G: unset subkey removes one contact", out,
		"{\"aor\":\"a\",\"contacts\":{\"ct2\":{\"y\":2}}}");
	free(out);

	/* H. unset subkey when only one contact: leaves empty object */
	out = APPLY("{\"contacts\":{\"ct1\":{\"x\":1}}}",
		"contacts", "ct1", 1, 'N', NULL, 0);
	check("H: unset last subkey leaves {}", out, "{\"contacts\":{}}");
	free(out);

	/* I. unset top-level field */
	out = APPLY("{\"aor\":\"a\",\"aorhash\":42}",
		"aorhash", NULL, 1, 'N', NULL, 0);
	check("I: unset top-level field", out, "{\"aor\":\"a\"}");
	free(out);

	/* J. value escaping: a contact URI containing a quote must round-trip */
	out = APPLY("{}", "ua", NULL, 0, 'S', "Ev\"il/1", 0);
	check("J: string field escapes quote", out, "{\"ua\":\"Ev\\\"il/1\"}");
	free(out);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
