/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * MI-OUTPUT-FORMAT-SPEC.md [FMT-4..7]: the pure table formatter behind
 * format=csv / format=txt on the [OBS]/[KVOBS] commands, plus the format
 * option parsing (bare "csv" or "csv;eol=lf;header=0").
 *
 *   csv  RFC 4180: CRLF records, header first, fields containing comma /
 *        quote / CR / LF are double-quoted with quotes doubled; values are
 *        otherwise VERBATIM (backslashes are not special in CSV).
 *   txt  TAB-separated, CRLF, "# "-prefixed header; TAB/CR/LF INSIDE a
 *        value become one space (documented lossy).
 *   eol=lf switches both to bare LF; header=0 drops the header record.
 *   Unknown format/eol/header values are REFUSED (fail loud, FMT-4).
 *
 *   gcc -DFMT_CURRENT ... -> naive formatter: no quoting, no sanitizing,
 *                            LF-only, header always, options unparsed => RED.
 *   gcc ...               -> the FIXED formatter => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_fmt_table test_fmt_table.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum fmt_kind { FMT_JSON = 0, FMT_CSV = 1, FMT_TXT = 2 };

/* ─── carried copies of the production formatter (cachedb_nats_fmt.c) ─── */

struct fmt_table {
	char *buf;
	int len, cap;
	int kind;
	int eol_lf;
	int col;
	int oom;
};

static int _fmt_put(struct fmt_table *t, const char *p, int n)
{
	if (t->oom)
		return -1;
	if (t->len + n + 1 > t->cap) {
		int ncap = t->cap ? t->cap : 256;
		char *nb;
		while (t->len + n + 1 > ncap)
			ncap *= 2;
		nb = realloc(t->buf, ncap);
		if (!nb) { t->oom = 1; return -1; }
		t->buf = nb;
		t->cap = ncap;
	}
	memcpy(t->buf + t->len, p, n);
	t->len += n;
	t->buf[t->len] = '\0';
	return 0;
}

static void _fmt_eol(struct fmt_table *t)
{
#ifdef FMT_CURRENT
	_fmt_put(t, "\n", 1);                      /* LF only */
#else
	if (t->eol_lf)
		_fmt_put(t, "\n", 1);
	else
		_fmt_put(t, "\r\n", 2);
#endif
}

static void _fmt_sep(struct fmt_table *t)
{
	if (t->col++ == 0)
		return;
	_fmt_put(t, t->kind == FMT_CSV ? "," : "\t", 1);
}

/* csv: RFC 4180 quoting; txt: TAB/CR/LF in the value -> one space */
static void _fmt_value(struct fmt_table *t, const char *s, int n)
{
#ifdef FMT_CURRENT
	_fmt_put(t, s, n);                         /* verbatim, no protection */
#else
	int i, needs_quote = 0;

	if (t->kind == FMT_TXT) {
		for (i = 0; i < n; i++) {
			char c = s[i];
			if (c == '\t' || c == '\r' || c == '\n')
				c = ' ';
			_fmt_put(t, &c, 1);
		}
		return;
	}
	for (i = 0; i < n; i++)
		if (s[i] == ',' || s[i] == '"' || s[i] == '\r' || s[i] == '\n') {
			needs_quote = 1;
			break;
		}
	if (!needs_quote) {
		_fmt_put(t, s, n);
		return;
	}
	_fmt_put(t, "\"", 1);
	for (i = 0; i < n; i++) {
		if (s[i] == '"')
			_fmt_put(t, "\"\"", 2);
		else
			_fmt_put(t, &s[i], 1);
	}
	_fmt_put(t, "\"", 1);
#endif
}

static void fmt_str(struct fmt_table *t, const char *s, int n)
{
	_fmt_sep(t);
	_fmt_value(t, s, n);
}

static void fmt_int(struct fmt_table *t, long long v)
{
	char num[24];
	_fmt_sep(t);
	_fmt_put(t, num, snprintf(num, sizeof(num), "%lld", v));
}

static void fmt_empty(struct fmt_table *t)
{
	_fmt_sep(t);
}

static void fmt_end_record(struct fmt_table *t)
{
	_fmt_eol(t);
	t->col = 0;
}

static int fmt_init(struct fmt_table *t, int kind, int eol_lf, int header,
	const char **cols, int ncols)
{
	int i;
	memset(t, 0, sizeof(*t));
	t->kind = kind;
	t->eol_lf = eol_lf;
#ifdef FMT_CURRENT
	header = 1;                                /* flag ignored */
#endif
	if (!header)
		return 0;
	if (kind == FMT_TXT)
		_fmt_put(t, "# ", 2);
	for (i = 0; i < ncols; i++) {
		if (i)
			_fmt_put(t, kind == FMT_CSV ? "," : "\t", 1);
		_fmt_put(t, cols[i], (int)strlen(cols[i]));
	}
	fmt_end_record(t);
	t->col = 0;
	return t->oom ? -1 : 0;
}

static char *fmt_take(struct fmt_table *t, int *out_len)
{
	char *b;
	if (t->oom) {
		free(t->buf);
		t->buf = NULL;
		return NULL;
	}
	b = t->buf ? t->buf : strdup("");
	if (out_len)
		*out_len = t->len;
	t->buf = NULL;
	return b;
}

/* ─── format option parsing: bare kind, or ';' tokens (FMT-5) ────── */

static int _fmt_kind_parse(const char *v, int n)
{
	if (n == 4 && memcmp(v, "json", 4) == 0) return FMT_JSON;
	if (n == 3 && memcmp(v, "csv", 3) == 0)  return FMT_CSV;
	if (n == 3 && memcmp(v, "txt", 3) == 0)  return FMT_TXT;
	return -1;
}

/* "<fmt>[;eol=lf|crlf][;header=0|1]" or "format=<fmt>;..."; 0 ok / -1 bad */
static int _fmt_opts_parse(const char *s, int len,
	int *kind, int *eol_lf, int *header)
{
	*kind = FMT_JSON; *eol_lf = 0; *header = 1;
#ifdef FMT_CURRENT
	(void)s; (void)len; return 0;              /* unparsed */
#else
	{
		const char *p = s, *end = s + len;
		int first = 1;
		while (p < end) {
			const char *tok = p, *eq, *te;
			while (p < end && *p != ';')
				p++;
			te = p;
			if (p < end)
				p++;
			while (tok < te && (*tok == ' ' || *tok == '\t')) tok++;
			while (te > tok && (te[-1] == ' ' || te[-1] == '\t')) te--;
			if (tok == te)
				continue;
			for (eq = tok; eq < te && *eq != '='; eq++)
				;
			if (eq == te) {
				int k;
				if (!first)
					return -1;             /* bare kind only leads */
				k = _fmt_kind_parse(tok, (int)(te - tok));
				if (k < 0)
					return -1;
				*kind = k;
			} else {
				int klen = (int)(eq - tok);
				const char *v = eq + 1;
				int vlen = (int)(te - eq - 1);
				if (klen == 6 && memcmp(tok, "format", 6) == 0) {
					int k = _fmt_kind_parse(v, vlen);
					if (k < 0)
						return -1;
					*kind = k;
				} else if (klen == 3 && memcmp(tok, "eol", 3) == 0) {
					if (vlen == 2 && memcmp(v, "lf", 2) == 0)
						*eol_lf = 1;
					else if (vlen == 4 && memcmp(v, "crlf", 4) == 0)
						*eol_lf = 0;
					else
						return -1;
				} else if (klen == 6 && memcmp(tok, "header", 6) == 0) {
					if (vlen == 1 && *v == '0')
						*header = 0;
					else if (vlen == 1 && *v == '1')
						*header = 1;
					else
						return -1;
				} else {
					return -1;
				}
			}
			first = 0;
		}
		return 0;
	}
#endif
}

/* ─── harness ─────────────────────────────────────────────────────── */

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
#define BLOB_IS(want, msg) do { \
	int _l; char *_b = fmt_take(&t, &_l); \
	if (!_b || strcmp(_b, want) != 0) { \
		printf("  FAIL: %s\n    got:  \"%s\"\n    want: \"%s\"\n", msg, \
			_b ? _b : "<oom>", want); fails++; \
	} else printf("  ok:   %s\n", msg); \
	free(_b); \
} while (0)

int main(void)
{
	struct fmt_table t;
	static const char *C3[] = {"aor", "contacts", "ua"};

#ifdef FMT_CURRENT
	printf("== carried copy: FMT_CURRENT (naive) ==\n");
#else
	printf("== carried copy: FIXED formatter ==\n");
#endif

	printf("[FMT-5] csv basics: header, CRLF, plain fields:\n");
	fmt_init(&t, FMT_CSV, 0, 1, C3, 3);
	fmt_str(&t, "alice@x", 7); fmt_int(&t, 2); fmt_str(&t, "sipsak", 6);
	fmt_end_record(&t);
	BLOB_IS("aor,contacts,ua\r\nalice@x,2,sipsak\r\n",
		"header + record, CRLF-terminated");

	printf("[FMT-5] csv quoting matrix:\n");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "a,b", 3); fmt_int(&t, 1); fmt_str(&t, "say \"hi\"", 8);
	fmt_end_record(&t);
	BLOB_IS("\"a,b\",1,\"say \"\"hi\"\"\"\r\n",
		"comma quoted; quotes doubled (header=0)");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "evil\r\nua", 8); fmt_int(&t, 1); fmt_str(&t, "back\\slash", 10);
	fmt_end_record(&t);
	BLOB_IS("\"evil\r\nua\",1,back\\slash\r\n",
		"embedded CRLF quoted VERBATIM; backslash NOT special");

	printf("[FMT-6] txt: TAB join, '# ' header, sanitization:\n");
	fmt_init(&t, FMT_TXT, 0, 1, C3, 3);
	fmt_str(&t, "alice@x", 7); fmt_int(&t, 2); fmt_str(&t, "tab\there", 8);
	fmt_end_record(&t);
	BLOB_IS("# aor\tcontacts\tua\r\nalice@x\t2\ttab here\r\n",
		"TAB-separated, TAB-in-value becomes a space");
	fmt_init(&t, FMT_TXT, 0, 0, C3, 3);
	fmt_str(&t, "cr\rlf\n", 6); fmt_int(&t, 0); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("cr lf \t0\t\r\n",
		"CR/LF in value sanitized; empty field renders empty");

	printf("[FMT-7] eol=lf:\n");
	fmt_init(&t, FMT_CSV, 1, 1, C3, 3);
	fmt_str(&t, "a", 1); fmt_int(&t, 1); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("aor,contacts,ua\na,1,\n", "csv with bare-LF records");

	printf("[FMT-5] empty optional fields (never null/sentinel):\n");
	fmt_init(&t, FMT_CSV, 0, 0, C3, 3);
	fmt_str(&t, "b@x", 3); fmt_empty(&t); fmt_empty(&t);
	fmt_end_record(&t);
	BLOB_IS("b@x,,\r\n", "csv empty fields are just separators");

	printf("[FMT-4/5] option parsing:\n");
	{
		int k, e, h;
		CHECK(_fmt_opts_parse("csv", 3, &k, &e, &h) == 0 &&
		      k == FMT_CSV && e == 0 && h == 1,
		      "bare 'csv' => csv, CRLF, header (the defaults)");
		CHECK(_fmt_opts_parse("txt;eol=lf;header=0", 19, &k, &e, &h) == 0 &&
		      k == FMT_TXT && e == 1 && h == 0,
		      "'txt;eol=lf;header=0' fully parsed");
		CHECK(_fmt_opts_parse("format=csv;header=0", 19, &k, &e, &h) == 0 &&
		      k == FMT_CSV && h == 0,
		      "'format=csv;header=0' long form accepted");
		CHECK(_fmt_opts_parse("json", 4, &k, &e, &h) == 0 && k == FMT_JSON,
		      "explicit 'json' accepted");
		CHECK(_fmt_opts_parse("", 0, &k, &e, &h) == 0 && k == FMT_JSON,
		      "empty => json default");
		CHECK(_fmt_opts_parse("cvs", 3, &k, &e, &h) == -1,
		      "typo'd 'cvs' REFUSED (never silently json)");
		CHECK(_fmt_opts_parse("csv;eol=bogus", 13, &k, &e, &h) == -1,
		      "bad eol value refused");
		CHECK(_fmt_opts_parse("csv;header=2", 12, &k, &e, &h) == -1,
		      "bad header value refused");
		CHECK(_fmt_opts_parse("eol=lf;csv", 10, &k, &e, &h) == -1,
		      "bare kind only allowed as the FIRST token");
		CHECK(_fmt_opts_parse("csv;wat=1", 9, &k, &e, &h) == -1,
		      "unknown option key refused");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
