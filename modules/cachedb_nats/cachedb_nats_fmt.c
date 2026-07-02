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
 */

/*
 * cachedb_nats_fmt.c — [FMT] table formatter (MI-OUTPUT-FORMAT-SPEC.md).
 * Pure logic, unit-locked in tests/test_fmt_table.c (carried copies must
 * stay byte-identical to this file).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cachedb_nats_fmt.h"

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
	if (t->eol_lf)
		_fmt_put(t, "\n", 1);
	else
		_fmt_put(t, "\r\n", 2);
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
}

void fmt_str(struct fmt_table *t, const char *s, int n)
{
	_fmt_sep(t);
	_fmt_value(t, s, n);
}

void fmt_int(struct fmt_table *t, long long v)
{
	char num[24];
	_fmt_sep(t);
	_fmt_put(t, num, snprintf(num, sizeof(num), "%lld", v));
}

void fmt_empty(struct fmt_table *t)
{
	_fmt_sep(t);
}

void fmt_end_record(struct fmt_table *t)
{
	_fmt_eol(t);
	t->col = 0;
}

int fmt_init(struct fmt_table *t, int kind, int eol_lf, int header,
	const char **cols, int ncols)
{
	int i;
	memset(t, 0, sizeof(*t));
	t->kind = kind;
	t->eol_lf = eol_lf;
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

char *fmt_take(struct fmt_table *t, int *out_len)
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

void fmt_free(struct fmt_table *t)
{
	free(t->buf);
	t->buf = NULL;
	t->len = t->cap = 0;
}

int _fmt_kind_parse(const char *v, int n)
{
	if (n == 4 && memcmp(v, "json", 4) == 0) return FMT_JSON;
	if (n == 3 && memcmp(v, "csv", 3) == 0)  return FMT_CSV;
	if (n == 3 && memcmp(v, "txt", 3) == 0)  return FMT_TXT;
	return -1;
}

int _fmt_opts_parse(const char *s, int len,
	int *kind, int *eol_lf, int *header)
{
	const char *p = s, *end = s + len;
	int first = 1;

	*kind = FMT_JSON; *eol_lf = 0; *header = 1;

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
				return -1;                 /* bare kind only leads */
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
