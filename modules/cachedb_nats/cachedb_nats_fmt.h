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
 * cachedb_nats_fmt.h — the [FMT] table formatter behind format=csv/txt on
 * the [OBS]/[KVOBS] MI commands (MI-OUTPUT-FORMAT-SPEC.md).  Pure: no
 * MI/NATS coupling; unit-locked in tests/test_fmt_table.c.
 *
 *   csv  RFC 4180 (CRLF, header record, quote-and-double escaping)
 *   txt  TAB-separated, "# "-prefixed header, TAB/CR/LF in values -> space
 *   eol=lf switches both to bare LF; header=0 drops the header record.
 *
 * The formatted table rides as ONE string in the response's `data` field
 * [FMT-3]; the json path never touches this TU.
 */

#ifndef CACHEDB_NATS_FMT_H
#define CACHEDB_NATS_FMT_H

enum fmt_kind { FMT_JSON = 0, FMT_CSV = 1, FMT_TXT = 2 };

struct fmt_table {
	char *buf;
	int len, cap;
	int kind;                   /* FMT_CSV / FMT_TXT only */
	int eol_lf;                 /* 0 = CRLF [FMT-7], 1 = LF */
	int col;                    /* current column within the record */
	int oom;
};

/* Begin a table: writes the header record unless @header is 0.  0 ok. */
int  fmt_init(struct fmt_table *t, int kind, int eol_lf, int header,
	const char **cols, int ncols);
/* Append one field (separator handled internally). */
void fmt_str(struct fmt_table *t, const char *s, int n);
void fmt_int(struct fmt_table *t, long long v);
void fmt_empty(struct fmt_table *t);
/* Terminate the record with the configured EOL. */
void fmt_end_record(struct fmt_table *t);
/* Hand over the malloc'd, NUL-terminated blob (caller frees); NULL on OOM
 * (internal buffer already released). */
char *fmt_take(struct fmt_table *t, int *out_len);
void  fmt_free(struct fmt_table *t);

/* "json"/"csv"/"txt" -> enum, -1 unknown [FMT-4]. */
int cdbn_fmt_kind_parse(const char *v, int n);
/* The positional format parameter: "<fmt>[;eol=lf|crlf][;header=0|1]" (a
 * bare kind is shorthand; "format=<fmt>" long form accepted).  0 ok, -1
 * refused [FMT-5]. */
int cdbn_fmt_opts_parse(const char *s, int len,
	int *kind, int *eol_lf, int *header);

#endif /* CACHEDB_NATS_FMT_H */
