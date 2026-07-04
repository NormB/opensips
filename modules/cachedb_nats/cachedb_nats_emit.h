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
 * cachedb_nats_emit.h — the row emitter behind the [OBS]/[KVOBS] MI handlers
 * (MAINTAINABILITY-PERF-SPEC.md P2.4).  A handler walks its result set ONCE;
 * the backend picked at open time decides what a row becomes:
 *
 *   MI backend     rec() opens an object in a json array, str/i64 add named
 *                  fields, absent() omits the field, lit() is ignored.
 *   table backend  str/i64/absent/lit append csv/txt cells (names ignored --
 *                  the column header comes from open), end() ends the record.
 *
 * `absent` is the one contract that differs on purpose: a field with no
 * value is OMITTED from json but renders an EMPTY CELL in a fixed-width
 * table.  `lit` is the dual: a table-structural cell (e.g. the "scope"
 * column) that json has no use for.
 *
 * Unit-locked in tests/test_emit_rows.c, which compiles this TU directly
 * (NATS_EMIT_STANDALONE drops the MI backend, whose add_mi_* calls need the
 * cJSON core; the json shapes are asserted by the sip_e2e suite instead).
 */

#ifndef CACHEDB_NATS_EMIT_H
#define CACHEDB_NATS_EMIT_H

#include "cachedb_nats_fmt.h"

#ifdef NATS_EMIT_STANDALONE
typedef void mi_item_t;                  /* opaque: MI backend compiled out */
#else
#include "../../mi/mi.h"
#endif

struct nats_emit;

struct nats_emit_ops {
	int (*rec)(struct nats_emit *e);                     /* begin a row   */
	int (*str)(struct nats_emit *e, const char *name, int nlen,
		const char *v, int vlen);
	int (*i64)(struct nats_emit *e, const char *name, int nlen,
		long long v);
	int (*absent)(struct nats_emit *e, const char *name, int nlen);
	int (*lit)(struct nats_emit *e, const char *v, int vlen);
	int (*end)(struct nats_emit *e);                     /* end the row   */
};

struct nats_emit {
	const struct nats_emit_ops *ops;
	int table;                           /* 1 = table backend             */
	struct fmt_table t;                  /* table backend state           */
	mi_item_t *arr, *cur;                /* MI backend state              */
};

/* Table backend: header/eol per the [FMT] options.  0 ok, -1 OOM. */
int nats_emit_open_fmt(struct nats_emit *e, int kind, int eol_lf, int header,
	const char **cols, int ncols);
/* Hand over the table blob (see fmt_take); NULL for the MI backend. */
char *nats_emit_take(struct nats_emit *e, int *out_len);
/* Error-path teardown; safe on either backend. */
void nats_emit_abort(struct nats_emit *e);

static inline int nats_emit_rec(struct nats_emit *e)
	{ return e->ops->rec(e); }
static inline int nats_emit_str(struct nats_emit *e, const char *name,
	int nlen, const char *v, int vlen)
	{ return e->ops->str(e, name, nlen, v, vlen); }
static inline int nats_emit_i64(struct nats_emit *e, const char *name,
	int nlen, long long v)
	{ return e->ops->i64(e, name, nlen, v); }
static inline int nats_emit_absent(struct nats_emit *e, const char *name,
	int nlen)
	{ return e->ops->absent(e, name, nlen); }
static inline int nats_emit_lit(struct nats_emit *e, const char *v, int vlen)
	{ return e->ops->lit(e, v, vlen); }
static inline int nats_emit_end(struct nats_emit *e)
	{ return e->ops->end(e); }

#ifndef NATS_EMIT_STANDALONE
/* MI backend: rows land as objects in a new @arr_name array under @obj. */
int nats_emit_open_mi(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len);
/* One-stop open: picks the backend from @kind (FMT_JSON -> MI). */
int nats_emit_open(struct nats_emit *e, mi_item_t *obj,
	char *arr_name, int arr_len,
	int kind, int eol_lf, int header, const char **cols, int ncols);
/* Finish: table backend attaches format+data to @obj (frees the blob);
 * MI backend is a no-op.  0 ok, -1 OOM (emitter released either way). */
int nats_emit_close(struct nats_emit *e, mi_item_t *obj);
/* The [FMT-3] response shape for a pre-built table blob (frees @blob) --
 * for handlers whose table layout is not row-shaped (nats_stream_info). */
int nats_emit_attach_blob(mi_item_t *obj, int kind, char *blob, int blen);
/* The optional trailing `format` MI parameter, one parse for all handlers:
 * "<fmt>[;eol=lf|crlf][;header=0|1]".  0 ok (defaults json/crlf/header=1
 * when absent), -1 refused. */
int nats_mi_fmt_param(const mi_params_t *params,
	int *kind, int *eol_lf, int *header);
#endif

#endif /* CACHEDB_NATS_EMIT_H */
