/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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
 * cachedb_nats_json_rowmeta.c — usrloc row-metadata denormalization for the
 * NATS-backed location service (SPEC.md §3.3 / §4.1).  This TU owns the
 * cachedb_nats-private, usrloc-row-shaped transforms that run over the MERGED
 * document on the update() path — recomputing the `row_exp` / `schema_version`
 * top-level peers from the merged contact set.  It is kept separate from the
 * generic single-pass merge (cachedb_nats_json.c) and the cdb-dict serializer
 * (cachedb_nats_json_ser.c) so that usrloc-specific row semantics never leak
 * into the paths shared by other cachedb_nats consumers.  Built on the shared
 * iterative JSON walkers (_skip_ws/_parse_json_string/_skip_json_value) and the
 * json_sink_t serializer declared in cachedb_nats_json_internal.h.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cachedb_nats_json_internal.h"

/* ------------------------------------------------------------------ */
/*   P2.1 row_exp / schema_version denormalization (SPEC §3.3/§4.1)    */
/* ------------------------------------------------------------------ */

/* Parse a bare JSON integer (optional leading '-', then digits) in [p,end).
 * On success sets *out and returns the position just past the number; returns
 * NULL if there is no integer at p, or it would overflow int64.  Leading
 * whitespace must already be skipped.  Fractions/exponents are rejected — a
 * usrloc `expires` is always an integer epoch; anything else is "not a number"
 * and the caller treats the contact as having no usable expiry. [REV-34] */
static const char *_json_parse_int64(const char *p, const char *end,
	int64_t *out)
{
	int neg = 0;
	uint64_t mag = 0;

	if (p >= end)
		return NULL;
	if (*p == '-') { neg = 1; p++; }
	if (p >= end || *p < '0' || *p > '9')
		return NULL;
	for (; p < end && *p >= '0' && *p <= '9'; p++) {
		uint64_t d = (uint64_t)(*p - '0');
		/* int64 range: |min| = 2^63, max = 2^63 - 1. */
		uint64_t lim = neg ? 9223372036854775808ULL
				   : 9223372036854775807ULL;
		if (mag > (lim - d) / 10)
			return NULL;          /* would overflow int64 */
		mag = mag * 10 + d;
	}
	*out = neg ? -(int64_t)mag : (int64_t)mag;
	return p;
}

/* row_exp denormalization (SPEC §3.3 [REV-34]): the earliest time the row
 * needs reaper attention.  0 is the "permanent / never auto-expire" sentinel
 * — if ANY contact is permanent (expires==0) the whole row is permanent.  An
 * empty/NULL set yields 0.  Otherwise the minimum (earliest) expiry.  int64
 * throughout: no int32 clamp, so post-2038 epochs survive.  Only 0 is the
 * sentinel; a negative (already-past) expiry is a real candidate value. */
static int64_t _row_exp_min(const int64_t *exp, int n)
{
	int64_t m = 0;
	int i, seen = 0;

	if (!exp || n <= 0)
		return 0;
	for (i = 0; i < n; i++) {
		if (exp[i] == 0)
			return 0;             /* permanent contact => permanent row */
		if (!seen || exp[i] < m) {
			m = exp[i];
			seen = 1;
		}
	}
	return seen ? m : 0;
}

/* Find the integer-valued "expires" field within one contact-object slice
 * [vstart,vend).  Sets *out and returns 0 on success; returns -1 if the slice
 * is not an object, or has no integer "expires".  A contact with no usable
 * expiry contributes nothing to row_exp here (write side); the fail-closed
 * read handling of a poison/absent expiry is P2.5 [REV-26]. */
static int _contact_expires(const char *vstart, const char *vend,
	int64_t *out)
{
	const char *p = _skip_ws(vstart, vend);

	if (p >= vend || *p != '{')
		return -1;
	p++;
	while (p < vend) {
		const char *name, *vs;
		int nlen;

		p = _skip_ws(p, vend);
		if (p >= vend)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }

		p = _parse_json_string(p, vend, &name, &nlen);
		if (!p)
			return -1;
		p = _skip_ws(p, vend);
		if (p >= vend || *p != ':')
			return -1;
		p++;
		p = _skip_ws(p, vend);
		vs = p;
		if (nlen == 7 && memcmp(name, "expires", 7) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, vend, &v)) {
				*out = v;
				return 0;
			}
			/* non-integer expires — skip the value, keep scanning */
		}
		p = _skip_json_value(p, vend);
		if (!p)
			return -1;
	}
	return -1;
}

/* Collect every contact's integer `expires` from a "contacts" object slice
 * [vstart,vend) into a freshly malloc'd array (caller frees *out_arr).
 * Returns 0 on success (possibly 0 entries), -1 on malformed input. */
static int _row_collect_expiries(const char *vstart, const char *vend,
	int64_t **out_arr, int *out_n)
{
	const char *p = _skip_ws(vstart, vend);
	int64_t *arr = NULL;
	int n = 0, cap = 0;

	*out_arr = NULL;
	*out_n = 0;
	if (p >= vend || *p != '{')
		return -1;
	p++;
	while (p < vend) {
		const char *name, *cvs;
		int nlen;
		int64_t e;

		p = _skip_ws(p, vend);
		if (p >= vend) { free(arr); return -1; }
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }

		p = _parse_json_string(p, vend, &name, &nlen); /* contact subkey */
		if (!p) { free(arr); return -1; }
		p = _skip_ws(p, vend);
		if (p >= vend || *p != ':') { free(arr); return -1; }
		p++;
		p = _skip_ws(p, vend);
		cvs = p;
		p = _skip_json_value(p, vend);
		if (!p) { free(arr); return -1; }

		if (_contact_expires(cvs, p, &e) == 0) {
			if (n == cap) {
				int ncap = cap ? cap * 2 : 8;
				int64_t *na = realloc(arr, ncap * sizeof(*na));
				if (!na) { free(arr); return -1; }
				arr = na;
				cap = ncap;
			}
			arr[n++] = e;
		}
	}
	*out_arr = arr;
	*out_n = n;
	return 0;
}

/* Recompute the cachedb_nats-private `row_exp` / `schema_version` top-level
 * peers over the merged contact set (SPEC §3.3/§4.1 step 3, [REV-34/REV-25]).
 *
 * Returns a freshly malloc'd document (caller frees):
 *   - usrloc row (has a top-level "contacts" object): every top-level field is
 *     copied through except any stale "row_exp"/"schema_version", which are
 *     re-emitted fresh (row_exp from min(expires), schema_version=1).
 *   - non-usrloc document (no top-level "contacts"): returned byte-for-byte
 *     unchanged, so other cachedb_nats consumers are never disturbed.
 * Returns NULL on malformed input or OOM. */
char *_row_finalize_metadata(const char *json, int len, int *out_len)
{
	const char *p, *end, *c_vs = NULL, *c_ve = NULL;
	int64_t *exps = NULL;
	int n_exp = 0, first = 1;
	int64_t row_exp;
	json_sink_t s;

	if (!json || len <= 0)
		return NULL;

	/* Pass 1: locate the top-level "contacts" object. */
	end = json + len;
	p = _skip_ws(json, end);
	if (p >= end || *p != '{')
		return NULL;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;

		p = _skip_ws(p, end);
		if (p >= end)
			return NULL;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p)
			return NULL;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':')
			return NULL;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p)
			return NULL;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			c_vs = vs;
			c_ve = p;
		}
	}

	/* Non-usrloc document: return verbatim, never re-shape it. */
	if (!c_vs) {
		char *copy = malloc(len + 1);
		if (!copy)
			return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (out_len)
			*out_len = len;
		return copy;
	}

	if (_row_collect_expiries(c_vs, c_ve, &exps, &n_exp) < 0)
		return NULL;
	row_exp = _row_exp_min(exps, n_exp);
	free(exps);

	/* Pass 2: copy through every top-level field except the private peers,
	 * then append freshly computed row_exp + schema_version. */
	if (_sink_init(&s, len + 64) < 0)
		return NULL;
	if (_sink_putc(&s, '{') < 0)
		goto fail;
	p = _skip_ws(json, end);
	p++; /* past '{' */
	while (p < end) {
		const char *name, *vs;
		int nlen;

		p = _skip_ws(p, end);
		if (p >= end)
			goto fail;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p)
			goto fail;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':')
			goto fail;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p)
			goto fail;
		if ((nlen == 7 && memcmp(name, "row_exp", 7) == 0) ||
		    (nlen == 14 && memcmp(name, "schema_version", 14) == 0))
			continue;            /* drop stale private peer */
		if (!first && _sink_putc(&s, ',') < 0)
			goto fail;
		first = 0;
		if (_sink_emit_raw_string(&s, name, nlen) < 0)
			goto fail;
		if (_sink_putc(&s, ':') < 0)
			goto fail;
		if (_sink_write(&s, vs, (int)(p - vs)) < 0)
			goto fail;
	}
	if (!first && _sink_putc(&s, ',') < 0)
		goto fail;
	if (_sink_write(&s, "\"row_exp\":", 10) < 0)
		goto fail;
	if (_sink_emit_int(&s, row_exp) < 0)
		goto fail;
	if (_sink_write(&s, ",\"schema_version\":1", 19) < 0)
		goto fail;
	if (_sink_putc(&s, '}') < 0)
		goto fail;
	return _sink_take(&s, out_len);

fail:
	free(s.buf);
	return NULL;
}
