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
 * cachedb_nats_json_reap.c — P9 reaper row projection (SPEC.md §4.3A).  Pure,
 * broker-less, side-effect-free per-row decisions for the reaper timer host in
 * cachedb_nats.c: a cheap due-gate over the stored row_exp, and the survivor
 * projection that drops every DUE contact and recomputes the row metadata.
 *
 * Split out of cachedb_nats_json_rowmeta.c (which owns the WRITE-side row
 * denormalization) so the reaper's READ-then-prune semantics live on their own
 * and neither TU approaches the anti-monolith line cap.  Built on the shared
 * JSON walkers / json_sink_t (cachedb_nats_json_internal.h), the contact-field
 * parsers exposed from the rowmeta TU, and _row_finalize_metadata() for the
 * survivor row_exp recompute — so the 0=permanent sentinel + int64 [REV-34]
 * arithmetic has exactly one implementation.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cachedb_nats_json_internal.h"   /* walkers, json_sink_t, _contact_* , _row_finalize_metadata */
#include "cachedb_nats_json.h"            /* _reap_project_survivors / _reap_row_due_json decls */
#include "cachedb_nats_reaper.h"          /* _reap_row_due() */

/* [REV-1/25] Cheap reaper due-gate over a STORED row: read the top-level
 * `row_exp` (= min contact expiry, 0 = permanent) and apply the grace-padded
 * due test.  1 = due (worth a full projection), 0 = not due / permanent (skip),
 * -1 = `row_exp` absent (legacy/pre-row_exp row [REV-25]) which the caller MUST
 * treat as due (fail-closed: project it rather than leave it unreaped). */
int _reap_row_due_json(const char *json, int len, time_t now, int grace)
{
	int64_t row_exp;
	if (!json || len <= 0)
		return -1;
	if (_contact_field_int64(json, json + len, "row_exp", 7, &row_exp) != 0)
		return -1;                          /* absent => caller treats as due */
	return _reap_row_due(row_exp, now, grace);
}

/* A JSON contact is DUE (the reaper drops it) iff expired OR carrying no
 * parseable integer `expires` -- fail-closed: a binding we cannot prove is live
 * is reaped, never retained [REV-26].  expires==0 is permanent and never due
 * (_reap_row_due returns 0 for it). */
static int _reap_contact_due(const char *cvs, const char *cve, time_t now, int grace)
{
	int64_t e;
	if (_contact_expires(cvs, cve, &e) != 0)
		return 1;                          /* unprovable => fail-closed due */
	return _reap_row_due(e, now, grace);
}

/* Emit a "contacts" object holding only the surviving (non-due) contacts of
 * [c_vs,c_ve), verbatim, and report the survivor count via *n_surv.  Returns 0
 * ok / -1 on sink OOM or malformed input. */
static int _emit_survivor_contacts(json_sink_t *s, const char *c_vs,
	const char *c_ve, time_t now, int grace, int *n_surv)
{
	const char *p = _skip_ws(c_vs, c_ve);
	int first = 1, kept = 0;

	if (p >= c_ve || *p != '{')
		return -1;
	if (_sink_putc(s, '{') < 0)
		return -1;
	p++;
	while (p < c_ve) {
		const char *name, *cvs;
		int nlen;
		p = _skip_ws(p, c_ve);
		if (p >= c_ve)
			return -1;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, c_ve, &name, &nlen);
		if (!p)
			return -1;
		p = _skip_ws(p, c_ve);
		if (p >= c_ve || *p != ':')
			return -1;
		p++;
		p = _skip_ws(p, c_ve);
		cvs = p;
		p = _skip_json_value(p, c_ve);
		if (!p)
			return -1;
		if (_reap_contact_due(cvs, p, now, grace))
			continue;                      /* drop a due contact */
		if (!first && _sink_putc(s, ',') < 0)
			return -1;
		first = 0;
		kept++;
		if (_sink_emit_raw_string(s, name, nlen) < 0)
			return -1;
		if (_sink_putc(s, ':') < 0)
			return -1;
		if (_sink_write(s, cvs, (int)(p - cvs)) < 0)
			return -1;
	}
	if (_sink_putc(s, '}') < 0)
		return -1;
	*n_surv = kept;
	return 0;
}

/* [REV-1/16] (SPEC §4.3A) Reaper survivor projection.  From a stored usrloc row
 * @json, drop every DUE contact, recompute `row_exp` over the survivors, and
 * return a fresh document (caller frees).  *n_survivors is set to the survivor
 * count (0 => the row is fully due and the caller must CAS-DELETE the key), or
 * to -1 when @json has no top-level "contacts" (not a usrloc row -> returned
 * unchanged so the reaper skips it).  NULL on malformed input / OOM.
 *
 * Two stages: (1) copy the doc with the contacts object filtered to survivors,
 * then (2) hand it to _row_finalize_metadata() which recomputes row_exp +
 * schema_version over exactly those survivors — so the 0=permanent sentinel and
 * int64 arithmetic have a single owner (the rowmeta TU). */
char *_reap_project_survivors(const char *json, int len, time_t now, int grace,
	int *n_survivors, int *out_len)
{
	const char *p, *end, *c_vs = NULL;
	int n_surv = 0, first = 1, tmp_len = 0;
	char *tmp, *final;
	json_sink_t s;

	if (n_survivors)
		*n_survivors = 0;
	if (!json || len <= 0)
		return NULL;
	end = json + len;
	p = _skip_ws(json, end);
	if (p >= end || *p != '{')
		return NULL;
	p++;
	/* pass 1: locate the top-level contacts object */
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
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0)
			c_vs = vs;                 /* marks "this is a usrloc row" */
	}
	if (!c_vs) {                               /* non-usrloc doc -> skip */
		char *copy = malloc(len + 1);
		if (!copy)
			return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (n_survivors)
			*n_survivors = -1;
		if (out_len)
			*out_len = len;
		return copy;
	}
	/* stage 1: copy every top-level field, filtering the contacts object to
	 * survivors.  Stale row_exp/schema_version are copied through and then
	 * replaced by stage 2's finalize. */
	if (_sink_init(&s, len + 16) < 0)
		return NULL;
	if (_sink_putc(&s, '{') < 0)
		goto fail;
	p = _skip_ws(json, end);
	p++;
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
		if (!first && _sink_putc(&s, ',') < 0)
			goto fail;
		first = 0;
		if (_sink_emit_raw_string(&s, name, nlen) < 0)
			goto fail;
		if (_sink_putc(&s, ':') < 0)
			goto fail;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (_emit_survivor_contacts(&s, vs, p, now, grace, &n_surv) < 0)
				goto fail;
		} else {
			if (_sink_write(&s, vs, (int)(p - vs)) < 0)
				goto fail;
		}
	}
	if (_sink_putc(&s, '}') < 0)
		goto fail;
	tmp = _sink_take(&s, &tmp_len);
	if (!tmp)
		return NULL;

	/* stage 2: recompute row_exp + schema_version over the survivors. */
	final = _row_finalize_metadata(tmp, tmp_len, out_len, NULL, NULL, NULL);
	free(tmp);
	if (!final)
		return NULL;
	if (n_survivors)
		*n_survivors = n_surv;
	return final;
fail:
	free(s.buf);
	return NULL;
}
