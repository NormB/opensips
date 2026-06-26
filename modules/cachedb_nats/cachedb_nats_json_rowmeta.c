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

#include "../../mem/mem.h"
#include "../../lib/osips_malloc.h"
#include "../../cachedb/cachedb_dict.h"
#include "cachedb_nats_json_internal.h"

/* ------------------------------------------------------------------ */
/*   P2.3 reject-at-write NUL hygiene (SPEC §3.1 / §4.1 step 0)        */
/* ------------------------------------------------------------------ */

/* [REV-20] An OpenSIPS str is length-based, so a 0x00 byte is reachable in a
 * contact field (ua/attr/...).  Such a value cannot round-trip: the reader is
 * cJSON_Parse + str.len = strlen(valuestring), so an interior NUL truncates
 * the value (silent corruption).  Returns 1 if @s carries a raw 0x00 OR the
 * 6-byte JSON escape "\u0000" (which cJSON decodes to 0x00); else 0.  Fail
 * closed: a value embedding the literal escape is conservatively refused (a
 * real SIP UA/attr never carries it). */
static int _field_has_nul(const char *s, int len)
{
	int i;

	if (!s || len <= 0)
		return 0;
	for (i = 0; i < len; i++) {
		if (s[i] == '\0')
			return 1;                       /* raw 0x00 byte */
		/* escaped JSON NUL: '\' 'u' '0' '0' '0' '0' (decodes to 0x00) */
		if (s[i] == '\\' && i + 5 < len &&
		    s[i+1] == 'u' &&
		    s[i+2] == '0' && s[i+3] == '0' &&
		    s[i+4] == '0' && s[i+5] == '0')
			return 1;
	}
	return 0;
}

/* Recurse the incoming update dict (usrloc nests each contact's fields under
 * contacts.<id>, so a NUL can sit at any depth); return 1 if any CDB_STR field
 * value carries an embedded NUL.  Run before any merge / kvStore op so the save
 * can be refused with no partial row (SPEC §4.1 step 0 [REV-20]). */
int _dict_has_nul_field(const cdb_dict_t *dict)
{
	struct list_head *pos;
	cdb_pair_t *pair;

	if (!dict)
		return 0;
	list_for_each(pos, dict) {
		pair = list_entry(pos, cdb_pair_t, list);
		if (pair->unset)
			continue;
		switch (pair->val.type) {
		case CDB_STR:
			if (_field_has_nul(pair->val.val.st.s,
					pair->val.val.st.len))
				return 1;
			break;
		case CDB_DICT:
			if (_dict_has_nul_field(&pair->val.val.dict))
				return 1;
			break;
		default:
			break;
		}
	}
	return 0;
}

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

/* Find the integer-valued field @fname (length @flen) within one contact-object
 * slice [vstart,vend).  Sets *out and returns 0 on success; returns -1 if the
 * slice is not an object, or the field is absent / not an integer.  Shared by
 * the row_exp `expires` scan (write side) and the int64 `last_mod` post-patch
 * (read side, P2.4). */
static int _contact_field_int64(const char *vstart, const char *vend,
	const char *fname, int flen, int64_t *out)
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
		if (nlen == flen && memcmp(name, fname, flen) == 0) {
			int64_t v;
			if (_json_parse_int64(vs, vend, &v)) {
				*out = v;
				return 0;
			}
			/* present but not an integer — keep scanning (no dup key
			 * expected, but be tolerant); fall through to skip. */
		}
		p = _skip_json_value(p, vend);
		if (!p)
			return -1;
	}
	return -1;
}

/* row_exp's per-contact `expires` accessor (write side).  A contact with no
 * usable expiry contributes nothing to row_exp; fail-closed read handling of a
 * poison/absent expiry is P2.5 [REV-26]. */
static int _contact_expires(const char *vstart, const char *vend, int64_t *out)
{
	return _contact_field_int64(vstart, vend, "expires", 7, out);
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

/* ------------------------------------------------------------------ */
/*   P2.4 int64 last_mod read seam (SPEC §3.1 Option A)               */
/* ------------------------------------------------------------------ */

/* Locate the raw JSON slice of the contact whose id == [id,id_len] within the
 * "contacts" object slice [c_vs,c_ve).  Contact ids are base64(matchkey), so
 * they are JSON-escape-free and a byte compare against the raw (un-decoded) key
 * is exact.  Returns 0 + [*out_vs,*out_ve) on success, -1 if not found. */
static int _raw_find_contact(const char *c_vs, const char *c_ve,
	const char *id, int id_len, const char **out_vs, const char **out_ve)
{
	const char *p = _skip_ws(c_vs, c_ve);

	if (p >= c_ve || *p != '{')
		return -1;
	p++;
	while (p < c_ve) {
		const char *name, *vs;
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
		vs = p;
		p = _skip_json_value(p, c_ve);
		if (!p)
			return -1;
		if (nlen == id_len && memcmp(name, id, id_len) == 0) {
			*out_vs = vs;
			*out_ve = p;
			return 0;
		}
	}
	return -1;
}

/* [REV-15/REV-30] (SPEC §3.1 Option A): the shared cdb_json_to_dict clamps every
 * JSON number to CDB_INT32 (cJSON valueint -> INT_MAX), silently narrowing a
 * `last_mod` (a usrloc CDB_INT64, read as i64) that exceeds INT32_MAX.  Re-parse
 * `last_mod` as int64 from the raw row JSON and overwrite each contact's
 * `last_mod` pair in @row_dict to CDB_INT64 with the true value.  Only last_mod
 * is widened — `expires` stays int32-bounded at the usrloc boundary [REV-30].
 * A no-op for a document without a top-level "contacts" object (non-usrloc row)
 * and for any contact whose last_mod is absent / non-integer (left untouched). */
void _row_patch_last_mod_int64(const char *json, int len, cdb_dict_t *row_dict)
{
	const char *p, *end, *c_vs = NULL, *c_ve = NULL;
	struct list_head *pos;
	cdb_pair_t *pair;

	if (!json || len <= 0 || !row_dict)
		return;

	/* locate the raw top-level "contacts" object slice */
	end = json + len;
	p = _skip_ws(json, end);
	if (p >= end || *p != '{')
		return;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;

		p = _skip_ws(p, end);
		if (p >= end)
			return;
		if (*p == '}')
			break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p)
			return;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':')
			return;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p)
			return;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			c_vs = vs;
			c_ve = p;
		}
	}
	if (!c_vs)
		return;            /* not a usrloc row */

	/* walk the parsed "contacts" dict; patch each contact's last_mod */
	list_for_each(pos, row_dict) {
		struct list_head *cpos;

		pair = list_entry(pos, cdb_pair_t, list);
		if (pair->val.type != CDB_DICT)
			continue;
		if (pair->key.name.len != 8 ||
		    memcmp(pair->key.name.s, "contacts", 8) != 0)
			continue;

		list_for_each(cpos, &pair->val.val.dict) {
			cdb_pair_t *cpair = list_entry(cpos, cdb_pair_t, list);
			const char *rc_vs, *rc_ve;
			struct list_head *fpos;
			int64_t lm;

			if (cpair->val.type != CDB_DICT)
				continue;
			if (_raw_find_contact(c_vs, c_ve, cpair->key.name.s,
					cpair->key.name.len, &rc_vs, &rc_ve) != 0)
				continue;
			if (_contact_field_int64(rc_vs, rc_ve, "last_mod", 8, &lm) != 0)
				continue;   /* absent / non-integer: leave the pair as-is */

			list_for_each(fpos, &cpair->val.val.dict) {
				cdb_pair_t *fp = list_entry(fpos, cdb_pair_t, list);
				if (fp->key.name.len == 8 &&
				    memcmp(fp->key.name.s, "last_mod", 8) == 0) {
					fp->val.type = CDB_INT64;
					fp->val.val.i64 = lm;
					break;
				}
			}
		}
		break;             /* only one top-level "contacts" */
	}
}

/* ------------------------------------------------------------------ */
/*   P2.5 fail-closed poison classification (SPEC §4.2 [REV-26])       */
/* ------------------------------------------------------------------ */

/* Classify a stored KV value on read (SPEC §4.2):
 *   NATS_VAL_EMPTY  — zero-length / all-whitespace: a server-side delete
 *                     marker; treat the AoR as absent (no error).
 *   NATS_VAL_OBJECT — first non-whitespace byte is '{': parse it.
 *   NATS_VAL_POISON — non-empty and not a JSON object (null / string / number
 *                     / array / garbage): a hard integrity error.  The current
 *                     `data[0]=='{'` gate masks this as an empty AoR — a silent
 *                     deregistration a stale node / co-writer / attacker could
 *                     plant — so [REV-26] alarms + counts instead. */
int _value_classify(const char *data, int len)
{
	const char *p, *end;

	if (!data || len <= 0)
		return NATS_VAL_EMPTY;
	p = data;
	end = data + len;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	if (p >= end)
		return NATS_VAL_EMPTY;        /* all whitespace == delete marker */
	return (*p == '{') ? NATS_VAL_OBJECT : NATS_VAL_POISON;
}

/* ------------------------------------------------------------------ */
/*   P2.6 strip cachedb_nats-private top-level peers (SPEC §4.2 step 3) */
/* ------------------------------------------------------------------ */

/* True for the cachedb_nats-private top-level peers usrloc must never see. */
static int _is_private_top_key(const char *name, int len)
{
	return (len == 7  && memcmp(name, "row_exp", 7) == 0) ||
	       (len == 14 && memcmp(name, "schema_version", 14) == 0);
}

/* Free one removed pair completely (it is no longer in any dict, so
 * cdb_free_rows will not reach it).  row_exp/schema_version are normally
 * CDB_INT32, but a crafted-yet-valid object could carry them as a string or a
 * nested dict (P2.5 only gates the top-level value type), so free by type. */
static void _free_one_pair(cdb_pair_t *p)
{
	switch (p->val.type) {
	case CDB_DICT:
		cdb_free_entries(&p->val.val.dict, osips_pkg_free);
		break;
	case CDB_STR:
		if (p->val.val.st.s)
			osips_pkg_free(p->val.val.st.s);
		break;
	default:
		break;
	}
	pkg_free(p);
}

/* [REV-18/REV-35] (SPEC §4.2 step 3): the cdb_row_t handed to usrloc must be
 * exactly {contacts, aorhash}.  Strip the cachedb_nats-private top-level peers
 * (row_exp, schema_version) at row assembly — they are top-level peers, not
 * members of any contact subdict, so this is a top-level walk.  Safe against
 * removal mid-iteration (list_for_each_safe). */
void _row_strip_private_keys(cdb_dict_t *row_dict)
{
	struct list_head *pos, *tmp;

	if (!row_dict)
		return;
	list_for_each_safe(pos, tmp, row_dict) {
		cdb_pair_t *pair = list_entry(pos, cdb_pair_t, list);
		if (_is_private_top_key(pair->key.name.s, pair->key.name.len)) {
			list_del(&pair->list);
			_free_one_pair(pair);
		}
	}
}

/* ------------------------------------------------------------------ */
/*   P2.7 skew-safe write-side expiry hygiene (SPEC §4.1 step 4)       */
/* ------------------------------------------------------------------ */

/* Upper bound on touched-expired subkeys dropped in one update.  An update that
 * sets more than this many already-expired contacts (pathological) leaves the
 * excess for the reaper (§4.3A) — never a correctness loss, only deferred. */
#define NATS_MAX_DROP_IDS 256

/* [REV-1/REV-21] A contact is already-expired when its absolute `expires` plus
 * the skew grace S has passed node-local `now`.  expires==0 is permanent. */
static int _contact_is_expired(int64_t expires, time_t now, int grace)
{
	return expires != 0 && (expires + (int64_t)grace) <= (int64_t)now;
}

/* Extract a set-contact pair's own `expires` (CDB_INT32/INT64) from its value
 * dict.  Returns 0 + *out, or -1 if absent / not an integer. */
static int _pair_contact_expires(const cdb_pair_t *p, int64_t *out)
{
	struct list_head *pos;

	if (p->val.type != CDB_DICT)
		return -1;
	list_for_each(pos, &p->val.val.dict) {
		cdb_pair_t *f = list_entry(pos, cdb_pair_t, list);
		if (f->key.name.len != 7 || memcmp(f->key.name.s, "expires", 7) != 0)
			continue;
		if (f->val.type == CDB_INT32) { *out = f->val.val.i32; return 0; }
		if (f->val.type == CDB_INT64) { *out = f->val.val.i64; return 0; }
		return -1;
	}
	return -1;
}

/* Rewrite a "contacts" object slice [cvs,cve), dropping any subkey in @ids. */
static int _emit_contacts_minus(json_sink_t *s, const char *cvs, const char *cve,
	const char **ids, const int *id_lens, int n_ids)
{
	const char *p = _skip_ws(cvs, cve), *end = cve;
	int first = 1;

	if (p >= end || *p != '{') return -1;
	if (_sink_putc(s, '{') < 0) return -1;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen, i, drop = 0;

		p = _skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p) return -1;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p) return -1;
		for (i = 0; i < n_ids; i++)
			if (nlen == id_lens[i] && memcmp(name, ids[i], nlen) == 0) { drop = 1; break; }
		if (drop) continue;
		if (!first && _sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (_sink_emit_raw_string(s, name, nlen) < 0) return -1;
		if (_sink_putc(s, ':') < 0) return -1;
		if (_sink_write(s, vs, (int)(p - vs)) < 0) return -1;
	}
	if (_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Copy @json through, dropping subkeys @ids from the top-level "contacts"
 * object.  Returns a fresh doc (caller frees), or NULL on error/OOM. */
static char *_contacts_drop_subkeys(const char *json, int len,
	const char **ids, const int *id_lens, int n_ids, int *out_len)
{
	const char *p, *end;
	json_sink_t s;
	int first = 1;

	if (!json || len <= 0) return NULL;
	end = json + len;
	p = _skip_ws(json, end);
	if (p >= end || *p != '{') return NULL;
	if (_sink_init(&s, len + 16) < 0) return NULL;
	if (_sink_putc(&s, '{') < 0) goto fail;
	p++;
	while (p < end) {
		const char *name, *vs;
		int nlen;

		p = _skip_ws(p, end);
		if (p >= end) goto fail;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &name, &nlen);
		if (!p) goto fail;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') goto fail;
		p++;
		p = _skip_ws(p, end);
		vs = p;
		p = _skip_json_value(p, end);
		if (!p) goto fail;
		if (!first && _sink_putc(&s, ',') < 0) goto fail;
		first = 0;
		if (_sink_emit_raw_string(&s, name, nlen) < 0) goto fail;
		if (_sink_putc(&s, ':') < 0) goto fail;
		if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
			if (_emit_contacts_minus(&s, vs, p, ids, id_lens, n_ids) < 0) goto fail;
		} else {
			if (_sink_write(&s, vs, (int)(p - vs)) < 0) goto fail;
		}
	}
	if (_sink_putc(&s, '}') < 0) goto fail;
	return _sink_take(&s, out_len);
fail:
	free(s.buf);
	return NULL;
}

/* [REV-21] (SPEC §4.1 step 4): drop from the merged @json only those contacts
 * THIS update set/unset whose own `expires` is already past `now + S`.  The
 * drop set is built solely from @pairs (the touched subkeys), so an untouched
 * merged-in contact is never even considered — no collateral cross-node delete.
 * A pair's subkey equals the stored contact key (base64, escape-free).  Returns
 * a fresh doc (caller frees): unchanged when nothing is due.  NULL on error. */
char *_row_drop_expired_own(const char *json, int len, const cdb_dict_t *pairs,
	time_t now, int grace, int *out_len)
{
	const char *ids[NATS_MAX_DROP_IDS];
	int id_lens[NATS_MAX_DROP_IDS];
	int n = 0;
	struct list_head *pos;

	if (!json || len <= 0) return NULL;
	if (pairs) {
		list_for_each(pos, pairs) {
			cdb_pair_t *p = list_entry(pos, cdb_pair_t, list);
			int64_t exp;

			if (p->unset) continue;
			if (p->key.name.len != 8 || memcmp(p->key.name.s, "contacts", 8) != 0)
				continue;
			if (p->subkey.len <= 0 || !p->subkey.s) continue;
			if (_pair_contact_expires(p, &exp) != 0) continue;
			if (!_contact_is_expired(exp, now, grace)) continue;
			if (n < NATS_MAX_DROP_IDS) {
				ids[n] = p->subkey.s;
				id_lens[n] = p->subkey.len;
				n++;
			}
		}
	}
	if (n == 0) {
		char *copy = malloc(len + 1);
		if (!copy) return NULL;
		memcpy(copy, json, len);
		copy[len] = '\0';
		if (out_len) *out_len = len;
		return copy;
	}
	return _contacts_drop_subkeys(json, len, ids, id_lens, n, out_len);
}
