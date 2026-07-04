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
 * cachedb_nats_expiry.c — the module's single expiry translation unit
 * (P1.5b consolidation of cachedb_nats_ttl.c, cachedb_nats_ttl_put.c,
 * cachedb_nats_reaper.c and cachedb_nats_json_reap.c).
 *
 * Contents:
 *   - pure decision helpers for the CAS row write (predicate, jsErrCode
 *     classification, key->subject mapping) and the mod_init guards;
 *   - nats_kv_put_row()/nats_kv_write_row_cas(): the single-shot CAS
 *     publish EVERY usrloc-row write goes through (§2.0 invariant);
 *   - the reaper decision logic (due-gate, per-row action) and the
 *     survivor projection used by the reaper timer host in
 *     cachedb_nats.c.
 *
 * The reaper is the module's SINGLE expiry mechanism: the native
 * per-message-TTL path was deleted in P1.5a.
 */

#include <stdio.h>   /* snprintf */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../lib/nats/nats_dl.h"
#include "../../lib/nats/nats_pool.h"     /* nats_pool_get_js */
#include "cachedb_nats_expiry.h"
#include "cachedb_nats_json_internal.h"   /* walkers, json_sink_t, _contact_*, _row_finalize_metadata */
#include "cachedb_nats_json.h"            /* _reap_project_survivors / _reap_row_due_json decls */

/* ==================================================================== */
/* pure decisions (was cachedb_nats_ttl.c)                              */
/* ==================================================================== */

/* (§2.2 [TREV-2/2a], [REV-27]) marker-aware CAS predicate. */
enum ttl_cas_pred _ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq)
{
	(void)value_len;   /* empty (marker) and non-empty both CAS at the rev */
	if (got_entry) {
		*out_seq = entry_rev;
		return TTL_CAS_LAST_SEQ;
	}
	if (head_seq > 0) {
		/* NOT_FOUND but a DEL/PURGE marker sits at the head — CAS there,
		 * never ExpectNoMessage (the server rejects it over a marker). */
		*out_seq = head_seq;
		return TTL_CAS_LAST_SEQ;
	}
	*out_seq = 0;
	return TTL_CAS_NO_MESSAGE;   /* provably empty subject */
}

/* (§2.2.1 [TREV-13]) js_PublishMsg outcome classification. */
enum ttl_outcome _ttl_classify(enum ttl_pub_status st, int jerr)
{
	if (st == TTL_PUB_OK)
		return TTL_DONE;
	if (st == TTL_PUB_CONN_DOWN)
		return TTL_FAIL_SAVE;            /* down: any jerr is stale/meaningless */
	if (jerr == 10071)                  /* JSStreamWrongLastSequenceErr */
		return TTL_RETRY;               /* CAS conflict: re-read+retry  */
	/* an unrecognized JS error => fail the save. */
	return TTL_FAIL_SAVE;
}

/* (§2.5) KV-Operation value for a publish-delete. */
const char *_ttl_delete_op(int purge)
{
	return purge ? NATS_KV_OP_PURGE : NATS_KV_OP_DEL;
}

/* (§5.3 [REV-7]) kv_ttl==0 startup guard. */
int _kv_ttl_guard(int kv_ttl)
{
	return (kv_ttl == 0) ? 0 : -1;
}

/* [D6/HREV-6] nats_expired_linger range guard: negative is meaningless,
 * > 1 day is almost certainly a typo'd epoch pasted into the config. */
int _linger_guard(int linger)
{
	return (linger >= 0 && linger <= 86400) ? 0 : -1;
}

/* P11b [REV-25 / §5.3 REV-7]: policy for a PRE-EXISTING bucket whose backing
 * stream already carries a non-zero MaxAge (created by an older deployment or
 * another tool — the _kv_ttl_guard modparam check above only stops THIS module
 * from creating one).  A non-zero stream MaxAge expires EVERY key after that
 * age, including PERMANENT contacts (expires==0) — silent registration loss.
 * @maxage_ns: the bound bucket's backing-stream MaxAge in ns.
 * @return 1 => warn (non-zero MaxAge; never silent), 0 => clean (MaxAge==0). */
int _kv_legacy_bucket_maxage_warn(int64_t maxage_ns)
{
	return maxage_ns != 0 ? 1 : 0;
}

/* (§2.1 [TREV-5]) build "$KV.<bucket>.<key>" — one mapping, three consumers. */
int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen)
{
	int n = snprintf(buf, buflen, "$KV.%s.%s", bucket, key);
	if (n < 0 || n >= buflen)
		return -1;
	return n;
}


/* ==================================================================== */
/* the single-shot CAS row write (was cachedb_nats_ttl_put.c)           */
/* ==================================================================== */

/* natsStatus -> ttl_pub_status, so the classifier stays free of nats.h coupling. */
static enum ttl_pub_status _pub_status(natsStatus s)
{
	if (s == NATS_OK)
		return TTL_PUB_OK;
	if (s == NATS_TIMEOUT || s == NATS_CONNECTION_CLOSED ||
	    s == NATS_CONNECTION_DISCONNECTED || s == NATS_NOT_YET_CONNECTED)
		return TTL_PUB_CONN_DOWN;
	return TTL_PUB_JS_ERR;
}

/* Write `json` (json_len bytes) to the usrloc row at `key`, preserving
 * optimistic concurrency.  Single-shot.
 *
 *   js/kv       : pool-owned JetStream ctx + KV store (both call sites hold them)
 *   got_entry   : the caller's prior read found an entry (NATS_OK)
 *   entry_rev   : its revision (CAS predicate target)
 *   out_rev     : new revision on success (may be NULL)
 *
 * Returns an enum ttl_outcome (TTL_DONE/RETRY/FAIL_SAVE); the caller maps
 * RETRY to its re-read loop.
 */
enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, uint64_t entry_rev, uint64_t *out_rev)
{
	char subj[512];
	uint64_t cas_seq = 0, rev = 0;
	enum ttl_cas_pred pred;
	natsMsg *m = NULL;
	jsPubAck *pa = NULL;
	jsErrCode je = 0;
	jsPubOptions o;
	natsStatus s;

	/* [R11] one mapping, three consumers (§2.1): never publish to a truncated
	 * subject -- that would land the value where the reader never queries
	 * (silent split-brain).  Fail the save instead. */
	if (nats_kv_key_to_subject(bucket, key, subj, sizeof(subj)) < 0) {
		LM_ERR("nats_kv_put_row: subject overflow for key '%s' -- failing "
			"the save\n", key);
		return TTL_FAIL_SAVE;
	}

	/* head_seq=0: js_GetLastMsg is unbound [R3], so an absent entry resolves to
	 * NO_MESSAGE and is serviced with kvStore_CreateString -- which re-creates
	 * over a server-side DEL/PURGE marker first-attempt (avoids the [REV-27]
	 * re-REGISTER lockout). */
	pred = _ttl_cas_predicate(got_entry, json_len, entry_rev, 0, &cas_seq);

	if (pred == TTL_CAS_NO_MESSAGE) {
		s = nats_dl.kvStore_CreateString(&rev, kv, key, json);
		if (s == NATS_OK) {
			if (out_rev)
				*out_rev = rev;
			return TTL_DONE;
		}
		if (_pub_status(s) == TTL_PUB_CONN_DOWN)
			return TTL_FAIL_SAVE;
		/* key already exists (a concurrent create won) -> re-read + retry */
		return TTL_RETRY;
	}

	/* update OR create-over-empty-marker: CAS-publish.
	 * ExpectLastSubjectSeq == the revision we read is byte-for-byte the
	 * optimistic check kvStore_UpdateString(rev) performed (§2.1). */
	if (nats_dl.natsMsg_Create(&m, subj, NULL, json, json_len) != NATS_OK)
		return TTL_FAIL_SAVE;
	nats_dl.jsPubOptions_Init(&o);
	o.ExpectLastSubjectSeq = cas_seq;

	s = nats_dl.js_PublishMsg(&pa, js, m, &o, &je);
	if (s == NATS_OK && pa && out_rev)
		*out_rev = pa->Sequence;           /* KV revision == stream seq */
	nats_dl.jsPubAck_Destroy(pa);
	nats_dl.natsMsg_Destroy(m);

	return _ttl_classify(_pub_status(s), je);
}

/* The §2.0 usrloc-row write entry point.  All writers (registration update,
 * first insert, reaper survivor-write) go through this; no caller calls
 * kvStore_UpdateString on the row path directly.
 *
 * `rev == 0` is the "no prior message" sentinel [HREV-2] (JetStream sequences
 * are 1-based): the write routes to a CREATE (kvStore_CreateString via the
 * NO_MESSAGE predicate).  `rev > 0` CAS-updates at that revision (a live doc
 * or a marker rev [REV-27]).
 *
 * Returns 0 = committed, 1 = CAS conflict (caller re-reads + retries),
 * -1 = fatal/fail-the-save.  *out_rev set on success. */
int nats_kv_write_row_cas(kvStore *kv, const char *bucket, const char *key,
	const char *json, int json_len, uint64_t rev, uint64_t *out_rev)
{
	enum ttl_outcome o = nats_kv_put_row(nats_pool_get_js(), kv, bucket,
		key, json, json_len, rev != 0, rev, out_rev);
	if (o == TTL_DONE)
		return 0;
	if (o == TTL_RETRY)
		return 1;
	return -1;
}


/* ==================================================================== */
/* reaper decision logic (was cachedb_nats_reaper.c)                    */
/* ==================================================================== */

/* (§4.3A [REV-1]) row-due selection. */
int _reap_row_due(int64_t row_exp, time_t now, int grace)
{
	return row_exp != 0 && (row_exp + (int64_t)grace) <= (int64_t)now;
}

/* (§4.3A [REV-16/31]) per-row action after pruning expired contacts. */
enum reap_action _reap_row_action(int n_live_survivors)
{
	return (n_live_survivors > 0) ? REAP_WRITE_SURVIVORS : REAP_DELETE_EMPTY;
}

/* (F2 [PREV-26/REV-2]) reaper-off guard.  The reaper is the SINGLE expiry
 * mechanism (the native per-message-TTL path was deleted, P1.5), so a
 * non-positive interval leaves nothing to reclaim expired records and is
 * refused unconditionally. */
int _reap_interval_guard(int interval)
{
	return (interval > 0) ? 0 : -1;
}


/* ==================================================================== */
/* reaper row projection (was cachedb_nats_json_reap.c)                 */
/* ==================================================================== */

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
/* [P2.5] pass-1: is this a usrloc row?  (has a top-level "contacts") */
static int _find_contacts_flag_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	int *has = ud;

	(void)vstart; (void)vend;
	if (nlen == 8 && memcmp(name, "contacts", 8) == 0)
		*has = 1;
	return 0;
}

/* [P2.5] stage-1: copy every top-level field, filtering the contacts
 * object down to its surviving members. */
struct project_walk_ctx {
	json_sink_t *s;
	time_t       now;
	int          grace;
	int          n_surv;
	int          first;
};

static int _project_field_cb(const char *name, int nlen,
	const char *vstart, const char *vend, void *ud)
{
	struct project_walk_ctx *c = ud;

	if (!c->first && _sink_putc(c->s, ',') < 0)
		return -1;
	c->first = 0;
	if (_sink_emit_raw_string(c->s, name, nlen) < 0)
		return -1;
	if (_sink_putc(c->s, ':') < 0)
		return -1;
	if (nlen == 8 && memcmp(name, "contacts", 8) == 0) {
		if (_emit_survivor_contacts(c->s, vstart, vend,
				c->now, c->grace, &c->n_surv) < 0)
			return -1;
	} else {
		if (_sink_write(c->s, vstart, (int)(vend - vstart)) < 0)
			return -1;
	}
	return 0;
}

char *_reap_project_survivors(const char *json, int len, time_t now, int grace,
	int *n_survivors, int *out_len,
	int64_t *out_row_exp, int *out_all_same)
{
	int has_contacts = 0;
	int n_surv = 0, tmp_len = 0;
	char *tmp, *final;
	json_sink_t s;

	if (n_survivors)
		*n_survivors = 0;
	if (out_row_exp)            /* P8: TTL eligibility of the projected survivors */
		*out_row_exp = 0;
	if (out_all_same)
		*out_all_same = 0;
	if (!json || len <= 0)
		return NULL;
	/* pass 1: is this a usrloc row at all? [P2.5] */
	if (_json_foreach_top_field(json, len,
			_find_contacts_flag_cb, &has_contacts) < 0)
		return NULL;
	if (!has_contacts) {                       /* non-usrloc doc -> skip */
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
	{
		struct project_walk_ctx pw = { &s, now, grace, 0, 1 };
		if (_json_foreach_top_field(json, len,
				_project_field_cb, &pw) < 0)
			goto fail;
		n_surv = pw.n_surv;
	}
	if (_sink_putc(&s, '}') < 0)
		goto fail;
	tmp = _sink_take(&s, &tmp_len);
	if (!tmp)
		return NULL;

	/* stage 2: recompute row_exp + schema_version over the survivors, and
	 * expose the TTL eligibility inputs (n_survivors == n_contacts). */
	final = _row_finalize_metadata(tmp, tmp_len, out_len,
		out_row_exp, NULL, out_all_same);
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
