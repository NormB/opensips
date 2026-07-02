/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 Stage 1b [TTL-SOLUTION-SPEC.md §2.0/§2.2]: nats_kv_put_row() -- the single
 * helper through which EVERY usrloc-row write goes (the §2.0 invariant), so
 * every write to a TTL-eligible subject re-asserts Nats-TTL [TREV-3].  It is a
 * thin, single-shot publish: all re-read/re-merge/backoff stays in the callers'
 * existing CAS loops.  The pure decisions it composes (_ttl_cas_predicate,
 * _ttl_classify) are unit-tested in cachedb_nats_ttl.c; this file is the glue.
 */
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../lib/nats/nats_dl.h"
#include "../../lib/nats/nats_pool.h"   /* ttl cap latch + AllowMsgTTL setup + get_js */
#include "cachedb_nats_ttl.h"
#include "cachedb_nats_dbase.h"         /* nats_cas_should_retry (legacy fallback) */

extern int nats_native_ttl;             /* [D6] master switch (cachedb_nats.c) */
extern int nats_ttl_allow_history;      /* [D6] history-gate override          */

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

/* Write `json` (json_len bytes) to the usrloc row at `key`, re-asserting the
 * per-message TTL and preserving optimistic concurrency.  Single-shot.
 *
 *   js/kv       : pool-owned JetStream ctx + KV store (both call sites hold them)
 *   got_entry   : the caller's prior read found an entry (NATS_OK)
 *   value_len   : its value length (0 => empty-value MaxAge marker)
 *   entry_rev   : its revision (CAS predicate target)
 *   msg_ttl_ms  : Nats-TTL in ms, 0 => no TTL (ineligible/permanent row)
 *   out_rev     : new revision on success (may be NULL)
 *
 * Returns an enum ttl_outcome (TTL_DONE/RETRY/LATCH_OFF/ASSERT_BUG/FAIL_SAVE);
 * the caller maps RETRY to its re-read loop and LATCH_OFF to the legacy
 * kvStore_UpdateString fallback + reaper.
 */
enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, int value_len, uint64_t entry_rev,
	int64_t msg_ttl_ms, uint64_t *out_rev)
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
	 * NO_MESSAGE and is serviced with kvStore_CreateStringWithTTL [PR #1000] --
	 * which re-creates over a server-side DEL/PURGE/MaxAge marker first-attempt
	 * (avoids the [REV-27] re-REGISTER lockout) AND carries the per-key TTL on
	 * that create (Phase B).  ttl<=0 means no TTL (identical to kvStore_Create),
	 * so the reaper no longer has to backstop the create path. */
	pred = _ttl_cas_predicate(got_entry, value_len, entry_rev, 0, &cas_seq);

	if (pred == TTL_CAS_NO_MESSAGE) {
		s = nats_dl.kvStore_CreateStringWithTTL(&rev, kv, key, json, msg_ttl_ms);
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

	/* update OR create-over-empty-marker: CAS-publish with re-asserted TTL.
	 * ExpectLastSubjectSeq == the revision we read is byte-for-byte the
	 * optimistic check kvStore_UpdateString(rev) performed (§2.1).
	 *
	 * Phase C: this path deliberately KEEPS the raw js_PublishMsg rather than
	 * adopting kvStore_UpdateWithTTL [PR #1000].  js_PublishMsg returns the
	 * numeric jsErrCode inline, which _ttl_classify needs for its stable
	 * 10071(RETRY)/10166(LATCH_OFF)/10165(BUG) dispatch; the kvStore_*WithTTL
	 * helpers expose only the error text (PR #1001), not the code.  Revisit once
	 * libnats grows a jsErrCode accessor (nats_GetLastJSErrCode). */
	if (nats_dl.natsMsg_Create(&m, subj, NULL, json, json_len) != NATS_OK)
		return TTL_FAIL_SAVE;
	nats_dl.jsPubOptions_Init(&o);
	o.ExpectLastSubjectSeq = cas_seq;
	if (msg_ttl_ms > 0)
		o.MsgTTL = msg_ttl_ms;             /* re-assert Nats-TTL [TREV-3] */

	s = nats_dl.js_PublishMsg(&pa, js, m, &o, &je);
	if (s == NATS_OK && pa && out_rev)
		*out_rev = pa->Sequence;           /* KV revision == stream seq */
	nats_dl.jsPubAck_Destroy(pa);
	nats_dl.natsMsg_Destroy(m);

	return _ttl_classify(_pub_status(s), je);
}

/* The §2.0 usrloc-row write entry point.  All writers (registration update,
 * first insert, reaper survivor-write) go through this; no caller calls
 * kvStore_UpdateString on the row path directly.  Resolves per-message-TTL
 * capability (probing + enabling AllowMsgTTL once per connection epoch, latch
 * via _ttl_cap_next) gated behind the nats_native_ttl master switch [D6],
 * computes ttl_ms from eligibility (§5), publishes with re-asserted TTL via
 * nats_kv_put_row when supported, and falls back to the legacy CAS write
 * (identical to pre-P8 behaviour) on a <2.11 / TTL-disabled / not-yet-probed
 * broker or nats_native_ttl=0.
 *
 * `rev == 0` is the "no prior message" sentinel [HREV-2] (JetStream sequences
 * are 1-based): the write routes to a CREATE that carries the row's TTL
 * (kvStore_CreateStringWithTTL via the NO_MESSAGE predicate, or
 * kvStore_CreateString on the legacy path).  `rev > 0` CAS-updates at that
 * revision (a live doc or a marker rev [REV-27]).
 *
 * Returns 0 = committed, 1 = CAS conflict (caller re-reads + retries),
 * -1 = fatal/fail-the-save.  *out_rev set on success. */
int nats_kv_write_row_cas(kvStore *kv, const char *bucket, const char *key,
	const char *json, int json_len, uint64_t rev,
	int64_t row_exp, int n_contacts, int all_same, int grace,
	uint64_t *out_rev)
{
	int cap = nats_pool_ttl_cap();
	natsStatus s;
	uint64_t nr = 0;

	/* probe once per connection epoch: detect AllowMsgTTL capability + latch
	 * the result.  The bucket is created with AllowMsgTTL natively via
	 * kvConfig.LimitMarkerTTL (nats_pool_get_kv), so this is now a read-only
	 * capability check -- no js_UpdateStream retrofit.  Skipped entirely when
	 * the operator switched the TTL path off (nats_native_ttl=0 [D6]). */
	if (nats_native_ttl && cap == TTL_CAP_UNPROBED) {
		int64_t mmps = 0;
		int r = nats_pool_kv_supports_ttl(bucket, &mmps);
		/* [HREV-1] the history rule: per-message TTL misbehaves on a
		 * history-keeping stream (late removal + revision rollback,
		 * verified on 2.11.10) -- refuse it there unless the operator
		 * explicitly opted in via nats_ttl_allow_history. */
		if (r == 1 && !_kv_ttl_history_ok(mmps, nats_ttl_allow_history)) {
			LM_WARN("cachedb_nats: bucket '%s' keeps %lld versions per key "
				"(MaxMsgsPerSubject=%lld); per-message TTL disabled -- "
				"expired keys would roll back to older revisions. The "
				"reaper remains authoritative; set kv_history=1 and "
				"recreate the bucket for on-time native expiry\n",
				bucket, (long long)mmps, (long long)mmps);
			r = 0;
		} else if (r == 1 && _kv_history_ttl_warn(mmps)) {
			LM_WARN("cachedb_nats: nats_ttl_allow_history=1 -- using "
				"per-message TTL on history-keeping bucket '%s' "
				"(MaxMsgsPerSubject=%lld): expiry may be late and older "
				"revisions can transiently resurface\n",
				bucket, (long long)mmps);
		}
		if (r >= 0) {                          /* r<0 transient: stay UNPROBED */
			cap = _ttl_cap_next(TTL_CAP_UNPROBED,
				r == 1 ? TTL_EV_SETUP_OK : TTL_EV_SETUP_FAIL);
			nats_pool_ttl_cap_set(cap);
		}
	}

	if (nats_native_ttl && cap == TTL_CAP_SUPPORTED) {
		int64_t ttl_ms = 0;
		enum ttl_outcome o;
		jsCtx *js = nats_pool_get_js();

		if (_ttl_eligible(row_exp, n_contacts, all_same))
			ttl_ms = _ttl_msgttl_ms(
				_ttl_seconds(row_exp, (int64_t)time(NULL), grace));

		/* got_entry = (rev != 0) [HREV-2]: rev==0 resolves to NO_MESSAGE and
		 * the TTL-carrying create; rev>0 means the caller read the row at
		 * `rev` (a live doc, or a seed re-built over an empty marker [R4]). */
		o = nats_kv_put_row(js, kv, bucket, key, json, json_len,
			rev != 0, json_len, rev, ttl_ms, out_rev);
		if (o == TTL_DONE)
			return 0;
		if (o == TTL_RETRY)
			return 1;
		if (o == TTL_LATCH_OFF)                /* 10166: latch off, fall back */
			nats_pool_ttl_cap_set(
				_ttl_cap_next(nats_pool_ttl_cap(), TTL_EV_SAW_10166));
		else
			return -1;                         /* FAIL_SAVE / ASSERT_BUG */
	}

	/* Legacy CAS write -- byte-for-byte the pre-P8 path; the ONLY allowed
	 * kvStore_UpdateString on the usrloc row path (gated on TTL unavailable).
	 * rev==0 (first insert [HREV-2]) creates instead; a lost create race is
	 * a retryable conflict exactly like a revision mismatch (mirrors the
	 * add/sub split in cachedb_nats_dbase.c). */
	if (rev == 0)
		s = nats_dl.kvStore_CreateString(&nr, kv, key, json);
	else
		s = nats_dl.kvStore_UpdateString(&nr, kv, key, json, rev);
	if (s == NATS_OK) {
		if (out_rev)
			*out_rev = nr;
		return 0;
	}
	if (!nats_cas_should_retry(s))
		return -1;
	return 1;
}
