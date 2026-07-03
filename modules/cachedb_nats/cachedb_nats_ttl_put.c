/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * nats_kv_put_row() / nats_kv_write_row_cas() -- the single helper pair
 * through which EVERY usrloc-row write goes (the §2.0 invariant).  A thin,
 * single-shot CAS publish: all re-read/re-merge/backoff stays in the
 * callers' existing CAS loops.  The pure decisions it composes
 * (_ttl_cas_predicate, _ttl_classify) are unit-tested in
 * cachedb_nats_ttl.c; this file is the glue.
 *
 * The native per-message-TTL arms (Nats-TTL re-assertion, the capability
 * latch/probe, the TTL-carrying create and the legacy kvStore_UpdateString
 * fallback) were deleted in P1.5: the reaper is the single expiry
 * authority.  The js_PublishMsg CAS path is kept because it returns the
 * numeric jsErrCode inline, which _ttl_classify needs to distinguish a
 * genuine revision conflict (10071 -> RETRY) from a generic/transient
 * failure (FAIL_SAVE) -- the kvStore_* helpers expose only error text.
 */
#include <stdint.h>
#include <string.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../lib/nats/nats_dl.h"
#include "../../lib/nats/nats_pool.h"   /* nats_pool_get_js */
#include "cachedb_nats_ttl.h"

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
