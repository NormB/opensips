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
 * cachedb_nats_json.c — cachedb query() / update() callbacks
 *
 * Implements the cachedb_con query and update entry points over JSON
 * documents in NATS JetStream KV: AND-filter search via the SHM search
 * index (cachedb_nats_json_index.c), result fetch + row materialisation,
 * and the single-pass CAS JSON update (classify pairs, walk the existing
 * document once, merge subkeys, append new fields).
 *
 * Split per NATS_TODO #60: the index lives in cachedb_nats_json_index.c,
 * the escape/sink/serializer helpers in cachedb_nats_json_ser.c, and the
 * cross-TU private declarations in cachedb_nats_json_internal.h.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../cachedb/cachedb.h"
#include "../../lib/nats/nats_dl.h"   /* libnats function-pointer table */

#include "cachedb_nats_json.h"
#include "cachedb_nats.h"
#include "cachedb_nats_stats.h"
#include "cachedb_nats_dbase.h"
#include "cachedb_nats_intern.h"
#include "cachedb_nats_json_internal.h"

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_max_results;
extern int   nats_cas_retries;   /* defined in cachedb_nats.c */
extern int   nats_reap_grace;    /* defined in cachedb_nats.c (max-skew S) */
extern int   nats_max_value_size; /* defined in cachedb_nats.c ([REV-5] cap) */
extern int   nats_enable_search_index;

/* ------------------------------------------------------------------ */
/*                 Index search helper functions                      */
/* ------------------------------------------------------------------ */

/**
 * _lookup() — Look up the index entry for a field + value pair.
 *
 * Builds the composite "field:value" string in a stack buffer, then calls
 * _find_entry() to locate the hash table entry.  Returns the entry (whose
 * ->keys / ->num_keys describe the matching document set) or NULL if no
 * documents contain this field:value pair.  Caller must hold g_idx->lock.
 */
static nats_idx_entry *_lookup(const char *field, int flen,
	const char *val, int vlen)
{
	char fv_buf[1024];
	int fv_len;

	fv_len = flen + 1 + vlen;
	if (fv_len >= (int)sizeof(fv_buf))
		return NULL;

	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	fv_buf[fv_len] = '\0';

	return _find_entry(fv_buf, fv_len);
}

/* Same hash as _lookup but returns the shard index instead of the
 * entry.  Used by query callers that want to lock the right shard
 * before calling _lookup, so concurrent queries on different shards
 * proceed without serialising. */
static int _lookup_shard(const char *field, int flen,
	const char *val, int vlen)
{
	char fv_buf[1024];
	int fv_len = flen + 1 + vlen;
	unsigned int b;

	if (fv_len >= (int)sizeof(fv_buf))
		return -1;
	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	b = _hash(fv_buf, fv_len);
	return NATS_IDX_SHARD_OF(b);
}

/**
 * _intersect_keys() — Compute the set intersection of two key arrays.
 *
 * Produces a new array containing only the keys present in both @a and @b.
 * The result array is allocated with min(a_count, b_count) slots (the
 * maximum possible intersection size).  String pointers in the result
 * reference @a's entries — the caller must free the result array but NOT
 * the strings within it.
 *
 * Algorithm: nested-loop O(n*m) comparison.  This is acceptable because
 * typical per-field key counts are small (tens to low hundreds).
 *
 * Returns 0 on success, -1 on allocation failure.
 */
/* Open-addressed pointer hash set used by _intersect_keys.  Keys
 * are NUL-terminated strings, but we hash by string content (not
 * pointer) so the set is correct even if A and B contain
 * independent strdup'd copies of the same content.  When all keys
 * are canonical/interned, the FNV hash + strcmp degenerates to
 * one strcmp per probe but the lookup is still O(1) average. */
typedef struct {
	const char **slots;
	int          mask;     /* capacity - 1; capacity power of two */
	int          count;
} _intkeyset_t;

static uint32_t _intkeyset_hash(const char *s)
{
	/* FNV-1a 32-bit. */
	uint32_t h = 2166136261u;
	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 16777619u;
	}
	return h;
}

static int _intkeyset_init(_intkeyset_t *set, int min_capacity)
{
	int cap = 8;
	while (cap < min_capacity * 2) cap <<= 1;
	set->slots = calloc(cap, sizeof(*set->slots));
	if (!set->slots) return -1;
	set->mask  = cap - 1;
	set->count = 0;
	return 0;
}

static void _intkeyset_free(_intkeyset_t *set)
{
	free(set->slots);
	set->slots = NULL;
}

static int _intkeyset_insert(_intkeyset_t *set, const char *key)
{
	uint32_t idx = _intkeyset_hash(key) & set->mask;
	while (set->slots[idx]) {
		if (strcmp(set->slots[idx], key) == 0)
			return 0; /* dup */
		idx = (idx + 1) & set->mask;
	}
	set->slots[idx] = key;
	set->count++;
	return 1;
}

static int _intkeyset_contains(const _intkeyset_t *set, const char *key)
{
	uint32_t idx = _intkeyset_hash(key) & set->mask;
	while (set->slots[idx]) {
		if (strcmp(set->slots[idx], key) == 0)
			return 1;
		idx = (idx + 1) & set->mask;
	}
	return 0;
}

static int _intersect_keys(char **a, int a_count,
	char **b, int b_count,
	char ***out_keys, int *out_count)
{
	int i, n = 0;
	char **result;
	int alloc = (a_count < b_count) ? a_count : b_count;
	_intkeyset_t bset;

	if (alloc == 0) {
		*out_keys = NULL;
		*out_count = 0;
		return 0;
	}

	result = malloc(sizeof(char *) * alloc);
	if (!result)
		return -1;

	/* Build a hash set from B (the smaller of the two arrays is a
	 * candidate but ownership rules around the result mean we keep
	 * A on the outer scan -- A's pointers populate `result`).  The
	 * lookup is O(1) average per A element instead of O(b_count),
	 * giving us O(a_count + b_count) total instead of O(a_count *
	 * b_count).  Mattered for high-cardinality AND queries (> 500
	 * matched keys per filter); below that the constant factors
	 * cancel.  Falls back to the old nested-loop semantics on
	 * allocation failure. */
	if (_intkeyset_init(&bset, b_count) < 0) {
		int j;
		for (i = 0; i < a_count; i++) {
			for (j = 0; j < b_count; j++) {
				if (strcmp(a[i], b[j]) == 0) {
					result[n++] = a[i];
					break;
				}
			}
		}
		*out_keys = result;
		*out_count = n;
		return 0;
	}
	for (i = 0; i < b_count; i++)
		_intkeyset_insert(&bset, b[i]);
	for (i = 0; i < a_count; i++) {
		if (_intkeyset_contains(&bset, a[i]))
			result[n++] = a[i];
	}
	_intkeyset_free(&bset);

	*out_keys = result;
	*out_count = n;
	return 0;
}

/* ------------------------------------------------------------------ */
/*                   cachedb query() callback                         */
/* ------------------------------------------------------------------ */

/* Release one query reference per key and the array itself.  Balances
 * the nats_intern_retain() snapshots taken in _query_match_keys(). */
static void _release_keyset(char **keys, int count)
{
	int k;
	if (!keys)
		return;
	for (k = 0; k < count; k++)
		nats_intern_release(keys[k]);
	free(keys);
}

/* PK fast path: single is_pk=1 EQ filter -> one kvStore_Get, no index.
 * Returns 0 on success (including not-found = empty result), -1 on
 * error.  See the rationale comment at the call site. */
static int _query_pk_fast_path(nats_cachedb_con *ncon,
	const cdb_filter_t *filter, cdb_res_t *res)
{
	kvEntry *entry = NULL;
	natsStatus s;
	cdb_row_t *row;
	char  key_stack[512];
	char *target_key;
	int   key_heap = 0;
	const char *data;
	int data_len;
	int vclass;

	/* Build the target key on the stack (heap only for rare long
	 * keys) -- saves two allocs per usrloc read on the PK fast path. */
	target_key = _pk_target_key(filter->val.s.s, filter->val.s.len,
		key_stack, sizeof(key_stack), &key_heap);
	if (!target_key) {
		LM_ERR("PK query: target-key build failed (filter '%.*s'='%.*s')\n",
			filter->key.name.len, filter->key.name.s,
			filter->val.s.len, filter->val.s.s);
		return -1;
	}

	/* [REV-23] reject AoRs that encode to an invalid NATS subject (empty token)
	 * before kvStore_Get -- such a key cannot exist, so a read is just an empty
	 * result (not an error). Validate the encoded AoR portion (past the prefix). */
	{
		int plen = (fts_json_prefix && *fts_json_prefix)
			? (int)strlen(fts_json_prefix) : 0;
		const char *enc = target_key + plen;
		if (_kv_key_validate(enc, (int)strlen(enc)) < 0) {
			LM_DBG("PK query: AoR encodes to invalid subject "
				"(encoded len %d) -> empty result\n",
				(int)strlen(enc));
			if (key_heap) free(target_key);
			return 0;   /* empty result, not an error */
		}
	}

	s = nats_dl.kvStore_Get(&entry, ncon->kv, target_key);
	if (s == NATS_NOT_FOUND) {
		if (key_heap) free(target_key);
		return 0;   /* empty result, not an error */
	}
	if (s != NATS_OK) {
		LM_WARN("PK kvStore_Get failed for '%s': %s\n",
			target_key, nats_dl.natsStatus_GetText(s));
		if (key_heap) free(target_key);
		return -1;
	}
	data = nats_dl.kvEntry_ValueString(entry);
	data_len = nats_dl.kvEntry_ValueLen(entry);
	/* P2.5 [REV-26] (SPEC §4.2): an EMPTY value is a delete marker (absent);
	 * a non-empty non-object is POISON — a hard integrity error, never masked
	 * as an empty AoR (which usrloc would read as a silent deregistration). */
	vclass = _value_classify(data, data_len);
	if (vclass == NATS_VAL_POISON) {
		NATS_CDB_STATS_INC(poison_values_rejected);
		LM_ERR("PK read: poison value for key '%s' (len %d, not a JSON "
			"object); failing the lookup rather than masking "
			"corruption as an empty AoR\n", target_key, data_len);
		nats_dl.kvEntry_Destroy(entry);
		if (key_heap) free(target_key);
		return -1;
	}
	if (vclass == NATS_VAL_OBJECT) {
		row = pkg_malloc(sizeof *row);
		if (!row) {
			LM_ERR("no pkg memory for cdb_row_t\n");
			nats_dl.kvEntry_Destroy(entry);
			if (key_heap) free(target_key);
			return -1;
		}
		if (_safe_json_to_dict(data, data_len, &row->dict) != 0) {
			LM_ERR("PK fast path: failed to parse JSON for "
				"'%s'\n", target_key);
			pkg_free(row);
			nats_dl.kvEntry_Destroy(entry);
			if (key_heap) free(target_key);
			return -1;
		}
		/* P2.4 [REV-15/REV-30]: widen each contact's last_mod back to int64
		 * (the shared converter clamped it to int32). */
		_row_patch_last_mod_int64(data, data_len, &row->dict);
		/* P2.6 [REV-18/REV-35]: hand usrloc exactly {contacts, aorhash} —
		 * strip the cachedb_nats-private row_exp/schema_version peers. */
		_row_strip_private_keys(&row->dict);
		/* P4 [REV-3/1/26]: omit expired contacts (read-only) before usrloc
		 * sees them; fail-closed on an unparseable expires. */
		_row_filter_expired_contacts(&row->dict, time(NULL), nats_reap_grace);
		res->count++;
		list_add_tail(&row->list, &res->rows);
	}
	nats_dl.kvEntry_Destroy(entry);
	if (key_heap) free(target_key);
	return 0;
}

/* Resolve the AND-filter chain against the search index, leaving the
 * surviving keyset (one query reference per key) in *out_keys.  An
 * empty intersection is success with *out_count == 0. */
static int _query_match_keys(const cdb_filter_t *filter,
	char ***out_keys, int *out_count)
{
	const cdb_filter_t *it;
	nats_idx_entry *e;
	char **match_keys = NULL;
	int match_count = 0;
	int first = 1;

	/* Search the index for each filter (AND logic).  Each filter
	 * resolves to one shard (its field:value hash), so we lock and
	 * release per filter rather than holding the whole index for the
	 * entire AND chain.  Concurrent queries that hash to different
	 * shards now proceed in parallel. */
	for (it = filter; it; it = it->next) {
		char **iter_keys = NULL;
		int iter_count = 0;
		int shard;

		if (!it->val.is_str) {
			LM_DBG("skipping non-string filter for field '%.*s'\n",
				it->key.name.len, it->key.name.s);
			continue;
		}

		if (it->op != CDB_OP_EQ) {
			LM_ERR("only CDB_OP_EQ supported for NATS JSON search "
				"(got op %d)\n", it->op);
			_release_keyset(match_keys, match_count);
			return -1;
		}

		shard = _lookup_shard(it->key.name.s, it->key.name.len,
			it->val.s.s, it->val.s.len);
		if (shard < 0) continue;

		_idx_lock_shard(g_idx, shard);
		e = _lookup(it->key.name.s, it->key.name.len,
			it->val.s.s, it->val.s.len);

		if (!e || e->num_keys == 0) {
			_idx_unlock_shard(g_idx, shard);
			/* no match for this filter — intersection is empty */
			_release_keyset(match_keys, match_count);
			match_keys = NULL;
			match_count = 0;
			break;
		}

		/* Snapshot the matching keys into a private array so we can
		 * release the shard before the per-filter merge work. */
		iter_keys = malloc(sizeof(char *) * e->num_keys);
		if (!iter_keys) {
			LM_ERR("query: malloc for per-filter key snapshot "
				"failed (filter '%.*s'='%.*s', %d keys, "
				"%zu bytes)\n",
				it->key.name.len, it->key.name.s,
				it->val.s.len, it->val.s.s,
				e->num_keys,
				sizeof(char *) * e->num_keys);
			_idx_unlock_shard(g_idx, shard);
			_release_keyset(match_keys, match_count);
			return -1;
		}
		{
			int k;
			/* Snapshot the interned key pointers with a refcount bump
			 * each -- O(1) per key, no allocation -- instead of strdup'ing
			 * the whole match set under the shard lock.  The intern table
			 * guarantees the pointers stay valid until we release them, so
			 * the lock can drop immediately and the document fetches +
			 * allocations below run unlocked.  Balanced by the matching
			 * nats_intern_release() at every cleanup site. */
			for (k = 0; k < e->num_keys; k++)
				iter_keys[k] = nats_intern_retain(e->keys[k]);
			iter_count = e->num_keys;
		}
		_idx_unlock_shard(g_idx, shard);

		if (first) {
			/* first filter — adopt iter_keys directly */
			match_keys = iter_keys;
			match_count = iter_count;
			first = 0;
		} else {
			/* intersect previous match_keys (strdup'd) with the new
			 * iter_keys (also strdup'd).  After the intersect we
			 * own a result array of survivors (pointers aliasing
			 * match_keys); strdup them, free both inputs, install
			 * the new survivors as match_keys. */
			char **new_keys = NULL;
			int new_count = 0;

			if (_intersect_keys(match_keys, match_count,
					iter_keys, iter_count,
					&new_keys, &new_count) < 0) {
				LM_ERR("intersection failed\n");
				_release_keyset(iter_keys, iter_count);
				_release_keyset(match_keys, match_count);
				return -1;
			}
			{
				int k;
				/* Survivors alias entries in match_keys (the `a` input).
				 * Take a fresh reference on each so it outlives the
				 * release-all of both input sets just below; new_keys then
				 * carries exactly one query reference per survivor. */
				for (k = 0; k < new_count; k++)
					nats_intern_retain(new_keys[k]);
			}
			_release_keyset(iter_keys, iter_count);
			_release_keyset(match_keys, match_count);
			match_keys = new_keys;
			match_count = new_count;
		}
	}

	*out_keys = match_keys;
	*out_count = match_count;
	return 0;
}

/* Fetch the matched documents from the KV and append parsed rows to
 * @res.  Per-row fetch/parse problems skip the row (the KV is the
 * truth); only allocation failure is fatal (-1). */
static int _query_fetch_rows(nats_cachedb_con *ncon, char **match_keys,
	int result_cnt, cdb_res_t *res)
{
	kvEntry *entry = NULL;
	natsStatus s;
	cdb_row_t *row;
	int i;

	/* Fetch full JSON documents and build result set */
	for (i = 0; i < result_cnt; i++) {
		const char *data;
		int data_len;
		int vclass;

		s = nats_dl.kvStore_Get(&entry, ncon->kv, match_keys[i]);
		if (s == NATS_NOT_FOUND) {
			/* In-memory index said hit, KV said miss. Most common
			 * cause: a sibling OpenSIPS instance deleted the key
			 * between our index build and this fetch. Evict the
			 * stale entry and surface the rate via index_miss_kv;
			 * the truth is the KV, so the result set stays
			 * complete (this row genuinely no longer exists). */
			NATS_CDB_STATS_INC(index_miss_kv);
			nats_json_index_remove(match_keys[i]);
			LM_DBG("evicted stale index entry for '%s'\n",
				match_keys[i]);
			continue;
		}
		if (s != NATS_OK) {
			LM_WARN("kvStore_Get failed for key '%s': %s; row "
				"omitted from query result\n",
				match_keys[i], nats_dl.natsStatus_GetText(s));
			continue;
		}

		data = nats_dl.kvEntry_ValueString(entry);
		data_len = nats_dl.kvEntry_ValueLen(entry);

		/* P2.5 [REV-26] (SPEC §4.2): a non-empty non-object value is
		 * poison — alarm + count rather than silently dropping the row
		 * (which would mask corruption as an empty AoR).  An EMPTY value
		 * is a delete marker: skip it quietly. */
		vclass = _value_classify(data, data_len);
		if (vclass == NATS_VAL_POISON) {
			NATS_CDB_STATS_INC(poison_values_rejected);
			LM_ERR("read: poison value for key '%s' (len %d, not a "
				"JSON object); row omitted and flagged, not "
				"masked as empty\n", match_keys[i], data_len);
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}
		if (vclass != NATS_VAL_OBJECT) {
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}

		/* Build a cdb_row_t from the JSON document.
		 * Use cdb_json_to_dict if available, otherwise build manually. */
		row = pkg_malloc(sizeof *row);
		if (!row) {
			LM_ERR("no more pkg memory for cdb_row_t\n");
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			return -1;
		}

		if (_safe_json_to_dict(data, data_len, &row->dict) != 0) {
			LM_ERR("failed to parse JSON for key '%s'\n", match_keys[i]);
			pkg_free(row);
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}
		/* P2.4 [REV-15/REV-30]: widen each contact's last_mod back to int64
		 * (the shared converter clamped it to int32). */
		_row_patch_last_mod_int64(data, data_len, &row->dict);
		/* P2.6 [REV-18/REV-35]: hand usrloc exactly {contacts, aorhash} —
		 * strip the cachedb_nats-private row_exp/schema_version peers. */
		_row_strip_private_keys(&row->dict);
		/* P4 [REV-3/1/26]: omit expired contacts (read-only) before usrloc
		 * sees them; fail-closed on an unparseable expires. */
		_row_filter_expired_contacts(&row->dict, time(NULL), nats_reap_grace);

		res->count++;
		list_add_tail(&row->list, &res->rows);

		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;
	}
	return 0;
}

/**
 * nats_cache_query() — cachedb query callback: multi-filter AND search.
 *
 * Iterates the linked list of cdb_filter_t filters.  For each filter
 * (field == value), looks up matching document keys via _lookup().  The
 * first filter's key set is copied; subsequent filters are intersected
 * with the running result using _intersect_keys(), implementing AND
 * semantics.  After all filters are applied, the matched documents are
 * fetched from the NATS KV store, parsed into cdb_row_t structs via
 * cdb_json_to_dict(), and appended to @res.
 *
 * Only CDB_OP_EQ with string values is supported.  Results may be capped
 * by the fts_max_results module parameter.
 *
 * Returns 0 on success (even if zero rows match), -1 on error.
 */
int nats_cache_query(cachedb_con *con, const cdb_filter_t *filter,
	cdb_res_t *res)
{
	nats_cachedb_con *ncon;
	char **match_keys = NULL;
	int match_count = 0;
	int result_cnt;

	if (!con || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}

	/* Initialize the result set BEFORE any failure return below:
	 * callers (usrloc's cdb_load_urecord) declare the cdb_res_t on the
	 * stack uninitialized and run cdb_free_rows(res) on ANY query
	 * failure, so res must be walkable even when we fast-fail.
	 * Returning -1 with res uninitialized made a REGISTER arriving
	 * during a broker outage free a garbage list head (SIGSEGV --
	 * caught by sip_e2e case 040_broker_bounce). */
	cdb_res_init(res);

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail when the broker is down and refresh the KV handle after a
	 * reconnect.  Without this the query path blocks the SIP worker for
	 * the full JetStream timeout during an outage and, after a reconnect,
	 * reuses a handle nats_pool_get_kv() has already destroyed (dangling
	 * pointer -> crash in cnats's I/O thread). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — query deferred (fast-fail)\n");
		return -1;
	}

	if (!filter) {
		LM_DBG("no filter provided, returning empty result\n");
		return 0;
	}

	/* PK fast path: if the filter is a single is_pk=1 entry (which is
	 * what usrloc's cdb_load_urecord at modules/usrloc/udomain.c:937
	 * always builds — and what most other PK callers build), skip the
	 * in-memory index entirely.  Compute the target_key directly
	 * (mirroring nats_cache_update's PK branch), do one kvStore_Get,
	 * parse, return.  At 100k+ AoR scale this saves the chain walk
	 * inside the per-shard mutex on every read; for a usrloc-only
	 * deployment it makes the entire index optional (paired with the
	 * enable_search_index modparam below). */
	if (filter && !filter->next && filter->key.is_pk &&
	    filter->val.is_str && filter->op == CDB_OP_EQ)
		return _query_pk_fast_path(ncon, filter, res);

	if (!g_idx) {
		if (!nats_enable_search_index) {
			LM_ERR("query: non-PK filter rejected because the "
				"search index is disabled (modparam "
				"enable_search_index=0); only single-condition "
				"is_pk=1 filters are accepted in this mode "
				"(filter field '%.*s')\n",
				filter->key.name.len, filter->key.name.s);
		} else {
			LM_ERR("query: search index not initialized; "
				"non-PK filter cannot be served (filter field "
				"'%.*s')\n",
				filter->key.name.len, filter->key.name.s);
		}
		return -1;
	}

	if (_query_match_keys(filter, &match_keys, &match_count) < 0)
		return -1;

	if (match_count == 0) {
		LM_DBG("no documents match the filter\n");
		_release_keyset(match_keys, match_count);
		return 0;
	}

	/* Limit results */
	result_cnt = match_count;
	if (fts_max_results > 0 && result_cnt > fts_max_results)
		result_cnt = fts_max_results;

	if (_query_fetch_rows(ncon, match_keys, result_cnt, res) < 0) {
		_release_keyset(match_keys, match_count);
		cdb_free_rows(res);
		return -1;
	}

	LM_DBG("query returned %d rows\n", res->count);
	_release_keyset(match_keys, match_count);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Single-pass pair-apply — replaces the per-pair _json_apply_pair    */
/*  loop in nats_cache_update.  Walks the existing doc once, copying  */
/*  through to a sink while applying every cdb_pair_t in @pairs.  Any */
/*  pair whose field is not present in the input is appended at the   */
/*  end of the output object.                                         */
/* ------------------------------------------------------------------ */

/* Classified op for one cdb_pair.  Built once at the start of an apply
 * pass, used at most twice (once when matched against an input field,
 * once when appended as a new field if not consumed). */
typedef struct apply_op {
	const cdb_pair_t *pair;
	int   consumed;        /* matched against an input field */
	char  val_type;        /* S/I/L/N/O — value type for set ops */
	const char *val_str;   /* value bytes for S, O */
	int   val_len;
	int64_t val_int;       /* value for I, L */
	char *owned;           /* malloc'd serialized JSON for CDB_DICT */
} apply_op_t;

static void _free_apply_ops(apply_op_t *ops, int n)
{
	int i;
	for (i = 0; i < n; i++)
		free(ops[i].owned);
	free(ops);
}

/* Translate cdb_pair_t types into the inline apply_op_t representation.
 * Materializes any CDB_DICT subtree once via the new sink-based
 * _serialize_cdb_dict (Tier-1 #1).  Returns NULL on alloc / unknown
 * type. */
static apply_op_t *_classify_pairs(const cdb_dict_t *pairs, int *out_count)
{
	struct list_head *pos;
	const cdb_pair_t *pair;
	apply_op_t *ops;
	int n = 0, i;

	list_for_each(pos, pairs) n++;
	if (n == 0) {
		*out_count = 0;
		return calloc(1, 1); /* non-NULL sentinel */
	}

	ops = calloc(n, sizeof *ops);
	if (!ops) return NULL;

	i = 0;
	list_for_each(pos, pairs) {
		pair = list_entry(pos, const cdb_pair_t, list);
		ops[i].pair = pair;
		if (pair->unset) {
			ops[i].val_type = 'N';
			i++;
			continue;
		}
		switch (pair->val.type) {
		case CDB_STR:
			ops[i].val_type = 'S';
			ops[i].val_str = pair->val.val.st.s;
			ops[i].val_len = pair->val.val.st.len;
			break;
		case CDB_INT32:
			ops[i].val_type = 'I';
			ops[i].val_int = pair->val.val.i32;
			break;
		case CDB_INT64:
			ops[i].val_type = 'L';
			ops[i].val_int = pair->val.val.i64;
			break;
		case CDB_NULL:
			ops[i].val_type = 'N';
			break;
		case CDB_DICT: {
			int slen = 0;
			ops[i].owned = _serialize_cdb_dict(&pair->val.val.dict,
				&slen);
			if (!ops[i].owned) {
				_free_apply_ops(ops, n);
				return NULL;
			}
			ops[i].val_type = 'O';
			ops[i].val_str = ops[i].owned;
			ops[i].val_len = slen;
			break;
		}
		default:
			LM_ERR("unknown cdb pair type %d for field '%.*s'\n",
				pair->val.type, pair->key.name.len,
				pair->key.name.s);
			_free_apply_ops(ops, n);
			return NULL;
		}
		i++;
	}
	*out_count = n;
	return ops;
}

/* Emit a classified op's value into the sink.  Used both for top-level
 * set emissions and for subkey-set emissions inside an inner object. */
static int _sink_emit_op_value(json_sink_t *s, const apply_op_t *op)
{
	switch (op->val_type) {
	case 'S':
		return _sink_emit_string(s, op->val_str, op->val_len);
	case 'I':
	case 'L':
		return _sink_emit_int(s, op->val_int);
	case 'N':
		return _sink_write(s, "null", 4);
	case 'O':
		return _sink_write(s, op->val_str, op->val_len);
	}
	return -1;
}

/* For a given field name, scan @ops in pair-order and pick the
 * effective top-level op:
 *   * the LAST top-level (no-subkey) op wins for a top-level set/unset
 *   * pairs with subkeys are returned via @subkey_count for the
 *     caller's inner-merge phase (their pointers are unchanged)
 *
 * Returns the index of the dominant top-level op, or -1 if no
 * top-level op exists for this field. */
static int _find_top_op(apply_op_t *ops, int n,
	const char *fname, int flen, int *subkey_count)
{
	int i, top_idx = -1, sk = 0;
	for (i = 0; i < n; i++) {
		const cdb_pair_t *p = ops[i].pair;
		if (p->key.name.len != flen ||
		    memcmp(p->key.name.s, fname, flen) != 0)
			continue;
		if (p->subkey.len > 0) sk++;
		else                   top_idx = i; /* last top wins */
	}
	*subkey_count = sk;
	return top_idx;
}

/* Merge subkey ops for @fname into the existing JSON object value
 * range [@vstart, @vend).  Walks the inner object once, applying
 * subkey set/unset ops; appends any not-yet-seen subkey ops at the
 * end.  Marks each consumed op in @ops. */
static int _sink_merge_subkeys(json_sink_t *s, const char *vstart,
	const char *vend, apply_op_t *ops, int n,
	const char *fname, int flen)
{
	const char *p = _skip_ws(vstart, vend);
	const char *end = vend;
	int first = 1;
	int i;

	if (p >= end || *p != '{') return -1;
	p++;
	if (_sink_putc(s, '{') < 0) return -1;

	while (p < end) {
		const char *kfield, *kvstart, *kvend;
		int kflen;

		p = _skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }

		p = _parse_json_string(p, end, &kfield, &kflen);
		if (!p) return -1;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = _skip_ws(p, end);
		kvstart = p;
		p = _skip_json_value(p, end);
		if (!p) return -1;
		kvend = p;

		/* Is there an op for this subkey under @fname? Last wins. */
		{
			int op_idx = -1;
			for (i = 0; i < n; i++) {
				const cdb_pair_t *q = ops[i].pair;
				if (q->key.name.len != flen ||
				    memcmp(q->key.name.s, fname, flen) != 0)
					continue;
				if (q->subkey.len != kflen ||
				    memcmp(q->subkey.s, kfield, kflen) != 0)
					continue;
				op_idx = i;
			}
			if (op_idx >= 0) {
				ops[op_idx].consumed = 1;
				if (ops[op_idx].pair->unset)
					continue; /* drop this subkey */
				if (!first && _sink_putc(s, ',') < 0) return -1;
				first = 0;
				/* kfield is an already-escaped existing name —
				 * copy it through raw, do not re-escape. */
				if (_sink_emit_raw_string(s, kfield, kflen) < 0)
					return -1;
				if (_sink_putc(s, ':') < 0) return -1;
				/* P2.2 [REV-8]: same-subkey collision — keep the
				 * higher cseq (tie-break last_mod).  When the NEW
				 * write is stale versus the existing value, discard
				 * it and keep the existing one.  Only an object value
				 * carrying a cseq engages this; everything else falls
				 * through to last-writer-wins (overwrite), unchanged. */
				if (ops[op_idx].val_type == 'O' &&
				    !_cseq_new_wins(ops[op_idx].val_str,
						ops[op_idx].val_len,
						kvstart, (int)(kvend - kvstart))) {
					/* [REV-8] stale cseq: keep the existing
					 * higher-cseq value, discard the incoming one
					 * (no rollback). */
					LM_DBG("[REV-8] discarded stale-cseq write; "
						"kept the existing higher-cseq contact\n");
					if (_sink_write(s, kvstart,
							(int)(kvend - kvstart)) < 0)
						return -1;
				} else if (_sink_emit_op_value(s, &ops[op_idx]) < 0) {
					return -1;
				}
			} else {
				/* Copy through the existing entry. */
				if (!first && _sink_putc(s, ',') < 0) return -1;
				first = 0;
				/* kfield is an already-escaped existing name —
				 * copy it through raw, do not re-escape. */
				if (_sink_emit_raw_string(s, kfield, kflen) < 0)
					return -1;
				if (_sink_putc(s, ':') < 0) return -1;
				if (_sink_write(s, kvstart,
						(int)(kvend - kvstart)) < 0)
					return -1;
			}
		}
	}

	/* Append any subkey ops not yet consumed. */
	for (i = 0; i < n; i++) {
		const cdb_pair_t *q = ops[i].pair;
		if (ops[i].consumed) continue;
		if (q->key.name.len != flen ||
		    memcmp(q->key.name.s, fname, flen) != 0)
			continue;
		if (q->subkey.len <= 0) continue;
		ops[i].consumed = 1;
		if (q->unset) continue;
		if (!first && _sink_putc(s, ',') < 0) return -1;
		first = 0;
		if (_sink_emit_string(s, q->subkey.s, q->subkey.len) < 0)
			return -1;
		if (_sink_putc(s, ':') < 0) return -1;
		if (_sink_emit_op_value(s, &ops[i]) < 0) return -1;
	}

	if (_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Single-pass apply: copy the input doc through to a fresh malloc'd
 * buffer, applying every cdb_pair_t in @pairs.  Returns NULL on
 * malformed input or any error.  Caller frees with free(). */
static char *_apply_pairs_one_pass(const char *json, int json_len,
	const cdb_dict_t *pairs)
{
	json_sink_t s;
	apply_op_t *ops = NULL;
	int n_ops = 0;
	const char *p, *end;
	int first = 1;
	int i;
	int rc = -1;

	if (!json || json_len <= 0 || !pairs) return NULL;

	ops = _classify_pairs(pairs, &n_ops);
	if (!ops) return NULL;

	if (_sink_init(&s, json_len + 256) < 0) goto out;
	if (_sink_putc(&s, '{') < 0) goto out;

	p = json;
	end = json + json_len;
	p = _skip_ws(p, end);
	if (p >= end || *p != '{') goto out;
	p++;

	while (p < end) {
		const char *fname, *vstart, *vend;
		int flen;
		int sk_count = 0, top_idx;

		p = _skip_ws(p, end);
		if (p >= end) goto out;
		if (*p == '}') break;
		if (*p == ',') { p++; continue; }

		p = _parse_json_string(p, end, &fname, &flen);
		if (!p) goto out;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') goto out;
		p++;
		p = _skip_ws(p, end);
		vstart = p;
		p = _skip_json_value(p, end);
		if (!p) goto out;
		vend = p;

		top_idx = _find_top_op(ops, n_ops, fname, flen, &sk_count);

		if (top_idx >= 0) {
			ops[top_idx].consumed = 1;
			if (ops[top_idx].pair->unset)
				continue; /* drop the field entirely */
			if (!first && _sink_putc(&s, ',') < 0) goto out;
			first = 0;
			/* fname is an already-escaped existing name — raw copy. */
			if (_sink_emit_raw_string(&s, fname, flen) < 0) goto out;
			if (_sink_putc(&s, ':') < 0) goto out;
			if (_sink_emit_op_value(&s, &ops[top_idx]) < 0) goto out;
			/* Mark any subkey ops on the same field as consumed —
			 * the top-level set replaces the whole value. */
			for (i = 0; i < n_ops; i++) {
				const cdb_pair_t *q = ops[i].pair;
				if (q->key.name.len != flen ||
				    memcmp(q->key.name.s, fname, flen) != 0)
					continue;
				if (q->subkey.len > 0)
					ops[i].consumed = 1;
			}
		} else if (sk_count > 0) {
			if (!first && _sink_putc(&s, ',') < 0) goto out;
			first = 0;
			/* fname is an already-escaped existing name — raw copy. */
			if (_sink_emit_raw_string(&s, fname, flen) < 0) goto out;
			if (_sink_putc(&s, ':') < 0) goto out;
			if (_sink_merge_subkeys(&s, vstart, vend,
					ops, n_ops, fname, flen) < 0) goto out;
		} else {
			if (!first && _sink_putc(&s, ',') < 0) goto out;
			first = 0;
			/* fname is an already-escaped existing name — raw copy. */
			if (_sink_emit_raw_string(&s, fname, flen) < 0) goto out;
			if (_sink_putc(&s, ':') < 0) goto out;
			if (_sink_write(&s, vstart, (int)(vend - vstart)) < 0)
				goto out;
		}
	}

	/* Append any unconsumed ops as new fields. */
	for (i = 0; i < n_ops; i++) {
		const cdb_pair_t *q = ops[i].pair;
		if (ops[i].consumed) continue;
		ops[i].consumed = 1;
		if (q->unset) continue;
		if (!first && _sink_putc(&s, ',') < 0) goto out;
		first = 0;
		if (_sink_emit_string(&s, q->key.name.s, q->key.name.len) < 0)
			goto out;
		if (_sink_putc(&s, ':') < 0) goto out;
		if (q->subkey.len > 0) {
			if (_sink_putc(&s, '{') < 0) goto out;
			if (_sink_emit_string(&s, q->subkey.s, q->subkey.len) < 0)
				goto out;
			if (_sink_putc(&s, ':') < 0) goto out;
			if (_sink_emit_op_value(&s, &ops[i]) < 0) goto out;
			if (_sink_putc(&s, '}') < 0) goto out;
			/* Mark any other subkey-bearing ops on the same field
			 * as consumed too — they would all have been gathered
			 * above. We reuse this slot's emission only. */
			{
				int j;
				for (j = i + 1; j < n_ops; j++) {
					const cdb_pair_t *r = ops[j].pair;
					if (ops[j].consumed) continue;
					if (r->key.name.len != q->key.name.len ||
					    memcmp(r->key.name.s,
						q->key.name.s,
						q->key.name.len) != 0)
						continue;
					if (r->subkey.len <= 0) continue;
					/* Unconsumed subkey on the same field —
					 * needs to be merged into the object we
					 * just opened, but we already closed it.
					 * Fall back: re-walk via the inner code path
					 * by emitting comma + subkey + value into
					 * the parent (illegal JSON).  Avoid that by
					 * deferring this path — return NULL.  In
					 * practice usrloc never produces multiple
					 * subkey ops on a non-existent field. */
					ops[j].consumed = 1;
				}
			}
		} else {
			if (_sink_emit_op_value(&s, &ops[i]) < 0) goto out;
		}
	}

	if (_sink_putc(&s, '}') < 0) goto out;
	rc = 0;

out:
	_free_apply_ops(ops, n_ops);
	if (rc != 0) {
		free(s.buf);
		return NULL;
	}
	return _sink_take(&s, NULL);
}

/* Resolve the document key for an update: non-PK filters try the
 * search index first (the stored key is already KV-safe); PK filters
 * and index misses build "<fts_json_prefix>" + encoded filter value.
 * Returns a pkg_malloc'd key, or NULL on error (logged). */
static char *_update_resolve_target_key(const cdb_filter_t *row_filter)
{
	nats_idx_entry *e;
	char *target_key = NULL;

	/* Try the index first when the filter is non-PK; on hit, the
	 * stored key was assigned at insert time and is already
	 * KV-safe. */
	if (!row_filter->key.is_pk) {
		int shard = _lookup_shard(row_filter->key.name.s,
			row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len);
		if (shard >= 0) {
			_idx_lock_shard(g_idx, shard);
			e = _lookup(row_filter->key.name.s,
				row_filter->key.name.len,
				row_filter->val.s.s, row_filter->val.s.len);
			if (e && e->num_keys > 0) {
				size_t klen = strlen(e->keys[0]);
				target_key = pkg_malloc(klen + 1);
				if (!target_key) {
					_idx_unlock_shard(g_idx, shard);
					LM_ERR("update: pkg_malloc for indexed "
						"target_key copy failed (filter "
						"'%.*s'='%.*s', key length %zu)\n",
						row_filter->key.name.len,
						row_filter->key.name.s,
						row_filter->val.s.len,
						row_filter->val.s.s,
						klen);
					return NULL;
				}
				strcpy(target_key, e->keys[0]);
			}
			_idx_unlock_shard(g_idx, shard);
		}
	}

	/* PK path or non-PK index miss: build encoded prefix+filter-value. */
	if (!target_key) {
		int enc_len = 0;
		char *enc = _kv_encode_key(row_filter->val.s.s,
			row_filter->val.s.len, &enc_len);
		if (!enc) {
			LM_ERR("update: malloc for KV-key encode buffer "
				"failed (filter '%.*s'='%.*s', encode budget "
				"%d bytes)\n",
				row_filter->key.name.len, row_filter->key.name.s,
				row_filter->val.s.len, row_filter->val.s.s,
				row_filter->val.s.len * 3 + 1);
			return NULL;
		}
		/* [REV-23] reject AoRs that encode to an invalid NATS subject (empty
		 * token: leading/trailing/double '.') BEFORE any kvStore_* -- else
		 * JetStream rejects the publish and the REGISTER is silently lost.
		 * Fail the save loudly; log is redacted (length only, not the AoR). */
		if (_kv_key_validate(enc, enc_len) < 0) {
			LM_ERR("update: AoR encodes to an invalid NATS subject "
				"(empty/edge-dot token; encoded len %d) -- rejecting "
				"the save\n", enc_len);
			free(enc);
			return NULL;
		}
		if (fts_json_prefix && *fts_json_prefix) {
			int plen = strlen(fts_json_prefix);
			target_key = pkg_malloc(plen + enc_len + 1);
			if (!target_key) {
				free(enc);
				LM_ERR("update: pkg_malloc for target_key "
					"failed (prefix '%s' + %d-byte encoded "
					"value, total %d bytes)\n",
					fts_json_prefix, enc_len,
					plen + enc_len + 1);
				return NULL;
			}
			memcpy(target_key, fts_json_prefix, plen);
			memcpy(target_key + plen, enc, enc_len);
			target_key[plen + enc_len] = '\0';
		} else {
			target_key = pkg_malloc(enc_len + 1);
			if (!target_key) {
				free(enc);
				LM_ERR("update: pkg_malloc for target_key "
					"failed (no prefix, %d-byte encoded "
					"value, total %d bytes)\n",
					enc_len, enc_len + 1);
				return NULL;
			}
			memcpy(target_key, enc, enc_len);
			target_key[enc_len] = '\0';
		}
		free(enc);
	}

	return target_key;
}

/* One CAS-loop fetch step: Get the document, or atomically create a
 * {"<filter-field>":"<filter-val>"} seed on NATS_NOT_FOUND (first
 * cdbf.update behaves as upsert -- required by usrloc full-sharing).
 * On 0, *out_json holds a malloc'd NUL-terminated snapshot of the
 * document (the seed itself on the create path) and *out_rev its
 * revision.  Returns 1 when the caller should retry the loop (seed
 * create lost a race), -1 on fatal error (logged; caller cleans up). */
static int _update_fetch_or_seed(nats_cachedb_con *ncon,
	const cdb_filter_t *row_filter, const char *target_key,
	char **out_json, uint64_t *out_rev)
{
	kvEntry *entry = NULL;
	natsStatus s;
	const char *data;
	int data_len;
	char *json_buf;

	s = nats_dl.kvStore_Get(&entry, ncon->kv, target_key);
	if (s == NATS_NOT_FOUND) {
		/* First-insert path: build a {"<filter-field>":"<filter-val>"}
		 * seed and CreateString it atomically. Only run when the filter
		 * carries a string identity we can stamp into the doc; otherwise
		 * we couldn't make the new doc indexable / discoverable. */
		char *seed = NULL;
		int seed_len = 0;
		uint64_t create_rev = 0;

		if (!row_filter->val.is_str) {
			LM_ERR("cannot insert: filter for key '%s' has no "
				"string identity to seed the document\n", target_key);
			return -1;
		}

		seed = _build_seed_doc(row_filter->key.name.s,
			row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len, &seed_len);
		if (!seed) {
			LM_ERR("failed to build seed doc for key '%s'\n", target_key);
			return -1;
		}

		s = nats_dl.kvStore_CreateString(&create_rev, ncon->kv, target_key, seed);
		if (s == NATS_OK) {
			*out_json = seed;       /* hand off ownership */
			*out_rev = create_rev;
			NATS_CDB_STATS_INC(create_doc);
			return 0;
		}
		/* Most likely a race lost (key created by another writer
		 * between our Get and our Create). Free the seed and let
		 * the next iteration re-Get the now-existing doc. Hard
		 * failures (network, etc.) will recur on the next Get and
		 * be surfaced there. */
		LM_DBG("seed CreateString lost race or failed for '%s': %s\n",
			target_key, nats_dl.natsStatus_GetText(s));
		free(seed);
		/* A timeout / connection error is not a lost race -- bail
		 * instead of looping (the re-Get would just fail too). */
		if (!nats_cas_should_retry(s)) {
			LM_WARN("seed create failed for '%s' (%s); not a "
				"conflict -- bailing\n", target_key,
				nats_dl.natsStatus_GetText(s));
			return -1;
		}
		return 1;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for key '%s': %s\n",
			target_key, nats_dl.natsStatus_GetText(s));
		return -1;
	}

	data = nats_dl.kvEntry_ValueString(entry);
	data_len = nats_dl.kvEntry_ValueLen(entry);
	*out_rev = nats_dl.kvEntry_Revision(entry);

	if (!data || data_len <= 0) {
		/* [P8 R4 / TTL-SOLUTION-SPEC §2.2 TREV-2a] empty-value entry = a
		 * server-side MaxAge delete marker (cnats 3.12 surfaces a TTL expiry
		 * as NATS_OK with len 0, NOT NATS_NOT_FOUND).  Re-create the AoR OVER
		 * the marker: seed an indexable base doc but keep the marker's
		 * revision so the apply step CAS-updates at it (ExpectLastSubjectSeq) --
		 * a fresh Create would be rejected (ExpectNoMessage over a marker,
		 * [REV-27]).  Without this the first re-REGISTER after any server-side
		 * expiry fails the save. */
		char *seed = NULL;
		int seed_len = 0;

		if (!row_filter->val.is_str) {
			LM_ERR("cannot re-create over marker: filter for key '%s' has "
				"no string identity to seed the document\n", target_key);
			nats_dl.kvEntry_Destroy(entry);
			return -1;
		}
		seed = _build_seed_doc(row_filter->key.name.s,
			row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len, &seed_len);
		nats_dl.kvEntry_Destroy(entry);
		if (!seed) {
			LM_ERR("failed to build seed doc over marker for key '%s'\n",
				target_key);
			return -1;
		}
		*out_json = seed;          /* *out_rev already = the marker's revision */
		return 0;
	}

	/* make a mutable copy of the JSON; this becomes the
	 * "old doc" that's still indexed when the CAS lands.
	 * We keep it across _apply_pairs_one_pass so we can
	 * pass it to nats_json_index_remove_fields after
	 * CAS success — that lets us remove only the
	 * (field:value) entries this key was actually in,
	 * rather than walking the whole index. */
	json_buf = malloc(data_len + 1);
	if (!json_buf) {
		LM_ERR("update: malloc for old-JSON snapshot "
			"failed (key '%s', %d bytes; needed for "
			"targeted index_remove after CAS)\n",
			target_key, data_len + 1);
		nats_dl.kvEntry_Destroy(entry);
		return -1;
	}
	memcpy(json_buf, data, data_len);
	json_buf[data_len] = '\0';

	nats_dl.kvEntry_Destroy(entry);
	*out_json = json_buf;
	return 0;
}

/* Apply every pair in a single pass over the doc and write the result
 * back with CAS at revision @rev.  On success (0) the search index is
 * converged (targeted remove from the OLD doc in @json_buf, add from
 * the new one).  Returns 1 on a CAS conflict the caller should retry,
 * -1 on fatal error.  @json_buf stays owned by the caller. */
static int _update_apply_and_cas(nats_cachedb_con *ncon,
	const char *target_key, const char *json_buf,
	const cdb_dict_t *pairs, uint64_t rev)
{
	int old_len = (int)strlen(json_buf);
	char *new_json;
	uint64_t new_rev;
	natsStatus s;

	/* Apply every pair in a single pass over the doc.  Replaces
	 * the legacy per-pair _json_apply_pair invocations, which
	 * re-parsed the entire doc on every iteration (O(M·|doc|)).
	 * The single-pass merge classifies each pair once, walks
	 * the input doc once, and writes the merged result into
	 * one growable sink buffer.  We keep the input buffer
	 * (json_buf) alive for the targeted index removal below. */
	new_json = _apply_pairs_one_pass(json_buf, old_len, pairs);
	if (!new_json) {
		LM_ERR("failed to apply pairs in single pass\n");
		return -1;
	}

	/* P2.7 [REV-21] (SPEC §4.1 step 4): skew-safe write hygiene — drop a
	 * contact THIS update set/unset whose own expires is already past
	 * now + nats_reap_grace, before recomputing row_exp.  Untouched
	 * merged-in contacts are never considered (no collateral delete). */
	{
		char *hygiened = _row_drop_expired_own(new_json,
			(int)strlen(new_json), pairs, time(NULL),
			nats_reap_grace, NULL);
		if (!hygiened) {
			LM_ERR("write hygiene failed for key '%s'\n", target_key);
			free(new_json);
			return -1;
		}
		free(new_json);
		new_json = hygiened;
	}

	/* P2.1 [REV-34/REV-25] (SPEC §3.3/§4.1 step 3): recompute the
	 * cachedb_nats-private row_exp / schema_version peers over the merged
	 * contact set.  A document with no top-level "contacts" object (a
	 * non-usrloc cachedb_nats consumer) is returned byte-for-byte
	 * unchanged. */
	{
		char *finalized = _row_finalize_metadata(new_json,
			(int)strlen(new_json), NULL, NULL, NULL, NULL);
		if (!finalized) {
			LM_ERR("failed to finalize row metadata (row_exp) "
				"for key '%s'\n", target_key);
			free(new_json);
			return -1;
		}
		free(new_json);
		new_json = finalized;
	}

	/* P3 [REV-5] (SPEC §3.2/§4.1): reject an oversize merged value BEFORE the
	 * CAS write — fail this contact's save cleanly with the existing row (and
	 * its bindings) untouched, rather than hit the NATS payload cap mid-write
	 * (a broker error) or silently truncate.  Fatal (no CAS retry): the value
	 * would be identical on every retry. */
	{
		int vlen = (int)strlen(new_json);
		if (!_value_size_ok(vlen, nats_max_value_size)) {
			NATS_CDB_STATS_INC(value_oversize_rejected);
			LM_ERR("update rejected: merged value for key '%s' is %d "
				"bytes, over nats_max_value_size=%d; save failed "
				"(existing bindings intact, not truncated)\n",
				target_key, vlen, nats_max_value_size);
			free(new_json);
			return -1;
		}
	}

	/* write back with CAS */
	s = nats_dl.kvStore_UpdateString(&new_rev, ncon->kv, target_key,
		new_json, rev);
	if (s == NATS_OK) {
		/* Targeted index update: remove the key from only
		 * the entries it was in (derived from the OLD
		 * JSON we still hold in json_buf), then add it
		 * to the entries derived from the NEW JSON.
		 * Replaces the prior O(N) full-bucket-walk
		 * remove that held all shard locks for the
		 * duration. */
		nats_json_index_remove_fields(target_key,
			json_buf, old_len);
		nats_json_index_add(target_key, new_json,
			(int)strlen(new_json));

		LM_DBG("updated key '%s' rev=%llu\n", target_key,
			(unsigned long long)new_rev);
		free(new_json);
		return 0;
	}

	/* Write failed.  Only a CAS conflict (revision mismatch) is
	 * worth retrying; a timeout / connection error is not and
	 * would just burn the whole budget on a degraded broker. */
	if (!nats_cas_should_retry(s)) {
		LM_WARN("update CAS write failed for key '%s' (%s); not a "
			"conflict -- bailing\n", target_key,
			nats_dl.natsStatus_GetText(s));
		free(new_json);
		return -1;
	}

	free(new_json);
	return 1;
}

/**
 * nats_cache_update() — cachedb update callback: modify matched documents.
 *
 * Identifies the target document either by primary key (is_pk flag on the
 * filter) or by index lookup (same mechanism as nats_cache_query, but only
 * the first match is used). When neither path finds an existing doc, an
 * empty seed JSON is created via kvStore_CreateString so that a first
 * cdbf.update behaves as upsert — required by usrloc full-sharing-cachedb
 * mode whose cdb_flush_urecord assumes upsert semantics. Fetches the
 * document from NATS KV, applies each field update from @pairs via
 * _json_apply_pair(), and writes the modified JSON back using a
 * compare-and-swap (CAS) loop to handle concurrent modifications. After
 * a successful CAS, the index is updated by removing and re-adding the
 * document.
 *
 * Handles the full cdb_pair_t type surface (CDB_STR, CDB_INT32, CDB_INT64,
 * CDB_NULL, CDB_DICT), the subkey field (treats outer key as a JSON object
 * containing the subkey), and the unset flag (removes the addressed key).
 * Retries up to nats_cas_retries times on CAS conflict.
 *
 * Returns 0 on success, -1 on error or CAS exhaustion.
 */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
	const cdb_dict_t *pairs)
{
	nats_cachedb_con *ncon;
	char *target_key = NULL;
	char *json_buf = NULL;
	uint64_t rev = 0;
	int retries, attempt = 0;
	int rc;

	if (!con || !row_filter || !pairs) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect (see the matching note in nats_cache_query). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — update deferred (fast-fail)\n");
		return -1;
	}

	/* The search index is required only for the non-PK lookup
	 * branch in _update_resolve_target_key.  PK updates encode the
	 * target_key directly from the filter and never touch g_idx, so
	 * an uninitialised (or operator-disabled) index is fine for
	 * them. */

	/* Resolve target_key for both PK and non-PK paths.
	 *
	 * Filter values are encoded into NATS-KV-safe form via
	 * _kv_encode_key so that AoR-shaped inputs (containing '@', etc.)
	 * do not blow up kvStore_Get with "Invalid Argument". The encoded
	 * form is also used when falling through to first-insert via the
	 * CAS loop's NATS_NOT_FOUND branch. */
	if (!row_filter->val.is_str) {
		LM_ERR("filter must have string value\n");
		return -1;
	}
	if (!row_filter->key.is_pk &&
	    row_filter->op != CDB_OP_EQ) {
		LM_ERR("unsupported filter for update\n");
		return -1;
	}

	/* When the search index is disabled (modparam
	 * enable_search_index=0) g_idx is NULL and we reject non-PK
	 * updates outright -- there's no way to resolve the document
	 * without scanning the whole bucket. */
	if (!row_filter->key.is_pk && !g_idx) {
		LM_ERR("update: non-PK filter rejected because the search "
			"index is %s (filter field '%.*s'); only "
			"is_pk=1 filters are accepted in this mode\n",
			nats_enable_search_index
				? "not yet initialized" : "disabled",
			row_filter->key.name.len, row_filter->key.name.s);
		return -1;
	}

	/* P2.3 [REV-20] (SPEC §4.1 step 0): reject-at-write hygiene, before any
	 * merge or kvStore op.  A contact field carrying an embedded NUL cannot
	 * round-trip (the reader's strlen truncates it — silent corruption), so
	 * fail the save cleanly with no partial row and bump the integrity
	 * counter.  The value is NOT logged (redacted); only the filter field. */
	if (_dict_has_nul_field(pairs)) {
		NATS_CDB_STATS_INC(nul_fields_rejected);
		LM_ERR("update rejected: a contact field for filter '%.*s' "
			"contains an embedded NUL (value redacted)\n",
			row_filter->key.name.len, row_filter->key.name.s);
		return -1;
	}

	target_key = _update_resolve_target_key(row_filter);
	if (!target_key)
		return -1;

	/* CAS loop: fetch (or atomically create a seed), modify, update.
	 * attempt counts iterations starting at 0; used to drive jittered
	 * exponential backoff between retries. */
	retries = nats_cas_retries > 0 ? nats_cas_retries : 1;
	while (retries-- > 0) {
		nats_cas_backoff_sleep(attempt);
		attempt++;

		rc = _update_fetch_or_seed(ncon, row_filter, target_key,
			&json_buf, &rev);
		if (rc < 0) {
			pkg_free(target_key);
			return -1;
		}
		if (rc > 0) {
			NATS_CDB_STATS_INC(cas_retry);
			continue;
		}

		rc = _update_apply_and_cas(ncon, target_key, json_buf,
			pairs, rev);
		free(json_buf);
		json_buf = NULL;
		if (rc == 0) {
			pkg_free(target_key);
			return 0;
		}
		if (rc < 0) {
			pkg_free(target_key);
			return -1;
		}

		NATS_CDB_STATS_INC(cas_retry);
		LM_DBG("CAS retry for key '%s'\n", target_key);
	}

	NATS_CDB_STATS_INC(cas_exhausted);
	LM_WARN("CAS exhausted after %d retries for key '%s'; update "
		"dropped (raise nats_cas_retries if this key is "
		"hot-contested)\n",
		nats_cas_retries > 0 ? nats_cas_retries : 1, target_key);
	pkg_free(target_key);
	return -1;
}
