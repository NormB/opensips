/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Implementation of the SHM string intern table -- see header
 * for the rationale.  ~half of all opensips CPU at 100k AoRs
 * was sem_wait -> hp_shm_malloc on the watcher's _entry_add_key
 * path; this module collapses those allocations into a single
 * intern-or-acquire per unique doc key, with refcounted release.
 */

/*
 * fts_query.c — the non-PK filter walk over the FTS index (moved out of
 * cachedb_nats_json.c in the P1.2 module split).  Produces a retained
 * key snapshot for cachedb_nats's row fetcher.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../cachedb/cachedb.h"

#include "fts_index.h"
#include "fts_intern.h"
#include "../cachedb_nats/cachedb_nats_json_internal.h"  /* g_idx, _find_entry, shard locks */

extern int fts_max_results;   /* modparam (cachedb_nats_fts.c) */

/* ------------------------------------------------------------------ */
/*                 Index search helper functions                      */
/* ------------------------------------------------------------------ */

/**
 * _lookup() — Look up the index entry for a field + value pair.
 *
 * Builds the composite "field:value" string in a stack buffer, then calls
 * _find_entry() to locate the hash table entry.  Returns the entry (whose
 * ->keys / ->num_keys describe the matching document set) or NULL if no
 * documents contain this field:value pair.  Caller must hold the entry's
 * shard lock.
 */
static nats_idx_entry *_lookup(const char *field, int flen,
	const char *val, int vlen)
{
	char fv_buf[1024];
	int fv_len;

	/* Guard negative lengths before the size math: a negative flen/vlen
	 * could keep fv_len under the ceiling below yet sign-extend to a huge
	 * size_t in memcpy (OOB).  Mirrors the other fv-builders. */
	if (flen < 0 || vlen < 0)
		return NULL;

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
	int fv_len;
	unsigned int b;

	if (flen < 0 || vlen < 0)
		return -1;
	fv_len = flen + 1 + vlen;
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
void _release_keyset(char **keys, int count)
{
	int k;
	if (!keys)
		return;
	for (k = 0; k < count; k++)
		nats_intern_release(keys[k]);
	free(keys);
}


/* Resolve the AND-filter chain against the search index, leaving the
 * surviving keyset (one query reference per key) in *out_keys.  An
 * empty intersection is success with *out_count == 0. */
int _query_match_keys(const cdb_filter_t *filter,
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

	/* Cap the result set (fts_max_results modparam): release the
	 * excess retained keys before handing the snapshot over. */
	if (fts_max_results > 0 && match_count > fts_max_results) {
		int k;
		for (k = fts_max_results; k < match_count; k++)
			nats_intern_release(match_keys[k]);
		match_count = fts_max_results;
	}

	*out_keys = match_keys;
	*out_count = match_count;
	return 0;
}



/* single-key resolve for cachedb_nats's update(): first indexed doc key
 * matching field=val.  1 = hit (out filled), 0 = miss, -1 = overflow. */
int _fts_resolve_key(const str *field, const str *val, char *out, int out_len)
{
	nats_idx_entry *e;
	int rc = 0;
	int shard = _lookup_shard(field->s, field->len, val->s, val->len);

	if (shard < 0 || !g_idx)
		return 0;
	_idx_lock_shard(g_idx, shard);
	e = _lookup(field->s, field->len, val->s, val->len);
	if (e && e->num_keys > 0) {
		size_t klen = strlen(e->keys[0]);
		if ((int)klen + 1 > out_len) {
			rc = -1;
		} else {
			memcpy(out, e->keys[0], klen + 1);
			rc = 1;
		}
	}
	_idx_unlock_shard(g_idx, shard);
	return rc;
}
