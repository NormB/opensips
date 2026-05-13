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
 * cachedb_nats_json.c — Process-local JSON full-text search index
 *
 * This file implements an in-process search index for JSON documents stored
 * in NATS JetStream KV buckets.  Documents are parsed and indexed by their
 * top-level field:value pairs so that cachedb query() and update() operations
 * can locate documents without scanning the entire KV store.
 *
 * Index structure:
 *   - Hash table with `nats_idx_buckets` buckets (runtime-tunable
 *     via the `index_buckets` modparam, default 4096) and separate
 *     chaining.
 *   - Each entry maps a "field:value" string to a dynamic array of document
 *     keys that contain that pair.
 *
 * Thread safety:
 *   - A pthread mutex (g_idx->lock) protects every read and write to the
 *     index.  The mutex is acquired in the public API functions and must also
 *     be held by callers of the internal _find_entry / _get_or_create_entry
 *     helpers.
 *
 * Usage:
 *   - nats_json_index_init()   — allocate the global index (once per process)
 *   - nats_json_index_build()  — bulk-load from NATS KV
 *   - nats_cache_query()       — cachedb query callback (AND-filter search)
 *   - nats_cache_update()      — cachedb update callback (CAS JSON update)
 *   - nats_json_index_destroy()— teardown
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

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_max_results;
extern int   nats_cas_retries;   /* defined in cachedb_nats.c */
extern int   nats_enable_search_index;

/* Forward declarations for helpers that callers earlier in the file
 * need to reach.  Definitions live further down for locality with
 * the related JSON-handling code. */
static char *_kv_encode_key(const char *in, int in_len, int *out_len);

/* ------------------------------------------------------------------ */
/*                       Global search index                          */
/* ------------------------------------------------------------------ */

static nats_search_idx *g_idx = NULL;

/**
 * nats_json_get_index() — Return the global search index pointer.
 *
 * Other modules (e.g. MI commands, watchers) use this to inspect index
 * state such as document counts.  Returns NULL if the index has not been
 * initialised yet.
 */
nats_search_idx *nats_json_get_index(void)
{
	return g_idx;
}

/* ------------------------------------------------------------------ */
/*                       djb2 hash function                           */
/* ------------------------------------------------------------------ */

/* Runtime bucket count (set by nats_json_index_init from the
 * `index_buckets` modparam).  Default keeps current behaviour for
 * callers that don't override it. */
int nats_idx_buckets = NATS_IDX_DEFAULT_BUCKETS;
int nats_idx_bucket_mask = NATS_IDX_DEFAULT_BUCKETS - 1;

/**
 * _hash() — Compute a bucket index using the djb2 hash algorithm.
 *
 * Takes a byte string of length @len and produces a value in
 * [0, nats_idx_buckets).  djb2 is a fast, well-distributed hash suitable
 * for short strings such as "field:value" index keys.  The magic constant
 * 5381 and the shift-add recurrence (h * 33 + c) are from Dan Bernstein's
 * original comp.lang.c posting.  The bucket count is forced to a power
 * of two at init, so `& nats_idx_bucket_mask` replaces the modulo.
 */
static unsigned int _hash(const char *s, int len)
{
	unsigned int h = 5381;
	int i;
	/* djb2: h = h * 33 + c, expressed as ((h << 5) + h) + c */
	for (i = 0; i < len; i++)
		h = ((h << 5) + h) + (unsigned char)s[i];
	return h & nats_idx_bucket_mask;
}

/* ------------------------------------------------------------------ */
/*                    Simple JSON field parser                         */
/* ------------------------------------------------------------------ */

/**
 * _skip_ws() — Advance past JSON whitespace characters.
 *
 * Skips spaces, tabs, newlines, and carriage returns.  All JSON parser
 * entry points call this before inspecting the next token.  Returns a
 * pointer to the first non-whitespace character, or @end if the buffer
 * is exhausted.
 */
static const char *_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}

/**
 * _parse_json_string() — Parse a JSON quoted string with escape handling.
 *
 * Expects @p to point at the opening double-quote.  Scans forward,
 * honouring backslash-escaped characters (\\, \", \n, etc.) so that
 * embedded quotes do not terminate the string early.  On success, sets
 * *out to the first character after the opening quote and *out_len to
 * the raw byte length (escape sequences are NOT decoded — the returned
 * slice points directly into the original buffer).
 *
 * Returns a pointer past the closing quote, or NULL on malformed input.
 */
static const char *_parse_json_string(const char *p, const char *end,
	const char **out, int *out_len)
{
	const char *start;

	if (p >= end || *p != '"')
		return NULL;
	p++; /* skip opening quote */
	start = p;

	while (p < end && *p != '"') {
		if (*p == '\\') {
			p++; /* skip escaped char */
			if (p >= end)
				return NULL;
		}
		p++;
	}
	if (p >= end)
		return NULL;

	*out = start;
	*out_len = (int)(p - start);
	p++; /* skip closing quote */
	return p;
}

/**
 * _skip_json_value() — Skip over any JSON value without extracting it.
 *
 * Handles all six JSON value types via a simple state machine:
 *   - Strings:  scan to closing quote, respecting backslash escapes.
 *   - Objects / Arrays: track brace/bracket depth, skipping over nested
 *     strings (to avoid miscounting braces inside string literals).
 *   - Primitives (number, bool, null): advance until the next structural
 *     character or whitespace.
 *
 * Returns a pointer past the value, or NULL on malformed input.
 */
static const char *_skip_json_value(const char *p, const char *end)
{
	int depth;

	p = _skip_ws(p, end);
	if (p >= end)
		return NULL;

	/*
	 * JSON parser state machine — dispatch on the first character to
	 * determine the value type, then advance past the entire value.
	 */
	switch (*p) {
	case '"': /* string — scan to unescaped closing quote */
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') {
				p++; /* skip the escaped character */
				if (p >= end) return NULL;
			}
			p++;
		}
		return (p < end) ? p + 1 : NULL;

	case '{': /* object */
	case '[': /* array  */
		/* depth-tracking: increment on open, decrement on close */
		depth = 1;
		p++;
		while (p < end && depth > 0) {
			if (*p == '{' || *p == '[') depth++;
			else if (*p == '}' || *p == ']') depth--;
			else if (*p == '"') {
				/* skip embedded strings so their content cannot
				 * be mistaken for structural characters */
				p++;
				while (p < end && *p != '"') {
					if (*p == '\\') { p++; if (p >= end) return NULL; }
					p++;
				}
				if (p >= end) return NULL;
			}
			p++;
		}
		return p;

	default: /* number, bool, null — consume until delimiter */
		while (p < end && *p != ',' && *p != '}' && *p != ']'
				&& *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		return p;
	}
}

/**
 * _parse_json_fields() — Extract top-level string fields from a JSON object.
 *
 * Iterates over the top-level key/value pairs of a JSON object.  For every
 * pair whose value is a JSON string, the user-supplied @callback is invoked
 * with the field name, field length, value, value length, and the opaque
 * @ctx pointer.  Non-string values (numbers, bools, nested objects/arrays)
 * are silently skipped.
 *
 * Callback mechanism:
 *   The callback signature is:
 *     void cb(const char *field, int flen, const char *val, int vlen, void *ctx)
 *   It is called synchronously for each string field while the JSON buffer
 *   is still valid.  The field/val pointers reference the original @json
 *   buffer and must not be stored beyond the callback's lifetime.
 *
 * Returns the number of string fields processed, or -1 on parse error.
 */
static int _parse_json_fields(const char *json, int len,
	void (*callback)(const char *field, int flen,
		const char *val, int vlen, void *ctx),
	void *ctx)
{
	const char *p = json;
	const char *end = json + len;
	const char *field, *val;
	int flen, vlen;
	int count = 0;

	p = _skip_ws(p, end);
	if (p >= end || *p != '{')
		return -1;
	p++; /* skip '{' */

	while (1) {
		p = _skip_ws(p, end);
		if (p >= end)
			return -1;
		if (*p == '}')
			break;

		/* expect comma between pairs (skip it) */
		if (*p == ',') {
			p++;
			p = _skip_ws(p, end);
			if (p >= end)
				return -1;
		}

		/* parse field name */
		p = _parse_json_string(p, end, &field, &flen);
		if (!p)
			return -1;

		/* expect colon */
		p = _skip_ws(p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		if (p >= end)
			return -1;

		/* check if value is a string */
		p = _skip_ws(p, end);
		if (p >= end)
			return -1;

		if (*p == '"') {
			/* string value — parse and invoke the caller's callback
			 * with field name + value slices from the original buffer */
			p = _parse_json_string(p, end, &val, &vlen);
			if (!p)
				return -1;
			callback(field, flen, val, vlen, ctx);
			count++;
		} else {
			/* non-string value — skip without invoking callback */
			p = _skip_json_value(p, end);
			if (!p)
				return -1;
		}
	}

	return count;
}

/* ------------------------------------------------------------------ */
/*                    Index entry management                          */
/* ------------------------------------------------------------------ */

/**
 * _find_entry() — Look up an index entry by its "field:value" key.
 *
 * Hashes @fv to select a bucket, then walks the singly-linked chain of
 * entries in that bucket comparing both length and content.  Returns the
 * matching entry or NULL.  Must be called with g_idx->lock held.
 */
static nats_idx_entry *_find_entry_in(nats_search_idx *idx,
	const char *fv, int fv_len)
{
	unsigned int bucket = _hash(fv, fv_len);
	nats_idx_entry *e;

	for (e = idx->buckets[bucket]; e; e = e->next) {
		if (e->fv_len == (unsigned int)fv_len
				&& memcmp(e->field_value, fv, fv_len) == 0)
			return e;
	}
	return NULL;
}

static nats_idx_entry *_find_entry(const char *fv, int fv_len)
{
	return _find_entry_in(g_idx, fv, fv_len);
}

/**
 * _get_or_create_entry() — Find or create an index entry for a field:value.
 *
 * First tries _find_entry(); if the entry does not exist, allocates a new
 * nats_idx_entry, copies the "field:value" string, pre-allocates the key
 * array (initial capacity 8), and inserts the entry at the head of the
 * bucket's chain.  Must be called with g_idx->lock held.
 *
 * Returns the entry pointer, or NULL on allocation failure.
 */
static nats_idx_entry *_get_or_create_entry_in(nats_search_idx *idx,
	const char *fv, int fv_len)
{
	nats_idx_entry *e;
	unsigned int bucket;

	e = _find_entry_in(idx, fv, fv_len);
	if (e)
		return e;

	/* SHM allocations: the index lives in shared memory so every
	 * worker dereferences the same pointers; entry storage must
	 * follow.  Failures here are unlikely but logged loudly because
	 * they reflect SHM exhaustion rather than per-process pkg
	 * pressure. */
	/* Single-allocation layout to cut the per-new-entry shm_malloc
	 * count from 3 to 1.  The blob is sized to hold the entry
	 * struct + the field_value bytes + an inline keys[] array of
	 * NATS_IDX_KEYS_INLINE pointers.  field_value and keys are
	 * pointer-arithmetic'd into the blob; _free_entry releases
	 * just the blob (no separate shm_free for fv/keys) unless
	 * keys_inline has been cleared by a later geometric-growth.
	 *
	 * Why this matters: the watcher's nats_json_index_add path was
	 * spending half of opensips CPU on hp_shm_malloc -> sem_wait at
	 * 100k AoRs (PERF_NOTES "HP_MALLOC contention hypothesis").
	 * Cutting allocs from 3 to 1 per new entry gives the cold-fill
	 * path 3x fewer bucket-lock acquires; the re-register hot path
	 * was already cut to ~zero by the doc-key intern table.
	 *
	 * Memory waste: the inline keys[] occupies
	 * NATS_IDX_KEYS_INLINE * 8 = 64 bytes in the blob.  When the
	 * key array grows beyond NATS_IDX_KEYS_INLINE, _entry_add_key
	 * allocates a fresh keys[] separately and clears keys_inline;
	 * the inline 64 bytes is then dead but stays in the blob until
	 * the entry itself is freed.  Trivial overhead. */
	{
		size_t entry_sz = sizeof(nats_idx_entry);
		size_t fv_sz    = (size_t)fv_len + 1;
		size_t keys_sz  = sizeof(char *) * NATS_IDX_KEYS_INLINE;
		size_t blob_sz  = entry_sz + fv_sz + keys_sz;
		char  *blob     = shm_malloc(blob_sz);
		if (!blob) {
			LM_ERR("no SHM for index entry blob (%zu bytes)\n",
				blob_sz);
			return NULL;
		}
		memset(blob, 0, blob_sz);
		e               = (nats_idx_entry *)blob;
		e->field_value  = blob + entry_sz;
		e->keys         = (char **)(blob + entry_sz + fv_sz);
		e->keys_inline  = 1;
	}

	memcpy(e->field_value, fv, (size_t)fv_len);
	e->field_value[fv_len] = '\0';
	e->fv_len = fv_len;

	e->alloc_keys = NATS_IDX_KEYS_INLINE;
	e->num_keys   = 0;

	bucket = _hash(fv, fv_len);
	e->next = idx->buckets[bucket];
	idx->buckets[bucket] = e;

	return e;
}

/* The thin wrapper _get_or_create_entry(fv, fv_len) -> _get_or_create_entry_in(
 * g_idx, fv, fv_len) was removed: every call site already targets a
 * specific index (the live index OR a shadow index during rebuild),
 * so the wrapper had no callers and gcc -Wunused-function under
 * -Werror flagged it. */

/**
 * _entry_add_key() — Append a document key to an entry's key list.
 *
 * The key list is a dynamic array of strdup'd strings.  Duplicates are
 * detected by a linear scan and silently ignored.  When the array is full
 * it is doubled in size via realloc (geometric growth: 8 -> 16 -> 32 ...).
 * Must be called with g_idx->lock held.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int _entry_add_key(nats_idx_entry *e, const char *key)
{
	int i;
	char *interned;
	int   klen = (int)strlen(key);

	/* Intern up front so the dup check can compare pointers instead
	 * of running strcmp on every stored key.  All stored keys are
	 * already canonical (acquired through nats_intern_acquire); the
	 * intern table guarantees the same content always resolves to
	 * the same SHM pointer.  Pointer equality is therefore both
	 * correct and O(1).
	 *
	 * Cost of the upfront acquire: one hash lookup + (if hit) one
	 * refcount bump.  Cheaper than strcmp over N >= 2 stored keys,
	 * which is the common case in re-register storms where every
	 * AoR's 5 indexed fields share the same doc key. */
	interned = nats_intern_acquire(key, klen);
	if (!interned) {
		LM_ERR("no SHM for interned key string\n");
		return -1;
	}

	for (i = 0; i < e->num_keys; i++) {
		if (e->keys[i] == interned) {
			/* duplicate: drop the extra refcount we just took
			 * so the intern entry's refcount stays balanced. */
			nats_intern_release(interned);
			return 0;
		}
	}

	/* Geometric growth (double) when the key array is full.  The
	 * twist: the initial keys[] is INSIDE the entry's single-alloc
	 * blob (e->keys_inline=1) and cannot be shm_realloc'd because
	 * it isn't a separate allocation.  The first time we grow past
	 * NATS_IDX_KEYS_INLINE we shm_malloc a fresh array, copy the
	 * inline contents over, clear keys_inline.  Subsequent grows
	 * use shm_realloc on the now-separate block. */
	if (e->num_keys >= e->alloc_keys) {
		int    new_alloc = e->alloc_keys * 2;
		char **new_keys;
		if (e->keys_inline) {
			new_keys = shm_malloc(sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow inline keys array\n");
				return -1;
			}
			memcpy(new_keys, e->keys,
				sizeof(char *) * (size_t)e->num_keys);
			e->keys         = new_keys;
			e->keys_inline  = 0;
		} else {
			/* shm_realloc preserves contents; on failure the
			 * original block is untouched. */
			new_keys = shm_realloc(e->keys,
				sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow keys array\n");
				return -1;
			}
			e->keys = new_keys;
		}
		e->alloc_keys = new_alloc;
	}

	/* New unique key for this entry: store the canonical pointer
	 * we already acquired at the top of the function.  The intern
	 * refcount is now owned by this slot in e->keys[]; release
	 * happens in _entry_remove_key. */
	e->keys[e->num_keys++] = interned;
	return 0;
}

/**
 * _entry_remove_key() — Remove a document key from an entry's key list.
 *
 * Performs a linear scan for @key.  When found, frees the string and fills
 * the gap by moving the last element into the vacated slot (swap-remove).
 * This is O(n) in the key count but avoids a memmove and keeps the array
 * compact.  Must be called with g_idx->lock held.
 */
static void _entry_remove_key(nats_idx_entry *e, const char *key)
{
	int   i;
	char *interned;
	int   klen = (int)strlen(key);

	/* Intern to get the canonical pointer; subsequent scan is O(1)
	 * pointer compare.  This adds an extra acquire+release per call
	 * but eliminates the strcmp per stored key. */
	interned = nats_intern_acquire(key, klen);
	if (!interned) return;

	for (i = 0; i < e->num_keys; i++) {
		if (e->keys[i] == interned) {
			/* Release twice: once for the slot's ref (kept since
			 * _entry_add_key), once for the acquire we just did
			 * at the top of this function. */
			nats_intern_release(e->keys[i]);
			nats_intern_release(interned);
			/* swap-remove: move the last element into this slot */
			e->num_keys--;
			if (i < e->num_keys)
				e->keys[i] = e->keys[e->num_keys];
			return;
		}
	}
	/* Not found: release our extra acquire to balance refcount. */
	nats_intern_release(interned);
}

/**
 * _free_entry() — Free a single index entry and all its owned memory.
 *
 * Releases the field_value string, every strdup'd key in the key array,
 * the key array itself, and finally the entry struct.  Safe to call with
 * a NULL pointer (no-op).
 */
static void _free_entry(nats_idx_entry *e)
{
	int i;
	if (!e)
		return;

	/* Release intern refcounts on every doc key.  The underlying
	 * SHM string is freed only when no other entry still
	 * references it. */
	if (e->keys) {
		for (i = 0; i < e->num_keys; i++)
			nats_intern_release(e->keys[i]);
	}

	/* Free the keys[] array only if it has been grown past the
	 * inline NATS_IDX_KEYS_INLINE slots into a separate SHM
	 * allocation.  When still inline, it is part of the entry
	 * blob and freed with the entry below. */
	if (!e->keys_inline && e->keys)
		shm_free(e->keys);

	/* The entry struct, the field_value bytes, and (if inline)
	 * the keys[] slots all live in a single shm_malloc'd blob.
	 * One free releases the lot. */
	shm_free(e);
}

/* ------------------------------------------------------------------ */
/*             Callback context for JSON field indexing                */
/* ------------------------------------------------------------------ */

typedef struct _idx_add_ctx {
	const char *doc_key;     /* the KV key for this document */
	nats_search_idx *target; /* destination index — NULL means g_idx */
} idx_add_ctx;

/**
 * _index_field_cb() — Callback used during JSON parsing to index fields.
 *
 * Invoked by _parse_json_fields() for every top-level string field in a
 * JSON document.  Builds the composite "field:value" lookup key into a
 * stack buffer, then calls _get_or_create_entry() + _entry_add_key() to
 * record the association between this field:value pair and the document's
 * KV key (carried in ctx->doc_key).
 */
static void _index_field_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	idx_add_ctx *actx = (idx_add_ctx *)ctx;
	char fv_buf[1024];
	int fv_len;
	nats_idx_entry *e;

	/* guard against negative lengths that could cause integer underflow
	 * and subsequent out-of-bounds memcpy */
	if (flen < 0 || vlen < 0)
		return;

	/* build "field:value" string */
	fv_len = flen + 1 + vlen;
	if (fv_len >= (int)sizeof(fv_buf)) {
		LM_WARN("field:value too long (%d), skipping\n", fv_len);
		return;
	}
	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	fv_buf[fv_len] = '\0';

	e = _get_or_create_entry_in(actx->target ? actx->target : g_idx,
		fv_buf, fv_len);
	if (!e)
		return;

	_entry_add_key(e, actx->doc_key);
}

/* ------------------------------------------------------------------ */
/*                      Public API functions                          */
/* ------------------------------------------------------------------ */

/**
 * nats_json_index_init() — Allocate and initialise the global search index.
 *
 * Allocates the nats_search_idx struct (heap, not SHM — the index is
 * process-local), zeroes the bucket array, and initialises the protecting
 * mutex.  Must be called once per OpenSIPS worker process before any
 * index_add / query / update operations.
 *
 * Returns 0 on success, -1 on failure.
 */
/* Round @v up to the next power of two, with a floor at @min.
 * Used to coerce the operator-supplied `index_buckets` modparam
 * into a power-of-two value so `_hash` can use a bitmask. */
static int _round_up_pow2(int v, int min)
{
	int r = 1;
	if (v < min)
		v = min;
	while (r < v)
		r <<= 1;
	return r;
}

int nats_json_index_init(void)
{
	if (g_idx) {
		LM_WARN("search index already initialized\n");
		return 0;
	}

	/* Coerce the requested bucket count into a power of two (so the
	 * hash can use a bitmask) and at least NATS_IDX_SHARDS (so each
	 * shard guards exactly buckets/shards buckets). */
	int requested = nats_idx_buckets > 0
		? nats_idx_buckets : NATS_IDX_DEFAULT_BUCKETS;
	int rounded = _round_up_pow2(requested, NATS_IDX_SHARDS);
	if (rounded != requested)
		LM_INFO("index_buckets %d rounded up to power of two "
			"%d (min %d)\n",
			requested, rounded, NATS_IDX_SHARDS);
	nats_idx_buckets = rounded;
	nats_idx_bucket_mask = rounded - 1;

	/* Allocate the index header in SHM so every forked OpenSIPS
	 * worker sees the same instance.  Pre-fork allocation matters:
	 * once child_init runs, each worker maps the same SHM segment
	 * and dereferences the same pointer values. */
	g_idx = shm_malloc(sizeof(nats_search_idx));
	if (!g_idx) {
		LM_ERR("index init: shm_malloc for nats_search_idx header "
			"failed (%zu bytes; tune -m / shared memory size)\n",
			sizeof(nats_search_idx));
		return -1;
	}
	memset(g_idx, 0, sizeof(nats_search_idx));
	atomic_store(&g_idx->num_documents, 0);

	g_idx->buckets = shm_malloc(
		sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);
	if (!g_idx->buckets) {
		LM_ERR("index init: shm_malloc for buckets array failed "
			"(%d buckets, %zu bytes)\n",
			nats_idx_buckets,
			sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}
	memset(g_idx->buckets, 0,
		sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets);

	g_idx->shard_locks = lock_set_alloc(NATS_IDX_SHARDS);
	if (!g_idx->shard_locks) {
		LM_ERR("index init: lock_set_alloc(%d) for shard locks "
			"failed (SHM exhausted?)\n", NATS_IDX_SHARDS);
		shm_free(g_idx->buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}
	if (!lock_set_init(g_idx->shard_locks)) {
		LM_ERR("index init: lock_set_init failed for %d shards\n",
			NATS_IDX_SHARDS);
		lock_set_dealloc(g_idx->shard_locks);
		shm_free(g_idx->buckets);
		shm_free(g_idx);
		g_idx = NULL;
		return -1;
	}

	LM_DBG("search index initialized in SHM (%d buckets, %d shards)\n",
		nats_idx_buckets, NATS_IDX_SHARDS);
	return 0;
}

/* Shard-locking helpers.  Whole-index ops acquire shards in index
 * order to keep the lock hierarchy consistent.  The lock set itself
 * is SHM-backed so cross-process synchronisation is safe. */
static inline void _idx_lock_shard(nats_search_idx *idx, int shard)
{
	lock_set_get(idx->shard_locks, shard);
}
static inline void _idx_unlock_shard(nats_search_idx *idx, int shard)
{
	lock_set_release(idx->shard_locks, shard);
}
static inline void _idx_lock_all(nats_search_idx *idx)
{
	int i;
	for (i = 0; i < NATS_IDX_SHARDS; i++)
		lock_set_get(idx->shard_locks, i);
}
static inline void _idx_unlock_all(nats_search_idx *idx)
{
	int i;
	for (i = NATS_IDX_SHARDS - 1; i >= 0; i--)
		lock_set_release(idx->shard_locks, i);
}

/* Per-entry callback type used by _drain_kv_snapshot.  Return 0 to
 * keep iterating, non-zero to stop early. */
typedef int (*_kv_snapshot_cb)(const char *key,
	const char *data, int data_len, void *ctx);

/* Drain the initial snapshot phase of a kvStore_WatchAll subscription:
 * open a watcher with UpdatesOnly=false, loop on kvWatcher_Next until
 * libnats delivers the end-of-snapshot sentinel (NULL entry), invoke
 * @cb for each delivered live entry, then destroy the watcher.
 *
 * Replaces the legacy "kvStore_Keys + N × kvStore_Get" pattern: instead
 * of N round-trips serially, the broker streams every existing entry
 * through a single subscription (one round-trip latency, then
 * server-paced delivery).  For a 50k-key bucket on a typical 200 µs
 * RTT this collapses cold-start work from ~10 s to ~1-2 s.
 *
 * IgnoreDeletes is set so tombstones are skipped (we only index live
 * docs).  MetaOnly is left false because we need value bytes to parse
 * JSON.  The snapshot phase's per-call timeout is large (30 s) — the
 * broker delivers entries immediately once the subscription is
 * established; a 30-s wait is only hit if the broker is actually
 * stalled, in which case caller-bubbled error is the right outcome.
 *
 * Returns the number of entries the callback successfully indexed
 * (return value 0), or -1 on a NATS-level error before any entry was
 * delivered. */
static int _drain_kv_snapshot(kvStore *kv,
	_kv_snapshot_cb cb, void *ctx)
{
	kvWatcher *w = NULL;
	kvWatchOptions opts;
	kvEntry *entry = NULL;
	natsStatus s;
	int count = 0;

	nats_dl.kvWatchOptions_Init(&opts);
	opts.IgnoreDeletes = true;
	opts.UpdatesOnly   = false;   /* include the initial snapshot */

	s = nats_dl.kvStore_WatchAll(&w, kv, &opts);
	if (s != NATS_OK) {
		LM_ERR("kvStore_WatchAll failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return -1;
	}

	for (;;) {
		const char *key, *data;
		int data_len;

		s = nats_dl.kvWatcher_Next(&entry, w, 30000);
		if (s == NATS_TIMEOUT) {
			LM_WARN("snapshot stalled at %d entries; aborting\n",
				count);
			break;
		}
		if (s != NATS_OK) {
			LM_ERR("kvWatcher_Next failed: %s\n",
				nats_dl.natsStatus_GetText(s));
			nats_dl.kvWatcher_Destroy(w);
			return -1;
		}
		if (!entry)
			break;   /* end-of-snapshot sentinel */

		key      = nats_dl.kvEntry_Key(entry);
		data     = nats_dl.kvEntry_ValueString(entry);
		data_len = nats_dl.kvEntry_ValueLen(entry);

		if (key && data && data_len > 0) {
			if (cb(key, data, data_len, ctx) == 0)
				count++;
		}

		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;
	}

	if (entry) nats_dl.kvEntry_Destroy(entry);
	nats_dl.kvWatcher_Destroy(w);
	return count;
}

/* Snapshot-callback adapter for nats_json_index_build: filters by
 * prefix and JSON-shape heuristic, then invokes the global-index
 * insert. */
struct _build_snapshot_ctx {
	const char *prefix;
	int prefix_len;
};

static int _build_snapshot_cb(const char *key,
	const char *data, int data_len, void *ctx)
{
	struct _build_snapshot_ctx *bctx = ctx;
	if (bctx->prefix_len > 0 &&
	    strncmp(key, bctx->prefix, bctx->prefix_len) != 0)
		return -1;
	if (data[0] != '{')
		return -1;
	return nats_json_index_add(key, data, data_len);
}

/**
 * nats_json_index_build() — Bulk-load the index from a NATS KV store.
 *
 * For each live entry whose key matches @prefix and whose value
 * starts with '{' (heuristic JSON detection), calls
 * nats_json_index_add() to parse and index every top-level string
 * field.  Used once at startup to warm the index.
 *
 * Returns the number of documents indexed, or -1 on error.
 */
int nats_json_index_build(kvStore *kv, const char *prefix)
{
	struct _build_snapshot_ctx ctx;
	int count;

	if (!g_idx) {
		LM_ERR("search index not initialized\n");
		return -1;
	}
	if (!kv) {
		LM_ERR("null KV store\n");
		return -1;
	}

	ctx.prefix = prefix;
	ctx.prefix_len = prefix ? (int)strlen(prefix) : 0;

	count = _drain_kv_snapshot(kv, _build_snapshot_cb, &ctx);
	if (count < 0) return -1;

	LM_INFO("search index built: %d documents indexed\n", count);
	return count;
}

/**
 * nats_json_index_add() — Parse a JSON document and add it to the index.
 *
 * Acquires the index mutex, invokes _parse_json_fields() with the
 * _index_field_cb callback to extract every top-level string field, and
 * creates or updates "field:value" -> key mappings in the hash table.
 * Increments the global document counter on success.
 *
 * Returns 0 on success, -1 if parsing fails or parameters are NULL.
 */
/* Two-phase index_add: parse the document into a stack/heap-backed
 * field-value list outside the lock, then take the lock briefly only
 * to insert each (field:value, key) pair.  The previous design held
 * the index mutex for the full duration of _parse_json_fields, which
 * scaled with document size and serialised concurrent index work
 * (queries, removes, other adds) on the entire CPU-bound parse.
 *
 * For a typical AoR document (~500 bytes, 2-3 top-level string
 * fields) the lock-held window drops from "parse + N inserts" to
 * "N inserts", roughly a 10× reduction. */

#define _IDX_FV_INLINE 16

typedef struct {
	const char *field; int flen;
	const char *val;   int vlen;
} _idx_fv_t;

typedef struct {
	_idx_fv_t  inline_buf[_IDX_FV_INLINE];
	_idx_fv_t *items;
	int n;
	int cap;
	int oom;
} _idx_fv_list_t;

static void _idx_fv_init(_idx_fv_list_t *l)
{
	l->items = l->inline_buf;
	l->n = 0;
	l->cap = _IDX_FV_INLINE;
	l->oom = 0;
}

static void _idx_fv_free(_idx_fv_list_t *l)
{
	if (l->items != l->inline_buf)
		free(l->items);
	l->items = NULL;
}

static int _idx_fv_grow(_idx_fv_list_t *l)
{
	int newcap = l->cap * 2;
	_idx_fv_t *next;
	if (l->items == l->inline_buf) {
		next = malloc(newcap * sizeof(_idx_fv_t));
		if (!next) return -1;
		memcpy(next, l->items, l->n * sizeof(_idx_fv_t));
	} else {
		next = realloc(l->items, newcap * sizeof(_idx_fv_t));
		if (!next) return -1;
	}
	l->items = next;
	l->cap = newcap;
	return 0;
}

static void _collect_fv_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	_idx_fv_list_t *l = ctx;
	if (l->oom) return;
	if (flen < 0 || vlen < 0) return;
	if (l->n == l->cap && _idx_fv_grow(l) < 0) {
		l->oom = 1;
		return;
	}
	l->items[l->n++] = (_idx_fv_t){field, flen, val, vlen};
}

int nats_json_index_add(const char *key, const char *json_str, int json_len)
{
	_idx_fv_list_t list;
	int rc, i;

	if (!g_idx || !key || !json_str)
		return -1;

	/* Phase A: parse the document into a flat (field, value) list
	 * with no lock held.  The parser is CPU-bound at ~bytes/cycle,
	 * so this is where the heavy lifting happens; running it
	 * unlocked lets concurrent queries / removes / adds proceed. */
	_idx_fv_init(&list);
	rc = _parse_json_fields(json_str, json_len, _collect_fv_cb, &list);
	if (rc < 0 || list.oom) {
		_idx_fv_free(&list);
		LM_WARN("failed to parse JSON for key '%s'\n", key);
		return -1;
	}

	/* Phase B: per-field shard locking.  Each collected pair hashes
	 * to one bucket → one shard; we lock only that shard for the
	 * insert, release between fields.  Two concurrent index_add
	 * calls whose fields happen to land on disjoint shards
	 * therefore proceed in parallel rather than serialising on a
	 * shared lock-all.
	 *
	 * Locking order is determined per-field by NATS_IDX_SHARD_OF
	 * so all callers acquire shards in increasing index order
	 * whenever they need more than one — but since each iteration
	 * acquires and immediately releases a single shard, the
	 * hierarchy is trivial: no thread ever holds two shard locks
	 * simultaneously here.  This means a high-fan-out doc cannot
	 * deadlock against a whole-index op (lock_all) — when lock_all
	 * is contending, our per-field lock waits behind it for that
	 * shard, then proceeds. */
	for (i = 0; i < list.n; i++) {
		char fv_buf[1024];
		int  fv_len;
		unsigned int bucket;
		int shard;
		nats_idx_entry *e;
		const _idx_fv_t *p = &list.items[i];

		if (p->flen < 0 || p->vlen < 0) continue;
		fv_len = p->flen + 1 + p->vlen;
		if (fv_len >= (int)sizeof(fv_buf)) {
			LM_WARN("field:value too long (%d), skipping\n", fv_len);
			continue;
		}
		memcpy(fv_buf, p->field, p->flen);
		fv_buf[p->flen] = ':';
		memcpy(fv_buf + p->flen + 1, p->val, p->vlen);
		fv_buf[fv_len] = '\0';

		bucket = _hash(fv_buf, fv_len);
		shard  = NATS_IDX_SHARD_OF(bucket);

		_idx_lock_shard(g_idx, shard);
		e = _get_or_create_entry_in(g_idx, fv_buf, fv_len);
		if (e)
			_entry_add_key(e, key);
		_idx_unlock_shard(g_idx, shard);
	}

	atomic_fetch_add_explicit(&g_idx->num_documents, 1,
		memory_order_relaxed);

	_idx_fv_free(&list);

	LM_DBG("indexed key '%s' (%d fields)\n", key, rc);
	return 0;
}

/* Internal: add a parsed JSON document to a CALLER-PROVIDED index
 * struct.  No locking — caller has exclusive ownership of @target
 * (the rebuild path holds it on a thread-local shadow until the
 * atomic swap). */
static int _index_add_into(nats_search_idx *target, const char *key,
	const char *json_str, int json_len)
{
	idx_add_ctx ctx;
	int rc;

	if (!target || !key || !json_str) return -1;
	ctx.doc_key = key;
	ctx.target = target;
	rc = _parse_json_fields(json_str, json_len, _index_field_cb, &ctx);
	if (rc >= 0)
		atomic_fetch_add_explicit(&target->num_documents, 1,
			memory_order_relaxed);
	return rc < 0 ? -1 : 0;
}

/**
 * nats_json_index_remove() — Remove a document from the index by its KV key.
 *
 * Acquires the mutex and walks every bucket/entry in the hash table,
 * calling _entry_remove_key() to strip the document key from each entry's
 * key list.  This is O(entries * keys_per_entry) but is acceptable because
 * remove is infrequent compared to queries.  Decrements the document count.
 *
 * Returns 0 on success, -1 if parameters are NULL or index is uninitialised.
 */
int nats_json_index_remove(const char *key)
{
	unsigned int b;
	nats_idx_entry *e;

	if (!g_idx || !key)
		return -1;

	_idx_lock_all(g_idx);

	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		for (e = g_idx->buckets[b]; e; e = e->next)
			_entry_remove_key(e, key);
	}

	_idx_unlock_all(g_idx);

	atomic_fetch_sub_explicit(&g_idx->num_documents, 1,
		memory_order_relaxed);

	LM_DBG("removed key '%s' from index\n", key);
	return 0;
}

/* Per-field-callback adapter for nats_json_index_remove_fields:
 * looks up the (field:value) entry, locks just its shard, removes
 * the doc-key from its keys[] array, releases the shard.  Field +
 * value byte slices alias into the caller-owned old JSON, which
 * stays live across this entire call sequence. */
typedef struct {
	const char *doc_key;
} _idx_remove_ctx;

static void _index_remove_field_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	_idx_remove_ctx *rctx = ctx;
	char fv_buf[1024];
	int fv_len = flen + 1 + vlen;
	unsigned int bucket;
	int shard;
	nats_idx_entry *e;

	if (flen < 0 || vlen < 0) return;
	if (fv_len >= (int)sizeof(fv_buf)) return;
	memcpy(fv_buf, field, flen);
	fv_buf[flen] = ':';
	memcpy(fv_buf + flen + 1, val, vlen);
	fv_buf[fv_len] = '\0';

	bucket = _hash(fv_buf, fv_len);
	shard  = NATS_IDX_SHARD_OF(bucket);

	_idx_lock_shard(g_idx, shard);
	e = _find_entry_in(g_idx, fv_buf, fv_len);
	if (e)
		_entry_remove_key(e, rctx->doc_key);
	_idx_unlock_shard(g_idx, shard);
}

int nats_json_index_remove_fields(const char *key,
	const char *json_str, int json_len)
{
	_idx_remove_ctx ctx;
	int rc;

	if (!g_idx || !key || !json_str || json_len <= 0)
		return 0;

	ctx.doc_key = key;
	rc = _parse_json_fields(json_str, json_len, _index_remove_field_cb,
		&ctx);
	if (rc < 0)
		return -1;

	atomic_fetch_sub_explicit(&g_idx->num_documents, 1,
		memory_order_relaxed);

	LM_DBG("removed key '%s' (%d field entries) from index\n",
		key, rc);
	return 0;
}

/**
 * nats_json_index_rebuild() — Clear the index and rebuild from KV data.
 *
 * Acquires the mutex, walks every bucket and frees all entries (clearing
 * the entire hash table), resets the document counter, then releases the
 * lock and calls nats_json_index_build() to re-scan the KV store.  Used
 * when the index may have drifted from the KV contents (e.g. after a
 * NATS reconnect or an MI rebuild command).
 *
 * Returns the number of documents re-indexed, or -1 on error.
 */
/* Snapshot-callback adapter for nats_json_index_rebuild: indexes
 * into the caller-owned shadow rather than the global index. */
struct _rebuild_snapshot_ctx {
	nats_search_idx *shadow;
	const char *prefix;
	int prefix_len;
};

static int _rebuild_snapshot_cb(const char *key,
	const char *data, int data_len, void *ctx)
{
	struct _rebuild_snapshot_ctx *rctx = ctx;
	if (rctx->prefix_len > 0 &&
	    strncmp(key, rctx->prefix, rctx->prefix_len) != 0)
		return -1;
	if (data[0] != '{')
		return -1;
	return _index_add_into(rctx->shadow, key, data, data_len);
}

int nats_json_index_rebuild(kvStore *kv, const char *prefix)
{
	nats_search_idx shadow;
	struct _rebuild_snapshot_ctx ctx;
	int count;
	nats_idx_entry **old_buckets;
	int old_num;
	unsigned int b;
	nats_idx_entry *e, *next;
	size_t buckets_bytes;

	if (!g_idx) return -1;
	if (!kv)    { LM_ERR("null KV store\n"); return -1; }

	LM_INFO("rebuilding search index (shadow build + atomic swap)...\n");

	/* Step 1: build the new state into a thread-local shadow struct.
	 * The shadow header is on the stack but its buckets array must be
	 * heap-allocated since the bucket count is now runtime-tunable.
	 * Only this caller sees the shadow; the lock field is unused
	 * because no other thread can reach `shadow` -- we pass it
	 * explicitly through _index_add_into. */
	memset(&shadow, 0, sizeof(shadow));
	buckets_bytes = sizeof(nats_idx_entry *) * (size_t)nats_idx_buckets;
	shadow.buckets = pkg_malloc(buckets_bytes);
	if (!shadow.buckets) {
		LM_ERR("rebuild: pkg_malloc for shadow buckets failed "
			"(%d buckets, %zu bytes)\n",
			nats_idx_buckets, buckets_bytes);
		return -1;
	}
	memset(shadow.buckets, 0, buckets_bytes);

	ctx.shadow = &shadow;
	ctx.prefix = prefix;
	ctx.prefix_len = prefix ? (int)strlen(prefix) : 0;

	count = _drain_kv_snapshot(kv, _rebuild_snapshot_cb, &ctx);
	if (count < 0) {
		/* No entries in bucket / WatchAll failed harmlessly →
		 * shadow stays empty; we still proceed with the atomic
		 * swap so the live index is reset to empty consistently
		 * with the legacy behaviour (which silently used count=0
		 * when kvStore_Keys returned NATS_NOT_FOUND). */
		count = 0;
	}

	/* Step 2: atomic swap under all shard locks.  Snapshot the old
	 * buckets pointer (entries remain reachable to readers up until
	 * we release the locks, after which they're disowned), then
	 * install the shadow's buckets and num_documents.  Queries
	 * arriving DURING this critical section block on whatever
	 * shard they need and see the new state when they get in.
	 *
	 * Note: we swap the pointer-to-buckets, not the buckets bytes.
	 * The old g_idx->buckets array (SHM) stays put; we copy from
	 * shadow.buckets into it.  This avoids forcing a SHM realloc
	 * while shards are locked. */
	_idx_lock_all(g_idx);
	old_buckets = pkg_malloc(buckets_bytes);
	if (!old_buckets) {
		_idx_unlock_all(g_idx);
		pkg_free(shadow.buckets);
		LM_ERR("rebuild: pkg_malloc for old-buckets snapshot "
			"failed (%d buckets, %zu bytes)\n",
			nats_idx_buckets, buckets_bytes);
		return -1;
	}
	memcpy(old_buckets, g_idx->buckets, buckets_bytes);
	old_num = atomic_load_explicit(&g_idx->num_documents,
		memory_order_relaxed);
	memcpy(g_idx->buckets, shadow.buckets, buckets_bytes);
	atomic_store_explicit(&g_idx->num_documents,
		atomic_load_explicit(&shadow.num_documents, memory_order_relaxed),
		memory_order_relaxed);
	_idx_unlock_all(g_idx);

	/* Step 3: free the old (now-disowned) bucket entries outside
	 * the lock, so any blocked readers proceed immediately. */
	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		e = old_buckets[b];
		while (e) {
			next = e->next;
			_free_entry(e);
			e = next;
		}
	}
	pkg_free(old_buckets);
	pkg_free(shadow.buckets);

	LM_INFO("search index rebuilt: %d docs (was %d)\n", count, old_num);
	return count;
}

/**
 * nats_json_index_destroy() — Tear down the global index and free all memory.
 *
 * Acquires the mutex, walks every bucket, frees all entries and their key
 * lists, then destroys the mutex and frees the nats_search_idx struct.
 * Sets g_idx to NULL so subsequent calls are safe no-ops.  Called during
 * OpenSIPS worker shutdown.
 */
void nats_json_index_destroy(void)
{
	unsigned int b;
	nats_idx_entry *e, *next;

	if (!g_idx)
		return;

	_idx_lock_all(g_idx);

	for (b = 0; b < (unsigned int)nats_idx_buckets; b++) {
		e = g_idx->buckets[b];
		while (e) {
			next = e->next;
			_free_entry(e);
			e = next;
		}
		g_idx->buckets[b] = NULL;
	}
	atomic_store_explicit(&g_idx->num_documents, 0,
		memory_order_relaxed);

	_idx_unlock_all(g_idx);

	if (g_idx->shard_locks) {
		lock_set_destroy(g_idx->shard_locks);
		lock_set_dealloc(g_idx->shard_locks);
	}

	if (g_idx->buckets)
		shm_free(g_idx->buckets);
	shm_free(g_idx);
	g_idx = NULL;

	LM_DBG("search index destroyed\n");
}

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
	const cdb_filter_t *it;
	nats_idx_entry *e;
	char **match_keys = NULL;
	int match_count = 0;
	int first = 1;
	int i, result_cnt;
	kvEntry *entry = NULL;
	natsStatus s;
	cdb_row_t *row;

	if (!con || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	cdb_res_init(res);

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
	    filter->val.is_str && filter->op == CDB_OP_EQ) {
		char *target_key = NULL;
		int enc_len = 0;
		const char *data;
		int data_len;
		char *enc;

		enc = _kv_encode_key(filter->val.s.s, filter->val.s.len,
			&enc_len);
		if (!enc) {
			LM_ERR("PK query: malloc for KV-key encode buffer "
				"failed (filter '%.*s'='%.*s', encode budget "
				"%d bytes)\n",
				filter->key.name.len, filter->key.name.s,
				filter->val.s.len, filter->val.s.s,
				filter->val.s.len * 3 + 1);
			return -1;
		}
		if (fts_json_prefix && *fts_json_prefix) {
			int plen = strlen(fts_json_prefix);
			target_key = pkg_malloc(plen + enc_len + 1);
			if (!target_key) {
				free(enc);
				LM_ERR("PK query: pkg_malloc for target_key "
					"failed (prefix '%s' + %d-byte encoded "
					"value, total %d bytes)\n",
					fts_json_prefix, enc_len,
					plen + enc_len + 1);
				return -1;
			}
			memcpy(target_key, fts_json_prefix, plen);
			memcpy(target_key + plen, enc, enc_len);
			target_key[plen + enc_len] = '\0';
		} else {
			target_key = pkg_malloc(enc_len + 1);
			if (!target_key) {
				free(enc);
				LM_ERR("PK query: pkg_malloc for target_key "
					"failed (no prefix, %d-byte encoded "
					"value, total %d bytes)\n",
					enc_len, enc_len + 1);
				return -1;
			}
			memcpy(target_key, enc, enc_len);
			target_key[enc_len] = '\0';
		}
		free(enc);

		s = nats_dl.kvStore_Get(&entry, ncon->kv, target_key);
		if (s == NATS_NOT_FOUND) {
			pkg_free(target_key);
			return 0;   /* empty result, not an error */
		}
		if (s != NATS_OK) {
			LM_WARN("PK kvStore_Get failed for '%s': %s\n",
				target_key, nats_dl.natsStatus_GetText(s));
			pkg_free(target_key);
			return -1;
		}
		data = nats_dl.kvEntry_ValueString(entry);
		data_len = nats_dl.kvEntry_ValueLen(entry);
		if (data && data_len > 0 && data[0] == '{') {
			row = pkg_malloc(sizeof *row);
			if (!row) {
				LM_ERR("no pkg memory for cdb_row_t\n");
				nats_dl.kvEntry_Destroy(entry);
				pkg_free(target_key);
				return -1;
			}
			if (cdb_json_to_dict(data, &row->dict, NULL) != 0) {
				LM_ERR("PK fast path: failed to parse JSON for "
					"'%s'\n", target_key);
				pkg_free(row);
				nats_dl.kvEntry_Destroy(entry);
				pkg_free(target_key);
				return -1;
			}
			res->count++;
			list_add_tail(&row->list, &res->rows);
		}
		nats_dl.kvEntry_Destroy(entry);
		pkg_free(target_key);
		return 0;
	}

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
			if (match_keys) {
				int k;
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
				free(match_keys);
			}
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
			if (match_keys) {
				int k;
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
				free(match_keys);
				match_keys = NULL;
			}
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
			if (match_keys) {
				int k;
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
				free(match_keys);
			}
			return -1;
		}
		{
			int k;
			for (k = 0; k < e->num_keys; k++) {
				iter_keys[k] = strdup(e->keys[k]);
				if (!iter_keys[k]) {
					int j;
					LM_ERR("query: strdup for key snapshot "
						"slot %d/%d failed (filter "
						"'%.*s'='%.*s', key length %zu)\n",
						k, e->num_keys,
						it->key.name.len, it->key.name.s,
						it->val.s.len, it->val.s.s,
						strlen(e->keys[k]));
					for (j = 0; j < k; j++)
						free(iter_keys[j]);
					free(iter_keys);
					_idx_unlock_shard(g_idx, shard);
					if (match_keys) {
						for (j = 0; j < match_count; j++)
							free(match_keys[j]);
						free(match_keys);
					}
					return -1;
				}
			}
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
				int k;
				LM_ERR("intersection failed\n");
				for (k = 0; k < iter_count; k++)
					free(iter_keys[k]);
				free(iter_keys);
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
				free(match_keys);
				return -1;
			}
			{
				int k;
				for (k = 0; k < new_count; k++) {
					char *dup = strdup(new_keys[k]);
					if (!dup) {
						int j;
						LM_ERR("query: strdup for AND-intersect "
							"survivor %d/%d failed (filter "
							"'%.*s'='%.*s', key length %zu)\n",
							k, new_count,
							it->key.name.len, it->key.name.s,
							it->val.s.len, it->val.s.s,
							strlen(new_keys[k]));
						for (j = 0; j < k; j++)
							free(new_keys[j]);
						free(new_keys);
						for (j = 0; j < iter_count; j++)
							free(iter_keys[j]);
						free(iter_keys);
						for (j = 0; j < match_count; j++)
							free(match_keys[j]);
						free(match_keys);
						return -1;
					}
					new_keys[k] = dup;
				}
			}
			{
				int k;
				for (k = 0; k < iter_count; k++)
					free(iter_keys[k]);
				free(iter_keys);
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
				free(match_keys);
			}
			match_keys = new_keys;
			match_count = new_count;
		}
	}

	if (match_count == 0) {
		LM_DBG("no documents match the filter\n");
		if (match_keys) {
			int k;
			for (k = 0; k < match_count; k++)
				free(match_keys[k]);
			free(match_keys);
		}
		return 0;
	}

	/* Limit results */
	result_cnt = match_count;
	if (fts_max_results > 0 && result_cnt > fts_max_results)
		result_cnt = fts_max_results;

	/* Fetch full JSON documents and build result set */
	for (i = 0; i < result_cnt; i++) {
		const char *data;
		int data_len;

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

		if (!data || data_len <= 0 || data[0] != '{') {
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
			goto error;
		}

		if (cdb_json_to_dict(data, &row->dict, NULL) != 0) {
			LM_ERR("failed to parse JSON for key '%s'\n", match_keys[i]);
			pkg_free(row);
			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}

		res->count++;
		list_add_tail(&row->list, &res->rows);

		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;
	}

	LM_DBG("query returned %d rows\n", res->count);
	{
		int k;
		for (k = 0; k < match_count; k++)
			free(match_keys[k]);
	}
	free(match_keys);
	return 0;

error:
	{
		int k;
		for (k = 0; k < match_count; k++)
			free(match_keys[k]);
	}
	free(match_keys);
	cdb_free_rows(res);
	return -1;
}

/* ------------------------------------------------------------------ */
/*                   cachedb update() callback                        */
/* ------------------------------------------------------------------ */

/*
 * _json_escape() — RFC 8259 string escape.
 *
 * Writes the JSON-escaped form of @in (without surrounding quotes)
 * into @out.  Returns the number of bytes written, or -1 if the
 * escaped form does not fit (including the trailing NUL).
 *
 * Escapes: " \ \b \f \n \r \t -> short forms; other bytes < 0x20 ->
 * \uXXXX; everything else passes through verbatim.
 *
 * The worst-case expansion is 6 bytes per input byte ( ...).
 */
static int _json_escape(const char *in, int in_len, char *out, int out_sz)
{
	int i, w = 0;
	if (out_sz <= 0) return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		const char *esc = NULL;
		char short_buf[2];

		switch (c) {
		case '"':  esc = "\\\""; break;
		case '\\': esc = "\\\\"; break;
		case '\b': esc = "\\b";  break;
		case '\f': esc = "\\f";  break;
		case '\n': esc = "\\n";  break;
		case '\r': esc = "\\r";  break;
		case '\t': esc = "\\t";  break;
		default:
			if (c < 0x20) {
				if (w + 6 > out_sz) return -1;
				w += snprintf(out + w, out_sz - w,
					"\\u%04x", c);
				continue;
			}
			short_buf[0] = (char)c;
			short_buf[1] = '\0';
			esc = short_buf;
		}
		{
			int n = (int)strlen(esc);
			if (w + n >= out_sz) return -1;
			memcpy(out + w, esc, n);
			w += n;
		}
	}
	if (w >= out_sz) return -1;
	out[w] = '\0';
	return w;
}

/* _json_set_field() (legacy string-only setter) was removed when
 * Tier-1 #1's _json_apply_pair / json_sink_t took over the entry
 * point — gcc with -Werror=unused-function rightly flagged the
 * leftover.  The sink-based path covers all the cases the old
 * helper handled (string field set / append) plus the typed-pair
 * surface (int / null / nested object / subkey-merge). */

/* ------------------------------------------------------------------ */
/*  Single-buffer JSON sink — replaces per-pair malloc-then-splice.    */
/* ------------------------------------------------------------------ */

typedef struct {
	char *buf;
	int   len;
	int   cap;
	int   oom;     /* sticky: once set, all subsequent ops are no-ops */
} json_sink_t;

static int _sink_init(json_sink_t *s, int initial)
{
	s->cap = initial > 16 ? initial : 16;
	s->len = 0;
	s->oom = 0;
	s->buf = malloc(s->cap);
	if (!s->buf) { s->oom = 1; return -1; }
	s->buf[0] = '\0';
	return 0;
}

static int _sink_grow(json_sink_t *s, int need)
{
	int newcap;
	char *nb;
	if (s->oom) return -1;
	if (s->len + need < s->cap) return 0;
	newcap = s->cap;
	while (newcap <= s->len + need) {
		if (newcap > INT_MAX / 2) { s->oom = 1; return -1; }
		newcap *= 2;
	}
	nb = realloc(s->buf, newcap);
	if (!nb) { s->oom = 1; return -1; }
	s->buf = nb;
	s->cap = newcap;
	return 0;
}

static int _sink_write(json_sink_t *s, const char *p, int n)
{
	if (s->oom || n <= 0) return s->oom ? -1 : 0;
	if (_sink_grow(s, n + 1) < 0) return -1;
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	s->buf[s->len] = '\0';
	return 0;
}

static int _sink_putc(json_sink_t *s, char c)
{
	return _sink_write(s, &c, 1);
}

/* Compute exactly how many bytes _json_escape will emit for `n` input
 * bytes.  This is a tight character-by-character scan but a single
 * pass over the input -- much cheaper than over-reserving 6*n bytes
 * per string and forcing the sink to amortise large growth steps on
 * a write that almost never escapes (typical SIP URIs / JSON values
 * escape < 1%).
 *
 * Matches the rules in _json_escape exactly:
 *   '"' '\\' '\b' '\f' '\n' '\r' '\t'  -> 2 bytes each
 *   any other control char (< 0x20)    -> 6 bytes (\u00xx)
 *   anything else                      -> 1 byte
 */
static int _json_escape_len(const char *in, int in_len)
{
	int i, out = 0;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
		case '"': case '\\':
		case '\b': case '\f': case '\n':
		case '\r': case '\t':
			out += 2;
			break;
		default:
			out += (c < 0x20) ? 6 : 1;
		}
	}
	return out;
}

static int _sink_emit_string(json_sink_t *s, const char *p, int n)
{
	int esc_len;
	int needed;
	if (s->oom) return -1;
	/* Two-pass: count exact escape size first, then allocate.
	 * Saves ~5x on worst-case reservation for typical inputs (no
	 * escapes), which on a multi-MB doc with many string fields
	 * eliminates a substantial fraction of grow / memcpy churn. */
	esc_len = _json_escape_len(p, n);
	needed  = esc_len + 2; /* + 2 quotes */
	if (_sink_grow(s, needed + 1) < 0) return -1;
	s->buf[s->len++] = '"';
	if (esc_len > 0) {
		int written = _json_escape(p, n, s->buf + s->len, esc_len);
		if (written < 0) { s->oom = 1; return -1; }
		s->len += written;
	}
	s->buf[s->len++] = '"';
	s->buf[s->len] = '\0';
	return 0;
}

static int _sink_emit_int(json_sink_t *s, int64_t v)
{
	char tmp[32];
	int n = snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
	if (n < 0 || n >= (int)sizeof(tmp)) { s->oom = 1; return -1; }
	return _sink_write(s, tmp, n);
}

/* Transfer ownership of the buffer to the caller; sink resets to empty.
 * Caller frees the returned pointer with free(). */
static char *_sink_take(json_sink_t *s, int *out_len)
{
	char *r;
	if (s->oom) {
		free(s->buf);
		s->buf = NULL; s->len = 0; s->cap = 0;
		return NULL;
	}
	r = s->buf;
	if (out_len) *out_len = s->len;
	s->buf = NULL; s->len = 0; s->cap = 0;
	return r;
}

/* Recursively emit a cdb_dict_t as a JSON object directly into the
 * sink — single growable buffer, no per-pair malloc churn.
 *
 * Pairs are written in list order with ',' separators.  Subkey-bearing
 * pairs and pair->unset are honoured: unset subkeys are simply omitted
 * from the output object (a fresh inner dict has no prior state to
 * remove from), and subkey-bearing sets emit "field":{ "subkey":val }.
 *
 * Returns 0 on success, -1 on OOM or unknown pair type. */
static int _sink_emit_cdb_dict(json_sink_t *s, const cdb_dict_t *dict)
{
	struct list_head *pos;
	cdb_pair_t *pair;
	int first = 1;

	if (_sink_putc(s, '{') < 0) return -1;

	list_for_each(pos, dict) {
		pair = list_entry(pos, cdb_pair_t, list);

		/* Inside a fresh dict, an unset pair simply omits the
		 * (sub)key.  No prior state to remove from. */
		if (pair->unset)
			continue;

		if (!first && _sink_putc(s, ',') < 0) return -1;
		first = 0;

		if (_sink_emit_string(s, pair->key.name.s,
				pair->key.name.len) < 0) return -1;
		if (_sink_putc(s, ':') < 0) return -1;

		/* If a subkey is present, the field's JSON value is itself
		 * an object whose only entry is the subkey -> value pair. */
		if (pair->subkey.len > 0 && pair->subkey.s) {
			if (_sink_putc(s, '{') < 0) return -1;
			if (_sink_emit_string(s, pair->subkey.s,
					pair->subkey.len) < 0) return -1;
			if (_sink_putc(s, ':') < 0) return -1;
		}

		switch (pair->val.type) {
		case CDB_STR:
			if (_sink_emit_string(s, pair->val.val.st.s,
					pair->val.val.st.len) < 0) return -1;
			break;
		case CDB_INT32:
			if (_sink_emit_int(s, pair->val.val.i32) < 0) return -1;
			break;
		case CDB_INT64:
			if (_sink_emit_int(s, pair->val.val.i64) < 0) return -1;
			break;
		case CDB_NULL:
			if (_sink_write(s, "null", 4) < 0) return -1;
			break;
		case CDB_DICT:
			if (_sink_emit_cdb_dict(s, &pair->val.val.dict) < 0)
				return -1;
			break;
		default:
			LM_ERR("unknown cdb pair type %d for field '%.*s'\n",
				pair->val.type, pair->key.name.len,
				pair->key.name.s);
			s->oom = 1;
			return -1;
		}

		if (pair->subkey.len > 0 && pair->subkey.s) {
			if (_sink_putc(s, '}') < 0) return -1;
		}
	}

	if (_sink_putc(s, '}') < 0) return -1;
	return 0;
}

/* Backwards-compatible wrapper: serialize dict into a malloc'd JSON
 * object string.  Replaces the old per-pair-_json_apply_pair pattern
 * with a single growable buffer; caller still frees with free(). */
static char *_serialize_cdb_dict(const cdb_dict_t *dict, int *out_len)
{
	json_sink_t s;
	if (_sink_init(&s, 256) < 0) return NULL;
	if (_sink_emit_cdb_dict(&s, dict) < 0) {
		free(s.buf);
		return NULL;
	}
	return _sink_take(&s, out_len);
}


static int _kv_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	case '-': case '_': case '/': case '\\': case '.':
		return 1;
	}
	return 0;
}

/* Encode @in into NATS-KV-safe form with '=HH' escape for unsafe
 * bytes. Caller must free(). NATS-KV subject tokens reject
 * characters outside [-./_=a-zA-Z0-9]; usrloc AoRs commonly contain
 * '@' which would otherwise produce kvStore "Invalid Argument"
 * errors and silently drop every REGISTER. The encoding is
 * round-trippable: literal '=' becomes '=3D'. */
static char *_kv_encode_key(const char *in, int in_len, int *out_len)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, w = 0;
	int cap = in_len * 3 + 1;
	char *out = malloc(cap);
	if (!out) return NULL;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c != '=' && _kv_char_safe(c)) {
			out[w++] = (char)c;
		} else {
			out[w++] = '=';
			out[w++] = hex[(c >> 4) & 0xF];
			out[w++] = hex[c & 0xF];
		}
	}
	out[w] = '\0';
	if (out_len) *out_len = w;
	return out;
}

/* Build a malloc'd seed JSON document {"<field>":"<val>"} for the
 * first-insert path. Both field name and value are RFC 8259 escaped.
 * If field is NULL/empty, returns "{}" so the doc is still a valid JSON
 * object. Returns NULL on error. Caller must free(). */
static char *_build_seed_doc(const char *field, int flen,
	const char *val, int vlen, int *out_len)
{
	char *buf, *esc_field, *esc_val;
	int esc_field_len, esc_val_len;
	int new_len;

	if (flen <= 0 || !field) {
		buf = malloc(3);
		if (!buf) return NULL;
		memcpy(buf, "{}", 3);
		*out_len = 2;
		return buf;
	}
	if (flen > (INT_MAX - 16) / 6 || vlen > (INT_MAX - 16) / 6)
		return NULL;

	esc_field = malloc(flen * 6 + 1);
	esc_val   = malloc((vlen > 0 ? vlen : 1) * 6 + 1);
	if (!esc_field || !esc_val) {
		free(esc_field); free(esc_val);
		return NULL;
	}
	esc_field_len = _json_escape(field, flen, esc_field, flen * 6 + 1);
	esc_val_len   = vlen > 0
		? _json_escape(val, vlen, esc_val, vlen * 6 + 1)
		: 0;
	if (esc_field_len < 0 || esc_val_len < 0) {
		free(esc_field); free(esc_val);
		return NULL;
	}

	new_len = 2 + esc_field_len + 3 + esc_val_len + 2;
	buf = malloc(new_len + 1);
	if (!buf) { free(esc_field); free(esc_val); return NULL; }
	buf[0] = '{';
	buf[1] = '"';
	memcpy(buf + 2, esc_field, esc_field_len);
	buf[2 + esc_field_len]     = '"';
	buf[2 + esc_field_len + 1] = ':';
	buf[2 + esc_field_len + 2] = '"';
	memcpy(buf + 2 + esc_field_len + 3, esc_val, esc_val_len);
	buf[2 + esc_field_len + 3 + esc_val_len]     = '"';
	buf[2 + esc_field_len + 3 + esc_val_len + 1] = '}';
	buf[new_len] = '\0';
	free(esc_field); free(esc_val);
	*out_len = new_len;
	return buf;
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
				if (_sink_emit_string(s, kfield, kflen) < 0)
					return -1;
				if (_sink_putc(s, ':') < 0) return -1;
				if (_sink_emit_op_value(s, &ops[op_idx]) < 0)
					return -1;
			} else {
				/* Copy through the existing entry. */
				if (!first && _sink_putc(s, ',') < 0) return -1;
				first = 0;
				if (_sink_emit_string(s, kfield, kflen) < 0)
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
			if (_sink_emit_string(&s, fname, flen) < 0) goto out;
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
			if (_sink_emit_string(&s, fname, flen) < 0) goto out;
			if (_sink_putc(&s, ':') < 0) goto out;
			if (_sink_merge_subkeys(&s, vstart, vend,
					ops, n_ops, fname, flen) < 0) goto out;
		} else {
			if (!first && _sink_putc(&s, ',') < 0) goto out;
			first = 0;
			if (_sink_emit_string(&s, fname, flen) < 0) goto out;
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
	nats_idx_entry *e;
	char *target_key = NULL;
	kvEntry *entry = NULL;
	natsStatus s;
	const char *data;
	int data_len;
	char *json_buf = NULL;
	char *new_json = NULL;
	struct list_head *pos;
	cdb_pair_t *pair;
	uint64_t rev, new_rev;
	int retries;

	if (!con || !row_filter || !pairs) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	/* The search index is required only for the non-PK lookup
	 * branch below.  PK updates encode the target_key directly
	 * from the filter and never touch g_idx, so an uninitialised
	 * (or operator-disabled) index is fine for them.  The non-PK
	 * branch handles the missing-index case explicitly with a
	 * dedicated error message; don't pre-empt it here. */

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

	/* Try the index first when the filter is non-PK; on hit, the
	 * stored key was assigned at insert time and is already
	 * KV-safe.  When the search index is disabled (modparam
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
					return -1;
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
			return -1;
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
				return -1;
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
				return -1;
			}
			memcpy(target_key, enc, enc_len);
			target_key[enc_len] = '\0';
		}
		free(enc);
	}

	/* CAS loop: fetch (or atomically create a seed), modify, update.
	 * attempt counts iterations starting at 0; used to drive jittered
	 * exponential backoff between retries. */
	retries = nats_cas_retries > 0 ? nats_cas_retries : 1;
	int attempt = 0;
	while (retries-- > 0) {
		nats_cas_backoff_sleep(attempt);
		attempt++;
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
				pkg_free(target_key);
				return -1;
			}

			seed = _build_seed_doc(row_filter->key.name.s,
				row_filter->key.name.len,
				row_filter->val.s.s, row_filter->val.s.len, &seed_len);
			if (!seed) {
				LM_ERR("failed to build seed doc for key '%s'\n", target_key);
				pkg_free(target_key);
				return -1;
			}

			s = nats_dl.kvStore_CreateString(&create_rev, ncon->kv, target_key, seed);
			if (s == NATS_OK) {
				json_buf = seed;        /* hand off ownership */
				rev = create_rev;
				NATS_CDB_STATS_INC(create_doc);
				/* fall through to the apply-pairs block */
			} else {
				/* Most likely a race lost (key created by another writer
				 * between our Get and our Create). Free the seed and let
				 * the next iteration re-Get the now-existing doc. Hard
				 * failures (network, etc.) will recur on the next Get and
				 * be surfaced there. */
				LM_DBG("seed CreateString lost race or failed for '%s': %s\n",
					target_key, nats_dl.natsStatus_GetText(s));
				free(seed);
				NATS_CDB_STATS_INC(cas_retry);
				continue;
			}
		} else if (s != NATS_OK) {
			LM_ERR("kvStore_Get failed for key '%s': %s\n",
				target_key, nats_dl.natsStatus_GetText(s));
			pkg_free(target_key);
			return -1;
		} else {
			data = nats_dl.kvEntry_ValueString(entry);
			data_len = nats_dl.kvEntry_ValueLen(entry);
			rev = nats_dl.kvEntry_Revision(entry);

			if (!data || data_len <= 0) {
				LM_ERR("empty document for key '%s'\n", target_key);
				nats_dl.kvEntry_Destroy(entry);
				entry = NULL;
				pkg_free(target_key);
				return -1;
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
				entry = NULL;
				pkg_free(target_key);
				return -1;
			}
			memcpy(json_buf, data, data_len);
			json_buf[data_len] = '\0';

			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
		}

		/* Apply every pair in a single pass over the doc.  Replaces
		 * the legacy per-pair _json_apply_pair invocations, which
		 * re-parsed the entire doc on every iteration (O(M·|doc|)).
		 * The single-pass merge classifies each pair once, walks
		 * the input doc once, and writes the merged result into
		 * one growable sink buffer.  We keep the input buffer
		 * (json_buf) alive for the targeted index removal below. */
		{
			int old_len = (int)strlen(json_buf);
			new_json = _apply_pairs_one_pass(json_buf, old_len, pairs);
			if (!new_json) {
				LM_ERR("failed to apply pairs in single pass\n");
				free(json_buf);
				pkg_free(target_key);
				return -1;
			}
			(void)pair; (void)pos; /* silence -Wunused under this branch */

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
				free(json_buf);
				pkg_free(target_key);
				return 0;
			}

			free(new_json);
		}
		free(json_buf);
		json_buf = NULL;

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
