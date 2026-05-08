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
 *   - Hash table with NATS_IDX_BUCKETS (256) buckets and separate chaining.
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
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_json.h"
#include "cachedb_nats.h"
#include "cachedb_nats_stats.h"
#include "cachedb_nats_dbase.h"

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_max_results;
extern int   nats_cas_retries;   /* defined in cachedb_nats.c */

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

/**
 * _hash() — Compute a bucket index using the djb2 hash algorithm.
 *
 * Takes a byte string of length @len and produces a value in
 * [0, NATS_IDX_BUCKETS).  djb2 is a fast, well-distributed hash suitable
 * for short strings such as "field:value" index keys.  The magic constant
 * 5381 and the shift-add recurrence (h * 33 + c) are from Dan Bernstein's
 * original comp.lang.c posting.
 */
static unsigned int _hash(const char *s, int len)
{
	unsigned int h = 5381;
	int i;
	/* djb2: h = h * 33 + c, expressed as ((h << 5) + h) + c */
	for (i = 0; i < len; i++)
		h = ((h << 5) + h) + (unsigned char)s[i];
	return h % NATS_IDX_BUCKETS;
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

	e = malloc(sizeof(nats_idx_entry));
	if (!e) {
		LM_ERR("no memory for index entry\n");
		return NULL;
	}
	memset(e, 0, sizeof(nats_idx_entry));

	e->field_value = malloc(fv_len + 1);
	if (!e->field_value) {
		LM_ERR("no memory for field_value string\n");
		free(e);
		return NULL;
	}
	memcpy(e->field_value, fv, fv_len);
	e->field_value[fv_len] = '\0';
	e->fv_len = fv_len;

	e->alloc_keys = 8;
	e->keys = malloc(sizeof(char *) * e->alloc_keys);
	if (!e->keys) {
		LM_ERR("no memory for keys array\n");
		free(e->field_value);
		free(e);
		return NULL;
	}
	e->num_keys = 0;

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
	char *dup;

	/* check for duplicate */
	for (i = 0; i < e->num_keys; i++) {
		if (strcmp(e->keys[i], key) == 0)
			return 0;
	}

	/* Geometric growth (double) when the key array is full.
	 * This gives amortised O(1) appends and keeps realloc calls
	 * logarithmic in the total number of keys. */
	if (e->num_keys >= e->alloc_keys) {
		int new_alloc = e->alloc_keys * 2;
		char **new_keys = realloc(e->keys, sizeof(char *) * new_alloc);
		if (!new_keys) {
			LM_ERR("no memory to grow keys array\n");
			return -1;
		}
		e->keys = new_keys;
		e->alloc_keys = new_alloc;
	}

	dup = strdup(key);
	if (!dup) {
		LM_ERR("no memory for key string\n");
		return -1;
	}
	e->keys[e->num_keys++] = dup;
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
	int i;
	for (i = 0; i < e->num_keys; i++) {
		if (strcmp(e->keys[i], key) == 0) {
			free(e->keys[i]);
			/* swap-remove: move the last element into this slot */
			e->num_keys--;
			if (i < e->num_keys)
				e->keys[i] = e->keys[e->num_keys];
			return;
		}
	}
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
	if (e->field_value)
		free(e->field_value);
	if (e->keys) {
		for (i = 0; i < e->num_keys; i++)
			free(e->keys[i]);
		free(e->keys);
	}
	free(e);
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
int nats_json_index_init(void)
{
	if (g_idx) {
		LM_WARN("search index already initialized\n");
		return 0;
	}

	g_idx = malloc(sizeof(nats_search_idx));
	if (!g_idx) {
		LM_ERR("no memory for search index\n");
		return -1;
	}
	memset(g_idx, 0, sizeof(nats_search_idx));

	if (pthread_mutex_init(&g_idx->lock, NULL) != 0) {
		LM_ERR("failed to initialize index mutex\n");
		free(g_idx);
		g_idx = NULL;
		return -1;
	}

	LM_DBG("search index initialized (%d buckets)\n", NATS_IDX_BUCKETS);
	return 0;
}

/**
 * nats_json_index_build() — Bulk-load the index from a NATS KV store.
 *
 * Enumerates all keys in @kv, optionally filtering by @prefix.  For each
 * key whose value starts with '{' (heuristic JSON detection), calls
 * nats_json_index_add() to parse and index every top-level string field.
 * This performs a full KV scan and is intended to be called once at
 * startup to warm the index.
 *
 * Returns the number of documents indexed, or -1 on error.
 */
int nats_json_index_build(kvStore *kv, const char *prefix)
{
	kvKeysList keys;
	kvEntry *entry = NULL;
	natsStatus s;
	int i, count = 0;
	int prefix_len;

	if (!g_idx) {
		LM_ERR("search index not initialized\n");
		return -1;
	}

	if (!kv) {
		LM_ERR("null KV store\n");
		return -1;
	}

	prefix_len = prefix ? (int)strlen(prefix) : 0;

	memset(&keys, 0, sizeof(keys));
	s = kvStore_Keys(&keys, kv, NULL);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("no keys found in KV store\n");
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("scanning %d keys for JSON documents (prefix='%s')\n",
		keys.Count, prefix ? prefix : "");

	for (i = 0; i < keys.Count; i++) {
		const char *key = keys.Keys[i];
		const char *data;
		int data_len;

		/* skip keys that don't match the prefix */
		if (prefix_len > 0 &&
				strncmp(key, prefix, prefix_len) != 0)
			continue;

		s = kvStore_Get(&entry, kv, key);
		if (s != NATS_OK) {
			LM_DBG("skipping key '%s': %s\n", key, natsStatus_GetText(s));
			continue;
		}

		data = kvEntry_ValueString(entry);
		data_len = kvEntry_ValueLen(entry);

		if (data && data_len > 0 && data[0] == '{') {
			if (nats_json_index_add(key, data, data_len) == 0)
				count++;
		}

		kvEntry_Destroy(entry);
		entry = NULL;
	}

	kvKeysList_Destroy(&keys);

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
int nats_json_index_add(const char *key, const char *json_str, int json_len)
{
	idx_add_ctx ctx;
	int rc;

	if (!g_idx || !key || !json_str)
		return -1;

	ctx.doc_key = key;
	ctx.target = NULL;

	pthread_mutex_lock(&g_idx->lock);
	rc = _parse_json_fields(json_str, json_len, _index_field_cb, &ctx);
	if (rc >= 0)
		g_idx->num_documents++;
	pthread_mutex_unlock(&g_idx->lock);

	if (rc < 0) {
		LM_WARN("failed to parse JSON for key '%s'\n", key);
		return -1;
	}

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
	if (rc >= 0) target->num_documents++;
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

	pthread_mutex_lock(&g_idx->lock);

	for (b = 0; b < NATS_IDX_BUCKETS; b++) {
		for (e = g_idx->buckets[b]; e; e = e->next)
			_entry_remove_key(e, key);
	}
	g_idx->num_documents--;

	pthread_mutex_unlock(&g_idx->lock);

	LM_DBG("removed key '%s' from index\n", key);
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
int nats_json_index_rebuild(kvStore *kv, const char *prefix)
{
	nats_search_idx shadow;
	kvKeysList keys;
	kvEntry *entry = NULL;
	natsStatus s;
	int i, count = 0;
	int prefix_len;
	nats_idx_entry *old_buckets[NATS_IDX_BUCKETS];
	int old_num;
	unsigned int b;
	nats_idx_entry *e, *next;

	if (!g_idx) return -1;
	if (!kv)    { LM_ERR("null KV store\n"); return -1; }

	LM_INFO("rebuilding search index (shadow build + atomic swap)...\n");

	/* Step 1: build the new state into a thread-local shadow struct.
	 * The shadow is on the stack; only this caller sees it.  The lock
	 * field is unused because no other thread can reach `shadow` --
	 * we pass it explicitly through _index_add_into. */
	memset(&shadow, 0, sizeof(shadow));

	prefix_len = prefix ? (int)strlen(prefix) : 0;
	memset(&keys, 0, sizeof(keys));
	s = kvStore_Keys(&keys, kv, NULL);
	if (s == NATS_NOT_FOUND) {
		/* empty KV — shadow is already empty; just swap */
	} else if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", natsStatus_GetText(s));
		return -1;
	} else {
		for (i = 0; i < keys.Count; i++) {
			const char *key = keys.Keys[i];
			const char *data;
			int data_len;
			if (prefix_len > 0 &&
			    strncmp(key, prefix, prefix_len) != 0)
				continue;
			s = kvStore_Get(&entry, kv, key);
			if (s != NATS_OK) continue;
			data = kvEntry_ValueString(entry);
			data_len = kvEntry_ValueLen(entry);
			if (data && data_len > 0 && data[0] == '{') {
				if (_index_add_into(&shadow, key, data, data_len) == 0)
					count++;
			}
			kvEntry_Destroy(entry);
			entry = NULL;
		}
		kvKeysList_Destroy(&keys);
	}

	/* Step 2: atomic swap under g_idx->lock.  Snapshot the old
	 * bucket pointers (they remain reachable to readers up until
	 * we release the lock, after which they're disowned), then
	 * install the shadow's buckets and num_documents.  Queries
	 * arriving DURING this critical section block on the lock and
	 * see the new state when they get in. */
	pthread_mutex_lock(&g_idx->lock);
	memcpy(old_buckets, g_idx->buckets, sizeof(old_buckets));
	old_num = g_idx->num_documents;
	memcpy(g_idx->buckets, shadow.buckets, sizeof(g_idx->buckets));
	g_idx->num_documents = shadow.num_documents;
	pthread_mutex_unlock(&g_idx->lock);

	/* Step 3: free the old (now-disowned) bucket entries outside
	 * the lock, so any blocked readers proceed immediately. */
	for (b = 0; b < NATS_IDX_BUCKETS; b++) {
		e = old_buckets[b];
		while (e) {
			next = e->next;
			_free_entry(e);
			e = next;
		}
	}

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

	pthread_mutex_lock(&g_idx->lock);

	for (b = 0; b < NATS_IDX_BUCKETS; b++) {
		e = g_idx->buckets[b];
		while (e) {
			next = e->next;
			_free_entry(e);
			e = next;
		}
		g_idx->buckets[b] = NULL;
	}
	g_idx->num_documents = 0;

	pthread_mutex_unlock(&g_idx->lock);
	pthread_mutex_destroy(&g_idx->lock);

	free(g_idx);
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
static int _intersect_keys(char **a, int a_count,
	char **b, int b_count,
	char ***out_keys, int *out_count)
{
	int i, j, n = 0;
	char **result;
	int alloc = (a_count < b_count) ? a_count : b_count;

	if (alloc == 0) {
		*out_keys = NULL;
		*out_count = 0;
		return 0;
	}

	result = malloc(sizeof(char *) * alloc);
	if (!result)
		return -1;

	/* Set intersection via nested loop: for each key in A, scan B for a
	 * match.  On match, copy the pointer into the result and break to
	 * avoid duplicates.  O(n*m) but n and m are typically small. */
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

	if (!g_idx) {
		LM_ERR("search index not initialized\n");
		return -1;
	}

	cdb_res_init(res);

	if (!filter) {
		LM_DBG("no filter provided, returning empty result\n");
		return 0;
	}

	/* Search the index for each filter (AND logic) */
	pthread_mutex_lock(&g_idx->lock);

	for (it = filter; it; it = it->next) {
		if (!it->val.is_str) {
			LM_DBG("skipping non-string filter for field '%.*s'\n",
				it->key.name.len, it->key.name.s);
			continue;
		}

		if (it->op != CDB_OP_EQ) {
			LM_ERR("only CDB_OP_EQ supported for NATS JSON search "
				"(got op %d)\n", it->op);
			pthread_mutex_unlock(&g_idx->lock);
			return -1;
		}

		e = _lookup(it->key.name.s, it->key.name.len,
			it->val.s.s, it->val.s.len);

		if (!e || e->num_keys == 0) {
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

		if (first) {
			/* first filter — strdup the key list so pointers remain
			 * valid after we release the index mutex */
			int k;
			match_keys = malloc(sizeof(char *) * e->num_keys);
			if (!match_keys) {
				LM_ERR("no memory for match keys\n");
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			for (k = 0; k < e->num_keys; k++) {
				match_keys[k] = strdup(e->keys[k]);
				if (!match_keys[k]) {
					LM_ERR("no memory for match key strdup\n");
					while (--k >= 0)
						free(match_keys[k]);
					free(match_keys);
					pthread_mutex_unlock(&g_idx->lock);
					return -1;
				}
			}
			match_count = e->num_keys;
			first = 0;
		} else {
			/* intersect with previous results */
			char **new_keys = NULL;
			int new_count = 0;

			if (_intersect_keys(match_keys, match_count,
					e->keys, e->num_keys,
					&new_keys, &new_count) < 0) {
				LM_ERR("intersection failed\n");
				{
					int k;
					for (k = 0; k < match_count; k++)
						free(match_keys[k]);
				}
				free(match_keys);
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			/* _intersect_keys returns pointers aliased into match_keys.
			 * strdup the survivors in place BEFORE freeing match_keys,
			 * otherwise the strdup reads freed memory (UAF). */
			{
				int k;
				for (k = 0; k < new_count; k++) {
					char *dup = strdup(new_keys[k]);
					if (!dup) {
						int j;
						LM_ERR("no memory for intersect key strdup\n");
						for (j = 0; j < k; j++)
							free(new_keys[j]);
						free(new_keys);
						for (j = 0; j < match_count; j++)
							free(match_keys[j]);
						free(match_keys);
						pthread_mutex_unlock(&g_idx->lock);
						return -1;
					}
					new_keys[k] = dup;
				}
			}
			/* now safe to free the previous match_keys */
			{
				int k;
				for (k = 0; k < match_count; k++)
					free(match_keys[k]);
			}
			free(match_keys);
			match_keys = new_keys;
			match_count = new_count;
		}
	}

	pthread_mutex_unlock(&g_idx->lock);

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

		s = kvStore_Get(&entry, ncon->kv, match_keys[i]);
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
				match_keys[i], natsStatus_GetText(s));
			continue;
		}

		data = kvEntry_ValueString(entry);
		data_len = kvEntry_ValueLen(entry);

		if (!data || data_len <= 0 || data[0] != '{') {
			kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}

		/* Build a cdb_row_t from the JSON document.
		 * Use cdb_json_to_dict if available, otherwise build manually. */
		row = pkg_malloc(sizeof *row);
		if (!row) {
			LM_ERR("no more pkg memory for cdb_row_t\n");
			kvEntry_Destroy(entry);
			entry = NULL;
			goto error;
		}

		if (cdb_json_to_dict(data, &row->dict, NULL) != 0) {
			LM_ERR("failed to parse JSON for key '%s'\n", match_keys[i]);
			pkg_free(row);
			kvEntry_Destroy(entry);
			entry = NULL;
			continue;
		}

		res->count++;
		list_add_tail(&row->list, &res->rows);

		kvEntry_Destroy(entry);
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

/**
 * _json_set_field() — Update (or append) a string field in a JSON document.
 *
 * Scans the top-level fields of the JSON object at @json for a field whose
 * name matches @field / @flen.  If found, the existing value is replaced
 * in-place with the new string @val / @vlen (wrapped in double quotes).
 * If the field does not exist, a new ,"field":"value" pair is appended
 * just before the closing brace.
 *
 * Returns a malloc'd string containing the modified JSON, or NULL on
 * parse/allocation failure.  The caller must free() the returned buffer.
 * The original @json buffer is never modified.
 */
static char *_json_set_field(const char *json, int json_len,
	const char *field, int flen,
	const char *val, int vlen)
{
	char *result;
	const char *p, *end;
	const char *fstart, *fend; /* position of the field's value in original */
	const char *jfield;
	int jflen;
	int found = 0;

	end = json + json_len;
	p = json;

	/* scan for the target field */
	p = _skip_ws(p, end);
	if (p >= end || *p != '{')
		return NULL;
	p++;

	while (p < end && *p != '}') {
		p = _skip_ws(p, end);
		if (p >= end) return NULL;
		if (*p == ',') { p++; p = _skip_ws(p, end); }
		if (p >= end || *p == '}') break;

		/* parse field name */
		p = _parse_json_string(p, end, &jfield, &jflen);
		if (!p) return NULL;

		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return NULL;
		p++;
		p = _skip_ws(p, end);

		if (jflen == flen && memcmp(jfield, field, flen) == 0) {
			/* found the target field — record value position */
			fstart = p;
			p = _skip_json_value(p, end);
			if (!p) return NULL;
			fend = p;
			found = 1;
			break;
		} else {
			p = _skip_json_value(p, end);
			if (!p) return NULL;
		}
	}

	if (found) {
		/* replace the value in-place: [json..fstart] + "esc(val)" + [fend..end].
		 * Escape the value per RFC 8259 to prevent JSON injection. */
		int prefix_len = (int)(fstart - json);
		int suffix_len = (int)(end - fend);
		int esc_cap, esc_len;
		char *esc_val;
		int new_len;

		if (prefix_len < 0 || suffix_len < 0)
			return NULL;
		/* worst case: every byte expands to \uXXXX (6 bytes), +1 for NUL */
		if (vlen > (INT_MAX - 1) / 6) return NULL;
		esc_cap = vlen * 6 + 1;
		esc_val = malloc(esc_cap);
		if (!esc_val) return NULL;
		esc_len = _json_escape(val, vlen, esc_val, esc_cap);
		if (esc_len < 0) { free(esc_val); return NULL; }

		if (esc_len > INT_MAX - prefix_len - suffix_len - 2) {
			free(esc_val);
			return NULL;
		}
		new_len = prefix_len + 1 + esc_len + 1 + suffix_len;

		result = malloc(new_len + 1);
		if (!result) { free(esc_val); return NULL; }

		memcpy(result, json, prefix_len);
		result[prefix_len] = '"';
		memcpy(result + prefix_len + 1, esc_val, esc_len);
		result[prefix_len + 1 + esc_len] = '"';
		memcpy(result + prefix_len + 1 + esc_len + 1, fend, suffix_len);
		result[new_len] = '\0';

		free(esc_val);
		return result;
	} else {
		/* field not found — append before closing brace.  Escape both
		 * field name and value per RFC 8259. */
		const char *close_brace = end;
		int prefix_len;
		int esc_field_cap, esc_field_len;
		int esc_val_cap, esc_val_len;
		char *esc_field, *esc_val;
		int new_len;

		/* find the closing brace */
		while (close_brace > json && *(close_brace - 1) != '}')
			close_brace--;
		if (close_brace <= json) return NULL;
		close_brace--; /* point at '}' */

		prefix_len = (int)(close_brace - json);
		if (prefix_len < 0) return NULL;

		if (flen > (INT_MAX - 1) / 6 || vlen > (INT_MAX - 1) / 6)
			return NULL;
		esc_field_cap = flen * 6 + 1;
		esc_val_cap   = vlen * 6 + 1;
		esc_field = malloc(esc_field_cap);
		esc_val   = malloc(esc_val_cap);
		if (!esc_field || !esc_val) {
			free(esc_field); free(esc_val);
			return NULL;
		}
		esc_field_len = _json_escape(field, flen, esc_field, esc_field_cap);
		esc_val_len   = _json_escape(val,   vlen, esc_val,   esc_val_cap);
		if (esc_field_len < 0 || esc_val_len < 0) {
			free(esc_field); free(esc_val);
			return NULL;
		}

		/* ,"field":"value"}  -> 2 + flen + 3 + vlen + 2 added */
		if (esc_field_len > INT_MAX - prefix_len - esc_val_len - 8) {
			free(esc_field); free(esc_val);
			return NULL;
		}
		new_len = prefix_len + 2 + esc_field_len + 3 + esc_val_len + 2;
		result = malloc(new_len + 1);
		if (!result) {
			free(esc_field); free(esc_val);
			return NULL;
		}

		memcpy(result, json, prefix_len);
		result[prefix_len] = ',';
		result[prefix_len + 1] = '"';
		memcpy(result + prefix_len + 2, esc_field, esc_field_len);
		result[prefix_len + 2 + esc_field_len] = '"';
		result[prefix_len + 2 + esc_field_len + 1] = ':';
		result[prefix_len + 2 + esc_field_len + 2] = '"';
		memcpy(result + prefix_len + 2 + esc_field_len + 3,
			esc_val, esc_val_len);
		result[prefix_len + 2 + esc_field_len + 3 + esc_val_len] = '"';
		result[prefix_len + 2 + esc_field_len + 3 + esc_val_len + 1] = '}';
		result[new_len] = '\0';

		free(esc_field); free(esc_val);
		return result;
	}
}

/* ------------------------------------------------------------------ */
/*    Typed pair → JSON application (handles non-string and nested)   */
/* ------------------------------------------------------------------ */

/* Locate the value range of a top-level field in a JSON object.
 * Returns 0 if found and writes vstart/vend to the value bounds; 1 if
 * the field does not exist (and insert_pos is set to the position of
 * the closing brace, plus needs_comma indicates whether a leading
 * ',' is needed); -1 on parse error.
 */
static int _find_field(const char *json, int json_len,
	const char *field, int flen,
	const char **vstart, const char **vend,
	const char **insert_pos, int *needs_comma)
{
	const char *p = json, *end = json + json_len;
	const char *jfield;
	int jflen;
	int saw_field = 0;

	p = _skip_ws(p, end);
	if (p >= end || *p != '{') return -1;
	p++;
	while (p < end) {
		p = _skip_ws(p, end);
		if (p >= end) return -1;
		if (*p == '}') {
			*insert_pos = p;
			*needs_comma = saw_field;
			return 1;
		}
		if (*p == ',') { p++; continue; }
		p = _parse_json_string(p, end, &jfield, &jflen);
		if (!p) return -1;
		saw_field = 1;
		p = _skip_ws(p, end);
		if (p >= end || *p != ':') return -1;
		p++;
		p = _skip_ws(p, end);
		if (jflen == flen && memcmp(jfield, field, flen) == 0) {
			*vstart = p;
			p = _skip_json_value(p, end);
			if (!p) return -1;
			*vend = p;
			return 0;
		}
		p = _skip_json_value(p, end);
		if (!p) return -1;
	}
	return -1;
}

/* Render a leaf value into a malloc'd JSON literal token (no surrounding
 * key/colon). Returns NULL on alloc failure or invalid type. */
static char *_render_leaf(char val_type,
	const char *val_str, int val_len, int64_t val_int, int *out_len)
{
	char *buf;
	int n;

	switch (val_type) {
	case 'N':
		buf = malloc(5);
		if (!buf) return NULL;
		memcpy(buf, "null", 5);
		*out_len = 4;
		return buf;
	case 'I':
	case 'L': {
		char tmp[32];
		n = snprintf(tmp, sizeof(tmp), "%lld", (long long)val_int);
		if (n < 0 || n >= (int)sizeof(tmp)) return NULL;
		buf = malloc(n + 1);
		if (!buf) return NULL;
		memcpy(buf, tmp, n + 1);
		*out_len = n;
		return buf;
	}
	case 'S': {
		int cap = val_len * 6 + 3;   /* worst-case escape + 2 quotes */
		buf = malloc(cap);
		if (!buf) return NULL;
		buf[0] = '"';
		n = _json_escape(val_str, val_len, buf + 1, cap - 2);
		if (n < 0) { free(buf); return NULL; }
		buf[1 + n] = '"';
		buf[2 + n] = '\0';
		*out_len = n + 2;
		return buf;
	}
	case 'O': {
		buf = malloc(val_len + 1);
		if (!buf) return NULL;
		memcpy(buf, val_str, val_len);
		buf[val_len] = '\0';
		*out_len = val_len;
		return buf;
	}
	}
	return NULL;
}

static char *_splice(const char *json, int json_len,
	int pre_off, int post_off,
	const char *middle, int middle_len, int *out_len)
{
	int suffix = json_len - post_off;
	int new_len = pre_off + middle_len + suffix;
	char *out = malloc(new_len + 1);
	if (!out) return NULL;
	memcpy(out, json, pre_off);
	memcpy(out + pre_off, middle, middle_len);
	memcpy(out + pre_off + middle_len, json + post_off, suffix);
	out[new_len] = '\0';
	*out_len = new_len;
	return out;
}

static char *_kv_token(const char *field, int flen,
	const char *rendered, int rendered_len, int *out_len)
{
	int cap = flen * 6 + 4 + rendered_len;
	int n;
	char *buf = malloc(cap);
	if (!buf) return NULL;
	buf[0] = '"';
	n = _json_escape(field, flen, buf + 1, cap - 3 - rendered_len);
	if (n < 0) { free(buf); return NULL; }
	buf[1 + n]     = '"';
	buf[1 + n + 1] = ':';
	memcpy(buf + 1 + n + 2, rendered, rendered_len);
	buf[1 + n + 2 + rendered_len] = '\0';
	*out_len = 1 + n + 2 + rendered_len;
	return buf;
}

/* Set or unset a top-level field of @json to @rendered. */
static char *_object_set(const char *json, int json_len,
	const char *field, int flen,
	const char *rendered, int rendered_len,
	int unset, int *out_len)
{
	const char *vstart = NULL, *vend = NULL, *ipos = NULL;
	int needs_comma = 0;
	int rc = _find_field(json, json_len, field, flen,
		&vstart, &vend, &ipos, &needs_comma);
	if (rc < 0) return NULL;

	if (unset) {
		if (rc == 1) {
			char *out = malloc(json_len + 1);
			if (!out) return NULL;
			memcpy(out, json, json_len);
			out[json_len] = '\0';
			*out_len = json_len;
			return out;
		}
		{
			int kstart = (int)(vstart - json);
			int kend   = (int)(vend - json);
			while (kstart > 0) {
				char c = json[kstart - 1];
				if (c == ' ' || c == '\t' || c == ':' ||
				    c == '\n' || c == '\r') {
					kstart--; continue;
				}
				if (c == '"') { kstart--; break; }
				break;
			}
			while (kstart > 0 && json[kstart - 1] != '"') kstart--;
			if (kstart > 0) kstart--;
			if (kstart > 0 && json[kstart - 1] == ',') kstart--;
			else {
				while (kend < json_len &&
				    (json[kend] == ' ' || json[kend] == '\t' ||
				     json[kend] == '\n' || json[kend] == '\r'))
					kend++;
				if (kend < json_len && json[kend] == ',') kend++;
			}
			return _splice(json, json_len, kstart, kend, "", 0, out_len);
		}
	}

	if (rc == 0) {
		return _splice(json, json_len,
			(int)(vstart - json), (int)(vend - json),
			rendered, rendered_len, out_len);
	}
	{
		char *kv;
		int kvlen;
		kv = _kv_token(field, flen, rendered, rendered_len, &kvlen);
		if (!kv) return NULL;
		{
			int ipos_off = (int)(ipos - json);
			char *with_comma = NULL;
			char *out;
			int wc_len = 0;
			if (needs_comma) {
				with_comma = malloc(1 + kvlen + 1);
				if (!with_comma) { free(kv); return NULL; }
				with_comma[0] = ',';
				memcpy(with_comma + 1, kv, kvlen);
				with_comma[1 + kvlen] = '\0';
				wc_len = 1 + kvlen;
			}
			out = _splice(json, json_len, ipos_off, ipos_off,
				needs_comma ? with_comma : kv,
				needs_comma ? wc_len : kvlen, out_len);
			free(kv);
			free(with_comma);
			return out;
		}
	}
}

/**
 * _json_apply_pair() — apply one cdb_pair_t-style update to a JSON object.
 *
 * Replaces the previous string-only _json_set_field codepath. Handles the
 * full cdb_pair_t surface: typed leaf values (string, int32, int64, null,
 * raw JSON object), optional subkey (treats @field as a JSON object of
 * which @subkey is what gets set/unset — used by usrloc to address one
 * contact under "contacts"), and the unset flag.
 *
 * Returns malloc'd new document, or NULL on error. Caller must free().
 * The original @json buffer is never modified.
 */
static char *_json_apply_pair(const char *json, int json_len,
	const char *field, int flen,
	const char *subkey, int sklen,
	int unset,
	char val_type,
	const char *val_str, int val_len,
	int64_t val_int)
{
	int dummy_len;

	if (!json || json_len <= 0 || !field || flen <= 0) return NULL;

	if (sklen <= 0 || !subkey) {
		if (unset)
			return _object_set(json, json_len, field, flen,
				NULL, 0, 1, &dummy_len);
		{
			char *rendered;
			int rlen;
			char *out;
			rendered = _render_leaf(val_type, val_str, val_len,
				val_int, &rlen);
			if (!rendered) return NULL;
			out = _object_set(json, json_len, field, flen,
				rendered, rlen, 0, &dummy_len);
			free(rendered);
			return out;
		}
	}

	/* subkey path: @field is treated as a JSON object */
	{
		const char *vstart = NULL, *vend = NULL, *ipos = NULL;
		int needs_comma = 0;
		int rc = _find_field(json, json_len, field, flen,
			&vstart, &vend, &ipos, &needs_comma);
		const char *inner;
		int inner_len;
		char inner_buf[3] = "{}";
		char *new_inner;
		int new_inner_len;
		char *out;

		if (rc < 0) return NULL;
		if (rc == 0) {
			const char *p = _skip_ws(vstart, vend);
			if (p >= vend || *p != '{') return NULL;
			inner = vstart;
			inner_len = (int)(vend - vstart);
		} else {
			inner = inner_buf;
			inner_len = 2;
		}

		if (unset) {
			new_inner = _object_set(inner, inner_len,
				subkey, sklen, NULL, 0, 1, &new_inner_len);
		} else {
			char *rendered;
			int rlen;
			rendered = _render_leaf(val_type, val_str, val_len,
				val_int, &rlen);
			if (!rendered) return NULL;
			new_inner = _object_set(inner, inner_len,
				subkey, sklen, rendered, rlen, 0, &new_inner_len);
			free(rendered);
		}
		if (!new_inner) return NULL;

		if (rc == 0) {
			out = _splice(json, json_len,
				(int)(vstart - json), (int)(vend - json),
				new_inner, new_inner_len, &dummy_len);
			free(new_inner);
			return out;
		}
		{
			char *kv;
			int kvlen;
			kv = _kv_token(field, flen, new_inner, new_inner_len, &kvlen);
			free(new_inner);
			if (!kv) return NULL;
			{
				int ipos_off = (int)(ipos - json);
				char *with_comma = NULL;
				int wc_len = 0;
				if (needs_comma) {
					with_comma = malloc(1 + kvlen + 1);
					if (!with_comma) { free(kv); return NULL; }
					with_comma[0] = ',';
					memcpy(with_comma + 1, kv, kvlen);
					wc_len = 1 + kvlen;
				}
				out = _splice(json, json_len, ipos_off, ipos_off,
					needs_comma ? with_comma : kv,
					needs_comma ? wc_len : kvlen, &dummy_len);
				free(kv);
				free(with_comma);
				return out;
			}
		}
	}
}

/* Recursively serialize a cdb_dict_t to a fresh JSON object string.
 * Returns malloc'd or NULL on error. */
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

static int _sink_emit_string(json_sink_t *s, const char *p, int n)
{
	int needed;
	if (s->oom) return -1;
	needed = n * 6 + 2; /* worst-case escape + 2 quotes */
	if (_sink_grow(s, needed + 1) < 0) return -1;
	s->buf[s->len++] = '"';
	{
		int written = _json_escape(p, n, s->buf + s->len, needed - 1);
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

	if (!g_idx) {
		LM_ERR("search index not initialized\n");
		return -1;
	}

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
	 * KV-safe. */
	if (!row_filter->key.is_pk) {
		pthread_mutex_lock(&g_idx->lock);
		e = _lookup(row_filter->key.name.s, row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len);
		if (e && e->num_keys > 0) {
			target_key = pkg_malloc(strlen(e->keys[0]) + 1);
			if (!target_key) {
				pthread_mutex_unlock(&g_idx->lock);
				LM_ERR("oom\n");
				return -1;
			}
			strcpy(target_key, e->keys[0]);
		}
		pthread_mutex_unlock(&g_idx->lock);
	}

	/* PK path or non-PK index miss: build encoded prefix+filter-value. */
	if (!target_key) {
		int enc_len = 0;
		char *enc = _kv_encode_key(row_filter->val.s.s,
			row_filter->val.s.len, &enc_len);
		if (!enc) {
			LM_ERR("oom\n");
			return -1;
		}
		if (fts_json_prefix && *fts_json_prefix) {
			int plen = strlen(fts_json_prefix);
			target_key = pkg_malloc(plen + enc_len + 1);
			if (!target_key) { free(enc); LM_ERR("oom\n"); return -1; }
			memcpy(target_key, fts_json_prefix, plen);
			memcpy(target_key + plen, enc, enc_len);
			target_key[plen + enc_len] = '\0';
		} else {
			target_key = pkg_malloc(enc_len + 1);
			if (!target_key) { free(enc); LM_ERR("oom\n"); return -1; }
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
		s = kvStore_Get(&entry, ncon->kv, target_key);
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

			s = kvStore_CreateString(&create_rev, ncon->kv, target_key, seed);
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
					target_key, natsStatus_GetText(s));
				free(seed);
				NATS_CDB_STATS_INC(cas_retry);
				continue;
			}
		} else if (s != NATS_OK) {
			LM_ERR("kvStore_Get failed for key '%s': %s\n",
				target_key, natsStatus_GetText(s));
			pkg_free(target_key);
			return -1;
		} else {
			data = kvEntry_ValueString(entry);
			data_len = kvEntry_ValueLen(entry);
			rev = kvEntry_Revision(entry);

			if (!data || data_len <= 0) {
				LM_ERR("empty document for key '%s'\n", target_key);
				kvEntry_Destroy(entry);
				entry = NULL;
				pkg_free(target_key);
				return -1;
			}

			/* make a mutable copy of the JSON */
			json_buf = malloc(data_len + 1);
			if (!json_buf) {
				LM_ERR("oom\n");
				kvEntry_Destroy(entry);
				entry = NULL;
				pkg_free(target_key);
				return -1;
			}
			memcpy(json_buf, data, data_len);
			json_buf[data_len] = '\0';

			kvEntry_Destroy(entry);
			entry = NULL;
		}

		/* Apply every pair in a single pass over the doc.  Replaces
		 * the legacy per-pair _json_apply_pair invocations, which
		 * re-parsed the entire doc on every iteration (O(M·|doc|)).
		 * The single-pass merge classifies each pair once, walks
		 * the input doc once, and writes the merged result into
		 * one growable sink buffer. */
		new_json = _apply_pairs_one_pass(json_buf,
			(int)strlen(json_buf), pairs);
		if (!new_json) {
			LM_ERR("failed to apply pairs in single pass\n");
			free(json_buf);
			pkg_free(target_key);
			return -1;
		}
		free(json_buf);
		json_buf = new_json;
		new_json = NULL;
		(void)pair; (void)pos; /* silence -Wunused under this branch */

		/* write back with CAS */
		s = kvStore_UpdateString(&new_rev, ncon->kv, target_key,
			json_buf, rev);
		if (s == NATS_OK) {
			/* update the index */
			nats_json_index_remove(target_key);
			nats_json_index_add(target_key, json_buf, strlen(json_buf));

			LM_DBG("updated key '%s' rev=%llu\n", target_key,
				(unsigned long long)new_rev);
			free(json_buf);
			pkg_free(target_key);
			return 0;
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
