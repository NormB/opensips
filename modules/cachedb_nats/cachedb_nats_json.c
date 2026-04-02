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
#include "cachedb_nats_dbase.h"

/* module parameters (defined in cachedb_nats.c) */
extern char *fts_json_prefix;
extern int   fts_max_results;

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
static nats_idx_entry *_find_entry(const char *fv, int fv_len)
{
	unsigned int bucket = _hash(fv, fv_len);
	nats_idx_entry *e;

	/* Walk the separate-chaining linked list for this bucket.
	 * Each bucket head is g_idx->buckets[bucket]; collisions are
	 * linked via e->next (LIFO insertion order). */
	for (e = g_idx->buckets[bucket]; e; e = e->next) {
		if (e->fv_len == (unsigned int)fv_len
				&& memcmp(e->field_value, fv, fv_len) == 0)
			return e;
	}
	return NULL;
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
static nats_idx_entry *_get_or_create_entry(const char *fv, int fv_len)
{
	nats_idx_entry *e;
	unsigned int bucket;

	e = _find_entry(fv, fv_len);
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

	/* Insert at head of this bucket's chain (LIFO order).
	 * The new entry's next pointer takes the current head, then
	 * the bucket head is updated to point to the new entry. */
	bucket = _hash(fv, fv_len);
	e->next = g_idx->buckets[bucket];
	g_idx->buckets[bucket] = e;

	return e;
}

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
	const char *doc_key;  /* the KV key for this document */
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

	e = _get_or_create_entry(fv_buf, fv_len);
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
	unsigned int b;
	nats_idx_entry *e, *next;

	if (!g_idx)
		return -1;

	LM_INFO("rebuilding search index...\n");

	/* clear all entries */
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

	/* rebuild from KV data */
	return nats_json_index_build(kv, prefix);
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
				free(match_keys);
				match_keys = NULL;
			}
			match_count = 0;
			break;
		}

		if (first) {
			/* first filter — copy the key list */
			match_keys = malloc(sizeof(char *) * e->num_keys);
			if (!match_keys) {
				LM_ERR("no memory for match keys\n");
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			memcpy(match_keys, e->keys, sizeof(char *) * e->num_keys);
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
				free(match_keys);
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			free(match_keys);
			match_keys = new_keys;
			match_count = new_count;
		}
	}

	pthread_mutex_unlock(&g_idx->lock);

	if (match_count == 0) {
		LM_DBG("no documents match the filter\n");
		if (match_keys)
			free(match_keys);
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
		if (s != NATS_OK) {
			LM_DBG("skipping key '%s': %s\n",
				match_keys[i], natsStatus_GetText(s));
			continue;
		}

		data = kvEntry_ValueString(entry);
		data_len = kvEntry_ValueLen(entry);

		if (!data || data_len <= 0 || data[0] != '{') {
			kvEntry_Destroy(entry);
			continue;
		}

		/* Build a cdb_row_t from the JSON document.
		 * Use cdb_json_to_dict if available, otherwise build manually. */
		row = pkg_malloc(sizeof *row);
		if (!row) {
			LM_ERR("no more pkg memory for cdb_row_t\n");
			kvEntry_Destroy(entry);
			goto error;
		}

		if (cdb_json_to_dict(data, &row->dict, NULL) != 0) {
			LM_ERR("failed to parse JSON for key '%s'\n", match_keys[i]);
			pkg_free(row);
			kvEntry_Destroy(entry);
			continue;
		}

		res->count++;
		list_add_tail(&row->list, &res->rows);

		kvEntry_Destroy(entry);
		entry = NULL;
	}

	LM_DBG("query returned %d rows\n", res->count);
	free(match_keys);
	return 0;

error:
	free(match_keys);
	cdb_free_rows(res);
	return -1;
}

/* ------------------------------------------------------------------ */
/*                   cachedb update() callback                        */
/* ------------------------------------------------------------------ */

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
		/* replace the value in-place: [json..fstart] + "new_val" + [fend..end] */
		int prefix_len = (int)(fstart - json);
		int suffix_len = (int)(end - fend);

		/* guard against integer overflow in the length computation */
		if (prefix_len < 0 || suffix_len < 0 ||
				vlen > INT_MAX - prefix_len - suffix_len - 2)
			return NULL;

		int new_len = prefix_len + 1 + vlen + 1 + suffix_len;

		result = malloc(new_len + 1);
		if (!result) return NULL;

		memcpy(result, json, prefix_len);
		result[prefix_len] = '"';
		memcpy(result + prefix_len + 1, val, vlen);
		result[prefix_len + 1 + vlen] = '"';
		memcpy(result + prefix_len + 1 + vlen + 1, fend, suffix_len);
		result[new_len] = '\0';

		return result;
	} else {
		/* field not found — append before closing brace */
		const char *close_brace = end;
		int prefix_len;
		int new_len;

		/* find the closing brace */
		while (close_brace > json && *(close_brace - 1) != '}')
			close_brace--;
		if (close_brace <= json) return NULL;
		close_brace--; /* point at '}' */

		prefix_len = (int)(close_brace - json);

		/* ,"field":"value"} */
		new_len = prefix_len + 2 + flen + 3 + vlen + 2;
		result = malloc(new_len + 1);
		if (!result) return NULL;

		memcpy(result, json, prefix_len);
		result[prefix_len] = ',';
		result[prefix_len + 1] = '"';
		memcpy(result + prefix_len + 2, field, flen);
		result[prefix_len + 2 + flen] = '"';
		result[prefix_len + 2 + flen + 1] = ':';
		result[prefix_len + 2 + flen + 2] = '"';
		memcpy(result + prefix_len + 2 + flen + 3, val, vlen);
		result[prefix_len + 2 + flen + 3 + vlen] = '"';
		result[prefix_len + 2 + flen + 3 + vlen + 1] = '}';
		result[new_len] = '\0';

		return result;
	}
}

/**
 * nats_cache_update() — cachedb update callback: modify matched documents.
 *
 * Identifies the target document either by primary key (is_pk flag on the
 * filter) or by index lookup (same mechanism as nats_cache_query, but only
 * the first match is used).  Fetches the document from NATS KV, applies
 * each field update from @pairs via _json_set_field(), and writes the
 * modified JSON back using a compare-and-swap (CAS) loop to handle
 * concurrent modifications.  After a successful CAS, the index is updated
 * by removing and re-adding the document.
 *
 * Only string-valued pairs are applied; non-string pairs are skipped.
 * Retries up to NATS_CAS_RETRIES times on CAS conflict.
 *
 * Returns 0 on success, -1 on error or CAS exhaustion.
 */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
	const cdb_dict_t *pairs)
{
	nats_cachedb_con *ncon;
	const cdb_filter_t *it;
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

	/* The row_filter identifies the target document.
	 * If is_pk is set, the value IS the key directly.
	 * Otherwise, use the index to find the key. */
	if (row_filter->key.is_pk) {
		if (!row_filter->val.is_str) {
			LM_ERR("PK filter must have string value\n");
			return -1;
		}
		/* Build the full KV key with prefix */
		if (fts_json_prefix && *fts_json_prefix) {
			int prefix_len = strlen(fts_json_prefix);
			target_key = pkg_malloc(prefix_len + row_filter->val.s.len + 1);
			if (!target_key) {
				LM_ERR("oom\n");
				return -1;
			}
			memcpy(target_key, fts_json_prefix, prefix_len);
			memcpy(target_key + prefix_len, row_filter->val.s.s,
				row_filter->val.s.len);
			target_key[prefix_len + row_filter->val.s.len] = '\0';
		} else {
			target_key = pkg_malloc(row_filter->val.s.len + 1);
			if (!target_key) {
				LM_ERR("oom\n");
				return -1;
			}
			memcpy(target_key, row_filter->val.s.s, row_filter->val.s.len);
			target_key[row_filter->val.s.len] = '\0';
		}
	} else {
		/* Use index to find matching document */
		if (!row_filter->val.is_str || row_filter->op != CDB_OP_EQ) {
			LM_ERR("unsupported filter for update\n");
			return -1;
		}

		pthread_mutex_lock(&g_idx->lock);
		e = _lookup(row_filter->key.name.s, row_filter->key.name.len,
			row_filter->val.s.s, row_filter->val.s.len);
		if (!e || e->num_keys == 0) {
			pthread_mutex_unlock(&g_idx->lock);
			LM_DBG("no document matches filter\n");
			return -1;
		}
		/* take the first matching key */
		target_key = pkg_malloc(strlen(e->keys[0]) + 1);
		if (!target_key) {
			pthread_mutex_unlock(&g_idx->lock);
			LM_ERR("oom\n");
			return -1;
		}
		strcpy(target_key, e->keys[0]);
		pthread_mutex_unlock(&g_idx->lock);
	}

	/* CAS loop: fetch, modify, update atomically */
	retries = NATS_CAS_RETRIES;
	while (retries-- > 0) {
		s = kvStore_Get(&entry, ncon->kv, target_key);
		if (s != NATS_OK) {
			LM_ERR("kvStore_Get failed for key '%s': %s\n",
				target_key, natsStatus_GetText(s));
			pkg_free(target_key);
			return -1;
		}

		data = kvEntry_ValueString(entry);
		data_len = kvEntry_ValueLen(entry);
		rev = kvEntry_Revision(entry);

		if (!data || data_len <= 0) {
			LM_ERR("empty document for key '%s'\n", target_key);
			kvEntry_Destroy(entry);
			pkg_free(target_key);
			return -1;
		}

		/* make a mutable copy of the JSON */
		json_buf = malloc(data_len + 1);
		if (!json_buf) {
			LM_ERR("oom\n");
			kvEntry_Destroy(entry);
			pkg_free(target_key);
			return -1;
		}
		memcpy(json_buf, data, data_len);
		json_buf[data_len] = '\0';

		kvEntry_Destroy(entry);
		entry = NULL;

		/* apply each pair update */
		list_for_each(pos, pairs) {
			pair = list_entry(pos, cdb_pair_t, list);

			if (pair->val.type != CDB_STR) {
				LM_DBG("skipping non-string pair '%.*s'\n",
					pair->key.name.len, pair->key.name.s);
				continue;
			}

			new_json = _json_set_field(json_buf, strlen(json_buf),
				pair->key.name.s, pair->key.name.len,
				pair->val.val.st.s, pair->val.val.st.len);
			if (!new_json) {
				LM_ERR("failed to update field '%.*s'\n",
					pair->key.name.len, pair->key.name.s);
				free(json_buf);
				pkg_free(target_key);
				return -1;
			}
			free(json_buf);
			json_buf = new_json;
			new_json = NULL;
		}

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

		LM_DBG("CAS retry for key '%s'\n", target_key);
	}

	LM_ERR("CAS failed after retries for key '%s'\n", target_key);
	pkg_free(target_key);
	return -1;
}
