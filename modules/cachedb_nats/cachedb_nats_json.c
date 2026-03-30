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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

nats_search_idx *nats_json_get_index(void)
{
	return g_idx;
}

/* ------------------------------------------------------------------ */
/*                       djb2 hash function                           */
/* ------------------------------------------------------------------ */

static unsigned int _hash(const char *s, int len)
{
	unsigned int h = 5381;
	int i;
	for (i = 0; i < len; i++)
		h = ((h << 5) + h) + (unsigned char)s[i];
	return h % NATS_IDX_BUCKETS;
}

/* ------------------------------------------------------------------ */
/*                    Simple JSON field parser                         */
/* ------------------------------------------------------------------ */

/**
 * Skip whitespace in a JSON string.
 */
static const char *_skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	return p;
}

/**
 * Parse a JSON quoted string. Returns pointer past closing quote.
 * Writes the unescaped string start into *out and length into *out_len.
 * The string is NOT null-terminated (points into the original buffer).
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
 * Skip a JSON value (string, number, object, array, bool, null).
 * Returns pointer past the value.
 */
static const char *_skip_json_value(const char *p, const char *end)
{
	int depth;

	p = _skip_ws(p, end);
	if (p >= end)
		return NULL;

	switch (*p) {
	case '"': /* string */
		p++;
		while (p < end && *p != '"') {
			if (*p == '\\') {
				p++;
				if (p >= end) return NULL;
			}
			p++;
		}
		return (p < end) ? p + 1 : NULL;

	case '{': /* object */
	case '[': /* array */
		depth = 1;
		p++;
		while (p < end && depth > 0) {
			if (*p == '{' || *p == '[') depth++;
			else if (*p == '}' || *p == ']') depth--;
			else if (*p == '"') {
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

	default: /* number, bool, null */
		while (p < end && *p != ',' && *p != '}' && *p != ']'
				&& *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
			p++;
		return p;
	}
}

/**
 * Parse top-level string fields from a JSON object.
 * Calls callback for each "field":"value" pair found at the top level.
 * Only processes string values; non-string values are skipped.
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
			/* string value — parse and invoke callback */
			p = _parse_json_string(p, end, &val, &vlen);
			if (!p)
				return -1;
			callback(field, flen, val, vlen, ctx);
			count++;
		} else {
			/* non-string value — skip */
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
 * Find an index entry for a given field:value string.
 * Must be called with the lock held.
 */
static nats_idx_entry *_find_entry(const char *fv, int fv_len)
{
	unsigned int bucket = _hash(fv, fv_len);
	nats_idx_entry *e;

	for (e = g_idx->buckets[bucket]; e; e = e->next) {
		if (e->fv_len == (unsigned int)fv_len
				&& memcmp(e->field_value, fv, fv_len) == 0)
			return e;
	}
	return NULL;
}

/**
 * Create or find an index entry for a field:value string.
 * Must be called with the lock held.
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

	bucket = _hash(fv, fv_len);
	e->next = g_idx->buckets[bucket];
	g_idx->buckets[bucket] = e;

	return e;
}

/**
 * Add a key to an index entry's key list.
 * Must be called with the lock held. Skips duplicates.
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

	/* grow array if needed */
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
 * Remove a key from an index entry's key list.
 * Must be called with the lock held.
 */
static void _entry_remove_key(nats_idx_entry *e, const char *key)
{
	int i;
	for (i = 0; i < e->num_keys; i++) {
		if (strcmp(e->keys[i], key) == 0) {
			free(e->keys[i]);
			/* shift remaining keys down */
			e->num_keys--;
			if (i < e->num_keys)
				e->keys[i] = e->keys[e->num_keys];
			return;
		}
	}
}

/**
 * Free a single index entry and all its data.
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
 * Callback from _parse_json_fields — add field:value to the index.
 */
static void _index_field_cb(const char *field, int flen,
	const char *val, int vlen, void *ctx)
{
	idx_add_ctx *actx = (idx_add_ctx *)ctx;
	char fv_buf[1024];
	int fv_len;
	nats_idx_entry *e;

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

int nats_json_index_remove(const char *key)
{
	unsigned int b;
	nats_idx_entry *e;

	if (!g_idx || !key)
		return -1;

	pthread_mutex_lock(&g_idx->lock);

	{
		int found = 0;
		for (b = 0; b < NATS_IDX_BUCKETS; b++) {
			for (e = g_idx->buckets[b]; e; e = e->next) {
				int old_cnt = e->num_keys;
				_entry_remove_key(e, key);
				if (e->num_keys < old_cnt)
					found = 1;
			}
		}
		if (found && g_idx->num_documents > 0)
			g_idx->num_documents--;
	}

	pthread_mutex_unlock(&g_idx->lock);

	LM_DBG("removed key '%s' from index\n", key);
	return 0;
}

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
 * Look up matching document keys for a field:value combination.
 * Returns the index entry (or NULL). Caller must hold the lock.
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
 * Intersect two sorted-ish key arrays. Puts the intersection result
 * into out_keys/out_count. out_keys points into existing entry data.
 * Caller must free out_keys array (but not the strings in it).
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

	/* simple O(n*m) intersection — fine for typical document counts */
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
				for (i = 0; i < match_count; i++)
					free(match_keys[i]);
				free(match_keys);
				match_keys = NULL;
			}
			match_count = 0;
			break;
		}

		if (first) {
			/* first filter — strdup each key so we can safely
			 * use them after releasing the index lock */
			match_keys = malloc(sizeof(char *) * e->num_keys);
			if (!match_keys) {
				LM_ERR("no memory for match keys\n");
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			for (i = 0; i < e->num_keys; i++) {
				match_keys[i] = strdup(e->keys[i]);
				if (!match_keys[i]) {
					int k;
					for (k = 0; k < i; k++)
						free(match_keys[k]);
					free(match_keys);
					LM_ERR("no memory for key strdup\n");
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
				for (i = 0; i < match_count; i++)
					free(match_keys[i]);
				free(match_keys);
				pthread_mutex_unlock(&g_idx->lock);
				return -1;
			}
			/* free non-matching strdup'd keys from previous set */
			for (i = 0; i < match_count; i++) {
				int found = 0, k;
				for (k = 0; k < new_count; k++) {
					if (new_keys[k] == match_keys[i]) {
						found = 1;
						break;
					}
				}
				if (!found)
					free(match_keys[i]);
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
			/* match_keys may still have strdup'd strings if break
			 * was hit on a subsequent filter (count was set to 0
			 * but the array was already freed above). Safe no-op. */
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
	for (i = 0; i < match_count; i++)
		free(match_keys[i]);
	free(match_keys);
	return 0;

error:
	for (i = 0; i < match_count; i++)
		free(match_keys[i]);
	free(match_keys);
	cdb_free_rows(res);
	return -1;
}

/* ------------------------------------------------------------------ */
/*                   cachedb update() callback                        */
/* ------------------------------------------------------------------ */

/**
 * Compute the length of a JSON-escaped version of a string.
 * Escapes: " \ and control chars (< 0x20).
 */
static int _json_escaped_len(const char *s, int len)
{
	int i, elen = 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\')
			elen += 2;
		else if (c < 0x20)
			elen += 6; /* \uXXXX */
		else
			elen += 1;
	}
	return elen;
}

/**
 * Write JSON-escaped string into dst. Returns number of bytes written.
 * Caller must ensure dst has at least _json_escaped_len(s, len) bytes.
 */
static int _json_escape(char *dst, const char *s, int len)
{
	int i, pos = 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\') {
			dst[pos++] = '\\';
			dst[pos++] = (char)c;
		} else if (c < 0x20) {
			pos += snprintf(dst + pos, 7, "\\u%04x", c);
		} else {
			dst[pos++] = (char)c;
		}
	}
	return pos;
}

/**
 * Simple JSON field updater.
 * Given a JSON string and a field name + new value, produce a new JSON
 * string with that field replaced (or appended). Values are properly
 * JSON-escaped.
 *
 * Returns a malloc'd string or NULL on failure. Caller must free().
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

	{
		int escaped_vlen = _json_escaped_len(val, vlen);

		if (found) {
			/* replace the value: [json..fstart] + "escaped_val" + [fend..end] */
			int prefix_len = (int)(fstart - json);
			int suffix_len = (int)(end - fend);
			int new_len = prefix_len + 1 + escaped_vlen + 1 + suffix_len;
			int pos;

			result = malloc(new_len + 1);
			if (!result) return NULL;

			memcpy(result, json, prefix_len);
			pos = prefix_len;
			result[pos++] = '"';
			pos += _json_escape(result + pos, val, vlen);
			result[pos++] = '"';
			memcpy(result + pos, fend, suffix_len);
			pos += suffix_len;
			result[pos] = '\0';

			return result;
		} else {
			/* field not found — append before closing brace */
			const char *close_brace = end;
			int prefix_len;
			int new_len;
			int pos;

			/* find the closing brace */
			while (close_brace > json && *(close_brace - 1) != '}')
				close_brace--;
			if (close_brace <= json) return NULL;
			close_brace--; /* point at '}' */

			prefix_len = (int)(close_brace - json);

			/* ,"field":"escaped_value"} */
			new_len = prefix_len + 2 + flen + 3 + escaped_vlen + 2;
			result = malloc(new_len + 1);
			if (!result) return NULL;

			memcpy(result, json, prefix_len);
			pos = prefix_len;
			result[pos++] = ',';
			result[pos++] = '"';
			memcpy(result + pos, field, flen);
			pos += flen;
			result[pos++] = '"';
			result[pos++] = ':';
			result[pos++] = '"';
			pos += _json_escape(result + pos, val, vlen);
			result[pos++] = '"';
			result[pos++] = '}';
			result[pos] = '\0';

			return result;
		}
	}
}

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
