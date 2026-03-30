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

#ifndef CACHEDB_NATS_JSON_H
#define CACHEDB_NATS_JSON_H

#include <nats/nats.h>
#include "../../cachedb/cachedb.h"
#include <pthread.h>

/* Index entry — one per unique field:value combination */
typedef struct _nats_idx_entry {
	char *field_value;          /* "field:value" string (heap allocated) */
	unsigned int fv_len;        /* length of field_value */
	char **keys;                /* array of document keys */
	int num_keys;
	int alloc_keys;
	struct _nats_idx_entry *next; /* hash bucket chain */
} nats_idx_entry;

/* Search index — hash table with mutex for thread safety */
#define NATS_IDX_BUCKETS 256

typedef struct _nats_search_idx {
	nats_idx_entry *buckets[NATS_IDX_BUCKETS];
	int num_documents;
	pthread_mutex_t lock;       /* protects index during watcher updates */
} nats_search_idx;

/* Initialize the search index (called in child_init) */
int nats_json_index_init(void);

/* Build index from existing KV data */
int nats_json_index_build(kvStore *kv, const char *prefix);

/* Clear and rebuild index (used after reconnection) */
int nats_json_index_rebuild(kvStore *kv, const char *prefix);

/* Add a document to the index */
int nats_json_index_add(const char *key, const char *json_str, int json_len);

/* Remove a document from the index */
int nats_json_index_remove(const char *key);

/* Destroy the index */
void nats_json_index_destroy(void);

/* cachedb query callback — search the index */
int nats_cache_query(cachedb_con *con, const cdb_filter_t *filter,
                     cdb_res_t *res);

/* cachedb update callback — update JSON document fields */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
                      const cdb_dict_t *pairs);

/* Get the global search index (for watcher thread access) */
nats_search_idx *nats_json_get_index(void);

#endif /* CACHEDB_NATS_JSON_H */
