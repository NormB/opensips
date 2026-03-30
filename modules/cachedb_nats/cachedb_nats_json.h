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
 * cachedb_nats_json.h — JSON Document Search Index for NATS KV
 *
 * Module:  cachedb_nats
 *
 * Implements a process-local, hash-based search index over JSON documents
 * stored in a NATS JetStream KV bucket.  The index maps field:value pairs
 * to sets of document keys, enabling efficient cachedb query() operations
 * (SQL-like WHERE clauses) without scanning all keys.
 *
 * The index is populated at startup by scanning the KV bucket, and kept
 * in sync via a NATS KV watcher that receives real-time updates on a
 * background thread.  Access is protected by a pthread mutex.
 *
 * Key types:
 *   nats_idx_entry   — one hash bucket entry mapping a "field:value" to keys
 *   nats_search_idx  — the hash table with mutex protection
 *
 * Key constants:
 *   NATS_IDX_BUCKETS — number of hash buckets (256)
 *
 * Thread safety:
 *   All index operations (add, remove, query, rebuild) acquire the
 *   nats_search_idx.lock mutex.  The KV watcher thread calls
 *   nats_json_index_add() and nats_json_index_remove() as documents
 *   change, while OpenSIPS worker processes call nats_cache_query()
 *   and nats_cache_update() from routing scripts.  The mutex ensures
 *   mutual exclusion between these concurrent accesses.
 */

#ifndef CACHEDB_NATS_JSON_H
#define CACHEDB_NATS_JSON_H

#include <nats/nats.h>
#include "../../cachedb/cachedb.h"
#include <pthread.h>

/*
 * Index entry — one per unique "field:value" combination.
 *
 * Stored in a singly-linked hash bucket chain.  Each entry tracks
 * the set of document keys that contain this field:value pair.
 * The keys array grows dynamically (doubled when full).
 */
typedef struct _nats_idx_entry {
	char *field_value;          /* Concatenated "field:value" string.
	                             * Heap-allocated; freed when the entry
	                             * is removed from the index. */
	unsigned int fv_len;        /* Length of field_value in bytes
	                             * (excluding null terminator). */
	char **keys;                /* Array of document key strings.
	                             * Each element is heap-allocated.
	                             * Length: num_keys valid entries. */
	int num_keys;               /* Number of document keys currently
	                             * stored in the keys array. */
	int alloc_keys;             /* Allocated capacity of the keys array.
	                             * Doubles when num_keys == alloc_keys. */
	struct _nats_idx_entry *next; /* Next entry in the hash bucket chain
	                               * (singly linked, NULL at tail). */
} nats_idx_entry;

/*
 * Number of hash buckets in the search index.
 *
 * The hash function distributes "field:value" strings across this many
 * buckets using a simple multiplicative hash.  256 provides a reasonable
 * trade-off between memory usage and chain length for typical deployments
 * (hundreds to low thousands of indexed documents).
 */
#define NATS_IDX_BUCKETS 256

/*
 * Search index — hash table with mutex for thread-safe access.
 *
 * One global instance per OpenSIPS worker process, allocated in
 * process-local (heap) memory during child_init.
 */
typedef struct _nats_search_idx {
	nats_idx_entry *buckets[NATS_IDX_BUCKETS];
	                            /* Array of hash bucket chain heads.
	                             * Each element is NULL (empty bucket) or
	                             * points to the first nats_idx_entry in
	                             * a singly-linked chain. */
	int num_documents;          /* Total number of unique document keys
	                             * tracked across all index entries.
	                             * Used for MI status reporting. */
	pthread_mutex_t lock;       /* Mutex protecting all index state.
	                             * Must be held during any read or write
	                             * to buckets[] or num_documents.
	                             * Contention sources: KV watcher thread
	                             * (writes) vs. OpenSIPS workers (reads). */
} nats_search_idx;

/*
 * Initialize the search index data structure.
 *
 * Allocates the global nats_search_idx, zeroes all bucket pointers,
 * and initializes the mutex.  Must be called from child_init (post-fork,
 * before any index operations).
 *
 * @return  0 on success, -1 on allocation or mutex init failure.
 *
 * Thread safety: NOT thread-safe.  Call once per process from child_init.
 */
int nats_json_index_init(void);

/*
 * Build the search index from existing KV data.
 *
 * Iterates all keys in the KV bucket matching the given prefix, reads
 * each JSON document, and indexes all top-level string and integer fields.
 * Called once during startup after child_init.
 *
 * @param kv      KV store handle (from nats_pool_get_kv).
 * @param prefix  Key prefix filter (e.g., "user." to index only user
 *                documents).  Pass NULL or "" to index all keys.
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Acquires the index mutex internally.
 */
int nats_json_index_build(kvStore *kv, const char *prefix);

/*
 * Clear and rebuild the search index from scratch.
 *
 * Removes all existing index entries and calls nats_json_index_build().
 * Used after a NATS reconnection, when the KV watcher is re-established
 * and the index may be stale due to missed updates during the disconnect.
 *
 * @param kv      Fresh KV store handle (post-reconnection).
 * @param prefix  Key prefix filter (same semantics as index_build).
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Acquires the index mutex internally.
 */
int nats_json_index_rebuild(kvStore *kv, const char *prefix);

/*
 * Add a JSON document to the search index.
 *
 * Parses the JSON string and creates index entries for each top-level
 * field:value pair.  If the key already exists in the index, the old
 * entries are removed first (update semantics).
 *
 * Called by the KV watcher thread when a key is created or updated.
 *
 * @param key       Document key string.
 * @param json_str  Raw JSON string content.
 * @param json_len  Length of json_str in bytes.
 * @return          0 on success, -1 on parse error or allocation failure.
 *
 * Thread safety: Acquires the index mutex internally.
 */
int nats_json_index_add(const char *key, const char *json_str, int json_len);

/*
 * Remove a document from the search index.
 *
 * Removes all field:value entries associated with the given key.
 * Called by the KV watcher thread when a key is deleted or purged.
 *
 * @param key  Document key string to remove.
 * @return     0 on success (or key not found — idempotent), -1 on error.
 *
 * Thread safety: Acquires the index mutex internally.
 */
int nats_json_index_remove(const char *key);

/*
 * Destroy the search index and free all resources.
 *
 * Frees all index entries, document key strings, and the mutex.
 * Called during process shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only during shutdown when
 *                no other threads are accessing the index.
 */
void nats_json_index_destroy(void);

/*
 * CacheDB query callback — search the index for matching documents.
 *
 * Translates cdb_filter_t conditions into index lookups.  For equality
 * filters on indexed fields, performs O(1) hash lookup per condition
 * and intersects the resulting key sets.  Fetches full documents for
 * matched keys and populates the result set.
 *
 * @param con     cachedb connection (used to fetch document values).
 * @param filter  Chain of filter conditions (field op value).
 * @param res     Output: result set with matching document rows.
 * @return        0 on success (res may have 0 rows), -1 on error.
 *
 * Thread safety: Acquires the index mutex for the lookup phase.
 *                KV fetches happen outside the mutex.
 */
int nats_cache_query(cachedb_con *con, const cdb_filter_t *filter,
                     cdb_res_t *res);

/*
 * CacheDB update callback — modify fields in matching JSON documents.
 *
 * Finds documents matching row_filter (via index lookup), reads each
 * document, merges the provided field-value pairs, writes back to KV,
 * and updates the index to reflect the new field values.
 *
 * @param con         cachedb connection.
 * @param row_filter  Filter to identify documents to update.
 * @param pairs       Dictionary of field-value pairs to set.
 * @return            0 on success, -1 on error.
 *
 * Thread safety: Acquires the index mutex for lookup; KV operations
 *                happen outside the mutex.
 */
int nats_cache_update(cachedb_con *con, const cdb_filter_t *row_filter,
                      const cdb_dict_t *pairs);

/*
 * Get a pointer to the global search index.
 *
 * Used by the KV watcher setup code to pass the index reference to
 * the watcher thread's closure.  Returns NULL if the index has not
 * been initialized.
 *
 * @return  Pointer to the global nats_search_idx instance.
 *
 * Thread safety: The returned pointer is stable after child_init.
 *                Callers must acquire the index mutex before accessing
 *                index contents.
 */
nats_search_idx *nats_json_get_index(void);

#endif /* CACHEDB_NATS_JSON_H */
