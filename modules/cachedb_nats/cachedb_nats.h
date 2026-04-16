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
 *
 */

/*
 * cachedb_nats.h — CacheDB Backend for NATS JetStream KV
 *
 * Module:  cachedb_nats
 *
 * Declares the cachedb connection wrapper and the full set of cachedb
 * API functions that map OpenSIPS cache operations onto NATS JetStream
 * KV store operations.
 *
 * Key types:
 *   nats_cachedb_con  — per-connection state wrapping a NATS KV handle
 *
 * Key functions:
 *   nats_con_refresh_kv()   — epoch-based KV handle refresh
 *   nats_cachedb_init()     — cachedb init callback
 *   nats_cachedb_destroy()  — cachedb destroy callback
 *   nats_cache_get/set/remove/add/sub/get_counter — scalar operations
 *   nats_cache_raw_query_impl — raw query (keys/purge)
 *   nats_cache_map_get/set/remove — JSON document map operations
 */

#ifndef CACHEDB_NATS_H
#define CACHEDB_NATS_H

#include <nats/nats.h>
#include "../../cachedb/cachedb.h"

/*
 * CacheDB connection wrapper for NATS JetStream KV.
 *
 * The first three fields (id, ref, next) form the fixed cachedb header
 * required by the OpenSIPS cachedb pooling framework.  They must appear
 * first and in this exact order.  The NATS-specific fields follow.
 */
typedef struct _nats_cachedb_con {
    /* ------ Fixed cachedb header (must be first, exact order) ------ */
    struct cachedb_id *id;              /* Parsed cachedb URL (scheme,
                                         * host, port, database). Owned by
                                         * the cachedb framework. */
    unsigned int ref;                   /* Reference count, managed by the
                                         * cachedb connection pool. */
    struct cachedb_pool_con_t *next;    /* Linked-list pointer for the
                                         * cachedb connection pool. */
    /* ------ NATS-specific fields ------ */
    kvStore *kv;                        /* NATS JetStream KV store handle.
                                         * Obtained from nats_pool_get_kv()
                                         * and cached here.  Becomes stale
                                         * after a reconnection. */
    char *bucket_name;                  /* KV bucket name string (heap
                                         * allocated, freed on destroy).
                                         * Corresponds to the "database"
                                         * portion of the cachedb URL. */
    int kv_epoch;                       /* Reconnect epoch at which this
                                         * kv handle was obtained.  Compared
                                         * against nats_pool_get_reconnect_epoch()
                                         * to detect staleness.  See
                                         * nats_con_refresh_kv(). */
} nats_cachedb_con;

/*
 * Refresh the KV store handle if a NATS reconnection has occurred.
 *
 * Compares the connection's saved kv_epoch against the pool's current
 * reconnect epoch.  If they differ, the old KV handle is stale (the
 * underlying JetStream subscription was lost during reconnect), so this
 * function obtains a fresh handle from nats_pool_get_kv().
 *
 * Call this at the top of every cachedb operation (get, set, remove, etc.)
 * before using ncon->kv.  This is the primary mechanism for transparent
 * reconnection recovery in the cachedb layer.
 *
 * @param ncon  Pointer to the cachedb connection wrapper.
 * @return      0 on success (handle is valid), -1 if refresh failed
 *              (KV bucket could not be re-opened).
 *
 * Thread safety: Safe from OpenSIPS worker process context.  Each
 *                process has its own nats_cachedb_con instance.
 */
int nats_con_refresh_kv(nats_cachedb_con *ncon);

/*
 * CacheDB init callback — called by the cachedb framework when a
 * "nats" cachedb URL is first used.
 *
 * Parses the URL, allocates a nats_cachedb_con, obtains the KV store
 * handle from the shared connection pool, and returns the wrapped
 * cachedb_con to the framework.
 *
 * @param url   Parsed cachedb URL string (e.g., "nats:///mybucket").
 * @return      cachedb_con pointer on success, NULL on error.
 */
cachedb_con* nats_cachedb_init(str *url);

/*
 * CacheDB destroy callback — releases the NATS cachedb connection.
 *
 * Frees the bucket_name string and the wrapper struct.  Does not close
 * the underlying NATS connection (that is managed by the shared pool).
 *
 * @param con   cachedb_con pointer to destroy.
 */
void nats_cachedb_destroy(cachedb_con *con);

/*
 * Get a value from the KV store by key.
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @param val     Output: value string (pkg_malloc'd by this function;
 *                caller must pkg_free).
 * @return        0 on success, -2 if key not found, -1 on error.
 */
int nats_cache_get(cachedb_con *con, str *attr, str *val);

/*
 * Store a key-value pair in the KV store.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value string to store.
 * @param expires  TTL in seconds (0 = use bucket default).
 *                 Note: NATS KV TTL is bucket-wide; per-key TTL is
 *                 not supported.  This parameter is accepted for API
 *                 compatibility but only takes effect at bucket creation.
 * @return         0 on success, -1 on error.
 */
int nats_cache_set(cachedb_con *con, str *attr, str *val, int expires);

/*
 * Remove a key from the KV store (soft delete / purge).
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @return        0 on success, -1 on error.
 */
int nats_cache_remove(cachedb_con *con, str *attr);

/*
 * Atomic add to a counter stored as an integer value.
 *
 * Uses compare-and-swap (CAS) with up to NATS_CAS_RETRIES attempts
 * to handle concurrent updates.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value to add (can be negative for subtraction).
 * @param expires  TTL in seconds (see nats_cache_set note).
 * @param new_val  Output: the resulting counter value after addition.
 * @return         0 on success, -1 on error (including CAS exhaustion).
 */
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires, int *new_val);

/*
 * Atomic subtract from a counter stored as an integer value.
 *
 * Equivalent to nats_cache_add() with a negated value.
 *
 * @param con      cachedb connection.
 * @param attr     Key string.
 * @param val      Value to subtract.
 * @param expires  TTL in seconds (see nats_cache_set note).
 * @param new_val  Output: the resulting counter value after subtraction.
 * @return         0 on success, -1 on error.
 */
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires, int *new_val);

/*
 * Read the current value of an integer counter.
 *
 * @param con     cachedb connection.
 * @param attr    Key string.
 * @param val     Output: current counter value.
 * @return        0 on success, -2 if key not found, -1 on error.
 */
int nats_cache_get_counter(cachedb_con *con, str *attr, int *val);

/*
 * Execute a raw query against the KV store.
 *
 * Supports commands like "keys <prefix>" and "purge <key>".
 * Implemented in cachedb_nats_native.c.
 *
 * @param con             cachedb connection.
 * @param attr            Raw query string.
 * @param reply           Output: array of result entries (caller frees).
 * @param expected_kv_no  Expected number of key-value pairs per entry.
 * @param reply_no        Output: number of entries returned.
 * @return                0 on success, -1 on error.
 */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr, cdb_raw_entry ***reply, int expected_kv_no, int *reply_no);

/*
 * Get a JSON document from the KV store and return as map columns.
 *
 * Retrieves the raw JSON value, parses it, and populates cdb_res_t
 * with one row whose columns correspond to the JSON object fields.
 * Implemented in cachedb_nats_native.c.
 *
 * @param con   cachedb connection.
 * @param key   Document key.
 * @param res   Output: result set with parsed columns.
 * @return      0 on success, -2 if not found, -1 on error.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res);

/*
 * Set fields in a JSON document stored in the KV store.
 *
 * Reads the existing document (or starts with {}), merges the provided
 * key-value pairs, and writes back.  Uses CAS for consistency.
 * Implemented in cachedb_nats_native.c.
 *
 * @param con     cachedb connection.
 * @param key     Document key.
 * @param subkey  Sub-key filter (unused, pass NULL).
 * @param pairs   Dictionary of field-value pairs to set.
 * @return        0 on success, -1 on error.
 */
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey,
                       const cdb_dict_t *pairs);

/*
 * Remove fields from a JSON document stored in the KV store.
 *
 * Reads the existing document, removes matching fields, and writes back.
 * If no fields remain, deletes the key entirely.
 * Implemented in cachedb_nats_native.c.
 *
 * @param con     cachedb connection.
 * @param key     Document key.
 * @param subkey  Field name to remove (NULL removes entire document).
 * @return        0 on success, -1 on error.
 */
int nats_cache_map_remove(cachedb_con *con, const str *key, const str *subkey);

#endif /* CACHEDB_NATS_H */
