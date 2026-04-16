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
 * cachedb_nats_native.h — NATS-Native Script Functions and Advanced Operations
 *
 * Module:  cachedb_nats
 *
 * Declares OpenSIPS script-callable functions that expose NATS-native
 * capabilities beyond the standard cachedb API:
 *
 *   - Request-reply messaging (nats_request)
 *   - KV history retrieval (nats_kv_history)
 *   - Raw query implementation (keys listing, purge)
 *   - JSON document map operations (get/set/remove fields)
 *
 * These functions are registered via the cmds[] array in the module
 * export and are available in opensips.cfg routing scripts.
 */

#ifndef CACHEDB_NATS_NATIVE_H
#define CACHEDB_NATS_NATIVE_H

#include "../../sr_module.h"
#include "../../cachedb/cachedb.h"
#include "../../pvar.h"

/*
 * Script function: nats_request(subject, payload, timeout_ms, $result)
 *
 * Sends a NATS request (request-reply pattern) and waits synchronously
 * for a response up to the specified timeout.  The response payload is
 * stored in the given pseudo-variable.
 *
 * @param msg         SIP message context (provided by OpenSIPS).
 * @param subject     NATS subject to send the request to.
 * @param payload     Request payload string.
 * @param timeout_ms  Pointer to timeout value in milliseconds.  If the
 *                    responder does not reply within this window, the
 *                    function returns -1.
 * @param result_var  Pseudo-variable spec to store the response payload.
 * @return            1 on success (response received), -1 on error or
 *                    timeout.  (OpenSIPS script convention: 1 = success.)
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int w_nats_request(struct sip_msg *msg, str *subject, str *payload,
                   int *timeout_ms, pv_spec_t *result_var);

/*
 * Script function: nats_kv_history(key, $result)
 *
 * Retrieves the revision history for a KV key and stores it as a JSON
 * array string in the given pseudo-variable.  Each array element contains
 * the value, revision number, and timestamp.  Requires kv_history > 1
 * on the bucket configuration.
 *
 * @param msg         SIP message context (provided by OpenSIPS).
 * @param key         KV key to retrieve history for.
 * @param result_var  Pseudo-variable spec to store the JSON history array.
 * @return            1 on success, -1 on error or key not found.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int w_nats_kv_history(struct sip_msg *msg, str *key, pv_spec_t *result_var);

/*
 * Script function: nats_kv_get(bucket, key, $value, [$revision])
 *
 * Reads a KV entry and stores the value in value_var. If rev_var is
 * provided, also stores the revision number (uint64 as int).
 *
 * @return 1 success, -1 error, -2 not found.
 */
int w_nats_kv_get(struct sip_msg *msg, str *bucket, str *key,
                  pv_spec_t *value_var, pv_spec_t *rev_var);

/*
 * Script function: nats_kv_put(bucket, key, value)
 *
 * Unconditional write (overwrites regardless of current revision).
 *
 * @return 1 success, -1 error.
 */
int w_nats_kv_put(struct sip_msg *msg, str *bucket, str *key, str *value);

/*
 * Script function: nats_kv_update(bucket, key, value, expected_revision)
 *
 * Conditional write (CAS). Only succeeds if current revision matches
 * expected_revision. Returns -2 on revision mismatch.
 *
 * @return 1 success, -1 error, -2 revision mismatch.
 */
int w_nats_kv_update(struct sip_msg *msg, str *bucket, str *key,
                     str *value, int *expected_rev);

/*
 * Script function: nats_kv_delete(bucket, key)
 *
 * Delete a key (creates a delete marker, revision incremented).
 *
 * @return 1 success, -1 error.
 */
int w_nats_kv_delete(struct sip_msg *msg, str *bucket, str *key);

/*
 * Script function: nats_kv_revision(bucket, key, $revision)
 *
 * Lightweight read of only the current revision number.
 *
 * @return 1 success, -1 error, -2 not found.
 */
int w_nats_kv_revision(struct sip_msg *msg, str *bucket, str *key,
                       pv_spec_t *rev_var);

/*
 * CacheDB raw_query implementation for NATS KV.
 *
 * Parses the query string for supported commands:
 *   - "keys <prefix>"  — list all keys matching the prefix
 *   - "purge <key>"    — permanently remove a key and its history
 *
 * @param con             cachedb connection.
 * @param attr            Raw query command string.
 * @param reply           Output: array of result entries (pkg_malloc'd;
 *                        caller must free via cachedb framework).
 * @param expected_kv_no  Expected columns per entry (typically 1 for keys).
 * @param reply_no        Output: number of entries returned.
 * @return                0 on success, -1 on error or unknown command.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr,
                              cdb_raw_entry ***reply, int expected_kv_no,
                              int *reply_no);

/*
 * CacheDB map_get: retrieve a JSON document and return parsed fields.
 *
 * Fetches the raw JSON value for the given key, parses it with cJSON,
 * and populates cdb_res_t with a single row whose columns correspond
 * to the top-level JSON object fields.
 *
 * @param con   cachedb connection.
 * @param key   Document key in the KV store.
 * @param res   Output: result set populated with parsed columns.
 * @return      0 on success, -2 if key not found, -1 on error.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res);

/*
 * CacheDB map_set: merge fields into a JSON document in the KV store.
 *
 * Reads the existing document (or creates {}), merges the provided
 * field-value pairs from the dictionary, and writes the result back.
 * Uses compare-and-swap for consistency when the key already exists.
 *
 * @param con     cachedb connection.
 * @param key     Document key in the KV store.
 * @param subkey  Unused (pass NULL).  Reserved for future sub-document
 *                addressing.
 * @param pairs   Dictionary of field names to values.  Supported value
 *                types: string, integer.
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey,
                       const cdb_dict_t *pairs);

/*
 * CacheDB map_remove: delete fields from a JSON document in the KV store.
 *
 * Reads the existing document, removes the specified field(s), and writes
 * the result back.  If no fields remain after removal, the key itself is
 * deleted from the KV store.
 *
 * @param con     cachedb connection.
 * @param key     Document key in the KV store.
 * @param subkey  Field name to remove, or NULL to remove the entire
 *                document.
 * @return        0 on success, -1 on error.
 *
 * Thread safety: Safe from OpenSIPS worker process context.
 */
int nats_cache_map_remove(cachedb_con *con, const str *key,
                          const str *subkey);

#endif /* CACHEDB_NATS_NATIVE_H */
