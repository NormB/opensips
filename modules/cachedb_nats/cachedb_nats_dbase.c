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
 * cachedb_nats_dbase.c — cachedb API implementation for NATS JetStream KV
 *
 * This file implements the OpenSIPS cachedb interface backed by a NATS
 * JetStream Key-Value store.  Supported operations:
 *
 *   get          — retrieve a value by key
 *   set          — store a key-value pair (put)
 *   remove       — delete a key (purge)
 *   add / sub    — atomic counter increment / decrement via CAS
 *   get_counter  — read a numeric value stored as a string integer
 *
 * Thread safety
 * -------------
 * All functions in this file are called from OpenSIPS worker process
 * threads (UDP/TCP receivers, timer processes, etc.).  No additional
 * locking is required because each process holds its own nats_cachedb_con
 * with a per-process KV handle.  The underlying nats.c library manages
 * its own I/O thread internally.
 *
 * KV handle refresh
 * -----------------
 * After a NATS reconnection, old kvStore handles reference freed internal
 * subscriptions/consumers inside nats.c.  Every operation calls
 * nats_con_refresh_kv() which compares a per-connection epoch against the
 * global reconnect epoch maintained by the connection pool.  On mismatch,
 * the KV handle is transparently replaced with a fresh one.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_dbase.h"
#include "cachedb_nats_watch.h"
#include "../../lib/nats/nats_pool.h"

/**
 * nats_new_connection() — allocate and initialise a NATS cachedb connection.
 *
 * Called indirectly by cachedb_do_init(), which passes this function as a
 * callback.  Allocates a nats_cachedb_con, copies the cachedb_id supplied
 * by the framework, and obtains a KV store handle from the shared
 * connection pool for the configured bucket (kv_bucket module parameter).
 *
 * @param id   Parsed cachedb URL (scheme, host, group, etc.).  Ownership
 *             is retained by the cachedb framework — we just store a pointer.
 * @return     Pointer to the new connection, or NULL on failure.
 *             The caller (cachedb_do_init) wraps this in a cachedb_con.
 */
static nats_cachedb_con *nats_new_connection(struct cachedb_id *id)
{
	nats_cachedb_con *con;

	if (!id) {
		LM_ERR("null cachedb_id\n");
		return NULL;
	}

	con = pkg_malloc(sizeof(nats_cachedb_con));
	if (!con) {
		LM_ERR("no more pkg memory for nats_cachedb_con\n");
		return NULL;
	}
	memset(con, 0, sizeof(nats_cachedb_con));

	con->id = id;
	con->ref = 1;
	con->bucket_name = kv_bucket;

	/* get/create KV store handle from the shared pool */
	con->kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!con->kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n", kv_bucket);
		pkg_free(con);
		return NULL;
	}
	con->kv_epoch = nats_pool_get_reconnect_epoch();

	LM_DBG("NATS cachedb connection created for bucket '%s'\n", kv_bucket);
	return con;
}

/**
 * nats_con_refresh_kv() — refresh the KV handle if a reconnection occurred.
 *
 * Uses an epoch-based strategy: the shared connection pool maintains a
 * monotonically increasing reconnect epoch that is bumped each time nats.c
 * re-establishes the server connection.  Each nats_cachedb_con stores the
 * epoch at which its KV handle was obtained.  If the two diverge, the old
 * handle is stale (it references freed internal subscriptions/consumers
 * inside nats.c) and must be replaced.
 *
 * This function is called at the top of every cachedb operation (get, set,
 * remove, counter_op, get_counter) so that callers never use a stale handle.
 *
 * Thread safety: each OpenSIPS process has its own nats_cachedb_con, so no
 * locking is needed.  The epoch read is atomic (int assignment on all
 * supported architectures).
 *
 * @return  0 if the handle is valid (or was successfully refreshed),
 *         -1 if NATS is disconnected or the refresh failed.
 */
int nats_con_refresh_kv(nats_cachedb_con *ncon)
{
	int epoch;

	if (!ncon)
		return -1;

	/* If NATS is disconnected, fail fast.  Operations on stale handles
	 * during the disconnect window cause free(): invalid pointer in
	 * nats.c's internal I/O thread (race between reconnection cleanup
	 * and our KV operations). */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred\n");
		return -1;
	}

	epoch = nats_pool_get_reconnect_epoch();
	if (epoch == ncon->kv_epoch)
		return 0;  /* still valid */

	/* Reconnection occurred — get a fresh KV handle.
	 * Don't destroy the old one (other code may reference it). */
	ncon->kv = nats_pool_get_kv(ncon->bucket_name,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	ncon->kv_epoch = epoch;

	if (!ncon->kv) {
		LM_ERR("failed to refresh KV handle after reconnect\n");
		return -1;
	}

	LM_INFO("refreshed KV handle (epoch %d)\n", epoch);
	return 0;
}

/**
 * nats_free_connection() — release a NATS cachedb connection.
 *
 * Called by cachedb_do_close() when the cachedb framework tears down
 * this connection.  Only the nats_cachedb_con wrapper is freed here.
 *
 * Ownership semantics: the kvStore handle (ncon->kv) is owned by the
 * shared connection pool (nats_pool) and must NOT be destroyed by us.
 * The pool manages KV handle lifecycles across reconnections.
 */
static void nats_free_connection(cachedb_pool_con *cpc)
{
	if (!cpc)
		return;

	LM_DBG("freeing NATS cachedb connection\n");
	pkg_free(cpc);
}

/**
 * nats_cachedb_init() — cachedb framework init callback.
 *
 * Registered as the "init" function pointer in the cachedb_engine struct.
 * Delegates to cachedb_do_init(), which parses the URL, manages the
 * connection pool, and calls nats_new_connection() to create the
 * backend-specific connection object.
 *
 * @param url  The cachedb URL from opensips.cfg (e.g. "nats://bucket_name").
 * @return     An opaque cachedb_con handle, or NULL on failure.
 */
cachedb_con *nats_cachedb_init(str *url)
{
	return cachedb_do_init(url, (void *)nats_new_connection);
}

/**
 * nats_cachedb_destroy() — cachedb framework destroy callback.
 *
 * Registered as the "destroy" function pointer in the cachedb_engine struct.
 * Delegates to cachedb_do_close(), which calls nats_free_connection() to
 * release the backend-specific connection and then frees the cachedb_con
 * wrapper.
 *
 * @param con  The cachedb_con handle returned by nats_cachedb_init().
 */
void nats_cachedb_destroy(cachedb_con *con)
{
	LM_DBG("destroying NATS cachedb connection\n");
	cachedb_do_close(con, nats_free_connection);
}

/* ------------- helper: null-terminate an OpenSIPS str ------------- */

/**
 * str_to_buf() — convert an OpenSIPS str to a null-terminated C string.
 *
 * OpenSIPS str fields carry a pointer and a length but are NOT
 * null-terminated.  Most NATS C API functions expect standard C strings,
 * so this helper copies up to buf_size-1 bytes from s->s into buf and
 * appends a '\0'.
 *
 * @param s         Source OpenSIPS str (may be NULL or empty).
 * @param buf       Destination buffer (must be at least 1 byte).
 * @param buf_size  Total size of buf including space for the terminator.
 * @return  0 on success (including empty/NULL input → empty string),
 *         -1 if s->len is negative (corrupt str) or exceeds buf_size.
 */
static inline int str_to_buf(const str *s, char *buf, size_t buf_size)
{
	/* Guard against corrupt str: s->len is int, but the (size_t) cast
	 * below would turn a negative value into a very large positive number,
	 * silently passing the size check and causing a massive memcpy. */
	if (s && s->len < 0)
		return -1;
	if (!s || !s->s || s->len == 0) {
		buf[0] = '\0';
		return 0;
	}
	if ((size_t)s->len >= buf_size) {
		LM_ERR("string too long (%d >= %zu)\n", s->len, buf_size);
		return -1;
	}
	memcpy(buf, s->s, s->len);
	buf[s->len] = '\0';
	return 0;
}

/**
 * validate_kv_key() — reject keys NATS KV cannot represent as a subject token.
 *
 * NATS JetStream KV maps keys onto a subject of the form "$KV.<bucket>.<key>",
 * so the key must be a valid subject token: alphanumeric plus `_`, `-`, `=`,
 * `/`, `\`, `.` (dots split into sub-tokens), no whitespace, no control chars,
 * and no wildcard chars (`*`, `>`). An empty key is rejected by NATS too.
 *
 * Returns 0 if key is valid, -1 otherwise.
 */
static inline int validate_kv_key(const str *s)
{
	int i;
	unsigned char c;
	if (!s || !s->s || s->len <= 0) {
		LM_ERR("KV key empty or NULL\n");
		return -1;
	}
	for (i = 0; i < s->len; i++) {
		c = (unsigned char)s->s[i];
		if (c < 0x20 || c == 0x7f) {
			LM_ERR("KV key contains control char 0x%02x at offset %d\n",
				c, i);
			return -1;
		}
		if (c == ' ' || c == '\t') {
			LM_ERR("KV key contains whitespace at offset %d\n", i);
			return -1;
		}
		if (c == '*' || c == '>') {
			LM_ERR("KV key contains wildcard '%c' at offset %d\n", c, i);
			return -1;
		}
		if (c == ':') {
			LM_ERR("KV key contains ':' at offset %d (reserved)\n", i);
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/*                       cachedb API operations                       */
/* ------------------------------------------------------------------ */

/**
 * nats_cache_get() — retrieve a value from the NATS KV store by key.
 *
 * Looks up the given key (attr) in the JetStream KV bucket and returns
 * the value in an OpenSIPS str.  The value buffer is allocated with
 * pkg_malloc and must be freed by the caller (the cachedb framework
 * handles this).
 *
 * @param con   cachedb connection handle.
 * @param attr  Key to look up (OpenSIPS str, not null-terminated).
 * @param val   [out] Receives the value; val->s is pkg_malloc'd on success.
 * @return  0  on success (val is populated),
 *         -1  on error (NATS failure, allocation failure, etc.),
 *         -2  if the key was not found in the KV store.
 */
int nats_cache_get(cachedb_con *con, str *attr, str *val)
{
	nats_cachedb_con *ncon;
	kvEntry *entry = NULL;
	natsStatus s;
	const char *data;
	int data_len;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* kvEntry lifecycle: kvStore_Get allocates an entry that we must
	 * destroy with kvEntry_Destroy once we have extracted the value. */
	s = kvStore_Get(&entry, ncon->kv, key_buf);

	/* NATS_NOT_FOUND is not an error — the cachedb framework uses -2
	 * to distinguish "key absent" from "operation failed". */
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key not found: '%s'\n", key_buf);
		val->s = NULL;
		val->len = 0;
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for key '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	/* Read the value from the entry before destroying it — the pointer
	 * returned by kvEntry_ValueString is only valid while entry exists. */
	data = kvEntry_ValueString(entry);
	data_len = kvEntry_ValueLen(entry);

	if (!data || data_len <= 0) {
		/* key exists but empty value */
		val->s = NULL;
		val->len = 0;
		kvEntry_Destroy(entry);
		return 0;
	}

	/* Allocate pkg memory for the return value.  The cachedb framework
	 * will free this buffer after the script has consumed it. */
	val->s = pkg_malloc(data_len);
	if (!val->s) {
		LM_ERR("no more pkg memory for value (%d bytes)\n", data_len);
		kvEntry_Destroy(entry);
		return -1;
	}
	memcpy(val->s, data, data_len);
	val->len = data_len;

	kvEntry_Destroy(entry);
	return 0;
}

/**
 * nats_cache_set() — store a key-value pair in the NATS KV store.
 *
 * Performs a kvStore_PutString to write (or overwrite) the value for the
 * given key.  The value is copied into a null-terminated buffer before
 * passing to the NATS C API.
 *
 * @param con      cachedb connection handle.
 * @param attr     Key (OpenSIPS str).
 * @param val      Value to store (OpenSIPS str).
 * @param expires  Per-key TTL in seconds.  Accepted for API compatibility
 *                 but ignored — NATS JetStream KV only supports bucket-level
 *                 TTL, which is configured at bucket creation time.
 * @return  0 on success, -1 on error.
 */
int nats_cache_set(cachedb_con *con, str *attr, str *val, int expires)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	uint64_t rev;
	char key_buf[NATS_KEY_BUF_SIZE];
	char *val_buf = NULL;
	char val_stack[NATS_VAL_BUF_SIZE];
	int use_heap = 0;

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	if (expires > 0)
		LM_DBG("per-key TTL (%d s) ignored — NATS KV uses bucket-level TTL\n",
			expires);

	/* null-terminate the value — use stack buffer or heap for large values */
	if ((size_t)val->len < sizeof(val_stack)) {
		val_buf = val_stack;
	} else {
		val_buf = pkg_malloc(val->len + 1);
		if (!val_buf) {
			LM_ERR("no more pkg memory for value (%d bytes)\n", val->len);
			return -1;
		}
		use_heap = 1;
	}
	memcpy(val_buf, val->s, val->len);
	val_buf[val->len] = '\0';

	s = kvStore_PutString(&rev, ncon->kv, key_buf, val_buf);

	if (use_heap)
		pkg_free(val_buf);

	if (s != NATS_OK) {
		LM_ERR("kvStore_PutString failed for key '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("SET '%s' rev=%llu\n", key_buf, (unsigned long long)rev);
	return 0;
}

/**
 * nats_cache_remove() — delete a key from the NATS KV store.
 *
 * Issues a kvStore_Delete (soft delete / purge marker) for the given key.
 * Deleting a key that does not exist is treated as success to maintain
 * idempotent semantics expected by the cachedb framework.
 *
 * @param con   cachedb connection handle.
 * @param attr  Key to delete (OpenSIPS str).
 * @return  0 on success (including "key not found"), -1 on error.
 */
int nats_cache_remove(cachedb_con *con, str *attr)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	s = kvStore_Delete(ncon->kv, key_buf);
	if (s != NATS_OK && s != NATS_NOT_FOUND) {
		LM_ERR("kvStore_Delete failed for key '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("DELETE '%s' (%s)\n", key_buf,
		s == NATS_NOT_FOUND ? "not found" : "ok");
	return 0;
}

/**
 * nats_cache_counter_op() — atomic counter increment/decrement via CAS.
 *
 * Implements an atomic read-modify-write cycle using NATS KV revisions
 * as the compare-and-swap mechanism:
 *
 *   1. Read the current value and its revision number (kvStore_Get).
 *   2. Parse the value as an integer, apply the delta.
 *   3. Write the new value back, conditioned on the revision not having
 *      changed (kvStore_UpdateString with last_rev).
 *   4. If another writer modified the key between steps 1 and 3, the
 *      update fails with a CAS conflict — retry from step 1.
 *
 * If the key does not exist yet, kvStore_CreateString is used instead
 * (initial value = delta).  Retries up to NATS_CAS_RETRIES times.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param delta    Value to add (positive) or subtract (negative).
 * @param expires  Per-key TTL (ignored, see nats_cache_set).
 * @param new_val  [out] Receives the new counter value on success (may be NULL).
 * @return  0 on success, -1 on error or CAS exhaustion.
 */
static int nats_cache_counter_op(cachedb_con *con, str *attr, int delta,
	int expires, int *new_val)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	kvEntry *entry = NULL;
	int64_t current;
	uint64_t last_rev, new_rev;
	int retries = NATS_CAS_RETRIES;
	char key_buf[NATS_KEY_BUF_SIZE];
	char buf[32];

	if (!con || !attr) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	if (expires > 0)
		LM_DBG("per-key TTL (%d s) ignored for counter '%s'\n",
			expires, key_buf);

	/* CAS retry loop: each iteration reads the current value and
	 * attempts a conditional write.  On conflict (another process
	 * updated the key between our read and write), we re-read and
	 * try again, up to NATS_CAS_RETRIES times. */
	while (retries-- > 0) {
		current = 0;
		last_rev = 0;

		/* Step 1: read current value.  NATS_NOT_FOUND means the
		 * counter doesn't exist yet — we'll use CreateString below. */
		s = kvStore_Get(&entry, ncon->kv, key_buf);
		if (s == NATS_OK) {
			/* kvEntry lifecycle: extract value + revision, then
			 * destroy immediately — we don't need it after this. */
			const char *vs = kvEntry_ValueString(entry);
			current = vs ? strtoll(vs, NULL, 10) : 0;
			last_rev = kvEntry_Revision(entry);
			kvEntry_Destroy(entry);
			entry = NULL;
		} else if (s != NATS_NOT_FOUND) {
			LM_ERR("kvStore_Get failed for counter '%s': %s\n",
				key_buf, natsStatus_GetText(s));
			return -1;
		}

		/* Step 2: compute new value and serialise to string. */
		current += delta;
		snprintf(buf, sizeof(buf), "%lld", (long long)current);

		/* Step 3: conditional write.  UpdateString checks that the
		 * key's revision still matches last_rev (CAS semantics).
		 * CreateString fails if the key already exists (another
		 * process created it between our Get and this call). */
		if (last_rev > 0)
			s = kvStore_UpdateString(&new_rev, ncon->kv, key_buf,
				buf, last_rev);
		else
			s = kvStore_CreateString(&new_rev, ncon->kv, key_buf, buf);

		if (s == NATS_OK) {
			if (new_val)
				*new_val = (int)current;
			LM_DBG("counter '%s' = %lld (rev=%llu)\n",
				key_buf, (long long)current,
				(unsigned long long)new_rev);
			return 0;
		}

		/* CAS conflict or key-already-exists — another writer won
		 * the race.  Loop back to re-read and retry. */
		LM_DBG("CAS retry for key '%s' (attempt %d)\n",
			key_buf, NATS_CAS_RETRIES - retries);
	}

	LM_ERR("CAS failed after %d retries for counter '%s'\n",
		NATS_CAS_RETRIES, key_buf);
	return -1;
}

/**
 * nats_cache_add() — atomically increment a counter in the KV store.
 *
 * Delegates to nats_cache_counter_op() with a positive delta (val).
 * The counter is stored as a string integer in the KV bucket.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param val      Amount to add.
 * @param expires  Per-key TTL (ignored).
 * @param new_val  [out] Receives the new counter value (may be NULL).
 * @return  0 on success, -1 on error.
 */
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, val, expires, new_val);
}

/**
 * nats_cache_sub() — atomically decrement a counter in the KV store.
 *
 * Delegates to nats_cache_counter_op() with a negated delta (-val).
 * The counter is stored as a string integer in the KV bucket.
 *
 * @param con      cachedb connection handle.
 * @param attr     Counter key (OpenSIPS str).
 * @param val      Amount to subtract.
 * @param expires  Per-key TTL (ignored).
 * @param new_val  [out] Receives the new counter value (may be NULL).
 * @return  0 on success, -1 on error.
 */
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, -val, expires, new_val);
}

/**
 * nats_cache_get_counter() — read a numeric counter value from the KV store.
 *
 * Retrieves the value for the given key and parses it as an integer using
 * atoi().  The value is expected to be a decimal string written by
 * nats_cache_counter_op() (via nats_cache_add / nats_cache_sub).
 *
 * @param con   cachedb connection handle.
 * @param attr  Counter key (OpenSIPS str).
 * @param val   [out] Receives the integer counter value on success.
 * @return  0  on success,
 *         -1  on error,
 *         -2  if the key was not found.
 */
int nats_cache_get_counter(cachedb_con *con, str *attr, int *val)
{
	nats_cachedb_con *ncon;
	kvEntry *entry = NULL;
	natsStatus s;
	char key_buf[NATS_KEY_BUF_SIZE];

	if (!con || !attr || !val) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_ERR("KV handle unavailable\n");
		return -1;
	}

	if (validate_kv_key(attr) < 0)
		return -1;
	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* kvEntry lifecycle: Get allocates, we read, then Destroy. */
	s = kvStore_Get(&entry, ncon->kv, key_buf);

	/* NATS_NOT_FOUND → return -2 so the cachedb framework knows the
	 * counter has not been initialised yet (distinct from error). */
	if (s == NATS_NOT_FOUND) {
		LM_DBG("counter not found: '%s'\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for counter '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	/* Parse the string value as an integer; kvEntry_ValueString returns
	 * a pointer valid only while entry is alive. */
	{
		const char *val_str = kvEntry_ValueString(entry);
		*val = val_str ? (int)strtol(val_str, NULL, 10) : 0;
	}
	kvEntry_Destroy(entry);

	LM_DBG("GET_COUNTER '%s' = %d\n", key_buf, *val);
	return 0;
}

/* raw_query moved to cachedb_nats_native.c as nats_cache_raw_query_impl() */
