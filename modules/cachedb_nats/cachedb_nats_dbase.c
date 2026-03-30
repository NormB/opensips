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

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_dbase.h"
#include "../../lib/nats/nats_pool.h"

/**
 * Create a new NATS cachedb connection.
 *
 * Called by cachedb_do_init via the function pointer passed to it.
 * Allocates the nats_cachedb_con struct, stores the cachedb_id,
 * and obtains the KV store handle from the shared connection pool.
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

	LM_DBG("NATS cachedb connection created for bucket '%s'\n", kv_bucket);
	return con;
}

/**
 * Free a NATS cachedb connection.
 *
 * Called by cachedb_do_close. The kvStore handle is owned by the
 * connection pool and must NOT be destroyed here.
 */
static void nats_free_connection(cachedb_pool_con *cpc)
{
	if (!cpc)
		return;

	LM_DBG("freeing NATS cachedb connection\n");
	pkg_free(cpc);
}

/**
 * cachedb init callback — wraps cachedb_do_init
 */
cachedb_con *nats_cachedb_init(str *url)
{
	return cachedb_do_init(url, (void *)nats_new_connection);
}

/**
 * cachedb destroy callback — wraps cachedb_do_close
 */
void nats_cachedb_destroy(cachedb_con *con)
{
	LM_DBG("destroying NATS cachedb connection\n");
	cachedb_do_close(con, nats_free_connection);
}

/* ------------- helper: null-terminate an OpenSIPS str ------------- */

/**
 * Copy an OpenSIPS str into a null-terminated buffer.
 * Returns 0 on success, -1 if the string is too long.
 */
static inline int str_to_buf(const str *s, char *buf, size_t buf_size)
{
	if (!s || !s->s || s->len <= 0) {
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

/* ------------------------------------------------------------------ */
/*                       cachedb API operations                       */
/* ------------------------------------------------------------------ */

/**
 * GET — retrieve a value by key.
 *
 * Return codes: 0=success, -1=error, -2=not found.
 * The returned val->s is allocated with pkg_malloc; caller frees it.
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
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	s = kvStore_Get(&entry, ncon->kv, key_buf);
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

	data = kvEntry_ValueString(entry);
	data_len = kvEntry_ValueLen(entry);

	if (!data || data_len <= 0) {
		/* key exists but empty value */
		val->s = NULL;
		val->len = 0;
		kvEntry_Destroy(entry);
		return 0;
	}

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
 * SET — store a key-value pair.
 *
 * Return codes: 0=success, -1=error.
 * The 'expires' parameter is accepted but not used (NATS KV does not
 * support per-key TTL; bucket-level TTL is set at creation time).
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
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

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
 * REMOVE — delete a key.
 *
 * Return codes: 0=success, -1=error.
 * Deleting a non-existent key is treated as success (idempotent).
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
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

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
 * Atomic counter operation (add or subtract) using CAS (compare-and-swap).
 *
 * Reads the current value, computes new = current +/- delta, then uses
 * kvStore_UpdateString with the last revision to atomically write it back.
 * Retries up to NATS_CAS_RETRIES times on CAS conflict.
 *
 * @param delta  positive for add, negative for subtract
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
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	if (expires > 0)
		LM_DBG("per-key TTL (%d s) ignored for counter '%s'\n",
			expires, key_buf);

	while (retries-- > 0) {
		current = 0;
		last_rev = 0;

		s = kvStore_Get(&entry, ncon->kv, key_buf);
		if (s == NATS_OK) {
			const char *val_str = kvEntry_ValueString(entry);
			current = val_str ? strtoll(val_str, NULL, 10) : 0;
			last_rev = kvEntry_Revision(entry);
			kvEntry_Destroy(entry);
			entry = NULL;
		} else if (s != NATS_NOT_FOUND) {
			LM_ERR("kvStore_Get failed for counter '%s': %s\n",
				key_buf, natsStatus_GetText(s));
			return -1;
		}

		current += delta;
		snprintf(buf, sizeof(buf), "%lld", (long long)current);

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

		/* CAS conflict or key-already-exists — retry */
		LM_DBG("CAS retry for key '%s' (attempt %d)\n",
			key_buf, NATS_CAS_RETRIES - retries);
	}

	LM_ERR("CAS failed after %d retries for counter '%s'\n",
		NATS_CAS_RETRIES, key_buf);
	return -1;
}

/**
 * ADD — atomic increment of a counter stored as a string integer.
 */
int nats_cache_add(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, val, expires, new_val);
}

/**
 * SUB — atomic decrement of a counter stored as a string integer.
 */
int nats_cache_sub(cachedb_con *con, str *attr, int val, int expires,
	int *new_val)
{
	return nats_cache_counter_op(con, attr, -val, expires, new_val);
}

/**
 * GET_COUNTER — retrieve an integer counter value.
 *
 * Return codes: 0=success, -1=error, -2=not found.
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
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	if (str_to_buf(attr, key_buf, sizeof(key_buf)) < 0)
		return -1;

	s = kvStore_Get(&entry, ncon->kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("counter not found: '%s'\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for counter '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	{
		const char *val_str = kvEntry_ValueString(entry);
		*val = val_str ? (int)strtol(val_str, NULL, 10) : 0;
	}
	kvEntry_Destroy(entry);

	LM_DBG("GET_COUNTER '%s' = %d\n", key_buf, *val);
	return 0;
}

/* raw_query moved to cachedb_nats_native.c as nats_cache_raw_query_impl() */
