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
 * cachedb_nats_native.c — Advanced NATS operations beyond basic cachedb
 *
 * This file provides extended NATS functionality that goes beyond the standard
 * cachedb get/set/remove interface:
 *
 *   - Request/reply RPC:  Synchronous NATS request/reply pattern for
 *     microservice-style calls from OpenSIPS script (w_nats_request).
 *
 *   - KV history:  Retrieves the full version history of a NATS KV key
 *     and returns it as a JSON array (w_nats_kv_history).
 *
 *   - Raw commands:  A cachedb raw_query dispatcher that supports KV KEYS,
 *     KV PURGE, and KV BUCKET INFO commands (nats_cache_raw_query_impl).
 *
 *   - Map operations:  Composite key (prefix:subkey) operations that emulate
 *     hash-map semantics on top of flat NATS KV (nats_cache_map_get/set/remove).
 *
 * All functions in this file run on OpenSIPS worker process threads (post-fork).
 * They use pkg_malloc for per-process allocations and access shared NATS
 * connections via the nats_pool API.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_native.h"
#include "cachedb_nats.h"
#include "cachedb_nats_dbase.h"
#include "../../lib/nats/nats_pool.h"

/* maximum buffer sizes (reuse from dbase.h) */
#define NATS_NATIVE_KEY_BUF   512
#define NATS_NATIVE_VAL_BUF   4096
#define NATS_MAP_KEY_BUF      1024
#define NATS_HISTORY_BUF      8192
#define NATS_RAW_CMD_BUF      256

/* separator for map keys: key:subkey */
#define NATS_MAP_SEP ':'

/*
 * native_str_to_buf() — Null-terminate an OpenSIPS str into a fixed buffer.
 *
 * Copies s->len bytes from s->s into buf and appends '\0'.  Returns 0 on
 * success, -1 if the string does not fit or has a negative length.  When
 * s is NULL, empty, or zero-length, buf is set to an empty string.
 */
static inline int native_str_to_buf(const str *s, char *buf, size_t buf_size)
{
	/* guard against corrupted str descriptors with negative length */
	if (s && s->len < 0) {
		LM_ERR("negative string length (%d)\n", s->len);
		return -1;
	}
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

/* ================================================================== */
/*               Script function: nats_request                        */
/* ================================================================== */

/**
 * Synchronous NATS request/reply (RPC pattern).
 *
 * Script usage:
 *   nats_request("auth.check", "$var(payload)", 2000, $var(reply));
 *
 * Returns:
 *   1  success (reply stored in result_var)
 *  -1  error
 *  -2  timeout
 */
int w_nats_request(struct sip_msg *msg, str *subject, str *payload,
                   int *timeout_ms, pv_spec_t *result_var)
{
	natsConnection *nc;
	natsMsg *reply = NULL;
	natsStatus s;
	char subj_buf[NATS_NATIVE_KEY_BUF];
	char pay_buf[NATS_NATIVE_VAL_BUF];
	char *pay_ptr = pay_buf;
	int pay_heap = 0;
	int reply_len;
	char *reply_copy;
	pv_value_t val;

	if (!subject || !payload || !timeout_ms || !result_var) {
		LM_ERR("null parameter\n");
		return -1;
	}

	nc = nats_pool_get();
	if (!nc) {
		LM_ERR("no NATS connection available\n");
		return -1;
	}

	/* clamp timeout to a sane range */
	if (*timeout_ms > 30000) {
		static int warned = 0;
		if (!warned) {
			LM_WARN("nats_request timeout %d ms clamped to 30000 ms\n",
				*timeout_ms);
			warned = 1;
		}
		*timeout_ms = 30000;
	}

	/* null-terminate subject */
	if (native_str_to_buf(subject, subj_buf, sizeof(subj_buf)) < 0)
		return -1;

	/* null-terminate payload (use heap for large payloads) */
	if ((size_t)payload->len < sizeof(pay_buf)) {
		memcpy(pay_buf, payload->s, payload->len);
		pay_buf[payload->len] = '\0';
	} else {
		pay_ptr = pkg_malloc(payload->len + 1);
		if (!pay_ptr) {
			LM_ERR("no more pkg memory for payload (%d bytes)\n",
				payload->len);
			return -1;
		}
		memcpy(pay_ptr, payload->s, payload->len);
		pay_ptr[payload->len] = '\0';
		pay_heap = 1;
	}

	s = natsConnection_RequestString(&reply, nc, subj_buf,
		pay_ptr, *timeout_ms);

	if (pay_heap)
		pkg_free(pay_ptr);

	if (s == NATS_TIMEOUT) {
		LM_DBG("nats_request to '%s' timed out (%dms)\n",
			subj_buf, *timeout_ms);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("nats_request to '%s' failed: %s\n",
			subj_buf, natsStatus_GetText(s));
		return -1;
	}

	/* copy reply data before destroying message */
	reply_len = natsMsg_GetDataLength(reply);
	reply_copy = pkg_malloc(reply_len + 1);
	if (!reply_copy) {
		LM_ERR("no more pkg memory for reply (%d bytes)\n", reply_len);
		natsMsg_Destroy(reply);
		return -1;
	}
	memcpy(reply_copy, natsMsg_GetData(reply), reply_len);
	reply_copy[reply_len] = '\0';
	natsMsg_Destroy(reply);

	/* set result variable */
	memset(&val, 0, sizeof(val));
	val.flags = PV_VAL_STR;
	val.rs.s = reply_copy;
	val.rs.len = reply_len;
	pv_set_value(msg, result_var, 0, &val);
	pkg_free(reply_copy);

	LM_DBG("nats_request to '%s' got %d-byte reply\n", subj_buf, reply_len);
	return 1;
}

/* ================================================================== */
/*               Script function: nats_kv_history                     */
/* ================================================================== */

/**
 * Retrieve the version history of a KV key as a JSON array.
 *
 * Script usage:
 *   nats_kv_history("usrloc.alice", $var(history));
 *   # $var(history) = [{"rev":1,"value":"..."},{"rev":2,"value":"..."}]
 *
 * Returns:
 *   1  success (JSON array stored in result_var)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_history(struct sip_msg *msg, str *key, pv_spec_t *result_var)
{
	kvStore *kv;
	kvEntryList list;
	natsStatus s;
	char key_buf[NATS_NATIVE_KEY_BUF];
	char *buf;
	int buf_size = NATS_HISTORY_BUF;
	int pos, i, entry_count;
	pv_value_t val;

	if (!key || !result_var) {
		LM_ERR("null parameter\n");
		return -1;
	}

	/* get KV store from the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n", kv_bucket);
		return -1;
	}

	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	memset(&list, 0, sizeof(list));
	s = kvStore_History(&list, kv, key_buf, NULL);

	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found in history\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_History failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	entry_count = list.Count;

	/* build JSON array of historical values */
	buf = pkg_malloc(buf_size);
	if (!buf) {
		LM_ERR("no more pkg memory for history buffer\n");
		kvEntryList_Destroy(&list);
		return -1;
	}

	pos = 0;
	pos += snprintf(buf + pos, buf_size - pos, "[");

	for (i = 0; i < list.Count && pos < buf_size - 128; i++) {
		kvEntry *e = list.Entries[i];
		const char *eval = kvEntry_ValueString(e);
		int eval_len = kvEntry_ValueLen(e);

		if (i > 0)
			pos += snprintf(buf + pos, buf_size - pos, ",");

		/* JSON-encode: escape quotes in value for safety */
		pos += snprintf(buf + pos, buf_size - pos,
			"{\"rev\":%llu,\"value\":\"",
			(unsigned long long)kvEntry_Revision(e));

		/* Simple JSON string escape: replace '"' and '\' with their
		 * backslash-escaped forms.  The direct buf[pos++] writes bypass
		 * snprintf bounds checking, so we use a conservative limit:
		 * room for escape char + char + closing '"}' + NUL = 4 bytes. */
		int j;
		for (j = 0; j < eval_len && pos < buf_size - 4; j++) {
			if (eval[j] == '"' || eval[j] == '\\') {
				if (pos >= buf_size - 4) break;
				buf[pos++] = '\\';
			}
			buf[pos++] = eval[j];
		}

		pos += snprintf(buf + pos, buf_size - pos, "\"}");
	}

	pos += snprintf(buf + pos, buf_size - pos, "]");

	kvEntryList_Destroy(&list);

	/* set result variable */
	memset(&val, 0, sizeof(val));
	val.flags = PV_VAL_STR;
	val.rs.s = buf;
	val.rs.len = pos;
	pv_set_value(msg, result_var, 0, &val);
	pkg_free(buf);

	LM_DBG("kv_history for '%s': %d entries, %d bytes JSON\n",
		key_buf, entry_count, pos);
	return 1;
}

/* ================================================================== */
/*          Script functions: nats_kv_get / put / update / delete     */
/* ================================================================== */

/**
 * Get a KV entry's value and optionally its revision number.
 *
 * Script usage:
 *   nats_kv_get("opensips", "asr.model", $var(val), $var(rev));
 *   nats_kv_get("opensips", "asr.model", $var(val));  # rev is optional
 *
 * Returns:
 *   1  success (value and optionally revision stored)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_get(struct sip_msg *msg, str *bucket, str *key,
                  pv_spec_t *value_var, pv_spec_t *rev_var)
{
	kvStore *kv;
	kvEntry *entry = NULL;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	pv_value_t val;

	if (!bucket || !key || !value_var) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (native_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	/* set value pvar */
	const char *entry_val = kvEntry_ValueString(entry);
	int entry_len = kvEntry_ValueLen(entry);

	memset(&val, 0, sizeof(val));
	val.flags = PV_VAL_STR;
	val.rs.s = (char *)entry_val;
	val.rs.len = entry_len;
	pv_set_value(msg, value_var, 0, &val);

	/* set revision pvar (optional) */
	if (rev_var) {
		uint64_t rev = kvEntry_Revision(entry);
		char rev_buf[24];
		snprintf(rev_buf, sizeof(rev_buf), "%llu", (unsigned long long)rev);
		memset(&val, 0, sizeof(val));
		val.flags = PV_VAL_STR;
		val.rs.s = rev_buf;
		val.rs.len = strlen(rev_buf);
		pv_set_value(msg, rev_var, 0, &val);
	}

	LM_DBG("nats_kv_get '%s' = '%.*s' (rev=%llu)\n",
		key_buf, entry_len, entry_val,
		(unsigned long long)kvEntry_Revision(entry));

	kvEntry_Destroy(entry);
	return 1;
}

/**
 * Unconditional write to KV store.
 *
 * Script usage:
 *   nats_kv_put("opensips", "call.$ci.state", "recording");
 *
 * Returns:
 *   1  success
 *  -1  error
 */
int w_nats_kv_put(struct sip_msg *msg, str *bucket, str *key, str *value)
{
	kvStore *kv;
	natsStatus s;
	uint64_t rev;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	char val_buf[NATS_NATIVE_VAL_BUF];
	char *val_ptr = val_buf;
	int val_heap = 0;

	if (!bucket || !key || !value) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (native_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* null-terminate value, heap-alloc if too large for stack buf */
	if (value->s && value->len > 0) {
		if ((size_t)value->len >= sizeof(val_buf)) {
			val_ptr = pkg_malloc(value->len + 1);
			if (!val_ptr) {
				LM_ERR("no more pkg memory for value\n");
				return -1;
			}
			val_heap = 1;
		}
		memcpy(val_ptr, value->s, value->len);
		val_ptr[value->len] = '\0';
	} else {
		val_ptr[0] = '\0';
	}

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		if (val_heap) pkg_free(val_ptr);
		return -1;
	}

	s = kvStore_PutString(&rev, kv, key_buf, val_ptr);
	if (val_heap) pkg_free(val_ptr);

	if (s != NATS_OK) {
		LM_ERR("kvStore_PutString failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("nats_kv_put '%s' rev=%llu\n", key_buf, (unsigned long long)rev);
	return 1;
}

/**
 * Conditional (CAS) write to KV store.
 *
 * Script usage:
 *   nats_kv_get("opensips", "key", $var(val), $var(rev));
 *   # ... modify $var(val) ...
 *   nats_kv_update("opensips", "key", $var(new_val), $var(rev));
 *   # returns -2 on revision mismatch (concurrent update)
 *
 * Returns:
 *   1  success (CAS succeeded)
 *  -1  error
 *  -2  revision mismatch (caller should retry)
 */
int w_nats_kv_update(struct sip_msg *msg, str *bucket, str *key,
                     str *value, int *expected_rev)
{
	kvStore *kv;
	natsStatus s;
	uint64_t new_rev;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	char val_buf[NATS_NATIVE_VAL_BUF];
	char *val_ptr = val_buf;
	int val_heap = 0;

	if (!bucket || !key || !value || !expected_rev) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (native_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* null-terminate value */
	if (value->s && value->len > 0) {
		if ((size_t)value->len >= sizeof(val_buf)) {
			val_ptr = pkg_malloc(value->len + 1);
			if (!val_ptr) {
				LM_ERR("no more pkg memory for value\n");
				return -1;
			}
			val_heap = 1;
		}
		memcpy(val_ptr, value->s, value->len);
		val_ptr[value->len] = '\0';
	} else {
		val_ptr[0] = '\0';
	}

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		if (val_heap) pkg_free(val_ptr);
		return -1;
	}

	s = kvStore_UpdateString(&new_rev, kv, key_buf, val_ptr,
		(uint64_t)*expected_rev);
	if (val_heap) pkg_free(val_ptr);

	if (s == NATS_ERR || s == NATS_MISMATCH) {
		/* nats.c returns NATS_ERR with "wrong last sequence" on mismatch */
		LM_DBG("CAS mismatch for '%s' (expected rev %d)\n",
			key_buf, *expected_rev);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_UpdateString failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("nats_kv_update '%s' rev=%llu (was %d)\n",
		key_buf, (unsigned long long)new_rev, *expected_rev);
	return 1;
}

/**
 * Delete a key from the KV store.
 *
 * Script usage:
 *   nats_kv_delete("opensips", "call.$ci.state");
 *
 * Returns:
 *   1  success
 *  -1  error
 */
int w_nats_kv_delete(struct sip_msg *msg, str *bucket, str *key)
{
	kvStore *kv;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];

	if (!bucket || !key) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (native_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = kvStore_Delete(kv, key_buf);
	if (s != NATS_OK) {
		LM_ERR("kvStore_Delete failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("nats_kv_delete '%s'\n", key_buf);
	return 1;
}

/**
 * Read only the revision number of a KV key (lightweight check).
 *
 * Script usage:
 *   nats_kv_revision("opensips", "asr.model", $var(rev));
 *
 * Returns:
 *   1  success (revision stored)
 *  -1  error
 *  -2  key not found
 */
int w_nats_kv_revision(struct sip_msg *msg, str *bucket, str *key,
                       pv_spec_t *rev_var)
{
	kvStore *kv;
	kvEntry *entry = NULL;
	natsStatus s;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	pv_value_t val;

	if (!bucket || !key || !rev_var) {
		LM_ERR("null parameter\n");
		return -1;
	}

	if (native_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (native_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			key_buf, natsStatus_GetText(s));
		return -1;
	}

	uint64_t rev = kvEntry_Revision(entry);
	char rev_buf[24];
	kvEntry_Destroy(entry);

	snprintf(rev_buf, sizeof(rev_buf), "%llu", (unsigned long long)rev);
	memset(&val, 0, sizeof(val));
	val.flags = PV_VAL_STR;
	val.rs.s = rev_buf;
	val.rs.len = strlen(rev_buf);
	pv_set_value(msg, rev_var, 0, &val);

	LM_DBG("nats_kv_revision '%s' = %llu\n",
		key_buf, (unsigned long long)rev);
	return 1;
}

/* ================================================================== */
/*                     cachedb raw_query                              */
/* ================================================================== */

/* Forward declarations for raw_query sub-commands */
static int raw_kv_keys(kvStore *kv, cdb_raw_entry ***reply,
                       int expected_kv_no, int *reply_no);
static int raw_kv_purge(kvStore *kv, const char *key);
static int raw_kv_bucket_info(kvStore *kv, cdb_raw_entry ***reply,
                              int expected_kv_no, int *reply_no);

/**
 * nats_cache_raw_query_impl() — Dispatch raw NATS-specific commands.
 *
 * Implements the cachedb raw_query callback, providing a text-based command
 * interface for NATS operations that do not map to standard cachedb verbs.
 * The command string is tokenized with strtok_r (up to 3 space-delimited
 * tokens) and dispatched to the appropriate handler.
 *
 * Supported commands:
 *   "KV KEYS"              - list all keys in the bucket (raw_kv_keys)
 *   "KV PURGE <key>"       - purge all revisions of a key (raw_kv_purge)
 *   "KV BUCKET INFO"       - return bucket statistics (raw_kv_bucket_info)
 *   "STREAM INFO <name>"   - placeholder (not implemented)
 *   "STREAM PURGE <name>"  - placeholder (not implemented)
 *
 * Returns: 0 on success, -1 on error.
 */
int nats_cache_raw_query_impl(cachedb_con *con, str *attr,
                              cdb_raw_entry ***reply, int expected_kv_no,
                              int *reply_no)
{
	nats_cachedb_con *ncon;
	char cmd_buf[NATS_RAW_CMD_BUF];
	char *tok1, *tok2, *tok3, *saveptr;

	if (!con || !attr || !attr->s || attr->len <= 0) {
		LM_ERR("null or empty raw_query command\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	if (native_str_to_buf(attr, cmd_buf, sizeof(cmd_buf)) < 0)
		return -1;

	/* Tokenize the command string using strtok_r (reentrant).  We parse
	 * up to 3 space/tab-delimited tokens from the local cmd_buf copy.
	 * strtok_r modifies cmd_buf in place, inserting NUL terminators.
	 * tok1 = command group (e.g. "KV"), tok2 = sub-command (e.g. "KEYS"),
	 * tok3 = optional argument (e.g. key name for PURGE). */
	tok1 = strtok_r(cmd_buf, " \t", &saveptr);
	tok2 = strtok_r(NULL, " \t", &saveptr);
	tok3 = strtok_r(NULL, " \t", &saveptr);

	if (!tok1) {
		LM_ERR("empty raw_query command\n");
		return -1;
	}

	if (strcasecmp(tok1, "KV") == 0) {
		if (!tok2) {
			LM_ERR("KV sub-command missing\n");
			return -1;
		}

		if (strcasecmp(tok2, "KEYS") == 0) {
			return raw_kv_keys(ncon->kv, reply, expected_kv_no,
				reply_no);
		}

		if (strcasecmp(tok2, "PURGE") == 0) {
			if (!tok3) {
				LM_ERR("KV PURGE requires a key argument\n");
				return -1;
			}
			return raw_kv_purge(ncon->kv, tok3);
		}

		if (strcasecmp(tok2, "BUCKET") == 0) {
			if (tok3 && strcasecmp(tok3, "INFO") == 0) {
				return raw_kv_bucket_info(ncon->kv, reply,
					expected_kv_no, reply_no);
			}
			LM_ERR("unknown KV BUCKET sub-command: %s\n",
				tok3 ? tok3 : "(none)");
			return -1;
		}

		LM_ERR("unknown KV sub-command: %s\n", tok2);
		return -1;
	}

	if (strcasecmp(tok1, "STREAM") == 0) {
		LM_ERR("STREAM commands not yet implemented (got: STREAM %s %s)\n",
			tok2 ? tok2 : "", tok3 ? tok3 : "");
		return -1;
	}

	LM_ERR("unknown raw_query command: %s\n", tok1);
	return -1;
}

/**
 * raw_kv_keys() — List all keys in the NATS KV bucket.
 *
 * Calls kvStore_Keys() to enumerate every key in the bucket, then builds
 * a cdb_raw_entry result set with one row per key.  Each row contains a
 * single CDB_STR column holding the key name.  The caller (cachedb core)
 * owns the returned memory and is responsible for freeing it.
 *
 * Returns: 0 on success (even if bucket is empty), -1 on error.
 */
static int raw_kv_keys(kvStore *kv, cdb_raw_entry ***reply,
                       int expected_kv_no, int *reply_no)
{
	kvKeysList keys;
	natsStatus s;
	cdb_raw_entry **rows;
	int i, key_count;

	memset(&keys, 0, sizeof(keys));
	s = kvStore_Keys(&keys, kv, NULL);

	if (s == NATS_NOT_FOUND) {
		/* empty bucket */
		if (reply_no)
			*reply_no = 0;
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", natsStatus_GetText(s));
		return -1;
	}

	key_count = keys.Count;

	if (key_count <= 0) {
		kvKeysList_Destroy(&keys);
		if (reply_no)
			*reply_no = 0;
		return 0;
	}

	/* Allocate the cdb_raw_entry reply array.  The cachedb core expects
	 * a two-level allocation: an array of row pointers (rows[]), where
	 * each row is a separately allocated array of cdb_raw_entry structs
	 * (one per column).  For KV KEYS we have 1 column per row.  Each
	 * string value gets its own pkg_malloc'd buffer that the cachedb
	 * core will free after consuming the results. */
	rows = pkg_malloc(key_count * sizeof(cdb_raw_entry *));
	if (!rows) {
		LM_ERR("no more pkg memory for keys reply\n");
		kvKeysList_Destroy(&keys);
		return -1;
	}

	/* Iterate over kvKeysList: keys.Keys[i] is a C string owned by
	 * the NATS client library.  We must copy each key before calling
	 * kvKeysList_Destroy() which frees the underlying storage. */
	for (i = 0; i < key_count; i++) {
		rows[i] = pkg_malloc(sizeof(cdb_raw_entry));
		if (!rows[i]) {
			LM_ERR("no more pkg memory for key entry %d\n", i);
			/* free what we allocated so far */
			int j;
			for (j = 0; j < i; j++)
				pkg_free(rows[j]);
			pkg_free(rows);
			kvKeysList_Destroy(&keys);
			return -1;
		}
		memset(rows[i], 0, sizeof(cdb_raw_entry));

		rows[i][0].type = CDB_STR;
		int klen = strlen(keys.Keys[i]);
		rows[i][0].val.s.s = pkg_malloc(klen + 1);
		if (!rows[i][0].val.s.s) {
			LM_ERR("no more pkg memory for key string %d\n", i);
			pkg_free(rows[i]);
			int j;
			for (j = 0; j < i; j++) {
				if (rows[j][0].val.s.s)
					pkg_free(rows[j][0].val.s.s);
				pkg_free(rows[j]);
			}
			pkg_free(rows);
			kvKeysList_Destroy(&keys);
			return -1;
		}
		memcpy(rows[i][0].val.s.s, keys.Keys[i], klen);
		rows[i][0].val.s.s[klen] = '\0';
		rows[i][0].val.s.len = klen;
	}

	kvKeysList_Destroy(&keys);

	if (reply)
		*reply = rows;
	if (reply_no)
		*reply_no = key_count;

	LM_DBG("KV KEYS returned %d keys\n", key_count);
	return 0;
}

/**
 * raw_kv_purge() — Purge all revisions of a key from the NATS KV bucket.
 *
 * Removes the key and all of its historical revisions from the underlying
 * JetStream stream.  This is a destructive operation — purged data cannot
 * be recovered.  The operation is idempotent: purging a non-existent key
 * returns success (0).
 *
 * Returns: 0 on success, -1 on error.
 */
static int raw_kv_purge(kvStore *kv, const char *key)
{
	natsStatus s;

	s = kvStore_Purge(kv, key, NULL);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("KV PURGE: key '%s' not found\n", key);
		return 0; /* idempotent */
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Purge failed for key '%s': %s\n",
			key, natsStatus_GetText(s));
		return -1;
	}

	LM_DBG("KV PURGE: purged key '%s'\n", key);
	return 0;
}

/**
 * raw_kv_bucket_info() — Return bucket statistics as a JSON-like result set.
 *
 * Queries the NATS KV bucket status and returns a single-row result with
 * six columns describing the bucket configuration and usage:
 *   col 0: bucket name (CDB_STR)
 *   col 1: number of live values (CDB_INT32)
 *   col 2: max history depth per key (CDB_INT32)
 *   col 3: TTL in seconds (CDB_INT32, converted from NATS nanoseconds)
 *   col 4: replica count (CDB_INT32)
 *   col 5: total bytes stored (CDB_INT32)
 *
 * Returns: 0 on success, -1 on error.
 */
static int raw_kv_bucket_info(kvStore *kv, cdb_raw_entry ***reply,
                              int expected_kv_no, int *reply_no)
{
	kvStatus *sts = NULL;
	natsStatus s;
	cdb_raw_entry **rows;
	const char *bname;
	int blen;

	s = kvStore_Status(&sts, kv);
	if (s != NATS_OK) {
		LM_ERR("kvStore_Status failed: %s\n", natsStatus_GetText(s));
		return -1;
	}

	/* allocate 1 row with 6 columns */
	rows = pkg_malloc(sizeof(cdb_raw_entry *));
	if (!rows) {
		kvStatus_Destroy(sts);
		return -1;
	}
	rows[0] = pkg_malloc(6 * sizeof(cdb_raw_entry));
	if (!rows[0]) {
		pkg_free(rows);
		kvStatus_Destroy(sts);
		return -1;
	}
	memset(rows[0], 0, 6 * sizeof(cdb_raw_entry));

	/* col 0: bucket name */
	bname = kvStatus_Bucket(sts);
	blen = bname ? strlen(bname) : 0;
	rows[0][0].type = CDB_STR;
	if (blen > 0) {
		rows[0][0].val.s.s = pkg_malloc(blen);
		if (rows[0][0].val.s.s) {
			memcpy(rows[0][0].val.s.s, bname, blen);
			rows[0][0].val.s.len = blen;
		}
	}

	/* col 1: values count */
	rows[0][1].type = CDB_INT32;
	rows[0][1].val.n = (int)kvStatus_Values(sts);

	/* col 2: history */
	rows[0][2].type = CDB_INT32;
	rows[0][2].val.n = (int)kvStatus_History(sts);

	/* col 3: ttl (in nanoseconds from NATS, convert to seconds) */
	rows[0][3].type = CDB_INT32;
	rows[0][3].val.n = (int)(kvStatus_TTL(sts) / 1000000000LL);

	/* col 4: replicas */
	rows[0][4].type = CDB_INT32;
	rows[0][4].val.n = (int)kvStatus_Replicas(sts);

	/* col 5: bytes */
	rows[0][5].type = CDB_INT32;
	rows[0][5].val.n = (int)kvStatus_Bytes(sts);

	kvStatus_Destroy(sts);

	if (reply)
		*reply = rows;
	if (reply_no)
		*reply_no = 1;

	LM_DBG("KV BUCKET INFO returned successfully\n");
	return 0;
}

/* ================================================================== */
/*                       Map operations                               */
/* ================================================================== */

/**
 * build_map_key() — Construct a composite "key:subkey" string in a buffer.
 *
 * Concatenates key, the NATS_MAP_SEP separator (':'), and subkey into buf,
 * then null-terminates.  The buffer must be large enough for
 * key->len + 1 + subkey->len + 1 bytes (content + separator + NUL).
 *
 * If subkey is NULL or empty, the function falls back to copying just the
 * key via native_str_to_buf().
 *
 * Returns: 0 on success, -1 if inputs are invalid or the buffer is too small.
 */
static int build_map_key(char *buf, size_t buf_size,
                         const str *key, const str *subkey)
{
	int total;

	if (!key || !key->s || key->len <= 0) {
		LM_ERR("null or empty map key\n");
		return -1;
	}

	if (!subkey || !subkey->s || subkey->len <= 0) {
		/* no subkey — just the key */
		return native_str_to_buf(key, buf, buf_size);
	}

	total = key->len + 1 + subkey->len; /* key:subkey (without NUL) */
	/* need total + 1 bytes for the NUL terminator */
	if ((size_t)(total + 1) > buf_size) {
		LM_ERR("map key too long (%d + 1 > %zu)\n", total, buf_size);
		return -1;
	}

	memcpy(buf, key->s, key->len);
	buf[key->len] = NATS_MAP_SEP;
	memcpy(buf + key->len + 1, subkey->s, subkey->len);
	buf[total] = '\0';
	return 0;
}

/**
 * nats_cache_map_get() — Retrieve all subkeys matching a "key:*" prefix.
 *
 * Implements the cachedb map_get callback using a composite key pattern.
 * NATS KV has no native hash-map type, so map semantics are emulated by
 * storing each field as a separate KV entry with the key "prefix:field".
 *
 * This function lists all keys in the bucket via kvStore_Keys(), filters
 * for those starting with "key:", fetches each matching value, and builds
 * a cdb_res_t result set.  Each result row contains one cdb_pair_t whose
 * key name is the subkey portion (after the ':') and whose value is the
 * stored string.
 *
 * Returns: 0 on success (even if no keys match), -1 on error.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res)
{
	nats_cachedb_con *ncon;
	kvKeysList keys;
	natsStatus s;
	char prefix[NATS_NATIVE_KEY_BUF];
	int prefix_len;
	int i;

	if (!con || !key || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	cdb_res_init(res);

	/* build the prefix "key:" for client-side filtering */
	if (key->len <= 0 || (size_t)key->len >= sizeof(prefix) - 2) {
		LM_ERR("invalid map key length\n");
		return -1;
	}
	memcpy(prefix, key->s, key->len);
	prefix[key->len] = NATS_MAP_SEP;
	prefix[key->len + 1] = '\0';
	prefix_len = key->len + 1;

	/* list all keys */
	memset(&keys, 0, sizeof(keys));
	s = kvStore_Keys(&keys, ncon->kv, NULL);

	if (s == NATS_NOT_FOUND) {
		LM_DBG("map_get: no keys in bucket\n");
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", natsStatus_GetText(s));
		return -1;
	}

	/* Iterate the kvKeysList: keys.Count entries in keys.Keys[].
	 * NATS KV has no server-side prefix filter, so we do client-side
	 * filtering by comparing each key against the "key:" prefix.
	 * For each match, we fetch the value and build a cdb_row_t with
	 * a single cdb_pair_t containing the subkey name and value. */
	for (i = 0; i < keys.Count; i++) {
		int klen = strlen(keys.Keys[i]);
		kvEntry *entry = NULL;
		cdb_row_t *row;
		cdb_pair_t *pair;
		const char *val_data;
		int val_len;
		str subkey_str;

		if (klen <= prefix_len)
			continue;
		if (strncmp(keys.Keys[i], prefix, prefix_len) != 0)
			continue;

		/* fetch the value */
		s = kvStore_Get(&entry, ncon->kv, keys.Keys[i]);
		if (s != NATS_OK) {
			LM_DBG("map_get: skipping key '%s' (get failed)\n",
				keys.Keys[i]);
			continue;
		}

		val_data = kvEntry_ValueString(entry);
		val_len = kvEntry_ValueLen(entry);

		/* create result row */
		row = pkg_malloc(sizeof(cdb_row_t));
		if (!row) {
			kvEntry_Destroy(entry);
			continue;
		}
		memset(row, 0, sizeof(cdb_row_t));
		INIT_LIST_HEAD(&row->dict);

		/* create pair: subkey name = value */
		pair = pkg_malloc(sizeof(cdb_pair_t));
		if (!pair) {
			pkg_free(row);
			kvEntry_Destroy(entry);
			continue;
		}
		memset(pair, 0, sizeof(cdb_pair_t));
		INIT_LIST_HEAD(&pair->list);

		/* set the subkey name (part after prefix) */
		subkey_str.s = keys.Keys[i] + prefix_len;
		subkey_str.len = klen - prefix_len;

		pair->key.name.s = pkg_malloc(subkey_str.len);
		if (!pair->key.name.s) {
			LM_ERR("no more pkg memory for subkey name\n");
			pkg_free(pair);
			pkg_free(row);
			kvEntry_Destroy(entry);
			continue;
		}
		memcpy(pair->key.name.s, subkey_str.s, subkey_str.len);
		pair->key.name.len = subkey_str.len;

		/* set the value */
		pair->val.type = CDB_STR;
		if (val_data && val_len > 0) {
			pair->val.val.st.s = pkg_malloc(val_len);
			if (pair->val.val.st.s) {
				memcpy(pair->val.val.st.s, val_data, val_len);
				pair->val.val.st.len = val_len;
			}
		}

		list_add_tail(&pair->list, &row->dict);
		list_add_tail(&row->list, &res->rows);
		res->count++;

		kvEntry_Destroy(entry);
	}

	kvKeysList_Destroy(&keys);

	LM_DBG("map_get for '%.*s': %d entries\n", key->len, key->s,
		res->count);
	return 0;
}

/**
 * nats_cache_map_set() — Store key-value pairs under composite keys.
 *
 * Implements the cachedb map_set callback.  Each pair in the input dict
 * is stored as a separate NATS KV entry with a constructed composite key:
 *
 *   - With subkey:    "key:subkey:pair_name" = value
 *   - Without subkey: "key:pair_name" = value
 *
 * The key:subkey construction allows hash-map semantics on top of flat
 * NATS KV.  Values are converted to strings (CDB_STR used directly,
 * CDB_INT32 formatted via snprintf).
 *
 * Returns: 0 on success, -1 on error (including partial failures).
 */
int nats_cache_map_set(cachedb_con *con, const str *key, const str *subkey,
                       const cdb_dict_t *pairs)
{
	nats_cachedb_con *ncon;
	char map_key[NATS_MAP_KEY_BUF];
	char val_buf[NATS_NATIVE_VAL_BUF];
	uint64_t rev;
	natsStatus s;
	cdb_pair_t *pair;
	struct list_head *it;

	if (!con || !key || !pairs) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	/* if subkey is provided, build "key:subkey" composite key and
	 * store each pair's value under that single key */
	if (subkey && subkey->s && subkey->len > 0) {
		if (build_map_key(map_key, sizeof(map_key), key, subkey) < 0)
			return -1;

		/* for map_set with a single subkey, iterate pairs and store
		 * each as "key:subkey:pair_name" */
		list_for_each(it, (struct list_head *)pairs) {
			char full_key[NATS_MAP_KEY_BUF];
			int mk_len = strlen(map_key);
			int pk_len;

			pair = list_entry(it, cdb_pair_t, list);
			if (!pair->key.name.s || pair->key.name.len <= 0)
				continue;

			pk_len = pair->key.name.len;
			if ((size_t)(mk_len + 1 + pk_len) >= sizeof(full_key)) {
				LM_ERR("composite key too long\n");
				return -1;
			}

			memcpy(full_key, map_key, mk_len);
			full_key[mk_len] = NATS_MAP_SEP;
			memcpy(full_key + mk_len + 1, pair->key.name.s, pk_len);
			full_key[mk_len + 1 + pk_len] = '\0';

			/* convert value to string */
			if (pair->val.type == CDB_STR) {
				if (native_str_to_buf(&pair->val.val.st, val_buf,
						sizeof(val_buf)) < 0)
					return -1;
			} else if (pair->val.type == CDB_INT32) {
				snprintf(val_buf, sizeof(val_buf), "%d",
					pair->val.val.i32);
			} else {
				LM_DBG("skipping unsupported value type %d\n",
					pair->val.type);
				continue;
			}

			s = kvStore_PutString(&rev, ncon->kv, full_key, val_buf);
			if (s != NATS_OK) {
				LM_ERR("kvStore_PutString failed for '%s': %s\n",
					full_key, natsStatus_GetText(s));
				return -1;
			}
			LM_DBG("map_set: stored '%s' rev=%llu\n", full_key,
				(unsigned long long)rev);
		}
	} else {
		/* no subkey: store each pair as "key:pair_name" */
		list_for_each(it, (struct list_head *)pairs) {
			str pair_name;

			pair = list_entry(it, cdb_pair_t, list);
			if (!pair->key.name.s || pair->key.name.len <= 0)
				continue;

			pair_name = pair->key.name;
			if (build_map_key(map_key, sizeof(map_key), key,
					&pair_name) < 0)
				return -1;

			/* convert value to string */
			if (pair->val.type == CDB_STR) {
				if (native_str_to_buf(&pair->val.val.st, val_buf,
						sizeof(val_buf)) < 0)
					return -1;
			} else if (pair->val.type == CDB_INT32) {
				snprintf(val_buf, sizeof(val_buf), "%d",
					pair->val.val.i32);
			} else {
				LM_DBG("skipping unsupported value type %d\n",
					pair->val.type);
				continue;
			}

			s = kvStore_PutString(&rev, ncon->kv, map_key, val_buf);
			if (s != NATS_OK) {
				LM_ERR("kvStore_PutString failed for '%s': %s\n",
					map_key, natsStatus_GetText(s));
				return -1;
			}
			LM_DBG("map_set: stored '%s' rev=%llu\n", map_key,
				(unsigned long long)rev);
		}
	}

	return 0;
}

/**
 * nats_cache_map_remove() — Delete map entries by composite key.
 *
 * Implements the cachedb map_remove callback.  Two modes of operation:
 *
 *   - Single removal (subkey provided): Constructs "key:subkey" and deletes
 *     that single NATS KV entry.
 *
 *   - Prefix removal (no subkey): Lists all keys in the bucket, filters for
 *     those starting with "key:", and deletes each matching entry.  This
 *     effectively removes the entire "hash map" associated with the key.
 *
 * Deletion of non-existent keys is treated as success (idempotent).
 *
 * Returns: 0 on success, -1 on error.
 */
int nats_cache_map_remove(cachedb_con *con, const str *key,
                          const str *subkey)
{
	nats_cachedb_con *ncon;
	natsStatus s;
	char map_key[NATS_MAP_KEY_BUF];

	if (!con || !key) {
		LM_ERR("null parameter\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon || !ncon->kv) {
		LM_ERR("null NATS connection or KV store\n");
		return -1;
	}

	if (subkey && subkey->s && subkey->len > 0) {
		/* delete single key:subkey */
		if (build_map_key(map_key, sizeof(map_key), key, subkey) < 0)
			return -1;

		s = kvStore_Delete(ncon->kv, map_key);
		if (s != NATS_OK && s != NATS_NOT_FOUND) {
			LM_ERR("kvStore_Delete failed for '%s': %s\n",
				map_key, natsStatus_GetText(s));
			return -1;
		}
		LM_DBG("map_remove: deleted '%s'\n", map_key);
	} else {
		/* delete all keys with prefix "key:" */
		kvKeysList keys;
		char prefix[NATS_NATIVE_KEY_BUF];
		int prefix_len;
		int i;

		if (key->len <= 0 ||
				(size_t)key->len >= sizeof(prefix) - 2) {
			LM_ERR("invalid map key length\n");
			return -1;
		}
		memcpy(prefix, key->s, key->len);
		prefix[key->len] = NATS_MAP_SEP;
		prefix[key->len + 1] = '\0';
		prefix_len = key->len + 1;

		memset(&keys, 0, sizeof(keys));
		s = kvStore_Keys(&keys, ncon->kv, NULL);
		if (s == NATS_NOT_FOUND) {
			LM_DBG("map_remove: no keys in bucket\n");
			return 0;
		}
		if (s != NATS_OK) {
			LM_ERR("kvStore_Keys failed: %s\n",
				natsStatus_GetText(s));
			return -1;
		}

		for (i = 0; i < keys.Count; i++) {
			int klen = strlen(keys.Keys[i]);
			if (klen <= prefix_len)
				continue;
			if (strncmp(keys.Keys[i], prefix, prefix_len) != 0)
				continue;

			s = kvStore_Delete(ncon->kv, keys.Keys[i]);
			if (s != NATS_OK && s != NATS_NOT_FOUND) {
				LM_WARN("map_remove: failed to delete '%s': %s\n",
					keys.Keys[i], natsStatus_GetText(s));
			} else {
				LM_DBG("map_remove: deleted '%s'\n",
					keys.Keys[i]);
			}
		}

		kvKeysList_Destroy(&keys);
	}

	return 0;
}
