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
#include <limits.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../cachedb/cachedb.h"

#include "cachedb_nats_native.h"
#include "cachedb_nats.h"
#include "cachedb_nats_dbase.h"
#include "../../lib/nats/nats_pool.h"
#include "cachedb_nats_ttl.h"   /* nats_kv_put_row + enum ttl_outcome (CAS classify) */
#include "../../lib/nats/nats_str.h"
#include "../../mi/mi.h"
#include "../../mi/item.h"

/* maximum buffer sizes (reuse from dbase.h) */
#define NATS_NATIVE_KEY_BUF   512
#define NATS_NATIVE_VAL_BUF   4096
#define NATS_MAP_KEY_BUF      1024
#define NATS_HISTORY_BUF      8192
#define NATS_RAW_CMD_BUF      256

/* Structural separator between the (hex-escaped) map key and field in a
 * composed map subject:  enc(key) '.' enc(field).  '.' is the NATS subject
 * token separator, so an exact server-side prefix filter "enc(key).>" can
 * list one map without scanning the whole bucket.  Both components are
 * hex-escaped (nats_map_encode) so they never contain a raw '.', keeping the
 * structure unambiguous and letting users put any byte in a key/field. */
#define NATS_MAP_SEP    '.'
/* Legacy separator (':') used by map entries written before the format
 * change.  Reads fall back to a legacy scan for these while
 * nats_map_legacy_read is enabled; nats_map_migrate rewrites them. */
#define NATS_MAP_SEP_LEGACY ':'

/* defined in cachedb_nats.c — caps the per-call pkg_malloc in
 * w_nats_request to bound resource usage when a remote responder
 * sends an oversized reply. */
extern int nats_request_max_reply;

/* defined in cachedb_nats.c — default request timeout when caller
 * passes 0 or negative.  Bounded by NATS_REQUEST_MIN_TIMEOUT_MS and
 * the existing 30 s upper clamp. */
extern int nats_request_default_timeout_ms;

/* Floor for any positive caller-supplied timeout.  Below this the
 * cnats library's behavior is undefined and a 0 ms timeout is
 * effectively "give up before the request leaves the host." */
#define NATS_REQUEST_MIN_TIMEOUT_MS  10

/* Ceiling for any caller-supplied timeout.  A SIP worker holding the
 * w_nats_request call cannot service other traffic until the request
 * either replies or times out, so the upper bound has to keep the
 * worker available for SIP work even when the responder is wedged.
 * 30 s matches OpenSIPS's default fr_timer for in-flight transactions
 * -- a request that hasn't replied in that window is dead from the
 * caller's perspective. */
#define NATS_REQUEST_MAX_TIMEOUT_MS  30000

/* nats_str_to_buf() was consolidated into lib/nats/nats_str.h as
 * nats_str_to_buf() -- see P3-63. */

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

	/* Fast-fail if the pool is currently disconnected.  cnats would
	 * otherwise block this SIP worker for up to 30 s waiting for a
	 * reconnect that may not come in time. */
	if (!nats_pool_is_connected()) {
		LM_DBG("nats_request: pool disconnected, fast-failing\n");
		return -1;
	}

	/* Normalize the caller-supplied timeout into a sane range.
	 *   - <= 0:                                substitute the configured default
	 *   - 1..NATS_REQUEST_MIN_TIMEOUT_MS-1:    clamp up to MIN (cnats
	 *                                          behavior under tiny
	 *                                          timeouts is impl-defined)
	 *   - > NATS_REQUEST_MAX_TIMEOUT_MS:       clamp down to MAX
	 *   - in-range:                            unchanged
	 *
	 * Use a local variable for the effective timeout so we don't
	 * mutate the caller's pvar in-place (which the old code did). */
	int eff = *timeout_ms;
	if (eff <= 0) eff = nats_request_default_timeout_ms;
	if (eff < NATS_REQUEST_MIN_TIMEOUT_MS)
		eff = NATS_REQUEST_MIN_TIMEOUT_MS;
	if (eff > NATS_REQUEST_MAX_TIMEOUT_MS) {
		static int warned = 0;
		if (!warned) {
			LM_WARN("nats_request timeout %d ms clamped to %d ms\n",
				eff, NATS_REQUEST_MAX_TIMEOUT_MS);
			warned = 1;
		}
		eff = NATS_REQUEST_MAX_TIMEOUT_MS;
	}

	/* null-terminate subject */
	if (nats_str_to_buf(subject, subj_buf, sizeof(subj_buf)) < 0)
		return -1;

	/* null-terminate payload (use heap for large payloads).
	 * Guard the source descriptor: a corrupted str with a negative
	 * length would underflow the (size_t) cast below and an empty/NULL
	 * payload must not be fed to memcpy. Treat NULL/empty as "". */
	if (payload->len < 0) {
		LM_ERR("nats_request: negative payload length (%d)\n",
			payload->len);
		return -1;
	}
	if (!payload->s || payload->len == 0) {
		pay_buf[0] = '\0';
	} else if ((size_t)payload->len < sizeof(pay_buf)) {
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

	s = nats_dl.natsConnection_RequestString(&reply, nc, subj_buf,
		pay_ptr, eff);

	if (pay_heap)
		pkg_free(pay_ptr);

	if (s == NATS_TIMEOUT) {
		LM_DBG("nats_request to '%s' timed out (%dms)\n",
			subj_buf, eff);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("nats_request to '%s' failed: %s\n",
			subj_buf, nats_dl.natsStatus_GetText(s));
		return -1;
	}

	/* copy reply data before destroying message — but cap the size
	 * first to bound peer-controlled allocation. */
	reply_len = nats_dl.natsMsg_GetDataLength(reply);
	if (reply_len < 0 || reply_len > nats_request_max_reply) {
		LM_ERR("nats_request to '%s' rejected: reply size %d "
			"exceeds nats_request_max_reply=%d\n",
			subj_buf, reply_len, nats_request_max_reply);
		nats_dl.natsMsg_Destroy(reply);
		return -1;
	}
	reply_copy = pkg_malloc(reply_len + 1);
	if (!reply_copy) {
		LM_ERR("no more pkg memory for reply (%d bytes)\n", reply_len);
		nats_dl.natsMsg_Destroy(reply);
		return -1;
	}
	memcpy(reply_copy, nats_dl.natsMsg_GetData(reply), reply_len);
	reply_copy[reply_len] = '\0';
	nats_dl.natsMsg_Destroy(reply);

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
	if (validate_kv_key(key) < 0)
		return -1;

	/* Fast-fail when the broker is down (see the other w_nats_kv_* ops). */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — kv_history deferred (fast-fail)\n");
		return -1;
	}

	/* get KV store from the shared pool */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n", kv_bucket);
		return -1;
	}

	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	memset(&list, 0, sizeof(list));
	s = nats_dl.kvStore_History(&list, kv, key_buf, NULL);

	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found in history\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_History failed for '%s': %s\n",
			key_buf, nats_dl.natsStatus_GetText(s));
		return -1;
	}

	entry_count = list.Count;

	/* build JSON array of historical values */
	buf = pkg_malloc(buf_size);
	if (!buf) {
		LM_ERR("no more pkg memory for history buffer\n");
		nats_dl.kvEntryList_Destroy(&list);
		return -1;
	}

	pos = 0;

	/* snprintf() returns the number of bytes it WOULD have written, which
	 * on truncation exceeds the size limit and can push `pos` past
	 * buf_size.  The next call would then compute buf_size - pos as a
	 * negative int that converts to a huge size_t, defeating the bound
	 * and overrunning the buffer.  Clamp pos after every advance so the
	 * remaining size can never underflow. */
#define HIST_ADVANCE(...) do { \
		int _w = snprintf(buf + pos, (size_t)(buf_size - pos), \
			__VA_ARGS__); \
		if (_w < 0) { pos = buf_size - 1; } \
		else { \
			pos += _w; \
			if (pos >= buf_size) pos = buf_size - 1; \
		} \
	} while (0)

	HIST_ADVANCE("[");

	for (i = 0; i < list.Count && pos < buf_size - 128; i++) {
		kvEntry *e = list.Entries[i];
		const char *eval = nats_dl.kvEntry_ValueString(e);
		int eval_len = nats_dl.kvEntry_ValueLen(e);

		if (i > 0)
			HIST_ADVANCE(",");

		/* JSON-encode: escape quotes in value for safety */
		HIST_ADVANCE("{\"rev\":%llu,\"value\":\"",
			(unsigned long long)nats_dl.kvEntry_Revision(e));

		/* JSON string escape.  '"' and '\' get a backslash; control chars
		 * (< 0x20) are NOT legal raw in a JSON string and would produce
		 * malformed output, so escape them as \u00xx.  The direct
		 * buf[pos++] writes bypass snprintf bounds checking; a \u00xx
		 * escape needs 6 bytes plus the closing '"}' + NUL, so keep 9
		 * bytes of headroom. */
		int j;
		static const char _hex[] = "0123456789abcdef";
		for (j = 0; eval && j < eval_len && pos < buf_size - 9; j++) {
			unsigned char vc = (unsigned char)eval[j];
			if (vc == '"' || vc == '\\') {
				buf[pos++] = '\\';
				buf[pos++] = (char)vc;
			} else if (vc < 0x20) {
				buf[pos++] = '\\';
				buf[pos++] = 'u';
				buf[pos++] = '0';
				buf[pos++] = '0';
				buf[pos++] = _hex[vc >> 4];
				buf[pos++] = _hex[vc & 0x0f];
			} else {
				buf[pos++] = (char)vc;
			}
		}

		HIST_ADVANCE("\"}");
	}

	HIST_ADVANCE("]");
#undef HIST_ADVANCE

	nats_dl.kvEntryList_Destroy(&list);

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
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			key_buf, nats_dl.natsStatus_GetText(s));
		return -1;
	}

	/* Copy the value out of the kvEntry into worker-local memory before
	 * destroying the entry — same defensive pattern as w_nats_request.
	 * Every current OpenSIPS pvar setter copies PV_VAL_STR data, so the
	 * existing inline use was safe today, but the explicit copy keeps
	 * us robust if any future module-defined pvar setter forgets to. */
	{
		const char *entry_val = nats_dl.kvEntry_ValueString(entry);
		int entry_len = nats_dl.kvEntry_ValueLen(entry);
		uint64_t rev = nats_dl.kvEntry_Revision(entry);
		char *value_copy = pkg_malloc(entry_len + 1);
		if (!value_copy) {
			LM_ERR("no more pkg memory for kv value (%d bytes)\n",
				entry_len);
			nats_dl.kvEntry_Destroy(entry);
			return -1;
		}
		memcpy(value_copy, entry_val, entry_len);
		value_copy[entry_len] = '\0';
		nats_dl.kvEntry_Destroy(entry);
		entry = NULL;

		/* set value pvar */
		memset(&val, 0, sizeof(val));
		val.flags = PV_VAL_STR;
		val.rs.s = value_copy;
		val.rs.len = entry_len;
		pv_set_value(msg, value_var, 0, &val);

		/* set revision pvar (optional)
		 *
		 * Set both PV_VAL_STR and PV_VAL_INT so the rev can drive a
		 * subsequent nats_kv_update() — that wrapper takes
		 * CMD_PARAM_INT, and core's get_cmd_fixups() rejects script
		 * vars that lack PV_VAL_INT with "Variable in param [N] is not
		 * an integer" (mod_fix.c:366-370).  Without the int flag CAS
		 * is unusable from script.
		 *
		 * Truncation: NATS revisions are uint64; OpenSIPS script ints
		 * are 32-bit.  In practice INT_MAX revisions per key is many
		 * decades of updates; we warn if we ever cross it. */
		if (rev_var) {
			char rev_buf[24];
			int rev_buf_len = snprintf(rev_buf, sizeof(rev_buf), "%llu",
				(unsigned long long)rev);
			if (rev > (uint64_t)INT_MAX) {
				LM_WARN("KV revision %llu for '%s' exceeds INT_MAX; "
					"script var will receive a truncated int — CAS using "
					"this var will fail\n",
					(unsigned long long)rev, key_buf);
			}
			memset(&val, 0, sizeof(val));
			/* PV_TYPE_INT tells pv_set_scriptvar to store the var as int
			 * (avp_val.n); without it the setter falls back to str storage
			 * and the next read will not restore PV_VAL_INT, so CAS via
			 * nats_kv_update($var(rev)) is rejected at fixup time with
			 * "Variable in param [N] is not an integer". */
			val.flags = PV_VAL_STR | PV_VAL_INT | PV_TYPE_INT;
			val.rs.s = rev_buf;
			val.rs.len = rev_buf_len;
			val.ri = (int)rev;
			pv_set_value(msg, rev_var, 0, &val);
		}

		LM_DBG("nats_kv_get '%s' = '%.*s' (rev=%llu)\n",
			key_buf, entry_len, value_copy,
			(unsigned long long)rev);

		pkg_free(value_copy);
	}
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
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
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

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		if (val_heap) pkg_free(val_ptr);
		return -1;
	}

	s = nats_dl.kvStore_PutString(&rev, kv, key_buf, val_ptr);
	if (val_heap) pkg_free(val_ptr);

	if (s != NATS_OK) {
		LM_ERR("kvStore_PutString failed for '%s': %s\n",
			key_buf, nats_dl.natsStatus_GetText(s));
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
	uint64_t new_rev = 0;
	char bucket_buf[NATS_NATIVE_KEY_BUF];
	char key_buf[NATS_NATIVE_KEY_BUF];
	char val_buf[NATS_NATIVE_VAL_BUF];
	char *val_ptr = val_buf;
	int val_heap = 0;

	if (!bucket || !key || !value || !expected_rev) {
		LM_ERR("null parameter\n");
		return -1;
	}
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
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

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		if (val_heap) pkg_free(val_ptr);
		return -1;
	}

	/* Route the CAS through nats_kv_put_row (js_PublishMsg with
	 * ExpectLastSubjectSeq == *expected_rev -- byte-for-byte the optimistic
	 * check kvStore_UpdateString(rev) performs) rather than
	 * kvStore_UpdateString itself.  js_PublishMsg returns the numeric
	 * jsErrCode inline, so we can distinguish a genuine revision conflict
	 * (10071 -> TTL_RETRY -> -2, the caller re-reads and retries) from a
	 * generic/transient failure (-1, not retryable).  The old path collapsed
	 * every NATS_ERR into -2, so a script CAS loop could spin on a
	 * non-retryable error.  ttl=0: a plain CAS update, no per-message TTL.
	 * got_entry=1 / value_len=1: an existing (non-marker) row updated at rev. */
	{
		jsCtx *js = nats_pool_get_js();
		enum ttl_outcome o = nats_kv_put_row(js, kv,
			bucket_buf[0] ? bucket_buf : kv_bucket, key_buf,
			val_ptr, value->len > 0 ? value->len : 0,
			/*got_entry=*/1, /*value_len=*/1,
			(uint64_t)*expected_rev, /*msg_ttl_ms=*/0, &new_rev);
		if (val_heap) pkg_free(val_ptr);

		if (o == TTL_RETRY) {
			LM_DBG("CAS mismatch for '%s' (expected rev %d)\n",
				key_buf, *expected_rev);
			return -2;
		}
		if (o != TTL_DONE) {
			LM_ERR("kv update CAS failed for '%s' (outcome %d)\n",
				key_buf, (int)o);
			return -1;
		}
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
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Delete(kv, key_buf);
	if (s != NATS_OK) {
		LM_ERR("kvStore_Delete failed for '%s': %s\n",
			key_buf, nats_dl.natsStatus_GetText(s));
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
	if (validate_kv_key(key) < 0)
		return -1;

	if (nats_str_to_buf(bucket, bucket_buf, sizeof(bucket_buf)) < 0)
		return -1;
	if (nats_str_to_buf(key, key_buf, sizeof(key_buf)) < 0)
		return -1;

	/* Fast-fail when the broker is down: nats_pool_get_kv() + kvStore_*
	 * on a disconnected pool blocks the SIP worker and can hit cnats's
	 * "free(): invalid pointer" reconnect race. */
	if (!nats_pool_is_connected()) {
		LM_DBG("NATS disconnected — KV operation deferred (fast-fail)\n");
		return -1;
	}
	kv = nats_pool_get_kv(bucket_buf[0] ? bucket_buf : kv_bucket,
		kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV store for bucket '%s'\n",
			bucket_buf[0] ? bucket_buf : kv_bucket);
		return -1;
	}

	s = nats_dl.kvStore_Get(&entry, kv, key_buf);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("key '%s' not found\n", key_buf);
		return -2;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Get failed for '%s': %s\n",
			key_buf, nats_dl.natsStatus_GetText(s));
		return -1;
	}

	uint64_t rev = nats_dl.kvEntry_Revision(entry);
	char rev_buf[24];
	int rev_buf_len;
	nats_dl.kvEntry_Destroy(entry);

	rev_buf_len = snprintf(rev_buf, sizeof(rev_buf), "%llu",
		(unsigned long long)rev);
	if (rev > (uint64_t)INT_MAX) {
		LM_WARN("KV revision %llu for '%s' exceeds INT_MAX; "
			"script var will receive a truncated int — CAS using "
			"this var will fail\n",
			(unsigned long long)rev, key_buf);
	}
	memset(&val, 0, sizeof(val));
	/* See the matching block in w_nats_kv_get for the rationale on
	 * PV_TYPE_INT — without it pv_set_scriptvar stores the var as a
	 * string and a subsequent CMD_PARAM_INT read fails. */
	val.flags = PV_VAL_STR | PV_VAL_INT | PV_TYPE_INT;
	val.rs.s = rev_buf;
	val.rs.len = rev_buf_len;
	val.ri = (int)rev;
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

	/* Zero the out-params FIRST so every failure return below leaves
	 * them deterministic -- the API contract does not require callers
	 * to pre-initialize them, and a -1 with garbage *reply_no / *reply
	 * is a latent crash in any caller that checks them before rc (see
	 * the matching cdb_res_init fix in nats_cache_query). */
	if (reply)
		*reply = NULL;
	if (reply_no)
		*reply_no = 0;

	if (!con || !attr || !attr->s || attr->len <= 0) {
		LM_ERR("null or empty raw_query command\n");
		return -1;
	}

	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	if (nats_str_to_buf(attr, cmd_buf, sizeof(cmd_buf)) < 0)
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
 * Calls nats_dl.kvStore_Keys() to enumerate every key in the bucket, then builds
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
	int ncols_per_row;

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_Keys(&keys, kv, NULL);

	if (s == NATS_NOT_FOUND) {
		/* empty bucket */
		if (reply_no)
			*reply_no = 0;
		return 0;
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Keys failed: %s\n", nats_dl.natsStatus_GetText(s));
		return -1;
	}

	key_count = keys.Count;

	if (key_count <= 0) {
		nats_dl.kvKeysList_Destroy(&keys);
		if (reply_no)
			*reply_no = 0;
		return 0;
	}

	/* The cachedb core frees expected_kv_no columns per row, so each row
	 * MUST have at least that many cdb_raw_entry slots -- allocating only
	 * the single column we fill leaves the core's free loop reading past
	 * the row (OOB free) when the caller asked for more columns.  The
	 * extra slots are zero-initialised (type 0, NULL val), so the core
	 * frees them harmlessly. */
	ncols_per_row = (expected_kv_no >= 1) ? expected_kv_no : 1;

	/* Allocate the cdb_raw_entry reply array.  The cachedb core expects
	 * a two-level allocation: an array of row pointers (rows[]), where
	 * each row is a separately allocated array of cdb_raw_entry structs
	 * (one per column).  For KV KEYS we have 1 column per row.  Each
	 * string value gets its own pkg_malloc'd buffer that the cachedb
	 * core will free after consuming the results. */
	rows = pkg_malloc(key_count * sizeof(cdb_raw_entry *));
	if (!rows) {
		LM_ERR("no more pkg memory for keys reply\n");
		nats_dl.kvKeysList_Destroy(&keys);
		return -1;
	}

	/* Iterate over kvKeysList: keys.Keys[i] is a C string owned by
	 * the NATS client library.  We must copy each key before calling
	 * nats_dl.kvKeysList_Destroy() which frees the underlying storage. */
	for (i = 0; i < key_count; i++) {
		rows[i] = pkg_malloc(ncols_per_row * sizeof(cdb_raw_entry));
		if (!rows[i]) {
			LM_ERR("no more pkg memory for key entry %d\n", i);
			/* free what we allocated so far */
			int j;
			for (j = 0; j < i; j++)
				pkg_free(rows[j]);
			pkg_free(rows);
			nats_dl.kvKeysList_Destroy(&keys);
			return -1;
		}
		memset(rows[i], 0, ncols_per_row * sizeof(cdb_raw_entry));

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
			nats_dl.kvKeysList_Destroy(&keys);
			return -1;
		}
		memcpy(rows[i][0].val.s.s, keys.Keys[i], klen);
		rows[i][0].val.s.s[klen] = '\0';
		rows[i][0].val.s.len = klen;
	}

	nats_dl.kvKeysList_Destroy(&keys);

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
	str key_s;

	/* Reject wildcards ('*'/'>') and other illegal tokens before Purge: a
	 * wildcard key would purge EVERY matching entry (a mass delete). */
	key_s.s = (char *)key;
	key_s.len = key ? (int)strlen(key) : 0;
	if (validate_kv_key(&key_s) < 0) {
		LM_ERR("KV PURGE: refusing invalid/wildcard key '%s'\n",
			key ? key : "(null)");
		return -1;
	}

	s = nats_dl.kvStore_Purge(kv, key, NULL);
	if (s == NATS_NOT_FOUND) {
		LM_DBG("KV PURGE: key '%s' not found\n", key);
		return 0; /* idempotent */
	}
	if (s != NATS_OK) {
		LM_ERR("kvStore_Purge failed for key '%s': %s\n",
			key, nats_dl.natsStatus_GetText(s));
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

	s = nats_dl.kvStore_Status(&sts, kv);
	if (s != NATS_OK) {
		LM_ERR("kvStore_Status failed: %s\n", nats_dl.natsStatus_GetText(s));
		return -1;
	}

	/* Allocate 1 row.  We fill 6 fixed columns, but the cachedb core frees
	 * expected_kv_no columns per row (free_raw_fetch), so the row MUST have
	 * at least that many cdb_raw_entry slots -- a caller asking for > 6
	 * output vars would otherwise make the core read+free past the row (heap
	 * OOB).  Size to max(expected_kv_no, 6); the extra slots are zeroed so
	 * they free harmlessly as NULL.  (Mirrors the raw_kv_keys ncols_per_row
	 * fix.) */
	int bi_ncols = (expected_kv_no > 6) ? expected_kv_no : 6;
	rows = pkg_malloc(sizeof(cdb_raw_entry *));
	if (!rows) {
		nats_dl.kvStatus_Destroy(sts);
		return -1;
	}
	rows[0] = pkg_malloc(bi_ncols * sizeof(cdb_raw_entry));
	if (!rows[0]) {
		pkg_free(rows);
		nats_dl.kvStatus_Destroy(sts);
		return -1;
	}
	memset(rows[0], 0, bi_ncols * sizeof(cdb_raw_entry));

	/* col 0: bucket name */
	bname = nats_dl.kvStatus_Bucket(sts);
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
	rows[0][1].val.n = (int)nats_dl.kvStatus_Values(sts);

	/* col 2: history */
	rows[0][2].type = CDB_INT32;
	rows[0][2].val.n = (int)nats_dl.kvStatus_History(sts);

	/* col 3: ttl (in nanoseconds from NATS, convert to seconds) */
	rows[0][3].type = CDB_INT32;
	rows[0][3].val.n = (int)(nats_dl.kvStatus_TTL(sts) / 1000000000LL);

	/* col 4: replicas */
	rows[0][4].type = CDB_INT32;
	rows[0][4].val.n = (int)nats_dl.kvStatus_Replicas(sts);

	/* col 5: bytes */
	rows[0][5].type = CDB_INT32;
	rows[0][5].val.n = (int)nats_dl.kvStatus_Bytes(sts);

	nats_dl.kvStatus_Destroy(sts);

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

/* Enable the legacy (':' separated) read/scan fall-back.  Default on so an
 * upgrade keeps serving map entries written in the old format; operators set
 * it to 0 after running nats_map_migrate, which makes map_get / map_remove
 * pure O(matches) server-side-filtered operations.  Defined in cachedb_nats.c. */
extern int nats_map_legacy_read;

/* nats_map_encode() — hex-escape a map key/field component into a single
 * NATS subject token.  Bytes outside the subject-safe set [0-9A-Za-z-_/\]
 * are written as "=HH"; '.' (the separator) and '=' (the escape char) are
 * therefore always escaped, so an encoded component never contains a raw
 * '.' and decodes unambiguously.  Returns the encoded length (excl. NUL),
 * or -1 if the output buffer is too small. */
static int _map_char_safe(unsigned char c)
{
	if ((c >= '0' && c <= '9') ||
	    (c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z'))
		return 1;
	switch (c) {
	case '-': case '_': case '/': case '\\':
		return 1;
	}
	return 0;
}

static int nats_map_encode(const char *in, int in_len, char *out, int out_size)
{
	static const char hex[] = "0123456789ABCDEF";
	int i, pos = 0;

	if (in_len < 0)
		return -1;
	for (i = 0; i < in_len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (_map_char_safe(c)) {
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = (char)c;
		} else {
			if (pos + 3 >= out_size)
				return -1;
			out[pos++] = '=';
			out[pos++] = hex[c >> 4];
			out[pos++] = hex[c & 0x0f];
		}
	}
	if (pos >= out_size)
		return -1;
	out[pos] = '\0';
	return pos;
}

static int _map_hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* nats_map_decode() — inverse of nats_map_encode().  Returns the decoded
 * length (excl. NUL), or -1 on a malformed escape or overflow. */
static int nats_map_decode(const char *in, int in_len, char *out, int out_size)
{
	int i = 0, pos = 0;

	if (in_len < 0)
		return -1;
	while (i < in_len) {
		char c = in[i];
		if (c == '=') {
			int hi, lo;
			if (i + 2 >= in_len)
				return -1;
			hi = _map_hexval(in[i + 1]);
			lo = _map_hexval(in[i + 2]);
			if (hi < 0 || lo < 0)
				return -1;
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = (char)((hi << 4) | lo);
			i += 3;
		} else {
			if (pos + 1 >= out_size)
				return -1;
			out[pos++] = c;
			i++;
		}
	}
	if (pos >= out_size)
		return -1;
	out[pos] = '\0';
	return pos;
}

/* nats_map_compose() — build the composed map subject enc(key)['.'enc(field)]
 * into out.  When field is NULL, only enc(key) is written (used to build the
 * "enc(key)." filter prefix by the caller).  Returns the composed length, or
 * -1 on encode/overflow error. */
static int nats_map_compose(char *out, int out_size, const str *key,
		const char *field, int field_len)
{
	int n, pos;

	if (!key || key->len <= 0)
		return -1;
	n = nats_map_encode(key->s, key->len, out, out_size);
	if (n < 0)
		return -1;
	pos = n;
	if (field) {
		if (pos + 1 >= out_size)
			return -1;
		out[pos++] = NATS_MAP_SEP;
		n = nats_map_encode(field, field_len, out + pos, out_size - pos);
		if (n < 0)
			return -1;
		pos += n;
	}
	return pos;
}

/**
 * build_map_key() — Construct a composite "key:subkey" string in a buffer.
 *
 * Concatenates key, the NATS_MAP_SEP separator (':'), and subkey into buf,
 * then null-terminates.  The buffer must be large enough for
 * key->len + 1 + subkey->len + 1 bytes (content + separator + NUL).
 *
 * If subkey is NULL or empty, the function falls back to copying just the
 * key via nats_str_to_buf().
 *
 * Returns: 0 on success, -1 if inputs are invalid or the buffer is too small.
 */
static int build_map_key(char *buf, size_t buf_size,
                         const str *key, const str *subkey)
{
	if (!key || !key->s || key->len <= 0) {
		LM_ERR("null or empty map key\n");
		return -1;
	}

	/* No char-level rejection needed: nats_map_encode hex-escapes every
	 * byte outside the subject-safe set, so a SIP-derived key/subkey cannot
	 * inject the separator (or a wildcard / control char) to alias another
	 * map -- the structural '.' only ever appears between the two encoded
	 * components. */
	if (!subkey || !subkey->s || subkey->len <= 0)
		return nats_map_compose(buf, (int)buf_size, key, NULL, 0) < 0 ? -1 : 0;

	return nats_map_compose(buf, (int)buf_size, key,
		subkey->s, subkey->len) < 0 ? -1 : 0;
}

/* Build the legacy (':' separated, unescaped) composite key for compat
 * reads/removes and migration: "key:subkey" or just "key".  Returns 0 / -1. */
static int build_map_key_legacy(char *buf, size_t buf_size,
                                const str *key, const str *subkey)
{
	int total;

	if (!key || !key->s || key->len <= 0)
		return -1;
	if (!subkey || !subkey->s || subkey->len <= 0)
		return nats_str_to_buf(key, buf, buf_size);

	total = key->len + 1 + subkey->len;
	if ((size_t)(total + 1) > buf_size)
		return -1;
	memcpy(buf, key->s, key->len);
	buf[key->len] = NATS_MAP_SEP_LEGACY;
	memcpy(buf + key->len + 1, subkey->s, subkey->len);
	buf[total] = '\0';
	return 0;
}

/* _map_add_row() — fetch full_key's value and append a result row whose
 * single pair is (field -> value).  Skips silently on a get / alloc
 * failure.  Returns 1 if a row was added, 0 otherwise. */
static int _map_add_row(cdb_res_t *res, kvStore *kv, const char *full_key,
		const char *field, int field_len)
{
	kvEntry *entry = NULL;
	cdb_row_t *row;
	cdb_pair_t *pair;
	const char *val_data;
	int val_len;
	natsStatus s;

	s = nats_dl.kvStore_Get(&entry, kv, full_key);
	if (s != NATS_OK) {
		LM_DBG("map_get: skipping key '%s' (get failed)\n", full_key);
		return 0;
	}
	val_data = nats_dl.kvEntry_ValueString(entry);
	val_len  = nats_dl.kvEntry_ValueLen(entry);

	row = pkg_malloc(sizeof(cdb_row_t));
	if (!row) { nats_dl.kvEntry_Destroy(entry); return 0; }
	memset(row, 0, sizeof(cdb_row_t));
	INIT_LIST_HEAD(&row->dict);

	pair = pkg_malloc(sizeof(cdb_pair_t));
	if (!pair) { pkg_free(row); nats_dl.kvEntry_Destroy(entry); return 0; }
	memset(pair, 0, sizeof(cdb_pair_t));
	INIT_LIST_HEAD(&pair->list);

	if (field_len > 0) {
		pair->key.name.s = pkg_malloc(field_len);
		if (!pair->key.name.s) {
			LM_ERR("no more pkg memory for subkey name\n");
			pkg_free(pair); pkg_free(row);
			nats_dl.kvEntry_Destroy(entry);
			return 0;
		}
		memcpy(pair->key.name.s, field, field_len);
		pair->key.name.len = field_len;
	}

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
	nats_dl.kvEntry_Destroy(entry);
	return 1;
}

/**
 * nats_cache_map_get() — Retrieve all fields of a map.
 *
 * New format: each field is stored under the subject "enc(key).enc(field)",
 * so a single server-side filtered list ("enc(key).>") returns exactly this
 * map's keys -- O(matches), not O(total bucket keys).  Each matched key's
 * suffix is decoded back to the field name.
 *
 * While nats_map_legacy_read is enabled (the default, for upgrade compat),
 * a second pass also scans for the legacy raw "key:" prefix and returns
 * those entries verbatim.  That pass is O(total keys); operators disable it
 * (and reclaim the full speed-up) after running nats_map_migrate.
 *
 * Returns: 0 on success (even if no keys match), -1 on error.
 */
int nats_cache_map_get(cachedb_con *con, const str *key, cdb_res_t *res)
{
	nats_cachedb_con *ncon;
	kvKeysList keys;
	natsStatus s;
	char enc_prefix[NATS_MAP_KEY_BUF];   /* "enc(key)." */
	char filter[NATS_MAP_KEY_BUF];       /* "enc(key).>" */
	const char *filters[1];
	int ep_len, i;

	if (!con || !key || !res) {
		LM_ERR("null parameter\n");
		return -1;
	}
	/* Init the result set BEFORE any failure return: callers may
	 * cdb_free_rows(res) on failure (see the matching fix + rationale
	 * in nats_cache_query, sip_e2e case 040_broker_bounce). */
	cdb_res_init(res);
	ncon = (nats_cachedb_con *)con->data;
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}
	if (key->len <= 0) {
		LM_ERR("invalid map key length\n");
		return -1;
	}

	/* ---- new format: server-side filtered list "enc(key).>" ---- */
	ep_len = nats_map_compose(enc_prefix, (int)sizeof(enc_prefix) - 2,
		key, NULL, 0);
	if (ep_len < 0) {
		LM_ERR("map_get: key encode failed (too long?)\n");
		return -1;
	}
	enc_prefix[ep_len++] = NATS_MAP_SEP;
	enc_prefix[ep_len]   = '\0';
	memcpy(filter, enc_prefix, ep_len);
	filter[ep_len]     = '>';
	filter[ep_len + 1] = '\0';
	filters[0] = filter;

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_KeysWithFilters(&keys, ncon->kv, filters, 1, NULL);
	if (s == NATS_OK) {
		for (i = 0; i < keys.Count; i++) {
			const char *k = keys.Keys[i];
			int klen = (int)strlen(k);
			char field[NATS_MAP_KEY_BUF];
			int flen;

			if (klen <= ep_len || strncmp(k, enc_prefix, ep_len) != 0)
				continue;   /* defensive; the filter already guarantees it */
			flen = nats_map_decode(k + ep_len, klen - ep_len,
				field, sizeof(field));
			if (flen < 0) {
				LM_WARN("map_get: undecodable key '%s' skipped\n", k);
				continue;
			}
			_map_add_row(res, ncon->kv, k, field, flen);
		}
		nats_dl.kvKeysList_Destroy(&keys);
	} else if (s != NATS_NOT_FOUND) {
		LM_ERR("map_get: KeysWithFilters failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		/* fall through to the legacy pass rather than hard-failing */
	}

	/* ---- legacy compat: raw "key:" prefix scan over all keys ---- */
	if (nats_map_legacy_read && (size_t)key->len + 2 <= sizeof(filter)) {
		char lprefix[NATS_NATIVE_KEY_BUF];
		int lp_len;

		if ((size_t)key->len + 2 <= sizeof(lprefix)) {
			memcpy(lprefix, key->s, key->len);
			lprefix[key->len]     = NATS_MAP_SEP_LEGACY;
			lprefix[key->len + 1] = '\0';
			lp_len = key->len + 1;

			memset(&keys, 0, sizeof(keys));
			s = nats_dl.kvStore_Keys(&keys, ncon->kv, NULL);
			if (s == NATS_OK) {
				for (i = 0; i < keys.Count; i++) {
					const char *k = keys.Keys[i];
					int klen = (int)strlen(k);
					if (klen <= lp_len ||
							strncmp(k, lprefix, lp_len) != 0)
						continue;
					_map_add_row(res, ncon->kv, k,
						k + lp_len, klen - lp_len);
				}
				nats_dl.kvKeysList_Destroy(&keys);
			} else if (s != NATS_NOT_FOUND) {
				LM_DBG("map_get legacy scan: %s\n",
					nats_dl.natsStatus_GetText(s));
			}
		}
	}

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
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	/* if subkey is provided, store each pair under
	 * enc(key) '.' enc("subkey:pair_name") -- the ':' between subkey and
	 * pair name is kept as a data byte (hex-escaped), so map_get returns
	 * the identical "subkey:pair_name" field name as before. */
	if (subkey && subkey->s && subkey->len > 0) {
		list_for_each(it, (struct list_head *)pairs) {
			char full_key[NATS_MAP_KEY_BUF];
			char field[NATS_MAP_KEY_BUF];
			int flen;

			pair = list_entry(it, cdb_pair_t, list);
			if (!pair->key.name.s || pair->key.name.len <= 0)
				continue;

			/* raw field = subkey ':' pair_name */
			if ((size_t)(subkey->len + 1 + pair->key.name.len) >=
					sizeof(field)) {
				LM_ERR("composite map field too long\n");
				return -1;
			}
			memcpy(field, subkey->s, subkey->len);
			field[subkey->len] = NATS_MAP_SEP_LEGACY;
			memcpy(field + subkey->len + 1, pair->key.name.s,
				pair->key.name.len);
			flen = subkey->len + 1 + pair->key.name.len;

			if (nats_map_compose(full_key, sizeof(full_key), key,
					field, flen) < 0) {
				LM_ERR("map_set: composite key encode failed\n");
				return -1;
			}

			/* convert value to string */
			if (pair->val.type == CDB_STR) {
				if (nats_str_to_buf(&pair->val.val.st, val_buf,
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

			s = nats_dl.kvStore_PutString(&rev, ncon->kv, full_key, val_buf);
			if (s != NATS_OK) {
				LM_ERR("kvStore_PutString failed for '%s': %s\n",
					full_key, nats_dl.natsStatus_GetText(s));
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
				if (nats_str_to_buf(&pair->val.val.st, val_buf,
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

			s = nats_dl.kvStore_PutString(&rev, ncon->kv, map_key, val_buf);
			if (s != NATS_OK) {
				LM_ERR("kvStore_PutString failed for '%s': %s\n",
					map_key, nats_dl.natsStatus_GetText(s));
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
	if (!ncon) {
		LM_ERR("null NATS connection\n");
		return -1;
	}
	/* Fast-fail on a down broker and refresh the KV handle after a
	 * reconnect; otherwise this op blocks the worker during an outage and
	 * can reuse a destroyed handle after reconnect (see nats_con_refresh_kv). */
	if (nats_con_refresh_kv(ncon) < 0 || !ncon->kv) {
		LM_DBG("NATS unavailable — operation deferred (fast-fail)\n");
		return -1;
	}

	if (subkey && subkey->s && subkey->len > 0) {
		/* delete the single new-format enc(key).enc(subkey) ... */
		if (build_map_key(map_key, sizeof(map_key), key, subkey) < 0)
			return -1;
		s = nats_dl.kvStore_Delete(ncon->kv, map_key);
		if (s != NATS_OK && s != NATS_NOT_FOUND) {
			LM_ERR("kvStore_Delete failed for '%s': %s\n",
				map_key, nats_dl.natsStatus_GetText(s));
			return -1;
		}
		LM_DBG("map_remove: deleted '%s'\n", map_key);

		/* ...and the legacy "key:subkey" if compat reads are enabled. */
		if (nats_map_legacy_read) {
			char legacy_key[NATS_MAP_KEY_BUF];
			if (build_map_key_legacy(legacy_key, sizeof(legacy_key),
					key, subkey) == 0) {
				s = nats_dl.kvStore_Delete(ncon->kv, legacy_key);
				if (s != NATS_OK && s != NATS_NOT_FOUND)
					LM_DBG("map_remove: legacy delete '%s': %s\n",
						legacy_key, nats_dl.natsStatus_GetText(s));
			}
		}
	} else {
		/* prefix remove: new-format server-side filter "enc(key).>", plus
		 * the legacy raw "key:" full scan while compat reads are enabled. */
		kvKeysList keys;
		char enc_prefix[NATS_MAP_KEY_BUF];
		char filter[NATS_MAP_KEY_BUF];
		const char *filters[1];
		int ep_len, i;

		if (key->len <= 0) {
			LM_ERR("invalid map key length\n");
			return -1;
		}

		ep_len = nats_map_compose(enc_prefix, (int)sizeof(enc_prefix) - 2,
			key, NULL, 0);
		if (ep_len < 0) {
			LM_ERR("map_remove: key encode failed (too long?)\n");
			return -1;
		}
		enc_prefix[ep_len++] = NATS_MAP_SEP;
		enc_prefix[ep_len]   = '\0';
		memcpy(filter, enc_prefix, ep_len);
		filter[ep_len]     = '>';
		filter[ep_len + 1] = '\0';
		filters[0] = filter;

		memset(&keys, 0, sizeof(keys));
		s = nats_dl.kvStore_KeysWithFilters(&keys, ncon->kv, filters, 1, NULL);
		if (s == NATS_OK) {
			for (i = 0; i < keys.Count; i++) {
				s = nats_dl.kvStore_Delete(ncon->kv, keys.Keys[i]);
				if (s != NATS_OK && s != NATS_NOT_FOUND)
					LM_WARN("map_remove: failed to delete '%s': %s\n",
						keys.Keys[i], nats_dl.natsStatus_GetText(s));
			}
			nats_dl.kvKeysList_Destroy(&keys);
		} else if (s != NATS_NOT_FOUND) {
			LM_ERR("map_remove: KeysWithFilters failed: %s\n",
				nats_dl.natsStatus_GetText(s));
		}

		if (nats_map_legacy_read) {
			char lprefix[NATS_NATIVE_KEY_BUF];
			int lp_len;

			if ((size_t)key->len + 2 <= sizeof(lprefix)) {
				memcpy(lprefix, key->s, key->len);
				lprefix[key->len]     = NATS_MAP_SEP_LEGACY;
				lprefix[key->len + 1] = '\0';
				lp_len = key->len + 1;

				memset(&keys, 0, sizeof(keys));
				s = nats_dl.kvStore_Keys(&keys, ncon->kv, NULL);
				if (s == NATS_OK) {
					for (i = 0; i < keys.Count; i++) {
						int klen = (int)strlen(keys.Keys[i]);
						if (klen <= lp_len ||
								strncmp(keys.Keys[i], lprefix, lp_len) != 0)
							continue;
						s = nats_dl.kvStore_Delete(ncon->kv, keys.Keys[i]);
						if (s != NATS_OK && s != NATS_NOT_FOUND)
							LM_WARN("map_remove: legacy delete '%s': %s\n",
								keys.Keys[i],
								nats_dl.natsStatus_GetText(s));
					}
					nats_dl.kvKeysList_Destroy(&keys);
				} else if (s != NATS_NOT_FOUND) {
					LM_DBG("map_remove legacy scan: %s\n",
						nats_dl.natsStatus_GetText(s));
				}
			}
		}
	}

	return 0;
}

/**
 * mi_nats_map_migrate() — rewrite legacy ':' map keys into the new
 * '.'-separated, hex-escaped format, in place.
 *
 * Any key containing ':' is a legacy map entry (validate_kv_key forbids ':'
 * in non-map keys, and the new format hex-escapes ':' so new keys never
 * carry a raw one).  For each, split on the FIRST ':' into map-key + field,
 * recompose as enc(map-key).enc(field), copy the value across, and delete
 * the old key.  Idempotent: re-running migrates only the entries still in
 * the legacy format.  After a clean run operators can set
 * map_legacy_read=0 to drop the O(total keys) compat scans.
 *
 * Returns { scanned, migrated, skipped, failed }.
 */
mi_response_t *mi_nats_map_migrate(const mi_params_t *params,
		struct mi_handler *async)
{
	kvStore *kv;
	kvKeysList keys;
	natsStatus s;
	int i;
	unsigned long scanned = 0, migrated = 0, skipped = 0, failed = 0;
	mi_response_t *resp;
	mi_item_t *obj;

	(void)params;
	(void)async;

	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history, (int64_t)kv_ttl);
	if (!kv)
		return init_mi_error(503, MI_SSTR("NATS KV unavailable"));

	memset(&keys, 0, sizeof(keys));
	s = nats_dl.kvStore_Keys(&keys, kv, NULL);
	if (s != NATS_OK && s != NATS_NOT_FOUND)
		return init_mi_error(500, MI_SSTR("kvStore_Keys failed"));

	if (s == NATS_OK) {
		for (i = 0; i < keys.Count; i++) {
			const char *k = keys.Keys[i];
			const char *colon = strchr(k, NATS_MAP_SEP_LEGACY);
			char newkey[NATS_MAP_KEY_BUF];
			str mkey;
			const char *field;
			int field_len;
			kvEntry *e = NULL;
			const char *val;
			int vlen;
			char *valbuf;
			uint64_t rev;

			scanned++;
			if (!colon)
				continue;             /* not a legacy map key */

			mkey.s   = (char *)k;
			mkey.len = (int)(colon - k);
			field     = colon + 1;
			field_len = (int)strlen(field);
			if (mkey.len <= 0) { skipped++; continue; }

			if (nats_map_compose(newkey, sizeof(newkey), &mkey,
					field, field_len) < 0) {
				LM_WARN("map_migrate: '%s' too long to re-encode; skipped\n", k);
				skipped++;
				continue;
			}

			if (nats_dl.kvStore_Get(&e, kv, k) != NATS_OK) {
				failed++;
				continue;
			}
			val  = nats_dl.kvEntry_ValueString(e);
			vlen = nats_dl.kvEntry_ValueLen(e);
			if (vlen < 0) vlen = 0;
			valbuf = pkg_malloc((size_t)vlen + 1);
			if (!valbuf) {
				nats_dl.kvEntry_Destroy(e);
				failed++;
				continue;
			}
			if (val && vlen > 0)
				memcpy(valbuf, val, vlen);
			valbuf[vlen] = '\0';
			nats_dl.kvEntry_Destroy(e);

			if (nats_dl.kvStore_PutString(&rev, kv, newkey, valbuf) != NATS_OK) {
				pkg_free(valbuf);
				failed++;
				continue;
			}
			pkg_free(valbuf);
			(void)nats_dl.kvStore_Delete(kv, k);
			migrated++;
			LM_DBG("map_migrate: '%s' -> '%s'\n", k, newkey);
		}
		nats_dl.kvKeysList_Destroy(&keys);
	}

	resp = init_mi_result_object(&obj);
	if (!resp)
		return NULL;
	if (add_mi_number(obj, MI_SSTR("scanned"),  (double)scanned)  < 0 ||
	    add_mi_number(obj, MI_SSTR("migrated"), (double)migrated) < 0 ||
	    add_mi_number(obj, MI_SSTR("skipped"),  (double)skipped)  < 0 ||
	    add_mi_number(obj, MI_SSTR("failed"),   (double)failed)   < 0) {
		free_mi_response(resp);
		return NULL;
	}
	LM_INFO("map_migrate: scanned=%lu migrated=%lu skipped=%lu failed=%lu\n",
		scanned, migrated, skipped, failed);
	return resp;
}
