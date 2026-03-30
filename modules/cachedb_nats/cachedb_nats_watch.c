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

#include <pthread.h>
#include <string.h>
#include <stdatomic.h>
#include <nats/nats.h>

#include "../../dprint.h"
#include "../../str.h"

/*
 * EVI support: OpenSIPS 4.x provides evi_publish_event(), evi_raise_event(),
 * etc. in evi/evi.h and evi/evi_params.h.  We conditionally include them
 * and fall back to logging stubs if the headers are not present at build
 * time.  The Makefile does not yet set HAVE_EVI; flip it once the module
 * compiles inside the full OpenSIPS tree.
 */
#ifdef HAVE_EVI
#include "../../evi/evi.h"
#include "../../evi/evi_params.h"
#define EVI_AVAILABLE 1
#else
/* Stub types so the rest of the file compiles stand-alone */
typedef int event_id_t;
#ifndef EVI_ERROR
#define EVI_ERROR (-1)
#endif
#define EVI_AVAILABLE 0
#endif

#include "cachedb_nats_json.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_dbase.h"
#include "../../lib/nats/nats_pool.h"

/* Module globals from cachedb_nats.c — needed for reconnection */
extern char *kv_bucket;
extern int kv_replicas;
extern int kv_history;
extern int kv_ttl;
extern char *fts_json_prefix;

/* ---- watcher thread state (process-local) ---- */
static pthread_t       _watcher_tid;
static atomic_int      _watcher_running = 0;
static kvWatcher      *_watcher         = NULL;
static kvStore        *_watch_kv        = NULL;
static char            _watch_pattern[256] = {0};

/* ---- EVI event for E_NATS_KV_CHANGE ---- */
static event_id_t evi_kv_change_id = EVI_ERROR;

#ifdef HAVE_EVI
static str evi_kv_change_name = str_init("E_NATS_KV_CHANGE");
#endif

/* ---- forward declarations ---- */
static void *_watcher_thread_fn(void *arg);
static void  _raise_kv_change_event(kvEntry *entry, kvOperation op);

/* ------------------------------------------------------------------ */
/*  EVI event raising                                                  */
/* ------------------------------------------------------------------ */
static void _raise_kv_change_event(kvEntry *entry, kvOperation op)
{
#ifdef HAVE_EVI
	evi_params_t *params;
	str key_str, op_str, val_str;
	int rev;

	static str pn_key = str_init("key");
	static str pn_op  = str_init("operation");
	static str pn_val = str_init("value");
	static str pn_rev = str_init("revision");

	/* Only raise if EVI event is subscribed */
	if (evi_kv_change_id == EVI_ERROR)
		return;
	if (!evi_probe_event(evi_kv_change_id))
		return;

	params = evi_get_params();
	if (!params)
		return;

	/* key */
	key_str.s   = (char *)kvEntry_Key(entry);
	key_str.len = strlen(key_str.s);

	/* operation */
	switch (op) {
		case kvOp_Put:    op_str = (str){.s = "put",    .len = 3}; break;
		case kvOp_Delete: op_str = (str){.s = "delete", .len = 6}; break;
		default:          op_str = (str){.s = "purge",  .len = 5}; break;
	}

	if (evi_param_add_str(params, &pn_key, &key_str) < 0)
		goto err;
	if (evi_param_add_str(params, &pn_op, &op_str) < 0)
		goto err;

	/* value (only for put operations) */
	if (op == kvOp_Put) {
		val_str.s   = (char *)kvEntry_ValueString(entry);
		val_str.len = kvEntry_ValueLen(entry);
		if (evi_param_add_str(params, &pn_val, &val_str) < 0)
			goto err;
	}

	/* revision */
	rev = (int)kvEntry_Revision(entry);
	if (evi_param_add_int(params, &pn_rev, &rev) < 0)
		goto err;

	if (evi_raise_event(evi_kv_change_id, params) < 0)
		LM_ERR("failed to raise E_NATS_KV_CHANGE event\n");
	return;

err:
	evi_free_params(params);
#else
	/* EVI not available at build time -- log the change instead */
	const char *key = kvEntry_Key(entry);
	const char *op_name;

	switch (op) {
		case kvOp_Put:    op_name = "put";    break;
		case kvOp_Delete: op_name = "delete"; break;
		default:          op_name = "purge";  break;
	}

	LM_DBG("KV change (EVI unavailable): key=%s op=%s rev=%llu\n",
		key, op_name, (unsigned long long)kvEntry_Revision(entry));
#endif /* HAVE_EVI */
}

/* ------------------------------------------------------------------ */
/*  Watcher thread                                                     */
/* ------------------------------------------------------------------ */
static void *_watcher_thread_fn(void *arg)
{
	kvEntry    *entry = NULL;
	natsStatus  s;

	LM_INFO("NATS KV watcher thread started\n");

	while (atomic_load(&_watcher_running)) {
		s = kvWatcher_Next(&entry, _watcher, 5000);

		if (s == NATS_TIMEOUT)
			continue;

		if (s != NATS_OK) {
			if (atomic_load(&_watcher_running))
				LM_ERR("kvWatcher_Next failed: %s\n",
					natsStatus_GetText(s));
			break;
		}

		const char   *key = kvEntry_Key(entry);
		kvOperation   op  = kvEntry_Operation(entry);

		if (op == kvOp_Put) {
			const char *val     = kvEntry_ValueString(entry);
			int         val_len = kvEntry_ValueLen(entry);
			nats_json_index_add(key, val, val_len);
		} else if (op == kvOp_Delete || op == kvOp_Purge) {
			nats_json_index_remove(key);
		}

		/* Raise EVI event if available */
		_raise_kv_change_event(entry, op);

		kvEntry_Destroy(entry);
		entry = NULL;
	}

	LM_INFO("NATS KV watcher thread stopped\n");
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

int nats_watch_start(kvStore *kv, const char *pattern)
{
	kvWatchOptions opts;
	natsStatus s;

	if (!kv) {
		LM_ERR("nats_watch_start: NULL kv handle\n");
		return -1;
	}

	_watch_kv = kv;
	/* Copy pattern, but skip if it's the same buffer (reconnect path
	 * passes _watch_pattern itself — overlapping copy is UB). */
	if (pattern && *pattern && pattern != _watch_pattern) {
		int plen = strlen(pattern);
		if (plen >= (int)sizeof(_watch_pattern))
			plen = sizeof(_watch_pattern) - 1;
		memcpy(_watch_pattern, pattern, plen);
		_watch_pattern[plen] = '\0';
	}

	/* Register EVI event */
#ifdef HAVE_EVI
	evi_kv_change_id = evi_publish_event(evi_kv_change_name);
	if (evi_kv_change_id == EVI_ERROR)
		LM_WARN("cannot register E_NATS_KV_CHANGE event "
			"(EVI not available?)\n");
#else
	LM_INFO("EVI not compiled in -- E_NATS_KV_CHANGE events disabled\n");
#endif

	kvWatchOptions_Init(&opts);
	/*
	 * UpdatesOnly = true: skip the initial snapshot replay.
	 * The search index was already populated from a full KV scan
	 * in nats_json_index_build(), so replaying history here would
	 * duplicate entries.
	 */
	opts.UpdatesOnly = true;

	if (pattern && *pattern)
		s = kvStore_Watch(&_watcher, kv, pattern, &opts);
	else
		s = kvStore_WatchAll(&_watcher, kv, &opts);

	if (s != NATS_OK) {
		LM_ERR("kvStore_Watch failed: %s\n", natsStatus_GetText(s));
		return -1;
	}

	atomic_store(&_watcher_running, 1);
	if (pthread_create(&_watcher_tid, NULL, _watcher_thread_fn, NULL) != 0) {
		LM_ERR("failed to create watcher thread\n");
		kvWatcher_Destroy(_watcher);
		_watcher = NULL;
		atomic_store(&_watcher_running, 0);
		return -1;
	}

	LM_INFO("NATS KV watcher started (pattern: %s)\n",
		(pattern && *pattern) ? pattern : "*");
	return 0;
}

void nats_watch_stop(void)
{
	if (!atomic_load(&_watcher_running))
		return;

	atomic_store(&_watcher_running, 0);

	/* Stop the watcher first -- this unblocks kvWatcher_Next() */
	if (_watcher) {
		kvWatcher_Stop(_watcher);
	}

	pthread_join(_watcher_tid, NULL);

	if (_watcher) {
		kvWatcher_Destroy(_watcher);
		_watcher = NULL;
	}
}

void nats_watch_reconnect_handler(void *closure)
{
	kvStore *kv;

	LM_INFO("NATS reconnected -- rebuilding index and restarting watcher\n");

	nats_watch_stop();

	/* Get fresh KV handle from pool (old one was invalidated) */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("failed to get KV handle after reconnect\n");
		return;
	}

	_watch_kv = kv;

	/* Rebuild the search index from current KV state */
	nats_json_index_rebuild(kv, fts_json_prefix);

	/* Restart the watcher */
	nats_watch_start(kv, _watch_pattern);
}
