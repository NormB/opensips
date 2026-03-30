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
 * cachedb_nats_watch.c -- Self-healing KV watcher for NATS JetStream
 *
 * Architecture overview:
 *
 * This module implements a resilient, self-healing watcher thread that
 * monitors a NATS JetStream KV bucket for changes.  The watcher runs as
 * a pthread for the lifetime of the OpenSIPS worker process and drives
 * two downstream subsystems:
 *
 *   1. JSON full-text search index -- kept in sync with live KV mutations
 *      so that script-level FTS queries always reflect the latest state.
 *
 *   2. EVI events (E_NATS_KV_CHANGE) -- raised for every put/delete/purge
 *      so that OpenSIPS routing scripts can react to KV changes in real time.
 *
 * The thread follows a four-phase loop:
 *
 *   Phase 1 -- Wait for NATS connectivity (poll nats_pool_is_connected).
 *   Phase 2 -- Acquire a fresh KV handle and rebuild the search index
 *              from the full bucket contents (crash-recovery path).
 *   Phase 3 -- Create a kvWatcher on the bucket (with optional key pattern).
 *   Phase 4 -- Process live kvWatcher_Next() updates until disconnect or
 *              reconnect-epoch change, then loop back to Phase 1.
 *
 * On disconnect, the watcher is stopped BEFORE nats.c tears down internal
 * subscription state, avoiding a use-after-free race.  On reconnect, the
 * epoch check triggers a full index rebuild so the index never drifts.
 *
 * Thread safety: _watcher_running is an atomic_int accessed with
 * atomic_load/atomic_store.  An acquire fence after epoch-change detection
 * ensures subsequent KV operations see the new connection state.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
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
#define EVI_ERROR (-1)
#define EVI_AVAILABLE 0
#endif

#include "cachedb_nats_json.h"
#include "cachedb_nats_watch.h"
#include "cachedb_nats_dbase.h"
#include "../../lib/nats/nats_pool.h"

/* Module globals from cachedb_nats.c -- needed for reconnection */
extern char *kv_bucket;
extern int kv_replicas;
extern int kv_history;
extern int kv_ttl;
extern char *fts_json_prefix;

/* ---- watcher thread state (process-local) ---- */
static pthread_t       _watcher_tid;
static atomic_int      _watcher_running = 0;
static kvWatcher      *_watcher         = NULL;

/* Multiple watch patterns -- set by nats_watch_start(), read by thread.
 * When _num_patterns == 0, watches all keys via kvStore_WatchAll().
 * When > 0, uses kvStore_WatchMulti() for selective watching. */
static const char    **_watch_patterns  = NULL;
static int             _num_patterns    = 0;

/* ---- EVI event for E_NATS_KV_CHANGE ---- */
/* Non-static: set by mod_init() in cachedb_nats.c via evi_publish_event() */
event_id_t evi_kv_change_id = EVI_ERROR;

/* ---- forward declarations ---- */
static void *_watcher_thread_fn(void *arg);
static void  _raise_kv_change_event(kvEntry *entry, kvOperation op);

/* ------------------------------------------------------------------ */
/*  EVI event raising                                                  */
/* ------------------------------------------------------------------ */

/**
 * _raise_kv_change_event() -- Raise an E_NATS_KV_CHANGE EVI event.
 *
 * Called from the watcher thread for every KV mutation (put, delete, purge).
 * When compiled with HAVE_EVI, builds an EVI parameter set containing
 * the key, operation name, value (for puts), and revision number, then
 * raises the event through the OpenSIPS EVI subsystem.
 *
 * When EVI is not available at build time, falls back to a DBG log line
 * so KV changes are still observable during development.
 *
 * @param entry  The kvEntry delivered by kvWatcher_Next().
 * @param op     The KV operation type (put, delete, or purge).
 */
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

	/* operation -- map enum to human-readable string */
	switch (op) {
		case kvOp_Put:    op_str = (str){.s = "put",    .len = 3}; break;
		case kvOp_Delete: op_str = (str){.s = "delete", .len = 6}; break;
		default:          op_str = (str){.s = "purge",  .len = 5}; break;
	}

	if (evi_param_add_str(params, &pn_key, &key_str) < 0)
		goto err;
	if (evi_param_add_str(params, &pn_op, &op_str) < 0)
		goto err;

	/* value (only for put operations -- deletes/purges have no payload) */
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

	/* Dispatch the event to all subscribed EVI listeners */
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
/*  Watcher thread -- self-healing resilient loop                      */
/* ------------------------------------------------------------------ */

/**
 * _watcher_thread_fn() -- Main watcher thread entry point.
 *
 * Runs for the lifetime of the OpenSIPS worker process.  Implements a
 * four-phase self-healing loop:
 *
 *   Phase 1: Block until NATS connectivity is established (500ms poll).
 *   Phase 2: Obtain a fresh KV handle from the pool and rebuild the
 *            JSON full-text search index from the complete bucket state.
 *   Phase 3: Create a kvWatcher with the configured key pattern (or
 *            watch all keys if no pattern is set).
 *   Phase 4: Process live updates from kvWatcher_Next() in a tight loop.
 *            On reconnect-epoch change or disconnect, break out and
 *            restart from Phase 1 to get a fresh KV handle and index.
 *
 * Cleanup between iterations destroys the stale kvWatcher.  During
 * disconnect, kvWatcher_Destroy is skipped to avoid double-free races
 * with nats.c's internal I/O thread cleanup.
 *
 * @param arg  Unused (required by pthread_create signature).
 * @return     Always returns NULL.
 */
static void *_watcher_thread_fn(void *arg)
{
	kvEntry        *entry = NULL;
	natsStatus      s;
	kvWatchOptions  opts;
	kvStore        *kv;
	int             last_epoch;
	int             prefix_len;

	LM_INFO("NATS KV watcher thread started\n");

	prefix_len = fts_json_prefix ? (int)strlen(fts_json_prefix) : 0;

	while (atomic_load(&_watcher_running)) {

		/* ---- Phase 1: wait for NATS connection ----
		 * Poll every 500ms until the pool reports connectivity.
		 * This covers both initial startup and post-disconnect recovery. */
		while (atomic_load(&_watcher_running) && !nats_pool_is_connected()) {
			usleep(500000); /* 500ms */
		}
		if (!atomic_load(&_watcher_running))
			break;

		last_epoch = nats_pool_get_reconnect_epoch();

		/* ---- Phase 2: get fresh KV handle + rebuild search index ----
		 * After every reconnect the old KV handle is stale.  We obtain
		 * a new one from the pool and do a full index rebuild so the
		 * search index is consistent with the actual bucket state. */
		kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
			(int64_t)kv_ttl);
		if (!kv) {
			LM_ERR("watcher: failed to get KV handle, retrying in 2s\n");
			sleep(2);
			continue;
		}

		nats_json_index_rebuild(kv, fts_json_prefix);

		/* ---- Phase 3: create kvWatcher ----
		 * Set UpdatesOnly so we only receive mutations after the
		 * current revision (the full state was already loaded in
		 * Phase 2 via index_rebuild). */
		kvWatchOptions_Init(&opts);
		opts.UpdatesOnly = true;

		s = kvStore_WatchMulti(&_watcher, kv,
			_watch_patterns, _num_patterns, &opts);

		if (s != NATS_OK) {
			LM_ERR("watcher: kvStore_WatchMulti failed: %s, "
				"retrying in 2s\n", natsStatus_GetText(s));
			sleep(2);
			continue;
		}

		LM_INFO("watcher: watching KV (%d pattern(s), epoch: %d)\n",
			_num_patterns, last_epoch);

		/* ---- Phase 4: event loop ----
		 * Process live KV updates until a reconnect or disconnect
		 * invalidates the current watcher and KV handle. */
		while (atomic_load(&_watcher_running)) {
			/* Check for reconnect -- epoch changed means connection
			 * was lost and restored; our KV handle and watcher are
			 * stale. Break out to Phase 1 for a full rebuild. */
			if (nats_pool_get_reconnect_epoch() != last_epoch) {
				/* Memory barrier: ensure subsequent KV operations
				 * (Phase 2 rebuild) see the new connection state
				 * established by the reconnect callback thread. */
				atomic_thread_fence(memory_order_acquire);
				LM_INFO("watcher: reconnect detected (epoch %d->%d), "
					"restarting\n", last_epoch,
					nats_pool_get_reconnect_epoch());
				break;
			}

			/* Check for disconnect -- if NATS is down, stop the
			 * watcher BEFORE nats.c's reconnection logic destroys
			 * internal subscription state (race -> free(): invalid
			 * pointer).  Short timeout (500ms) minimizes the window
			 * where kvWatcher_Next() is blocked with stale state. */
			if (!nats_pool_is_connected()) {
				LM_INFO("watcher: disconnect detected, stopping "
					"watcher to prevent use-after-free\n");
				break;
			}

			s = kvWatcher_Next(&entry, _watcher, 500);

			if (s == NATS_TIMEOUT)
				continue;

			if (s != NATS_OK) {
				if (atomic_load(&_watcher_running))
					LM_WARN("watcher: kvWatcher_Next failed: %s\n",
						natsStatus_GetText(s));
				break;
			}

			const char   *key = kvEntry_Key(entry);
			kvOperation   op  = kvEntry_Operation(entry);

			if (op == kvOp_Put) {
				const char *val     = kvEntry_ValueString(entry);
				int         val_len = kvEntry_ValueLen(entry);

				/* Only index keys that match the JSON prefix and
				 * actually contain JSON data. Non-JSON keys are
				 * silently skipped -- no warning spam. */
				if (val && val_len > 0 && val[0] == '{' &&
				    (prefix_len == 0 ||
				     strncmp(key, fts_json_prefix, prefix_len) == 0)) {
					nats_json_index_add(key, val, val_len);
				}
			} else if (op == kvOp_Delete || op == kvOp_Purge) {
				nats_json_index_remove(key);
			}

			/* Raise EVI event for downstream script consumers */
			_raise_kv_change_event(entry, op);

			kvEntry_Destroy(entry);
			entry = NULL;
		}

		/* ---- Cleanup before retry ----
		 * Destroy the stale watcher.  Clear the pointer first to
		 * prevent races with nats_watch_stop() reading it. */
		if (_watcher) {
			kvWatcher      *w = _watcher;
			_watcher = NULL;  /* clear first -- prevent races */
			kvWatcher_Stop(w);
			/* Only destroy if still connected.  During disconnect,
			 * nats.c's I/O thread may be cleaning up the same
			 * internal structures -- destroying here causes
			 * double-free.  The handle is tiny; leak is bounded. */
			if (nats_pool_is_connected())
				kvWatcher_Destroy(w);
		}

		/* Brief pause before restarting to avoid tight loop on
		 * repeated failures.  Wait longer if disconnected -- let
		 * nats.c finish reconnection before we retry. */
		if (atomic_load(&_watcher_running)) {
			if (nats_pool_is_connected())
				usleep(250000);  /* 250ms */
			else
				usleep(1000000); /* 1s -- wait for reconnect */
		}
	}

	LM_INFO("NATS KV watcher thread stopped\n");
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * nats_watch_start() -- Start the self-healing KV watcher thread.
 *
 * Called from child_init() on the first SIP worker (rank == 1) to
 * minimize the number of JetStream ordered consumers.  Registers the
 * E_NATS_KV_CHANGE EVI event (if compiled with HAVE_EVI), stores the
 * watch patterns, and spawns the watcher pthread.
 *
 * The thread runs autonomously for the lifetime of the process,
 * handling all reconnection and index-rebuild logic internally.
 *
 * @param kv            Initial KV store handle (used only to validate that
 *                      the bucket exists; the thread obtains fresh handles
 *                      after each reconnect).
 * @param patterns      Array of key patterns to watch (e.g., "usrloc.>").
 *                      NULL with num_patterns==0 means watch all keys.
 * @param num_patterns  Number of entries in the patterns array.
 * @return              0 on success, -1 on error.
 */
int nats_watch_start(kvStore *kv, const char **patterns, int num_patterns)
{
	int i;

	if (!kv) {
		LM_ERR("nats_watch_start: NULL kv handle\n");
		return -1;
	}

	if (num_patterns <= 0 || !patterns) {
		LM_ERR("nats_watch_start: no patterns specified\n");
		return -1;
	}

	/* Store patterns for the watcher thread.  The strings are owned by
	 * OpenSIPS's module parameter parser and persist for the process
	 * lifetime, so we only need to copy the pointer array. */
	_watch_patterns = malloc(num_patterns * sizeof(char *));
	if (!_watch_patterns) {
		LM_ERR("failed to allocate watch patterns array\n");
		return -1;
	}
	for (i = 0; i < num_patterns; i++)
		_watch_patterns[i] = patterns[i];
	_num_patterns = num_patterns;

	atomic_store(&_watcher_running, 1);
	if (pthread_create(&_watcher_tid, NULL, _watcher_thread_fn, NULL) != 0) {
		LM_ERR("failed to create watcher thread\n");
		atomic_store(&_watcher_running, 0);
		return -1;
	}

	if (num_patterns > 0) {
		LM_INFO("NATS KV watcher started (%d pattern(s):", num_patterns);
		for (i = 0; i < num_patterns; i++)
			LM_INFO("  kv_watch[%d]: %s", i, patterns[i]);
	} else {
		LM_INFO("NATS KV watcher started (all keys)\n");
	}
	return 0;
}

/**
 * nats_watch_stop() -- Stop the KV watcher thread and clean up.
 *
 * Called from mod_destroy() during OpenSIPS shutdown.  Clears the
 * running flag, stops the kvWatcher (which unblocks kvWatcher_Next()),
 * then joins the thread.  After the thread exits, the kvWatcher handle
 * is destroyed.
 *
 * Safe to call multiple times or when the watcher was never started.
 */
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

	if (_watch_patterns) {
		free(_watch_patterns);
		_watch_patterns = NULL;
		_num_patterns = 0;
	}
}
