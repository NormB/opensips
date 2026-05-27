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
 * The thread follows a four-step loop:
 *
 *   1. Wait for NATS connectivity (poll nats_pool_is_connected).
 *   2. Acquire a fresh KV handle and rebuild the search index
 *      from the full bucket contents (crash-recovery path).
 *   3. Create a kvWatcher on the bucket (with optional key pattern).
 *   4. Process live nats_dl.kvWatcher_Next() updates until disconnect or
 *      reconnect-epoch change, then loop back to step 1.
 *
 * On disconnect, the watcher is stopped BEFORE nats.c tears down internal
 * subscription state, avoiding a use-after-free race.  On reconnect, the
 * epoch check triggers a full index rebuild so the index never drifts.
 *
 * Thread safety: _watcher_running is an atomic_int accessed with
 * atomic_load/atomic_store.  An acquire fence after epoch-change detection
 * ensures subsequent KV operations see the new connection state.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <nats/nats.h>

#include "../../dprint.h"
#include "../../str.h"
#include "../../ipc.h"
#include "../../mem/shm_mem.h"

/* Module-scope params defined in cachedb_nats.c. */
extern int index_resync_on_reconnect;

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

/* Module globals from cachedb_nats.c are declared extern in
 * cachedb_nats_dbase.h (kv_bucket, kv_replicas, kv_history, kv_ttl)
 * which is included above; redeclaring them here triggers gcc's
 * -Wredundant-decls under -Werror.  fts_json_prefix isn't yet in a
 * header, so it stays as a single extern below. */
extern char *fts_json_prefix;

/* ---- watcher thread state (process-local) ---- */
static pthread_t       _watcher_tid;
static atomic_int      _watcher_running = 0;
/* _watcher is written by the watcher thread (create + per-iteration
 * teardown) and read/torn-down by nats_watch_stop() on another thread.
 * Make it atomic and have every teardown path atomic_exchange() it to
 * NULL: only the caller that observes the non-NULL value owns the
 * Stop/Destroy, so overlapping shutdown can never double-free. */
static _Atomic(kvWatcher *) _watcher    = NULL;

/* Multiple watch patterns -- set by nats_watch_start(), read by thread.
 * When _num_patterns == 0, watches all keys via nats_dl.kvStore_WatchAll().
 * When > 0, uses nats_dl.kvStore_WatchMulti() for selective watching. */
static const char    **_watch_patterns  = NULL;
static int             _num_patterns    = 0;

/* ---- EVI event for E_NATS_KV_CHANGE ---- */
/* Non-static: set by mod_init() in cachedb_nats.c via evi_publish_event() */
event_id_t evi_kv_change_id = EVI_ERROR;

/* ---- forward declarations ---- */
static void *_watcher_thread_fn(void *arg);
static void  _watcher_loop(void);
static void  _raise_kv_change_event(kvEntry *entry, kvOperation op);

/* ------------------------------------------------------------------ */
/*  EVI event raising via IPC (thread-safe)                            */
/* ------------------------------------------------------------------ */

/*
 * Architecture: The watcher runs as a pthread inside a SIP worker process.
 * EVI functions (evi_get_params, evi_raise_event) use pkg_malloc which is
 * NOT thread-safe.  To avoid heap corruption, the pthread copies event
 * data into a shm_malloc'd struct and dispatches an IPC RPC to a SIP
 * worker, where the EVI functions run safely in the reactor context.
 *
 * Flow:  pthread → shm_malloc + copy → ipc_dispatch_rpc → worker raises EVI → shm_free
 */

#ifdef HAVE_EVI
/**
 * IPC event struct -- carries KV change data from pthread to worker.
 * Single allocation with flexible array for key + value strings.
 */
struct kv_change_ipc_event {
	kvOperation op;
	int         revision;
	int         key_len;
	int         val_len;   /* 0 when op != kvOp_Put */
	char        data[0];   /* key\0[value\0] packed */
};

/**
 * _kv_change_rpc_cb() -- IPC callback that raises the EVI event.
 *
 * Runs in a SIP worker's reactor context where pkg_malloc is safe.
 * Reconstructs the event parameters from the shm struct, raises the
 * EVI event, then frees the shm allocation.
 */
static void _kv_change_rpc_cb(int sender, void *param)
{
	struct kv_change_ipc_event *ev = (struct kv_change_ipc_event *)param;
	evi_params_t *params;
	str key_str, op_str, val_str;
	int rev;

	static str pn_key = str_init("key");
	static str pn_op  = str_init("operation");
	static str pn_val = str_init("value");
	static str pn_rev = str_init("revision");

	LM_DBG("kv-change worker handler: sender=%d evi_id=%d probe=%d "
		"key_len=%d val_len=%d\n",
		sender, (int)evi_kv_change_id,
		evi_probe_event(evi_kv_change_id),
		ev->key_len, ev->val_len);

	/* Short-circuit if no subscribers */
	if (evi_kv_change_id == EVI_ERROR || !evi_probe_event(evi_kv_change_id))
		goto done;

	params = evi_get_params();
	if (!params)
		goto done;

	/* Reconstruct strings from packed data */
	key_str.s   = ev->data;
	key_str.len = ev->key_len;

	switch (ev->op) {
		case kvOp_Put:    op_str = (str){.s = "put",    .len = 3}; break;
		case kvOp_Delete: op_str = (str){.s = "delete", .len = 6}; break;
		default:          op_str = (str){.s = "purge",  .len = 5}; break;
	}

	if (evi_param_add_str(params, &pn_key, &key_str) < 0)
		goto err;
	if (evi_param_add_str(params, &pn_op, &op_str) < 0)
		goto err;

	if (ev->op == kvOp_Put && ev->val_len > 0) {
		val_str.s   = ev->data + ev->key_len + 1; /* after key\0 */
		val_str.len = ev->val_len;
		if (evi_param_add_str(params, &pn_val, &val_str) < 0)
			goto err;
	}

	rev = ev->revision;
	if (evi_param_add_int(params, &pn_rev, &rev) < 0)
		goto err;

	if (evi_raise_event(evi_kv_change_id, params) < 0)
		LM_ERR("failed to raise E_NATS_KV_CHANGE event\n");
	goto done;

err:
	evi_free_params(params);
done:
	shm_free(ev);
}
#endif /* HAVE_EVI */

/**
 * _raise_kv_change_event() -- Dispatch a KV change to the EVI subsystem.
 *
 * Called from the watcher pthread.  Copies event data into shared memory
 * and dispatches an IPC RPC to a SIP worker for safe EVI event raising.
 * No pkg_malloc is used in this function -- only shm_malloc (thread-safe)
 * and ipc_dispatch_rpc (atomic pipe write, thread-safe).
 *
 * @param entry  The kvEntry delivered by nats_dl.kvWatcher_Next().
 * @param op     The KV operation type (put, delete, or purge).
 */
static void _raise_kv_change_event(kvEntry *entry, kvOperation op)
{
#ifdef HAVE_EVI
	struct kv_change_ipc_event *ev;
	const char *key;
	const char *val = NULL;
	int key_len, val_len = 0;
	unsigned long alloc_size;

	if (evi_kv_change_id == EVI_ERROR)
		return;

	key     = nats_dl.kvEntry_Key(entry);
	if (!key) {
		LM_WARN("kv-change: entry has NULL key, skipping event\n");
		return;
	}
	key_len = strlen(key);

	if (op == kvOp_Put) {
		val     = nats_dl.kvEntry_ValueString(entry);
		val_len = nats_dl.kvEntry_ValueLen(entry);
		if (!val) val_len = 0;
	}

	/* Single shm allocation: struct + key\0 + [value\0] */
	alloc_size = sizeof(*ev) + key_len + 1
		+ (val_len > 0 ? val_len + 1 : 0);

	ev = shm_malloc(alloc_size);
	if (!ev) {
		LM_ERR("shm_malloc failed for KV change event (%lu bytes)\n",
			alloc_size);
		return;
	}

	ev->op       = op;
	ev->revision = (int)nats_dl.kvEntry_Revision(entry);
	ev->key_len  = key_len;
	ev->val_len  = val_len;

	/* Pack key into data[] */
	memcpy(ev->data, key, key_len);
	ev->data[key_len] = '\0';

	/* Pack value after key (put operations only) */
	if (val_len > 0) {
		memcpy(ev->data + key_len + 1, val, val_len);
		ev->data[key_len + 1 + val_len] = '\0';
	}

	/* Dispatch to a SIP worker -- atomic pipe write, pthread-safe */
	LM_DBG("kv-change dispatch: key=%s op=%d val_len=%d\n",
		key, (int)op, val_len);
	if (ipc_dispatch_rpc(_kv_change_rpc_cb, ev) < 0) {
		LM_ERR("ipc_dispatch_rpc failed for KV change event\n");
		shm_free(ev);
	}
#else
	/* EVI not available at build time -- log the change instead */
	const char *key = nats_dl.kvEntry_Key(entry);
	const char *op_name;

	if (!key) {
		LM_WARN("kv-change: entry has NULL key, skipping log\n");
		return;
	}

	switch (op) {
		case kvOp_Put:    op_name = "put";    break;
		case kvOp_Delete: op_name = "delete"; break;
		default:          op_name = "purge";  break;
	}

	LM_DBG("KV change (EVI unavailable): key=%s op=%s rev=%llu\n",
		key, op_name, (unsigned long long)nats_dl.kvEntry_Revision(entry));
#endif /* HAVE_EVI */
}

/* ------------------------------------------------------------------ */
/*  Watcher thread -- self-healing resilient loop                      */
/* ------------------------------------------------------------------ */

/**
 * _watcher_thread_fn() -- Main watcher thread entry point.
 *
 * Runs for the lifetime of the OpenSIPS worker process.  Implements a
 * four-step self-healing loop:
 *
 *   1. Block until NATS connectivity is established (500ms poll).
 *   2. Obtain a fresh KV handle from the pool and rebuild the
 *      JSON full-text search index from the complete bucket state.
 *   3. Create a kvWatcher with the configured key pattern (or
 *      watch all keys if no pattern is set).
 *   4. Process live updates from nats_dl.kvWatcher_Next() in a tight loop.
 *      On reconnect-epoch change or disconnect, break out and
 *      restart from step 1 to get a fresh KV handle and index.
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
	(void)arg;
	LM_INFO("NATS KV watcher thread started\n");
	_watcher_loop();
	LM_INFO("NATS KV watcher thread stopped\n");
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  _watcher_loop() -- shared self-healing event loop                  */
/* ------------------------------------------------------------------ */

/*
 * The self-healing loop body factored out so both the legacy rank-1
 * pthread (_watcher_thread_fn) and the dedicated-process main
 * (nats_watcher_proc_main) call the same code.  Loops while
 * _watcher_running is non-zero; in the dedicated-process variant
 * the running flag is set to 1 before this is called and is
 * cleared only by the OpenSIPS core sending SIGTERM (which
 * terminates the process directly).
 */
static void _watcher_loop(void)
{
	kvEntry        *entry = NULL;
	natsStatus      s;
	kvWatchOptions  opts;
	kvStore        *kv;
	kvWatcher      *w;
	int             last_epoch;
	int             prefix_len;

	prefix_len = fts_json_prefix ? (int)strlen(fts_json_prefix) : 0;

	while (atomic_load(&_watcher_running)) {

		/* ---- Wait for NATS connection ----
		 * Poll every 500ms until the pool reports connectivity.
		 * This covers both initial startup and post-disconnect recovery. */
		while (atomic_load(&_watcher_running) && !nats_pool_is_connected()) {
			usleep(500000); /* 500ms */
		}
		if (!atomic_load(&_watcher_running))
			break;

		last_epoch = nats_pool_get_reconnect_epoch();

		/* ---- Get fresh KV handle + rebuild search index ----
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

		/* index_resync_on_reconnect (default 1): rebuild the JSON
		 * index in full from KV. The query path has stale-entry
		 * self-heal, so operators may opt out of the O(N) rebuild
		 * for hot-reconnect topologies and accept a brief window
		 * where queries may evict a few stale entries before the
		 * index converges. */
		{
			if (index_resync_on_reconnect)
				nats_json_index_rebuild(kv, fts_json_prefix);
			else
				LM_DBG("watcher: index_resync_on_reconnect=0; "
					"skipping post-reconnect rebuild and "
					"deferring to lazy self-heal\n");
		}

		/* ---- Create kvWatcher ----
		 * Set UpdatesOnly so we only receive mutations after the
		 * current revision (the full state was already loaded via
		 * the index_rebuild above). */
		nats_dl.kvWatchOptions_Init(&opts);
		opts.UpdatesOnly = true;

		/* Create into a local handle, then publish it atomically.
		 * libnats wants a plain kvWatcher**, so we cannot pass
		 * &_watcher (it is _Atomic). */
		w = NULL;
		s = nats_dl.kvStore_WatchMulti(&w, kv,
			_watch_patterns, _num_patterns, &opts);

		if (s != NATS_OK) {
			LM_ERR("watcher: kvStore_WatchMulti failed: %s, "
				"retrying in 2s\n", nats_dl.natsStatus_GetText(s));
			sleep(2);
			continue;
		}

		atomic_store(&_watcher, w);

		LM_INFO("watcher: watching KV (%d pattern(s), epoch: %d)\n",
			_num_patterns, last_epoch);

		/* ---- Event loop ----
		 * Process live KV updates until a reconnect or disconnect
		 * invalidates the current watcher and KV handle. */
		while (atomic_load(&_watcher_running)) {
			/* Check for reconnect -- epoch changed means connection
			 * was lost and restored; our KV handle and watcher are
			 * stale. Break out for a full rebuild. */
			if (nats_pool_get_reconnect_epoch() != last_epoch) {
				/* Memory barrier: ensure subsequent KV operations
				 * (the rebuild path above) see the new connection
				 * state established by the reconnect callback thread. */
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
			 * where nats_dl.kvWatcher_Next() is blocked with stale state. */
			if (!nats_pool_is_connected()) {
				LM_INFO("watcher: disconnect detected, stopping "
					"watcher to prevent use-after-free\n");
				break;
			}

			s = nats_dl.kvWatcher_Next(&entry,
				atomic_load(&_watcher), 500);

			if (s == NATS_TIMEOUT) {
				/* Belt-and-suspenders for the dedicated-process
				 * topology (dedicated_watcher_proc=1): if our parent died and
				 * PR_SET_PDEATHSIG somehow didn't fire (kernel
				 * version with the bug, prctl rejected, etc.),
				 * the kernel re-parents us to PID 1.  Detect
				 * that here and exit so we never become an
				 * orphan watcher.  Cheap on every 500 ms tick;
				 * no-op for the rank-1 pthread variant where
				 * getppid() returns the master forever. */
				if (getppid() == 1) {
					LM_NOTICE("watcher: parent gone "
						"(reparented to init); exiting\n");
					atomic_store(&_watcher_running, 0);
					break;
				}
				continue;
			}

			if (s != NATS_OK) {
				if (atomic_load(&_watcher_running))
					LM_WARN("watcher: kvWatcher_Next failed: %s\n",
						nats_dl.natsStatus_GetText(s));
				break;
			}

			const char   *key = nats_dl.kvEntry_Key(entry);
			kvOperation   op  = nats_dl.kvEntry_Operation(entry);

			/* A NULL key would crash strncmp / index_add below.
			 * Drop the entry and keep watching. */
			if (!key) {
				LM_WARN("watcher: entry has NULL key, skipping\n");
				nats_dl.kvEntry_Destroy(entry);
				entry = NULL;
				continue;
			}

			if (op == kvOp_Put) {
				const char *val     = nats_dl.kvEntry_ValueString(entry);
				int         val_len = nats_dl.kvEntry_ValueLen(entry);

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

			nats_dl.kvEntry_Destroy(entry);
			entry = NULL;
		}

		/* ---- Cleanup before retry ----
		 * Destroy the stale watcher.  atomic_exchange claims the
		 * handle: whoever swaps the non-NULL value to NULL owns the
		 * Stop/Destroy.  If nats_watch_stop() raced us and already
		 * claimed it, we observe NULL here and do nothing -- no
		 * double Stop/Destroy. */
		{
			kvWatcher *w_claim = atomic_exchange(&_watcher, NULL);
			if (w_claim) {
				nats_dl.kvWatcher_Stop(w_claim);
				/* Only destroy if still connected.  During
				 * disconnect, nats.c's I/O thread may be cleaning
				 * up the same internal structures -- destroying
				 * here causes double-free.  The handle is tiny;
				 * leak is bounded. */
				if (nats_pool_is_connected())
					nats_dl.kvWatcher_Destroy(w_claim);
			}
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
		free(_watch_patterns);
		_watch_patterns = NULL;
		_num_patterns   = 0;
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
 * running flag, stops the kvWatcher (which unblocks nats_dl.kvWatcher_Next()),
 * then joins the thread.  After the thread exits, the kvWatcher handle
 * is destroyed.
 *
 * Safe to call multiple times or when the watcher was never started.
 */
void nats_watch_stop(void)
{
	kvWatcher *w_claim;

	if (!atomic_load(&_watcher_running))
		return;

	atomic_store(&_watcher_running, 0);

	/* Claim the watcher handle with a single atomic_exchange.  The
	 * watcher thread's per-iteration teardown does the same; only the
	 * thread that swaps the non-NULL value to NULL owns Stop/Destroy,
	 * so an overlapping shutdown can never double-free.  Stopping the
	 * watcher we claimed unblocks nats_dl.kvWatcher_Next() so the
	 * thread can observe _watcher_running == 0 and exit. */
	w_claim = atomic_exchange(&_watcher, NULL);
	if (w_claim)
		nats_dl.kvWatcher_Stop(w_claim);

	pthread_join(_watcher_tid, NULL);

	/* Thread has exited; safe to destroy the handle we claimed. */
	if (w_claim)
		nats_dl.kvWatcher_Destroy(w_claim);

	if (_watch_patterns) {
		free(_watch_patterns);
		_watch_patterns = NULL;
		_num_patterns = 0;
	}
}

/* ------------------------------------------------------------------ */
/*  Dedicated-process watcher entry                          */
/* ------------------------------------------------------------------ */

/* The kv_watch_list / kv_watch_count globals are owned by
 * cachedb_nats.c; their declarations live in cachedb_nats_watch.h
 * so this translation unit can read them without a duplicate decl. */

/**
 * nats_watcher_proc_main() -- dedicated-process watcher entry point.
 *
 * Forked by the OpenSIPS core via the proc_export_t entry registered
 * in cachedb_nats.c when both `dedicated_watcher_proc` and
 * `enable_search_index` are 1.  The function never returns.
 *
 * The body mirrors nats_watch_start() / _watcher_thread_fn() but
 * runs in its own process: it calls nats_pool_get() to bring up the
 * per-process NATS connection (nats_pool_register having seeded the
 * shared config in mod_init pre-fork), validates the KV bucket, and
 * enters the same self-healing loop.  Index updates are
 * written to the SHM-backed g_idx that every SIP worker also maps;
 * the per-shard locks added in commit 43ceca02b serialise the
 * cross-process writes safely without any new synchronisation.
 *
 * Signal handling: relies on the OpenSIPS core's default SIGTERM
 * delivery to children -- the kernel terminates the process on
 * shutdown, the SHM handles are released as part of process exit,
 * and the parent's destroy() path frees g_idx itself.
 */
void nats_watcher_proc_main(int rank)
{
	kvStore                  *kv;
	struct kv_watch_entry    *e;
	const char              **patterns;
	int                       i;

	(void)rank;

	LM_INFO("NATS watcher proc starting (pid=%d, ppid=%d)\n",
		(int)getpid(), (int)getppid());

	/* Parent-death handling: if the OpenSIPS master process exits
	 * (orderly shutdown OR a pre-fork abort like a failed
	 * mi_init_datagram_server), the kernel must reap us.  Without
	 * this we orphan: linux re-parents to PID 1, the watcher loop
	 * keeps running forever, and the next OpenSIPS startup races
	 * with a stale watcher writing to the SHM index of a freshly-
	 * allocated bucket.  Reproduces 100% of the time when the
	 * master aborts after the proc_export_t fork but before
	 * start_module_procs returns successfully -- e.g., when a
	 * sibling module's pre-fork hook fails.
	 *
	 * Use SIGKILL rather than SIGTERM.  OpenSIPS core installs a
	 * SIGTERM handler in every forked child that does graceful
	 * shutdown via destroy(); under PDEATHSIG that handler runs
	 * but its cleanup waits on shared resources owned by the
	 * already-dead parent, leaving us hung.  SIGKILL is
	 * uncatchable -- the kernel kills the process immediately
	 * and reclaims its pages on schedule.  The SHM index is
	 * parent-owned and is freed when the parent's destroy() path
	 * runs (orderly shutdown) or when the kernel reaps the SHM
	 * segment after the last attached process exits. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
		LM_WARN("watcher proc: prctl(PR_SET_PDEATHSIG) failed: "
			"%s; orphan-on-parent-death not protected\n",
			strerror(errno));
	}

	/* Race window: the parent could have died between our fork() and
	 * the prctl() above.  prctl arms only future deaths, so we'd miss
	 * an already-dead parent and run forever.  Re-check getppid: if
	 * it's 1 we have already been re-parented to init -- exit now. */
	if (getppid() == 1) {
		LM_NOTICE("watcher proc: parent died before we armed "
			"PR_SET_PDEATHSIG (re-parented to init); exiting\n");
		return;
	}

	/* Ensure the per-process NATS connection is up.  nats_pool_get()
	 * is lazy-init: the first call in this process opens the
	 * connection from the shared pool config that mod_init built. */
	if (!nats_pool_get()) {
		LM_ERR("watcher proc: NATS connection unavailable, exiting\n");
		return;
	}

	/* Validate the KV bucket exists.  The watcher loop fetches its
	 * own KV handle from the pool on each iteration anyway, but we
	 * keep this gate here for symmetry with the rank-1 child_init flow:
	 * if the bucket is missing or the broker is unreachable at
	 * startup, fail loudly rather than silently entering the
	 * reconnect loop. */
	kv = nats_pool_get_kv(kv_bucket, kv_replicas, kv_history,
		(int64_t)kv_ttl);
	if (!kv) {
		LM_ERR("watcher proc: failed to open KV bucket '%s'\n",
			kv_bucket);
		/* fall through -- the loop's reconnect-wait step will keep
		 * trying so a transient broker outage doesn't kill the
		 * process. */
	}

	/* Build the patterns array from the modparam-fed kv_watch_list.
	 * Stays alive for the lifetime of the process; no need to free. */
	if (kv_watch_count > 0) {
		patterns = malloc((kv_watch_count + 1) * sizeof(char *));
		if (!patterns) {
			LM_ERR("watcher proc: malloc failed for patterns\n");
			return;
		}
		i = 0;
		for (e = kv_watch_list; e; e = e->next)
			patterns[i++] = e->pattern;
		patterns[i] = NULL;
		_watch_patterns = patterns;
		_num_patterns = kv_watch_count;
	} else {
		_watch_patterns = NULL;
		_num_patterns = 0;
	}

	atomic_store(&_watcher_running, 1);

	if (_num_patterns > 0) {
		LM_INFO("watcher proc: watching %d pattern(s)\n", _num_patterns);
	} else {
		LM_INFO("watcher proc: no kv_watch patterns configured; "
			"loop will block on watcher creation until at least one is set\n");
	}

	/* Run forever.  SIGTERM from main on shutdown will terminate the
	 * process directly. */
	_watcher_loop();

	LM_INFO("NATS watcher proc exiting\n");
}
