/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * cachedb_nats_reap_enum.c -- see cachedb_nats_reap_enum.h.
 */

#include <stddef.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../lib/nats/nats_dl.h"
#include "cachedb_nats_reap_enum.h"

int nats_kv_enum_live_values(kvStore *kv, int64_t next_timeout_ms,
		nats_kv_enum_cb_f cb, void *arg)
{
	kvWatchOptions opts;
	kvWatcher *w = NULL;
	kvEntry *e;
	natsStatus s;
	int visited = 0, rc;

	if (!kv || !cb || next_timeout_ms <= 0)
		return NATS_KV_ENUM_EARG;

	nats_dl.kvWatchOptions_Init(&opts);
	/* parity with the kvStore_Keys() enumeration this replaces: live
	 * keys only.  Values ride along (MetaOnly stays false) -- that is
	 * the point: no per-key Get round trips. */
	opts.IgnoreDeletes = true;

	s = nats_dl.kvStore_WatchAll(&w, kv, &opts);
	if (s != NATS_OK || !w) {
		LM_DBG("reap enum: kvStore_WatchAll failed: %s\n",
			nats_dl.natsStatus_GetText(s));
		return NATS_KV_ENUM_EWATCH;
	}

	for (;;) {
		e = NULL;
		s = nats_dl.kvWatcher_Next(&e, w, next_timeout_ms);
		if (s != NATS_OK) {
			LM_DBG("reap enum: kvWatcher_Next failed after %d "
				"entrie(s): %s\n", visited,
				nats_dl.natsStatus_GetText(s));
			nats_dl.kvWatcher_Stop(w);
			nats_dl.kvWatcher_Destroy(w);
			return NATS_KV_ENUM_ENEXT;
		}
		if (!e)
			break;   /* initial-data sentinel: bucket enumerated */
		rc = cb(e, arg);
		nats_dl.kvEntry_Destroy(e);
		visited++;
		if (rc < 0) {
			nats_dl.kvWatcher_Stop(w);
			nats_dl.kvWatcher_Destroy(w);
			return NATS_KV_ENUM_EABORT;
		}
	}

	nats_dl.kvWatcher_Stop(w);
	nats_dl.kvWatcher_Destroy(w);
	return visited;
}
