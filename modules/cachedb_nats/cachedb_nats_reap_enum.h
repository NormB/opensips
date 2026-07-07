/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * cachedb_nats_reap_enum.h -- one value-carrying watch pass over the
 * KV bucket, for the reaper.
 *
 * Why this exists: the reaper tick used to enumerate with
 * kvStore_Keys() (MetaOnly) and then re-fetch EVERY key's value with
 * an individual synchronous kvStore_Get() -- O(bucket) broker round
 * trips per tick.  Measured on the 30k-AoR bench (2026-07-07): the
 * per-key GET storm runs ~7-17 s per pass at ~1.6k req/s alongside
 * live traffic and drives REGISTER p99/max from ~1 ms to 27-88 ms
 * while it lasts.  A single WatchAll pass carries the values with it
 * (entry = key + value + revision), so the whole enumeration is one
 * ordered-consumer drain: no per-key round trips at all.
 */

#ifndef CACHEDB_NATS_REAP_ENUM_H
#define CACHEDB_NATS_REAP_ENUM_H

#include <stdint.h>
#include <nats/nats.h>

/* Per-entry wait budget the reaper hands to kvWatcher_Next().  Big
 * enough to ride out a flow-control pause, small enough that a dead
 * broker ends the pass promptly (the next tick rescans). */
#define NATS_REAP_ENUM_NEXT_TIMEOUT_MS  5000

/* Return codes (all < 0; success returns the visit count >= 0). */
#define NATS_REAP_ENUM_EARG    (-1)  /* bad arguments */
#define NATS_REAP_ENUM_EWATCH  (-2)  /* WatchAll create failed */
#define NATS_REAP_ENUM_ENEXT   (-3)  /* Next failed/timed out mid-pass */
#define NATS_REAP_ENUM_EABORT  (-4)  /* callback asked to abort */

/*
 * Per-entry callback.  Runs once for every live key's LATEST revision
 * (deletes/purges are not delivered).  The entry is owned by the
 * enumerator: it is destroyed after the callback returns -- do not
 * destroy it, do not keep pointers into it past the return.
 * Return >= 0 to continue the pass, < 0 to abort it.
 */
typedef int (*nats_reap_enum_cb_f)(kvEntry *entry, void *arg);

/*
 * nats_reap_enum_bucket() -- drain one full initial watch pass.
 *
 * @kv               bucket handle (from nats_pool_get_kv()).
 * @next_timeout_ms  per-entry wait budget handed to kvWatcher_Next();
 *                   must be > 0.  A broker stall longer than this ends
 *                   the pass with NATS_REAP_ENUM_ENEXT (the next tick
 *                   simply rescans -- the reaper is idempotent).
 * @cb / @arg        per-entry visitor.
 *
 * Returns the number of entries visited (>= 0), or one of the
 * NATS_REAP_ENUM_E* codes above.  The end of the initial data set is
 * signalled by libnats delivering a NULL entry from kvWatcher_Next();
 * the enumerator stops there -- live updates are never consumed.
 */
int nats_reap_enum_bucket(kvStore *kv, int64_t next_timeout_ms,
		nats_reap_enum_cb_f cb, void *arg);

#endif /* CACHEDB_NATS_REAP_ENUM_H */
