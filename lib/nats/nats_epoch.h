/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * nats_epoch.h -- the epoch-tagged handle idiom [P2.8], in ONE place.
 *
 * The pool bumps a per-process reconnect epoch from the libnats
 * reconnect callback.  Any handle DERIVED from the connection (KV
 * store, JetStream context, subscription, in-flight RPC) is dead
 * weight after a reconnect; consumers tag the handle with the epoch
 * at acquire time and re-acquire when the tag goes stale.  This
 * header replaces the save/compare/refresh dance that used to be
 * re-implemented at every site.
 *
 * THE TRAP this header exists to encode (it was P0.1, a permanent
 * per-worker outage): on a REFRESH path, snapshot the epoch BEFORE
 * acquiring the new handle and adopt the snapshot only AFTER the
 * acquire succeeds.  Re-reading the epoch at adopt time can pair an
 * OLD-connection handle with a NEW epoch tag -- the staleness check
 * then never fires again until the next reconnect.  Snapshot-first is
 * conservative in the benign direction: a reconnect that lands mid-
 * refresh leaves the tag stale, so the next call refreshes again.
 *
 *   acquire:   nats_epoch_save(&h->epoch);          (with the handle)
 *   fast path: if (nats_epoch_current(&h->epoch) && h->kv) use it;
 *   refresh:   int snap = nats_epoch_snapshot();
 *              h->kv = nats_pool_get_kv(...);
 *              if (h->kv) nats_epoch_adopt(&h->epoch, snap);
 *   liveness:  nats_epoch_lost(&h->epoch)  ==  reconnected OR
 *              currently disconnected (the "did we lose the broker
 *              since this started" test for in-flight work).
 *
 * Self-contained: only the two pool accessors are declared here, so
 * SHM-struct headers (e.g. nats_rpc_slot.h) can embed nats_epoch_t
 * without pulling the whole pool surface.
 */

#ifndef LIB_NATS_NATS_EPOCH_H
#define LIB_NATS_NATS_EPOCH_H

int nats_pool_get_reconnect_epoch(void);
int nats_pool_is_connected(void);

typedef struct nats_epoch {
	int seen;
} nats_epoch_t;

/* Tag: the handle being tagged was just acquired from the live pool. */
static inline void nats_epoch_save(nats_epoch_t *e)
{
	e->seen = nats_pool_get_reconnect_epoch();
}

/* Fast-path check: no reconnect since the tag was taken. */
static inline int nats_epoch_current(const nats_epoch_t *e)
{
	return e->seen == nats_pool_get_reconnect_epoch();
}

/* Refresh protocol (see the file comment): snapshot BEFORE the
 * acquire, adopt only after success. */
static inline int nats_epoch_snapshot(void)
{
	return nats_pool_get_reconnect_epoch();
}

static inline void nats_epoch_adopt(nats_epoch_t *e, int snapshot)
{
	e->seen = snapshot;
}

/* In-flight liveness: the broker was lost (reconnected since the tag,
 * or not connected right now). */
static inline int nats_epoch_lost(const nats_epoch_t *e)
{
	return !nats_pool_is_connected() || !nats_epoch_current(e);
}

#endif /* LIB_NATS_NATS_EPOCH_H */
