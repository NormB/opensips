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
 * cachedb_nats_reaper.h — the reaper: the AUTHORITATIVE per-contact expiry
 * mechanism (SPEC.md §4.3A).  Native per-message TTL (TTL-SOLUTION-SPEC.md) is
 * only an opportunistic optimization; the reaper is what actually guarantees an
 * expired contact is reclaimed (and the only correct behavior for servers <2.11,
 * mixed-expiry rows, and #6959/#1994 regressions).
 *
 * This header currently exposes the broker-less DECISION helpers (row-due
 * selection, per-row action, interval guard).  The reaper loop / process host
 * (its own register_timer [REV-17], the bounded KeysWithFilters scan [REV-28],
 * the in-SHM (row_exp,key) index, the CAS-prune via nats_kv_put_row [TREV-3]
 * with the CAS-guarded publish-delete [REV-16]) integrates on top and is gated
 * on the opensips+nats e2e harness.
 */

#ifndef CACHEDB_NATS_REAPER_H
#define CACHEDB_NATS_REAPER_H

#include <stdint.h>
#include <time.h>

/* (§4.3A [REV-1]) A row is a reap candidate iff row_exp != 0 && row_exp + slack
 * <= now.  row_exp == 0 is permanent and is NEVER due.  The slack the caller
 * passes is nats_reap_grace + nats_expired_linger [HREV-3]: the skew margin
 * keeps the reaper from purging within S of an expiry, the linger keeps it
 * from defeating the operator's physical-retention window. */
int _reap_row_due(int64_t row_exp, time_t now, int grace);

/* (§4.3A [REV-16/31]) What the reaper does with a due row after pruning its
 * expired contacts. */
enum reap_action {
	REAP_WRITE_SURVIVORS = 0,   /* CAS survivor-write via nats_kv_put_row     */
	REAP_DELETE_EMPTY    = 1,   /* CAS-guarded publish-delete (never blind)   */
};
enum reap_action _reap_row_action(int n_live_survivors);

/* (F2 [PREV-26/REV-2], extended [D6/HREV-6]) nats_reap_interval guard.
 * Returns 0 to start, -1 to refuse: interval <= 0 (reaper-off, TTL-only) is
 * unsupported unless the operator explicitly sets nats_unsafe_ttl_only (which
 * LM_WARNs #6959/#1994) -- and never supported with nats_native_ttl=0, which
 * would leave no expiry mechanism at all. */
int _reap_interval_guard(int interval, int unsafe_ttl_only, int native_ttl);

#endif /* CACHEDB_NATS_REAPER_H */
