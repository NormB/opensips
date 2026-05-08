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
 * cachedb_nats_stats.h — counters for the cachedb path.
 *
 * Mirrors the SHM-atomic pattern from event_nats/nats_stats.h:
 *   - struct allocated in mod_init (pre-fork) so all workers inherit it
 *   - C11 _Atomic counters with relaxed ordering
 *   - exposed via the nats_cdb_stats MI command
 *
 * Counters tracked:
 *   cas_retry        — total CAS retries across all cdbf.update / add /
 *                      sub calls. Bumped once per failed kvStore_Update.
 *   cas_exhausted    — total cdbf calls that ran out of nats_cas_retries
 *                      and dropped the write.
 *   create_doc       — total times nats_cache_update synthesized a seed
 *                      document and CreateString'd it (insert path).
 *   index_miss_kv    — query/update found a key in the in-memory index
 *                      but the KV store said NOT_FOUND. Flags index
 *                      staleness, typically from a sibling-instance delete.
 */

#ifndef _CACHEDB_NATS_STATS_H_
#define _CACHEDB_NATS_STATS_H_

#include <stddef.h>
#include <stdatomic.h>

#include "../../mi/mi.h"

/* Per-process upper bound for the SHM cdb-stats table.  See the
 * mirror constant in event_nats/nats_stats.h for the rationale; the
 * two NATS modules use the same scheme to keep counter bumps off
 * each others' cachelines. */
#define NATS_CDB_STATS_MAX_PROCS 512

typedef struct _nats_cdb_stats {
	_Atomic unsigned long cas_retry;
	_Atomic unsigned long cas_exhausted;
	_Atomic unsigned long create_doc;
	_Atomic unsigned long index_miss_kv;
} __attribute__((aligned(64))) nats_cdb_stats_t;

/* Pointer to the SHM array of NATS_CDB_STATS_MAX_PROCS slots. */
extern nats_cdb_stats_t *nats_cdb_stats;

static inline nats_cdb_stats_t *nats_cdb_stats_slot(void)
{
	extern int process_no;
	if (!nats_cdb_stats) return NULL;
	if (process_no < 0 || process_no >= NATS_CDB_STATS_MAX_PROCS)
		return NULL;
	return &nats_cdb_stats[process_no];
}

unsigned long nats_cdb_stats_sum(size_t field_offset);
#define NATS_CDB_STATS_SUM(field) \
	nats_cdb_stats_sum(offsetof(nats_cdb_stats_t, field))

/*
 * Allocate and zero-initialize the stats structure in shared memory.
 * Call from mod_init (pre-fork). Returns 0 on success, -1 on SHM
 * allocation failure.
 */
int nats_cdb_stats_init(void);

/*
 * Free the SHM block. Call from mod_destroy.
 */
void nats_cdb_stats_destroy(void);

/*
 * MI handler: "nats_cdb_stats" — returns a JSON object with all four
 * counters. Safe to call from the MI process.
 */
mi_response_t *mi_nats_cdb_stats(const mi_params_t *params,
	struct mi_handler *async_hdl);

/* Convenience bump — no-op if stats are not yet initialized.  Each
 * process writes to its own cacheline-sized slot indexed by
 * process_no, eliminating inter-process cacheline ping-pong on
 * publish-rate-bound counters. */
#define NATS_CDB_STATS_INC(field) do { \
	nats_cdb_stats_t *_s = nats_cdb_stats_slot(); \
	if (_s) atomic_fetch_add_explicit(&_s->field, 1, \
		memory_order_relaxed); \
} while (0)

/*
 * Bounded jittered exponential backoff for CAS retry loops.
 *
 * Sleeps for a random interval in [0, max_us(attempt)] where
 *   max_us(attempt) = min(BASE * 2^(attempt-1), CAP)
 *   BASE = 50 us, CAP = 5000 us
 *
 * attempt=0 returns immediately. The cap bounds total sleep across
 * the default 10-retry budget at ~50 ms, well under usrloc's
 * REGISTER processing budget.
 */
#define NATS_CAS_BACKOFF_BASE_US   50UL
#define NATS_CAS_BACKOFF_CAP_US    5000UL

unsigned long nats_cas_backoff_max_us(int attempt);
void nats_cas_backoff_sleep(int attempt);

#endif /* _CACHEDB_NATS_STATS_H_ */
