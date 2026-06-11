/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CACHEDB_NATS_INTERN_H
#define CACHEDB_NATS_INTERN_H

/*
 * cachedb_nats_intern -- refcounted SHM string intern table
 *
 * Why this exists.  At 100k AoRs / 2000 RPS the watcher's
 * nats_json_index_add hot path was spending ~half of all opensips
 * CPU in sem_wait -> hp_shm_malloc paths (see PERF_NOTES.md).
 * Each indexed field on a usrloc contact triggers _entry_add_key
 * -> shm_malloc(klen+1) for a duplicate of the document key,
 * which then takes a per-bucket SHM_LOCK semaphore inside
 * HP_MALLOC.  ~5 indexed fields per contact x 2000 events/s =
 * ~10k shm_mallocs/s of small strings, all on the same hot path.
 *
 * Insight: the document key is the same string across ALL
 * field-entries for a given AoR.  Today we strdup it 5 times.
 * Interning the doc key collapses those 5 strdups into 1
 * lookup-or-allocate-once, and on every subsequent re-register
 * of the same AoR (the dominant workload) the lookup hits an
 * existing entry and does NO shm_malloc at all.
 *
 * The intern table is a sharded hash table: 1024 buckets,
 * 32 lock shards.  Refcounts are bumped on acquire and
 * decremented on release; the entry is freed when the count
 * reaches zero.  Lookups under the shard lock; the shard lock
 * is independent of the index shard lock so there's no
 * deadlock with cachedb_nats_json's per-shard scheme (the
 * index lock is always taken first; intern lock is always
 * taken second; never the other way around).
 *
 * Memory: each intern node is sizeof(nats_intern_node_t) +
 * len + 1, allocated with a single shm_malloc.  At steady
 * state with 100k AoRs and ~30-byte doc keys, the intern
 * table holds 100k entries x ~70 bytes each = ~7 MB SHM --
 * trivial.
 *
 * Lifetime: nodes are kept in SHM until refcount hits zero,
 * which happens when the last index entry that referenced
 * the doc key is freed (typically via _entry_remove_key when
 * an AoR de-registers, or _free_entry on full index destroy).
 *
 * Thread safety: every operation locks the relevant shard.
 * Multi-process safe: the table lives in SHM, the locks are
 * gen_lock_set_t (POSIX-sem on aarch64), so the dedicated
 * watcher proc and the rank-1 pthread are equally well
 * supported.
 */

/* Initialise the global intern table in SHM.  Call once from mod_init
 * pre-fork so every worker (and the dedicated watcher proc) maps the same
 * table.  @num_buckets sizes the bucket array (rounded up to a power of
 * two; <= 0 selects the default) -- pass the index_buckets modparam so the
 * intern chains scale with the deployment instead of being fixed at 1024.
 * Returns 0 on success, -1 on SHM exhaustion. */
int  nats_intern_init(int num_buckets);

/* Tear down the intern table.  Call once from mod_destroy.
 * Frees all entries and the table itself; safe to call when
 * init failed (no-op). */
void nats_intern_destroy(void);

/* Look up a string in the intern table; insert and allocate it
 * if absent.  In either case the entry's refcount is bumped by
 * one and the SHM-resident NUL-terminated string pointer is
 * returned.  The caller MUST eventually balance every successful
 * acquire with a matching release.
 *
 * Returns NULL if SHM allocation fails on insert.  The caller
 * should treat NULL as a fatal-this-call error and propagate
 * upward (matching the prior shm_malloc-based code).
 *
 * Safe to call from any process that has mapped SHM.  The shard
 * lock is held only across the chain walk + node insert.  Hash
 * is FNV-1a over the byte sequence (len bytes; the input does
 * not need to be NUL-terminated). */
char *nats_intern_acquire(const char *s, int len);

/* Release a string previously obtained from nats_intern_acquire.
 * Decrements the refcount; when it reaches zero the entry is
 * removed from its bucket chain and shm_free'd.  Safe to call
 * with NULL (no-op).
 *
 * The pointer must be the exact value returned by acquire --
 * pointer-arithmetic on the inline string (e.g., passing
 * `p + 1` from a string offset) will fail because the
 * container_of conversion needs the original head pointer. */
void nats_intern_release(char *p);

/* Diagnostic: number of unique entries currently held in the
 * table.  Used by structural tests; not on the hot path. */
int  nats_intern_size(void);

#endif /* CACHEDB_NATS_INTERN_H */
