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

#ifndef CACHEDB_NATS_WATCH_H
#define CACHEDB_NATS_WATCH_H

#include <nats/nats.h>

/*
 * KV watch pattern list, populated by the kv_watch modparam in
 * cachedb_nats.c.  Exposed here so the dedicated-process watcher
 * (nats_watcher_proc_main) can build its patterns[] array from it.
 */
struct kv_watch_entry {
	char                   *pattern;
	struct kv_watch_entry  *next;
};
extern struct kv_watch_entry *kv_watch_list;
extern int kv_watch_count;

/**
 * nats_watcher_proc_main() -- Dedicated-process watcher entry point.
 *
 * The ONLY watcher mode.  When enable_search_index=1 and at least one
 * kv_watch pattern is configured, the OpenSIPS core forks an extra
 * child process via the proc_export_t entry in cachedb_nats.c and
 * calls this function as its main loop.  The function never returns:
 * it joins the shared NATS pool, acquires the configured KV bucket
 * handle, and runs the self-healing watcher loop.  SIP workers read
 * the SHM-backed JSON-FTS index that this process keeps live.
 *
 * (The former in-worker pthread mode was removed: a second thread in
 * a SIP worker raced the connection pool's process-single-threaded
 * KV-handle cache — use-after-free under broker flap.)
 *
 * Signal handling: relies on the OpenSIPS core's default SIGTERM
 * delivery to children, which terminates the process at shutdown.
 * Process-local NATS handles are released as part of the kernel's
 * page cleanup; the SHM index is owned by the parent and freed in
 * destroy().
 *
 * @param rank  Rank assigned by the core fork loop (always 0 here:
 *              we declare exactly one instance).  Unused.
 */
void nats_watcher_proc_main(int rank);

/**
 * [P3.3] Shared bring-up for the module's dedicated processes (KV
 * watcher + reaper): arms PR_SET_PDEATHSIG(SIGKILL) so the kernel
 * reaps the child if the OpenSIPS master dies, closes the
 * fork-vs-parent-death race via a getppid() re-check, and lazily
 * opens the per-process NATS connection (nats_pool_get() first-use
 * init from the shared config mod_init seeded).
 *
 * @param who  short tag for the log lines ("watcher", "reaper");
 *             borrowed for the call, not stored.
 * @return 0 to proceed, -1 when the caller must exit (parent already
 *         dead, or no NATS connection can be established).
 *
 * Nothing allocated for the caller.  Locking: none.  Context: the
 * FIRST thing a dedicated-process main (nats_watcher_proc_main /
 * nats_cdb_reaper_proc_main) runs after being forked by the core;
 * never call it from SIP workers or the MI process.
 */
int nats_cdb_dedicated_proc_guard(const char *who);

/**
 * [P2.7] Periodic FTS index resync pass body: acquires a fresh KV
 * handle from the per-process pool and rebuilds the SHM-backed JSON
 * search index in full (cdbn_fts.rebuild).  Skips the tick silently
 * when the broker is down (NULL KV handle); the next tick or the next
 * reconnect retries.
 *
 * @param ticks  unused (signature kept from its register_timer era).
 * @param param  unused.
 *
 * O(bucket) and blocking.  Nothing allocated for the caller; index
 * memory is the SHM index owned by the module (freed in destroy()).
 * Locking: takes no locks itself — cross-process index writes are
 * serialized by the FTS index's internal per-shard locks.  Context:
 * [P3.3] the dedicated reaper process (hosted next to the reaper pass,
 * see nats_cdb_reaper_proc_main), no longer the core timer process.
 */
void nats_cdb_periodic_resync(unsigned int ticks, void *param);

#endif /* CACHEDB_NATS_WATCH_H */
