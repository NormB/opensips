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
 * (nats_watcher_proc_main) can build its patterns[] array from the
 * same source the rank-1 pthread (child_init) uses.
 */
struct kv_watch_entry {
	char                   *pattern;
	struct kv_watch_entry  *next;
};
extern struct kv_watch_entry *kv_watch_list;
extern int kv_watch_count;

/**
 * nats_watch_start() -- Start the self-healing KV watcher thread.
 *
 * Called from child_init() on the first SIP worker process.  Spawns a
 * pthread that monitors the KV bucket for changes and keeps the JSON
 * full-text search index in sync.  The thread is fully self-healing:
 * it detects disconnects and reconnects, rebuilds the index from
 * scratch on each new connection, and raises E_NATS_KV_CHANGE EVI
 * events for every mutation.
 *
 * Only one watcher per OpenSIPS instance is needed (rank == 1) to
 * minimize JetStream ordered consumer count.
 *
 * @param kv            KV store handle (used for initial validation only;
 *                      the thread obtains fresh handles after reconnect).
 * @param patterns      Array of key patterns to watch (e.g., "usrloc.>").
 *                      Use ">" to watch all keys.  Must have at least one.
 * @param num_patterns  Number of entries in the patterns array (must be > 0).
 * @return              0 on success, -1 on error.
 */
int nats_watch_start(kvStore *kv, const char **patterns, int num_patterns);

/**
 * nats_watch_stop() -- Stop the KV watcher thread and clean up.
 *
 * Called from mod_destroy() during OpenSIPS shutdown.  Signals the
 * watcher thread to exit, unblocks kvWatcher_Next() by stopping the
 * kvWatcher, then joins the thread and destroys the handle.
 *
 * Safe to call multiple times or when the watcher was never started.
 */
void nats_watch_stop(void);

/**
 * nats_watcher_proc_main() -- Dedicated-process watcher entry point.
 *
 * Item 4: when dedicated_watcher_proc=1 (and enable_search_index=1),
 * the OpenSIPS core forks an extra child process via the
 * proc_export_t entry in cachedb_nats.c and calls this function as
 * its main loop.  The function never returns: it joins the shared
 * NATS pool, acquires the configured KV bucket handle, and runs
 * the same self-healing watcher loop that the rank-1 pthread runs
 * in legacy mode.  SIP workers continue to read the SHM-backed
 * JSON-FTS index that this process keeps live.
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

#endif /* CACHEDB_NATS_WATCH_H */
