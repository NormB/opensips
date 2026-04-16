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

#endif /* CACHEDB_NATS_WATCH_H */
