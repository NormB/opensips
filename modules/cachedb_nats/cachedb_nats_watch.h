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
 * Start the KV watcher thread. Called from child_init.
 * Creates a pthread that polls kvWatcher_Next() and:
 *   1. Updates the in-process search index
 *   2. Raises E_NATS_KV_CHANGE events via EVI (if event_nats loaded)
 *
 * @param kv       KV store handle
 * @param pattern  Key pattern to watch (e.g., "usrloc.>" for wildcard)
 *                 NULL or empty string means watch all keys
 * @return 0 on success, -1 on error
 */
int nats_watch_start(kvStore *kv, const char *pattern);

/*
 * Stop the watcher thread. Called from mod_destroy.
 */
void nats_watch_stop(void);

/*
 * Reconnection handler -- stops old watcher, rebuilds index,
 * starts new watcher. Registered via nats_pool_on_reconnect().
 */
void nats_watch_reconnect_handler(void *closure);

#endif /* CACHEDB_NATS_WATCH_H */
