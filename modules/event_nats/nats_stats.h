/*
 * Copyright (C) 2025 Summit-2026 / event_nats contributors
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
 *
 */

/*
 * nats_stats.h — NATS Statistics and MI Command Handlers
 *
 * Module:  event_nats
 *
 * Defines the shared-memory statistics structure for tracking NATS
 * connection state and publish metrics, plus MI (Management Interface)
 * command handlers for runtime introspection.
 *
 * Key types:
 *   nats_stats_t  — volatile counters in shared memory, updated by
 *                   all OpenSIPS worker processes
 *
 * MI commands:
 *   nats_status    — connection state and server info
 *   nats_stats     — publish/ack counters
 *   nats_reconnect — force a reconnection (drain + reconnect)
 */

#ifndef _NATS_STATS_H_
#define _NATS_STATS_H_

#include "../../mi/mi.h"
#include "../../statistics.h"

/*
 * NATS statistics counters, allocated in OpenSIPS shared memory.
 *
 * All fields are declared volatile because they are written by multiple
 * worker processes and read by the MI process.  Increments are not
 * atomic (acceptable for advisory counters — minor races do not affect
 * correctness).
 */
typedef struct _nats_stats {
    volatile int connected;             /* Connection state flag.
                                         * 1 = connected, 0 = disconnected.
                                         * Set by the nats.c reconnect/disconnect
                                         * callbacks (via atomic write). */
    volatile unsigned long published;   /* Total messages published (core NATS
                                         * + JetStream combined). */
    volatile unsigned long evi_published;   /* Messages published via EVI
                                             * subscribe_event() transport. */
    volatile unsigned long script_published; /* Messages published via the
                                              * nats_publish() script function. */
    volatile unsigned long failed;          /* Publish attempts that returned
                                             * an error from nats.c. */
    volatile unsigned long reconnects;      /* Number of successful reconnections
                                             * reported by the nats.c library. */
    volatile unsigned long js_ack_ok;       /* JetStream publish acknowledgments
                                             * received successfully. */
    volatile unsigned long js_ack_failed;   /* JetStream publish acknowledgments
                                             * that reported an error. */
} nats_stats_t;

/* Global pointer to the shared-memory stats structure.
 * Allocated by nats_stats_init(), freed by nats_stats_destroy().
 * NULL before initialization. */
extern nats_stats_t *nats_stats;

/*
 * Allocate and zero-initialize the stats structure in shared memory.
 *
 * Must be called from mod_init (pre-fork) so that all worker processes
 * inherit the same shared-memory pointer.
 *
 * @return  0 on success, -1 on shared-memory allocation failure.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_init.
 */
int nats_stats_init(void);

/*
 * Free the shared-memory stats structure.
 *
 * Called from mod_destroy during shutdown.
 *
 * Thread safety: NOT thread-safe.  Call only from mod_destroy.
 */
void nats_stats_destroy(void);

/*
 * MI handler: "nats_status"
 *
 * Returns a JSON object with connection state, server URLs, and
 * the current reconnect epoch.
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.
 */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl);

/*
 * MI handler: "nats_stats"
 *
 * Returns a JSON object with all publish/ack counters from nats_stats_t.
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.
 */
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl);

/*
 * MI handler: "nats_reconnect"
 *
 * Forces the NATS connection to drain and reconnect.  Useful for
 * maintenance or to pick up new cluster topology.
 *
 * @param params     MI parameters (unused).
 * @param async_hdl  Async handler (unused — this command is synchronous).
 * @return           MI response tree, or NULL on error.
 *
 * Thread safety: Safe to call from the MI process.  The actual drain/
 *                reconnect is serialized by nats.c internally.
 */
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif /* _NATS_STATS_H_ */
