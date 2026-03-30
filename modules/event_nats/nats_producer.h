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
 * nats_producer.h — NATS Message Publishing API
 *
 * Module:  event_nats
 *
 * Provides the publish interface used by the EVI transport callbacks
 * and the nats_publish() script function.  Supports both core NATS
 * publish (fire-and-forget) and JetStream async publish (with ack
 * tracking via nats_stats).
 *
 * Connection handles are injected via set functions during child_init,
 * obtained from the shared connection pool (nats_pool_get / _get_js).
 *
 * Key functions:
 *   nats_producer_set_connection() — inject core NATS connection
 *   nats_producer_set_js()         — inject JetStream context
 *   nats_publish()                 — core NATS publish
 *   nats_js_publish_async()        — JetStream publish with async ack
 */

#ifndef NATS_PRODUCER_H
#define NATS_PRODUCER_H

#include <nats/nats.h>

/*
 * Set the core NATS connection handle for this worker process.
 *
 * Must be called from child_init before any publish calls.  The handle
 * is obtained from nats_pool_get() and cached process-locally.
 *
 * @param nc  NATS connection handle (must not be NULL).
 *
 * Thread safety: Call only from OpenSIPS worker context (child_init).
 */
void nats_producer_set_connection(natsConnection *nc);

/*
 * Set the JetStream context handle for this worker process.
 *
 * Must be called from child_init.  If NULL is passed (JetStream not
 * available), nats_js_publish_async() will fall back to core publish.
 *
 * @param js  JetStream context handle, or NULL if JS is unavailable.
 *
 * Thread safety: Call only from OpenSIPS worker context (child_init).
 */
void nats_producer_set_js(jsCtx *js);

/*
 * Publish a message via core NATS (fire-and-forget).
 *
 * Non-blocking: nats.c buffers the message internally and flushes
 * asynchronously.  Increments nats_stats->published on success,
 * nats_stats->failed on error.
 *
 * @param subject  NATS subject string (e.g., "opensips.pike.blocked").
 * @param data     Pointer to message payload.
 * @param len      Length of the payload in bytes.
 * @return         0 on success, -1 on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 *                nats.c internally serializes publishes on the connection.
 */
int nats_publish(const char *subject, const void *data, int len);

/*
 * Publish a message via JetStream with asynchronous acknowledgment.
 *
 * If a JetStream context is available (set via nats_producer_set_js),
 * publishes using jsPublishAsync, which returns immediately and tracks
 * the ack via the pool's AckHandler (updating js_ack_ok / js_ack_failed
 * stats).  If no JetStream context is set, falls back to nats_publish().
 *
 * @param subject  NATS subject string (must map to a JetStream stream).
 * @param data     Pointer to message payload.
 * @param len      Length of the payload in bytes.
 * @return         0 on success (or successful fallback), -1 on error.
 *
 * Thread safety: Safe to call from any OpenSIPS worker process context.
 */
int nats_js_publish_async(const char *subject, const void *data, int len);

#endif /* NATS_PRODUCER_H */
