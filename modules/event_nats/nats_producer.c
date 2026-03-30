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
 * nats_producer.c -- NATS message publishing layer
 *
 * Provides the low-level publish functions used by the EVI transport
 * (nats_evi_raise) and the script function (nats_publish).  Supports
 * both core NATS publish and JetStream async publish.
 *
 * The NATS connection and JetStream context are set per-process by
 * child_init() in event_nats.c via the setter functions below.
 * All publish calls go through these process-local pointers.
 *
 * Statistics (published/failed counters) are updated in shared memory
 * via the nats_stats pointer from nats_stats.c.
 */

#include <nats/nats.h>
#include "../../dprint.h"
#include "nats_producer.h"
#include "nats_stats.h"

/* Set by child_init via event_nats.c */
static natsConnection *_nc = NULL;
static jsCtx *_js = NULL;

extern nats_stats_t *nats_stats;

/**
 * nats_producer_set_connection() -- Store the per-process NATS connection.
 *
 * Called from child_init() after obtaining a connection from the pool.
 *
 * @param nc  NATS connection handle (owned by the pool, not freed here).
 */
void nats_producer_set_connection(natsConnection *nc) { _nc = nc; }

/**
 * nats_producer_set_js() -- Store the per-process JetStream context.
 *
 * Called from child_init() when JetStream is enabled.
 *
 * @param js  JetStream context handle (owned by the pool, not freed here).
 */
void nats_producer_set_js(jsCtx *js) { _js = js; }

/**
 * nats_publish() -- Publish a message via core NATS.
 *
 * Sends a message to the given subject using the process-local NATS
 * connection.  Updates shared-memory publish/fail counters on completion.
 *
 * @param subject  Null-terminated NATS subject string.
 * @param data     Message payload bytes.
 * @param len      Length of the payload in bytes.
 * @return         0 on success, -1 on error.
 */
int nats_publish(const char *subject, const void *data, int len)
{
    if (!_nc) {
        LM_ERR("NATS publish to '%s' failed: connection not initialized\n",
               subject ? subject : "(null)");
        if (nats_stats) nats_stats->failed++;
        return -1;
    }

    natsStatus s = natsConnection_Publish(_nc, subject, data, len);
    if (s != NATS_OK) {
        LM_ERR("NATS publish to '%s' failed: %s\n", subject, natsStatus_GetText(s));
        if (nats_stats) nats_stats->failed++;
        return -1;
    }
    if (nats_stats) nats_stats->published++;
    return 0;
}

/**
 * nats_js_publish_async() -- Publish a message via JetStream (async).
 *
 * Sends a message to the given subject using the process-local JetStream
 * context for async publish (fire-and-forget with background ack).
 * Falls back to core NATS publish if the JetStream context is not set.
 *
 * @param subject  Null-terminated NATS subject string.
 * @param data     Message payload bytes.
 * @param len      Length of the payload in bytes.
 * @return         0 on success, -1 on error.
 */
int nats_js_publish_async(const char *subject, const void *data, int len)
{
    if (!_js) return nats_publish(subject, data, len);

    natsStatus s = js_PublishAsync(_js, subject, data, len, NULL);
    if (s != NATS_OK) {
        LM_ERR("JetStream async publish to '%s' failed: %s\n",
               subject, natsStatus_GetText(s));
        if (nats_stats) nats_stats->failed++;
        return -1;
    }
    if (nats_stats) nats_stats->published++;
    return 0;
}
