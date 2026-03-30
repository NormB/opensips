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

#include <nats/nats.h>
#include "../../dprint.h"
#include "nats_producer.h"
#include "nats_stats.h"

/* Set by child_init via event_nats.c */
static natsConnection *_nc = NULL;
static jsCtx *_js = NULL;

extern nats_stats_t *nats_stats;

void nats_producer_set_connection(natsConnection *nc) { _nc = nc; }
void nats_producer_set_js(jsCtx *js) { _js = js; }

int nats_publish(const char *subject, const void *data, int len)
{
    natsStatus s;

    if (!_nc) {
        LM_ERR("NATS publish to '%s' failed: no connection\n", subject);
        return -1;
    }

    s = natsConnection_Publish(_nc, subject, data, len);
    if (s != NATS_OK) {
        LM_ERR("NATS publish to '%s' failed: %s\n", subject, natsStatus_GetText(s));
        if (nats_stats) NATS_STAT_INC(failed);
        return -1;
    }
    if (nats_stats) NATS_STAT_INC(published);
    return 0;
}

int nats_js_publish_async(const char *subject, const void *data, int len)
{
    natsStatus s;

    if (!_js) return nats_publish(subject, data, len);

    s = js_PublishAsync(_js, subject, data, len, NULL);
    if (s != NATS_OK) {
        LM_ERR("JetStream async publish to '%s' failed: %s\n",
               subject, natsStatus_GetText(s));
        if (nats_stats) NATS_STAT_INC(failed);
        return -1;
    }
    if (nats_stats) NATS_STAT_INC(published);
    return 0;
}
