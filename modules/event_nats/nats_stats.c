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

#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "nats_stats.h"
#include "../../lib/nats/nats_pool.h"

/* module parameters (defined in event_nats.c) */
extern int nats_jetstream;

nats_stats_t *nats_stats = NULL;

int nats_stats_init(void)
{
    nats_stats = shm_malloc(sizeof(nats_stats_t));
    if (!nats_stats) {
        LM_ERR("oom for stats\n");
        return -1;
    }
    memset(nats_stats, 0, sizeof(nats_stats_t));
    return 0;
}

void nats_stats_destroy(void)
{
    if (nats_stats) {
        shm_free(nats_stats);
        nats_stats = NULL;
    }
}

/* MI: nats_status — connection state, server URL */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return 0;

    {
        const char *server_info = nats_pool_get_server_info();
        if (add_mi_string(resp_obj, MI_SSTR("server"),
                server_info, strlen(server_info)) < 0)
            goto error;
    }
    if (nats_pool_is_connected()) {
        if (add_mi_string(resp_obj, MI_SSTR("connected"), MI_SSTR("yes")) < 0)
            goto error;
    } else {
        if (add_mi_string(resp_obj, MI_SSTR("connected"), MI_SSTR("no")) < 0)
            goto error;
    }
    if (nats_jetstream) {
        if (add_mi_string(resp_obj, MI_SSTR("jetstream"), MI_SSTR("enabled")) < 0)
            goto error;
    } else {
        if (add_mi_string(resp_obj, MI_SSTR("jetstream"), MI_SSTR("disabled")) < 0)
            goto error;
    }

    return resp;
error:
    free_mi_response(resp);
    return 0;
}

/* MI: nats_stats — publish counts */
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return 0;

    if (!nats_stats) {
        if (add_mi_string(resp_obj, MI_SSTR("error"), MI_SSTR("stats not initialized")) < 0)
            goto error;
        return resp;
    }

    if (add_mi_number(resp_obj, MI_SSTR("published"), NATS_STAT_READ(published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("evi_published"), NATS_STAT_READ(evi_published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("script_published"), NATS_STAT_READ(script_published)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("failed"), NATS_STAT_READ(failed)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("reconnects"), NATS_STAT_READ(reconnects)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_ok"), NATS_STAT_READ(js_ack_ok)) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_failed"), NATS_STAT_READ(js_ack_failed)) < 0)
        goto error;

    return resp;
error:
    free_mi_response(resp);
    return 0;
}

/* MI: nats_reconnect — placeholder, actual reconnect would need IPC to worker */
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return 0;

    /* Note: actual reconnect requires signaling the worker process.
     * For now, nats.c handles reconnection automatically. */
    if (add_mi_string(resp_obj, MI_SSTR("status"),
            MI_SSTR("NATS auto-reconnect is active")) < 0) {
        free_mi_response(resp);
        return 0;
    }

    return resp;
}
