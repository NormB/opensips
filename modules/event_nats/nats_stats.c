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
 * nats_stats.c -- NATS publish statistics and MI command handlers
 *
 * Manages a shared-memory statistics block (nats_stats_t) that tracks
 * publish counts, failure counts, and JetStream ack results across all
 * OpenSIPS worker processes.  Exposes three MI commands:
 *
 *   nats_status    -- returns connection state and server info
 *   nats_stats     -- returns all publish/fail/ack counters
 *   nats_reconnect -- informational (auto-reconnect is always active)
 *
 * The stats block is allocated in shared memory during mod_init() and
 * freed during mod_destroy().
 */

#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../mi/mi.h"
#include "nats_stats.h"
#include "../../lib/nats/nats_pool.h"

/* module parameters (defined in event_nats.c) */
extern int nats_jetstream;

nats_stats_t *nats_stats = NULL;

/**
 * nats_stats_init() -- Allocate and zero-initialize the shared stats block.
 *
 * Called from mod_init() before forking.  The resulting block is in
 * shared memory and accessible from all worker processes.
 *
 * @return  0 on success, -1 on allocation failure.
 */
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

/**
 * nats_stats_destroy() -- Free the shared stats block.
 *
 * Called from mod_destroy() during shutdown.
 */
void nats_stats_destroy(void)
{
    if (nats_stats) {
        shm_free(nats_stats);
        nats_stats = NULL;
    }
}

/**
 * mi_nats_status() -- MI handler for "nats_status".
 *
 * Returns a JSON object with the NATS server URL, connection state
 * (yes/no), and JetStream mode (enabled/disabled).
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

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
    return NULL;
}

/**
 * mi_nats_stats() -- MI handler for "nats_stats".
 *
 * Returns a JSON object with all publish/fail counters: published,
 * evi_published, script_published, failed, reconnects, js_ack_ok,
 * and js_ack_failed.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

    if (!nats_stats) {
        if (add_mi_string(resp_obj, MI_SSTR("error"), MI_SSTR("stats not initialized")) < 0)
            goto error;
        return resp;
    }

    if (add_mi_number(resp_obj, MI_SSTR("published"), nats_stats->published) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("evi_published"), nats_stats->evi_published) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("script_published"), nats_stats->script_published) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("failed"), nats_stats->failed) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("reconnects"), nats_stats->reconnects) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_ok"), nats_stats->js_ack_ok) < 0)
        goto error;
    if (add_mi_number(resp_obj, MI_SSTR("js_ack_failed"), nats_stats->js_ack_failed) < 0)
        goto error;

    return resp;
error:
    free_mi_response(resp);
    return NULL;
}

/**
 * mi_nats_reconnect() -- MI handler for "nats_reconnect".
 *
 * Informational endpoint.  NATS auto-reconnect is always active via
 * nats.c's built-in reconnection logic; this MI command confirms that
 * status.  A true manual reconnect would require IPC to the worker
 * process, which is not implemented.
 *
 * @param params    MI parameters (unused).
 * @param async_hdl MI async handler (unused).
 * @return          MI response object, or NULL on error.
 */
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl)
{
    mi_response_t *resp;
    mi_item_t *resp_obj;

    resp = init_mi_result_object(&resp_obj);
    if (!resp) return NULL;

    /* Note: actual reconnect requires signaling the worker process.
     * For now, nats.c handles reconnection automatically. */
    if (add_mi_string(resp_obj, MI_SSTR("status"),
            MI_SSTR("NATS auto-reconnect is active")) < 0) {
        free_mi_response(resp);
        return NULL;
    }

    return resp;
}
