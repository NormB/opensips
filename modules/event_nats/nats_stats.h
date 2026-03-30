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

#ifndef _NATS_STATS_H_
#define _NATS_STATS_H_

#include "../../mi/mi.h"
#include "../../statistics.h"

/* Statistics counters — stored in shared memory, accessed from
 * multiple processes and the nats.c internal callback thread.
 * Use NATS_STAT_INC/NATS_STAT_READ for atomic access. */
typedef struct _nats_stats {
    unsigned long published;        /* total published */
    unsigned long evi_published;    /* from subscribe_event() */
    unsigned long script_published; /* from nats_publish() */
    unsigned long failed;           /* failed publishes */
    unsigned long reconnects;       /* reconnection count */
    unsigned long js_ack_ok;        /* JetStream acks received */
    unsigned long js_ack_failed;    /* JetStream acks failed */
} nats_stats_t;

/* Global stats pointer (shared memory) */
extern nats_stats_t *nats_stats;

/* Atomic increment — safe across processes and threads */
#define NATS_STAT_INC(field) \
    __atomic_fetch_add(&nats_stats->field, 1, __ATOMIC_RELAXED)

/* Atomic read — safe across processes and threads */
#define NATS_STAT_READ(field) \
    __atomic_load_n(&nats_stats->field, __ATOMIC_RELAXED)

/* Initialize stats in shared memory */
int nats_stats_init(void);

/* Destroy stats */
void nats_stats_destroy(void);

/* MI command handlers */
mi_response_t *mi_nats_status(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_nats_stats(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_nats_reconnect(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif /* _NATS_STATS_H_ */
