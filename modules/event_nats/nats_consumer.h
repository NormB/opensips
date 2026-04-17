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
 */

/*
 * nats_consumer.h — NATS subscription consumer for event_nats
 *
 * Manages NATS subscriptions that dispatch received messages to OpenSIPS
 * event_route[E_*] handlers via the EVI subsystem.
 *
 * Modparam format:
 *   modparam("event_nats", "subscribe", "subject=<pattern>;event=<name>[;queue=<group>]")
 *
 * Architecture:
 *   - Subscriptions are parsed in mod_init (pre-fork)
 *   - A dedicated consumer process (proc_export) subscribes to NATS post-fork
 *   - Messages are dispatched to SIP workers via ipc_dispatch_rpc()
 *   - Workers call evi_raise_event() to trigger event_route[E_*]
 */

#ifndef NATS_CONSUMER_H
#define NATS_CONSUMER_H

#include "../../str.h"
#include "../../evi/evi.h"
#include <nats/nats.h>

/* Maximum subscriptions */
#define NATS_MAX_SUBSCRIPTIONS 32

/* Single subscription entry */
typedef struct nats_subscription {
	char subject[256];      /* NATS subject pattern */
	char event_name[128];   /* OpenSIPS event name (e.g., "E_NATS_CALL") */
	char queue_group[64];   /* optional queue group (empty = no group) */
	event_id_t event_id;    /* EVI event ID (registered in mod_init) */
	natsSubscription *sub;  /* nats.c subscription handle (set in consumer process) */
} nats_subscription_t;

/* Global subscription list */
extern nats_subscription_t nats_subscriptions[];
extern int nats_subscription_count;

/**
 * Parse a "subscribe" modparam value.
 * Format: "subject=<pattern>;event=<name>[;queue=<group>]"
 *
 * Called from mod_init via USE_FUNC_PARAM.
 *
 * @param val  The modparam string value.
 * @return     0 on success, -1 on parse error.
 */
int nats_consumer_parse_subscribe(modparam_t type, void *val);

/**
 * Register all parsed subscriptions as EVI events.
 * Must be called from mod_init after all subscribe modparams are parsed.
 *
 * @return  0 on success, -1 on error.
 */
int nats_consumer_register_events(void);

/**
 * Main loop for the NATS consumer process.
 * Spawned via proc_export_t. Subscribes to configured subjects and
 * dispatches received messages via IPC to SIP workers.
 *
 * @param rank  OpenSIPS process rank (not used).
 */
void nats_consumer_process(int rank);

#endif /* NATS_CONSUMER_H */
