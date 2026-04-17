/*
 * Copyright (C) 2026 OpenSIPS Solutions
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
 * nats_ack_ipc.h -- worker -> consumer-process ack queue.
 *
 * This is a stub in Phase 3.  Only the allocation/teardown scaffold is
 * wired in the module lifecycle so Phase 4 can turn it into the real
 * MPSC queue (many SIP worker producers, the single consumer process
 * consumer) without restructuring mod_init / mod_destroy.
 *
 * Phase 4 will:
 *   - record a per-message `ack_token` when the consumer process
 *     publishes to a ring;
 *   - expose a `nats_ack(token, action)` script function that enqueues
 *     an ack request into this queue;
 *   - have the consumer process drain the queue on every iteration and
 *     translate tokens back to natsMsg refs for natsMsg_Ack / Nak /
 *     Term / InProgress.
 *
 * Phase 5+ will extend the action vocabulary to include AckAll,
 * Nak with redelivery hints, and priority-tier acks.
 */

#ifndef NATS_ACK_IPC_H
#define NATS_ACK_IPC_H

#include <stdint.h>

/* Tuning -- Phase 3 placeholder.  The real queue depth is chosen in
 * Phase 4 after load-testing, and will probably be per-handle rather
 * than module-global. */
#define NATS_ACK_IPC_QUEUE_DEPTH 4096

/* An in-flight ack request.  Phase 3: fields reserved, not used.
 * The queue holds slots by value so workers never malloc on the hot
 * path. */
typedef enum {
	NATS_ACK_ACTION_NOOP = 0,       /* ignored */
	NATS_ACK_ACTION_ACK,            /* natsMsg_Ack */
	NATS_ACK_ACTION_NAK,            /* natsMsg_Nak */
	NATS_ACK_ACTION_TERM,           /* natsMsg_Term */
	NATS_ACK_ACTION_IN_PROGRESS,    /* natsMsg_InProgress */
} nats_ack_action_e;

typedef struct nats_ack_ipc_slot {
	uint64_t ack_token;        /* issued by consumer process at push time */
	uint8_t  action;           /* nats_ack_action_e */
	uint8_t  _pad[7];
} nats_ack_ipc_slot_t;

/* Allocate the SHM-backed MPSC queue and its indices.
 * Called from mod_init (pre-fork).
 * Returns 0 on success, -1 on SHM exhaustion. */
int nats_ack_ipc_init(void);

/* Tear down the queue.  Called from mod_destroy before registry
 * teardown (so that anything still holding references is flushed
 * first).  Safe to call even if init failed; no-op on NULL. */
void nats_ack_ipc_destroy(void);

/* Drain whatever is currently queued.
 * Called by the consumer process on every iteration.  In Phase 3 this
 * is a no-op because no producer writes to the queue; Phase 4 will
 * implement the actual dequeue + natsMsg_Ack loop. */
void nats_ack_ipc_drain(void);

/* Advisory snapshots of queue depth and lifetime counters.  Safe from
 * any process -- atomic reads.  Always zero in Phase 3. */
uint64_t nats_ack_ipc_enqueued_total(void);
uint64_t nats_ack_ipc_drained_total(void);
uint32_t nats_ack_ipc_depth(void);

#endif /* NATS_ACK_IPC_H */
