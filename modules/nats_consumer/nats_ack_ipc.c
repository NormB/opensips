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
 * nats_ack_ipc.c -- Phase 3 scaffold.
 *
 * Allocates a fixed-size SHM slot array plus head/tail indices so that
 * Phase 4 can convert this into a real multi-producer / single-consumer
 * queue without touching mod_init or mod_destroy call sites.  The Phase
 * 3 code does not push or pop; only the enclosing lifecycle is wired.
 */

#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include "../../mem/shm_mem.h"
#include "../../dprint.h"

#include "nats_ack_ipc.h"

/* SHM-resident queue header.  Phase 3 keeps the fields -- they are read
 * by advisory getters and zeroed at init -- but the push/pop paths are
 * not yet implemented. */
typedef struct nats_ack_ipc_queue {
	_Atomic uint64_t head;           /* next producer write index */
	_Atomic uint64_t tail;           /* next consumer read index */
	_Atomic uint64_t enqueued_total;
	_Atomic uint64_t drained_total;
	uint32_t capacity;
	uint32_t _pad;
	nats_ack_ipc_slot_t slots[];     /* [capacity] */
} nats_ack_ipc_queue_t;

static nats_ack_ipc_queue_t *g_q = NULL;

int nats_ack_ipc_init(void)
{
	size_t bytes;

	if (g_q) {
		LM_WARN("nats_ack_ipc: already initialized\n");
		return 0;
	}

	bytes = sizeof(nats_ack_ipc_queue_t)
	      + sizeof(nats_ack_ipc_slot_t) * NATS_ACK_IPC_QUEUE_DEPTH;
	g_q = (nats_ack_ipc_queue_t *)shm_malloc(bytes);
	if (!g_q) {
		LM_ERR("nats_ack_ipc: shm alloc failed (%zu bytes)\n", bytes);
		return -1;
	}
	memset(g_q, 0, bytes);

	atomic_store_explicit(&g_q->head, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->enqueued_total, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->drained_total,  0, memory_order_relaxed);
	g_q->capacity = NATS_ACK_IPC_QUEUE_DEPTH;

	LM_DBG("nats_ack_ipc: queue ready (capacity=%u)\n", g_q->capacity);
	return 0;
}

void nats_ack_ipc_destroy(void)
{
	if (!g_q)
		return;
	shm_free(g_q);
	g_q = NULL;
}

void nats_ack_ipc_drain(void)
{
	/* Phase 3 stub.  Phase 4 dequeues slots, looks up the natsMsg
	 * stashed under each ack_token, and calls the requested
	 * natsMsg_Ack / Nak / Term / InProgress. */
	if (!g_q)
		return;
}

uint64_t nats_ack_ipc_enqueued_total(void)
{
	if (!g_q)
		return 0;
	return atomic_load_explicit(&g_q->enqueued_total, memory_order_relaxed);
}

uint64_t nats_ack_ipc_drained_total(void)
{
	if (!g_q)
		return 0;
	return atomic_load_explicit(&g_q->drained_total, memory_order_relaxed);
}

uint32_t nats_ack_ipc_depth(void)
{
	uint64_t h, t;
	if (!g_q)
		return 0;
	h = atomic_load_explicit(&g_q->head, memory_order_relaxed);
	t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
	return (uint32_t)(h - t);
}
