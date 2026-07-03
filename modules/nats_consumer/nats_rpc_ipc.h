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
 * nats_rpc_ipc.h -- worker -> consumer-process publish queue for
 * the consumer-process-routed async nats_request transport.
 *
 * Producers are any SIP worker that called
 * async(nats_request(...)).  The single consumer is the dedicated
 * nats_consumer process which receives the slot_idx, reads the
 * outbound publish data out of the SHM slot, and calls
 * natsConnection_PublishMsg with reply-to set to the consumer's
 * persistent inbox subject (the libnats-callback path then
 * delivers the reply back into the slot; the worker picks it up
 * on its next private-timerfd poll).
 *
 * Implementation mirrors nats_ack_ipc:
 *
 *   * Bounded SHM ring sized at init time.
 *   * Lock-free bounded MPSC (nats_mpsc.c): CAS head reservation +
 *     per-cell generation, no lock.
 *   * eventfd inherited by all children at fork() so the
 *     consumer process's reactor wakes on the empty -> non-empty
 *     edge.
 *
 * The payload of each queue entry is just the SHM-slot index --
 * everything else (subject, payload, headers, correlation id,
 * timeout, etc.) is already in the slot.  Producers transition
 * the slot from CLAIMED to INFLIGHT via nats_rpc_slot_publish()
 * BEFORE enqueueing here.
 */

#ifndef NATS_RPC_IPC_H
#define NATS_RPC_IPC_H

#include <stdint.h>

/* Tuning.  Sized for bursts when many SIP workers issue async
 * RPCs simultaneously.  Same default as the ack IPC -- if the
 * queue saturates the producer sees a -1 return and surfaces -5
 * (capacity exhausted) to the script. */
#define NATS_RPC_IPC_QUEUE_DEPTH 4096

/*
 * On-wire message format.  Carries the slot index plus the slot's
 * per-claim generation at enqueue time.  The consumer's publish_cb
 * revalidates the generation against the slot's current claim before
 * publishing: if the worker timed out and the slot was re-claimed by a
 * different request, the stale entry's generation no longer matches and
 * it is skipped, preventing a double-publish of the new claim.
 */
typedef struct nats_rpc_ipc_msg {
	uint32_t slot_idx;       /* index into the nats_rpc_slot pool */
	uint32_t generation;     /* slot generation captured at enqueue */
} nats_rpc_ipc_msg_t;

/* Typed veneers over the ONE generic queue wrapper (nats_ipcq.c, P1.3). */
#include "nats_ipcq.h"

static inline int nats_rpc_ipc_init(void)
{
	return nats_ipcq_init(&nats_rpc_ipcq, NATS_RPC_IPC_QUEUE_DEPTH,
		(uint32_t)sizeof(nats_rpc_ipc_msg_t));
}
static inline void nats_rpc_ipc_destroy(void)
{ nats_ipcq_destroy(&nats_rpc_ipcq); }
static inline int nats_rpc_ipc_enqueue(const nats_rpc_ipc_msg_t *msg)
{ return nats_ipcq_enqueue(&nats_rpc_ipcq, msg); }
static inline int nats_rpc_ipc_drain(
		void (*cb)(const void *elem, void *user), void *user)
{
	return nats_ipcq_drain(&nats_rpc_ipcq,
		(uint32_t)sizeof(nats_rpc_ipc_msg_t), cb, user);
}
static inline int nats_rpc_ipc_fd(void)
{ return nats_ipcq_fd(&nats_rpc_ipcq); }
static inline uint64_t nats_rpc_ipc_enqueued_total(void)
{ return nats_ipcq_enqueued_total(&nats_rpc_ipcq); }
static inline uint64_t nats_rpc_ipc_drained_total(void)
{ return nats_ipcq_drained_total(&nats_rpc_ipcq); }
static inline uint64_t nats_rpc_ipc_dropped_total(void)
{ return nats_ipcq_dropped_total(&nats_rpc_ipcq); }
static inline uint32_t nats_rpc_ipc_depth(void)
{ return nats_ipcq_depth(&nats_rpc_ipcq); }

#endif /* NATS_RPC_IPC_H */
