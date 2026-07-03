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
 * Implementation: a bounded SHM ring acting as a
 * multi-producer / single-consumer queue.  Producers are any SIP
 * worker that called nats_ack() / nats_nak() / nats_term() from a
 * script; the single consumer is the dedicated nats_consumer process
 * which turns queued entries into natsMsg_Ack / Nak / Term /
 * InProgress calls on the corresponding natsMsg refs it stashed when
 * it originally pushed the message into the per-handle ring.
 *
 * The queue has its own eventfd so the consumer process can block on
 * "something to ack OR something to fetch" with a single select() /
 * poll() without spinning.  Producers signal the eventfd on the
 * empty -> non-empty edge; the consumer drains everything visible on
 * wake.
 *
 * Concurrency: lock-free bounded MPSC (head/tail-CAS + per-cell
 * generation, via nats_mpsc.c).  Producers reserve a cell with a
 * single CAS and never take a lock or block on the consumer.
 */

#ifndef NATS_ACK_IPC_H
#define NATS_ACK_IPC_H

#include <stdint.h>

/* Tuning -- bounded ring sized for bursts.  Oversubscription is
 * handled by returning -1 from enqueue; the caller decides whether
 * to log+drop or retry.  We log+drop so a mis-scripted worker
 * cannot wedge the module. */
#define NATS_ACK_IPC_QUEUE_DEPTH 4096

/* Ack action vocabulary.  Keep this aligned with the nats.c JetStream
 * client enumerations -- the consumer process maps these into calls
 * on natsMsg_Ack / natsMsg_Nak / natsMsg_NakWithDelay /
 * natsMsg_InProgress / natsMsg_Term. */
typedef enum {
	NATS_ACK_ACTION_NOOP = 0,       /* ignored */
	NATS_ACK_ACTION_ACK,            /* natsMsg_Ack */
	NATS_ACK_ACTION_NAK,            /* natsMsg_Nak */
	NATS_ACK_ACTION_NAK_DELAY,      /* natsMsg_NakWithDelay */
	NATS_ACK_ACTION_TERM,           /* natsMsg_Term */
	NATS_ACK_ACTION_IN_PROGRESS,    /* natsMsg_InProgress */
	NATS_ACK_ACTION_ACK_NEXT,       /* natsMsg_AckSync + hint for an
	                                 * immediate pull refill.  nats.c
	                                 * 3.13 does not expose the server's
	                                 * native +NXT reply; we fall back
	                                 * to ack+ring-refill-on-next-tick. */
} nats_ack_action_e;

/* Public message format used by both producer (worker) and consumer
 * (consumer process).  Fits in one cache line so a producer publishes
 * it with a single memcpy + release-store into its reserved cell. */
typedef struct nats_ack_ipc_msg {
	uint64_t ack_token;        /* handle_idx:16 | slot_idx:32 | gen:16 */
	uint32_t action;           /* nats_ack_action_e -- 32 bits for ABI */
	uint32_t delay_ms;         /* NAK_DELAY only; ignored otherwise */
} nats_ack_ipc_msg_t;

/* Back-compat alias kept for any callers that referenced the old
 * slot-level struct.  Prefer nats_ack_ipc_msg_t. */
typedef struct nats_ack_ipc_slot {
	uint64_t ack_token;
	uint8_t  action;
	uint8_t  _pad[7];
} nats_ack_ipc_slot_t;

/* Typed veneers over the ONE generic queue wrapper (nats_ipcq.c, P1.3).
 * The callback receives a copied-out element, so a long-running
 * natsMsg_Ack/Nak network trip never holds a queue slot against
 * concurrent producers. */
#include "nats_ipcq.h"

static inline int nats_ack_ipc_init(void)
{
	return nats_ipcq_init(&nats_ack_ipcq, NATS_ACK_IPC_QUEUE_DEPTH,
		(uint32_t)sizeof(nats_ack_ipc_msg_t));
}
static inline void nats_ack_ipc_destroy(void)
{ nats_ipcq_destroy(&nats_ack_ipcq); }
static inline int nats_ack_ipc_enqueue(const nats_ack_ipc_msg_t *msg)
{ return nats_ipcq_enqueue(&nats_ack_ipcq, msg); }
static inline int nats_ack_ipc_drain(
		void (*cb)(const void *elem, void *user), void *user)
{
	return nats_ipcq_drain(&nats_ack_ipcq,
		(uint32_t)sizeof(nats_ack_ipc_msg_t), cb, user);
}
static inline int nats_ack_ipc_fd(void)
{ return nats_ipcq_fd(&nats_ack_ipcq); }
static inline uint64_t nats_ack_ipc_enqueued_total(void)
{ return nats_ipcq_enqueued_total(&nats_ack_ipcq); }
static inline uint64_t nats_ack_ipc_drained_total(void)
{ return nats_ipcq_drained_total(&nats_ack_ipcq); }
static inline uint64_t nats_ack_ipc_dropped_total(void)
{ return nats_ipcq_dropped_total(&nats_ack_ipcq); }
static inline uint32_t nats_ack_ipc_depth(void)
{ return nats_ipcq_depth(&nats_ack_ipcq); }

#endif /* NATS_ACK_IPC_H */
