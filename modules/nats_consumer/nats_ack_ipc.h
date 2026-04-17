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
 * Phase 4 implementation: a bounded SHM ring acting as a
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
 * Concurrency: a single SHM spinlock guards the head/tail advance
 * plus the slot write.  This is fine: acks are rare compared to the
 * data-plane and the critical section is a handful of stores.
 * Phase 5 can replace this with a lock-free variant if profiling shows
 * it matters.
 */

#ifndef NATS_ACK_IPC_H
#define NATS_ACK_IPC_H

#include <stdint.h>

/* Tuning -- bounded ring sized for bursts.  Oversubscription is
 * handled by returning -1 from enqueue; the caller decides whether
 * to log+drop or retry.  Phase 4 choice: log+drop so a mis-scripted
 * worker cannot wedge the module. */
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
 * (consumer process).  Fits in one cache line so the whole slot write
 * is a single store-after-lock sequence. */
typedef struct nats_ack_ipc_msg {
	uint64_t ack_token;        /* handle_idx:16 | slot_idx:32 | gen:16 */
	uint32_t action;           /* nats_ack_action_e -- 32 bits for ABI */
	uint32_t delay_ms;         /* NAK_DELAY only; ignored otherwise */
} nats_ack_ipc_msg_t;

/* Back-compat alias kept for any callers that referenced the Phase 3
 * slot-level struct.  Prefer nats_ack_ipc_msg_t. */
typedef struct nats_ack_ipc_slot {
	uint64_t ack_token;
	uint8_t  action;
	uint8_t  _pad[7];
} nats_ack_ipc_slot_t;

/* Allocate the SHM-backed queue, the eventfd, and the protecting
 * spinlock.  Called from mod_init (pre-fork) so the eventfd is
 * inherited by every child process.
 * Returns 0 on success, -1 on SHM exhaustion / eventfd failure. */
int nats_ack_ipc_init(void);

/* Tear down the queue.  Called from mod_destroy before registry
 * teardown.  Closes the eventfd and frees the SHM backing.  Safe to
 * call even if init failed; no-op on already-destroyed. */
void nats_ack_ipc_destroy(void);

/* Worker-side enqueue.  Returns 0 on success, -1 on full queue.
 * Signals the eventfd on the empty -> non-empty edge. */
int nats_ack_ipc_enqueue(const nats_ack_ipc_msg_t *msg);

/* Consumer-process side: drain everything visible right now,
 * invoking `cb` for each dequeued message.  `user` is passed through
 * to the callback.  Returns the number of messages drained.
 *
 * The callback is responsible for converting the token into a
 * natsMsg* and calling the appropriate natsMsg_Ack / Nak / etc.
 * The drainer does not read the eventfd -- callers that blocked on
 * it must drain the eventfd counter separately. */
int nats_ack_ipc_drain(
		void (*cb)(const nats_ack_ipc_msg_t *msg, void *user),
		void *user);

/* Return the eventfd for the consumer process to include in its
 * select() / reactor loop.  Ownership stays with the module; callers
 * must not close(). */
int nats_ack_ipc_fd(void);

/* Advisory snapshots of queue state.  Atomic, non-blocking, OK from
 * any process.  Zero when the queue is not initialized. */
uint64_t nats_ack_ipc_enqueued_total(void);
uint64_t nats_ack_ipc_drained_total(void);
uint32_t nats_ack_ipc_depth(void);
uint64_t nats_ack_ipc_dropped_total(void);

#endif /* NATS_ACK_IPC_H */
