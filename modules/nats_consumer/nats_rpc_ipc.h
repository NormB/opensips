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
 * delivers the reply back into the slot and wakes the worker via
 * the slot's pre-allocated eventfd).
 *
 * Implementation mirrors nats_ack_ipc:
 *
 *   * Bounded SHM ring sized at init time.
 *   * Single SHM spinlock around head/tail advance and the
 *     slot-byte write.
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

/* Allocate the SHM-backed queue + eventfd + spinlock.  Called
 * from mod_init (pre-fork) so the eventfd is inherited by every
 * child process.  Returns 0 on success, -1 on failure. */
int nats_rpc_ipc_init(void);

/* Tear down.  Called from mod_destroy after worker shutdown so
 * no producer is mid-enqueue.  Safe to call when init failed. */
void nats_rpc_ipc_destroy(void);

/* Worker-side enqueue.  Returns 0 on success, -1 on full queue.
 * Signals the eventfd on the empty -> non-empty edge.  The
 * caller must have already CAS'd the slot from CLAIMED to
 * INFLIGHT before invoking this. */
int nats_rpc_ipc_enqueue(const nats_rpc_ipc_msg_t *msg);

/* Consumer-side drain.  Invokes cb for each dequeued message
 * (in FIFO order).  Returns the number of messages drained.
 * Caller is responsible for draining the eventfd counter
 * separately if it was woken on it. */
int nats_rpc_ipc_drain(
		void (*cb)(const nats_rpc_ipc_msg_t *msg, void *user),
		void *user);

/* Return the eventfd to include in the consumer process's
 * select() / reactor loop.  Ownership stays with the module. */
int nats_rpc_ipc_fd(void);

/* Advisory snapshots. */
uint64_t nats_rpc_ipc_enqueued_total(void);
uint64_t nats_rpc_ipc_drained_total(void);
uint32_t nats_rpc_ipc_depth(void);
uint64_t nats_rpc_ipc_dropped_total(void);

#endif /* NATS_RPC_IPC_H */
