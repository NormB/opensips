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
 * nats_rpc_slot.h -- per-call SHM slot table for the
 * consumer-process-routed async nats_request transport.
 *
 * Why SHM
 *   An earlier per-worker subscription transport segfaulted
 *   because libnats's async-callback subscription thread is
 *   incompatible with the SIP UDP worker context.  This design
 *   moves the subscription to the consumer process (the only
 *   context that already runs libnats safely) and hands off
 *   in-flight state between worker and consumer via SHM.
 *
 * Wake mechanism (worker-private timerfd poll)
 *   OpenSIPS's reactor cannot register fork-inherited eventfds
 *   (see commit 8eae39a5b1).  Instead, each async call creates
 *   a fresh worker-private timerfd that fires every
 *   NATS_RPC_ASYNC_POLL_MS milliseconds; the resume function
 *   reads the slot's atomic state on each tick.  When the
 *   consumer writes the reply into the slot and transitions
 *   state to DELIVERED, the worker's next poll pick-up returns
 *   the reply.  Latency floor is the poll interval; CPU floor
 *   is one timerfd tick per in-flight call.
 *
 * State machine
 *
 *     FREE  -- slot is idle, may be claimed by a worker
 *     CLAIMED -- worker has CAS'd the slot, is filling out_*
 *     INFLIGHT -- worker has IPC'd to consumer, awaiting reply
 *     DELIVERED -- consumer has copied reply, signaled eventfd
 *     ABANDONED -- worker resume timed out; consumer must drop
 *                  any late reply landing on this slot_idx
 *
 *   FREE ->CLAIMED is a CAS by the worker; every other transition
 *   is done with the slot owned exclusively by either the worker
 *   or the consumer.  No mutex is needed because each role only
 *   reads the other's fields after observing the state
 *   transition that publishes them (acquire/release pairing).
 */

#ifndef NATS_RPC_SLOT_H
#define NATS_RPC_SLOT_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#include "nats_ring.h"   /* NATS_RING_*_MAX caps */

/*
 * Hard ceiling on simultaneous in-flight async nats_request calls
 * across ALL workers in this OpenSIPS instance.  Each slot consumes
 * one eventfd at mod_init.  Default 1024 fits comfortably under
 * typical RLIMIT_NOFILE (1024 soft / 4096 hard on most distros).
 * Raise via the modparam if you have headroom and need higher
 * concurrency.
 */
#ifndef NATS_RPC_SLOT_COUNT
#define NATS_RPC_SLOT_COUNT 64
#endif

/* Slot states.  Encoded as plain ints + atomic accesses so we can
 * CAS without an external mutex. */
enum {
	NATS_RPC_SLOT_FREE      = 0,
	NATS_RPC_SLOT_CLAIMED   = 1,
	NATS_RPC_SLOT_INFLIGHT  = 2,
	NATS_RPC_SLOT_DELIVERED = 3,
	NATS_RPC_SLOT_ABANDONED = 4,
};

/*
 * Per-slot SHM record.  Sized large enough to carry the outbound
 * publish payload AND the reply payload by value -- no pointer
 * chasing on either side, and no SHM allocation on the hot path.
 *
 * Memory ordering:
 *   * worker writes out_* fields, then transitions CLAIMED -> INFLIGHT
 *     with release ordering on `state`.  Consumer observes INFLIGHT
 *     with acquire and reads out_*.
 *   * consumer writes reply_* fields, then transitions INFLIGHT ->
 *     DELIVERED with release.  Worker observes DELIVERED with
 *     acquire and reads reply_*.
 *   * timed-out worker transitions INFLIGHT -> ABANDONED with release.
 *     A late reply from consumer that observes ABANDONED drops the
 *     payload without writing it; consumer never transitions
 *     ABANDONED -> DELIVERED.
 */
typedef struct nats_rpc_slot {
	_Atomic int state;          /* NATS_RPC_SLOT_* */

	/* Identifier echoed in the reply subject suffix so the
	 * consumer's libnats callback can look up the slot without
	 * a hash table.  Slot index in g_slots[]. */
	uint32_t slot_idx;

	/* Correlation id (UUIDv7 string, NUL-terminated).  Stashed
	 * here so the consumer process can include it in any logs
	 * without having to read it back from the worker. */
	char     corr_id[40];
	uint32_t corr_id_len;

	/* Outbound publish data (worker -> consumer).  Reused for any
	 * NATS subject -- not just the inbox. */
	char     out_subject[NATS_RING_SUBJECT_MAX];
	uint32_t out_subject_len;
	char     out_data[NATS_RING_PAYLOAD_MAX];
	uint32_t out_data_len;
	char     out_headers[NATS_RING_HEADERS_MAX];
	uint16_t out_headers_len;

	/* Reply data (consumer -> worker).  Populated only when state
	 * transitions to DELIVERED. */
	char     reply_subject[NATS_RING_SUBJECT_MAX];
	uint32_t reply_subject_len;
	char     reply_data[NATS_RING_PAYLOAD_MAX];
	uint32_t reply_data_len;
	char     reply_headers[NATS_RING_HEADERS_MAX];
	uint16_t reply_headers_len;
	uint8_t  reply_headers_truncated;
	char     reply_to[NATS_RING_SUBJECT_MAX];
	uint32_t reply_to_len;
	uint8_t  reply_has_reply_to;

	/* Snapshot of the pool reconnect-epoch at claim time.  The
	 * worker resume compares against the current value to surface
	 * -2 (connection lost) if a reconnect intervened. */
	uint32_t epoch_at_start;

	/* Per-claim generation, bumped on every FREE -> CLAIMED
	 * transition.  Echoed in the reply-inbox subject (see
	 * nats_rpc_subject.h) and revalidated by on_inbox_reply: a late
	 * reply whose generation no longer matches the slot's current
	 * claim is dropped instead of being delivered to whatever request
	 * has since re-claimed the slot.  Atomic because the consumer's
	 * libnats reply thread reads it while a worker may be claiming the
	 * slot for a new request. */
	_Atomic uint32_t generation;
} nats_rpc_slot_t;

/*
 * Module-init / module-destroy hooks.  Both are called from
 * nats_consumer.c::mod_init / mod_destroy.  init() allocates the
 * SHM array AND the eventfd pool (in main, pre-fork) so every
 * child inherits the fds.  destroy() closes the fds and frees the
 * SHM.  Returns 0 on success, -1 on failure (SHM exhausted,
 * eventfd_create failure, fd-limit hit).
 */
int  nats_rpc_slot_init(void);
void nats_rpc_slot_destroy(void);

/*
 * Claim a free slot.  Worker calls this from w_nats_request_async
 * after sanity-checking inputs.  Returns the slot pointer on
 * success, NULL if all slots are in use (the caller surfaces -5
 * to the script).  The returned slot is in state CLAIMED; the
 * caller fills out_* fields and then transitions to INFLIGHT via
 * nats_rpc_slot_publish().
 */
nats_rpc_slot_t *nats_rpc_slot_claim(void);

/*
 * Transition CLAIMED -> INFLIGHT.  Publishes the slot to the
 * consumer's view.  Returns 0 on success; -1 if the slot was not
 * in CLAIMED state (programmer error). */
int nats_rpc_slot_publish(nats_rpc_slot_t *s);

/*
 * Worker resume: transition INFLIGHT -> ABANDONED if the slot
 * hasn't been DELIVERED yet.  Returns the observed state.
 * Idempotent on ABANDONED. */
int nats_rpc_slot_abandon(nats_rpc_slot_t *s);

/*
 * Worker resume / cleanup: transition any state -> FREE.  The
 * slot becomes available for the next claimer.  Must be called
 * exactly once per claim; failing to free a slot leaks it until
 * mod_destroy.
 */
void nats_rpc_slot_free(nats_rpc_slot_t *s);

/*
 * Lookup by slot_idx.  Used by the consumer process's libnats
 * callback to find the slot from a reply-subject suffix.  Returns
 * NULL if the index is out of range OR the slot is currently FREE
 * (defensive against a late reply arriving after free). */
nats_rpc_slot_t *nats_rpc_slot_lookup(uint32_t slot_idx);

/*
 * Is an outbound IPC publish entry tagged with @gen still the current
 * claim of slot @s?  True only when the slot is INFLIGHT *and* its
 * generation matches @gen.
 *
 * The worker->consumer IPC entry carries (slot_idx, generation).  A
 * generation mismatch means the slot was freed and re-claimed since the
 * entry was enqueued -- e.g. the original worker timed out (abandon +
 * free) and a new request reused the slot.  Such a stale entry must be
 * skipped: publishing it would send the *new* claim's request a second
 * time (the new claim is also INFLIGHT, so a state-only check cannot tell
 * the two apart).  Used by publish_cb on the IPC drain path.
 */
static inline int nats_rpc_slot_entry_is_current(const nats_rpc_slot_t *s,
		uint32_t gen)
{
	if (!s)
		return 0;
	if (atomic_load_explicit(&s->state, memory_order_acquire)
			!= NATS_RPC_SLOT_INFLIGHT)
		return 0;
	if (atomic_load_explicit(&s->generation, memory_order_relaxed) != gen)
		return 0;
	return 1;
}

/* Advisory snapshots (atomic load of state counter; no lock). */
uint32_t nats_rpc_slot_inflight_count(void);
uint32_t nats_rpc_slot_total_count(void);

#endif /* NATS_RPC_SLOT_H */
