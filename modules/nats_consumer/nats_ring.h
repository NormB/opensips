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
 * nats_ring.h -- per-handle multi-producer / multi-consumer SHM ring.
 *
 * A fixed-capacity bounded queue used to hand JetStream messages from the
 * single consumer process (producer side) to multiple OpenSIPS SIP worker
 * processes (consumer side).  Producers and consumers live in separate
 * OS processes; the ring and its metadata are therefore allocated from
 * OpenSIPS shared memory and all synchronization is done with plain C11
 * atomics.  An eventfd -- inherited across fork(2) -- is signaled on the
 * empty -> non-empty edge so that a worker blocked on the OpenSIPS async
 * reactor is woken up exactly once per batch.
 *
 * The ring stores messages by value (fixed-size slots); there are no
 * SHM allocations on the hot path.
 */

#ifndef NATS_RING_H
#define NATS_RING_H

#include <stdint.h>
#include <stddef.h>

#include "../../str.h"

/*
 * Hard per-slot limits.  Messages exceeding these are rejected at push
 * time with a distinct error code; the producer is expected to redirect
 * oversized payloads to a side channel (or log + drop).  Sized so that
 * one slot fits comfortably in a page-aligned ~17 KB region; a ring of
 * 128 slots is therefore about 2.2 MB per bound handle.
 */
#define NATS_RING_SUBJECT_MAX   256
#define NATS_RING_PAYLOAD_MAX  16384

/*
 * One fixed-size cell in the ring.  Producer writes every field and then
 * publishes the slot with a release-store to `ready_gen`.  Consumer
 * acquires `ready_gen`, copies the slot, and clears it with
 * `consumed_gen`.
 *
 * The `ready_gen` / `consumed_gen` pair encodes the slot's lifecycle
 * without a separate lock: a slot is readable iff
 *     ready_gen    == current_tail_index
 * and is reusable iff
 *     consumed_gen == current_head_index - capacity
 * Both counters move strictly forward, giving ABA protection.
 */
typedef struct nats_ring_slot {
	/* sequence counters (see file-level comment in nats_ring.c) */
	uint64_t ready_gen;    /* release-stored by producer when slot is
	                        * fully written; the producer sets this to
	                        * the head index that reserved this slot. */
	uint64_t consumed_gen; /* stored by consumer after copying out; set
	                        * to the tail index that claimed the slot. */

	/* payload (inline; fixed max) */
	uint32_t subject_len;
	uint32_t data_len;
	char     subject[NATS_RING_SUBJECT_MAX];
	char     data[NATS_RING_PAYLOAD_MAX];

	/* broker metadata */
	uint64_t stream_seq;
	uint64_t consumer_seq;
	uint64_t delivered;
	uint64_t pending;
	int64_t  timestamp_ns;
	uint64_t ack_token;     /* opaque handle assigned by producer */

	/* reply-to */
	uint8_t  has_reply;
	uint32_t reply_to_len;
	char     reply_to[NATS_RING_SUBJECT_MAX];
} nats_ring_slot_t;

/* Opaque -- laid out in nats_ring.c. */
typedef struct nats_ring nats_ring_t;

/*
 * Allocate a ring in SHM with `capacity` slots.  `capacity` must be a
 * power of two and at least 2; other values are rejected.
 *
 * The eventfd is created with EFD_NONBLOCK | EFD_CLOEXEC and stored in
 * the ring struct; fork(2)'d child processes inherit it automatically.
 *
 * @return  pointer to the new ring, or NULL on invalid capacity or
 *          allocation / eventfd failure.
 */
nats_ring_t *nats_ring_create(uint32_t capacity);

/*
 * Tear down a ring.  Closes the eventfd and frees the SHM block.
 *
 * The ring is destroyed unconditionally -- any slots still in-flight are
 * discarded.  Callers that need a graceful drain must do so before
 * calling this function; the producer/consumer processes must have
 * stopped using `r` before destroy, otherwise behavior is undefined.
 */
void nats_ring_destroy(nats_ring_t *r);

/*
 * Producer: copy a message into the next free slot.
 *
 * Return codes:
 *     0   success (message committed; eventfd possibly signaled).
 *    -1   ring full -- caller should back off and retry.
 *    -2   `data_len`    exceeds NATS_RING_PAYLOAD_MAX.
 *    -3   `subject_len` exceeds NATS_RING_SUBJECT_MAX, or reply_to_len
 *         exceeds NATS_RING_SUBJECT_MAX.
 *
 * On the empty -> non-empty edge, a single uint64_t 1 is written to the
 * eventfd so that one waiter wakes up.  The ring does NOT write the
 * eventfd on every push; the waiter is expected to drain everything
 * available after a wake.
 *
 * `reply_to` may be NULL (and `reply_to_len` 0) for messages with no
 * reply subject; `has_reply` is set accordingly inside the slot.
 */
int nats_ring_push(nats_ring_t *r,
                   const char *subject, uint32_t subject_len,
                   const char *data,    uint32_t data_len,
                   uint64_t stream_seq, uint64_t consumer_seq,
                   uint64_t delivered,  uint64_t pending,
                   int64_t  timestamp_ns,
                   uint64_t ack_token,
                   const char *reply_to, uint32_t reply_to_len);

/*
 * Consumer: claim the oldest ready slot and copy it into `*out`.
 *
 * @return  0 on success, -1 if the ring is currently empty (including
 *          the transient case where the producer reserved a slot but
 *          has not yet released it).
 *
 * This function does NOT read() the eventfd.  A worker that blocked on
 * the eventfd must drain the 8-byte counter itself after wake-up to
 * rearm the reactor.
 */
int nats_ring_pop(nats_ring_t *r, nats_ring_slot_t *out);

/*
 * Return the read-only eventfd.  The fd becomes readable when the ring
 * transitions from empty to non-empty.  Ownership stays with the ring;
 * callers must NOT close(2) it.
 */
int nats_ring_eventfd(const nats_ring_t *r);

/*
 * Advisory snapshots.  These use relaxed atomic loads and may race with
 * concurrent producers / consumers -- the returned value is a hint, not
 * a guarantee.  Do not use them for control-flow decisions that require
 * strict correctness.
 */
uint32_t nats_ring_depth(const nats_ring_t *r);
uint32_t nats_ring_capacity(const nats_ring_t *r);

#endif /* NATS_RING_H */
