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
 * one slot fits comfortably in a page-aligned ~18 KB region; a ring of
 * 128 slots is therefore about 2.3 MB per bound handle.
 *
 * Headers are carried by value in a compact length-prefixed byte stream
 * (see nats_consumer_proc.c for the serializer); overflow drops the
 * tail headers and sets the headers_truncated flag so the worker can
 * log / stat the case.
 */
#define NATS_RING_SUBJECT_MAX   256
#define NATS_RING_PAYLOAD_MAX  16384
#define NATS_RING_HEADERS_MAX   1024

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

	/*
	 * NATS message headers serialized in a compact stream:
	 *   [u16 count]
	 *   repeated:
	 *     [u16 key_len][key bytes][u16 val_len][val bytes]
	 * Keys and values are raw bytes (no NUL); lookups by the
	 * $nats_hdr(name) pvar run a lazy scan.  Sizes are host-order --
	 * the ring lives in SHM shared by forked children of the same
	 * process, so no endian conversion is needed.
	 *
	 * `headers_truncated` is set when at least one header could not be
	 * appended because the serialized length would have exceeded
	 * NATS_RING_HEADERS_MAX.  The surviving prefix is still valid and
	 * the worker's getter must treat a miss on a truncated-tail header
	 * as a benign "not found".
	 */
	uint16_t headers_len;
	uint8_t  headers_truncated;
	uint8_t  _hdr_pad;
	char     headers[NATS_RING_HEADERS_MAX];
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
 *
 * `headers` must point at a pre-serialized header stream (see the
 * format note on `headers[]` above) of length `headers_len`, or be
 * NULL / 0 for no headers.  `headers_truncated` (0 or 1) is stored
 * verbatim in the slot; it lets the caller propagate a "we dropped
 * tail headers" signal it already detected while serializing.  The
 * ring itself does NOT parse the stream -- it is copied byte-for-byte.
 * Passing headers_len > NATS_RING_HEADERS_MAX returns -4.
 */
int nats_ring_push(nats_ring_t *r,
                   const char *subject, uint32_t subject_len,
                   const char *data,    uint32_t data_len,
                   uint64_t stream_seq, uint64_t consumer_seq,
                   uint64_t delivered,  uint64_t pending,
                   int64_t  timestamp_ns,
                   uint64_t ack_token,
                   const char *reply_to, uint32_t reply_to_len,
                   const char *headers,  uint16_t headers_len,
                   uint8_t headers_truncated);

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
