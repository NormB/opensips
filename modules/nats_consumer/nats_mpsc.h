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
 * nats_mpsc.h -- bounded lock-free multi-producer / single-consumer SHM
 * queue of fixed-size POD elements.
 *
 * This replaces the single gen_lock_t that previously serialized every
 * worker's enqueue into the ack-IPC and async-RPC-IPC queues (TODO #42).
 * It uses the same head/tail-CAS + per-slot generation idiom proven in
 * nats_ring.c -- here in its canonical Vyukov bounded-MPMC form: each cell
 * carries a sequence counter that gates when a producer may write it and
 * when the consumer may read it, so producers reserve slots with a single
 * relaxed CAS on the head cursor and never take a lock or block on the
 * consumer.
 *
 * Concurrency contract:
 *   - Any number of producer processes/threads may call nats_mpsc_enqueue()
 *     concurrently.  An enqueue never blocks on the consumer; it returns -1
 *     (counted as a drop) only when the queue is full.
 *   - Exactly ONE consumer calls nats_mpsc_dequeue() (the dedicated consumer
 *     process).  Calling it from more than one context is undefined.
 *   - The block lives in shared memory (allocated pre-fork in mod_init) so
 *     producer processes and the consumer process share it via fork().
 *
 * Wakeup: the queue owns an eventfd(2) (created at construction, inherited
 * across fork).  A producer writes it only on the empty -> non-empty edge,
 * so a burst of K enqueues issues at most a handful of wakes; the consumer
 * select()s on it and drains everything available.  Over-waking is harmless
 * (the eventfd counter coalesces); the consumer must also poll because a
 * wake may be skipped when it is already actively draining.
 */

#ifndef NATS_MPSC_H
#define NATS_MPSC_H

#include <stdint.h>

typedef struct nats_mpsc nats_mpsc_t;

/*
 * Create a queue holding `capacity` elements of `elem_size` bytes each.
 * `capacity` must be a power of two >= 2.  Allocated from shared memory
 * (or the heap under TEST_SHIM).  An eventfd is created and owned by the
 * queue; nats_mpsc_evfd() returns it (or -1 if eventfd creation failed,
 * in which case the queue still works, just without wake notifications).
 * Returns NULL on bad arguments or allocation failure.
 */
nats_mpsc_t *nats_mpsc_create(uint32_t capacity, uint32_t elem_size);

/* Free the queue and close its eventfd. */
void nats_mpsc_destroy(nats_mpsc_t *q);

/*
 * Producer (multi).  Copy `elem_size` bytes from `elem` into the queue.
 * Returns 0 on success (and writes the eventfd on the empty->non-empty
 * edge), or -1 if the queue is full (incrementing the dropped counter).
 */
int nats_mpsc_enqueue(nats_mpsc_t *q, const void *elem);

/*
 * Consumer (single).  Copy one element (`elem_size` bytes) into `out`.
 * Returns 1 if an element was dequeued, 0 if the queue is empty.
 */
int nats_mpsc_dequeue(nats_mpsc_t *q, void *out);

/* eventfd for select()/poll() wakeup, or -1 if unavailable. */
int nats_mpsc_evfd(const nats_mpsc_t *q);

/* Lifetime + live-depth counters (relaxed reads; safe from any process). */
uint64_t nats_mpsc_enqueued_total(const nats_mpsc_t *q);
uint64_t nats_mpsc_drained_total(const nats_mpsc_t *q);
uint64_t nats_mpsc_dropped_total(const nats_mpsc_t *q);
uint32_t nats_mpsc_depth(const nats_mpsc_t *q);
uint32_t nats_mpsc_capacity(const nats_mpsc_t *q);

#endif /* NATS_MPSC_H */
