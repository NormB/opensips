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
 * nats_mpsc.c -- bounded lock-free MPSC SHM queue (see nats_mpsc.h).
 *
 * Algorithm: Dmitry Vyukov's bounded MPMC queue, used here in its MPSC
 * specialisation (single consumer => the dequeue side needs no CAS on the
 * tail cursor).  Each cell carries an _Atomic uint64_t sequence number:
 *
 *   cell.seq == pos        => the cell is free and a producer may claim
 *                             position `pos` (CAS head pos -> pos+1, then
 *                             write payload, then release-store seq = pos+1).
 *   cell.seq == pos+1      => the cell holds a published element for the
 *                             consumer at `pos` (read payload, then
 *                             release-store seq = pos+capacity to free it).
 *
 * A producer that finds cell.seq < pos (one full generation behind) sees
 * the queue as full and drops; it never blocks on the consumer.  The
 * release/acquire pair on `seq` orders the payload write before the read.
 *
 * Cells are laid out in a single flex array as [seq(8 bytes)][payload], so
 * the whole queue is one shm_malloc block with no internal pointers (valid
 * across fork at the OpenSIPS-guaranteed shared mapping).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <sys/eventfd.h>

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include "nats_mpsc.h"

#ifdef TEST_SHIM
#define MPSC_ERR(...)   do { } while (0)
#else
#define MPSC_ERR(...)   LM_ERR(__VA_ARGS__)
#endif

struct nats_mpsc {
	uint32_t capacity;
	uint32_t mask;            /* capacity - 1 */
	uint32_t elem_size;
	uint32_t stride;          /* bytes per cell: round_up_8(8 + elem_size) */
	int      evfd;
	int      _pad;

	_Atomic uint64_t head;    /* producer reservation cursor */
	_Atomic uint64_t tail;    /* consumer cursor (single writer) */
	_Atomic uint64_t enqueued_total;
	_Atomic uint64_t drained_total;
	_Atomic uint64_t dropped_total;

	/* capacity cells of `stride` bytes; cell = [ _Atomic u64 seq | payload ] */
	char     cells[];
};

#define MPSC_SEQ_BYTES   ((uint32_t)sizeof(_Atomic uint64_t))

static inline char *mpsc_cell(nats_mpsc_t *q, uint64_t pos)
{
	return q->cells + (size_t)(pos & q->mask) * q->stride;
}

static int mpsc_pow2_ge2(uint32_t c)
{
	return c >= 2 && (c & (c - 1)) == 0;
}

nats_mpsc_t *nats_mpsc_create(uint32_t capacity, uint32_t elem_size)
{
	nats_mpsc_t *q;
	uint32_t stride;
	size_t bytes;
	uint32_t i;

	if (!mpsc_pow2_ge2(capacity) || elem_size == 0) {
		MPSC_ERR("nats_mpsc: bad capacity %u / elem_size %u\n",
			capacity, elem_size);
		return NULL;
	}

	/* round the cell stride up to an 8-byte multiple so every cell's seq
	 * lands 8-byte aligned. */
	stride = (MPSC_SEQ_BYTES + elem_size + 7u) & ~7u;

	bytes = sizeof(nats_mpsc_t) + (size_t)capacity * stride;
	q = (nats_mpsc_t *)shm_malloc(bytes);
	if (!q) {
		MPSC_ERR("nats_mpsc: shm alloc failed (%zu bytes)\n", bytes);
		return NULL;
	}
	memset(q, 0, bytes);

	q->capacity  = capacity;
	q->mask      = capacity - 1;
	q->elem_size = elem_size;
	q->stride    = stride;

	atomic_store_explicit(&q->head, 0, memory_order_relaxed);
	atomic_store_explicit(&q->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&q->enqueued_total, 0, memory_order_relaxed);
	atomic_store_explicit(&q->drained_total,  0, memory_order_relaxed);
	atomic_store_explicit(&q->dropped_total,  0, memory_order_relaxed);

	/* Seed every cell's sequence with its index: cell i is free for the
	 * producer that reserves position i. */
	for (i = 0; i < capacity; i++) {
		_Atomic uint64_t *seqp = (_Atomic uint64_t *)mpsc_cell(q, i);
		atomic_store_explicit(seqp, (uint64_t)i, memory_order_relaxed);
	}

	/* eventfd inherited across fork; created non-blocking + CLOEXEC.  A
	 * NULL/failed eventfd is non-fatal -- the queue still works, callers
	 * just lose the select()-wakeup edge (they can still poll). */
	q->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (q->evfd < 0) {
		MPSC_ERR("nats_mpsc: eventfd() failed: %d\n", errno);
		q->evfd = -1;
	}

	return q;
}

void nats_mpsc_destroy(nats_mpsc_t *q)
{
	if (!q)
		return;
	if (q->evfd >= 0)
		close(q->evfd);
	shm_free(q);
}

int nats_mpsc_enqueue(nats_mpsc_t *q, const void *elem)
{
	uint64_t pos;
	char *cell = NULL;
	_Atomic uint64_t *seqp = NULL;

	if (!q || !elem)
		return -1;

	pos = atomic_load_explicit(&q->head, memory_order_relaxed);
	for (;;) {
		uint64_t seq;
		int64_t  dif;

		cell = mpsc_cell(q, pos);
		seqp = (_Atomic uint64_t *)cell;
		seq  = atomic_load_explicit(seqp, memory_order_acquire);
		dif  = (int64_t)seq - (int64_t)pos;

		if (dif == 0) {
			/* cell is free for `pos`; try to claim it. */
			if (atomic_compare_exchange_weak_explicit(
					&q->head, &pos, pos + 1,
					memory_order_relaxed,
					memory_order_relaxed))
				break;
			/* CAS failed: pos was reloaded with the current head; retry. */
		} else if (dif < 0) {
			/* cell still holds an unconsumed element a full generation
			 * back => the queue is full. */
			atomic_fetch_add_explicit(&q->dropped_total, 1,
				memory_order_relaxed);
			return -1;
		} else {
			/* another producer advanced past this cell; resync. */
			pos = atomic_load_explicit(&q->head, memory_order_relaxed);
		}
	}

	/* `cell` at `pos` is ours.  Write the payload, then publish via the
	 * release-store so the consumer's acquire-load sees a complete element. */
	memcpy(cell + MPSC_SEQ_BYTES, elem, q->elem_size);
	atomic_store_explicit(seqp, pos + 1, memory_order_release);
	atomic_fetch_add_explicit(&q->enqueued_total, 1, memory_order_relaxed);

	/* Wake on the empty -> non-empty edge only: if the consumer's cursor
	 * still points at the cell we just published, the queue was empty
	 * (consumer idle) so it needs a wake.  Over-waking is harmless (the
	 * eventfd counter coalesces); a skipped wake only happens when the
	 * consumer is already draining past us. */
	if (q->evfd >= 0) {
		uint64_t t = atomic_load_explicit(&q->tail, memory_order_acquire);
		if (t == pos) {
			uint64_t one = 1;
			ssize_t w;
			do {
				w = write(q->evfd, &one, sizeof(one));
			} while (w < 0 && errno == EINTR);
			/* EAGAIN (counter saturated) is ignored: the consumer will
			 * observe the pending element on its next drain anyway. */
		}
	}
	return 0;
}

int nats_mpsc_dequeue(nats_mpsc_t *q, void *out)
{
	uint64_t pos, seq;
	int64_t  dif;
	char    *cell;
	_Atomic uint64_t *seqp;

	if (!q || !out)
		return 0;

	pos  = atomic_load_explicit(&q->tail, memory_order_relaxed);
	cell = mpsc_cell(q, pos);
	seqp = (_Atomic uint64_t *)cell;
	seq  = atomic_load_explicit(seqp, memory_order_acquire);
	dif  = (int64_t)seq - (int64_t)(pos + 1);

	if (dif != 0)
		return 0;   /* dif < 0: empty.  dif > 0: impossible (single consumer). */

	/* Copy the payload out BEFORE releasing the cell -- once we bump the
	 * sequence a producer may immediately overwrite the slot. */
	memcpy(out, cell + MPSC_SEQ_BYTES, q->elem_size);

	/* Single consumer: advance the tail cursor with a plain store. */
	atomic_store_explicit(&q->tail, pos + 1, memory_order_relaxed);

	/* Free the cell for the producer of the next generation (pos + capacity). */
	atomic_store_explicit(seqp, pos + q->capacity, memory_order_release);
	atomic_fetch_add_explicit(&q->drained_total, 1, memory_order_relaxed);
	return 1;
}

int nats_mpsc_evfd(const nats_mpsc_t *q)
{
	return q ? q->evfd : -1;
}

uint64_t nats_mpsc_enqueued_total(const nats_mpsc_t *q)
{
	return q ? atomic_load_explicit(&q->enqueued_total, memory_order_relaxed) : 0;
}

uint64_t nats_mpsc_drained_total(const nats_mpsc_t *q)
{
	return q ? atomic_load_explicit(&q->drained_total, memory_order_relaxed) : 0;
}

uint64_t nats_mpsc_dropped_total(const nats_mpsc_t *q)
{
	return q ? atomic_load_explicit(&q->dropped_total, memory_order_relaxed) : 0;
}

uint32_t nats_mpsc_depth(const nats_mpsc_t *q)
{
	uint64_t h, t;
	if (!q)
		return 0;
	h = atomic_load_explicit(&q->head, memory_order_relaxed);
	t = atomic_load_explicit(&q->tail, memory_order_relaxed);
	return h > t ? (uint32_t)(h - t) : 0;
}

uint32_t nats_mpsc_capacity(const nats_mpsc_t *q)
{
	return q ? q->capacity : 0;
}
