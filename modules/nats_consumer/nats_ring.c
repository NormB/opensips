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
 * nats_ring.c -- per-handle bounded MPMC SHM ring.
 *
 * Algorithm chosen: the "simpler correct variant" from the Phase 2
 * design note.  Two monotonically-increasing 64-bit indices (head and
 * tail) live in the ring header; a power-of-two capacity means the
 * actual slot index is `head & mask`.  Per-slot sequence counters
 * (ready_gen / consumed_gen) decide when a producer may write a slot
 * and when a consumer may read it.
 *
 * Push (producer):
 *   1. Load head, tail.  If head - tail >= capacity the ring is full.
 *   2. Before committing the reservation, wait until the slot's
 *      consumed_gen has caught up to the previous generation
 *      (head - capacity) so we know the slot is no longer in use by a
 *      consumer.  The very first `capacity` pushes skip this test
 *      because the slot has never been used.
 *   3. CAS head from h to h+1.  On failure, retry from (1).
 *   4. Copy payload into slots[h & mask].
 *   5. Release-store slot->ready_gen = h.  This publishes the slot.
 *   6. If the pre-push head equaled tail (i.e. the ring was empty),
 *      write 1 to the eventfd.  This is the empty -> non-empty edge.
 *
 * Pop (consumer):
 *   1. Load tail, head.  If tail >= head the ring is empty.
 *   2. Acquire-load slots[tail & mask].ready_gen.  If != tail the
 *      producer hasn't published yet; cpu_relax and retry the load,
 *      but re-check head first so a concurrent consumer that has
 *      advanced tail doesn't leave us spinning forever.
 *   3. CAS tail from t to t+1.  On failure, retry from (1).
 *   4. Copy slot contents into the caller's out buffer.
 *   5. Store slot->consumed_gen = t.  This releases the slot for the
 *      next producer generation.
 *
 * The eventfd is level-sensitive at the kernel layer (see eventfd(2))
 * but we treat it as edge-triggered: the producer only writes on the
 * empty -> non-empty transition, and the consumer is expected to
 * drain everything available after wake-up.  Spurious wakes are
 * harmless -- a subsequent pop just returns -1 and the worker
 * re-arms the reactor.
 *
 * Memory model: all shared indices use C11 _Atomic with explicit
 * memory_order annotations.  The release/acquire pair on ready_gen
 * synchronizes the payload write with the payload read; head and
 * tail advance with memory_order_acq_rel so the CAS is a full
 * barrier for the reservation itself.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <limits.h>

#include "nats_ring.h"

/*
 * cpu_relax is a hint to the CPU that we are in a spin loop.  On x86
 * this emits PAUSE; on aarch64 it emits YIELD.  Wrapped in a no-op for
 * unknown targets.
 */
#if defined(__x86_64__) || defined(__i386__)
# define nats_ring_cpu_relax() __asm__ __volatile__("pause" ::: "memory")
#elif defined(__aarch64__)
# define nats_ring_cpu_relax() __asm__ __volatile__("yield" ::: "memory")
#else
# define nats_ring_cpu_relax() ((void)0)
#endif

struct nats_ring {
	uint32_t         capacity;   /* power of 2 */
	uint32_t         mask;       /* capacity - 1 */
	int              evfd;       /* eventfd(2) fd; legacy, see wake_seq */
	int              _pad;       /* explicit padding for alignment */

	/* Cross-process wakeup primitive.  The eventfd above is created in
	 * whichever process happens to call nats_ring_create (typically a
	 * worker via the MI bind handler, post-fork) and is therefore not
	 * visible in other processes' fd tables.  We retain the fd field
	 * for source-compat with old call sites but the producer also
	 * bumps wake_seq + FUTEX_WAKEs on the address, which IS visible
	 * across processes because the address lives in SHM.  Workers
	 * snapshot wake_seq before a non-blocking pop and then call
	 * FUTEX_WAIT against the snapshot -- standard linux futex pattern,
	 * sub-millisecond wake-up vs. the historical 5 ms usleep tick. */
	_Atomic uint32_t wake_seq;
	uint32_t         _pad2;

	/* hot counters -- head is written by producers, tail by consumers;
	 * they are placed on separate 64-bit slots so the compiler cannot
	 * coalesce them but we deliberately do not false-share-pad: in our
	 * workload the per-slot sequence counters dominate. */
	_Atomic uint64_t head;
	_Atomic uint64_t tail;

	/* flexible array of fixed-size slots; sized at create time. */
	nats_ring_slot_t slots[];
};

/* power-of-two check (>= 2). */
static int nats_ring_valid_capacity(uint32_t c)
{
	if (c < 2)
		return 0;
	return (c & (c - 1)) == 0;
}

nats_ring_t *nats_ring_create(uint32_t capacity)
{
	nats_ring_t *r;
	size_t bytes;
	int fd;

	if (!nats_ring_valid_capacity(capacity)) {
		LM_ERR("nats_ring: invalid capacity %u (must be pow2 >= 2)\n",
			capacity);
		return NULL;
	}

	bytes = sizeof(*r) + (size_t)capacity * sizeof(nats_ring_slot_t);
	r = (nats_ring_t *)shm_malloc(bytes);
	if (!r) {
		LM_ERR("nats_ring: oom for ring of %u slots (%zu bytes)\n",
			capacity, bytes);
		return NULL;
	}
	memset(r, 0, bytes);

	r->capacity = capacity;
	r->mask     = capacity - 1;
	atomic_init(&r->head, (uint64_t)0);
	atomic_init(&r->tail, (uint64_t)0);

	/* Pre-seed every slot so the first `capacity` pushes don't need
	 * to wait for a prior consumer.  Before the first push, slot i
	 * appears to have been consumed at "generation" i - capacity,
	 * which is the condition the push loop expects. */
	for (uint32_t i = 0; i < capacity; i++) {
		/* UINT64_MAX stands in for "never been touched"; the push
		 * loop has an explicit first-round branch that skips the
		 * wait for head < capacity, so the exact value doesn't
		 * matter as long as it can't collide with a real index. */
		r->slots[i].ready_gen    = UINT64_MAX;
		r->slots[i].consumed_gen = UINT64_MAX;
	}

	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0) {
		LM_ERR("nats_ring: eventfd() failed: %d\n", errno);
		shm_free(r);
		return NULL;
	}
	r->evfd = fd;

	return r;
}

void nats_ring_destroy(nats_ring_t *r)
{
	if (!r)
		return;
	if (r->evfd >= 0) {
		close(r->evfd);
		r->evfd = -1;
	}
	shm_free(r);
}

int nats_ring_push(nats_ring_t *r,
                   const char *subject, uint32_t subject_len,
                   const char *data,    uint32_t data_len,
                   uint64_t stream_seq, uint64_t consumer_seq,
                   uint64_t delivered,  uint64_t pending,
                   int64_t  timestamp_ns,
                   uint64_t ack_token,
                   const char *reply_to, uint32_t reply_to_len,
                   const char *headers,  uint16_t headers_len,
                   uint8_t headers_truncated)
{
	uint64_t h, t;
	nats_ring_slot_t *slot;

	if (!r)
		return -1;
	if (data_len > NATS_RING_PAYLOAD_MAX)
		return -2;
	if (subject_len > NATS_RING_SUBJECT_MAX)
		return -3;
	if (reply_to_len > NATS_RING_SUBJECT_MAX)
		return -3;
	if (headers_len > NATS_RING_HEADERS_MAX)
		return -4;

	for (;;) {
		h = atomic_load_explicit(&r->head, memory_order_relaxed);
		t = atomic_load_explicit(&r->tail, memory_order_acquire);
		if (h - t >= r->capacity)
			return -1;   /* full */

		slot = &r->slots[h & r->mask];

		/*
		 * If this slot has been used before, we must wait for the
		 * previous consumer to have marked it consumed at the prior
		 * generation (h - capacity).  Until then a stale ready_gen
		 * could confuse future pops.  The UINT64_MAX sentinel set in
		 * nats_ring_create() means "never used" and passes this test
		 * trivially for the first `capacity` pushes.
		 */
		if (h >= r->capacity) {
			uint64_t want = h - r->capacity;
			uint64_t got = __atomic_load_n(&slot->consumed_gen,
				__ATOMIC_ACQUIRE);
			if (got != want) {
				/* Consumer is still finishing the previous
				 * generation of this slot.  Yield and retry
				 * the reservation loop -- another producer
				 * might race us past it. */
				nats_ring_cpu_relax();
				continue;
			}
		}

		if (atomic_compare_exchange_weak_explicit(
				&r->head, &h, h + 1,
				memory_order_acq_rel,
				memory_order_relaxed)) {
			break;
		}
		/* CAS lost: another producer took this head; retry. */
	}

	/* `slot` is ours.  Fill it in. */
	slot->subject_len = subject_len;
	if (subject_len)
		memcpy(slot->subject, subject, subject_len);

	slot->data_len = data_len;
	if (data_len)
		memcpy(slot->data, data, data_len);

	slot->stream_seq   = stream_seq;
	slot->consumer_seq = consumer_seq;
	slot->delivered    = delivered;
	slot->pending      = pending;
	slot->timestamp_ns = timestamp_ns;
	slot->ack_token    = ack_token;

	if (reply_to && reply_to_len) {
		slot->has_reply    = 1;
		slot->reply_to_len = reply_to_len;
		memcpy(slot->reply_to, reply_to, reply_to_len);
	} else {
		slot->has_reply    = 0;
		slot->reply_to_len = 0;
	}

	/* Headers: raw byte-for-byte copy of the caller-serialized stream.
	 * The wire format is documented on nats_ring_slot_t.headers[]. */
	slot->headers_len        = headers_len;
	slot->headers_truncated  = headers_truncated ? 1 : 0;
	if (headers && headers_len > 0)
		memcpy(slot->headers, headers, headers_len);

	/* Publish: release-store ready_gen so the pop-side acquire-load
	 * observes the fully-written slot. */
	__atomic_store_n(&slot->ready_gen, h, __ATOMIC_RELEASE);

	/*
	 * Empty -> non-empty edge detection.  At the time we reserved our
	 * slot (CAS committed head = h + 1), head - tail was 0 iff h == t.
	 * Only the producer that raised head from 0 above tail signals
	 * the eventfd; subsequent producers in the same batch skip the
	 * write to avoid the thundering-herd.  Using the pre-push values
	 * of h and t that we loaded is safe: tail can only move up, so
	 * if h == t at reservation time, we are definitely at the edge
	 * for the slot we just published.
	 */
	if (h == t) {
		/* Legacy eventfd path -- kept for source-compat with old
		 * consumers (lib/nats, async fetch reactor).  Workers that
		 * forked before this ring was bound cannot see this fd; they
		 * use the futex path below. */
		uint64_t one = 1;
		ssize_t w;
		do {
			w = write(r->evfd, &one, sizeof(one));
		} while (w < 0 && errno == EINTR);
		/* EAGAIN means the counter is already saturated at U64_MAX-1;
		 * no additional wake is needed because the fd is already
		 * readable.  Any other error is ignored here -- we do not
		 * want to fail a committed push on a wake-up glitch. */

		/* Cross-process wake.  Bump wake_seq under release ordering
		 * so any worker that observed the old value via the FUTEX_WAIT
		 * compare-and-block path sees the published slot when it
		 * retries the pop.  FUTEX_WAKE on INT_MAX wakes every waiter
		 * (typical N <= num workers, so the thundering-herd cost is
		 * bounded).  Like the eventfd, we only signal on the empty
		 * -> non-empty edge to avoid waking on every push. */
		atomic_fetch_add_explicit(&r->wake_seq, 1, memory_order_release);
		syscall(SYS_futex, &r->wake_seq, FUTEX_WAKE, INT_MAX,
			NULL, NULL, 0);
	}

	return 0;
}

int nats_ring_pop(nats_ring_t *r, nats_ring_slot_t *out)
{
	uint64_t t, h, ready;
	nats_ring_slot_t *slot;

	if (!r || !out)
		return -1;

	for (;;) {
		t = atomic_load_explicit(&r->tail, memory_order_relaxed);
		h = atomic_load_explicit(&r->head, memory_order_acquire);
		if (t >= h)
			return -1;   /* empty */

		slot = &r->slots[t & r->mask];
		ready = __atomic_load_n(&slot->ready_gen, __ATOMIC_ACQUIRE);
		if (ready != t) {
			/* Producer reserved but hasn't released yet -- or a
			 * concurrent consumer already advanced tail.  Loop:
			 * the next iteration's head/tail load will tell us
			 * which case we're in. */
			nats_ring_cpu_relax();
			continue;
		}

		if (atomic_compare_exchange_weak_explicit(
				&r->tail, &t, t + 1,
				memory_order_acq_rel,
				memory_order_relaxed)) {
			break;
		}
		/* CAS lost: another consumer took this tail; retry. */
	}

	/* Copy fields into caller's buffer.  We only copy the used prefix
	 * of subject/data/reply_to to avoid touching 17 KB of SHM per
	 * pop. */
	out->ready_gen    = slot->ready_gen;
	out->consumed_gen = slot->consumed_gen;

	out->subject_len = slot->subject_len;
	if (out->subject_len)
		memcpy(out->subject, slot->subject, out->subject_len);

	out->data_len = slot->data_len;
	if (out->data_len)
		memcpy(out->data, slot->data, out->data_len);

	out->stream_seq   = slot->stream_seq;
	out->consumer_seq = slot->consumer_seq;
	out->delivered    = slot->delivered;
	out->pending      = slot->pending;
	out->timestamp_ns = slot->timestamp_ns;
	out->ack_token    = slot->ack_token;

	out->has_reply    = slot->has_reply;
	out->reply_to_len = slot->reply_to_len;
	if (out->reply_to_len)
		memcpy(out->reply_to, slot->reply_to, out->reply_to_len);

	out->headers_len       = slot->headers_len;
	out->headers_truncated = slot->headers_truncated;
	out->_hdr_pad          = 0;
	if (out->headers_len)
		memcpy(out->headers, slot->headers, out->headers_len);

	/* Mark the slot consumed at generation t so the matching
	 * producer (generation t + capacity) may reuse it. */
	__atomic_store_n(&slot->consumed_gen, t, __ATOMIC_RELEASE);

	return 0;
}

int nats_ring_wait(nats_ring_t *r, int timeout_ms)
{
	uint32_t seq;
	uint64_t h, t;
	struct timespec ts;
	long rc;

	if (!r) return -1;
	if (timeout_ms <= 0) return -1;

	/* Sample the wake counter BEFORE checking emptiness; if a producer
	 * fires between our depth-check and the FUTEX_WAIT, the counter
	 * will have advanced and the syscall returns EAGAIN immediately. */
	seq = atomic_load_explicit(&r->wake_seq, memory_order_acquire);
	h = atomic_load_explicit(&r->head, memory_order_acquire);
	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	if (h > t) return 0;   /* not empty, no wait needed */

	ts.tv_sec  = timeout_ms / 1000;
	ts.tv_nsec = (timeout_ms % 1000) * 1000000L;

	rc = syscall(SYS_futex, &r->wake_seq, FUTEX_WAIT, seq, &ts, NULL, 0);
	if (rc == 0) return 0;
	/* EAGAIN means the value already differed -- producer raced us
	 * but the data is in the ring already.  Treat as success. */
	if (errno == EAGAIN) return 0;
	return -1;
}

int nats_ring_eventfd(const nats_ring_t *r)
{
	return r ? r->evfd : -1;
}

uint32_t nats_ring_depth(const nats_ring_t *r)
{
	uint64_t h, t;

	if (!r)
		return 0;
	/* Two relaxed loads; the result is advisory. */
	h = atomic_load_explicit(&r->head, memory_order_relaxed);
	t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	if (h <= t)
		return 0;
	return (uint32_t)(h - t);
}

uint32_t nats_ring_capacity(const nats_ring_t *r)
{
	return r ? r->capacity : 0;
}
