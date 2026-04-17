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
 * nats_ack_ipc.c -- MPSC ack queue between SIP workers and the
 * dedicated nats_consumer process.
 *
 * Structure: a SHM ring of nats_ack_ipc_msg_t slots protected by a
 * single SHM spinlock for push/pop index advance.  On the empty ->
 * non-empty edge the producer writes 1 to an eventfd (inherited by
 * all workers and the consumer process through fork(2)) so the
 * consumer's reactor-level select() wakes up.
 *
 * This is deliberately the simpler locked variant -- Phase 4 scope
 * prioritises correctness over throughput.  Profiling in later
 * phases can justify replacing the lock with head/tail CAS sequences
 * similar to nats_ring.
 */

#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <sys/eventfd.h>

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../dprint.h"
#endif

#include "nats_ack_ipc.h"

/* SHM-resident queue header.  Capacity is fixed at init time; the
 * slots[] flex array follows. */
typedef struct nats_ack_ipc_queue {
#ifndef TEST_SHIM
	gen_lock_t *lock;        /* short critical sections only */
#endif
	uint32_t  capacity;
	uint32_t  mask;          /* capacity - 1 */

	_Atomic uint64_t head;           /* producer cursor */
	_Atomic uint64_t tail;           /* consumer cursor */
	_Atomic uint64_t enqueued_total;
	_Atomic uint64_t drained_total;
	_Atomic uint64_t dropped_total;

	int       evfd;          /* eventfd(2); inherited by fork */
	int       _pad;

	nats_ack_ipc_msg_t slots[];
} nats_ack_ipc_queue_t;

static nats_ack_ipc_queue_t *g_q = NULL;

/* power-of-two check (>= 2). */
static int ack_ipc_valid_capacity(uint32_t c)
{
	if (c < 2)
		return 0;
	return (c & (c - 1)) == 0;
}

int nats_ack_ipc_init(void)
{
	size_t bytes;
	int fd = -1;

	if (g_q) {
		LM_WARN("nats_ack_ipc: already initialized\n");
		return 0;
	}

	if (!ack_ipc_valid_capacity(NATS_ACK_IPC_QUEUE_DEPTH)) {
		LM_ERR("nats_ack_ipc: invalid NATS_ACK_IPC_QUEUE_DEPTH %d "
			"(must be pow2 >= 2)\n", NATS_ACK_IPC_QUEUE_DEPTH);
		return -1;
	}

	bytes = sizeof(nats_ack_ipc_queue_t)
	      + sizeof(nats_ack_ipc_msg_t) * NATS_ACK_IPC_QUEUE_DEPTH;
	g_q = (nats_ack_ipc_queue_t *)shm_malloc(bytes);
	if (!g_q) {
		LM_ERR("nats_ack_ipc: shm alloc failed (%zu bytes)\n", bytes);
		return -1;
	}
	memset(g_q, 0, bytes);

#ifndef TEST_SHIM
	g_q->lock = lock_alloc();
	if (!g_q->lock) {
		LM_ERR("nats_ack_ipc: lock alloc failed\n");
		shm_free(g_q);
		g_q = NULL;
		return -1;
	}
	if (!lock_init(g_q->lock)) {
		LM_ERR("nats_ack_ipc: lock init failed\n");
		lock_dealloc(g_q->lock);
		shm_free(g_q);
		g_q = NULL;
		return -1;
	}
#endif

	g_q->capacity = NATS_ACK_IPC_QUEUE_DEPTH;
	g_q->mask     = NATS_ACK_IPC_QUEUE_DEPTH - 1;
	atomic_store_explicit(&g_q->head, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->tail, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->enqueued_total, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->drained_total,  0, memory_order_relaxed);
	atomic_store_explicit(&g_q->dropped_total,  0, memory_order_relaxed);

	/* Eventfd is created non-blocking and with CLOEXEC, inherited by
	 * every child via fork().  The consumer process reads it; workers
	 * only write to it on the empty -> non-empty edge. */
	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0) {
		LM_ERR("nats_ack_ipc: eventfd() failed: %d\n", errno);
#ifndef TEST_SHIM
		lock_destroy(g_q->lock);
		lock_dealloc(g_q->lock);
#endif
		shm_free(g_q);
		g_q = NULL;
		return -1;
	}
	g_q->evfd = fd;

	LM_DBG("nats_ack_ipc: queue ready (capacity=%u fd=%d)\n",
		g_q->capacity, g_q->evfd);
	return 0;
}

void nats_ack_ipc_destroy(void)
{
	if (!g_q)
		return;

	if (g_q->evfd >= 0) {
		close(g_q->evfd);
		g_q->evfd = -1;
	}
#ifndef TEST_SHIM
	if (g_q->lock) {
		lock_destroy(g_q->lock);
		lock_dealloc(g_q->lock);
		g_q->lock = NULL;
	}
#endif

	shm_free(g_q);
	g_q = NULL;
}

int nats_ack_ipc_enqueue(const nats_ack_ipc_msg_t *msg)
{
	uint64_t h, t;
	int edge = 0;

	if (!g_q || !msg)
		return -1;

#ifndef TEST_SHIM
	lock_get(g_q->lock);
#endif

	h = atomic_load_explicit(&g_q->head, memory_order_relaxed);
	t = atomic_load_explicit(&g_q->tail, memory_order_acquire);

	if (h - t >= g_q->capacity) {
#ifndef TEST_SHIM
		lock_release(g_q->lock);
#endif
		atomic_fetch_add_explicit(&g_q->dropped_total, 1,
			memory_order_relaxed);
		LM_WARN("nats_ack_ipc: queue full (capacity=%u) -- dropping "
			"ack for token=0x%016lx\n",
			g_q->capacity, (unsigned long)msg->ack_token);
		return -1;
	}

	g_q->slots[h & g_q->mask] = *msg;
	atomic_store_explicit(&g_q->head, h + 1, memory_order_release);
	atomic_fetch_add_explicit(&g_q->enqueued_total, 1, memory_order_relaxed);
	edge = (h == t);

#ifndef TEST_SHIM
	lock_release(g_q->lock);
#endif

	/* Only the producer that raised head above a previously-empty
	 * queue signals the eventfd -- this keeps wakes to one per
	 * drain batch instead of one per enqueue. */
	if (edge && g_q->evfd >= 0) {
		uint64_t one = 1;
		ssize_t w;
		do {
			w = write(g_q->evfd, &one, sizeof(one));
		} while (w < 0 && errno == EINTR);
		/* EAGAIN means the eventfd counter is saturated;
		 * the consumer will see the pending data on its next drain
		 * regardless.  Other errors are intentionally swallowed --
		 * we don't want to fail a committed enqueue on a wake glitch. */
	}

	return 0;
}

int nats_ack_ipc_drain(
		void (*cb)(const nats_ack_ipc_msg_t *msg, void *user),
		void *user)
{
	uint64_t t, h;
	int n = 0;

	if (!g_q || !cb)
		return 0;

#ifndef TEST_SHIM
	lock_get(g_q->lock);
#endif

	t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
	h = atomic_load_explicit(&g_q->head, memory_order_acquire);

	while (t < h) {
		nats_ack_ipc_msg_t snap = g_q->slots[t & g_q->mask];
		t++;

#ifndef TEST_SHIM
		/* Release the lock across the callback so a long-running
		 * natsMsg_Ack / Nak network trip does not block new
		 * enqueues.  Advance tail atomically so another drain
		 * attempt (there shouldn't be one, consumer is single) does
		 * not double-dispatch. */
		atomic_store_explicit(&g_q->tail, t, memory_order_release);
		lock_release(g_q->lock);
#else
		atomic_store_explicit(&g_q->tail, t, memory_order_release);
#endif

		cb(&snap, user);
		n++;
		atomic_fetch_add_explicit(&g_q->drained_total, 1,
			memory_order_relaxed);

#ifndef TEST_SHIM
		lock_get(g_q->lock);
		/* reload the head cursor; new messages may have landed. */
		h = atomic_load_explicit(&g_q->head, memory_order_acquire);
#endif
	}

#ifndef TEST_SHIM
	lock_release(g_q->lock);
#endif

	return n;
}

int nats_ack_ipc_fd(void)
{
	return g_q ? g_q->evfd : -1;
}

uint64_t nats_ack_ipc_enqueued_total(void)
{
	if (!g_q)
		return 0;
	return atomic_load_explicit(&g_q->enqueued_total, memory_order_relaxed);
}

uint64_t nats_ack_ipc_drained_total(void)
{
	if (!g_q)
		return 0;
	return atomic_load_explicit(&g_q->drained_total, memory_order_relaxed);
}

uint64_t nats_ack_ipc_dropped_total(void)
{
	if (!g_q)
		return 0;
	return atomic_load_explicit(&g_q->dropped_total, memory_order_relaxed);
}

uint32_t nats_ack_ipc_depth(void)
{
	uint64_t h, t;
	if (!g_q)
		return 0;
	h = atomic_load_explicit(&g_q->head, memory_order_relaxed);
	t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
	if (h <= t)
		return 0;
	return (uint32_t)(h - t);
}
