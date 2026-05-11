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
 * nats_rpc_ipc.c -- MPSC publish-request queue between SIP
 * workers and the dedicated nats_consumer process.  Mirror of
 * nats_ack_ipc.c with a different message type (slot_idx instead
 * of an ack token).  See nats_rpc_ipc.h for the rationale.
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

#include "nats_rpc_ipc.h"

typedef struct nats_rpc_ipc_queue {
#ifndef TEST_SHIM
	gen_lock_t *lock;
#endif
	uint32_t  capacity;
	uint32_t  mask;

	_Atomic uint64_t head;
	_Atomic uint64_t tail;
	_Atomic uint64_t enqueued_total;
	_Atomic uint64_t drained_total;
	_Atomic uint64_t dropped_total;

	int       evfd;
	int       _pad;

	nats_rpc_ipc_msg_t slots[];
} nats_rpc_ipc_queue_t;

static nats_rpc_ipc_queue_t *g_q = NULL;

static int rpc_ipc_valid_capacity(uint32_t c)
{
	if (c < 2) return 0;
	return (c & (c - 1)) == 0;
}

int nats_rpc_ipc_init(void)
{
	size_t bytes;
	int    fd;

	if (g_q) {
		LM_WARN("nats_rpc_ipc: already initialised\n");
		return 0;
	}

	if (!rpc_ipc_valid_capacity(NATS_RPC_IPC_QUEUE_DEPTH)) {
		LM_ERR("nats_rpc_ipc: invalid NATS_RPC_IPC_QUEUE_DEPTH %d "
			"(must be pow2 >= 2)\n", NATS_RPC_IPC_QUEUE_DEPTH);
		return -1;
	}

	bytes = sizeof(nats_rpc_ipc_queue_t)
	      + sizeof(nats_rpc_ipc_msg_t) * NATS_RPC_IPC_QUEUE_DEPTH;
	g_q = (nats_rpc_ipc_queue_t *)shm_malloc(bytes);
	if (!g_q) {
		LM_ERR("nats_rpc_ipc: shm alloc failed (%zu bytes)\n", bytes);
		return -1;
	}
	memset(g_q, 0, bytes);

#ifndef TEST_SHIM
	g_q->lock = lock_alloc();
	if (!g_q->lock) {
		LM_ERR("nats_rpc_ipc: lock alloc failed\n");
		shm_free(g_q); g_q = NULL;
		return -1;
	}
	if (!lock_init(g_q->lock)) {
		LM_ERR("nats_rpc_ipc: lock init failed\n");
		lock_dealloc(g_q->lock);
		shm_free(g_q); g_q = NULL;
		return -1;
	}
#endif

	g_q->capacity = NATS_RPC_IPC_QUEUE_DEPTH;
	g_q->mask     = NATS_RPC_IPC_QUEUE_DEPTH - 1;
	atomic_store_explicit(&g_q->head, 0, memory_order_relaxed);
	atomic_store_explicit(&g_q->tail, 0, memory_order_relaxed);

	fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0) {
		LM_ERR("nats_rpc_ipc: eventfd() failed: %d\n", errno);
#ifndef TEST_SHIM
		lock_destroy(g_q->lock);
		lock_dealloc(g_q->lock);
#endif
		shm_free(g_q); g_q = NULL;
		return -1;
	}
	g_q->evfd = fd;

	LM_DBG("nats_rpc_ipc: queue ready (capacity=%u fd=%d)\n",
		g_q->capacity, g_q->evfd);
	return 0;
}

void nats_rpc_ipc_destroy(void)
{
	if (!g_q) return;

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

int nats_rpc_ipc_enqueue(const nats_rpc_ipc_msg_t *msg)
{
	uint64_t h, t;
	int      edge = 0;

	if (!g_q || !msg) return -1;

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
		LM_WARN("nats_rpc_ipc: queue full (capacity=%u) -- dropping "
			"publish for slot %u\n",
			g_q->capacity, (unsigned)msg->slot_idx);
		return -1;
	}

	g_q->slots[h & g_q->mask] = *msg;
	atomic_store_explicit(&g_q->head, h + 1, memory_order_release);
	atomic_fetch_add_explicit(&g_q->enqueued_total, 1, memory_order_relaxed);
	edge = (h == t);

#ifndef TEST_SHIM
	lock_release(g_q->lock);
#endif

	if (edge && g_q->evfd >= 0) {
		uint64_t one = 1;
		ssize_t  w;
		do {
			w = write(g_q->evfd, &one, sizeof(one));
		} while (w < 0 && errno == EINTR);
	}
	return 0;
}

int nats_rpc_ipc_drain(
		void (*cb)(const nats_rpc_ipc_msg_t *msg, void *user),
		void *user)
{
	uint64_t t, h;
	int      n = 0;

	if (!g_q || !cb) return 0;

#ifndef TEST_SHIM
	lock_get(g_q->lock);
#endif
	t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
	h = atomic_load_explicit(&g_q->head, memory_order_acquire);

	while (t < h) {
		nats_rpc_ipc_msg_t snap = g_q->slots[t & g_q->mask];
		t++;
		n++;
		atomic_store_explicit(&g_q->tail, t, memory_order_release);
		atomic_fetch_add_explicit(&g_q->drained_total, 1, memory_order_relaxed);

#ifndef TEST_SHIM
		lock_release(g_q->lock);
#endif
		cb(&snap, user);
#ifndef TEST_SHIM
		lock_get(g_q->lock);
#endif
		/* Re-read head in case producers raced us during cb(). */
		t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
		h = atomic_load_explicit(&g_q->head, memory_order_acquire);
	}

#ifndef TEST_SHIM
	lock_release(g_q->lock);
#endif
	return n;
}

int nats_rpc_ipc_fd(void)
{
	return g_q ? g_q->evfd : -1;
}

uint64_t nats_rpc_ipc_enqueued_total(void)
{
	return g_q ? atomic_load_explicit(&g_q->enqueued_total,
		memory_order_relaxed) : 0;
}

uint64_t nats_rpc_ipc_drained_total(void)
{
	return g_q ? atomic_load_explicit(&g_q->drained_total,
		memory_order_relaxed) : 0;
}

uint32_t nats_rpc_ipc_depth(void)
{
	if (!g_q) return 0;
	{
		uint64_t h = atomic_load_explicit(&g_q->head, memory_order_relaxed);
		uint64_t t = atomic_load_explicit(&g_q->tail, memory_order_relaxed);
		return (uint32_t)(h - t);
	}
}

uint64_t nats_rpc_ipc_dropped_total(void)
{
	return g_q ? atomic_load_explicit(&g_q->dropped_total,
		memory_order_relaxed) : 0;
}
