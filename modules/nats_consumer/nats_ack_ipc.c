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
 * A thin wrapper over the lock-free bounded MPSC queue in nats_mpsc.c:
 * any number of SIP workers enqueue ack/nak/term actions concurrently
 * (no lock -- head/tail-CAS + per-cell generation, the same idiom as
 * nats_ring), and the single consumer process drains them.  On the
 * empty -> non-empty edge the producer writes the queue's eventfd
 * (inherited by all workers and the consumer through fork(2)) so the
 * consumer's reactor-level select() wakes up.
 */

#include <stdint.h>

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../dprint.h"
#endif

#include "nats_ack_ipc.h"
#include "nats_mpsc.h"

static nats_mpsc_t *g_q = NULL;

int nats_ack_ipc_init(void)
{
	if (g_q) {
		LM_WARN("nats_ack_ipc: already initialized\n");
		return 0;
	}

	g_q = nats_mpsc_create(NATS_ACK_IPC_QUEUE_DEPTH,
		(uint32_t)sizeof(nats_ack_ipc_msg_t));
	if (!g_q) {
		LM_ERR("nats_ack_ipc: queue create failed\n");
		return -1;
	}

	LM_DBG("nats_ack_ipc: queue ready (capacity=%u fd=%d)\n",
		nats_mpsc_capacity(g_q), nats_mpsc_evfd(g_q));
	return 0;
}

void nats_ack_ipc_destroy(void)
{
	if (!g_q)
		return;
	nats_mpsc_destroy(g_q);
	g_q = NULL;
}

int nats_ack_ipc_enqueue(const nats_ack_ipc_msg_t *msg)
{
	if (!g_q || !msg)
		return -1;
	if (nats_mpsc_enqueue(g_q, msg) < 0) {
		LM_WARN("nats_ack_ipc: queue full (capacity=%u) -- dropping "
			"ack for token=0x%016lx\n",
			nats_mpsc_capacity(g_q), (unsigned long)msg->ack_token);
		return -1;
	}
	return 0;
}

int nats_ack_ipc_drain(
		void (*cb)(const nats_ack_ipc_msg_t *msg, void *user),
		void *user)
{
	nats_ack_ipc_msg_t snap;
	int n = 0;

	if (!g_q || !cb)
		return 0;

	/* Each element is copied out of the queue before the callback runs,
	 * so a long-running natsMsg_Ack/Nak network trip never holds a slot
	 * against concurrent producers. */
	while (nats_mpsc_dequeue(g_q, &snap) == 1) {
		cb(&snap, user);
		n++;
	}
	return n;
}

int nats_ack_ipc_fd(void)
{
	return nats_mpsc_evfd(g_q);
}

uint64_t nats_ack_ipc_enqueued_total(void)
{
	return nats_mpsc_enqueued_total(g_q);
}

uint64_t nats_ack_ipc_drained_total(void)
{
	return nats_mpsc_drained_total(g_q);
}

uint64_t nats_ack_ipc_dropped_total(void)
{
	return nats_mpsc_dropped_total(g_q);
}

uint32_t nats_ack_ipc_depth(void)
{
	return nats_mpsc_depth(g_q);
}
