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
 * nats_rpc_ipc.c -- MPSC publish-request queue between SIP workers and
 * the dedicated nats_consumer process.  A thin wrapper over the lock-free
 * bounded MPSC queue in nats_mpsc.c (mirror of nats_ack_ipc.c with a
 * different message type: slot_idx instead of an ack token).  See
 * nats_rpc_ipc.h for the rationale.
 */

#include <stdint.h>

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../dprint.h"
#endif

#include "nats_rpc_ipc.h"
#include "nats_mpsc.h"

static nats_mpsc_t *g_q = NULL;

int nats_rpc_ipc_init(void)
{
	if (g_q) {
		LM_WARN("nats_rpc_ipc: already initialised\n");
		return 0;
	}

	g_q = nats_mpsc_create(NATS_RPC_IPC_QUEUE_DEPTH,
		(uint32_t)sizeof(nats_rpc_ipc_msg_t));
	if (!g_q) {
		LM_ERR("nats_rpc_ipc: queue create failed\n");
		return -1;
	}

	LM_DBG("nats_rpc_ipc: queue ready (capacity=%u fd=%d)\n",
		nats_mpsc_capacity(g_q), nats_mpsc_evfd(g_q));
	return 0;
}

void nats_rpc_ipc_destroy(void)
{
	if (!g_q)
		return;
	nats_mpsc_destroy(g_q);
	g_q = NULL;
}

int nats_rpc_ipc_enqueue(const nats_rpc_ipc_msg_t *msg)
{
	if (!g_q || !msg)
		return -1;
	if (nats_mpsc_enqueue(g_q, msg) < 0) {
		LM_WARN("nats_rpc_ipc: queue full (capacity=%u) -- dropping "
			"publish for slot %u\n",
			nats_mpsc_capacity(g_q), (unsigned)msg->slot_idx);
		return -1;
	}
	return 0;
}

int nats_rpc_ipc_drain(
		void (*cb)(const nats_rpc_ipc_msg_t *msg, void *user),
		void *user)
{
	nats_rpc_ipc_msg_t snap;
	int n = 0;

	if (!g_q || !cb)
		return 0;

	/* Each entry is copied out before the callback runs, so a publish
	 * that blocks briefly on libnats never holds a slot against
	 * concurrent producers. */
	while (nats_mpsc_dequeue(g_q, &snap) == 1) {
		cb(&snap, user);
		n++;
	}
	return n;
}

int nats_rpc_ipc_fd(void)
{
	return nats_mpsc_evfd(g_q);
}

uint64_t nats_rpc_ipc_enqueued_total(void)
{
	return nats_mpsc_enqueued_total(g_q);
}

uint64_t nats_rpc_ipc_drained_total(void)
{
	return nats_mpsc_drained_total(g_q);
}

uint32_t nats_rpc_ipc_depth(void)
{
	return nats_mpsc_depth(g_q);
}

uint64_t nats_rpc_ipc_dropped_total(void)
{
	return nats_mpsc_dropped_total(g_q);
}
