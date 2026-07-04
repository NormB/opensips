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
 * nats_ipcq.c -- the ONE generic worker->consumer IPC queue wrapper
 * (P1.3: replaces the byte-similar nats_ack_ipc.c and nats_rpc_ipc.c,
 * which differed only in payload struct and log strings).
 *
 * A thin instance layer over the lock-free bounded MPSC queue in
 * nats_mpsc.c: any number of SIP workers enqueue concurrently (no lock
 * -- head/tail-CAS + per-cell generation, the same idiom as nats_ring),
 * and the single consumer process drains.  On the empty -> non-empty
 * edge the producer writes the queue's eventfd (inherited by all
 * workers and the consumer through fork(2)) so the consumer's
 * reactor-level select() wakes up.  All of that lives in nats_mpsc.c;
 * this TU only owns the two named instances and their lifecycles.
 */

#include <stdint.h>

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../dprint.h"
#endif

#include "nats_ipcq.h"
#include "nats_mpsc.h"

/* The module's two queues: ack/nak/term actions, and publish requests. */
nats_ipcq_t nats_ack_ipcq = { NULL, "nats_ack_ipc" };

int nats_ipcq_init(nats_ipcq_t *iq, uint32_t capacity, uint32_t elem_size)
{
	if (iq->q) {
		LM_WARN("%s: already initialized\n", iq->name);
		return 0;
	}
	iq->q = nats_mpsc_create(capacity, elem_size);
	if (!iq->q) {
		LM_ERR("%s: queue create failed\n", iq->name);
		return -1;
	}
	LM_DBG("%s: queue ready (capacity=%u fd=%d)\n",
		iq->name, nats_mpsc_capacity(iq->q), nats_mpsc_evfd(iq->q));
	return 0;
}

void nats_ipcq_destroy(nats_ipcq_t *iq)
{
	if (!iq->q)
		return;
	nats_mpsc_destroy(iq->q);
	iq->q = NULL;
}

int nats_ipcq_enqueue(nats_ipcq_t *iq, const void *elem)
{
	if (!iq->q || !elem)
		return -1;
	if (nats_mpsc_enqueue(iq->q, elem) < 0) {
		LM_WARN("%s: queue full (capacity=%u) -- dropping element\n",
			iq->name, nats_mpsc_capacity(iq->q));
		return -1;
	}
	return 0;
}

int nats_ipcq_drain(nats_ipcq_t *iq, uint32_t elem_size,
		void (*cb)(const void *elem, void *user), void *user)
{
	/* copy each element out before the callback runs, so a long-running
	 * network trip inside the callback never holds a slot against
	 * concurrent producers.  Buffer sized for the largest payload. */
	unsigned char snap[NATS_IPCQ_MAX_ELEM];
	int n = 0;

	if (!iq->q || !cb || elem_size > sizeof(snap))
		return 0;
	while (nats_mpsc_dequeue(iq->q, snap) == 1) {
		cb(snap, user);
		n++;
	}
	return n;
}

int nats_ipcq_fd(const nats_ipcq_t *iq)
{
	return nats_mpsc_evfd(iq->q);
}

uint64_t nats_ipcq_enqueued_total(const nats_ipcq_t *iq)
{ return nats_mpsc_enqueued_total(iq->q); }
uint64_t nats_ipcq_drained_total(const nats_ipcq_t *iq)
{ return nats_mpsc_drained_total(iq->q); }
uint64_t nats_ipcq_dropped_total(const nats_ipcq_t *iq)
{ return nats_mpsc_dropped_total(iq->q); }
uint32_t nats_ipcq_depth(const nats_ipcq_t *iq)
{ return nats_mpsc_depth(iq->q); }
