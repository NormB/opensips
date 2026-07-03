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
 * nats_ipcq.h -- generic named instance of the nats_mpsc worker->consumer
 * queue (see nats_ipcq.c).  The typed veneers live in nats_ack_ipc.h and
 * nats_rpc_ipc.h.
 */

#ifndef NATS_IPCQ_H
#define NATS_IPCQ_H

#include <stdint.h>

struct nats_mpsc;
typedef struct nats_ipcq {
	struct nats_mpsc *q;
	const char       *name;   /* for logs */
} nats_ipcq_t;

/* Largest element any veneer may carry (drain snapshot buffer bound). */
#define NATS_IPCQ_MAX_ELEM 64

int  nats_ipcq_init(nats_ipcq_t *iq, uint32_t capacity, uint32_t elem_size);
void nats_ipcq_destroy(nats_ipcq_t *iq);
int  nats_ipcq_enqueue(nats_ipcq_t *iq, const void *elem);
int  nats_ipcq_drain(nats_ipcq_t *iq, uint32_t elem_size,
		void (*cb)(const void *elem, void *user), void *user);
int  nats_ipcq_fd(const nats_ipcq_t *iq);
uint64_t nats_ipcq_enqueued_total(const nats_ipcq_t *iq);
uint64_t nats_ipcq_drained_total(const nats_ipcq_t *iq);
uint64_t nats_ipcq_dropped_total(const nats_ipcq_t *iq);
uint32_t nats_ipcq_depth(const nats_ipcq_t *iq);

/* the module's two instances (defined in nats_ipcq.c) */
extern nats_ipcq_t nats_ack_ipcq;
extern nats_ipcq_t nats_rpc_ipcq;

#endif /* NATS_IPCQ_H */
