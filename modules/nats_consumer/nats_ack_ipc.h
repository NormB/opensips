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
 * nats_ack_ipc.h -- worker -> consumer-process ack hop.
 *
 * [P2.1] Acks ride OpenSIPS core IPC.  The ACTION is the ipc_send_rpc
 * function identity -- one handler per JetStream ack verb -- and the
 * 64-bit ack token travels verbatim as the opaque param pointer, so
 * the hot path allocates nothing:
 *
 *   ipc_send_rpc(nats_consumer_proc_no(), nats_ack_ipc_on_ack,
 *                (void *)(uintptr_t)token);
 *
 * The one exception is NAK_DELAY: token + delay_ms cannot fit a
 * pointer, so it carries a small SHM payload the handler frees.
 *
 * The consumer process pumps its IPC fd from the main loop, gated on
 * a live broker connection, so acks wait in the pipe across
 * reconnects exactly like they used to wait in the SHM ring.  A send
 * refused (pipe full / consumer proc not up) surfaces the usual -2 to
 * the script; the message stays un-acked and JetStream redelivers.
 *
 * Handler behavior is unit-locked in tests/test_ack_ipc_actions.c
 * (drives the production handlers against a recording nats_dl table).
 */

#ifndef NATS_ACK_IPC_H
#define NATS_ACK_IPC_H

#include <stdint.h>

/* Ack action vocabulary.  Kept for the worker-side dispatch and the
 * consumer-side apply switch -- the consumer process maps these into
 * calls on natsMsg_Ack / natsMsg_Nak / natsMsg_NakWithDelay /
 * natsMsg_InProgress / natsMsg_Term. */
typedef enum {
	NATS_ACK_ACTION_NOOP = 0,       /* ignored */
	NATS_ACK_ACTION_ACK,            /* natsMsg_Ack */
	NATS_ACK_ACTION_NAK,            /* natsMsg_Nak */
	NATS_ACK_ACTION_NAK_DELAY,      /* natsMsg_NakWithDelay */
	NATS_ACK_ACTION_TERM,           /* natsMsg_Term */
	NATS_ACK_ACTION_IN_PROGRESS,    /* natsMsg_InProgress */
	NATS_ACK_ACTION_ACK_NEXT,       /* natsMsg_AckSync + hint for an
	                                 * immediate pull refill.  nats.c
	                                 * 3.13 does not expose the server's
	                                 * native +NXT reply; we fall back
	                                 * to ack+ring-refill-on-next-tick. */
} nats_ack_action_e;

/* NAK_DELAY payload: SHM-allocated by the worker, freed by the
 * handler (or by the worker again if the send itself fails). */
typedef struct nats_ack_nak_delay {
	uint64_t token;
	uint32_t delay_ms;
} nats_ack_nak_delay_t;

/* The ipc_send_rpc handlers, one per action.  All run in the consumer
 * process; param is the raw token (cast via uintptr_t), except
 * on_nak_delay whose param is a nats_ack_nak_delay_t*. */
void nats_ack_ipc_on_ack(int sender, void *param);
void nats_ack_ipc_on_ack_next(int sender, void *param);
void nats_ack_ipc_on_nak(int sender, void *param);
void nats_ack_ipc_on_nak_delay(int sender, void *param);
void nats_ack_ipc_on_term(int sender, void *param);
void nats_ack_ipc_on_in_progress(int sender, void *param);

/* SHM counters behind the ack_ipc_* MI stats (init/destroy from
 * mod_init / mod_destroy; count_sent from the worker send path;
 * depth = sent - drained, floored at 0). */
int      nats_ack_ipc_stats_init(void);
void     nats_ack_ipc_stats_destroy(void);
void     nats_ack_ipc_count_sent(int ok);
uint64_t nats_ack_ipc_enqueued_total(void);
uint64_t nats_ack_ipc_drained_total(void);
uint64_t nats_ack_ipc_dropped_total(void);
uint32_t nats_ack_ipc_depth(void);

#endif /* NATS_ACK_IPC_H */
