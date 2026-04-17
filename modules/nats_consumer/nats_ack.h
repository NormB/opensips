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
 * nats_ack.h -- script-callable ack / nak / term / in_progress.
 *
 * Each of these enqueues an IPC message to the consumer process which
 * translates it into the corresponding natsMsg_* call on the stored
 * natsMsg ref.  They all consult the per-worker current-message state
 * established by w_nats_fetch* and clear it on success so the same
 * message cannot be double-acked by accident.
 */

#ifndef NATS_ACK_H
#define NATS_ACK_H

#include <stdint.h>

/* Forward-declare sip_msg to avoid pulling in the full parser header
 * from callers that only need the token helpers (e.g. unit tests). */
struct sip_msg;

/* Common result codes (returned to the script):
 *   1  success (ack enqueued)
 *  -1  no current message / state missing
 *  -2  IPC queue full / init failure (caller may retry) */

int w_nats_ack  (struct sip_msg *msg);
int w_nats_nak  (struct sip_msg *msg);
int w_nats_nak_delay(struct sip_msg *msg, int *delay_ms);
int w_nats_term (struct sip_msg *msg);
int w_nats_in_progress(struct sip_msg *msg);

/* Phase 5 additions.
 *
 * nats_ack_next(): acknowledge the current message and hint the
 *   consumer process to refill the ring as soon as possible.  nats.c
 *   3.13 does not expose the native "+NXT" ack-and-pull mechanism on
 *   natsMsg_Ack; the consumer process therefore runs an immediate
 *   pull_one_batch() right after the ack completes for that
 *   subscription (documented fallback).  Semantically equivalent to
 *   nats_ack() followed by a zero-budget nats_fetch() on the same id.
 *
 * nats_ack_progress(): same as nats_in_progress() but exported under
 *   the canonical Phase 5 name.  nats_in_progress remains as an alias
 *   to preserve Phase 4 scripts. */
int w_nats_ack_next    (struct sip_msg *msg);
int w_nats_ack_progress(struct sip_msg *msg);

/* Pack / unpack ack-token helpers.  Exported for the consumer process
 * which decodes tokens back to (handle_idx, slot_idx, generation). */

static inline uint64_t nats_ack_token_pack(uint16_t handle_idx,
                                           uint32_t slot_idx,
                                           uint16_t generation)
{
	return ((uint64_t)handle_idx     << 48)
	     | (((uint64_t)slot_idx & 0xFFFFFFFFu) << 16)
	     |  (uint64_t)generation;
}

static inline uint16_t nats_ack_token_handle(uint64_t tok)
{
	return (uint16_t)((tok >> 48) & 0xFFFFu);
}

static inline uint32_t nats_ack_token_slot(uint64_t tok)
{
	return (uint32_t)((tok >> 16) & 0xFFFFFFFFu);
}

static inline uint16_t nats_ack_token_generation(uint64_t tok)
{
	return (uint16_t)(tok & 0xFFFFu);
}

#endif /* NATS_ACK_H */
