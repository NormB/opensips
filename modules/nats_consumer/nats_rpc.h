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
 * nats_rpc.h -- script-callable NATS headers + reply-to + RPC.
 *
 * Phase 6 entry points:
 *
 *   $nats_hdr(Name)           -- pseudo-var; reads a header from the
 *                                current message (populated by
 *                                nats_fetch / nats_fetch_batch +
 *                                nats_batch_select).  Case-insensitive
 *                                lookup, returns NULL on miss.
 *
 *   nats_hdr_set(name, value) -- stage a (name, value) pair onto the
 *                                per-worker outbound header buffer.
 *                                Replaces a staged entry with the same
 *                                name.  Cleared automatically after the
 *                                next outbound publish (nats_reply /
 *                                nats_request), even on publish failure.
 *
 *   nats_reply(payload)       -- publish `payload` on the current
 *                                message's reply subject.  Plain core
 *                                NATS publish (not JetStream); attaches
 *                                any staged headers.  Returns
 *                                -1 no current message,
 *                                -2 no reply-to on the current message,
 *                                -3 NATS connection unavailable,
 *                                -4 publish failed,
 *                                 1 on success.
 *
 *   nats_request(subj, payload, timeout_ms) -- SYNC-ONLY core NATS RPC
 *                                request/reply.  Blocks the worker for
 *                                up to timeout_ms waiting for a reply.
 *                                Intended for timer_route / startup
 *                                contexts; DO NOT call from a UDP/TCP
 *                                SIP worker -- it stalls request
 *                                processing for that worker until the
 *                                reply (or timeout) comes back.  A
 *                                non-blocking async variant lands in a
 *                                later phase.  On success, the reply
 *                                populates the current-message state so
 *                                the script can read $nats_data,
 *                                $nats_subject, $nats_hdr(...), etc.
 *                                Returns 1 on success, 0 on timeout,
 *                                -3 NATS unavailable, -4 request error.
 */

#ifndef NATS_RPC_H
#define NATS_RPC_H

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"

/* Upper bound on staged-header entries per publish.  Sized generously
 * relative to real-world NATS use; each entry is a pair of `str`s
 * backed by a process-local pkg_malloc copy. */
#define NATS_MAX_STAGED_HDRS 16

/* pvar glue: parse the $nats_hdr(Name) name argument and hand it to the
 * getter.  Both follow the standard pvar callback signatures.  Name
 * match is case-insensitive (HTTP/NATS conventions). */
int pv_parse_nats_hdr_name(pv_spec_p sp, const str *in);
int pv_get_nats_hdr(struct sip_msg *msg, pv_param_t *param,
                    pv_value_t *res);

/* Script-callable header staging. */
int w_nats_hdr_set (struct sip_msg *msg, str *name, str *value);
int w_nats_reply   (struct sip_msg *msg, str *payload);
int w_nats_request (struct sip_msg *msg, str *subject, str *payload,
                    int *timeout_ms);

/* Clear the staged-header table and free the backing buffers.
 * Invoked internally by the publish paths; exposed so that a future
 * caller (e.g. a child_init reset / module destroy) can drop staging
 * state without publishing. */
void nats_rpc_staged_clear(void);

#endif /* NATS_RPC_H */
