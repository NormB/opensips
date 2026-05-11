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
 * Entry points:
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
 *   nats_request(subj, payload, timeout_ms) -- core NATS RPC
 *                                request/reply.  Two call shapes:
 *                                  bare nats_request(...)            -- sync
 *                                  async(nats_request(...), rt)      -- async
 *                                The sync shape blocks the worker for
 *                                up to timeout_ms; the async shape
 *                                yields to the reactor on a per-call
 *                                eventfd while a libnats subscription
 *                                thread waits for the reply.  On
 *                                success the reply populates the
 *                                per-worker current-message state so
 *                                the script can read $nats_data,
 *                                $nats_subject, $nats_hdr(...), etc.
 *                                Return codes:
 *                                   1  reply delivered.
 *                                   0  timeout (the broker is still
 *                                      reachable; the responder did
 *                                      not reply in time).
 *                                  -1  internal error (oom, format
 *                                      failure) -- async only.
 *                                  -2  connection lost mid-flight --
 *                                      async only.  The pool epoch
 *                                      advanced or is_connected
 *                                      went false during the call;
 *                                      the script should treat this
 *                                      as broker-down rather than
 *                                      retry-with-longer-tmo.
 *                                  -3  NATS unavailable at issue
 *                                      time (no pool connection).
 *                                  -4  request error (subject empty
 *                                      / too long, msg create failed,
 *                                      publish/request failed).
 *                                  -5  per-worker in-flight cap
 *                                      reached -- async only.
 */

#ifndef NATS_RPC_H
#define NATS_RPC_H

#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"
#include "../../async.h"

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

/* $nats_request_id pvar getter + setter.
 *
 * GET returns the value used (or to-be-used) for the most recent
 * nats_request issued by this worker; persists across an async()
 * yield so it is readable from the resume route.
 *
 * SET stashes a script-supplied value for the next nats_request
 * call to consume instead of minting a fresh UUIDv7 (consume-once
 * semantics).  Rejects values that are over 63 bytes or contain
 * CR/LF. */
int pv_get_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           pv_value_t *res);
int pv_set_nats_request_id(struct sip_msg *msg, pv_param_t *param,
                           int op, pv_value_t *val);

/* Stage a header onto the worker's outbound buffer iff no entry
 * with the same (case-insensitive) name is already staged.  Used
 * by the auto-stager for the per-call UUIDv7 so a deliberate
 * nats_hdr_set("X-Request-Id", ...) in the script wins.  Returns
 * 1 on stage, 0 if an existing entry was preserved, -1 on OOM or
 * full table. */
int nats_rpc_staged_set_if_absent(const str *name, const str *value);

/* Script-callable header staging. */
int w_nats_hdr_set (struct sip_msg *msg, str *name, str *value);
int w_nats_reply   (struct sip_msg *msg, str *payload);
int w_nats_request (struct sip_msg *msg, str *subject, str *payload,
                    int *timeout_ms);

/* Script-callable async variant of nats_request.  Registered in the
 * module's acmd table under the same name `nats_request`, so the
 * sync vs. async dispatch is driven by call-site syntax:
 *   bare        nats_request(...)            -> w_nats_request    (sync)
 *   wrapped in  async(nats_request(...), rt) -> w_nats_request_async
 *
 * Phase 1 fall-through skeleton: this entry point currently runs the
 * existing synchronous request path and reports completion via
 * async_status = ASYNC_SYNC.  Phase 2 will replace the body with a
 * libnats publish + reply-inbox subscription bridged onto an eventfd,
 * yielding the worker for the duration of the round trip.  The script
 * surface is stable across both phases. */
int w_nats_request_async(struct sip_msg *msg, async_ctx *ctx,
                         str *subject, str *payload, int *timeout_ms);

/* Clear the staged-header table and free the backing buffers.
 * Invoked internally by the publish paths; exposed so that a future
 * caller (e.g. a child_init reset / module destroy) can drop staging
 * state without publishing. */
void nats_rpc_staged_clear(void);

#endif /* NATS_RPC_H */
