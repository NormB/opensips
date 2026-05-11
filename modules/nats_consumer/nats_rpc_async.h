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
 * nats_rpc_async.h -- internal API of the async nats_request path.
 *
 * The async entry point itself (w_nats_request_async) is declared
 * in nats_rpc.h alongside the rest of the script-callable RPC
 * surface; that's the only symbol nats_consumer.c needs.  This
 * header exposes the state-machine primitives so the phase-2 unit
 * test (test_async_request_inflight.c) can drive them in isolation
 * without linking libnats.
 *
 * All functions are process-local (per-worker); the in-flight
 * table is statically sized in nats_rpc_async.c and is not shared
 * across processes.
 */

#ifndef NATS_RPC_ASYNC_H
#define NATS_RPC_ASYNC_H

/* Opaque in-flight context.  The concrete struct lives in
 * nats_rpc_async.c and the test driver only ever holds pointers. */
struct nats_rpc_async_ctx;

/*
 * Allocate a new in-flight context.  Generates a fresh correlation
 * id from a per-worker monotonic counter, allocates a non-blocking
 * eventfd, and initialises the per-ctx mutex.  Refcount starts at
 * 1 (held by the caller).
 *
 * Returns NULL on allocator failure or eventfd creation failure.
 */
struct nats_rpc_async_ctx *nats_rpc_async_ctx_new(void);

/* Bump the ctx refcount.  Used by the libnats callback path and
 * the test driver when staging a deliberate ref. */
void nats_rpc_async_ctx_addref(struct nats_rpc_async_ctx *c);

/* Drop one ref.  If this is the last ref, close the eventfd,
 * destroy the mutex, and pkg_free the struct. */
void nats_rpc_async_ctx_release(struct nats_rpc_async_ctx *c);

/* Insert a freshly-allocated ctx into the per-worker hash table.
 * Bumps the refcount on success (slot's ref).  Returns 0 on
 * success, -1 if the hard in-flight cap is reached, -2 on
 * duplicate corr_id (defence-in-depth -- the monotonic counter
 * makes this impossible in practice). */
int nats_rpc_async_install(struct nats_rpc_async_ctx *c);

/* Atomically unlink ctx from the table and transfer the hash's
 * refcount to the caller.  Returns 1 if the slot still held the
 * ctx (caller now owns +1 ref), 0 if it was already gone.  Used
 * by the resume path after wake-up / timeout. */
int nats_rpc_async_take_for_resume(struct nats_rpc_async_ctx *c);

/*
 * Deliver a reply into the context with the matching corr_id.
 * Performs hash-lookup-and-take, then under the per-ctx mutex
 * copies the reply bytes into the ctx and signals the eventfd.
 *
 * This is the unit-test entry point: tests call it with synthetic
 * reply data to exercise the state machine without the libnats
 * subscription / callback wiring.  The libnats on_inbox_reply
 * callback does the same thing inline (no second hash lookup).
 *
 * Returns 0 on successful delivery, -1 if no matching ctx (stale
 * reply -- caller should drop the payload).
 */
int nats_rpc_async_deliver(const char *corr_id, int corr_id_len,
                           const char *reply_subject, int reply_subject_len,
                           const char *reply_data,    int reply_data_len,
                           const char *reply_headers, int reply_headers_len,
                           int reply_headers_truncated,
                           const char *reply_to,      int reply_to_len);

/* Drain the per-ctx eventfd counter so a subsequent wait re-arms.
 * Returns 1 if a count was consumed, 0 if the fd was empty (e.g.
 * we were woken on timeout), -1 on error. */
int nats_rpc_async_drain_eventfd(struct nats_rpc_async_ctx *c);

/* Promote INFLIGHT -> ABANDONED if no reply has landed yet.
 * Returns the observed state after the operation. */
int nats_rpc_async_mark_abandoned(struct nats_rpc_async_ctx *c);

/* Accessors (opaque struct compatibility). */
int  nats_rpc_async_state    (struct nats_rpc_async_ctx *c);
int  nats_rpc_async_eventfd  (struct nats_rpc_async_ctx *c);
int  nats_rpc_async_corr_len (struct nats_rpc_async_ctx *c);
const char *nats_rpc_async_corr_id(struct nats_rpc_async_ctx *c);

/* Process-wide in-flight count snapshot (advisory, locked). */
int nats_rpc_async_inflight_count(void);

/* Format the per-call reply subject "<prefix>.<pid>.<corr>" into
 * the provided buffer.  Returns the written length, 0 on
 * truncation. */
int nats_rpc_async_format_reply_subject(struct nats_rpc_async_ctx *c,
                                        char *out, int cap);

/* Extract the correlation suffix from a reply subject of the form
 * "<prefix>.<pid>.<corr>".  Returns a pointer into the input
 * buffer plus the suffix length via *out_len; NULL on parse fail.
 * Used by the callback and by tests. */
const char *nats_rpc_async_corr_from_subject(const char *subject,
                                             int subject_len,
                                             int *out_len);

#endif /* NATS_RPC_ASYNC_H */
