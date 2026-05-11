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

/* Reconnect-epoch snapshot taken at ctx alloc time.  The
 * production start path overwrites with
 * `nats_pool_get_reconnect_epoch()`; tests can override
 * directly. */
void     nats_rpc_async_ctx_set_epoch_at_start(struct nats_rpc_async_ctx *c,
                                                uint32_t epoch);
uint32_t nats_rpc_async_ctx_epoch_at_start    (struct nats_rpc_async_ctx *c);

/* Pure decision: should the resume path return -2
 * (connection lost) instead of 0 (timeout) for this ctx given
 * the current pool epoch + connected flag?  Returns 1 = connection
 * lost, 0 = stable.  Exposed for unit tests; the production
 * resume function calls it with the live pool values. */
int nats_rpc_async_ctx_is_disconnected(struct nats_rpc_async_ctx *c,
                                       uint32_t current_epoch,
                                       int current_connected);

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

/*
 * Mint a UUIDv7 correlation id (RFC 9562 §5.7) into the provided
 * buffer.  `cap` must be at least 37 (36 chars + NUL).  Returns
 * the written length (36) on success or 0 on truncation /
 * getrandom failure.
 *
 * Used by the sync and async nats_request start paths to populate
 * the per-worker `$nats_request_id` stash and the auto-staged
 * outbound header (modparam `request_id_header`, default
 * `X-Request-Id`).  Exposed for unit tests that want to validate
 * the version-7 nibble and variant bits without booting opensips.
 */
int nats_rpc_async_uuidv7_mint(char *out, size_t cap);

/* Per-worker stash setter / getter for the most recent outbound
 * request's UUIDv7.  `_set` is used by the start paths to record
 * the just-used id (and clears the user-supplied override flag);
 * `_get` is read by the $nats_request_id pvar getter.
 *
 * The pointer returned by ..._get() is owned by the module; it is
 * valid until the next nats_request call on this worker.  Callers
 * that need the value to outlive that must copy. */
void        nats_rpc_async_request_id_set(const char *id, int len);
const char *nats_rpc_async_request_id_get(int *out_len);

/* Pvar-write entry point: the script has assigned to
 * $nats_request_id.  Stash the value with a consume-once flag so
 * the NEXT nats_request call uses it instead of minting a fresh
 * UUIDv7.  Returns 0 on success, -1 on validation failure
 * (length > 63 bytes, embedded CR/LF). */
int nats_rpc_async_request_id_user_set(const char *id, int len);

/* Start-path consumer: if a user-supplied id is pending, copy
 * it to `out` (cap-sized) and clear the pending flag.  Returns
 * the length copied, or 0 if no override is pending.  Consume-
 * once -- subsequent calls revert to minting unless the script
 * re-assigns. */
int nats_rpc_async_request_id_consume_user(char *out, int cap);

#endif /* NATS_RPC_ASYNC_H */
