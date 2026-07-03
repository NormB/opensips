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
 * header exposes the state-machine primitives so the in-flight
 * unit test (test_async_request_inflight.c) can drive them in
 * isolation without linking libnats.
 *
 * All functions are process-local (per-worker); the in-flight
 * table is statically sized in nats_rpc_async.c and is not shared
 * across processes.
 */

#ifndef NATS_RPC_ASYNC_H
#define NATS_RPC_ASYNC_H

/* The in-flight ctx state machine that used to be declared here (the
 * per-worker inbox-subscription async transport) was superseded by the
 * consumer-routed SHM-slot transport and deleted (P1.1). */

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


/* Per-call timerfd poll interval (ms), tunable via the nats_consumer
 * "async_rpc_poll_ms" modparam.  Clamped to [1, 1000] when used. */
extern int nats_rpc_async_poll_ms;

#endif /* NATS_RPC_ASYNC_H */
