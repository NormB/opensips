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
 * nats_handle_registry -- SHM-backed hash table of consumer handles.
 *
 * The registry is the single source of truth for bound JetStream consumer
 * configurations.  Handles are added/removed at runtime via the MI bind/
 * unbind commands (phase 1) or script functions (future phases).
 *
 * Concurrency:
 *   - Lookups (hot path) take a per-bucket read lock.
 *   - Bind/unbind take the matching bucket write lock; the global rwlock
 *     is taken only for registry-wide iteration and teardown.
 *   - The runtime counters block inside each handle is guarded by a
 *     per-handle rwlock; stats updates do not block lookups.
 *
 * Memory:
 *   - All handle allocations live in SHM.  Callers transfer ownership
 *     to the registry via nats_registry_bind().
 */

#ifndef NATS_HANDLE_REGISTRY_H
#define NATS_HANDLE_REGISTRY_H

#include <stdint.h>
#include <time.h>
#include "../../str.h"

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../rw_locking.h"
#endif

/* Forward declaration; full type defined in nats_ring.h.  The handle
 * keeps a pointer to the SHM-backed per-handle ring; consumers include
 * nats_ring.h directly when they need to operate on it. */
struct nats_ring;

typedef enum {
	NATS_CONSUMER_DURABLE = 0,
	NATS_CONSUMER_EPHEMERAL,
	NATS_CONSUMER_ORDERED,    /* reserved -- unused in phase 1 */
} nats_consumer_type_e;

typedef enum {
	NATS_DELIVER_ALL = 0,
	NATS_DELIVER_LAST,
	NATS_DELIVER_NEW,
	NATS_DELIVER_LAST_PER_SUBJECT,
	NATS_DELIVER_BY_START_SEQ,
	NATS_DELIVER_BY_START_TIME,
} nats_deliver_policy_e;

typedef enum {
	NATS_ACK_EXPLICIT = 0,
	NATS_ACK_NONE,
	NATS_ACK_ALL,
} nats_ack_policy_e;

typedef enum {
	NATS_REPLAY_INSTANT = 0,
	NATS_REPLAY_ORIGINAL,
} nats_replay_policy_e;

/* Upper bound on simultaneously-bound handles in a single opensips
 * instance.  Used both as a cap (bind past this returns -3) and to size
 * the consumer process's process-local natsMsg* ref table.  16 bits
 * worth is overkill; the limit is about keeping the ref table shallow.
 */
#define NATS_REGISTRY_MAX_HANDLES 256

typedef struct nats_handle {
	str id;                             /* registry key; SHM-owned */
	str stream;                         /* SHM-owned */
	str durable;                        /* SHM-owned, empty for ephemeral */
	nats_consumer_type_e type;

	/* Monotonic bind-order index, assigned atomically inside
	 * nats_registry_bind.  Valid range: [0, NATS_REGISTRY_MAX_HANDLES).
	 * Used to pack (handle_idx, slot_idx, generation) into an ack token
	 * so the consumer process can look up the stored natsMsg* without
	 * a hash.  Stable for the lifetime of the handle; not reused after
	 * unbind within a single opensips run (Phase 4 scope). */
	uint16_t index;

	/* filters */
	str filter;                         /* single-subject filter */
	str filters_csv;                    /* multi-filter raw CSV */

	/* delivery policy */
	nats_deliver_policy_e deliver_policy;
	uint64_t start_seq;
	int64_t  start_time_unix_ns;
	nats_replay_policy_e replay_policy;

	/* ack */
	nats_ack_policy_e ack_policy;
	int ack_wait_ms;
	int max_deliver;
	str backoff_csv;
	int max_ack_pending;

	/* shaping */
	int headers_only;
	int sample_freq;
	int rate_limit_bps;
	int inactive_threshold_ms;

	/* multi-env */
	str js_domain;
	str api_prefix;

	/* forward-compat */
	str extra_json;

	/* runtime (guarded by rlock) */
	rw_lock_t *rlock;
	time_t created_at;
	time_t last_used_at;
	uint64_t pulls_requested;
	uint64_t msgs_delivered;
	uint64_t acks;
	uint64_t naks;
	uint64_t terms;
	uint64_t redeliveries;
	int last_error_code;
	str last_error_msg;

	/* SHM ring for this handle -- created on bind, destroyed on unbind.
	 * Producer: the dedicated consumer process.
	 * Consumer: SIP workers.
	 * Ownership: the registry owns the ring and tears it down when the
	 * handle is released.  May be NULL under TEST_SHIM where the test
	 * shim does not provide eventfd-compatible allocation. */
	struct nats_ring *ring;

	/* Active JetStream subscription handle.
	 * Owned by the consumer process (not SHM; process-local).
	 * NULL until the consumer process creates the subscription.
	 *
	 * Not written by SIP workers.  Treated as opaque in shared headers;
	 * the consumer process code casts this to natsSubscription *. */
	void *subscription;

	/* intrusive bucket chain */
	struct nats_handle *next;
} nats_handle_t;

/* Initialize the registry with `bucket_count` buckets.
 * Call from mod_init (pre-fork).
 * Returns 0 on success, -1 on SHM exhaustion. */
int nats_registry_init(int bucket_count);

/* Tear down the registry.  Call from mod_destroy. */
void nats_registry_destroy(void);

/* Transfer ownership of a handle into the registry.
 * On success: registry owns `h`, initializes `h->rlock`, sets created_at.
 * On failure: caller retains ownership and must free.
 * Returns:
 *    0 on success
 *   -1 on duplicate id
 *   -2 on SHM exhaustion / internal error */
int nats_registry_bind(nats_handle_t *h);

/* Remove a handle by id.
 * Returns 0 on success, -1 if not found. */
int nats_registry_unbind(const str *id);

/* Borrowed lookup.  Returns NULL if not found.
 * Caller must not free.  Handle content is stable until unbind. */
nats_handle_t *nats_registry_lookup(const str *id);

/* Snapshot count.  Non-blocking read (atomic). */
int nats_registry_count(void);

/* Iterate holding the global read lock.
 * `cb` returns 0 to continue, non-zero to stop early (value is returned
 * to the caller).
 * Must not call registry_bind/unbind from within cb -- deadlock. */
int nats_registry_foreach(int (*cb)(nats_handle_t *h, void *user),
                          void *user);

/* Free a handle whose bind failed.  Frees all str buffers and the rlock
 * if initialized, then frees the handle itself.
 * Used by parse-then-fail paths where the caller still owns the handle. */
void nats_handle_free(nats_handle_t *h);

/* Accessor -- returns the SHM ring owned by the handle with the given
 * `id`, or NULL if no such handle is bound.  Intended for SIP worker
 * side script functions (Phase 4) that need to pop messages.
 *
 * The registry keeps the handle alive until nats_registry_unbind(), so
 * the returned pointer is valid until a concurrent unbind -- callers
 * that race with unbind must be prepared for the ring to disappear
 * underneath them.  A future phase will add refcounting. */
struct nats_ring *nats_registry_ring_get(const str *id);

#endif /* NATS_HANDLE_REGISTRY_H */
