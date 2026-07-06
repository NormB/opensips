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
 * nats_consumer_proc_internal.h — private cross-TU declarations for the
 * consumer-process translation units (the proc-TU split of
 * nats_consumer_proc.c into msg-ref / sub-config / proc-loop TUs).
 * Nothing here is module API: code outside the consumer process must
 * use nats_consumer_proc.h.
 */

#ifndef NATS_CONSUMER_PROC_INTERNAL_H
#define NATS_CONSUMER_PROC_INTERNAL_H

#include <stdint.h>
#include <time.h>

#include <nats/nats.h>

#include "../../str.h"
#include "nats_handle_registry.h"

/* Monotonic clock in microseconds (0 on clock_gettime failure). */
static inline long long _now_monotonic_us(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

/* ── per-subscription process-local state ─────────────────────── */

typedef struct proc_sub_state {
	str                   id;              /* copy of registry handle id
	                                        * (process-local buffer, NOT
	                                        *  shared) */
	uint16_t              handle_idx;      /* stable index from registry */
	natsSubscription     *sub;             /* active pull subscription */
	struct nats_ring     *ring;            /* borrowed ref to handle ring */
	nats_handle_t        *h_ref;           /* borrowed ref to SHM handle
	                                        * (used for pending_ops
	                                        *  accounting). */
	time_t                last_fetch;

	/* Per-handle pull/push/defer/error counters live in the SHM handle
	 * (nats_handle_t: pulls_requested, msgs_delivered, fetch_skips_full,
	 * backpressure_drops, fetch_errors, ...) so the attendant's MI
	 * handlers can read them.  Bumped here via hstat_add(). */

	/* Monotonic-us timestamp of the last oversize-message WARN, so a flood
	 * of oversized messages logs at most once per interval (the per-handle
	 * `terms` counter still increments on every one). */
	long long             last_oversize_warn_us;

	/* Highest stream sequence delivered so far.  Survives a rebuild (the
	 * proc_sub_state_t is kept when the natsSubscription is recreated), so
	 * a vanished+recreated durable can resume just past it instead of
	 * replaying the whole stream under deliver_policy=all. */
	uint64_t              last_stream_seq;

	/* Stream incarnation the watermark above belongs to
	 * (jsStreamInfo.Created, ns since epoch; 0 = unknown).  Stamped on
	 * every successful subscribe.  The rebuild bias is only valid for
	 * the SAME incarnation: a recreated stream restarts its sequences
	 * at 1, and resuming at a stale watermark would silently skip
	 * every new message until the sequence grows past it (bit us via
	 * test_reconnect.sh: broker restart on memory storage). */
	int64_t               stream_created_ns;

	/* Subscription-refresh bookkeeping. */
	int                   dirty;   /* 1 iff the subscription needs
	                                 * rebuild (epoch bump or broker
	                                 * GC'd ephemeral); cleared when
	                                 * ensure_subscription_for_handle
	                                 * successfully creates a fresh
	                                 * natsSubscription. */

	/* String cleanup slots.  These point at the malloc'd C-strings
	 * and arrays we hand to nats.c in ensure_subscription_for_handle();
	 * nats.c holds borrowed pointers for the life of the subscription,
	 * so we stash them here and the retire/reap teardown path frees
	 * them along with the proc_sub_state_t.  NULL entries mean
	 * "no allocation for that slot". */
	char                 *c_durable;
	char                 *c_filter;
	char                 *c_stream;
	char                 *c_domain;
	char                 *c_api_prefix;
	char                 *c_sample_freq;
	int64_t              *backoff_arr;
	const char          **filters_arr;
	int                   filters_arr_len;

	struct proc_sub_state *next;
} proc_sub_state_t;

/* Linked list of all subscription states (consumer process only). */
extern proc_sub_state_t *g_subs;
/* Dense idx -> state table for O(1) lookup from ack tokens. */
extern proc_sub_state_t *g_subs_by_idx[NATS_REGISTRY_MAX_HANDLES];
/* Process JetStream context (NULL until the proc loop connects). */
extern jsCtx *g_js;

/* ── natsMsg ref table (nats_msg_ref.c) ───────────────────────── */

typedef struct msg_ref_slot {
	natsMsg   *msg;
	uint16_t   generation;
	uint16_t   in_use;       /* 1 iff msg != NULL and ack pending */
	uint32_t   _pad;
	long long  claimed_at_us; /* CLOCK_MONOTONIC us at store; for orphan reap */
} msg_ref_slot_t;

typedef struct msg_ref_row {
	uint32_t         capacity;     /* 0 == row not allocated yet */
	msg_ref_slot_t  *slots;        /* [capacity] */
	uint32_t         next_slot;    /* round-robin hint */
	int              ack_wait_ms;  /* handle ack_wait; drives the orphan TTL */
} msg_ref_row_t;

/* How often the main loop scans for orphans (cheap, but no need every tick). */
#define NATS_MSG_REF_REAP_INTERVAL_US (30LL * 1000000LL)

/* Minimum interval between oversize-message WARN lines per subscription, so
 * a flood of oversized messages cannot flood the log. */
#define NATS_OVERSIZE_WARN_INTERVAL_US (5LL * 1000000LL)

extern msg_ref_row_t g_msg_refs[NATS_REGISTRY_MAX_HANDLES];

/* Per-handle stat bump without the rwlock (relaxed atomics; NULL-safe).
 * Shared by the fetch path (nats_consumer_proc.c) and the ack hop
 * (nats_ack_ipc.c). */
static inline void hstat_add(nats_handle_t *h, uint64_t *field, uint64_t v)
{
	if (!h || !field) return;
	__atomic_fetch_add(field, v, __ATOMIC_RELAXED);
}

/* Size (or re-size) a handle's ref row to the ring capacity. */
int ensure_row(uint16_t handle_idx, uint32_t capacity);
/* Stash a natsMsg under a fresh ack token; *ok is cleared (and 0
 * returned) on table exhaustion. */
uint64_t store_msg_ref(uint16_t handle_idx, uint32_t ring_capacity,
	int ack_wait_ms, natsMsg *m, int *ok);
/* Redeem an ack token; NULL if stale (generation mismatch) or unset. */
natsMsg *release_msg_ref(uint64_t token);
/* Reclaim slots older than the orphan TTL; returns the reap count. */
int reap_orphan_msg_refs(void);
/* [P2.1] Consume (and clear) a handle's ACK_NEXT refill hint; 1 if it
 * was set.  Proc-local; set by the ack IPC handlers, read by the main
 * loop right after the pump. */
int nats_ack_next_take(uint16_t handle_idx);
/* Destroy every outstanding natsMsg for a handle and free its ref row.
 * MUST be called at every subscription-destroy site: a fetched natsMsg
 * holds an unref'd msg->sub, so acking one after its sub is destroyed is a
 * use-after-free. */
void purge_msg_ref_row(uint16_t handle_idx);

/* Walk the registry's retire list and mark retired handles that never
 * got a subscription (no g_subs entry) as torn down so the reaper can
 * free them.  Called each consumer-loop tick; exported for unit tests. */
void mark_orphan_retired_handles(void);

/* ── subscription config / lifecycle (nats_sub_config.c) ──────── */

/* O(1) lookup of the owning subscription state by handle index. */
proc_sub_state_t *find_sub_by_index(uint16_t index);
/* Free the C-string/array slots nats.c borrowed for the sub's life. */
void free_proc_sub_strings(proc_sub_state_t *ss);
/* Create or rebuild the JetStream pull subscription for a handle. */
int ensure_subscription_for_handle(nats_handle_t *h);
/* Registry-walk callback: reconcile g_subs with the bound handles. */
int reconcile_subs_cb(nats_handle_t *h, void *user);

/*
 * 1 iff the rebuild's anti-replay resume bias must be DROPPED because
 * the stream is a different incarnation than the one the delivery
 * watermark came from (recreated / restored: sequences restarted).
 * Either side unknown (0) keeps the historical bias behavior --
 * fail-open to the cheaper wrong-direction (a possible replay) rather
 * than the silent-skip direction.  Unit-locked in
 * tests/test_rebuild_bias_stale.c; end-to-end in test_reconnect.sh.
 */
static inline int nats_rebuild_bias_stale(int64_t stamped_created_ns,
	int64_t current_created_ns)
{
	return stamped_created_ns != 0 && current_created_ns != 0 &&
		stamped_created_ns != current_created_ns;
}

#endif /* NATS_CONSUMER_PROC_INTERNAL_H */
