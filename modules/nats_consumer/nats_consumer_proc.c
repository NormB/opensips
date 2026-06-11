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
 * nats_consumer_proc.c -- dedicated JetStream pull consumer process.
 *
 *   The process owns one natsConnection (from the shared pool) and one
 *   jsCtx.  Every bound handle gets a single pull subscription owned by
 *   this process; the subscription pointer lives in process-local
 *   memory (g_subs) rather than in the SHM handle because the nats.c
 *   library's subscription objects are not SHM-safe.
 *
 *   On each iteration:
 *     1. reconcile_subs() walks the registry, creating a
 *        proc_sub_state_t + natsSubscription for any handle it has not
 *        yet seen.
 *     2. pull_one_batch() reads the SHM ring's free-slot count, clamps
 *        the request to min(fetch_batch, free_slots-1), and fetches
 *        that many messages with a `fetch_timeout_ms` timeout.  Each
 *        natsMsg is stashed under a freshly-minted ack_token, then
 *        pushed into the handle's SHM ring.  When the ring has no
 *        room, the Fetch is skipped entirely; pull-mode JetStream
 *        keeps the un-fetched messages on the broker side until the
 *        next iteration after the worker drains.
 *     3. drain_ack_ipc() dequeues every pending ack request from the
 *        IPC queue, looks up the stashed natsMsg, and calls the
 *        requested natsMsg_Ack / Nak / Term / InProgress.
 *
 *   Back-pressure model: the dynamic Fetch clamp in step (2) means
 *   a successful Fetch never produces a defer-drop on push, so the
 *   broker never sees an outstanding-then-redelivered cycle from
 *   over-fetching.  The legacy ring-full path (nats_ring_push -> -1)
 *   is still defended against (release_msg_ref + ss->total_dropped_*),
 *   but is unreachable in steady state with the clamp in place.
 *
 *   Throughput: with this design plus msg-ref sizing of
 *   max(ring_capacity, max_ack_pending) and the batch-fetch
 *   wait-loop in nats_fetch.c, sustained drain on aarch64
 *   loopback at fetch_batch=256 measures ~89 000 msgs/sec vs. ~2 000
 *   msgs/sec on the original per-message single-drain path.
 *
 *   Ack model: rather than auto-acking each pushed message, the
 *   consumer process stashes natsMsg* in a process-local ref table
 *   indexed by (handle_idx, slot_idx) and only calls
 *   natsMsg_Ack / Nak / Term / InProgress in drain_ack_ipc() on a
 *   worker's explicit request.  A 16-bit generation counter in each
 *   ref slot is bumped on (re)use and checked on ack to guard against
 *   ABA-style stale-token reuse after ring wrap.
 */

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <sys/timerfd.h>

#include <nats/nats.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../lib/nats/nats_pool.h"

#include "nats_handle_registry.h"
#include "nats_ring.h"
#include "nats_ack_ipc.h"
#include "nats_ack.h"
#include "nats_consumer_proc.h"
#include "nats_rpc_consumer.h"
#include "nats_rpc_ipc.h"

/* SHM heartbeat block -- bumped per loop iteration so a watchdog or
 * MI handler can detect a wedged or crashed consumer process.
 * Allocated by mod_init via nats_consumer_hb_init(); NULL until
 * then, so writes are guarded. */
nats_consumer_heartbeat_t *nats_consumer_hb = NULL;

int nats_consumer_hb_init(void)
{
	nats_consumer_hb = shm_malloc(sizeof(*nats_consumer_hb));
	if (!nats_consumer_hb) {
		LM_ERR("nats_consumer: shm_malloc for heartbeat failed\n");
		return -1;
	}
	memset(nats_consumer_hb, 0, sizeof(*nats_consumer_hb));
	atomic_store_explicit(&nats_consumer_hb->tick, 0, memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->last_tick_us, 0, memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->consumer_pid, 0, memory_order_relaxed);
	return 0;
}

void nats_consumer_hb_destroy(void)
{
	if (nats_consumer_hb) {
		shm_free(nats_consumer_hb);
		nats_consumer_hb = NULL;
	}
}

static inline long long _now_monotonic_us(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

static inline void nats_consumer_hb_tick(void)
{
	if (!nats_consumer_hb) return;
	atomic_fetch_add_explicit(&nats_consumer_hb->tick, 1,
		memory_order_relaxed);
	atomic_store_explicit(&nats_consumer_hb->last_tick_us,
		_now_monotonic_us(), memory_order_relaxed);
}

/* ── tuning ──────────────────────────────────────────────────── */

/* Fetch batch / per-Fetch timeout are operator-tunable.  Module-global
 * defaults come from the `fetch_batch` / `fetch_timeout_ms` modparams
 * (see nats_consumer.c).  Each bound handle may override either
 * value via `fetch_batch=` / `fetch_timeout_ms=` in nats_consumer_bind.
 * Resolved at every Fetch call so a runtime modparam tweak is picked
 * up without rebinding (modparams themselves are static-after-startup
 * in OpenSIPS, but this keeps the resolution logic in one place). */
static inline int eff_fetch_batch(const nats_handle_t *h)
{
	int v = (h && h->fetch_batch) ? (int)h->fetch_batch
	                              : nats_consumer_fetch_batch;
	if (v < 1)    v = 1;
	if (v > 4096) v = 4096;
	return v;
}

static inline int eff_fetch_timeout_ms(const nats_handle_t *h)
{
	int v = (h && h->fetch_timeout_ms) ? (int)h->fetch_timeout_ms
	                                   : nats_consumer_fetch_timeout_ms;
	if (v < 1)     v = 1;
	if (v > 60000) v = 60000;
	return v;
}

/* Floor on the per-fetch idle wait so we still actually block (and don't
 * busy-spin) when many handles share the budget. */
#define NATS_FETCH_MIN_BUDGET_MS  5

/*
 * Per-fetch timeout budget for one pass of the fetch sweep.  With one
 * handle, use the full configured timeout (an efficient idle wait).  With
 * N handles, divide it so the WHOLE sweep stays bounded at ~the configured
 * timeout instead of N * timeout -- otherwise a sweep over many idle
 * handles starves acks and async RPCs for num_handles * fetch_timeout
 * (head-of-line blocking).  Returns 0 ("no cap") for the single-handle
 * case so pull_one_batch uses the handle's own configured timeout.
 */
static int fetch_budget_ms(int configured, int num_subs)
{
	int b;
	if (num_subs <= 1)
		return 0;                 /* no cap: full per-handle timeout */
	b = configured / num_subs;
	if (b < NATS_FETCH_MIN_BUDGET_MS)
		b = NATS_FETCH_MIN_BUDGET_MS;
	if (b > configured)
		b = configured;
	return b;
}

/* Idle cycle: blocking select() on (ack_fd, retry_timerfd) instead of
 * a usleep spin.  The retry timerfd gives us a bounded upper wait so
 * a stalled subscription (e.g. broker TCP stall) does not keep us
 * asleep forever; acks still wake us immediately on any worker
 * ack-IPC enqueue. */
#define IDLE_RETRY_MS      1000   /* 1 s max idle before retry */

/* ── process-local state ─────────────────────────────────────── */

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

	/* Highest stream sequence delivered so far.  Survives a rebuild (the
	 * proc_sub_state_t is kept when the natsSubscription is recreated), so
	 * a vanished+recreated durable can resume just past it instead of
	 * replaying the whole stream under deliver_policy=all. */
	uint64_t              last_stream_seq;

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

static proc_sub_state_t *g_subs = NULL;

/* Dense idx -> proc_sub_state_t table maintained alongside g_subs so the
 * ack drain callback (which only carries the handle_idx via the ack
 * token) can find the owning subscription's handle in O(1) without
 * scanning the linked list per ack.  Updated under the same single-
 * producer assumption as g_subs (the consumer process only). */
static proc_sub_state_t *g_subs_by_idx[NATS_REGISTRY_MAX_HANDLES] = {0};

static natsConnection   *g_nc   = NULL;
static jsCtx            *g_js   = NULL;

/* SHM-handle stat bump.  All counters live in the per-handle SHM
 * struct; producers are this process only, readers are MI in the
 * attendant process (see nats_mi.c).  Use relaxed atomics so the
 * reader sees coherent increments without us paying for the per-handle
 * rwlock on every pull/push/ack.
 *
 * Wrapped in a static inline so the call sites stay terse; with NULL
 * the bump is a no-op (e.g. early TEST_SHIM init). */
static inline void hstat_add(nats_handle_t *h, uint64_t *field, uint64_t v)
{
	if (!h || !field) return;
	__atomic_fetch_add(field, v, __ATOMIC_RELAXED);
}

/* ── natsMsg ref table ───────────────────────────────────────── */

/*
 * Process-local 2D ref table: for each (handle_idx, slot_idx) we keep
 * the live natsMsg* plus a 16-bit generation counter bumped every
 * time the slot is reused.  The ack token encodes generation so a
 * stale ack (one issued for a natsMsg that has already been acked and
 * the slot reused) is detected and ignored.
 *
 * The ring-capacity dimension is sized at first use of a handle in
 * store_msg_ref().  Rings may share the same capacity
 * (NATS_HANDLE_RING_CAPACITY) or override it per-handle via
 * `ring_capacity` at bind time; we key off the handle's ring
 * object so any per-handle capacity is honoured.
 */
typedef struct msg_ref_slot {
	natsMsg   *msg;
	uint16_t   generation;
	uint16_t   in_use;       /* 1 iff msg != NULL and ack pending */
	uint32_t   _pad;
	long long  claimed_at_us; /* CLOCK_MONOTONIC us at store; for orphan reap */
} msg_ref_slot_t;

/* Reclaim a msg-ref slot if it has been outstanding longer than this: a
 * worker that died after popping a message but before acking would
 * otherwise leak its slot forever.  Generously larger than any reasonable
 * JetStream ack_wait (default 30s) so a slow-but-live worker still within
 * its ack_wait is never reaped; the broker has long since redelivered an
 * orphan this old, so its original ack would be rejected anyway. */
#define NATS_MSG_REF_ORPHAN_TTL_US   (120LL * 1000000LL)
/* How often the main loop scans for orphans (cheap, but no need every tick). */
#define NATS_MSG_REF_REAP_INTERVAL_US (30LL * 1000000LL)

/* Count of orphaned msg-ref slots reclaimed (telemetry). */
static unsigned long g_msg_ref_orphans_reaped;

typedef struct msg_ref_row {
	uint32_t         capacity;     /* 0 == row not allocated yet */
	msg_ref_slot_t  *slots;        /* [capacity] */
	uint32_t         next_slot;    /* round-robin hint */
} msg_ref_row_t;

static msg_ref_row_t g_msg_refs[NATS_REGISTRY_MAX_HANDLES];

static int ensure_row(uint16_t handle_idx, uint32_t capacity)
{
	msg_ref_row_t *row;
	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return -1;
	row = &g_msg_refs[handle_idx];
	if (row->slots)
		return 0;
	row->slots = (msg_ref_slot_t *)calloc(capacity, sizeof(msg_ref_slot_t));
	if (!row->slots) {
		LM_ERR("nats_consumer_proc: oom for msg-ref row "
			"handle_idx=%u capacity=%u\n",
			(unsigned)handle_idx, (unsigned)capacity);
		return -1;
	}
	row->capacity  = capacity;
	row->next_slot = 0;
	return 0;
}

/* Reserve a slot, stash the natsMsg, return the packed ack_token.
 * On failure (no free slot) returns 0 and sets *ok to 0. */
static uint64_t store_msg_ref(uint16_t handle_idx, uint32_t ring_capacity,
                              natsMsg *m, int *ok)
{
	msg_ref_row_t  *row;
	msg_ref_slot_t *slot;
	uint32_t        i, start;

	*ok = 0;
	if (ensure_row(handle_idx, ring_capacity) < 0)
		return 0;
	row = &g_msg_refs[handle_idx];

	/* Scan from next_slot for a free slot.  The ring and the ref
	 * table are the same size by construction, so if the ring ever
	 * has room (the worker hasn't acked yet for some outstanding
	 * slot), we should also have a free entry.  If not, the worker
	 * is lagging acks -- return the "full" signal and let the caller
	 * skip the push. */
	start = row->next_slot;
	for (i = 0; i < row->capacity; i++) {
		uint32_t idx = (start + i) % row->capacity;
		slot = &row->slots[idx];
		if (!slot->in_use) {
			slot->msg           = m;
			slot->in_use        = 1;
			slot->generation    = (uint16_t)(slot->generation + 1);
			slot->claimed_at_us = _now_monotonic_us();
			row->next_slot      = (idx + 1) % row->capacity;
			*ok = 1;
			return nats_ack_token_pack(handle_idx, idx, slot->generation);
		}
	}

	LM_WARN("nats_consumer_proc: msg-ref table full for handle_idx=%u; "
		"worker is not acking fast enough\n", (unsigned)handle_idx);
	return 0;
}

/* Take the msg out of the ref table if generation matches.  Returns
 * the natsMsg* (which the caller MUST destroy after calling the
 * requested ack action), or NULL if the slot is stale / unused. */
static natsMsg *release_msg_ref(uint64_t token)
{
	uint16_t         handle_idx = nats_ack_token_handle(token);
	uint32_t         slot_idx   = nats_ack_token_slot(token);
	uint16_t         gen        = nats_ack_token_generation(token);
	msg_ref_row_t   *row;
	msg_ref_slot_t  *slot;
	natsMsg         *m;

	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES)
		return NULL;
	row = &g_msg_refs[handle_idx];
	if (!row->slots || slot_idx >= row->capacity)
		return NULL;
	slot = &row->slots[slot_idx];
	if (!slot->in_use) {
		LM_DBG("nats_consumer_proc: stale ack for token=0x%016lx "
			"(slot already free)\n", (unsigned long)token);
		return NULL;
	}
	if (slot->generation != gen) {
		LM_DBG("nats_consumer_proc: generation mismatch for "
			"token=0x%016lx (expected gen=%u got %u) -- stale ack\n",
			(unsigned long)token,
			(unsigned)slot->generation, (unsigned)gen);
		return NULL;
	}
	m = slot->msg;
	slot->msg    = NULL;
	slot->in_use = 0;
	/* keep generation; next use bumps it again. */
	return m;
}

/*
 * Reclaim msg-ref slots that have been outstanding longer than
 * NATS_MSG_REF_ORPHAN_TTL_US -- the worker that owned them died before
 * acking.  Destroys the leaked natsMsg, frees the slot (bumping the
 * generation so a late ack is rejected), and counts it.  Runs in the
 * consumer process's single-threaded main loop, so no locking is needed.
 * Returns the number of slots reaped.
 */
static int reap_orphan_msg_refs(void)
{
	long long now = _now_monotonic_us();
	int reaped = 0;
	uint32_t h, i;

	for (h = 0; h < NATS_REGISTRY_MAX_HANDLES; h++) {
		msg_ref_row_t *row = &g_msg_refs[h];
		if (!row->slots)
			continue;
		for (i = 0; i < row->capacity; i++) {
			msg_ref_slot_t *slot = &row->slots[i];
			if (!slot->in_use)
				continue;
			if (now - slot->claimed_at_us <= NATS_MSG_REF_ORPHAN_TTL_US)
				continue;
			if (slot->msg)
				nats_dl.natsMsg_Destroy(slot->msg);
			slot->msg        = NULL;
			slot->in_use     = 0;
			slot->generation = (uint16_t)(slot->generation + 1);
			g_msg_ref_orphans_reaped++;
			reaped++;
		}
	}
	if (reaped > 0)
		LM_WARN("nats_consumer_proc: reaped %d orphaned msg-ref slot(s) "
			"(worker died mid-processing?); total reaped=%lu\n",
			reaped, g_msg_ref_orphans_reaped);
	return reaped;
}

/* ── forward declarations ────────────────────────────────────── */

typedef struct drain_ack_ctx drain_ack_ctx_t;

static int  reconcile_subs_cb(nats_handle_t *h, void *user);
static int  ensure_subscription_for_handle(nats_handle_t *h);
static int  pull_one_batch(proc_sub_state_t *ss, int budget_ms);
static void drain_ack_ipc_cb(const nats_ack_ipc_msg_t *m, void *user);
static int  drain_ack_ipc(drain_ack_ctx_t *ctx);
static proc_sub_state_t *find_sub_by_index(uint16_t index);

/* ── enum mapping helpers ────────────────────────────────────── */

static jsDeliverPolicy map_deliver_policy(nats_deliver_policy_e p)
{
	switch (p) {
		case NATS_DELIVER_ALL:              return js_DeliverAll;
		case NATS_DELIVER_LAST:             return js_DeliverLast;
		case NATS_DELIVER_NEW:              return js_DeliverNew;
		case NATS_DELIVER_LAST_PER_SUBJECT: return js_DeliverLastPerSubject;
		case NATS_DELIVER_BY_START_SEQ:     return js_DeliverByStartSequence;
		case NATS_DELIVER_BY_START_TIME:    return js_DeliverByStartTime;
	}
	return js_DeliverAll;
}

static jsAckPolicy map_ack_policy(nats_ack_policy_e p)
{
	switch (p) {
		case NATS_ACK_EXPLICIT: return js_AckExplicit;
		case NATS_ACK_NONE:     return js_AckNone;
		case NATS_ACK_ALL:      return js_AckAll;
	}
	return js_AckExplicit;
}

static jsReplayPolicy map_replay_policy(nats_replay_policy_e p)
{
	switch (p) {
		case NATS_REPLAY_INSTANT:  return js_ReplayInstant;
		case NATS_REPLAY_ORIGINAL: return js_ReplayOriginal;
	}
	return js_ReplayInstant;
}

/* ── helpers ─────────────────────────────────────────────────── */

/* Return NULL-terminated const char * from a str, or NULL if the str
 * is empty.  nats.c expects NUL-terminated C strings in its config
 * structs; registry str buffers are not guaranteed to be NUL-terminated,
 * so we allocate a process-local copy for each subscription we set up.
 * Since subscriptions are long-lived (one per handle for the life of
 * the process), pointers are kept alive on the proc_sub_state_t and
 * freed by the retire/reap teardown path. */
static char *str_to_cstr(const str *s)
{
	char *out;
	if (!s || s->len <= 0 || !s->s)
		return NULL;
	out = (char *)malloc((size_t)s->len + 1);
	if (!out)
		return NULL;
	memcpy(out, s->s, s->len);
	out[s->len] = '\0';
	return out;
}

static int dup_str_local(str *dst, const str *src)
{
	dst->s = (char *)malloc((size_t)src->len);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}

/* Match a proc-sub state by handle IDENTITY (the unique per-claim index),
 * NOT by id string.  Ids are reused on unbind+rebind, so an id match could
 * return a different (old or new) handle's sub; the index is unique among
 * live + retired-not-yet-reaped handles. */
static proc_sub_state_t *find_sub_by_index(uint16_t index)
{
	proc_sub_state_t *s;
	for (s = g_subs; s; s = s->next) {
		if (s->handle_idx == index)
			return s;
	}
	return NULL;
}

/* Free all the malloc'd C-strings / arrays we stashed on ss during
 * ensure_subscription_for_handle().  nats.c's jsConsumerConfig holds
 * borrowed pointers for the life of the subscription; the retire/reap
 * teardown path calls us once the subscription is destroyed.
 *
 * Leaves ss itself alive -- caller decides whether to free the struct
 * (on full teardown) or to clear the slots for recreation (on an
 * ephemeral consumer rebuild). */
static void free_proc_sub_strings(proc_sub_state_t *ss)
{
	int i;
	if (!ss)
		return;

	free(ss->c_durable);     ss->c_durable     = NULL;
	free(ss->c_filter);      ss->c_filter      = NULL;
	free(ss->c_stream);      ss->c_stream      = NULL;
	free(ss->c_domain);      ss->c_domain      = NULL;
	free(ss->c_api_prefix);  ss->c_api_prefix  = NULL;
	free(ss->c_sample_freq); ss->c_sample_freq = NULL;

	free(ss->backoff_arr);   ss->backoff_arr   = NULL;

	if (ss->filters_arr) {
		for (i = 0; i < ss->filters_arr_len; i++)
			free((void *)ss->filters_arr[i]);
		free(ss->filters_arr);
		ss->filters_arr     = NULL;
		ss->filters_arr_len = 0;
	}
}

/* ── subscription setup ──────────────────────────────────────── */

/*
 * Create a pull subscription for `h` if this process has not already
 * done so.  Succeeds idempotently: if we already have a proc_sub_state
 * for this id, returns 0 without touching the server.
 *
 * The c-string fields passed into nats.c config structs are stashed
 * on the proc_sub_state_t (see str_to_cstr comment) and freed by the
 * retire/reap teardown path when the subscription is destroyed.
 */
/* Parse a comma-separated list of durations into an allocated
 * `int64_t` array of nanoseconds.  Returns 0 on success and fills
 * `*out_arr` and `*out_len`; returns -1 on parse error.  Called only
 * when `csv` is non-empty.  The returned array is malloc'd (NOT SHM);
 * the caller owns it and should treat it as consumer-process-local
 * (freed by the retire/reap teardown path when the sub is destroyed).
 *
 * Grammar matches nats_handle_parse's duration syntax:
 *   <int>(ms|s|m|h|d), no suffix = ms.
 */
static int parse_backoff_csv(const str *csv, int64_t **out_arr, int *out_len)
{
	int64_t *arr = NULL;
	int      n = 0, cap = 0;
	const char *p = csv->s;
	const char *end = csv->s + csv->len;

	*out_arr = NULL;
	*out_len = 0;
	if (csv->len <= 0) return 0;

	while (p < end) {
		const char *tok_end;
		int tok_len;
		long long v = 0;
		int i = 0, digits = 0;
		long long mult;

		/* skip leading ws + commas */
		while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
			p++;
		if (p >= end) break;

		tok_end = memchr(p, ',', end - p);
		if (!tok_end) tok_end = end;
		tok_len = (int)(tok_end - p);
		/* trim trailing ws */
		while (tok_len > 0 &&
		       (p[tok_len-1] == ' ' || p[tok_len-1] == '\t'))
			tok_len--;
		if (tok_len == 0) { p = tok_end; continue; }

		while (i < tok_len && p[i] >= '0' && p[i] <= '9') {
			v = v * 10 + (p[i] - '0');
			digits++;
			i++;
			/* clamp to keep v * mult * 1e6 within int64; INT64_MAX/1e6
			 * is ~9.2e12 ms, well past any sane backoff. */
			if (v > 9000000000000LL) { free(arr); return -1; }
		}
		if (!digits) { free(arr); return -1; }

		if (i == tok_len)                                 mult = 1LL;
		else if (i + 2 == tok_len && p[i]=='m' && p[i+1]=='s') mult = 1LL;
		else if (i + 1 == tok_len && p[i]=='s') mult = 1000LL;
		else if (i + 1 == tok_len && p[i]=='m') mult = 60LL * 1000LL;
		else if (i + 1 == tok_len && p[i]=='h') mult = 60LL*60LL*1000LL;
		else if (i + 1 == tok_len && p[i]=='d') mult = 24LL*60LL*60LL*1000LL;
		else { free(arr); return -1; }

		/* Reject if conversion to nanoseconds would overflow int64. */
		if (mult > 0 && v > INT64_MAX / mult / 1000000LL) {
			free(arr);
			return -1;
		}

		if (n == cap) {
			int newcap = cap ? cap * 2 : 8;
			int64_t *tmp = (int64_t *)realloc(arr,
				sizeof(int64_t) * (size_t)newcap);
			if (!tmp) { free(arr); return -1; }
			arr = tmp;
			cap = newcap;
		}
		arr[n++] = v * mult * 1000000LL;   /* ms -> ns */

		p = tok_end;
	}

	*out_arr = arr;
	*out_len = n;
	return 0;
}

/* Parse a comma-separated list of filter subjects into an allocated
 * `const char **` array.  Returns 0 and fills `*out_arr` + `*out_len`;
 * returns -1 on OOM.  Each element and the array are malloc'd; the
 * retire/reap teardown path frees them when the subscription is
 * destroyed. */
static int parse_filters_csv(const str *csv,
                             const char ***out_arr, int *out_len)
{
	const char **arr = NULL;
	int n = 0, cap = 0;
	const char *p = csv->s;
	const char *end = csv->s + csv->len;

	*out_arr = NULL;
	*out_len = 0;
	if (csv->len <= 0) return 0;

	while (p < end) {
		const char *tok_end;
		int tok_len;
		char *dup;

		while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
			p++;
		if (p >= end) break;

		tok_end = memchr(p, ',', end - p);
		if (!tok_end) tok_end = end;
		tok_len = (int)(tok_end - p);
		while (tok_len > 0 &&
		       (p[tok_len-1] == ' ' || p[tok_len-1] == '\t'))
			tok_len--;
		if (tok_len == 0) { p = tok_end; continue; }

		dup = (char *)malloc((size_t)tok_len + 1);
		if (!dup) goto oom;
		memcpy(dup, p, tok_len);
		dup[tok_len] = '\0';

		if (n == cap) {
			int newcap = cap ? cap * 2 : 4;
			const char **tmp = (const char **)realloc(arr,
				sizeof(const char *) * (size_t)newcap);
			if (!tmp) { free(dup); goto oom; }
			arr = tmp;
			cap = newcap;
		}
		arr[n++] = dup;
		p = tok_end;
	}

	*out_arr = arr;
	*out_len = n;
	return 0;

oom:
	{
		int i;
		for (i = 0; i < n; i++) free((void *)arr[i]);
	}
	free(arr);
	return -1;
}

static int ensure_subscription_for_handle(nats_handle_t *h)
{
	proc_sub_state_t *ss;
	jsConsumerConfig  cc;
	jsSubOptions      so;
	jsOptions         js_opts;
	jsOptions        *js_opts_p = NULL;
	natsStatus        s;
	char             *durable_c     = NULL;
	char             *filter_c      = NULL;
	char             *stream_c      = NULL;
	char             *sample_freq_c = NULL;
	char             *domain_c      = NULL;
	char             *api_prefix_c  = NULL;
	int64_t          *backoff_arr   = NULL;
	int               backoff_len   = 0;
	const char      **filters_arr   = NULL;
	int               filters_len   = 0;
	int               is_rebuild    = 0;

	if (!h || !h->ring)
		return 0;   /* handle still being constructed or TEST_SHIM */

	/* Dirty handles refresh in place -- the sub was destroyed
	 * on the epoch bump or on a fetch-time "consumer vanished" error,
	 * and we now rebuild the natsSubscription while keeping the
	 * proc_sub_state_t (and its counters) intact. */
	ss = find_sub_by_index(h->index);
	if (ss) {
		if (!ss->dirty)
			return 0;   /* clean + already subscribed */
		/* Rebuild path: free any strings we allocated last time so
		 * we can stash fresh ones below.  The old natsSubscription
		 * has already been destroyed by whoever set dirty. */
		free_proc_sub_strings(ss);
		ss->sub = NULL;
		is_rebuild = 1;
		if (h->type == NATS_CONSUMER_EPHEMERAL) {
			LM_DBG("nats_consumer_proc: re-creating ephemeral "
				"consumer for %.*s\n",
				(int)h->id.len, h->id.s);
		} else {
			LM_DBG("nats_consumer_proc: refreshing subscription for "
				"%.*s (epoch bump)\n",
				(int)h->id.len, h->id.s);
		}
	} else {
		ss = (proc_sub_state_t *)calloc(1, sizeof(*ss));
		if (!ss) {
			LM_ERR("nats_consumer_proc: proc_sub_state calloc failed\n");
			return -1;
		}
		if (dup_str_local(&ss->id, &h->id) < 0) {
			LM_ERR("nats_consumer_proc: id dup failed\n");
			free(ss);
			return -1;
		}
		ss->ring       = h->ring;
		ss->handle_idx = h->index;
		ss->h_ref      = h;
	}

	/* Pre-size the ref row so pull_one_batch doesn't pay for the
	 * first-use allocation under load.
	 *
	 * The ref-row capacity must be at least max_ack_pending: the broker
	 * may deliver that many messages before any acks come back, and
	 * each delivery occupies one ref slot until acked.  Sizing from
	 * ring_capacity alone (an earlier design) caused
	 * msg-ref-table-full drops at any handle where max_ack_pending >
	 * ring_capacity, which then triggered ack_wait redeliveries and
	 * stalled the ack floor at the broker.
	 *
	 * Take max(ring_capacity, max_ack_pending) -- ring_capacity is the
	 * worker-visible buffer; max_ack_pending is the broker's in-flight
	 * cap; the ref table needs to span the larger of the two.  When
	 * max_ack_pending is unset (0 = "unlimited"), fall back to
	 * ring_capacity. */
	{
		uint32_t ref_cap = nats_ring_capacity(h->ring);
		if (h->max_ack_pending > 0 &&
		    (uint32_t)h->max_ack_pending > ref_cap)
			ref_cap = (uint32_t)h->max_ack_pending;
		if (ensure_row(h->index, ref_cap) < 0) {
			LM_ERR("nats_consumer_proc: ref-row init failed for "
				"id='%.*s'\n", h->id.len, h->id.s);
			if (!is_rebuild) {
				free(ss->id.s);
				free(ss);
			}
			return -1;
		}
	}
	/* Build jsConsumerConfig with the full handle-config matrix. */
	nats_dl.jsConsumerConfig_Init(&cc);

	durable_c    = str_to_cstr(&h->durable);
	filter_c     = str_to_cstr(&h->filter);
	stream_c     = str_to_cstr(&h->stream);
	domain_c     = str_to_cstr(&h->js_domain);
	api_prefix_c = str_to_cstr(&h->api_prefix);

	/* Render sample_freq as a string -- nats.c expects a C string here,
	 * e.g. "25" for 25% sampling.  Only set when the script supplied
	 * a non-zero value; zero means "disabled / don't sample".
	 *
	 * Buffer sized for any 32-bit int (max -2147483648 = 11 chars + NUL),
	 * not the validated 0..100 range, so gcc -Wformat-truncation is
	 * satisfied without relying on cross-translation-unit value tracking. */
	if (h->sample_freq > 0) {
		sample_freq_c = (char *)malloc(12);
		if (sample_freq_c)
			snprintf(sample_freq_c, 12, "%d", h->sample_freq);
	}

	if (h->type == NATS_CONSUMER_DURABLE && durable_c)
		cc.Durable = durable_c;
	if (filter_c)
		cc.FilterSubject = filter_c;

	/* Multi-filter: nats.c 3.13 exposes FilterSubjects (array) +
	 * FilterSubjectsLen.  Only honored when single-subject FilterSubject
	 * is unset -- the broker rejects the combination.  We parse the CSV
	 * at subscription time rather than keeping it pre-split in SHM so
	 * the parser output stays simple. */
	if (h->filters_csv.len > 0) {
		if (parse_filters_csv(&h->filters_csv,
				&filters_arr, &filters_len) < 0) {
			LM_ERR("nats_consumer_proc: filters= oom/parse failure "
				"for id='%.*s'\n", h->id.len, h->id.s);
			goto fail_free_sub;
		}
		if (filter_c && filters_len > 0) {
			LM_WARN("nats_consumer_proc: both filter= and filters= set "
				"for id='%.*s'; ignoring multi-filter list\n",
				h->id.len, h->id.s);
		} else if (filters_len > 0) {
			cc.FilterSubjects    = filters_arr;
			cc.FilterSubjectsLen = filters_len;
		}
	}

	cc.DeliverPolicy  = map_deliver_policy(h->deliver_policy);
	cc.AckPolicy      = map_ack_policy(h->ack_policy);
	cc.ReplayPolicy   = map_replay_policy(h->replay_policy);

	/* ack_wait / max_deliver / max_ack_pending (ns vs unit-less in nats.c) */
	if (h->ack_wait_ms > 0)
		cc.AckWait = (int64_t)h->ack_wait_ms * 1000000LL;
	if (h->max_deliver > 0)
		cc.MaxDeliver = (int64_t)h->max_deliver;
	if (h->max_ack_pending > 0)
		cc.MaxAckPending = (int64_t)h->max_ack_pending;

	/* Backoff: nats.c takes int64_t[] in nanoseconds.  Drop in on top
	 * of MaxDeliver; the broker honours whichever CSV length we ship. */
	if (h->backoff_csv.len > 0) {
		if (parse_backoff_csv(&h->backoff_csv,
				&backoff_arr, &backoff_len) < 0) {
			LM_ERR("nats_consumer_proc: backoff= parse failed for "
				"id='%.*s'\n", h->id.len, h->id.s);
			goto fail_free_sub;
		}
		if (backoff_len > 0) {
			cc.BackOff    = backoff_arr;
			cc.BackOffLen = backoff_len;
		}
	}

	if (h->deliver_policy == NATS_DELIVER_BY_START_SEQ)
		cc.OptStartSeq = h->start_seq;
	if (h->deliver_policy == NATS_DELIVER_BY_START_TIME)
		cc.OptStartTime = h->start_time_unix_ns;

	/* Replay-flood guard: a durable consumer that vanished (deleted server
	 * side / GC'd) and is being recreated with deliver_policy=all would
	 * otherwise replay the ENTIRE stream from sequence 1 -- a flood
	 * proportional to stream size.  If we have already delivered messages,
	 * bias the recreate to resume just past the last one instead. */
	if (is_rebuild && ss && ss->last_stream_seq > 0 &&
	    h->deliver_policy == NATS_DELIVER_ALL) {
		LM_WARN("nats_consumer_proc: recreating consumer '%.*s' with "
			"deliver_policy=all would replay the whole stream; biasing "
			"to resume from stream_seq %llu\n",
			(int)h->id.len, h->id.s,
			(unsigned long long)(ss->last_stream_seq + 1));
		cc.DeliverPolicy = js_DeliverByStartSequence;
		cc.OptStartSeq   = ss->last_stream_seq + 1;
	}

	/* Shaping + ephemeral options.  nats.c uses ns for InactiveThreshold. */
	if (h->inactive_threshold_ms > 0)
		cc.InactiveThreshold =
			(int64_t)h->inactive_threshold_ms * 1000000LL;
	if (h->rate_limit_bps > 0)
		cc.RateLimit = (uint64_t)h->rate_limit_bps;
	if (sample_freq_c)
		cc.SampleFrequency = sample_freq_c;
	if (h->headers_only)
		cc.HeadersOnly = true;

	if (h->replay_policy == NATS_REPLAY_ORIGINAL) {
		LM_INFO("nats_consumer_proc: id='%.*s' replay_policy=original; "
			"historical replay may introduce multi-second idle gaps "
			"between messages and is not a correctness issue\n",
			h->id.len, h->id.s);
	}

	nats_dl.jsSubOptions_Init(&so);
	so.Stream    = stream_c;
	so.Config    = cc;
	/* We drive acks ourselves via the worker-driven ack-IPC path,
	 * not via nats.c's auto-ack. */
	so.ManualAck = true;

	/* Multi-env: when js_domain / api_prefix are set, build a per-call
	 * jsOptions and hand it to js_PullSubscribe.  nats.c uses
	 * jsOptions.Domain to route API calls to a mirror / leaf domain and
	 * jsOptions.Prefix to override the default "$JS.API" prefix when a
	 * site has a custom gateway. */
	if (domain_c || api_prefix_c) {
		nats_dl.jsOptions_Init(&js_opts);
		if (domain_c)     js_opts.Domain = domain_c;
		if (api_prefix_c) js_opts.Prefix = api_prefix_c;
		js_opts_p = &js_opts;
	}

	/* nats.c 3.10's js_PullSubscribe has no public multi-filter form:
	 * the public signature only takes a single `subject` string, and the
	 * library's internal _subscribeMulti validator rejects
	 *   ((numSubjects <= 0) || empty(subjects[0])) && !consBound
	 * with NATS_INVALID_ARG, even when Config.FilterSubjects is populated.
	 *
	 * Workaround: when FilterSubjects is in play we
	 *   1. js_AddConsumer up-front with the full config so the broker
	 *      materializes the multi-filter consumer (falling back to
	 *      js_UpdateConsumer if the consumer already exists with a
	 *      compatible config from a prior run);
	 *   2. flip jsSubOptions into the consBound branch (so.Stream +
	 *      so.Consumer) so js_PullSubscribe takes the "attach to existing
	 *      consumer" path instead of trying to create one from an empty
	 *      subject and a `Config.FilterSubject` it cannot use.
	 *
	 * Single-filter pull subscribe stays on the original direct path.
	 */
	if (!filter_c && cc.FilterSubjectsLen > 0 && durable_c) {
		jsConsumerInfo *ci_tmp = NULL;
		natsStatus      cs;

		cs = nats_dl.js_AddConsumer(&ci_tmp, g_js, stream_c, &cc,
			js_opts_p, NULL);
		if (cs != NATS_OK) {
			natsStatus us;
			us = nats_dl.js_UpdateConsumer(&ci_tmp, g_js, stream_c, &cc,
				js_opts_p, NULL);
			if (us != NATS_OK) {
				LM_ERR("nats_consumer_proc: nats_dl.js_AddConsumer('%.*s')"
					" failed: %s (update also %s)\n",
					h->id.len, h->id.s,
					nats_dl.natsStatus_GetText(cs),
					nats_dl.natsStatus_GetText(us));
				goto fail_free_sub;
			}
		}
		if (ci_tmp)
			nats_dl.jsConsumerInfo_Destroy(ci_tmp);

		/* In the bound path nats.c does not consult so.Config; it
		 * looks up the existing consumer via Stream + Consumer. */
		so.Consumer = durable_c;

		s = nats_dl.js_PullSubscribe(&ss->sub, g_js,
			"" /* subject empty: bound path uses opts->Consumer */,
			NULL /* durable NULL: same reason */,
			js_opts_p,
			&so,
			NULL);
	} else {
		s = nats_dl.js_PullSubscribe(&ss->sub, g_js,
			filter_c /* may be NULL when Config has FilterSubject */,
			durable_c /* may be NULL for ephemeral */,
			js_opts_p,
			&so,
			NULL);
	}
	if (s != NATS_OK) {
		LM_ERR("nats_consumer_proc: nats_dl.js_PullSubscribe('%.*s') failed: %s\n",
			h->id.len, h->id.s, nats_dl.natsStatus_GetText(s));
		goto fail_free_sub;
	}

	ss->last_fetch = 0;
	ss->dirty      = 0;
	if (!is_rebuild) {
		ss->next = g_subs;
		g_subs = ss;
		if (ss->handle_idx < NATS_REGISTRY_MAX_HANDLES)
			g_subs_by_idx[ss->handle_idx] = ss;
	}

	/* Stash the allocations on ss so the retire / rebuild paths can
	 * free them without leaking.  nats.c has borrowed pointers into
	 * these for the life of the subscription, so they must outlive
	 * the nats_dl.natsSubscription_Destroy() call but NOT the
	 * proc_sub_state_t itself. */
	ss->c_durable       = durable_c;
	ss->c_filter        = filter_c;
	ss->c_stream        = stream_c;
	ss->c_domain        = domain_c;
	ss->c_api_prefix    = api_prefix_c;
	ss->c_sample_freq   = sample_freq_c;
	ss->backoff_arr     = backoff_arr;
	ss->filters_arr     = filters_arr;
	ss->filters_arr_len = filters_len;

	/* Publish the subscription pointer back to the handle so MI can
	 * introspect it (read-only).  This is a process-local pointer the
	 * SIP workers must not dereference; they just observe non-NULL as
	 * "consumer process has a live sub". */
	h->subscription = (void *)ss->sub;

	LM_INFO("nats_consumer_proc: %s id='%.*s' index=%u "
		"stream='%.*s' filter='%.*s' durable='%.*s' filters_n=%d "
		"backoff_n=%d domain='%s' prefix='%s'\n",
		is_rebuild ? "refreshed" : "subscribed",
		h->id.len, h->id.s, (unsigned)h->index,
		h->stream.len, h->stream.s,
		h->filter.len, h->filter.s,
		h->durable.len, h->durable.s,
		filters_len, backoff_len,
		domain_c ? domain_c : "",
		api_prefix_c ? api_prefix_c : "");

	return 0;

fail_free_sub:
	{
		int i;
		for (i = 0; i < filters_len; i++) free((void *)filters_arr[i]);
	}
	free(filters_arr);
	free(backoff_arr);
	free(sample_freq_c);
	free(domain_c);
	free(api_prefix_c);
	free(durable_c);
	free(filter_c);
	free(stream_c);
	/* On rebuild failure, keep the proc_sub_state_t on g_subs but
	 * leave dirty=1 so the next reconcile tick retries.  Reset any
	 * partially filled string slots (we freed the locals above, so
	 * the ss-> copies must not point at stale memory).  On first-bind
	 * failure, free the struct since it never landed on g_subs. */
	if (is_rebuild) {
		ss->c_durable     = NULL;
		ss->c_filter      = NULL;
		ss->c_stream      = NULL;
		ss->c_domain      = NULL;
		ss->c_api_prefix  = NULL;
		ss->c_sample_freq = NULL;
		ss->backoff_arr   = NULL;
		ss->filters_arr     = NULL;
		ss->filters_arr_len = 0;
		return -1;
	}
	free(ss->id.s);
	free(ss);
	return -1;
}

/* Exponential backoff for ensure_subscription_for_handle() failures.
 *
 * Capped at 60 s -- long enough that a wedged handle (e.g. broker-side
 * durable deleted by an operator) stops dominating tick CPU and log
 * noise, short enough that a transient broker outage clears within a
 * minute of recovery.  The shift on `failures` saturates harmlessly
 * once it exceeds the unsigned width, but the cap fires long before
 * that ever matters. */
#define ENSURE_BACKOFF_CAP_S 60u

static unsigned ensure_backoff_seconds(unsigned failures)
{
	unsigned shift;
	if (failures == 0)
		return 0;
	shift = failures - 1;
	if (shift >= 6)            /* 1<<6 = 64 > cap; saturate */
		return ENSURE_BACKOFF_CAP_S;
	return 1u << shift;
}

static int reconcile_subs_cb(nats_handle_t *h, void *user)
{
	time_t now;
	int    rc;

	(void)user;
	/* Skip retired handles -- the teardown path owns them now.
	 * A retired handle is already off its bucket chain so registry
	 * foreach should not surface it, but defense-in-depth against a
	 * race where unbind fires between the foreach-global-lock
	 * acquisition and the bucket-lock acquisition. */
	if (__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST))
		return 0;

	/* Backoff gate: a handle whose ensure_subscription_for_handle()
	 * has been failing keeps getting visited every reconcile tick,
	 * but we only actually retry once `ensure_next_retry_at` has
	 * elapsed.  Keeps a wedged handle from sucking IDLE_RETRY_MS of
	 * CPU per tick and flooding the log with the same "Error (update
	 * also Error)" line. */
	now = time(NULL);
	if (h->ensure_next_retry_at != 0 && now < h->ensure_next_retry_at)
		return 0;

	rc = ensure_subscription_for_handle(h);
	if (rc == 0) {
		/* Success or no-op (clean + already subscribed).  Either way,
		 * the broker is happy -- reset the backoff so the next failure
		 * starts at the 1 s base.  Only logs the recovery transition
		 * to avoid spamming every tick of a stable handle. */
		if (h->ensure_failures > 0) {
			LM_INFO("nats_consumer_proc: handle '%.*s' recovered after "
			        "%u failed ensure attempt(s)\n",
			        (int)h->id.len, h->id.s, h->ensure_failures);
		}
		h->ensure_failures = 0;
		h->ensure_next_retry_at = 0;
	} else {
		unsigned wait_s;
		h->ensure_failures++;
		wait_s = ensure_backoff_seconds(h->ensure_failures);
		h->ensure_next_retry_at = now + (time_t)wait_s;
		/* Log the saturation transition once so operators see when a
		 * handle has truly wedged versus when the backoff is still
		 * climbing -- the WARN at the cap is the signal to inspect or
		 * unbind. */
		if (h->ensure_failures == 7) {
			LM_WARN("nats_consumer_proc: handle '%.*s' has failed "
			        "ensure_subscription %u times; backoff now capped "
			        "at %u s.  Likely broker-side consumer was deleted; "
			        "run `nats_consumer_unbind` to clear or recreate the "
			        "durable.\n",
			        (int)h->id.len, h->id.s, h->ensure_failures,
			        ENSURE_BACKOFF_CAP_S);
		}
	}
	return 0;
}

/* ── header serialization ────────────────────────────────────── */

/*
 * Serialize the headers of `m` into `out[]` using the compact stream
 * format documented on nats_ring_slot_t.headers[]:
 *     [u16 count]
 *     repeated:  [u16 key_len][key][u16 val_len][val]
 *
 * All sizes are host-order uint16 (the ring lives in SHM shared
 * between forked workers of this process, so no endian conversion is
 * necessary).  Multi-valued keys are flattened: each value becomes a
 * separate entry with the same key.  Binary / NUL bytes in values are
 * preserved because we write `strlen(value)` and copy the bytes
 * verbatim -- nats.c does not document binary-safe headers, so this is
 * a best effort.
 *
 * Returns:
 *    the number of bytes written to `out[]` on success (0 when there
 *    were no headers to serialize -- not an error).
 *    `*truncated` is set to 1 iff at least one header was dropped
 *    because the output would have exceeded `out_cap`; the surviving
 *    prefix is still valid.
 *    `*count_out` receives the number of headers actually written.
 *
 * The count field is patched after the fact once we know how many
 * headers survived truncation.
 */
static int serialize_headers(natsMsg *m, char *out, int out_cap,
                             int *truncated, int *count_out)
{
	const char * *keys   = NULL;
	int           nkeys  = 0;
	natsStatus    s;
	int           pos    = 0;
	int           count  = 0;
	int           i;
	int           trunc  = 0;

	*truncated = 0;
	*count_out = 0;

	if (!m || !out || out_cap < 2)
		return 0;

	/* Reserve the count prefix; patched after the loop. */
	pos = 2;

	s = nats_dl.natsMsgHeader_Keys(m, &keys, &nkeys);
	if (s != NATS_OK || !keys || nkeys <= 0) {
		/* No headers -- still emit the zero count so the stream is
		 * valid.  Callers that see headers_len == 2 know the message
		 * carried no headers but was inspected. */
		out[0] = 0;
		out[1] = 0;
		if (keys) free((void *)keys);
		return 2;
	}

	for (i = 0; i < nkeys; i++) {
		const char * *vals = NULL;
		int           nvals = 0;
		natsStatus    vs;
		int           j;
		int           klen;

		if (!keys[i])
			continue;
		klen = (int)strlen(keys[i]);
		if (klen <= 0 || klen > 0xFFFF)
			continue;

		vs = nats_dl.natsMsgHeader_Values(m, keys[i], &vals, &nvals);
		if (vs != NATS_OK || !vals || nvals <= 0) {
			if (vals) free((void *)vals);
			continue;
		}

		for (j = 0; j < nvals; j++) {
			int  vlen;
			int  need;

			if (!vals[j]) continue;
			vlen = (int)strlen(vals[j]);
			if (vlen < 0 || vlen > 0xFFFF) continue;
			/* 2 (klen) + klen + 2 (vlen) + vlen */
			need = 2 + klen + 2 + vlen;
			if (pos + need > out_cap) {
				/* No room for this entry or any more; mark truncated
				 * and stop.  Header order is not specified by the
				 * NATS protocol so we don't try to skip-ahead. */
				trunc = 1;
				goto done_vals;
			}

			out[pos++] = (char)(klen & 0xFF);
			out[pos++] = (char)((klen >> 8) & 0xFF);
			memcpy(out + pos, keys[i], klen); pos += klen;
			out[pos++] = (char)(vlen & 0xFF);
			out[pos++] = (char)((vlen >> 8) & 0xFF);
			if (vlen) memcpy(out + pos, vals[j], vlen);
			pos += vlen;
			count++;
			if (count >= 0xFFFF) {
				/* u16 ceiling -- cannot encode more headers even if
				 * we had room.  Unlikely in practice but guard for
				 * correctness. */
				trunc = 1;
				goto done_vals;
			}
		}
done_vals:
		free((void *)vals);
		if (trunc)
			break;
	}

	free((void *)keys);

	out[0] = (char)(count & 0xFF);
	out[1] = (char)((count >> 8) & 0xFF);
	*truncated = trunc;
	*count_out = count;
	return pos;
}

/* ── fetch loop ──────────────────────────────────────────────── */

static int pull_one_batch(proc_sub_state_t *ss, int budget_ms)
{
	natsMsgList  list;
	natsStatus   s;
	int          pushed = 0;
	int          i;

	if (!ss || !ss->sub || !ss->ring)
		return 0;

	/* In-use guard: hold a pending_ops reference across the blocking
	 * Fetch() + push loop so unbind can defer while we're mid-pull.
	 * Paired with the dec below. */
	nats_handle_pending_inc(ss->h_ref);

	/* Dynamic batch sizing: never request more than will fit in the
	 * ring's free slots.  Prior to this, a static fetch_batch larger
	 * than the worker's drain rate would push messages until the ring
	 * filled, then defer-drop the surplus.  Dropped messages are not
	 * acked, the broker holds them as outstanding, ack_wait expires,
	 * the broker redelivers under a NEW consumer-seq, and any later
	 * worker-driven ack of the original consumer-seq is rejected as
	 * stale -- which is what stalled the broker ack-floor at small N
	 * for fetch_batch in (16..64).
	 *
	 * Clamp to free slots so the Fetch never produces a defer-drop on
	 * push.  When the ring is completely full, skip the Fetch entirely
	 * and let the worker drain first; the next consumer-process loop
	 * iteration will re-evaluate.  This is pure flow-control: the
	 * un-fetched messages remain owned by the broker and are delivered
	 * cleanly on the next pull.
	 *
	 * Subtract one from depth so we always leave headroom for the
	 * generation-bump invariant in the ring's CAS push path. */
	{
		uint32_t cap     = nats_ring_capacity(ss->ring);
		uint32_t depth   = nats_ring_depth(ss->ring);
		int      max_fb  = eff_fetch_batch(ss->h_ref);
		int      free_sl = (cap > depth) ? (int)(cap - depth) : 0;
		int      eff_fb;

		if (free_sl <= 1) {
			/* Ring full: skip the Fetch entirely.  No message is
			 * touched -- the broker keeps the un-fetched messages and
			 * redelivers them next pull.  This is flow control, not a
			 * drop, so it has its own counter. */
			hstat_add(ss->h_ref, &ss->h_ref->fetch_skips_full, 1);
			goto out;
		}
		eff_fb = (max_fb < free_sl) ? max_fb : (free_sl - 1);
		if (eff_fb < 1)
			eff_fb = 1;

		int tmo = eff_fetch_timeout_ms(ss->h_ref);
		/* Cap the per-fetch wait to the caller's budget so a sweep over
		 * many idle handles cannot block acks / async RPCs for
		 * num_handles * fetch_timeout (head-of-line blocking). */
		if (budget_ms > 0 && budget_ms < tmo)
			tmo = budget_ms;

		memset(&list, 0, sizeof(list));
		hstat_add(ss->h_ref, &ss->h_ref->pulls_requested, 1);
		s = nats_dl.natsSubscription_Fetch(&list, ss->sub,
		        eff_fb, tmo, NULL);
	}

	/* Fast path on idle: timeout is the steady-state condition when
	 * the broker has nothing to send us. */
	if (s == NATS_TIMEOUT)
		goto out;

	if (s == NATS_CONNECTION_CLOSED) {
		LM_DBG("nats_consumer_proc: connection closed during fetch "
			"on id='%.*s'\n", ss->id.len, ss->id.s);
		/* The outer loop's epoch check will observe the reconnect
		 * when the library reconnects and will flip ss->dirty then. */
		goto out;
	}

	/* Ephemeral-GC / subscription-invalidated detection.
	 *
	 * NATS_NOT_FOUND comes back when JetStream has GC'd the consumer
	 * past its inactive_threshold (the common ephemeral-GC case).
	 * NATS_INVALID_SUBSCRIPTION means the nats.c subscription object
	 * has gone into a bad state (e.g. after a server-initiated close).
	 * In both cases the right thing is to destroy the subscription
	 * and flag it dirty so the next reconcile tick rebuilds it.
	 * Ephemeral consumers get a brand-new server-side id on recreate
	 * (see the rebuild log line in ensure_subscription_for_handle). */
	if (s == NATS_NOT_FOUND || s == NATS_INVALID_SUBSCRIPTION) {
		LM_INFO("nats_consumer_proc: consumer for %.*s vanished (%s); "
			"will recreate\n",
			ss->id.len, ss->id.s, nats_dl.natsStatus_GetText(s));
		if (ss->sub) {
			nats_dl.natsSubscription_Unsubscribe(ss->sub);
			nats_dl.natsSubscription_Destroy(ss->sub);
			ss->sub = NULL;
		}
		ss->dirty = 1;
		hstat_add(ss->h_ref, &ss->h_ref->fetch_errors, 1);
		goto out;
	}

	if (s != NATS_OK && list.Count == 0) {
		/* Non-fatal per-sub error; log at DBG to avoid flooding logs
		 * when e.g. max_ack_pending gates us out. */
		hstat_add(ss->h_ref, &ss->h_ref->fetch_errors, 1);
		LM_DBG("nats_consumer_proc: fetch id='%.*s': %s\n",
			ss->id.len, ss->id.s, nats_dl.natsStatus_GetText(s));
		goto out;
	}

	ss->last_fetch = time(NULL);

	for (i = 0; i < list.Count; i++) {
		natsMsg    *m = list.Msgs[i];
		const char *subject;
		const char *data;
		const char *reply;
		int         data_len;
		size_t      subject_len;
		size_t      reply_len;

		jsMsgMetaData *md = NULL;
		uint64_t  stream_seq   = 0;
		uint64_t  consumer_seq = 0;
		uint64_t  delivered    = 0;
		uint64_t  pending      = 0;
		int64_t   timestamp_ns = 0;
		uint64_t  ack_token    = 0;
		int       ref_ok       = 0;

		char     hdr_buf[NATS_RING_HEADERS_MAX];
		int      hdr_len       = 0;
		int      hdr_truncated = 0;
		int      hdr_count     = 0;

		int rc;

		if (!m)
			continue;

		subject     = nats_dl.natsMsg_GetSubject(m);
		data        = nats_dl.natsMsg_GetData(m);
		data_len    = nats_dl.natsMsg_GetDataLength(m);
		reply       = nats_dl.natsMsg_GetReply(m);
		subject_len = subject ? strlen(subject) : 0;
		reply_len   = reply   ? strlen(reply)   : 0;

		/* JetStream pull-delivered messages have nats_dl.natsMsg_GetReply()
		 * set to the per-delivery $JS.ACK.<...> subject for ack
		 * tracking, NOT to the publisher's application reply.  Acks
		 * are dispatched separately via the ref-table token, so the
		 * ACK subject is not useful to the script via $nats_reply_to.
		 *
		 * The original publisher's application reply is preserved by
		 * convention in the Nats-Reply-To header (set by the
		 * publisher with `nats pub -H 'Nats-Reply-To: <inbox>'` or
		 * the equivalent SDK call).  For JS-delivered messages we
		 * extract that header and surface it as the reply; without
		 * it, the message has no application reply destination. */
		if (reply_len >= 8 &&
		    memcmp(reply, "$JS.ACK.", 8) == 0) {
			const char *hdr_reply = NULL;
			natsStatus  hs;

			hs = nats_dl.natsMsgHeader_Get(m, "Nats-Reply-To", &hdr_reply);
			if (hs == NATS_OK && hdr_reply != NULL) {
				reply     = hdr_reply;
				reply_len = (int)strlen(hdr_reply);
			} else {
				reply     = NULL;
				reply_len = 0;
			}
		}

		/* Serialize headers into the per-message stack buffer; ring_push
		 * copies the bytes into the slot so this local array's lifetime
		 * ends with the loop iteration. */
		hdr_len = serialize_headers(m, hdr_buf, (int)sizeof(hdr_buf),
			&hdr_truncated, &hdr_count);
		if (hdr_truncated) {
			LM_DBG("nats_consumer_proc: headers truncated on id='%.*s' "
				"(count_emitted=%d cap=%d)\n",
				ss->id.len, ss->id.s,
				hdr_count, (int)sizeof(hdr_buf));
		}

		if (nats_dl.natsMsg_GetMetaData(&md, m) == NATS_OK && md) {
			stream_seq   = md->Sequence.Stream;
			consumer_seq = md->Sequence.Consumer;
			delivered    = md->NumDelivered;
			pending      = md->NumPending;
			timestamp_ns = md->Timestamp;
			nats_dl.jsMsgMetaData_Destroy(md);
			/* Track the high-water stream sequence so a
			 * vanished+recreated durable can resume past it. */
			if (stream_seq > ss->last_stream_seq)
				ss->last_stream_seq = stream_seq;
		}

		/* Stash the natsMsg under a fresh (handle, slot, gen) token.
		 * On ref-table exhaustion we leave the broker to redeliver --
		 * not acking this message means it comes back after
		 * ack_wait, by which time workers will (hopefully) have
		 * caught up on their ack backlog. */
		ack_token = store_msg_ref(ss->handle_idx,
			nats_ring_capacity(ss->ring), m, &ref_ok);
		if (!ref_ok) {
			/* msg-ref table exhausted: the message was fetched but
			 * can't be tracked for ack, so leave it un-acked and let
			 * the broker redeliver after ack_wait. */
			hstat_add(ss->h_ref, &ss->h_ref->backpressure_drops, 1);
			nats_dl.natsMsg_Destroy(m);
			list.Msgs[i] = NULL;
			continue;
		}

		rc = nats_ring_push(ss->ring,
			subject ? subject : "", (uint32_t)subject_len,
			data    ? data    : "", (uint32_t)data_len,
			stream_seq, consumer_seq, delivered, pending,
			timestamp_ns, ack_token,
			reply   ? reply   : "", (uint32_t)reply_len,
			hdr_len > 0 ? hdr_buf : NULL,
			(uint16_t)(hdr_len > 0 ? hdr_len : 0),
			(uint8_t)(hdr_truncated ? 1 : 0));

		if (rc == 0) {
			pushed++;
			hstat_add(ss->h_ref, &ss->h_ref->msgs_delivered, 1);
			if (delivered > 1)
				hstat_add(ss->h_ref, &ss->h_ref->redeliveries, 1);
			/* natsMsg stays alive in the ref table until the worker
			 * sends an ack IPC.  Do NOT destroy it here. */
			list.Msgs[i] = NULL;
		} else if (rc == -1) {
			/* Ring full: release the ref slot and do NOT ack.
			 * Broker redelivers after ack_wait. */
			(void)release_msg_ref(ack_token);
			hstat_add(ss->h_ref, &ss->h_ref->backpressure_drops, 1);
			LM_DBG("nats_consumer_proc: ring full id='%.*s', "
				"deferring message\n",
				ss->id.len, ss->id.s);
			nats_dl.natsMsg_Destroy(m);
			list.Msgs[i] = NULL;
		} else {
			/* -2 / -3: payload or subject too large.  These are
			 * permanently undeliverable on the current ring
			 * geometry; terminate the message so the broker
			 * doesn't redeliver forever.  Release the ref slot
			 * first so we don't leak it on retry. */
			(void)release_msg_ref(ack_token);
			/* This is a permanent Term, not back-pressure -- it is
			 * counted via the per-handle `terms` counter below, so do
			 * not also fold it into backpressure_drops. */
			LM_WARN("nats_consumer_proc: oversize message on "
				"id='%.*s' (subject_len=%zu data_len=%d rc=%d); "
				"terminating\n",
				ss->id.len, ss->id.s,
				subject_len, data_len, rc);
			(void)nats_dl.natsMsg_Term(m, NULL);
			hstat_add(ss->h_ref, &ss->h_ref->terms, 1);
			nats_dl.natsMsg_Destroy(m);
			list.Msgs[i] = NULL;
		}
	}

	/* natsMsgList_Destroy walks the Msgs array and destroys any
	 * non-NULL entries; we've already consumed (or destroyed) ours
	 * above, so this just frees the Msgs array itself. */
	nats_dl.natsMsgList_Destroy(&list);

out:
	nats_handle_pending_dec(ss->h_ref);
	return pushed;
}

/* ── ack IPC drain ───────────────────────────────────────────── */

/* Per-drain cookie: counts acks applied and tracks which handle
 * indices saw an ACK_NEXT so the outer loop can prioritize pulling
 * from them on the same iteration. */
typedef struct drain_ack_ctx {
	int      count;
	uint64_t next_bits[(NATS_REGISTRY_MAX_HANDLES + 63) / 64];
} drain_ack_ctx_t;

static inline void next_bits_set(drain_ack_ctx_t *c, uint16_t handle_idx)
{
	if (handle_idx < NATS_REGISTRY_MAX_HANDLES)
		c->next_bits[handle_idx / 64] |= (uint64_t)1 << (handle_idx % 64);
}

static inline int next_bits_test(const drain_ack_ctx_t *c,
                                 uint16_t handle_idx)
{
	if (handle_idx >= NATS_REGISTRY_MAX_HANDLES) return 0;
	return (c->next_bits[handle_idx / 64] >> (handle_idx % 64)) & 1;
}

static void drain_ack_ipc_cb(const nats_ack_ipc_msg_t *m, void *user)
{
	natsMsg    *nmsg;
	natsStatus  s;
	drain_ack_ctx_t *ctx = (drain_ack_ctx_t *)user;
	uint16_t           h_idx = nats_ack_token_handle(m->ack_token);
	proc_sub_state_t  *cb_ss = (h_idx < NATS_REGISTRY_MAX_HANDLES)
	                          ? g_subs_by_idx[h_idx] : NULL;
	nats_handle_t     *cb_h  = cb_ss ? cb_ss->h_ref : NULL;

	nmsg = release_msg_ref(m->ack_token);
	if (!nmsg) {
		/* Stale or already-released.  release_msg_ref logged at DBG. */
		return;
	}

	switch ((nats_ack_action_e)m->action) {
		case NATS_ACK_ACTION_ACK:
			s = nats_dl.natsMsg_Ack(nmsg, NULL);
			if (s == NATS_OK)
				hstat_add(cb_h, &cb_h->acks, 1);
			break;
		case NATS_ACK_ACTION_ACK_NEXT:
			/* nats.c 3.13 does not expose the server's +NXT ack-and-pull
			 * payload via the public API, so we fall back to:
			 *   1) synchronous ack (so the broker has definitively seen
			 *      the ack before we ask for a refill), and
			 *   2) flag the originating handle in the drain context so
			 *      the outer loop runs an extra pull_one_batch() for it
			 *      on this tick rather than waiting for the next idle
			 *      wake-up.
			 * This matches the user-observable semantics of +NXT
			 * (finish the current message and immediately hand me the
			 * next one) without depending on library internals. */
			s = nats_dl.natsMsg_AckSync(nmsg, NULL, NULL);
			if (s == NATS_OK)
				hstat_add(cb_h, &cb_h->acks, 1);
			if (ctx)
				next_bits_set(ctx, h_idx);
			break;
		case NATS_ACK_ACTION_NAK:
			s = nats_dl.natsMsg_Nak(nmsg, NULL);
			if (s == NATS_OK)
				hstat_add(cb_h, &cb_h->naks, 1);
			break;
		case NATS_ACK_ACTION_NAK_DELAY:
			s = nats_dl.natsMsg_NakWithDelay(nmsg,
				(int64_t)m->delay_ms * 1000000LL, NULL);
			if (s == NATS_OK)
				hstat_add(cb_h, &cb_h->naks, 1);
			break;
		case NATS_ACK_ACTION_TERM:
			s = nats_dl.natsMsg_Term(nmsg, NULL);
			if (s == NATS_OK)
				hstat_add(cb_h, &cb_h->terms, 1);
			break;
		case NATS_ACK_ACTION_IN_PROGRESS:
			s = nats_dl.natsMsg_InProgress(nmsg, NULL);
			/* in_progress does NOT finalize the message; we must
			 * keep it alive.  Put it back in the ref table under
			 * the same token (same handle, slot, and generation). */
			{
				uint16_t handle_idx =
					nats_ack_token_handle(m->ack_token);
				uint32_t slot_idx =
					nats_ack_token_slot(m->ack_token);
				uint16_t gen =
					nats_ack_token_generation(m->ack_token);
				msg_ref_slot_t *slot;
				if (handle_idx < NATS_REGISTRY_MAX_HANDLES &&
				    g_msg_refs[handle_idx].slots &&
				    slot_idx < g_msg_refs[handle_idx].capacity) {
					slot = &g_msg_refs[handle_idx].slots[slot_idx];
					slot->msg        = nmsg;
					slot->in_use     = 1;
					slot->generation = gen;
					if (ctx)
						ctx->count++;
					return;
				}
				/* Fall through to destroy if somehow invalid. */
			}
			break;
		default:
			LM_WARN("nats_consumer_proc: unknown ack action %u for "
				"token=0x%016lx\n",
				(unsigned)m->action,
				(unsigned long)m->ack_token);
			s = NATS_OK;
			break;
	}

	if (s != NATS_OK) {
		LM_DBG("nats_consumer_proc: ack action=%u token=0x%016lx "
			"returned %s\n",
			(unsigned)m->action, (unsigned long)m->ack_token,
			nats_dl.natsStatus_GetText(s));
	}

	nats_dl.natsMsg_Destroy(nmsg);
	if (ctx)
		ctx->count++;
}

static int drain_ack_ipc(drain_ack_ctx_t *ctx)
{
	int n;
	n = nats_ack_ipc_drain(drain_ack_ipc_cb, ctx);
	(void)n;   /* currently logged only if ack_count differs, but
	            * they should match -- kept for future MI metrics */
	return ctx->count;
}

/* Read the ack eventfd counter to rearm the reactor-ish select().
 * The eventfd is edge-signaled on empty->non-empty; one read clears
 * the counter irrespective of how many enqueues coalesced. */
static void drain_ack_eventfd(int fd)
{
	uint64_t sink;
	ssize_t r;
	if (fd < 0)
		return;
	do {
		r = read(fd, &sink, sizeof(sink));
	} while (r < 0 && errno == EINTR);
}

/* ── retire teardown ─────────────────────────────────────────── */

/*
 * Walk g_subs and tear down any proc_sub_state_t whose underlying
 * handle is (a) gone from the registry entirely, or (b) still in the
 * registry but with retire=1.  For case (b) we set sub_torn_down on
 * the handle so nats_registry_reap() can free it; for case (a) the
 * handle was already freed by a parallel teardown path, so we just
 * drop our ss.
 *
 * Must NOT be called while iterating g_subs via another pointer --
 * it mutates the list.  The main loop calls this after the pull /
 * drain phases complete so the iteration pointers have gone out of
 * scope.
 */
static void tear_down_retired_subs(void)
{
	proc_sub_state_t **pp = &g_subs;

	while (*pp) {
		proc_sub_state_t *ss = *pp;
		/* Resolve the handle by IDENTITY (the pointer stashed at ss
		 * creation), not by id string.  An id-keyed weak lookup would
		 * return a freshly-rebound handle of the same id (retire==0) and
		 * we'd never tear down the old retired one it actually belongs
		 * to.  ss->h_ref is safe to deref here: while ss is on g_subs its
		 * handle has not been reaped (reap requires sub_torn_down, which
		 * only this teardown sets — and it then removes ss). */
		nats_handle_t *h = ss->h_ref;

		int should_tear_down = 0;
		if (!h) {
			/* Defensive: no handle reference (should not happen for a
			 * created ss).  Tear down the proc-local state only. */
			should_tear_down = 1;
		} else if (__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST)) {
			should_tear_down = 1;
		}

		if (!should_tear_down) {
			pp = &(*pp)->next;
			continue;
		}

		LM_INFO("nats_consumer_proc: tearing down retired "
			"subscription id='%.*s'\n",
			ss->id.len, ss->id.s);

		if (ss->sub) {
			nats_dl.natsSubscription_Unsubscribe(ss->sub);
			nats_dl.natsSubscription_Destroy(ss->sub);
			ss->sub = NULL;
		}

		/* Free the C-strings and arrays we stashed when we built
		 * the natsSubscription. */
		free_proc_sub_strings(ss);

		/*
		 * Reclaim the process-local msg-ref row for this handle.  After
		 * the subscription is destroyed no more acks can arrive for it,
		 * but messages that were pushed to the ring and not yet acked
		 * still hold a live natsMsg* in g_msg_refs[handle_idx].slots[*].
		 * Normally those are released + destroyed on the ack drain path
		 * (release_msg_ref + nats_dl.natsMsg_Destroy); here we must walk
		 * the row ourselves, destroy every in-use natsMsg, then free the
		 * row's slots buffer (calloc'd in ensure_row) and zero the row.
		 * handle_idx is monotonic and never reused, so leaving the row
		 * populated would leak both the slots buffer and the libnats
		 * messages for the lifetime of the process.
		 */
		if (ss->handle_idx < NATS_REGISTRY_MAX_HANDLES) {
			msg_ref_row_t *row = &g_msg_refs[ss->handle_idx];
			if (row->slots) {
				uint32_t i;
				for (i = 0; i < row->capacity; i++) {
					msg_ref_slot_t *slot = &row->slots[i];
					if (slot->in_use && slot->msg) {
						nats_dl.natsMsg_Destroy(slot->msg);
						slot->msg    = NULL;
						slot->in_use = 0;
					}
				}
				free(row->slots);
			}
			row->slots     = NULL;
			row->capacity  = 0;
			row->next_slot = 0;
		}

		if (h) {
			/* Publish the teardown completion so the reaper can
			 * free the handle.  This store MUST happen AFTER the
			 * subscription destroy + string free so the reaper sees
			 * a fully torn-down handle if it observes sub_torn_down=1. */
			__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		}

		*pp = ss->next;
		if (ss->handle_idx < NATS_REGISTRY_MAX_HANDLES &&
		    g_subs_by_idx[ss->handle_idx] == ss)
			g_subs_by_idx[ss->handle_idx] = NULL;

		/* Clear the handle's subscription publish pointer; the handle
		 * may still be on the retire list (not yet reaped) and MI
		 * could observe it.  Do this AFTER the sub_torn_down store
		 * above so there's no window where sub_torn_down=1 but the
		 * handle->subscription pointer still looks live. */
		if (h)
			h->subscription = NULL;

		free(ss->id.s);
		free(ss);
	}
}

/*
 * Mark retired handles that never got a subscription as torn down.
 *
 * tear_down_retired_subs() above only walks g_subs, so a handle that was
 * bound and then unbound before the consumer process ever built a
 * subscription for it has no g_subs entry -- its sub_torn_down is never
 * set, the reaper never frees it, and its ring (allocated at bind time)
 * leaks for the process lifetime.  Walk the registry's retire list and set
 * sub_torn_down on any retired handle that has no live proc-sub state.
 */
static int mark_orphan_retired_cb(nats_handle_t *h, void *user)
{
	(void)user;
	if (!h)
		return 0;
	/* Already torn down (or handled by the g_subs pass) -- nothing to do. */
	if (__atomic_load_n(&h->sub_torn_down, __ATOMIC_SEQ_CST))
		return 0;
	/* A live proc-sub state means the g_subs teardown pass owns this
	 * handle; only handles with NO g_subs entry were never subscribed. */
	if (h->index < NATS_REGISTRY_MAX_HANDLES &&
	    g_subs_by_idx[h->index] != NULL)
		return 0;
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	LM_INFO("nats_consumer_proc: marking never-subscribed retired handle "
		"id='%.*s' torn down so it can be reaped\n",
		h->id.len, h->id.s);
	return 0;
}

static void mark_orphan_retired_handles(void)
{
	nats_registry_foreach_retired(mark_orphan_retired_cb, NULL);
}

/* ── main loop ───────────────────────────────────────────────── */

void nats_consumer_proc_main(int rank)
{
	int ack_fd;
	int retry_fd;
	int baseline_epoch;

	LM_INFO("nats_consumer_proc: starting (pid=%d rank=%d)\n",
		(int)getpid(), rank);

	/* Acquire the NATS connection + JetStream context.  Do NOT return on
	 * failure: an unexpected exit of this dedicated process is fatal to
	 * the whole OpenSIPS instance, so a broker that is merely down at boot
	 * would otherwise take the entire SIP server down with it.  Retry
	 * until the broker is reachable instead.  nats_pool_get() re-attempts
	 * its bounded internal connect on each call while the connection is
	 * unset, so repeated calls are safe; the sleep is interrupted by
	 * SIGTERM so shutdown remains prompt. */
	{
		int attempt = 0;
		const int boot_retry_s = 2;
		for (;;) {
			g_nc = nats_pool_get();
			if (g_nc) {
				g_js = nats_pool_get_js();
				if (g_js)
					break;
				LM_WARN("nats_consumer_proc: NATS connected but no "
					"JetStream context (attempt %d); retrying in "
					"%ds instead of exiting\n",
					++attempt, boot_retry_s);
			} else {
				LM_WARN("nats_consumer_proc: no NATS connection "
					"(broker down?, attempt %d); retrying in %ds "
					"instead of exiting (an exit would abort the "
					"instance)\n", ++attempt, boot_retry_s);
			}
			sleep(boot_retry_s);
		}
	}

	ack_fd = nats_ack_ipc_fd();
	baseline_epoch = nats_pool_get_reconnect_epoch();

	/* Blocking-idle timerfd -- armed each idle round to cap how long
	 * we sleep when there is no worker ack traffic.  If timerfd_create
	 * fails we fall back to a coarse 1s select() timeout. */
	retry_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (retry_fd < 0) {
		LM_WARN("nats_consumer_proc: timerfd_create failed (%s); "
			"falling back to 1s select timeout\n", strerror(errno));
	}

	/* Async nats_request: stand up the persistent inbox
	 * subscription so worker-issued RPCs can route their
	 * publish + reply through this process (libnats-safe
	 * context) instead of running directly in the SIP worker
	 * (libnats-unsafe context).  Non-fatal: if the subscribe
	 * fails the IPC drain below will surface -3 to each
	 * pending slot. */
	if (nats_rpc_consumer_subscribe() < 0) {
		LM_WARN("nats_consumer_proc: async inbox subscribe "
			"failed; async nats_request RPCs that arrive on "
			"the IPC will be marked abandoned\n");
	}

	LM_INFO("nats_consumer_proc: pool ready, ack_fd=%d retry_fd=%d, "
		"baseline_epoch=%d, entering main loop\n",
		ack_fd, retry_fd, baseline_epoch);

	if (nats_consumer_hb) {
		atomic_store_explicit(&nats_consumer_hb->consumer_pid,
			(int)getpid(), memory_order_relaxed);
		nats_consumer_hb_tick();
	}

	long long last_reap_us = _now_monotonic_us();

	for (;;) {
		nats_consumer_hb_tick();
		proc_sub_state_t *ss;
		int any_work = 0;
		int cur_epoch;

		/* Periodically reclaim msg-ref slots orphaned by workers that
		 * died after popping a message but before acking (otherwise the
		 * per-handle table fills and delivery stalls). */
		{
			long long now = _now_monotonic_us();
			if (now - last_reap_us >= NATS_MSG_REF_REAP_INTERVAL_US) {
				reap_orphan_msg_refs();
				last_reap_us = now;
			}
		}

		/* 0. Reconnect-epoch check.  The nats.c library bumps
		 *    the epoch from its reconnect callback (on a library
		 *    thread); here we observe the bump and mark every live
		 *    subscription dirty so the next reconcile pass rebuilds
		 *    them.  Destroying the old subs immediately avoids the
		 *    "ghost subscription held against a new connection"
		 *    failure mode where nats.c has internally re-plumbed
		 *    everything but our old Subscription* still points at a
		 *    dead context. */
		cur_epoch = nats_pool_get_reconnect_epoch();
		if (cur_epoch != baseline_epoch) {
			LM_INFO("nats_consumer_proc: reconnect detected "
				"(epoch %d -> %d); refreshing all subscriptions\n",
				baseline_epoch, cur_epoch);
			for (ss = g_subs; ss; ss = ss->next) {
				if (ss->sub) {
					nats_dl.natsSubscription_Unsubscribe(ss->sub);
					nats_dl.natsSubscription_Destroy(ss->sub);
					ss->sub = NULL;
				}
				ss->dirty = 1;
			}
			baseline_epoch = cur_epoch;
		}

		/* 1. Reconcile subscriptions with the registry.  New binds
		 *    land here on the next tick; dirty subs are rebuilt in
		 *    place. */
		(void)nats_registry_foreach(reconcile_subs_cb, NULL);

		/* 2. Fetch + push for every live subscription.  A ring-full
		 *    handle contributes 0 to any_work so the idle sleep
		 *    applies and we don't burn CPU spinning on it.
		 *
		 *    The per-fetch wait is budgeted by the number of handles so
		 *    the whole sweep stays bounded at ~one fetch_timeout instead
		 *    of num_handles * fetch_timeout, and the latency-sensitive
		 *    async-RPC publish IPC is drained between fetches so an RPC
		 *    isn't stuck behind a sweep of idle handles. */
		{
			int num_subs = 0, budget;
			for (ss = g_subs; ss; ss = ss->next)
				num_subs++;
			budget = fetch_budget_ms(nats_consumer_fetch_timeout_ms,
				num_subs);
			for (ss = g_subs; ss; ss = ss->next) {
				int pushed = pull_one_batch(ss, budget);
				if (pushed > 0)
					any_work = 1;
				if (num_subs > 1) {
					int rpcs = nats_rpc_consumer_drain_ipc();
					if (rpcs > 0)
						any_work = 1;
				}
			}
		}

		/* 3. Service pending ack requests.  Drain the eventfd
		 *    counter first so the next edge wakes us again; then
		 *    drain the IPC queue.  The order matters: reading the
		 *    counter BEFORE draining the queue is a rendez-vous
		 *    against the producer-side race where an enqueue
		 *    happens right between the two steps -- we simply see
		 *    it on the next iteration. */
		if (ack_fd >= 0) {
			struct timeval tv;
			fd_set rfds;
			int sr;

			/* Non-blocking poll of the ack fd.  We already polled
			 * nats for up to fetch_timeout above, so here we only
			 * check whether acks arrived during that window. */
			FD_ZERO(&rfds);
			FD_SET(ack_fd, &rfds);
			tv.tv_sec  = 0;
			tv.tv_usec = 0;
			sr = select(ack_fd + 1, &rfds, NULL, NULL, &tv);
			if (sr > 0 && FD_ISSET(ack_fd, &rfds)) {
				drain_ack_eventfd(ack_fd);
			}
		}
		{
			drain_ack_ctx_t ctx;
			int acks;
			memset(&ctx, 0, sizeof(ctx));
			acks = drain_ack_ipc(&ctx);
			if (acks > 0)
				any_work = 1;

			/* ACK_NEXT fallback: any handle that got an ack-and-pull
			 * hint on this tick gets an extra pull_one_batch() right
			 * now, without waiting for the next outer iteration.  This
			 * is the fallback for the missing +NXT payload API. */
			for (ss = g_subs; ss; ss = ss->next) {
				if (next_bits_test(&ctx, ss->handle_idx)) {
					/* ack-and-pull hint: the next message is likely
					 * already waiting, so use the full timeout (0 = no
					 * cap) -- this is not part of the idle sweep. */
					int pushed = pull_one_batch(ss, 0);
					if (pushed > 0)
						any_work = 1;
				}
			}
		}

		/* 3.5 Async nats_request: drain the worker ->
		 *     consumer publish IPC.  For each entry the helper
		 *     reads the slot's out_* fields and PublishMsg's
		 *     against our libnats connection with reply-to
		 *     pointing back at our persistent inbox.  Replies
		 *     land in on_inbox_reply (running on the libnats
		 *     thread, also in this process) which writes
		 *     reply_* + signals the slot's wake_fd. */
		{
			int rpcs = nats_rpc_consumer_drain_ipc();
			if (rpcs > 0)
				any_work = 1;
		}

		/* 4. Retire/reap lifecycle: tear down subscriptions whose
		 *    handles are retiring, then reap any fully-drained handles.
		 *    Running these every iteration keeps the unbind latency
		 *    bounded (worst case: one iteration delay between unbind
		 *    and reap).  Both are cheap when the retire list is
		 *    empty. */
		tear_down_retired_subs();
		mark_orphan_retired_handles();
		nats_registry_reap();

		if (!any_work) {
			/* Blocking idle: wait until either the ack IPC eventfd
			 * becomes readable (a worker acked something), the
			 * async RPC IPC eventfd becomes readable (a worker
			 * issued an async nats_request), or the retry
			 * timerfd fires (bounded stall recovery).  Avoids a
			 * busy poll so the consumer process spends ~0% CPU
			 * on empty subscriptions. */
			fd_set rfds;
			int    maxfd = ack_fd;
			int    rpc_fd = nats_rpc_ipc_fd();
			struct timeval tv;

			FD_ZERO(&rfds);
			if (ack_fd >= 0) FD_SET(ack_fd, &rfds);
			if (rpc_fd >= 0) {
				FD_SET(rpc_fd, &rfds);
				if (rpc_fd > maxfd) maxfd = rpc_fd;
			}

			if (retry_fd >= 0) {
				struct itimerspec its;
				memset(&its, 0, sizeof(its));
				its.it_value.tv_sec  = IDLE_RETRY_MS / 1000;
				its.it_value.tv_nsec =
					(IDLE_RETRY_MS % 1000) * 1000000L;
				if (timerfd_settime(retry_fd, 0, &its, NULL) == 0) {
					FD_SET(retry_fd, &rfds);
					if (retry_fd > maxfd) maxfd = retry_fd;
				}
			}

			tv.tv_sec  = 1;
			tv.tv_usec = 0;
			(void)select(maxfd + 1, &rfds, NULL, NULL, &tv);

			/* Drain the retry timer so the next arm is fresh. */
			if (retry_fd >= 0 && FD_ISSET(retry_fd, &rfds)) {
				uint64_t sink;
				ssize_t r;
				do {
					r = read(retry_fd, &sink, sizeof(sink));
				} while (r < 0 && errno == EINTR);
			}

			/* Drain the async RPC IPC eventfd so the next
			 * empty -> non-empty edge wakes us again.  The
			 * actual queue is drained on the next loop
			 * iteration via nats_rpc_consumer_drain_ipc(). */
			if (rpc_fd >= 0 && FD_ISSET(rpc_fd, &rfds)) {
				uint64_t sink;
				ssize_t r;
				do {
					r = read(rpc_fd, &sink, sizeof(sink));
				} while (r < 0 && errno == EINTR);
			}
		}
	}
}
