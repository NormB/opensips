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
 * ============================================================================
 *  IMPORTANT -- READ BEFORE TOUCHING THIS FILE
 * ----------------------------------------------------------------------------
 *  This translation unit contains TWO distinct things; only the second is
 *  wired into production:
 *
 *   (A) The per-worker inbox-subscription async-RPC state machine -- the
 *       ctx hash table, ensure_inbox_subscription(), on_inbox_reply(),
 *       nats_rpc_async_deliver(), nats_rpc_async_child_init(), and the
 *       refcount/lifecycle primitives documented just below.  This was the
 *       ORIGINAL async transport: it runs a libnats subscription directly
 *       on each SIP worker and dispatches replies from libnats's own
 *       thread.  It is **TEST-ONLY / SUPERSEDED**.  Production no longer
 *       wires it up -- nats_consumer.c::child_init() does NOT call
 *       nats_rpc_async_child_init(), and nothing in the live path calls
 *       ensure_inbox_subscription() or nats_rpc_async_deliver().  It is
 *       retained solely because the unit tests
 *       (tests/test_async_request_inflight.c, test_header_propagation.c)
 *       link and exercise the pure state machine under -DTEST_SHIM.
 *
 *       DO NOT wire nats_rpc_async_child_init() (or any other entry into
 *       this state machine) into child_init or the request path.  Running
 *       a libnats subscription on a SIP worker is exactly the pattern that
 *       crashes libnats 3.x on aarch64 (see nats_rpc_async.h) -- it was
 *       replaced for that reason.
 *
 *   (B) w_nats_request_async() at the bottom of this file -- the LIVE
 *       async acmd entry point registered by nats_consumer.c.  It does NOT
 *       use the inbox-subscription machinery above; it uses the
 *       consumer-routed SHM-slot transport (nats_rpc_slot.c +
 *       nats_rpc_ipc.c, serviced in the consumer process by
 *       nats_rpc_consumer.c) and yields the worker on a private timerfd.
 *       No libnats subscription is ever created on a worker.
 *
 *  The big architecture comment immediately below describes subsystem (A)
 *  for historical / test context.
 * ============================================================================
 */

/*
 * nats_rpc_async.c -- async entry point for nats_request.
 *
 * Implements a non-blocking JetStream/core NATS request/reply RPC
 * that yields the worker on an eventfd while the reply is in
 * flight, instead of blocking on nats_dl.natsConnection_RequestMsg().
 *
 * Architecture:
 *
 *   1.  Per-worker persistent inbox subscription.  The first async
 *       call from a worker subscribes once to the wildcard subject
 *       `_INBOX.opensips.<pid>.>`.  The libnats library spawns its
 *       own thread to dispatch matches to on_inbox_reply().  The
 *       subscription survives reconnect (lib/nats's pool handles
 *       resubscription) and is torn down at module shutdown.
 *
 *   2.  Per-call correlation + eventfd.  Every async call assigns a
 *       monotonic correlation id (<pid>.<counter>) and an eventfd.
 *       The full reply subject is `_INBOX.opensips.<pid>.<corr>`.
 *       Workers register the eventfd with the OpenSIPS reactor and
 *       yield; the libnats callback writes one byte to the eventfd
 *       when the reply lands.
 *
 *   3.  Process-local in-flight hash table.  Open-chained, indexed
 *       by correlation suffix.  The libnats callback looks up the
 *       ctx by suffix, transfers ownership of the slot, populates
 *       the reply buffers, and signals the eventfd.
 *
 * Lifecycle and refcount discipline (the only correctness-critical
 * piece of this module).  Every ctx carries a small refcount and a
 * per-ctx mutex.  Two threads can touch a single ctx -- the worker
 * (start path + resume) and the libnats subscription thread (reply
 * callback); the refcount guarantees the last toucher frees.
 *
 *   alloc                : refcount = 1  (held by caller)
 *   ht_insert            : refcount++   (held by hash slot)
 *   ht_take_for_callback : transfers hash's ref to caller; slot=NULL
 *   ht_take_for_resume   : transfers hash's ref to caller; slot=NULL
 *   ctx_release          : refcount-- ; if 0 -> free
 *
 * Net invariant: the sum of refs held by (resume_param, hash slot,
 * inflight callback) is the ctx's refcount.  Whichever thread
 * decrements last frees the struct.
 *
 * Reply / timeout race: the resume function may fire on the
 * eventfd, on a timer, or both nearly-simultaneously.  Decisions
 * are made by inspecting ctx->state under the per-ctx mutex, not
 * by the async-core's was_timeout flag -- a state of REPLIED wins
 * regardless of why we were woken up.  A pure-timeout (no reply
 * ever arrived) is observed as state == INFLIGHT under the mutex,
 * which we then promote to ABANDONED before releasing the hash's
 * ref.
 *
 * Scope: this file implements the steady-state happy path, the
 * timeout path, the callback/timeout race resolution, and
 * connection-drop detection (the resume path returns -2 if the
 * pool's reconnect epoch changed mid-flight, distinguishing a
 * broker crash from a clean timeout).
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
/* Stub libnats types -- the test driver never enters the libnats
 * glue; only the state machine is exercised. */
typedef struct _stub_natsMsg          natsMsg;
typedef struct _stub_natsConnection   natsConnection;
typedef struct _stub_natsSubscription natsSubscription;
typedef int                            natsStatus;
#define NATS_OK 0
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../async.h"
#include "../../lib/list.h"
#include "../../lib/nats/nats_pool.h"
#include <nats/nats.h>
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/random.h>

#include "nats_rpc.h"
#include "nats_ring.h"          /* NATS_RING_*_MAX caps */
#include "nats_rpc_async.h"
#include "nats_rpc_slot.h"
#include "nats_rpc_ipc.h"

/* ── tunables ─────────────────────────────────────────────────── */

/* Number of buckets in the in-flight table (process-local).  Power
 * of two is not strictly required (we hash & mod) but bias to one
 * anyway because we use a mask.  Sized to comfortably exceed any
 * realistic per-worker in-flight depth without breaking chaining. */
#ifndef NATS_RPC_ASYNC_HT_BUCKETS
#define NATS_RPC_ASYNC_HT_BUCKETS 1024u
#endif

/* Hard ceiling on simultaneous in-flight async requests per worker.
 * The start path rejects with -5 when this is exceeded so callers
 * can implement back-pressure; the default is generous enough that
 * a healthy responder will never come close. */
#ifndef NATS_RPC_ASYNC_MAX_INFLIGHT
#define NATS_RPC_ASYNC_MAX_INFLIGHT 4096
#endif

/* Inbox prefix.  The full subject any worker subscribes to is
 *   "<prefix>.<pid>.>"
 * and a per-call reply subject is
 *   "<prefix>.<pid>.<counter>".
 * Kept short to fit comfortably under NATS_RING_SUBJECT_MAX. */
#define NATS_RPC_ASYNC_INBOX_PREFIX "_INBOX.opensips"

/* ── ctx state machine ────────────────────────────────────────── */

/* ctx->state values.  Transitions:
 *   INFLIGHT -> REPLIED      (callback ran)
 *   INFLIGHT -> ABANDONED    (timeout fired before callback)
 * Once REPLIED, no further transitions (the resume function reads
 * the reply and drops the ctx).  ABANDONED is the terminal state
 * for late-callback drops. */
enum {
	NATS_RPC_ASYNC_INFLIGHT = 0,
	NATS_RPC_ASYNC_REPLIED  = 1,
	NATS_RPC_ASYNC_ABANDONED = 2,
};

/*
 * Per-call in-flight context.  Lives in pkg memory (process-local;
 * libnats subscription threads run inside the same worker process).
 * Embedded subject/data/header buffers avoid per-call malloc on the
 * hot path; the ~17 KB per-ctx fits inside one slab and amortises
 * well at typical in-flight counts.
 */
struct nats_rpc_async_ctx {
	struct nats_rpc_async_ctx *next;     /* hash chain link */

	/* identity */
	char     corr_id[32];                /* NUL-terminated */
	int      corr_id_len;

	/* wake-up + reactor handle */
	int      eventfd;

	/* concurrency */
	pthread_mutex_t mu;
	_Atomic int     refcount;
	int             state;               /* NATS_RPC_ASYNC_* */

	/* Pool reconnect-epoch snapshot taken at ctx alloc time.
	 * The resume function compares the snapshot against the
	 * current epoch (and `nats_pool_is_connected()`) to
	 * distinguish a clean timeout (state INFLIGHT, connection
	 * stable) from a connection-lost (state INFLIGHT, epoch
	 * changed OR pool reports disconnected).  Set to 0 under
	 * TEST_SHIM; tests override via
	 * nats_rpc_async_ctx_set_epoch_at_start(). */
	uint32_t        epoch_at_start;

	/* reply payload (populated by callback, consumed by resume) */
	uint32_t reply_subject_len;
	char     reply_subject[NATS_RING_SUBJECT_MAX];
	uint32_t reply_data_len;
	char     reply_data[NATS_RING_PAYLOAD_MAX];
	uint16_t reply_headers_len;
	uint8_t  reply_headers_truncated;
	uint8_t  reply_has_reply_to;
	char     reply_headers[NATS_RING_HEADERS_MAX];
	uint32_t reply_to_len;
	char     reply_to[NATS_RING_SUBJECT_MAX];
};

/* ── globals (per-worker process) ─────────────────────────────── */

static struct nats_rpc_async_ctx *g_ht[NATS_RPC_ASYNC_HT_BUCKETS];
static pthread_mutex_t            g_ht_mu = PTHREAD_MUTEX_INITIALIZER;
static int                        g_inflight_count;

/* Monotonic correlation counter per worker. */
static _Atomic uint64_t g_corr_counter;

/* Cached inbox prefix string `<prefix>.<pid>`.  Stored at first
 * lazy-init so the callback subject parser knows where the suffix
 * starts. */
static char g_inbox_owner[40];
static int  g_inbox_owner_len;

/*
 * Per-worker stash of the most recent outbound request's UUIDv7.
 * Set by both the sync (w_nats_request) and async (w_nats_request_
 * _async) start paths after they mint the correlation id; read by
 * the $nats_request_id pvar getter.  Lives in process memory and
 * persists across an async() yield so the resume route can read
 * it back to correlate the reply against logs / traces / etc.
 * Overwritten on the next nats_request call from this worker;
 * shielded from concurrent updates by the worker single-threading
 * (only the worker thread runs script code).
 *
 * `g_request_id_user_supplied` is the consume-once flag: when set,
 * the next nats_request start path uses `g_last_request_id` as
 * the outbound id instead of minting a fresh UUIDv7.  Cleared by
 * the start path on consumption.  Set by the pvar setter when the
 * script assigns to $nats_request_id.
 *
 * Storage is sized at 64 bytes to comfortably hold any UUID
 * variant plus common trace-id formats (ULIDs, base32 hashes,
 * vendor-prefixed strings) without spilling. */
static char g_last_request_id[64];
static int  g_last_request_id_len;
static int  g_request_id_user_supplied;

#ifndef TEST_SHIM
/* Persistent inbox subscription (one per worker, lazy-initialised
 * on first async request).  Guards: g_inbox_sub_mu serialises the
 * lazy-init; once g_inbox_sub_ready is set, the sub pointer is
 * read-only for the lifetime of the worker. */
static natsSubscription *g_inbox_sub;
static int               g_inbox_sub_ready;
static pthread_mutex_t   g_inbox_sub_mu = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ── helpers ──────────────────────────────────────────────────── */

/* FNV-1a 32-bit on the correlation id.  Cheap and well-distributed
 * for our short integer-like keys. */
static uint32_t fnv1a32(const char *s, int len)
{
	uint32_t h = 2166136261u;
	int i;
	for (i = 0; i < len; i++) {
		h ^= (uint8_t)s[i];
		h *= 16777619u;
	}
	return h;
}

/*
 * Mint a UUIDv7 (RFC 9562 §5.7) into `out`.  `cap` must be >= 37
 * (36 chars + NUL).  Layout:
 *
 *     | unix_ts_ms (48b) | ver (4b) | rand_a (12b) |
 *     | var (2b) | rand_b (62b) |
 *
 * Formatted as 8-4-4-4-12 lowercase hex with version nibble = 7
 * and variant bits = 10b.  Returns the written length (always
 * 36) on success; 0 on truncation or RNG failure.
 *
 * Hot-path cost: one CLOCK_REALTIME read + one getrandom() of 10
 * bytes (the timestamp fills the first 6 bytes).  No allocations.
 *
 * If getrandom() fails (kernel < 3.17 or seccomp restriction)
 * the function returns 0; callers should treat a zero return as
 * "no correlation id available" and skip header staging rather
 * than minting a low-entropy fallback.
 */
int nats_rpc_async_uuidv7_mint(char *out, size_t cap)
{
	struct timespec ts;
	uint64_t ts_ms;
	uint8_t  rand10[10];
	ssize_t  got;
	int      n;

	if (!out || cap < 37) return 0;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	ts_ms = (uint64_t)ts.tv_sec * 1000u +
	        (uint64_t)(ts.tv_nsec / 1000000);

	got = getrandom(rand10, sizeof(rand10), GRND_NONBLOCK);
	if (got != (ssize_t)sizeof(rand10))
		return 0;

	/* Set version nibble (7) in the high nibble of byte 6
	 * (which becomes the first nibble of the third group). */
	rand10[0] = (uint8_t)((rand10[0] & 0x0f) | 0x70);
	/* Set variant bits (10b) in the high two bits of byte 8
	 * (first byte of the fourth group). */
	rand10[2] = (uint8_t)((rand10[2] & 0x3f) | 0x80);

	n = snprintf(out, cap,
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		(unsigned)((ts_ms >> 40) & 0xff),
		(unsigned)((ts_ms >> 32) & 0xff),
		(unsigned)((ts_ms >> 24) & 0xff),
		(unsigned)((ts_ms >> 16) & 0xff),
		(unsigned)((ts_ms >>  8) & 0xff),
		(unsigned)( ts_ms        & 0xff),
		rand10[0], rand10[1],     /* version 7 + 12b rand_a */
		rand10[2], rand10[3],     /* variant 10b + 14b rand_b */
		rand10[4], rand10[5], rand10[6],
		rand10[7], rand10[8], rand10[9]);

	if (n != 36) return 0;
	return n;
}

/*
 * Stash the just-minted (or already-staged) outbound id in the
 * per-worker storage so $nats_request_id can read it back later
 * (including inside the resume route, after the async() yield).
 *
 * Empty input clears the stash.  Caller is responsible for keeping
 * the lifetime of `id` >= the call; we copy.
 */
void nats_rpc_async_request_id_set(const char *id, int len)
{
	if (!id || len <= 0) {
		g_last_request_id[0] = '\0';
		g_last_request_id_len = 0;
		g_request_id_user_supplied = 0;
		return;
	}
	if (len >= (int)sizeof(g_last_request_id))
		len = (int)sizeof(g_last_request_id) - 1;
	memcpy(g_last_request_id, id, len);
	g_last_request_id[len] = '\0';
	g_last_request_id_len = len;
	/* deliberate: callers from start-path use this to record the
	 * just-used id, which is NOT a user-supplied override. */
	g_request_id_user_supplied = 0;
}

const char *nats_rpc_async_request_id_get(int *out_len)
{
	if (out_len) *out_len = g_last_request_id_len;
	return g_last_request_id_len > 0 ? g_last_request_id : NULL;
}

/*
 * Pvar-write entry: the script has assigned to $nats_request_id.
 * Stash the value so the NEXT nats_request call uses it instead
 * of minting a fresh UUIDv7.  Returns 0 on success, -1 if the
 * value is rejected (too long, contains CR/LF, etc.); the
 * setter surfaces -1 to the script.
 *
 * Empty input clears the pending override and the last-used
 * stash (so $nats_request_id then reads NULL until the next
 * mint).
 */
int nats_rpc_async_request_id_user_set(const char *id, int len)
{
	int i;

	if (!id || len <= 0) {
		g_last_request_id[0] = '\0';
		g_last_request_id_len = 0;
		g_request_id_user_supplied = 0;
		return 0;
	}
	if (len >= (int)sizeof(g_last_request_id))
		return -1;
	/* Reject control characters that would break NATS header
	 * serialisation.  Header values per the NATS wire protocol
	 * are CRLF-delimited; embedded CR/LF would inject pseudo-
	 * headers downstream.  No log here; the pvar setter in
	 * nats_rpc.c surfaces a single LM_WARN on the -1 return so
	 * we keep this function dprint-free for the unit-test
	 * shim. */
	for (i = 0; i < len; i++) {
		if (id[i] == '\r' || id[i] == '\n')
			return -1;
	}
	memcpy(g_last_request_id, id, len);
	g_last_request_id[len] = '\0';
	g_last_request_id_len = len;
	g_request_id_user_supplied = 1;
	return 0;
}

/*
 * Start-path consumer: if a user-supplied id is pending, copy it
 * to `out` (cap-sized), clear the pending flag, and return the
 * length copied.  Returns 0 if no user-supplied id is pending --
 * the caller then mints a fresh UUIDv7.
 *
 * Consume-once semantics: the user's assignment is honoured by
 * one nats_request call.  Subsequent calls revert to minting
 * unless the script writes the pvar again.
 */
int nats_rpc_async_request_id_consume_user(char *out, int cap)
{
	if (!g_request_id_user_supplied)
		return 0;
	if (!out || cap <= g_last_request_id_len)
		return 0;
	memcpy(out, g_last_request_id, g_last_request_id_len);
	out[g_last_request_id_len] = '\0';
	g_request_id_user_supplied = 0;
	return g_last_request_id_len;
}

/* ── refcount / release ───────────────────────────────────────── */

void nats_rpc_async_ctx_addref(struct nats_rpc_async_ctx *c)
{
	if (c) atomic_fetch_add_explicit(&c->refcount, 1, memory_order_relaxed);
}

void nats_rpc_async_ctx_release(struct nats_rpc_async_ctx *c)
{
	int prev;
	if (!c) return;
	prev = atomic_fetch_sub_explicit(&c->refcount, 1, memory_order_acq_rel);
	if (prev != 1)
		return;
	/* last reference: tear down. */
	if (c->eventfd >= 0) {
		close(c->eventfd);
		c->eventfd = -1;
	}
	pthread_mutex_destroy(&c->mu);
	pkg_free(c);
}

/* ── hash table primitives (linked-list chaining, mutex protected) ── */

/* Insert ctx into the table.  Caller passes a ctx with refcount=1
 * (held by caller); on success the function bumps the refcount to
 * 2 (caller + hash slot).  Returns 0 on success, -1 on the in-flight
 * cap, -2 on duplicate corr_id (should never happen with the
 * monotonic counter, but defended against). */
static int ht_insert(struct nats_rpc_async_ctx *c)
{
	uint32_t h;
	unsigned idx;
	struct nats_rpc_async_ctx *cur;

	pthread_mutex_lock(&g_ht_mu);
	if (g_inflight_count >= NATS_RPC_ASYNC_MAX_INFLIGHT) {
		pthread_mutex_unlock(&g_ht_mu);
		return -1;
	}
	h = fnv1a32(c->corr_id, c->corr_id_len);
	idx = h % NATS_RPC_ASYNC_HT_BUCKETS;
	for (cur = g_ht[idx]; cur; cur = cur->next) {
		if (cur->corr_id_len == c->corr_id_len &&
		    memcmp(cur->corr_id, c->corr_id, c->corr_id_len) == 0) {
			pthread_mutex_unlock(&g_ht_mu);
			return -2;
		}
	}
	c->next = g_ht[idx];
	g_ht[idx] = c;
	g_inflight_count++;
	nats_rpc_async_ctx_addref(c);   /* hash slot's ref */
	pthread_mutex_unlock(&g_ht_mu);
	return 0;
}

/* Atomically unlink ctx if it is still in the table, transferring
 * the hash's ref to the caller.  Returns 1 if the slot still held
 * the ctx (and caller now owns +1 ref), 0 if the slot was already
 * empty (another path already took the ref).
 *
 * Used by both the resume path (after wake-up / timeout) and the
 * callback's claim step. */
static int ht_take(struct nats_rpc_async_ctx *target)
{
	uint32_t h;
	unsigned idx;
	struct nats_rpc_async_ctx *cur, *prev;

	pthread_mutex_lock(&g_ht_mu);
	h = fnv1a32(target->corr_id, target->corr_id_len);
	idx = h % NATS_RPC_ASYNC_HT_BUCKETS;
	prev = NULL;
	for (cur = g_ht[idx]; cur; cur = cur->next) {
		if (cur == target) {
			if (prev) prev->next = cur->next;
			else      g_ht[idx]  = cur->next;
			cur->next = NULL;
			g_inflight_count--;
			pthread_mutex_unlock(&g_ht_mu);
			/* Caller now owns the transferred ref; do not
			 * decrement here. */
			return 1;
		}
		prev = cur;
	}
	pthread_mutex_unlock(&g_ht_mu);
	return 0;
}

/* Lookup-and-take by corr_id (used by the callback path).  Returns
 * the ctx with its hash ref transferred to the caller, or NULL if
 * not found.  Constant work outside the bucket linked-list scan;
 * collisions on our integer-like corr_ids are essentially zero. */
static struct nats_rpc_async_ctx *ht_lookup_and_take(const char *corr_id,
                                                     int corr_id_len)
{
	uint32_t h;
	unsigned idx;
	struct nats_rpc_async_ctx *cur, *prev;

	if (!corr_id || corr_id_len <= 0)
		return NULL;
	pthread_mutex_lock(&g_ht_mu);
	h = fnv1a32(corr_id, corr_id_len);
	idx = h % NATS_RPC_ASYNC_HT_BUCKETS;
	prev = NULL;
	for (cur = g_ht[idx]; cur; cur = cur->next) {
		if (cur->corr_id_len == corr_id_len &&
		    memcmp(cur->corr_id, corr_id, corr_id_len) == 0) {
			if (prev) prev->next = cur->next;
			else      g_ht[idx]  = cur->next;
			cur->next = NULL;
			g_inflight_count--;
			pthread_mutex_unlock(&g_ht_mu);
			return cur;       /* caller owns hash's ref now */
		}
		prev = cur;
	}
	pthread_mutex_unlock(&g_ht_mu);
	return NULL;
}

/* ── ctx alloc / dispose ──────────────────────────────────────── */

struct nats_rpc_async_ctx *nats_rpc_async_ctx_new(void)
{
	struct nats_rpc_async_ctx *c;
	uint64_t n;
	int written;

	c = pkg_malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));

	c->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (c->eventfd < 0) {
		pkg_free(c);
		return NULL;
	}
	if (pthread_mutex_init(&c->mu, NULL) != 0) {
		close(c->eventfd);
		pkg_free(c);
		return NULL;
	}
	atomic_store_explicit(&c->refcount, 1, memory_order_relaxed);
	c->state = NATS_RPC_ASYNC_INFLIGHT;
	c->epoch_at_start = 0;     /* production path overwrites */

	n = atomic_fetch_add_explicit(&g_corr_counter, 1, memory_order_relaxed);
	written = snprintf(c->corr_id, sizeof(c->corr_id),
		"%lu", (unsigned long)n);
	if (written <= 0 || written >= (int)sizeof(c->corr_id)) {
		pthread_mutex_destroy(&c->mu);
		close(c->eventfd);
		pkg_free(c);
		return NULL;
	}
	c->corr_id_len = written;
	return c;
}

/* ── deliver / timeout state machine ──────────────────────────── */

/* Deliver a reply into the ctx with the matching corr_id.
 *
 * Drives the state machine: hash-lookup-and-take, then under the
 * per-ctx mutex copy the reply bytes in, set state=REPLIED, signal
 * the eventfd, drop the hash's transferred ref.  Late callbacks
 * (resume already ran with was_timeout) return -1 from the lookup
 * step and the caller is expected to discard the payload.
 *
 * Returns 0 if the reply was delivered (ctx will be freed by the
 * resume path); -1 if no matching ctx was found (caller should
 * drop the message).
 *
 * This function is the unit-test entry point: tests call it
 * directly with synthetic reply data to exercise the state machine
 * without the libnats subscription / callback wiring.
 */
int nats_rpc_async_deliver(const char *corr_id, int corr_id_len,
                           const char *reply_subject, int reply_subject_len,
                           const char *reply_data,    int reply_data_len,
                           const char *reply_headers, int reply_headers_len,
                           int reply_headers_truncated,
                           const char *reply_to,      int reply_to_len)
{
	struct nats_rpc_async_ctx *c;
	uint64_t v = 1;
	ssize_t w;

	c = ht_lookup_and_take(corr_id, corr_id_len);
	if (!c)
		return -1;

	pthread_mutex_lock(&c->mu);

	if (reply_subject_len < 0)            reply_subject_len = 0;
	if (reply_subject_len > NATS_RING_SUBJECT_MAX)
		reply_subject_len = NATS_RING_SUBJECT_MAX;
	if (reply_subject && reply_subject_len)
		memcpy(c->reply_subject, reply_subject, reply_subject_len);
	c->reply_subject_len = (uint32_t)reply_subject_len;

	if (reply_data_len < 0)               reply_data_len = 0;
	if (reply_data_len > NATS_RING_PAYLOAD_MAX)
		reply_data_len = NATS_RING_PAYLOAD_MAX;
	if (reply_data && reply_data_len)
		memcpy(c->reply_data, reply_data, reply_data_len);
	c->reply_data_len = (uint32_t)reply_data_len;

	if (reply_headers_len < 0)            reply_headers_len = 0;
	if (reply_headers_len > NATS_RING_HEADERS_MAX)
		reply_headers_len = NATS_RING_HEADERS_MAX;
	if (reply_headers && reply_headers_len)
		memcpy(c->reply_headers, reply_headers, reply_headers_len);
	c->reply_headers_len = (uint16_t)reply_headers_len;
	c->reply_headers_truncated = (uint8_t)(reply_headers_truncated ? 1 : 0);

	if (reply_to_len < 0)                 reply_to_len = 0;
	if (reply_to_len > NATS_RING_SUBJECT_MAX)
		reply_to_len = NATS_RING_SUBJECT_MAX;
	if (reply_to && reply_to_len) {
		memcpy(c->reply_to, reply_to, reply_to_len);
		c->reply_to_len = (uint32_t)reply_to_len;
		c->reply_has_reply_to = 1;
	}

	c->state = NATS_RPC_ASYNC_REPLIED;

	/* Signal the resume path.  The eventfd is in non-blocking
	 * mode; EAGAIN here means an earlier write saturated the
	 * counter, which can't happen on the well-formed callback
	 * path but is benign even if it did (the resume drains on
	 * any read). */
	do {
		w = write(c->eventfd, &v, sizeof(v));
	} while (w < 0 && errno == EINTR);

	pthread_mutex_unlock(&c->mu);

	nats_rpc_async_ctx_release(c);   /* drop hash's transferred ref */
	return 0;
}

/* Promote the ctx to ABANDONED state if it has not yet been
 * REPLIED.  Called by the resume path on a was_timeout dispatch.
 * The caller must also ht_take() the ctx (transferring the hash's
 * ref) before invoking this so subsequent callbacks do not race
 * the state change.
 *
 * Returns the observed state (REPLIED if the callback won the
 * race; ABANDONED if the timeout did). */
int nats_rpc_async_mark_abandoned(struct nats_rpc_async_ctx *c)
{
	int observed;
	if (!c) return -1;
	pthread_mutex_lock(&c->mu);
	if (c->state == NATS_RPC_ASYNC_INFLIGHT)
		c->state = NATS_RPC_ASYNC_ABANDONED;
	observed = c->state;
	pthread_mutex_unlock(&c->mu);
	return observed;
}

/* Drain the per-ctx eventfd counter so a subsequent wait re-arms.
 * Returns 1 if a count was consumed, 0 if the fd was already
 * empty, -1 on error. */
int nats_rpc_async_drain_eventfd(struct nats_rpc_async_ctx *c)
{
	uint64_t v;
	ssize_t r;
	if (!c || c->eventfd < 0) return -1;
	r = read(c->eventfd, &v, sizeof(v));
	if (r == sizeof(v))                       return 1;
	if (r < 0 && errno == EAGAIN)             return 0;
	return -1;
}

/* Accessors for the resume path.  Kept here (instead of inline in
 * the header) so the ctx struct stays opaque to nats_rpc.h. */
int  nats_rpc_async_state    (struct nats_rpc_async_ctx *c) { return c ? c->state : -1; }
int  nats_rpc_async_eventfd  (struct nats_rpc_async_ctx *c) { return c ? c->eventfd : -1; }
int  nats_rpc_async_corr_len (struct nats_rpc_async_ctx *c) { return c ? c->corr_id_len : 0; }
const char *nats_rpc_async_corr_id(struct nats_rpc_async_ctx *c) { return c ? c->corr_id : NULL; }

/* Record the reconnect-epoch snapshot taken at ctx alloc time.
 * Called by the production start path with the value of
 * nats_pool_get_reconnect_epoch(); called by tests with an
 * arbitrary value to drive the disconnection-detection logic. */
void nats_rpc_async_ctx_set_epoch_at_start(struct nats_rpc_async_ctx *c,
                                           uint32_t epoch)
{
	if (c) c->epoch_at_start = epoch;
}

uint32_t nats_rpc_async_ctx_epoch_at_start(struct nats_rpc_async_ctx *c)
{
	return c ? c->epoch_at_start : 0u;
}

/*
 * Pure decision: did the pool connection state change in a way
 * that means the script should see a connection-lost (-2)
 * instead of a clean timeout (0) for this ctx?
 *
 *   current_epoch != c->epoch_at_start  -> a reconnect occurred
 *                                          during the call;
 *                                          replies for the
 *                                          pre-reconnect inbox
 *                                          may have been lost.
 *   !current_connected                  -> pool is down right
 *                                          now; the reply
 *                                          cannot arrive.
 *
 * Either condition implies connection-lost.  Both being false
 * means the pool is stable -- a timeout is a real timeout.
 *
 * Exposed for tests so the state machine can be exercised under
 * -DTEST_SHIM without linking lib/nats.
 */
int nats_rpc_async_ctx_is_disconnected(struct nats_rpc_async_ctx *c,
                                       uint32_t current_epoch,
                                       int current_connected)
{
	if (!c) return 0;
	if (!current_connected)               return 1;
	if (current_epoch != c->epoch_at_start) return 1;
	return 0;
}

/*
 * Centralised script return-code policy for the async resume.
 *
 * OpenSIPS terminates the surrounding route when a script-
 * callable cmd returns 0 (action.c:196 sets ACT_FL_EXIT on
 * ret==0).  We deliberately avoid returning 0 from any
 * script-callable nats_* function; a timeout / no-result must
 * surface as a NEGATIVE value so the route continues and the
 * script can branch on $retcode.
 *
 * Decision:
 *   state == REPLIED    -> 1   reply delivered
 *   state != REPLIED &&  disconnected -> -2  connection lost
 *   state != REPLIED && !disconnected -> -1  clean timeout
 *
 * Exposed for unit tests so the policy can be locked down
 * without booting opensips.
 */
int nats_rpc_async_resume_rc(int state, int disconnected)
{
	if (state == NATS_RPC_ASYNC_REPLIED) return 1;
	if (disconnected)                    return -2;
	return -1;
}

int nats_rpc_async_take_for_resume(struct nats_rpc_async_ctx *c)
{
	return ht_take(c);
}

int nats_rpc_async_install(struct nats_rpc_async_ctx *c)
{
	return ht_insert(c);
}

int nats_rpc_async_inflight_count(void)
{
	int n;
	pthread_mutex_lock(&g_ht_mu);
	n = g_inflight_count;
	pthread_mutex_unlock(&g_ht_mu);
	return n;
}

/* Build the per-call reply subject "<prefix>.<pid>.<corr>" into
 * the caller-supplied buffer.  Returns the written length, 0 on
 * truncation.  Visible to tests so they can verify the format. */
int nats_rpc_async_format_reply_subject(struct nats_rpc_async_ctx *c,
                                        char *out, int cap)
{
	int n;
	if (!c || !out || cap <= 0) return 0;
	if (g_inbox_owner_len <= 0) {
		/* not lazy-inited yet; format using the prefix + pid
		 * so tests can drive without ensure_inbox_subscription */
		n = snprintf(out, cap, "%s.%d.%.*s",
			NATS_RPC_ASYNC_INBOX_PREFIX, (int)getpid(),
			c->corr_id_len, c->corr_id);
	} else {
		n = snprintf(out, cap, "%.*s.%.*s",
			g_inbox_owner_len, g_inbox_owner,
			c->corr_id_len, c->corr_id);
	}
	if (n <= 0 || n >= cap) return 0;
	return n;
}

/* Extract the correlation suffix from a reply subject of the form
 * "<prefix>.<pid>.<corr>".  Returns the suffix pointer (no NUL
 * terminator, into the input buffer) and writes the length to
 * *out_len.  Returns NULL on parse failure.  Visible so the libnats
 * callback and tests share the same parser. */
const char *nats_rpc_async_corr_from_subject(const char *subject,
                                             int subject_len,
                                             int *out_len)
{
	int i;
	int last_dot = -1;
	if (!subject || subject_len <= 0 || !out_len) return NULL;
	for (i = subject_len - 1; i >= 0; i--) {
		if (subject[i] == '.') { last_dot = i; break; }
	}
	if (last_dot < 0 || last_dot >= subject_len - 1) return NULL;
	*out_len = subject_len - last_dot - 1;
	return subject + last_dot + 1;
}

/* ── libnats glue (production only) ───────────────────────────── */

#ifndef TEST_SHIM

/* Forward declarations of the callback + headers helper.  The
 * latter is shared with nats_rpc.c's sync path; promoted to a
 * shared symbol so both call sites format headers identically. */
extern int nats_rpc_hdr_serialize_from_reply(natsMsg *m, char *out, int cap,
                                              int *truncated, int *count_out);

static void on_inbox_reply(natsConnection *nc, natsSubscription *sub,
                            natsMsg *msg, void *closure)
{
	const char *subject;
	const char *data;
	const char *reply_to;
	const char *corr;
	int         data_len;
	int         corr_len = 0;
	int         hdr_trunc = 0;
	int         hdr_count = 0;
	struct nats_rpc_async_ctx *c;
	int         hdr_len;
	char        hdrs[NATS_RING_HEADERS_MAX];

	(void)nc; (void)sub; (void)closure;

	if (!msg) return;

	subject  = nats_dl.natsMsg_GetSubject(msg);
	data     = nats_dl.natsMsg_GetData(msg);
	data_len = nats_dl.natsMsg_GetDataLength(msg);
	reply_to = nats_dl.natsMsg_GetReply(msg);

	corr = nats_rpc_async_corr_from_subject(subject,
		subject ? (int)strlen(subject) : 0, &corr_len);
	if (!corr) {
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	hdr_len = nats_rpc_hdr_serialize_from_reply(msg, hdrs, sizeof(hdrs),
		&hdr_trunc, &hdr_count);
	if (hdr_len < 0) hdr_len = 0;

	c = ht_lookup_and_take(corr, corr_len);
	if (!c) {
		/* either a stale reply (resume already timed out and
		 * took the ctx) or a delivery for a different worker
		 * that shares this connection -- libnats fans out the
		 * subscription to whichever worker has the active
		 * connection, so this is benign and expected to be
		 * rare. */
		nats_dl.natsMsg_Destroy(msg);
		return;
	}

	/* nats_rpc_async_deliver expects to do the ht_lookup_and_take
	 * itself.  We already took, so call the inline copy path
	 * directly (no second hash lookup). */
	pthread_mutex_lock(&c->mu);
	{
		int sl = subject ? (int)strlen(subject) : 0;
		int rl = reply_to ? (int)strlen(reply_to) : 0;
		if (sl > NATS_RING_SUBJECT_MAX) sl = NATS_RING_SUBJECT_MAX;
		if (data_len < 0)               data_len = 0;
		if (data_len > NATS_RING_PAYLOAD_MAX) data_len = NATS_RING_PAYLOAD_MAX;
		if (rl > NATS_RING_SUBJECT_MAX) rl = NATS_RING_SUBJECT_MAX;
		if (hdr_len > NATS_RING_HEADERS_MAX) hdr_len = NATS_RING_HEADERS_MAX;

		if (sl > 0) memcpy(c->reply_subject, subject, sl);
		c->reply_subject_len = (uint32_t)sl;
		if (data_len > 0 && data) memcpy(c->reply_data, data, data_len);
		c->reply_data_len = (uint32_t)data_len;
		if (rl > 0 && reply_to) {
			memcpy(c->reply_to, reply_to, rl);
			c->reply_to_len = (uint32_t)rl;
			c->reply_has_reply_to = 1;
		}
		if (hdr_len > 0) memcpy(c->reply_headers, hdrs, hdr_len);
		c->reply_headers_len       = (uint16_t)hdr_len;
		c->reply_headers_truncated = (uint8_t)(hdr_trunc ? 1 : 0);

		c->state = NATS_RPC_ASYNC_REPLIED;
	}
	{
		uint64_t v = 1;
		ssize_t w;
		do { w = write(c->eventfd, &v, sizeof(v)); }
		while (w < 0 && errno == EINTR);
	}
	pthread_mutex_unlock(&c->mu);

	nats_dl.natsMsg_Destroy(msg);
	nats_rpc_async_ctx_release(c);
}

/* Eager (preferred) or lazy fallback init of the per-worker
 * inbox subscription.  Called from nats_consumer.c's child_init
 * at worker boot, OR (as a fallback) from the async start path on
 * first use.  Thread-safe via g_inbox_sub_mu
 * (although the start path is single-threaded per worker, the
 * mutex hardens against pthread-spawned helpers landing here too).
 * Returns 0 on success / already-ready, -1 on failure (pool
 * unavailable, subscribe rejected).  Failures are surfaced as -3
 * (NATS unavailable) from the start path. */
static int ensure_inbox_subscription(void)
{
	natsConnection *nc;
	natsStatus      s;
	char            wildcard[64];
	int             n;

	if (g_inbox_sub_ready)
		return 0;
	pthread_mutex_lock(&g_inbox_sub_mu);
	if (g_inbox_sub_ready) {
		pthread_mutex_unlock(&g_inbox_sub_mu);
		return 0;
	}
	nc = nats_pool_get();
	if (!nc) {
		pthread_mutex_unlock(&g_inbox_sub_mu);
		return -1;
	}
	n = snprintf(g_inbox_owner, sizeof(g_inbox_owner), "%s.%d",
		NATS_RPC_ASYNC_INBOX_PREFIX, (int)getpid());
	if (n <= 0 || n >= (int)sizeof(g_inbox_owner)) {
		pthread_mutex_unlock(&g_inbox_sub_mu);
		return -1;
	}
	g_inbox_owner_len = n;

	n = snprintf(wildcard, sizeof(wildcard), "%s.>", g_inbox_owner);
	if (n <= 0 || n >= (int)sizeof(wildcard)) {
		pthread_mutex_unlock(&g_inbox_sub_mu);
		return -1;
	}
	s = nats_dl.natsConnection_Subscribe(&g_inbox_sub, nc, wildcard,
		on_inbox_reply, NULL);
	if (s != NATS_OK || !g_inbox_sub) {
		LM_ERR("nats_rpc_async: subscribe(%s) failed: %s\n",
			wildcard, nats_dl.natsStatus_GetText(s));
		pthread_mutex_unlock(&g_inbox_sub_mu);
		return -1;
	}
	g_inbox_sub_ready = 1;
	LM_INFO("nats_rpc_async: inbox subscription up on %s\n", wildcard);
	pthread_mutex_unlock(&g_inbox_sub_mu);
	return 0;
}

/*
 * Public per-worker init hook.  nats_consumer.c::child_init() calls
 * this so the inbox subscription is set up at worker boot, before
 * any SIP message lands on the worker.  Doing the libnats
 * `natsConnection_Subscribe` here rather than lazily on first
 * `nats_request_async` call avoids spawning the subscription
 * thread from inside script execution -- empirically that race
 * crashes libnats 3.x on aarch64 when the SIP worker enters
 * w_nats_request_async right after the SUB completes.
 *
 * Failure is non-fatal: if the pool isn't ready yet, this returns
 * a soft error and the lazy path inside w_nats_request_async tries
 * again on first request.  Always returns 0 so child_init does
 * not fail boot just because the broker is briefly unreachable.
 */
int nats_rpc_async_child_init(int rank)
{
	(void)rank;
	if (ensure_inbox_subscription() < 0) {
		LM_DBG("nats_rpc_async: eager inbox subscribe deferred; "
			"lazy fallback will retry on first nats_request\n");
	}
	return 0;
}

/* Forward decls of helpers from nats_rpc.c that are not visible
 * in nats_rpc.h.  nats_rpc_hdr_serialize_from_reply is also
 * declared earlier in this file; nats_rpc_staged_set_if_absent
 * is in nats_rpc.h and intentionally not re-declared here. */
extern void nats_rpc_staged_apply_and_clear_on(natsMsg *out);
extern const char *nats_rpc_cstr_buf(char *buf, size_t cap,
                                      const char *src, int len);

/* Operator-configurable outbound header name carrying the per-call
 * UUIDv7.  Owned by nats_consumer.c via the `request_id_header`
 * modparam.  An empty / NULL value disables auto-staging entirely;
 * callers can still mint and read the id but no header is added
 * to the outbound natsMsg. */
extern char *nats_request_id_header;

/* Populate g_cur from the ctx's stored reply buffers.  Mirrors
 * cur_set_from_nats_reply() in nats_rpc.c but reads from byte
 * buffers instead of a natsMsg (the natsMsg was destroyed back in
 * the libnats callback). */
extern void nats_rpc_cur_set_from_buffers(uint32_t handle_idx,
                                           const char *subject,  uint32_t slen,
                                           const char *data,     uint32_t dlen,
                                           const char *reply_to, uint32_t rlen,
                                           uint8_t   has_reply,
                                           const char *headers,  uint16_t hlen,
                                           uint8_t   hdr_truncated);

/*
 * Per-call wrapper: pairs the worker-private timerfd with the
 * SHM slot.  Lives in pkg memory (worker-local) for the duration
 * of one async() call; freed by resume_nats_request_slot on
 * completion or timeout.  The timerfd is created INSIDE the
 * worker (post-fork) so it doesn't trip the
 * OpenSIPS-reactor-can't-handle-fork-inherited-eventfds bug
 * isolated in commit 8eae39a5b1.
 */
typedef struct nats_rpc_call_wrap {
	nats_rpc_slot_t *slot;          /* SHM */
	int              timerfd;       /* worker-private, registered with reactor */
	int64_t          deadline_us;   /* CLOCK_MONOTONIC, microseconds */
} nats_rpc_call_wrap_t;

/* Default tick interval for the timerfd poll.  1 ms gives sub-ms p50 with
 * a measurable CPU cost (1000 wakes/sec per in-flight call). */
#define NATS_RPC_ASYNC_POLL_NS 1000000L   /* 1 ms */

/* Runtime poll interval in ms (modparam "async_rpc_poll_ms"); a larger
 * value trades reply latency for fewer timer wakeups under load.  Clamped
 * to [1, 1000] when first used. */
int nats_rpc_async_poll_ms = 1;

static long _async_poll_ns(void)
{
	int ms = nats_rpc_async_poll_ms;
	if (ms < 1)    ms = 1;
	if (ms > 1000) ms = 1000;
	return (long)ms * 1000000L;
}

static int64_t now_us_monotonic(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000 + (int64_t)ts.tv_nsec / 1000;
}

/*
 * Resume function for the worker-private timerfd-poll transport.
 *
 * Fires on every tick of the per-call timerfd OR when the
 * async-core timeout expires (was_timeout=1).  The slot's
 * atomic state is the source of truth: if DELIVERED, copy the
 * reply and return 1; if still INFLIGHT and we haven't timed
 * out, ASYNC_CONTINUE to keep polling; if timed out, transition
 * to ABANDONED and return -1 (or -2 on connection lost).
 */
static int resume_nats_request_slot(int fd, struct sip_msg *msg,
                                     void *param)
{
	nats_rpc_call_wrap_t *w = (nats_rpc_call_wrap_t *)param;
	uint64_t              sink;
	ssize_t               rd;
	int                   state_obs;
	int                   rc;
	nats_rpc_slot_t      *s;

	(void)msg;

	if (!w || !w->slot) {
		LM_ERR("nats_request[async]: resume with NULL wrap/slot\n");
		async_status = ASYNC_DONE;
		return -6;
	}
	s = w->slot;

	/* Drain the timerfd counter so the next tick still wakes us. */
	do { rd = read(fd, &sink, sizeof(sink)); }
	while (rd < 0 && errno == EINTR);

	state_obs = atomic_load_explicit(&s->state, memory_order_acquire);

	if (state_obs == NATS_RPC_SLOT_DELIVERED) {
		/* Got the reply: copy into cur_msg, free everything,
		 * report success to the script. */
		nats_rpc_cur_set_from_buffers(0xFFFF,
			s->reply_subject,  s->reply_subject_len,
			s->reply_data,     s->reply_data_len,
			s->reply_to,       s->reply_to_len,
			s->reply_has_reply_to,
			s->reply_headers,  s->reply_headers_len,
			s->reply_headers_truncated);

		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_slot_free(s);
		pkg_free(w);
		return 1;
	}

	if (state_obs == NATS_RPC_SLOT_ABANDONED) {
		/* Consumer-side abandon (publish failed, etc.).  Tear
		 * down and report timeout / connection-lost based on
		 * pool state. */
		uint32_t cur_epoch = (uint32_t)nats_pool_get_reconnect_epoch();
		int      cur_conn  = nats_pool_is_connected();
		int      disc = !cur_conn || cur_epoch != s->epoch_at_start;

		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_slot_free(s);
		pkg_free(w);
		return disc ? -2 : -1;
	}

	/* state == INFLIGHT.  Check the per-call deadline so we
	 * surface -1 even though the async core has no built-in
	 * timeout for raw FDs.  Otherwise re-arm and keep polling. */
	if (now_us_monotonic() >= w->deadline_us) {
		uint32_t cur_epoch = (uint32_t)nats_pool_get_reconnect_epoch();
		int      cur_conn  = nats_pool_is_connected();
		int      disc = !cur_conn || cur_epoch != s->epoch_at_start;

		(void)nats_rpc_slot_abandon(s);
		async_status = ASYNC_DONE_CLOSE_FD;
		nats_rpc_slot_free(s);
		pkg_free(w);
		return disc ? -2 : -1;
	}

	(void)rc;
	async_status = ASYNC_CONTINUE;
	return 0;
}

/*
 * w_nats_request_async -- async acmd entry point.
 *
 * Worker side of the consumer-process-routed transport:
 *
 *   1. Pre-flight: subject + payload bounds.
 *   2. Mint/consume UUIDv7 for $nats_request_id.
 *   3. Claim a SHM slot from the pool.  On full pool surface -5.
 *   4. Fill the slot's out_subject + out_data + corr_id +
 *      epoch_at_start.
 *   5. Transition slot CLAIMED -> INFLIGHT (release ordering --
 *      the consumer's IPC drain acquires this) and enqueue the
 *      slot_idx on the worker -> consumer IPC.
 *   6. Create a worker-private timerfd that ticks every
 *      NATS_RPC_ASYNC_POLL_NS ns.  Compute the per-call deadline
 *      from timeout_ms (caps the polling loop).
 *   7. Allocate a pkg wrapper, hand control to the reactor:
 *      async_status = timerfd, ctx->resume_f =
 *      resume_nats_request_slot, ctx->resume_param = wrap.
 *
 * Headers staged via nats_hdr_set() (including the auto-staged
 * X-Request-Id) are serialized into the slot's out_headers buffer
 * using the same compact length-prefixed wire format as the ring
 * slot's headers field, and the consumer process applies them via
 * natsMsgHeader_Set() before PublishMsg in publish_cb().  Headers
 * that don't fit the 1 KB out_headers buffer set the truncated
 * flag (logged on emit); the remaining oversize names/values are
 * dropped quietly rather than silently corrupting the wire format.
 *
 * On any pre-IPC failure the slot is freed and the worker
 * returns the appropriate negative rc.  On post-IPC failure
 * (queue full) the slot is also freed; the worker returns -5
 * (capacity exhausted).
 */
int w_nats_request_async(struct sip_msg *msg, async_ctx *ctx,
                         str *subject, str *payload, int *timeout_ms)
{
	nats_rpc_slot_t        *slot = NULL;
	nats_rpc_call_wrap_t   *wrap = NULL;
	nats_rpc_ipc_msg_t      ipc_msg;
	struct itimerspec       its;
	int                     tfd = -1;
	int                     tmo_ms;
	char                    id_buf[64];
	int                     id_len = 0;

	(void)msg;
	(void)ctx;
	LM_DBG("nats_request[async]: ENTER subject=%p len=%d payload=%p tmo=%p ctx=%p\n",
		(void*)(subject?subject->s:NULL),
		subject?subject->len:-1,
		(void*)(payload?payload->s:NULL),
		(void*)timeout_ms, (void*)ctx);

	if (!subject || subject->len <= 0 || !subject->s) {
		LM_DBG("nats_request[async]: empty/null subject\n");
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	if (subject->len > NATS_RING_SUBJECT_MAX) {
		LM_ERR("nats_request[async]: subject too long (%d > %d)\n",
			subject->len, NATS_RING_SUBJECT_MAX);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	/* Reject CR/LF, whitespace and wildcards before the subject reaches
	 * the line-oriented NATS wire (protocol-injection guard). */
	if (nats_validate_publish_subject(subject->s, subject->len) < 0) {
		LM_ERR("nats_request[async]: invalid subject '%.*s' "
			"(control/whitespace/wildcard rejected)\n",
			subject->len, subject->s);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}
	if (payload && payload->len > NATS_RING_PAYLOAD_MAX) {
		LM_ERR("nats_request[async]: payload too long (%d > %d)\n",
			payload->len, NATS_RING_PAYLOAD_MAX);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -4;
	}

	tmo_ms = (timeout_ms && *timeout_ms > 0) ? *timeout_ms : 1000;

	/* Mint or consume the UUIDv7 + stage X-Request-Id. */
	id_len = nats_rpc_async_request_id_consume_user(id_buf, sizeof(id_buf));
	if (id_len == 0)
		id_len = nats_rpc_async_uuidv7_mint(id_buf, sizeof(id_buf));
	if (id_len > 0) {
		nats_rpc_async_request_id_set(id_buf, id_len);
		if (nats_request_id_header && nats_request_id_header[0]) {
			str hname = { nats_request_id_header,
				(int)strlen(nats_request_id_header) };
			str hval  = { id_buf, id_len };
			(void)nats_rpc_staged_set_if_absent(&hname, &hval);
		}
	}

	LM_DBG("nats_request[async]: about to claim slot\n");
	slot = nats_rpc_slot_claim();
	LM_DBG("nats_request[async]: slot=%p idx=%u\n",
		(void*)slot, slot?slot->slot_idx:0xFFFFFFFFu);
	if (!slot) {
		LM_WARN("nats_request[async]: slot pool full (%u in flight)\n",
			nats_rpc_slot_inflight_count());
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -5;
	}

	/* Fill outbound + correlation. */
	memcpy(slot->out_subject, subject->s, (size_t)subject->len);
	slot->out_subject_len = (uint32_t)subject->len;
	if (payload && payload->len > 0) {
		memcpy(slot->out_data, payload->s, (size_t)payload->len);
		slot->out_data_len = (uint32_t)payload->len;
	} else {
		slot->out_data_len = 0;
	}
	{
		int hdr_trunc = 0, hdr_count = 0;
		int hdr_len = nats_rpc_staged_serialize(slot->out_headers,
			(int)sizeof(slot->out_headers),
			&hdr_trunc, &hdr_count);
		if (hdr_len < 0) hdr_len = 0;
		slot->out_headers_len = (uint16_t)hdr_len;
		if (hdr_trunc) {
			LM_WARN("nats_request[async]: staged-header buffer "
				"truncated (emitted %d/%d pairs) on slot %u\n",
				hdr_count, NATS_MAX_STAGED_HDRS,
				(unsigned)slot->slot_idx);
		}
	}
	if (id_len > 0) {
		int cp = id_len < (int)sizeof(slot->corr_id) - 1
			? id_len : (int)sizeof(slot->corr_id) - 1;
		memcpy(slot->corr_id, id_buf, (size_t)cp);
		slot->corr_id[cp] = '\0';
		slot->corr_id_len = (uint32_t)cp;
	} else {
		slot->corr_id[0] = '\0';
		slot->corr_id_len = 0;
	}
	slot->epoch_at_start = (uint32_t)nats_pool_get_reconnect_epoch();

	LM_DBG("nats_request[async]: filled slot, about to publish\n");
	if (nats_rpc_slot_publish(slot) < 0) {
		LM_ERR("nats_request[async]: slot_publish failed (slot %u)\n",
			slot->slot_idx);
		nats_rpc_slot_free(slot);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}

	memset(&ipc_msg, 0, sizeof(ipc_msg));
	ipc_msg.slot_idx = slot->slot_idx;
	/* Tag the entry with the slot's current claim generation so the
	 * consumer can reject this entry if the slot is freed and re-claimed
	 * before the drain (prevents a double-publish -- see publish_cb). */
	ipc_msg.generation = atomic_load_explicit(&slot->generation,
		memory_order_relaxed);
	LM_DBG("nats_request[async]: about to enqueue IPC slot_idx=%u gen=%u\n",
		ipc_msg.slot_idx, ipc_msg.generation);
	if (nats_rpc_ipc_enqueue(&ipc_msg) < 0) {
		LM_WARN("nats_request[async]: IPC full -- dropping (slot %u)\n",
			slot->slot_idx);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -5;
	}

	/* Worker-private timerfd: created post-fork so the reactor
	 * can register it (see commit 8eae39a5b1). */
	LM_DBG("nats_request[async]: about to create timerfd\n");
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		LM_ERR("nats_request[async]: timerfd_create: %s\n",
			strerror(errno));
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}
	memset(&its, 0, sizeof(its));
	{
		long poll_ns = _async_poll_ns();
		its.it_value.tv_sec     = 0;
		its.it_value.tv_nsec    = poll_ns;
		its.it_interval.tv_sec  = 0;
		its.it_interval.tv_nsec = poll_ns;
	}
	if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
		LM_ERR("nats_request[async]: timerfd_settime: %s\n",
			strerror(errno));
		close(tfd);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}

	LM_DBG("nats_request[async]: timerfd armed tfd=%d, allocating wrap\n", tfd);
	wrap = (nats_rpc_call_wrap_t *)pkg_malloc(sizeof(*wrap));
	if (!wrap) {
		LM_ERR("nats_request[async]: pkg_malloc wrap failed\n");
		close(tfd);
		(void)nats_rpc_slot_abandon(slot);
		nats_rpc_slot_free(slot);
		nats_rpc_staged_clear();
		async_status = ASYNC_NO_IO;
		return -6;
	}
	wrap->slot        = slot;
	wrap->timerfd     = tfd;
	wrap->deadline_us = now_us_monotonic() + (int64_t)tmo_ms * 1000;

	/* Hand off to the reactor.  The staged headers were
	 * "consumed" when we built the slot; clear the staging area
	 * so the next call starts fresh. */
	nats_rpc_staged_clear();

	LM_DBG("nats_request[async]: handing off ctx=%p resume_f=%p wrap=%p tfd=%d\n",
		(void*)ctx, (void*)resume_nats_request_slot,
		(void*)wrap, tfd);
	ctx->resume_f      = (void *)resume_nats_request_slot;
	ctx->resume_f_name = "resume_nats_request_slot";
	ctx->resume_param  = wrap;
	async_status       = tfd;
	return 1;
}

#endif /* !TEST_SHIM */
