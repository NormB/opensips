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
 * nats_handle_registry.c -- SHM hash table implementation.
 *
 * Fixed-bucket hash; no rehash.  FNV-1a over the id bytes.
 * Per-bucket rwlock for the hot path; global rwlock for iteration
 * and teardown.  Atomic counter for lock-free count().
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <string.h>
#include <stdint.h>

#include "nats_handle_registry.h"
#include "nats_ring.h"
#ifndef TEST_SHIM
#include "nats_persist.h"
#else
/* Unit tests do not link nats_persist; stub out the hook. */
static inline void nats_persist_schedule_write(void) {}
#endif

/* Default slot count for per-handle rings.  Phase 3: fixed.  A later
 * phase will expose this as a bind-time option. */
#define NATS_HANDLE_RING_CAPACITY 128

/* ── bucket ──────────────────────────────────────────────────── */

typedef struct nats_bucket {
	rw_lock_t *lock;
	nats_handle_t *head;
} nats_bucket_t;

typedef struct nats_registry {
	rw_lock_t *global_lock;
	int bucket_count;
	nats_bucket_t *buckets;
	int handle_count;           /* accessed with __atomic_* builtins */
	int next_index;             /* monotonic; used to assign h->index */

	/* Phase 7 retire list.  Handles removed from their bucket by
	 * nats_registry_unbind() are parked here until nats_registry_reap()
	 * can safely free them (sub_torn_down && pending_ops == 0).
	 *
	 * Guarded by `retire_lock`.  The retire list uses `h->next` as its
	 * chain pointer; once a handle is on the retire list it is not on
	 * any bucket chain, so the single `next` is not contested.
	 *
	 * Lock ordering: `retire_lock` is NEVER taken while holding a
	 * bucket lock.  The only place we need both is in unbind(), which
	 * takes them in order (bucket write -> drop -> retire write) --
	 * the bucket lock is released before the retire lock is acquired,
	 * so there is no nesting.  Callers of reap() hold no other lock. */
	rw_lock_t *retire_lock;
	nats_handle_t *retire_head;
} nats_registry_t;

static nats_registry_t *g_registry = NULL;

/* ── FNV-1a ──────────────────────────────────────────────────── */

#define FNV_OFFSET_BASIS_32 0x811c9dc5u
#define FNV_PRIME_32        0x01000193u

static inline uint32_t fnv1a_32(const char *s, int len)
{
	uint32_t h = FNV_OFFSET_BASIS_32;
	int i;
	for (i = 0; i < len; i++) {
		h ^= (uint8_t)s[i];
		h *= FNV_PRIME_32;
	}
	return h;
}

static inline int bucket_index(const str *id)
{
	uint32_t h = fnv1a_32(id->s, id->len);
	return (int)(h % (uint32_t)g_registry->bucket_count);
}

/* ── str helpers ─────────────────────────────────────────────── */

static inline int str_eq(const str *a, const str *b)
{
	return a->len == b->len && memcmp(a->s, b->s, a->len) == 0;
}

static inline void str_free_shm(str *s)
{
	if (s->s) {
		shm_free(s->s);
		s->s = NULL;
		s->len = 0;
	}
}

/* ── lifecycle ───────────────────────────────────────────────── */

int nats_registry_init(int bucket_count)
{
	int i;
	nats_registry_t *r;

	if (g_registry) {
		LM_WARN("nats_registry already initialized\n");
		return 0;
	}
	if (bucket_count <= 0)
		bucket_count = 256;

	r = (nats_registry_t *)shm_malloc(sizeof(nats_registry_t));
	if (!r) {
		LM_ERR("shm alloc registry failed\n");
		return -1;
	}
	memset(r, 0, sizeof(*r));

	r->bucket_count = bucket_count;
	r->buckets = (nats_bucket_t *)shm_malloc(
		sizeof(nats_bucket_t) * bucket_count);
	if (!r->buckets) {
		LM_ERR("shm alloc buckets failed\n");
		shm_free(r);
		return -1;
	}
	memset(r->buckets, 0, sizeof(nats_bucket_t) * bucket_count);

	for (i = 0; i < bucket_count; i++) {
		r->buckets[i].lock = lock_init_rw();
		if (!r->buckets[i].lock) {
			LM_ERR("bucket %d lock init failed\n", i);
			/* roll back */
			while (--i >= 0) {
				lock_destroy_rw(r->buckets[i].lock);
				r->buckets[i].lock = NULL;
			}
			shm_free(r->buckets);
			shm_free(r);
			return -1;
		}
	}

	r->global_lock = lock_init_rw();
	if (!r->global_lock) {
		LM_ERR("global rwlock init failed\n");
		for (i = 0; i < bucket_count; i++)
			lock_destroy_rw(r->buckets[i].lock);
		shm_free(r->buckets);
		shm_free(r);
		return -1;
	}

	r->retire_lock = lock_init_rw();
	if (!r->retire_lock) {
		LM_ERR("retire rwlock init failed\n");
		lock_destroy_rw(r->global_lock);
		for (i = 0; i < bucket_count; i++)
			lock_destroy_rw(r->buckets[i].lock);
		shm_free(r->buckets);
		shm_free(r);
		return -1;
	}
	r->retire_head = NULL;

	r->handle_count = 0;
	r->next_index   = 0;
	g_registry = r;
	return 0;
}

void nats_registry_destroy(void)
{
	int i;
	nats_handle_t *h, *next;
	nats_registry_t *r = g_registry;

	if (!r)
		return;

	/* no other process should be touching it now, but take the write
	 * locks anyway to flush any in-flight reader */
	lock_start_write(r->global_lock);

	for (i = 0; i < r->bucket_count; i++) {
		lock_start_write(r->buckets[i].lock);
		h = r->buckets[i].head;
		while (h) {
			next = h->next;
			nats_handle_free(h);
			h = next;
		}
		r->buckets[i].head = NULL;
		lock_stop_write(r->buckets[i].lock);
		lock_destroy_rw(r->buckets[i].lock);
	}

	/* Drain the retire list -- force-free anything that unbind parked
	 * but the consumer process never got around to tearing down.
	 * mod_destroy is the last writer, so ignore the retire bookkeeping
	 * (sub_torn_down / pending_ops) and just free. */
	if (r->retire_lock)
		lock_start_write(r->retire_lock);
	h = r->retire_head;
	while (h) {
		next = h->next;
		nats_handle_free(h);
		h = next;
	}
	r->retire_head = NULL;
	if (r->retire_lock) {
		lock_stop_write(r->retire_lock);
		lock_destroy_rw(r->retire_lock);
	}

	lock_stop_write(r->global_lock);
	lock_destroy_rw(r->global_lock);

	shm_free(r->buckets);
	shm_free(r);
	g_registry = NULL;
}

/* ── handle free ─────────────────────────────────────────────── */

void nats_handle_free(nats_handle_t *h)
{
	if (!h)
		return;

	str_free_shm(&h->id);
	str_free_shm(&h->stream);
	str_free_shm(&h->durable);
	str_free_shm(&h->filter);
	str_free_shm(&h->filters_csv);
	str_free_shm(&h->backoff_csv);
	str_free_shm(&h->js_domain);
	str_free_shm(&h->api_prefix);
	str_free_shm(&h->extra_json);
	str_free_shm(&h->last_error_msg);

	if (h->rlock) {
		lock_destroy_rw(h->rlock);
		h->rlock = NULL;
	}

	/* Tear down the SHM ring.  Subscription cleanup happens in the
	 * consumer process (process-local pointer), not here. */
#ifndef TEST_SHIM
	if (h->ring) {
		nats_ring_destroy(h->ring);
		h->ring = NULL;
	}
#endif

	shm_free(h);
}

/* ── bind / unbind / lookup ──────────────────────────────────── */

int nats_registry_bind(nats_handle_t *h)
{
	int idx;
	int assigned_index;
	nats_handle_t *cur;
	nats_bucket_t *b;

	if (!g_registry || !h)
		return -2;
	if (h->id.len <= 0 || !h->id.s)
		return -2;

	/* Assign monotonic bind-order index BEFORE dropping into the bucket.
	 * If we exceed the cap, refuse to bind -- the consumer process's
	 * ref table would not have a slot for us.  Phase 5: return the
	 * distinct -3 code so callers can surface a specific MI / script
	 * error ("handle count limit reached") instead of the generic -2. */
	assigned_index = __atomic_fetch_add(&g_registry->next_index, 1,
		__ATOMIC_SEQ_CST);
	if (assigned_index < 0 || assigned_index >= NATS_REGISTRY_MAX_HANDLES) {
		LM_ERR("nats_registry: handle index %d exceeds cap %d "
			"(NATS_REGISTRY_MAX_HANDLES)\n",
			assigned_index, NATS_REGISTRY_MAX_HANDLES);
		return -3;
	}
	h->index = (uint16_t)assigned_index;

	idx = bucket_index(&h->id);
	b = &g_registry->buckets[idx];

	/* need the rlock before insertion so runtime block is usable
	 * from the moment another process can see the handle */
	if (!h->rlock) {
		h->rlock = lock_init_rw();
		if (!h->rlock) {
			LM_ERR("handle rlock init failed\n");
			return -2;
		}
	}
	h->created_at = time(NULL);
	h->last_used_at = 0;

	/* Allocate the SHM ring that the consumer process will push into
	 * and SIP workers will pop from.  Under TEST_SHIM (unit tests) the
	 * ring would require eventfd and atomic SHM allocation which the
	 * pthread shim does not provide, so we skip it there.
	 *
	 * Phase 5: respect the per-handle ring_capacity override (the
	 * parser has already validated that it is a power of two >= 2 or
	 * zero).  A zero value means "use the module default". */
#ifndef TEST_SHIM
	if (!h->ring) {
		uint32_t cap = h->ring_capacity ? h->ring_capacity
		                                : NATS_HANDLE_RING_CAPACITY;
		h->ring = nats_ring_create(cap);
		if (!h->ring) {
			LM_ERR("handle ring create failed for id='%.*s' "
				"(capacity=%u)\n",
				h->id.len, h->id.s, (unsigned)cap);
			/* leave the rlock in place -- nats_handle_free()
			 * frees it either way.  The caller still owns h. */
			return -2;
		}
	}
#endif

	lock_start_write(b->lock);

	for (cur = b->head; cur; cur = cur->next) {
		if (str_eq(&cur->id, &h->id)) {
			lock_stop_write(b->lock);
			/* caller still owns h on duplicate -- free the rlock
			 * we just created so nats_handle_free() is idempotent */
			return -1;
		}
	}

	h->next = b->head;
	b->head = h;

	lock_stop_write(b->lock);

	__atomic_add_fetch(&g_registry->handle_count, 1, __ATOMIC_SEQ_CST);

	/* Persistence (Phase 8): schedule a debounced snapshot.  No-op if
	 * persist_handles was not enabled in the modparam. */
	nats_persist_schedule_write();
	return 0;
}

int nats_registry_unbind(const str *id)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur, *prev;
	nats_handle_t *retiree = NULL;

	if (!g_registry || !id || id->len <= 0)
		return -1;

	idx = bucket_index(id);
	b = &g_registry->buckets[idx];

	lock_start_write(b->lock);

	prev = NULL;
	for (cur = b->head; cur; prev = cur, cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			/* Phase 7: regardless of pending_ops we unlink the handle
			 * from its bucket chain immediately so subsequent lookups
			 * fail.  The physical free is deferred to
			 * nats_registry_reap() once the consumer process has torn
			 * down the JetStream subscription (sub_torn_down=1) and
			 * any in-flight ack-IPC references have drained
			 * (pending_ops==0).  Workers that raced and already hold
			 * a borrowed pointer observe retire=1 and release without
			 * making new calls. */
			if (prev)
				prev->next = cur->next;
			else
				b->head = cur->next;
			cur->next = NULL;
			retiree = cur;
			break;
		}
	}

	lock_stop_write(b->lock);

	if (!retiree)
		return -1;

	/* Mark retire BEFORE linking onto the retire list so any thread
	 * that observes the handle via a stale bucket-chain pointer (none
	 * should, but defensive) sees retire=1. */
	__atomic_store_n(&retiree->retire, 1, __ATOMIC_SEQ_CST);

	/* Park on the retire list for the reaper to drain.  The retire
	 * lock is never held simultaneously with a bucket lock (we dropped
	 * the bucket lock above), so no lock-order deadlock is possible. */
	lock_start_write(g_registry->retire_lock);
	retiree->next = g_registry->retire_head;
	g_registry->retire_head = retiree;
	lock_stop_write(g_registry->retire_lock);

	__atomic_sub_fetch(&g_registry->handle_count, 1, __ATOMIC_SEQ_CST);

	/* Persistence (Phase 8): snapshot drops the retired handle. */
	nats_persist_schedule_write();
	return 0;
}

nats_handle_t *nats_registry_lookup_weak(const str *id)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur, *found = NULL;

	if (!g_registry || !id || id->len <= 0)
		return NULL;

	/* First check the live bucket -- a non-retired handle with the
	 * same id lives here and is what the consumer process wants.
	 * A lookup that races with unbind may see either the live handle
	 * (before unbind takes the bucket write lock) or nothing (after
	 * unbind) -- both outcomes are safe. */
	idx = bucket_index(id);
	b = &g_registry->buckets[idx];
	lock_start_read(b->lock);
	for (cur = b->head; cur; cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			found = cur;
			break;
		}
	}
	lock_stop_read(b->lock);
	if (found)
		return found;

	/* Fall back to the retire list.  This is the expected path after
	 * unbind: the consumer process still has a proc_sub_state_t with
	 * a cached id and wants to observe `retire` on the original
	 * handle object to know it needs to tear down the subscription. */
	lock_start_read(g_registry->retire_lock);
	for (cur = g_registry->retire_head; cur; cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			found = cur;
			break;
		}
	}
	lock_stop_read(g_registry->retire_lock);

	return found;
}

void nats_registry_reap(void)
{
	nats_handle_t *reap_list = NULL;
	nats_handle_t *prev;
	nats_handle_t *cur;
	nats_handle_t *next;

	if (!g_registry)
		return;

	/* Walk the retire list under write lock; splice out anything that
	 * is ready to free (retire && sub_torn_down && pending_ops==0)
	 * into a private reap_list, then free under no lock.  Freeing
	 * under the retire lock would serialize every consumer-process
	 * iteration on a single lock; freeing outside keeps the critical
	 * section tiny. */
	lock_start_write(g_registry->retire_lock);

	prev = NULL;
	cur  = g_registry->retire_head;
	while (cur) {
		next = cur->next;

		int torn = __atomic_load_n(&cur->sub_torn_down, __ATOMIC_SEQ_CST);
		int pending = nats_handle_pending_get(cur);

		if (torn && pending == 0) {
			/* splice out */
			if (prev)
				prev->next = next;
			else
				g_registry->retire_head = next;

			/* Prepend to local reap_list */
			cur->next = reap_list;
			reap_list = cur;

			cur = next;
			continue;
		}
		prev = cur;
		cur  = next;
	}

	lock_stop_write(g_registry->retire_lock);

	while (reap_list) {
		next = reap_list->next;
		LM_DBG("nats_registry: reaping retired handle id='%.*s'\n",
			reap_list->id.len, reap_list->id.s);
		nats_handle_free(reap_list);
		reap_list = next;
	}
}

nats_handle_t *nats_registry_lookup(const str *id)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur, *found = NULL;

	if (!g_registry || !id || id->len <= 0)
		return NULL;

	idx = bucket_index(id);
	b = &g_registry->buckets[idx];

	lock_start_read(b->lock);
	for (cur = b->head; cur; cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			found = cur;
			break;
		}
	}
	lock_stop_read(b->lock);

	return found;
}

int nats_registry_count(void)
{
	if (!g_registry)
		return 0;
	return __atomic_load_n(&g_registry->handle_count, __ATOMIC_SEQ_CST);
}

int nats_registry_foreach(int (*cb)(nats_handle_t *h, void *user),
                          void *user)
{
	int i, rc = 0;
	nats_handle_t *cur;

	if (!g_registry || !cb)
		return 0;

	lock_start_read(g_registry->global_lock);

	for (i = 0; i < g_registry->bucket_count; i++) {
		nats_bucket_t *b = &g_registry->buckets[i];
		lock_start_read(b->lock);
		for (cur = b->head; cur; cur = cur->next) {
			rc = cb(cur, user);
			if (rc != 0) {
				lock_stop_read(b->lock);
				goto out;
			}
		}
		lock_stop_read(b->lock);
	}

out:
	lock_stop_read(g_registry->global_lock);
	return rc;
}

/* Phase 5 stub -- reserved for Phase 7 pause/teardown/recreate flow.
 * For now, only succeeds if the handle has no ring yet (i.e. bound
 * without initialization under TEST_SHIM).  Returns -1 otherwise. */
int nats_registry_set_ring_capacity(const str *id, uint32_t cap)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur;
	int rc = -1;

	if (!g_registry || !id || id->len <= 0)
		return -1;
	if (cap < 2 || (cap & (cap - 1)) != 0)
		return -1;

	idx = bucket_index(id);
	b = &g_registry->buckets[idx];

	lock_start_write(b->lock);
	for (cur = b->head; cur; cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			if (cur->ring) {
				/* Runtime resize requires drain-and-recreate; not in
				 * Phase 5 scope -- use at bind time via the
				 * ring_capacity= parameter. */
				rc = -1;
			} else {
				cur->ring_capacity = cap;
				rc = 0;
			}
			break;
		}
	}
	lock_stop_write(b->lock);
	return rc;
}

struct nats_ring *nats_registry_ring_get(const str *id)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur;
	struct nats_ring *ring = NULL;

	if (!g_registry || !id || id->len <= 0)
		return NULL;

	idx = bucket_index(id);
	b = &g_registry->buckets[idx];

	lock_start_read(b->lock);
	for (cur = b->head; cur; cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			ring = cur->ring;
			break;
		}
	}
	lock_stop_read(b->lock);

	return ring;
}
