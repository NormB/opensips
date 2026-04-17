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

	r->handle_count = 0;
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
	nats_handle_t *cur;
	nats_bucket_t *b;

	if (!g_registry || !h)
		return -2;
	if (h->id.len <= 0 || !h->id.s)
		return -2;

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
	 * pthread shim does not provide, so we skip it there. */
#ifndef TEST_SHIM
	if (!h->ring) {
		h->ring = nats_ring_create(NATS_HANDLE_RING_CAPACITY);
		if (!h->ring) {
			LM_ERR("handle ring create failed for id='%.*s'\n",
				h->id.len, h->id.s);
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
	return 0;
}

int nats_registry_unbind(const str *id)
{
	int idx;
	nats_bucket_t *b;
	nats_handle_t *cur, *prev;

	if (!g_registry || !id || id->len <= 0)
		return -1;

	idx = bucket_index(id);
	b = &g_registry->buckets[idx];

	lock_start_write(b->lock);

	prev = NULL;
	for (cur = b->head; cur; prev = cur, cur = cur->next) {
		if (str_eq(&cur->id, id)) {
			if (prev)
				prev->next = cur->next;
			else
				b->head = cur->next;
			lock_stop_write(b->lock);

			__atomic_sub_fetch(&g_registry->handle_count, 1,
				__ATOMIC_SEQ_CST);
			nats_handle_free(cur);
			return 0;
		}
	}

	lock_stop_write(b->lock);
	return -1;
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
