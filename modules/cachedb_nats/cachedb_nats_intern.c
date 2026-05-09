/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Implementation of the SHM string intern table -- see header
 * for the rationale.  ~half of all opensips CPU at 100k AoRs
 * was sem_wait -> hp_shm_malloc on the watcher's _entry_add_key
 * path; this module collapses those allocations into a single
 * intern-or-acquire per unique doc key, with refcounted release.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../dprint.h"
#include "../../locking.h"
#include "../../mem/shm_mem.h"

#include "cachedb_nats_intern.h"

#define NATS_INTERN_BUCKETS  1024     /* power of two -- bitmask hash */
#define NATS_INTERN_SHARDS   32       /* lock-set size */
#define NATS_INTERN_BMASK    (NATS_INTERN_BUCKETS - 1)

typedef struct nats_intern_node {
	struct nats_intern_node *next;
	int                      refcount;
	int                      len;
	char                     str[];   /* flexible array, NUL-terminated */
} nats_intern_node_t;

struct nats_intern_table {
	nats_intern_node_t **buckets;     /* SHM array of NATS_INTERN_BUCKETS */
	gen_lock_set_t      *locks;        /* SHM lock set, NATS_INTERN_SHARDS */
	int                  size;         /* live entry count, advisory */
};

static struct nats_intern_table *g_t = NULL;

/* FNV-1a over the bytes.  Cheap, decent distribution for short
 * ASCII strings like our doc keys.  We mask off the hash mod
 * NATS_INTERN_BUCKETS for the bucket; the SAME bucket is used
 * to derive the shard, so acquire and release always lock the
 * same shard for a given string. */
static inline unsigned int _fnv1a(const char *s, int len)
{
	unsigned int h = 2166136261u;
	int i;
	for (i = 0; i < len; i++) {
		h ^= (unsigned char)s[i];
		h *= 16777619u;
	}
	return h;
}

static inline unsigned int _bucket_of(unsigned int hash)
{
	return hash & NATS_INTERN_BMASK;
}

static inline int _shard_of(unsigned int bucket)
{
	return (int)(bucket % NATS_INTERN_SHARDS);
}

int nats_intern_init(void)
{
	struct nats_intern_table *t;

	if (g_t) {
		LM_WARN("intern: already initialised\n");
		return 0;
	}

	t = shm_malloc(sizeof(*t));
	if (!t) {
		LM_ERR("intern: no SHM for table struct\n");
		return -1;
	}
	memset(t, 0, sizeof(*t));

	t->buckets = shm_malloc(sizeof(nats_intern_node_t *) *
		NATS_INTERN_BUCKETS);
	if (!t->buckets) {
		LM_ERR("intern: no SHM for %d bucket heads\n",
			NATS_INTERN_BUCKETS);
		shm_free(t);
		return -1;
	}
	memset(t->buckets, 0,
		sizeof(nats_intern_node_t *) * NATS_INTERN_BUCKETS);

	t->locks = lock_set_alloc(NATS_INTERN_SHARDS);
	if (!t->locks) {
		LM_ERR("intern: lock_set_alloc(%d) failed\n",
			NATS_INTERN_SHARDS);
		shm_free(t->buckets);
		shm_free(t);
		return -1;
	}
	if (!lock_set_init(t->locks)) {
		LM_ERR("intern: lock_set_init failed for %d shards\n",
			NATS_INTERN_SHARDS);
		lock_set_dealloc(t->locks);
		shm_free(t->buckets);
		shm_free(t);
		return -1;
	}

	g_t = t;
	LM_DBG("intern: initialised (%d buckets, %d shards)\n",
		NATS_INTERN_BUCKETS, NATS_INTERN_SHARDS);
	return 0;
}

void nats_intern_destroy(void)
{
	int i;
	nats_intern_node_t *n, *next;

	if (!g_t) return;

	/* Take all shard locks before walking buckets so a concurrent
	 * acquire/release blocks until we're done.  Order is increasing
	 * shard index so any future code that takes multiple shards
	 * follows the same convention. */
	for (i = 0; i < NATS_INTERN_SHARDS; i++)
		lock_set_get(g_t->locks, i);

	for (i = 0; i < NATS_INTERN_BUCKETS; i++) {
		for (n = g_t->buckets[i]; n; n = next) {
			next = n->next;
			shm_free(n);
		}
		g_t->buckets[i] = NULL;
	}

	for (i = NATS_INTERN_SHARDS - 1; i >= 0; i--)
		lock_set_release(g_t->locks, i);

	lock_set_destroy(g_t->locks);
	lock_set_dealloc(g_t->locks);
	shm_free(g_t->buckets);
	shm_free(g_t);
	g_t = NULL;
}

char *nats_intern_acquire(const char *s, int len)
{
	unsigned int        hash, bucket;
	int                 shard;
	nats_intern_node_t *n;

	if (!g_t || !s || len < 0)
		return NULL;

	hash   = _fnv1a(s, len);
	bucket = _bucket_of(hash);
	shard  = _shard_of(bucket);

	lock_set_get(g_t->locks, shard);

	for (n = g_t->buckets[bucket]; n; n = n->next) {
		if (n->len == len && memcmp(n->str, s, (size_t)len) == 0) {
			n->refcount++;
			lock_set_release(g_t->locks, shard);
			return n->str;
		}
	}

	/* Not found -- allocate one block for the header + string +
	 * trailing NUL.  Single shm_malloc per unique string; on the
	 * dominant re-register workload this branch is rare.  */
	n = shm_malloc(sizeof(*n) + (size_t)len + 1);
	if (!n) {
		LM_ERR("intern: no SHM for entry (len=%d)\n", len);
		lock_set_release(g_t->locks, shard);
		return NULL;
	}
	n->refcount = 1;
	n->len      = len;
	memcpy(n->str, s, (size_t)len);
	n->str[len] = '\0';

	/* Push at the head of the bucket chain.  No ordering
	 * guarantees on chain traversal order, so head-insert is
	 * fine and avoids a tail-walk. */
	n->next               = g_t->buckets[bucket];
	g_t->buckets[bucket]  = n;
	g_t->size++;

	lock_set_release(g_t->locks, shard);
	return n->str;
}

void nats_intern_release(char *p)
{
	nats_intern_node_t  *n, **prev;
	unsigned int         hash, bucket;
	int                  shard;

	if (!p || !g_t) return;

	/* Recover the node header.  The acquire returned &n->str, so
	 * subtract the offset to get the head.  Must be a pointer
	 * obtained from acquire -- arbitrary substrings are
	 * undefined behaviour. */
	n = (nats_intern_node_t *)(p - offsetof(nats_intern_node_t, str));

	hash   = _fnv1a(n->str, n->len);
	bucket = _bucket_of(hash);
	shard  = _shard_of(bucket);

	lock_set_get(g_t->locks, shard);

	if (--n->refcount > 0) {
		lock_set_release(g_t->locks, shard);
		return;
	}

	/* Refcount reached zero -- unlink and free.  Walk the chain
	 * to find our prev pointer; chains are short (1024 buckets,
	 * uniform hash, ~100k entries -> ~100 nodes per bucket worst
	 * case but typical 1-2). */
	for (prev = &g_t->buckets[bucket]; *prev; prev = &(*prev)->next) {
		if (*prev == n) {
			*prev = n->next;
			g_t->size--;
			lock_set_release(g_t->locks, shard);
			shm_free(n);
			return;
		}
	}

	/* Not found in chain -- this is a logic bug.  Either a
	 * double-release or the string was never interned.  We've
	 * already decremented refcount to a negative; can't safely
	 * roll that back without another walk.  Log and move on;
	 * the orphan node will leak but the system stays up. */
	LM_ERR("intern: release: node %p not found in bucket %u "
		"(double-release or non-interned pointer?)\n",
		(void *)n, bucket);
	lock_set_release(g_t->locks, shard);
}

int nats_intern_size(void)
{
	return g_t ? g_t->size : 0;
}
