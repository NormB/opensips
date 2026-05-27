/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats_json.c::_entry_add_key leaked the
 * interned doc-key reference it acquires up front when the keys[]
 * array growth (shm_malloc on the inline->heap transition, or
 * shm_realloc on a subsequent grow) failed.  The function returned -1
 * WITHOUT calling nats_intern_release(interned), so the intern entry's
 * refcount stayed permanently elevated and its node was never freed --
 * an unbounded SHM leak under memory pressure / re-register storms.
 *
 * The fix releases the ref before both OOM `return -1`s.
 *
 * This test carries a stripped intern table (same model as
 * test_intern_unit.c) plus a faithful copy of _entry_add_key, and a
 * failable allocator.  It asserts that after a forced grow-OOM the
 * intern table refcount is balanced (size returns to 0 once the
 * successfully-stored keys are removed) -- i.e. the failed-add did NOT
 * leave a stuck reference behind.  Two grow sites are exercised:
 * the inline->heap shm_malloc and the heap shm_realloc.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_entry_add_key_oom \
 *       test_entry_add_key_oom.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* ── failable allocator (drives the OOM branch) ───────────────────── */

static int g_fail_next_malloc;   /* when >0, the next shm_malloc fails  */
static int g_fail_next_realloc;  /* when >0, the next shm_realloc fails */

static void *test_shm_malloc(size_t n)
{
	if (g_fail_next_malloc) { g_fail_next_malloc = 0; return NULL; }
	return malloc(n);
}
static void *test_shm_realloc(void *p, size_t n)
{
	if (g_fail_next_realloc) { g_fail_next_realloc = 0; return NULL; }
	return realloc(p, n);
}
static void test_shm_free(void *p) { free(p); }

#define shm_malloc(n)     test_shm_malloc(n)
#define shm_realloc(p, n) test_shm_realloc(p, n)
#define shm_free(p)       test_shm_free(p)

#define LM_ERR(fmt, ...)  fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define LM_DBG(fmt, ...)  do { } while (0)

/* ── carried intern table (model of cachedb_nats_intern.c) ────────── */

#define NATS_INTERN_BUCKETS  1024
#define NATS_INTERN_BMASK    (NATS_INTERN_BUCKETS - 1)

typedef struct nats_intern_node {
	struct nats_intern_node *next;
	int   refcount;
	int   len;
	char  str[];
} nats_intern_node_t;

static nats_intern_node_t *g_buckets[NATS_INTERN_BUCKETS];
static int g_intern_size;

static unsigned int _fnv1a(const char *s, int len)
{
	unsigned int h = 2166136261u;
	int i;
	for (i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
	return h;
}

/* NOTE: the intern node uses the system allocator directly (malloc),
 * NOT the failable shm wrappers -- the bug under test is about the
 * keys[] array allocation failing, not the intern allocation. */
static char *nats_intern_acquire(const char *s, int len)
{
	unsigned int b = _fnv1a(s, len) & NATS_INTERN_BMASK;
	nats_intern_node_t *n;
	for (n = g_buckets[b]; n; n = n->next)
		if (n->len == len && memcmp(n->str, s, (size_t)len) == 0) {
			n->refcount++;
			return n->str;
		}
	n = malloc(sizeof(*n) + (size_t)len + 1);
	if (!n) return NULL;
	n->refcount = 1; n->len = len;
	memcpy(n->str, s, (size_t)len); n->str[len] = '\0';
	n->next = g_buckets[b]; g_buckets[b] = n; g_intern_size++;
	return n->str;
}

static void nats_intern_release(char *p)
{
	nats_intern_node_t *n = (nats_intern_node_t *)
		(p - offsetof(nats_intern_node_t, str));
	unsigned int b = _fnv1a(n->str, n->len) & NATS_INTERN_BMASK;
	nats_intern_node_t **prev;
	if (--n->refcount > 0) return;
	for (prev = &g_buckets[b]; *prev; prev = &(*prev)->next)
		if (*prev == n) { *prev = n->next; g_intern_size--; free(n); return; }
}

static int nats_intern_size(void) { return g_intern_size; }

/* ── entry struct + carried copy of _entry_add_key (FIXED form) ───── */

#define NATS_IDX_KEYS_INLINE 8

typedef struct {
	char **keys;
	int    num_keys;
	int    alloc_keys;
	int    keys_inline;
	char  *inline_storage[NATS_IDX_KEYS_INLINE];
} nats_idx_entry;

static void entry_init(nats_idx_entry *e)
{
	memset(e, 0, sizeof(*e));
	e->keys        = e->inline_storage;
	e->alloc_keys  = NATS_IDX_KEYS_INLINE;
	e->num_keys    = 0;
	e->keys_inline = 1;
}

static void entry_free(nats_idx_entry *e)
{
	int i;
	for (i = 0; i < e->num_keys; i++)
		nats_intern_release(e->keys[i]);
	if (!e->keys_inline && e->keys)
		shm_free(e->keys);
}

/* Faithful copy of the FIXED production _entry_add_key. */
static int _entry_add_key(nats_idx_entry *e, const char *key)
{
	int i;
	char *interned;
	int   klen = (int)strlen(key);

	interned = nats_intern_acquire(key, klen);
	if (!interned) { LM_ERR("no SHM for interned key string\n"); return -1; }

	for (i = 0; i < e->num_keys; i++) {
		if (e->keys[i] == interned) {
			nats_intern_release(interned);
			return 0;
		}
	}

	if (e->num_keys >= e->alloc_keys) {
		int    new_alloc = e->alloc_keys * 2;
		char **new_keys;
		if (e->keys_inline) {
			new_keys = shm_malloc(sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow inline keys array\n");
				nats_intern_release(interned);  /* FIX */
				return -1;
			}
			memcpy(new_keys, e->keys,
				sizeof(char *) * (size_t)e->num_keys);
			e->keys        = new_keys;
			e->keys_inline = 0;
		} else {
			new_keys = shm_realloc(e->keys, sizeof(char *) * new_alloc);
			if (!new_keys) {
				LM_ERR("no SHM to grow keys array\n");
				nats_intern_release(interned);  /* FIX */
				return -1;
			}
			e->keys = new_keys;
		}
		e->alloc_keys = new_alloc;
	}

	e->keys[e->num_keys++] = interned;
	return 0;
}

/* ── tests ────────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Fill the entry up to capacity with distinct keys, then attempt one
 * more add that triggers a grow which we force to fail.  The failed
 * add's key must NOT leave a stuck intern reference. */
static void test_grow_oom(int fail_realloc)
{
	nats_idx_entry e;
	char buf[32];
	int i;

	entry_init(&e);

	/* For the realloc path we must first grow once successfully so the
	 * keys[] becomes a heap block (keys_inline cleared), then fail the
	 * NEXT grow.  For the malloc path we fail the very first grow. */
	if (fail_realloc) {
		for (i = 0; i < NATS_IDX_KEYS_INLINE + 1; i++) {
			snprintf(buf, sizeof(buf), "doc_key_%d", i);
			ASSERT(_entry_add_key(&e, buf) == 0, "pre-grow add ok");
		}
		ASSERT(e.keys_inline == 0, "keys[] now on heap (realloc path)");
		/* fill remaining heap capacity so the next add grows again */
		while (e.num_keys < e.alloc_keys) {
			snprintf(buf, sizeof(buf), "doc_key_%d", i++);
			ASSERT(_entry_add_key(&e, buf) == 0, "fill heap capacity");
		}
		g_fail_next_realloc = 1;
	} else {
		for (i = 0; i < NATS_IDX_KEYS_INLINE; i++) {
			snprintf(buf, sizeof(buf), "doc_key_%d", i);
			ASSERT(_entry_add_key(&e, buf) == 0, "fill inline capacity");
		}
		g_fail_next_malloc = 1;
	}

	int size_before = nats_intern_size();

	/* This add must trigger a grow, the grow fails, the function
	 * returns -1 -- and (with the fix) releases its acquired ref. */
	snprintf(buf, sizeof(buf), "OOM_VICTIM_KEY");
	int rc = _entry_add_key(&e, buf);
	ASSERT(rc == -1, "add returns -1 on grow OOM");

	/* The victim key must NOT be left interned with a stuck refcount:
	 * the table size must be unchanged from before the failed add. */
	ASSERT(nats_intern_size() == size_before,
		fail_realloc
		? "no leaked intern ref after realloc-OOM"
		: "no leaked intern ref after malloc-OOM");

	/* Tidy up: release all successfully-stored keys; size must hit 0. */
	entry_free(&e);
	ASSERT(nats_intern_size() == 0,
		"intern table empty after entry teardown (balanced)");
}

int main(void)
{
	memset(g_buckets, 0, sizeof(g_buckets));
	g_intern_size = 0;

	fprintf(stderr, "-- inline->heap shm_malloc OOM --\n");
	test_grow_oom(0);

	fprintf(stderr, "-- heap shm_realloc OOM --\n");
	test_grow_oom(1);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
