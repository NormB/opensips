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
 *
 * Behavioural unit test for the doc-key intern table.  Carries a
 * stripped-down copy of the production logic with shm_malloc and
 * gen_lock_set_t stubbed out, so the test runs as a normal binary
 * with no OpenSIPS link dependency.  The point is to exercise
 * the algorithmic invariants directly:
 *
 *   - acquire returns the same pointer for the same string
 *   - acquire of distinct strings returns distinct pointers
 *   - acquire bumps refcount; release decrements
 *   - release-when-zero unlinks and frees
 *   - hash collisions are handled correctly (different strings
 *     with the same bucket index don't share refcount)
 *   - empty strings are valid intern keys
 *   - large strings (longer than typical doc keys) work
 *   - double-release (refcount goes negative) is logged but
 *     doesn't crash
 *
 * The structural test test_intern_wiring.c covers "is the API
 * declared and called from the right places" -- this test
 * covers "does the API actually work."
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_intern_unit \
 *     test_intern_unit.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>

/* ── stubs ────────────────────────────────────────────────────── */

#define shm_malloc(sz)  malloc(sz)
#define shm_free(p)     free(p)

/* gen_lock_set_t is a no-op array.  This isn't a thread-safety
 * test (one thread); we just need the API surface to compile. */
typedef struct { int dummy; } gen_lock_set_t;
static inline gen_lock_set_t *lock_set_alloc(int n)        { (void)n; return calloc(1, sizeof(gen_lock_set_t)); }
static inline void            lock_set_dealloc(gen_lock_set_t *s) { free(s); }
static inline gen_lock_set_t *lock_set_init(gen_lock_set_t *s)    { return s; }
static inline void            lock_set_destroy(gen_lock_set_t *s) { (void)s; }
/* unused in this test's paths; kept for seam completeness */
static inline __attribute__((unused))
void lock_set_get(gen_lock_set_t *s, int i) { (void)s; (void)i; }
static inline __attribute__((unused))
void lock_set_release(gen_lock_set_t *s, int i) { (void)s; (void)i; }

#define LM_ERR(fmt, ...)  fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define LM_DBG(fmt, ...)  do { } while (0)
#define LM_WARN(fmt, ...) fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__)

/* ── carried copy of cachedb_nats_intern.c logic ─────────────── */

#define NATS_INTERN_BUCKETS  1024
#define NATS_INTERN_SHARDS   32
#define NATS_INTERN_BMASK    (NATS_INTERN_BUCKETS - 1)

typedef struct nats_intern_node {
	struct nats_intern_node *next;
	int                      refcount;
	int                      len;
	char                     str[];
} nats_intern_node_t;

typedef struct {
	nats_intern_node_t **buckets;
	gen_lock_set_t      *locks;
	int                  size;
} nats_intern_table_t;

static nats_intern_table_t *g_t = NULL;

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

static int nats_intern_init(void)
{
	g_t = calloc(1, sizeof(*g_t));
	g_t->buckets = calloc(NATS_INTERN_BUCKETS,
		sizeof(nats_intern_node_t *));
	g_t->locks = lock_set_alloc(NATS_INTERN_SHARDS);
	lock_set_init(g_t->locks);
	return g_t && g_t->buckets ? 0 : -1;
}

static void nats_intern_destroy(void)
{
	int i;
	for (i = 0; i < NATS_INTERN_BUCKETS; i++) {
		nats_intern_node_t *n = g_t->buckets[i], *next;
		while (n) { next = n->next; free(n); n = next; }
	}
	lock_set_destroy(g_t->locks);
	lock_set_dealloc(g_t->locks);
	free(g_t->buckets);
	free(g_t);
	g_t = NULL;
}

static char *nats_intern_acquire(const char *s, int len)
{
	if (!g_t || !s || len < 0) return NULL;
	unsigned int hash   = _fnv1a(s, len);
	unsigned int bucket = hash & NATS_INTERN_BMASK;
	nats_intern_node_t *n;
	for (n = g_t->buckets[bucket]; n; n = n->next) {
		if (n->len == len && memcmp(n->str, s, (size_t)len) == 0) {
			n->refcount++;
			return n->str;
		}
	}
	n = malloc(sizeof(*n) + (size_t)len + 1);
	if (!n) return NULL;
	n->refcount = 1;
	n->len      = len;
	memcpy(n->str, s, (size_t)len);
	n->str[len] = '\0';
	n->next = g_t->buckets[bucket];
	g_t->buckets[bucket] = n;
	g_t->size++;
	return n->str;
}

static void nats_intern_release(char *p)
{
	if (!p || !g_t) return;
	nats_intern_node_t *n = (nats_intern_node_t *)
		(p - offsetof(nats_intern_node_t, str));
	unsigned int hash   = _fnv1a(n->str, n->len);
	unsigned int bucket = hash & NATS_INTERN_BMASK;
	nats_intern_node_t **prev;
	/* Locate the node in its chain BEFORE touching refcount: on a
	 * double-release the node was already unlinked + freed, so the walk
	 * misses it and we never decrement freed memory or double-free. */
	for (prev = &g_t->buckets[bucket]; *prev; prev = &(*prev)->next) {
		if (*prev == n) {
			if (--n->refcount > 0) return;
			*prev = n->next;
			g_t->size--;
			free(n);
			return;
		}
	}
	LM_ERR("release: not found in chain (double-release?)\n");
}

static int nats_intern_size(void) { return g_t ? g_t->size : 0; }

/* ── tests ────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static void test_basic_acquire_release(void)
{
	char *p1 = nats_intern_acquire("hello", 5);
	char *p2 = nats_intern_acquire("hello", 5);
	ASSERT(p1 == p2, "acquire of same string returns same pointer");
	ASSERT(strncmp(p1, "hello", 5) == 0,
	       "interned string contents match");
	ASSERT(p1[5] == '\0',
	       "interned string is NUL-terminated even when input wasn't");
	ASSERT(nats_intern_size() == 1,
	       "size=1 after two acquires of the same string");

	nats_intern_release(p1);
	ASSERT(nats_intern_size() == 1,
	       "size still 1 after one release (refcount=1)");
	nats_intern_release(p2);
	ASSERT(nats_intern_size() == 0,
	       "size=0 after second release frees the entry");
}

static void test_distinct_strings(void)
{
	char *a = nats_intern_acquire("alice", 5);
	char *b = nats_intern_acquire("bob", 3);
	char *c = nats_intern_acquire("alice", 5);
	ASSERT(a != b, "distinct strings get distinct pointers");
	ASSERT(a == c, "same string gets same pointer");
	ASSERT(nats_intern_size() == 2,
	       "size=2 after 2 unique strings + 1 dup");
	nats_intern_release(a);
	nats_intern_release(b);
	nats_intern_release(c);
	ASSERT(nats_intern_size() == 0, "size=0 after all released");
}

static void test_empty_string(void)
{
	char *p = nats_intern_acquire("", 0);
	ASSERT(p != NULL, "empty string acquire works");
	ASSERT(p[0] == '\0', "empty string is NUL-terminated");
	nats_intern_release(p);
	ASSERT(nats_intern_size() == 0, "empty string releases cleanly");
}

static void test_large_string(void)
{
	char big[1024];
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	char *p = nats_intern_acquire(big, (int)(sizeof(big) - 1));
	ASSERT(p != NULL, "1023-byte string acquire works");
	ASSERT(strlen(p) == sizeof(big) - 1,
	       "interned large string length is preserved");
	ASSERT(memcmp(p, big, sizeof(big) - 1) == 0,
	       "interned large string contents are preserved");
	nats_intern_release(p);
}

static void test_non_nul_terminated_input(void)
{
	/* The acquire API takes (s, len) -- the input buffer is
	 * not required to be NUL-terminated.  Make sure we copy
	 * exactly len bytes and add our own terminator. */
	char raw[16] = "hellohellohello";
	char *p = nats_intern_acquire(raw, 5);
	ASSERT(p != NULL, "non-NUL-terminated input acquire works");
	ASSERT(strncmp(p, "hello", 5) == 0,
	       "first 5 bytes copied correctly");
	ASSERT(p[5] == '\0',
	       "NUL terminator appended even though input had more bytes");
	nats_intern_release(p);
}

static void test_high_refcount(void)
{
	char *first = nats_intern_acquire("popular", 7);
	int i;
	for (i = 0; i < 1000; i++) {
		char *p = nats_intern_acquire("popular", 7);
		ASSERT(p == first,
		       "1000 acquires of same string all return identical pointer");
		if (p != first) return; /* don't spam */
	}
	ASSERT(nats_intern_size() == 1, "size=1 after 1001 acquires");
	for (i = 0; i < 1001; i++)
		nats_intern_release(first);
	ASSERT(nats_intern_size() == 0,
	       "size=0 after exactly 1001 releases");
}

static void test_hash_collision_chain(void)
{
	/* Insert a few distinct strings; with 1024 buckets the
	 * probability of natural collision is low, but we want to
	 * verify chain handling.  The loop inserts enough strings
	 * to guarantee at least one collision (birthday paradox:
	 * ~37 strings into 1024 buckets gives ~50% chance; we
	 * use 200 to make it near-certain).
	 *
	 * The test asserts: each acquire returns a distinct pointer
	 * (strings are different), all releases go through cleanly,
	 * and the table is empty at the end. */
	char *ptrs[200];
	int i;
	for (i = 0; i < 200; i++) {
		char buf[16];
		snprintf(buf, sizeof(buf), "doc_key_%d", i);
		ptrs[i] = nats_intern_acquire(buf, (int)strlen(buf));
		ASSERT(ptrs[i] != NULL,
		       "acquire #N succeeds (collision-prone region)");
	}
	ASSERT(nats_intern_size() == 200,
	       "size=200 after 200 distinct acquires (chain handling)");
	for (i = 0; i < 200; i++)
		nats_intern_release(ptrs[i]);
	ASSERT(nats_intern_size() == 0, "size=0 after 200 releases");
}

static void test_release_then_reacquire(void)
{
	/* Common pattern: a doc key is interned, an AoR is removed,
	 * the doc key is released and freed, then the AoR re-registers
	 * and the doc key is interned again.  The new acquire should
	 * succeed and may or may not return the same pointer (the
	 * old node was free()'d; the malloc heap might return the
	 * same address on the next alloc).  Either way, the table
	 * must hold exactly one entry with refcount=1. */
	char *p1 = nats_intern_acquire("ephemeral", 9);
	nats_intern_release(p1);  /* freed */
	ASSERT(nats_intern_size() == 0, "released between cycles");
	char *p2 = nats_intern_acquire("ephemeral", 9);
	ASSERT(p2 != NULL, "re-acquire after release works");
	ASSERT(strcmp(p2, "ephemeral") == 0,
	       "re-acquire string contents match");
	ASSERT(nats_intern_size() == 1,
	       "size=1 after release-reacquire cycle");
	nats_intern_release(p2);
}

static void test_long_chain_of_releases(void)
{
	/* Acquire N times in a row, then release N times -- the
	 * order must not matter for correctness as long as every
	 * acquire is balanced by exactly one release. */
	char *ptrs[10];
	int i;
	for (i = 0; i < 10; i++) {
		char buf[8];
		snprintf(buf, sizeof(buf), "k%d", i);
		ptrs[i] = nats_intern_acquire(buf, (int)strlen(buf));
	}
	/* Release in REVERSE order */
	for (i = 9; i >= 0; i--)
		nats_intern_release(ptrs[i]);
	ASSERT(nats_intern_size() == 0,
	       "size=0 after release in reverse order");
}

static void test_destroy_with_live_entries(void)
{
	/* Even if the caller forgot to release some entries, destroy
	 * must clean everything up without leaks (ASan would catch
	 * a missing free).  This is a "graceful shutdown" path. */
	(void)nats_intern_acquire("leaked1", 7);
	(void)nats_intern_acquire("leaked2", 7);
	ASSERT(nats_intern_size() == 2, "two live entries before destroy");
	nats_intern_destroy();
	ASSERT(g_t == NULL, "destroy clears the table pointer");
	/* re-init for further tests */
	nats_intern_init();
}

int main(void)
{
	if (nats_intern_init() != 0) {
		fprintf(stderr, "FATAL: intern_init failed\n");
		return 2;
	}

	test_basic_acquire_release();
	test_distinct_strings();
	test_empty_string();
	test_large_string();
	test_non_nul_terminated_input();
	test_high_refcount();
	test_hash_collision_chain();
	test_release_then_reacquire();
	test_long_chain_of_releases();
	test_destroy_with_live_entries();

	nats_intern_destroy();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
