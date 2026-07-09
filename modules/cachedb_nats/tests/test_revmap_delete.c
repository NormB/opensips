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
 * Regression test for the doc-key -> field:value reverse map that lets the
 * KV watcher's delete-by-key path remove a document from only the entries
 * it was indexed under (O(fields)) instead of walking every bucket under
 * all shard locks (the old nats_json_index_remove, O(buckets x entries)).
 *
 * This carries a faithful model of the reverse map (sharded hash table
 * with the SAME snapshot-under-rev-lock / process-without-rev-lock
 * discipline as nats_json_index_remove_by_revmap) and exercises:
 *   A. correctness   -- a "take" returns exactly the recorded fv strings
 *                       and removes the node; a miss returns -1 (so the
 *                       caller falls back to the full walk);
 *   B. lock discipline-- the reverse-shard lock is NEVER held while the
 *                       forward (index) work runs; an assertion trips if
 *                       it ever is (this is what makes the two lock sets
 *                       deadlock-free);
 *   C. concurrency   -- many threads put + take their own keys with no
 *                       corruption (final map empty).
 * Plus source-pattern checks of the production wiring.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address,undefined -Wall -pthread \
 *       -o test_revmap_delete test_revmap_delete.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ── model of the reverse map ────────────────────────────────────── */

#define NBUCKETS 256
#define NSHARDS  16
#define SHARD_OF(b) ((b) % NSHARDS)

typedef struct node {
	struct node *next;
	unsigned int hash;
	int   key_len, n_fv, blob_len;
	char *blob;
	char  key[];
} node;

static node          *g_buckets[NBUCKETS];
static pthread_mutex_t g_locks[NSHARDS];

/* Tracks, per shard, whether the reverse lock is currently held, so the
 * forward-work model can assert it is NOT held (lock discipline). */
static __thread int t_rev_held_shard = -1;

static unsigned int h_of(const char *s, int len)
{
	unsigned int h = 5381; int i;
	for (i = 0; i < len; i++) h = ((h << 5) + h) + (unsigned char)s[i];
	return h % NBUCKETS;
}

static void rev_put(const char *key, const char *blob, int blob_len, int n_fv)
{
	int kl = (int)strlen(key);
	unsigned int hash = h_of(key, kl), b = hash;
	int sh = SHARD_OF(b);
	node *n, **pp;
	char *bc = malloc(blob_len);
	memcpy(bc, blob, blob_len);

	pthread_mutex_lock(&g_locks[sh]);
	for (pp = &g_buckets[b]; *pp; pp = &(*pp)->next) {
		n = *pp;
		if (n->hash == hash && n->key_len == kl &&
		    memcmp(n->key, key, kl) == 0) {
			free(n->blob); n->blob = bc; n->blob_len = blob_len; n->n_fv = n_fv;
			pthread_mutex_unlock(&g_locks[sh]); return;
		}
	}
	n = malloc(sizeof(*n) + kl + 1);
	n->hash = hash; n->key_len = kl; n->n_fv = n_fv;
	n->blob_len = blob_len; n->blob = bc;
	memcpy(n->key, key, kl); n->key[kl] = '\0';
	n->next = g_buckets[b]; g_buckets[b] = n;
	pthread_mutex_unlock(&g_locks[sh]);
}

/* The remove_by_revmap core: snapshot+unlink under the rev lock, release
 * it, then run the "forward" work.  Returns the field count, or -1 on miss.
 * @fwd is the modeled forward-index removal, which asserts the rev lock is
 * released before it runs. */
static int rev_take(const char *key, void (*fwd)(const char *fv))
{
	int kl = (int)strlen(key);
	unsigned int hash = h_of(key, kl), b = hash;
	int sh = SHARD_OF(b), i, off, n_fv = 0, blob_len = 0;
	node *n, **pp;
	char *blob = NULL;
	const char *p;

	pthread_mutex_lock(&g_locks[sh]);
	t_rev_held_shard = sh;
	for (pp = &g_buckets[b]; *pp; pp = &(*pp)->next) {
		n = *pp;
		if (n->hash == hash && n->key_len == kl &&
		    memcmp(n->key, key, kl) == 0) {
			blob = malloc(n->blob_len);
			memcpy(blob, n->blob, n->blob_len);
			blob_len = n->blob_len; n_fv = n->n_fv;
			*pp = n->next;
			t_rev_held_shard = -1;
			pthread_mutex_unlock(&g_locks[sh]);
			free(n->blob); free(n);
			goto have;
		}
	}
	t_rev_held_shard = -1;
	pthread_mutex_unlock(&g_locks[sh]);
	return -1;
have:
	p = blob; off = 0;
	for (i = 0; i < n_fv && off < blob_len; i++) {
		int flen = (int)strlen(p);
		if (fwd) fwd(p);
		off += flen + 1; p += flen + 1;
	}
	free(blob);
	return n_fv;
}

/* Forward-removal model: assert the reverse lock is NOT held. */
static int g_fwd_calls;
static void fwd_model(const char *fv)
{
	(void)fv;
	if (t_rev_held_shard != -1) {
		fprintf(stderr, "FAIL: reverse lock held during forward work "
			"(deadlock hazard)\n");
		g_fails++;
	}
	__atomic_fetch_add(&g_fwd_calls, 1, __ATOMIC_RELAXED);
}

static int g_size(void)
{
	int i, c = 0; node *n;
	for (i = 0; i < NBUCKETS; i++)
		for (n = g_buckets[i]; n; n = n->next) c++;
	return c;
}

/* helper: build a blob from a NULL-terminated array of fv strings */
static int build_blob(char *out, const char *fvs[], int *n_fv)
{
	int len = 0, i;
	for (i = 0; fvs[i]; i++) {
		int l = (int)strlen(fvs[i]);
		memcpy(out + len, fvs[i], l + 1);
		len += l + 1;
	}
	*n_fv = i;
	return len;
}

/* ── concurrency ─────────────────────────────────────────────────── */

#define THREADS 8
#define ITERS   2000
static void *worker(void *arg)
{
	long id = (long)arg;
	char key[64], blob[256];
	const char *fvs[4];
	int n_fv, blob_len, it;
	for (it = 0; it < ITERS; it++) {
		snprintf(key, sizeof(key), "aor-%ld-%d", id, it);
		fvs[0] = "contact:sip:a"; fvs[1] = "expires:60";
		fvs[2] = "callid:xyz";    fvs[3] = NULL;
		blob_len = build_blob(blob, fvs, &n_fv);
		rev_put(key, blob, blob_len, n_fv);
		int got = rev_take(key, fwd_model);
		if (got != 3) {
			fprintf(stderr, "FAIL: concurrent take got %d (want 3)\n", got);
			__atomic_fetch_add(&g_fails, 1, __ATOMIC_RELAXED);
		}
	}
	return NULL;
}

/* ── source-pattern ──────────────────────────────────────────────── */

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[4096]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[4096]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	int i;
	for (i = 0; i < NSHARDS; i++) pthread_mutex_init(&g_locks[i], NULL);

	/* A. correctness */
	{
		char blob[256]; const char *fvs[] = {"f1:v1","f2:v2","f3:v3",NULL};
		int n_fv, bl = build_blob(blob, fvs, &n_fv);
		rev_put("doc1", blob, bl, n_fv);
		ASSERT(g_size() == 1, "rev_put records the doc");
		g_fwd_calls = 0;
		ASSERT(rev_take("doc1", fwd_model) == 3,
			"take returns the 3 recorded fv strings");
		ASSERT(g_fwd_calls == 3, "forward removal ran for each recorded field");
		ASSERT(g_size() == 0, "node removed after take");
		ASSERT(rev_take("doc1", fwd_model) == -1,
			"second take misses (caller falls back to full walk)");
	}

	/* put-replace */
	{
		char b1[64], b2[64]; const char *a[] = {"x:1",NULL}, *c[] = {"y:2","z:3",NULL};
		int n; int l1 = build_blob(b1, a, &n);
		rev_put("d2", b1, l1, n);
		int l2 = build_blob(b2, c, &n);
		rev_put("d2", b2, l2, n);
		ASSERT(g_size() == 1, "put-replace keeps a single node");
		ASSERT(rev_take("d2", NULL) == 2, "replaced node has the new fv set");
	}

	/* C. concurrency: distinct keys, no corruption, empty at the end */
	{
		pthread_t th[THREADS]; long t;
		for (t = 0; t < THREADS; t++) pthread_create(&th[t], NULL, worker, (void*)t);
		for (t = 0; t < THREADS; t++) pthread_join(th[t], NULL);
		ASSERT(g_size() == 0, "concurrent put+take leaves the map empty");
	}

	/* D. production wiring */
	{
		const char *json  = "../../cachedb_nats_fts/fts_index.c";
		const char *watch = "../cachedb_nats_watch.c";
		ASSERT(grep_in_function(json, "nats_json_index_add", "nats_rev_put") >= 1,
			"index_add populates the reverse map");
		ASSERT(file_contains(watch, "cdbn_fts.remove_by_revmap"),
			"watcher delete path uses the reverse-map fast delete");
		ASSERT(file_contains(watch, "cdbn_fts.remove(key)"),
			"watcher keeps the full-walk remove as the fallback");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
