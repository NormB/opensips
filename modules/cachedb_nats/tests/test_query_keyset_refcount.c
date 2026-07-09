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
 * Regression test for TODO #41: the non-PK query path (nats_cache_query)
 * strdup'd the entire matched key set while holding the per-shard index
 * lock, then freed all those copies after fetching.  The fix snapshots the
 * already-interned key pointers with a refcount bump (nats_intern_retain)
 * instead of strdup'ing, so the lock holds only O(1) refcount bumps and no
 * allocation; every former free() of a key copy becomes a balanced
 * nats_intern_release().
 *
 * The danger the TODO flags is refcount imbalance across the ~dozen
 * cleanup sites and the AND-intersection: an over-release frees a key the
 * index still references (use-after-free in a sibling query), an
 * under-release leaks the intern entry.
 *
 * This test carries a faithful refcount-tracking intern model and exercises
 * the query's snapshot -> intersect -> cleanup ownership exactly as the
 * production accounting does, asserting that after the query every key's
 * refcount returns to its index baseline -- no leak, no over-release.  Plus
 * source-pattern assertions that the production path uses retain/release
 * and no longer strdup's the index keys.
 *
 * Build (self-contained):
 *   gcc -g -O0 -fsanitize=address -Wall -o test_query_keyset_refcount \
 *       test_query_keyset_refcount.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ---- faithful refcount-tracking intern model ------------------------ */

#define MAXNODES 64
static char  g_str[MAXNODES][32];
static int   g_rc[MAXNODES];
static int   g_nodes;
static int   g_underflow;   /* set if any release drops a refcount below 0 */

/* acquire content -> canonical pointer (the interned string), refcount++ */
static char *m_acquire(const char *s)
{
	int i;
	for (i = 0; i < g_nodes; i++)
		if (strcmp(g_str[i], s) == 0) { g_rc[i]++; return g_str[i]; }
	snprintf(g_str[g_nodes], sizeof(g_str[0]), "%s", s);
	g_rc[g_nodes] = 1;
	return g_str[g_nodes++];
}
static int m_index_of(const char *p)
{
	int i;
	for (i = 0; i < g_nodes; i++) if (g_str[i] == p) return i;
	return -1;
}
static char *m_retain(char *p)            /* bump an already-interned ptr */
{
	int i = m_index_of(p);
	if (i >= 0) g_rc[i]++;
	return p;
}
static void m_release(char *p)
{
	int i = m_index_of(p);
	if (i < 0) return;
	if (--g_rc[i] < 0) g_underflow = 1;   /* over-release => prod UAF */
}

/* ---- carried copy of the query keyset ownership -------------------- */

/* snapshot an index entry's key set under the (modelled) shard lock:
 * retain each interned pointer; NO strdup, NO allocation of strings. */
static char **snapshot(char *const *entry_keys, int n)
{
	char **out = malloc(sizeof(char *) * n);
	int k;
	for (k = 0; k < n; k++)
		out[k] = m_retain(entry_keys[k]);   /* refcount bump only */
	return out;
}

/* release every key ref in a match set, then free the array. */
static void release_set(char **keys, int n)
{
	int k;
	for (k = 0; k < n; k++)
		m_release(keys[k]);
	free(keys);
}

/* AND-intersect: survivors carry their existing ref (from `a`); the
 * mirror of strdup-survivor / free-both is retain-survivor / release-both. */
static char **intersect(char **a, int an, char **b, int bn, int *outn)
{
	char **res = malloc(sizeof(char *) * (an < bn ? an : bn));
	int i, j, n = 0;
	for (i = 0; i < an; i++)
		for (j = 0; j < bn; j++)
			if (a[i] == b[j]) { res[n++] = m_retain(a[i]); break; }
	release_set(a, an);
	release_set(b, bn);
	*outn = n;
	return res;
}

int main(void)
{
	/* ---- model: a two-filter AND query, refcounts must balance ---- */
	{
		/* The index owns one ref on each key (baseline). */
		char *A = m_acquire("doc-A");   /* rc 1 */
		char *B = m_acquire("doc-B");   /* rc 1 */
		char *C = m_acquire("doc-C");   /* rc 1 */
		char *filter1_keys[] = { A, B, C };   /* field1=val matched A,B,C */
		char *filter2_keys[] = { B, C };      /* field2=val matched B,C   */
		/* reset baselines to exactly the index's single ref */
		g_rc[m_index_of(A)] = g_rc[m_index_of(B)] = g_rc[m_index_of(C)] = 1;
		g_underflow = 0;

		/* run the query accounting */
		char **match = snapshot(filter1_keys, 3);
		int mc = 3;
		int nc;
		char **nk = intersect(match, mc, snapshot(filter2_keys, 2), 2, &nc);
		match = nk; mc = nc;

		ASSERT(mc == 2, "AND of {A,B,C} and {B,C} yields 2 survivors");

		/* ...fetch loop would use match[i] as read-only key strings... */

		/* final cleanup after the fetch */
		release_set(match, mc);

		ASSERT(!g_underflow, "no key refcount ever dropped below zero");
		ASSERT(g_rc[m_index_of(A)] == 1, "key A back to index baseline");
		ASSERT(g_rc[m_index_of(B)] == 1, "key B back to index baseline");
		ASSERT(g_rc[m_index_of(C)] == 1, "key C back to index baseline");
	}

	/* ---- model: empty intersection still balances ----------------- */
	{
		g_nodes = 0; g_underflow = 0;
		char *X = m_acquire("x");
		char *Y = m_acquire("y");
		char *f1[] = { X };
		char *f2[] = { Y };
		g_rc[m_index_of(X)] = g_rc[m_index_of(Y)] = 1;

		int nc;
		char **m = intersect(snapshot(f1, 1), 1, snapshot(f2, 1), 1, &nc);
		ASSERT(nc == 0, "disjoint filters intersect to empty");
		release_set(m, nc);
		ASSERT(!g_underflow, "empty-result path does not over-release");
		ASSERT(g_rc[m_index_of(X)] == 1 && g_rc[m_index_of(Y)] == 1,
			"both keys back to baseline after empty result");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *j = "../../cachedb_nats_fts/fts_query.c";
		const char *ih = "../../cachedb_nats_fts/fts_intern.h";
		ASSERT(file_contains(ih, "nats_intern_retain"),
			"intern table exposes nats_intern_retain");
		ASSERT(file_contains(j, "nats_intern_retain(e->keys["),
			"query snapshots index keys via retain (no strdup under lock)");
		ASSERT(file_contains(j, "nats_intern_release"),
			"query releases the snapshotted keys");
		ASSERT(!file_contains(j, "strdup(e->keys["),
			"query no longer strdup's index keys");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
