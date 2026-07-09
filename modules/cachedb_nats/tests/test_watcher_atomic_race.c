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
 * Regression test: cachedb_nats_watch.c stored the kvWatcher* handle in
 * a PLAIN (non-atomic) static, written by the watcher thread (create +
 * per-iteration teardown) and read/torn-down by nats_watch_stop() on
 * another thread.  The teardown sequence was a non-atomic
 *     w = _watcher; _watcher = NULL; Stop(w); Destroy(w);
 * which races nats_watch_stop()'s own read+Stop+Destroy: an overlapping
 * shutdown could let BOTH threads observe the same non-NULL handle and
 * call kvWatcher_Stop()/kvWatcher_Destroy() on it twice (double-free).
 *
 * The fix makes _watcher an `_Atomic kvWatcher*` and has every teardown
 * path claim it with a single atomic_exchange(&_watcher, NULL): only the
 * thread that swaps the non-NULL value to NULL owns the Stop/Destroy, so
 * the handle is freed exactly once no matter how the two shutdown paths
 * interleave.
 *
 * Part A is behavioural: N threads hammer atomic_exchange() on a shared
 * pointer; we assert exactly ONE thread ever observes the non-NULL value
 * (the "claim once" property the fix relies on).  A plain (non-atomic)
 * exchange under the same load loses claims / double-claims under TSan
 * or on weak-memory hardware -- the property the bug violated.
 *
 * Part B is structural: it greps the production source to confirm
 * _watcher is declared _Atomic and that both teardown sites use
 * atomic_exchange(&_watcher, NULL).
 *
 * Build:
 *   gcc -g -O0 -Wall -pthread -o test_watcher_atomic_race \
 *       test_watcher_atomic_race.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

/* ── Part A: atomic-exchange claim-once property ──────────────────── */

#define NTHREADS 16
#define NROUNDS  20000

/* one dummy "handle" per round; the winner of the exchange increments
 * its claim count.  After all threads finish a round, exactly one
 * claim must have been recorded. */
static _Atomic(void *) shared_handle;
static atomic_int      claims_this_round;

typedef struct { int total_claims; } thread_res_t;

static pthread_barrier_t barrier;

static void *claimer(void *arg)
{
	thread_res_t *r = arg;
	int round;
	for (round = 0; round < NROUNDS; round++) {
		/* all threads line up, then race to claim */
		pthread_barrier_wait(&barrier);
		void *claimed = atomic_exchange(&shared_handle, NULL);
		if (claimed) {
			atomic_fetch_add(&claims_this_round, 1);
			r->total_claims++;
		}
		/* re-arm + verify exactly one claim happened */
		pthread_barrier_wait(&barrier);
	}
	return NULL;
}

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int found = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { found = 1; break; }
	fclose(f);
	return found;
}

/* Count occurrences (across all lines) of a substring in a file. */
static int file_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int n = 0;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while ((p = strstr(p, needle))) { n++; p += strlen(needle); }
	}
	fclose(f);
	return n;
}

int main(void)
{
	pthread_t th[NTHREADS];
	thread_res_t res[NTHREADS];
	int i;
	int total_claims = 0;
	int bad_rounds = 0;

	memset(res, 0, sizeof(res));
	pthread_barrier_init(&barrier, NULL, NTHREADS + 1);

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&th[i], NULL, claimer, &res[i]);

	{
		int round;
		for (round = 0; round < NROUNDS; round++) {
			/* arm a non-NULL handle, release threads to race */
			atomic_store(&shared_handle, (void *)0xDEADBEEF);
			atomic_store(&claims_this_round, 0);
			pthread_barrier_wait(&barrier);   /* go */
			pthread_barrier_wait(&barrier);   /* done */
			int c = atomic_load(&claims_this_round);
			if (c != 1) bad_rounds++;
		}
	}

	for (i = 0; i < NTHREADS; i++) {
		pthread_join(th[i], NULL);
		total_claims += res[i].total_claims;
	}
	pthread_barrier_destroy(&barrier);

	ASSERT(bad_rounds == 0,
		"every armed handle is claimed by EXACTLY one thread "
		"(atomic_exchange claim-once)");
	ASSERT(total_claims == NROUNDS,
		"total successful claims == number of rounds (no lost/double "
		"claims)");
	fprintf(stderr, "  (rounds=%d bad_rounds=%d total_claims=%d)\n",
		NROUNDS, bad_rounds, total_claims);

	/* ── Part B: production source structure ───────────────────────── */
	{
		const char *p = "../cachedb_nats_watch.c";
		int exch;

		ASSERT(file_contains(p, "_Atomic") &&
		       file_contains(p, "_watcher"),
			"_watcher uses _Atomic in production source");
		/* the exact declaration line */
		ASSERT(file_contains(p, "_Atomic(kvWatcher *) _watcher"),
			"_watcher declared as _Atomic(kvWatcher *)");

		/* The in-worker pthread mode (and its nats_watch_stop
		 * teardown) was removed with the dedicated_watcher_proc
		 * modparam (P0.2); the loop's per-iteration teardown is the
		 * only claimant left — but it must still claim via
		 * atomic_exchange (cnats callbacks run on library threads). */
		exch = file_count(p, "atomic_exchange(&_watcher, NULL)");
		ASSERT(exch >= 1,
			"the teardown path atomic_exchange(&_watcher, NULL)s "
			"to claim the handle");

		/* the buggy plain clear must be gone */
		ASSERT(!file_contains(p, "_watcher = NULL;  /* clear first"),
			"old non-atomic 'clear first' teardown removed");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
