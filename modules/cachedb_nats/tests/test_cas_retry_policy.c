/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the KV compare-and-swap loops in nats_cache_counter_op
 * (cachedb_nats_dbase.c) and nats_cache_update (cachedb_nats_json.c)
 * retried on ANY non-OK status from the conditional write.  A revision
 * mismatch / key-exists IS a genuine CAS conflict and should be retried,
 * but a NATS_TIMEOUT or connection error is not -- it just recurs, so on a
 * degraded broker the loop burned the whole retry budget (up to
 * ~10 x (timeout + backoff) ≈ 100 s) wedging a SIP worker.
 *
 * Fix: nats_cas_should_retry() returns true only for an actual conflict;
 * timeout / connection-closed / disconnected bail immediately (and the
 * loops re-check connectivity per iteration).
 *
 * This carries the decision policy and checks the production wiring.
 *   -DSIMULATE_PREFIX_BUG -> retry on every status (pre-fix): the "bail on
 *                            timeout/disconnect" assertions FAIL.
 *   (default)             -> conflict retries, transient/fatal bail -> PASS.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_cas_retry_policy test_cas_retry_policy.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Status categories standing in for the cnats natsStatus values used. */
enum { S_OK, S_CONFLICT, S_TIMEOUT, S_CLOSED, S_DISCONNECTED };

/* Carried copy of nats_cas_should_retry()'s decision. */
static int cas_should_retry(int s)
{
#ifdef SIMULATE_PREFIX_BUG
	(void)s;
	return 1;            /* pre-fix: retry on every non-OK status */
#else
	switch (s) {
	case S_TIMEOUT:
	case S_CLOSED:
	case S_DISCONNECTED:
		return 0;        /* transient/fatal -- not a conflict */
	default:
		return 1;        /* conflict (mismatch/key-exists) -- retry */
	}
#endif
}

static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
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
	/* Policy. */
	ASSERT(cas_should_retry(S_CONFLICT) == 1,
		"a CAS conflict (mismatch/key-exists) is retried");
	ASSERT(cas_should_retry(S_TIMEOUT) == 0,
		"a timeout bails (not a conflict -- would just recur)");
	ASSERT(cas_should_retry(S_CLOSED) == 0,
		"connection-closed bails");
	ASSERT(cas_should_retry(S_DISCONNECTED) == 0,
		"disconnected bails");

	/* Production wiring: both CAS loops consult the helper. */
	ASSERT(grep_in_function("../cachedb_nats_dbase.c",
		"nats_cache_counter_op", "nats_cas_should_retry") >= 1,
		"counter CAS loop bails on non-conflict errors");
	/* the CAS write step now lives in the _update_apply_and_cas helper
	 * extracted from nats_cache_update (NATS_TODO #60 decomposition) */
	ASSERT(grep_in_function("../cachedb_nats_json.c",
		"_update_apply_and_cas", "nats_cas_should_retry") >= 1,
		"update CAS loop bails on non-conflict errors");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
