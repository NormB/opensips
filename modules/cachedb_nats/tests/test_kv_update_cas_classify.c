/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: w_nats_kv_update (cachedb_nats_native.c) wrote via
 * kvStore_UpdateString, which yields only a coarse natsStatus.  It treated
 * BOTH NATS_ERR and NATS_MISMATCH as a CAS conflict and returned -2 ("revision
 * mismatch, retry").  A generic NATS_ERR (transient/library failure that is
 * NOT a revision conflict) was therefore reported as retryable, so a script
 * CAS loop could spin on a non-retryable error instead of failing.
 *
 * Fix: route the CAS through nats_kv_put_row (js_PublishMsg with
 * ExpectLastSubjectSeq -- byte-for-byte the same optimistic check
 * kvStore_UpdateString(rev) performs, per cachedb_nats_expiry.c), which
 * returns the numeric jsErrCode inline.  Map it: committed -> 0, 10071 (wrong
 * last sequence) -> -2 (real CAS conflict, retry), anything else -> -1.
 *
 * Models the classification:
 *   -DSIMULATE_ERR_IS_RETRY -> every failure -> -2 -> a generic error is
 *                              wrongly reported retryable -> assertion FAILS.
 *   (default)               -> only 10071 -> -2, generic -> -1.
 * plus source-wiring assertions.
 *
 * Build: cc -g -O0 -Wall -o test_kv_update_cas_classify test_kv_update_cas_classify.c
 */

#include <stdio.h>
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
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

#define JS_WRONG_LAST_SEQ 10071

/* Model the script rc from a publish outcome: @ok = committed, else @jerr is
 * the JetStream error code. */
static int kv_update_rc(int ok, int jerr)
{
#ifdef SIMULATE_ERR_IS_RETRY
	(void)jerr;
	return ok ? 0 : -2;              /* old: any failure -> retry */
#else
	if (ok) return 0;
	if (jerr == JS_WRONG_LAST_SEQ) return -2;   /* real CAS conflict */
	return -1;                                  /* generic -> not retryable */
#endif
}

int main(void)
{
	ASSERT(kv_update_rc(1, 0) == 0, "a committed update returns 0");
	ASSERT(kv_update_rc(0, JS_WRONG_LAST_SEQ) == -2,
		"a wrong-last-sequence (10071) conflict returns -2 (retry)");
	ASSERT(kv_update_rc(0, /*generic jerr*/ 0) == -1,
		"a generic failure returns -1 (NOT reported as a retryable conflict)");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../cachedb_nats_native.c";
		ASSERT(file_contains(src, "nats_kv_put_row"),
			"w_nats_kv_update routes the CAS through nats_kv_put_row");
		ASSERT(!file_contains(src, "s == NATS_ERR || s == NATS_MISMATCH"),
			"the coarse 'NATS_ERR => CAS mismatch' heuristic is gone");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
