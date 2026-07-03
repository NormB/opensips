/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P9 / SPEC.md §4.3A [REV-1/16/21]: the reaper's row-selection and per-row
 * action decisions (the broker-less core of the reaper loop).
 *
 *   _reap_row_due(row_exp, now, grace): a row is a reap candidate iff
 *     row_exp != 0 && row_exp + grace <= now.  row_exp == 0 is PERMANENT and is
 *     NEVER due (a permanent contact must never be reaped); the +grace (= S, max
 *     skew) margin means the reaper never purges within S of an expiry.
 *
 *   _reap_row_action(n_live_survivors): after the reaper prunes the expired
 *     contacts of a due row, > 0 survivors => a CAS survivor-write through
 *     nats_kv_put_row (which RE-asserts the per-message TTL, [TREV-3], and
 *     preserves aorhash/schema_version, [REV-31]); 0 survivors => a CAS-guarded
 *     publish-delete (never a revision-blind kvStore_Delete, [REV-16]).
 *
 *   gcc -DREAP_CURRENT ... -> naive: ignores the grace margin AND reaps
 *                            row_exp==0 (would purge permanent contacts) => RED.
 *   gcc ...               -> the FIXED decisions => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proofs are the reaper e2e (survivor re-asserts TTL;
 * a concurrent renew makes the CAS delete fail and the contact survives).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_select test_reap_select.c
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

enum reap_action { REAP_WRITE_SURVIVORS = 0, REAP_DELETE_EMPTY = 1 };

/* ─── carried copies of the production helpers (cachedb_nats_expiry.c) ─ */
static int _reap_row_due(int64_t row_exp, time_t now, int grace)
{
#ifdef REAP_CURRENT
	return row_exp <= (int64_t)now;   /* naive: no grace, reaps permanent (0) */
#else
	return row_exp != 0 && (row_exp + (int64_t)grace) <= (int64_t)now;
#endif
}
static enum reap_action _reap_row_action(int n_live_survivors)
{
	return (n_live_survivors > 0) ? REAP_WRITE_SURVIVORS : REAP_DELETE_EMPTY;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	const time_t now = 1000;
	const int S = 5;

#ifdef REAP_CURRENT
	printf("== carried copy: REAP_CURRENT (no grace, reaps permanent) ==\n");
#else
	printf("== carried copy: FIXED reaper decisions ==\n");
#endif

	printf("[REV-1] row due selection (now=1000, S=5):\n");
	CHECK(_reap_row_due(900, now, S) == 1, "row_exp 900 +5 <= 1000 => due");
	CHECK(_reap_row_due(995, now, S) == 1, "row_exp 995 +5 == 1000 boundary => due");
	CHECK(_reap_row_due(996, now, S) == 0, "row_exp 996 +5 > 1000 => NOT due (within skew)");
	CHECK(_reap_row_due(2000, now, S) == 0, "future row_exp => not due");
	CHECK(_reap_row_due(0, now, S) == 0, "row_exp==0 (permanent) => NEVER due");
	CHECK(_reap_row_due(0, 9999999999LL, S) == 0, "permanent still not due far in the future");
	CHECK(_reap_row_due(5000000000LL, now, S) == 0, "post-2038 future row_exp => not due");

	printf("[REV-16/31] per-row action after pruning:\n");
	CHECK(_reap_row_action(3) == REAP_WRITE_SURVIVORS, "3 survivors => CAS survivor-write (re-assert TTL)");
	CHECK(_reap_row_action(1) == REAP_WRITE_SURVIVORS, "1 survivor => survivor-write");
	CHECK(_reap_row_action(0) == REAP_DELETE_EMPTY, "0 survivors => CAS-guarded publish-delete");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
