/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TTL-HISTORY-FIX-SPEC.md D1 [HREV-1]: the per-message-TTL fast path requires
 * a bucket that keeps NO old revisions (MaxMsgsPerSubject == 1).
 *
 * Verified live on nats-server 2.11.10 (spec §0, E1/E3): on a history>1
 * bucket a TTL'd head is removed only at ~LimitMarkerTTL and the subject then
 * ROLLS BACK to the previous revision instead of expiring -- the key appears
 * to come back from the dead.  So:
 *
 *   _kv_ttl_history_ok(mmps, allow_history)  1 = TTL usable, 0 = refuse
 *       (fall back to reaper-only expiry).  mmps==1 always ok; mmps!=1 only
 *       with the operator's explicit nats_ttl_allow_history=1 override.
 *       mmps==0 means "unlimited" on the server -- history-keeping, refuse.
 *   _kv_history_ttl_warn(mmps)               1 = emit the startup WARN
 *       (any history-keeping stream warns, override or not: the operator
 *       must always learn that expiry semantics are degraded).
 *
 *   gcc -DHIST_CURRENT ... -> pre-HREV-1: no history check (TTL reported
 *                             usable on any bucket, no warn) => RED.
 *   gcc ...                -> the FIXED gate => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_history_ttl_warn test_kv_history_ttl_warn.c
 */
#include <stdio.h>
#include <stdint.h>

/* ─── carried copies of the production helpers (cachedb_nats_ttl.c) ─── */

static int _kv_ttl_history_ok(int64_t mmps, int allow_history)
{
#ifdef HIST_CURRENT
	(void)mmps; (void)allow_history; return 1;   /* no gate */
#else
	if (mmps == 1)
		return 1;
	return allow_history ? 1 : 0;
#endif
}

static int _kv_history_ttl_warn(int64_t mmps)
{
#ifdef HIST_CURRENT
	(void)mmps; return 0;                        /* never warns */
#else
	return mmps != 1;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef HIST_CURRENT
	printf("== carried copy: HIST_CURRENT (no history gate) ==\n");
#else
	printf("== carried copy: FIXED history gate ==\n");
#endif

	printf("[HREV-1] MaxMsgsPerSubject==1 is the only TTL-safe stream shape:\n");
	CHECK(_kv_ttl_history_ok(1, 0) == 1, "mmps=1 => TTL usable");
	CHECK(_kv_ttl_history_ok(2, 0) == 0, "mmps=2 => refused (rollback risk)");
	CHECK(_kv_ttl_history_ok(5, 0) == 0, "mmps=5 (old default) => refused");
	CHECK(_kv_ttl_history_ok(64, 0) == 0, "mmps=64 => refused");
	CHECK(_kv_ttl_history_ok(0, 0) == 0, "mmps=0 (server 'unlimited') => refused");
	CHECK(_kv_ttl_history_ok(-1, 0) == 0, "nonsense negative => refused (fail closed)");

	printf("[HREV-1/D6] nats_ttl_allow_history=1 is an explicit override:\n");
	CHECK(_kv_ttl_history_ok(5, 1) == 1, "mmps=5 + override => TTL used (operator's call)");
	CHECK(_kv_ttl_history_ok(1, 1) == 1, "mmps=1 + override => still fine (no-op)");

	printf("[HREV-1] the WARN fires for ANY history-keeping stream, override or not:\n");
	CHECK(_kv_history_ttl_warn(1) == 0, "mmps=1 => no warn");
	CHECK(_kv_history_ttl_warn(5) == 1, "mmps=5 => warn");
	CHECK(_kv_history_ttl_warn(0) == 1, "mmps=0 (unlimited) => warn");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
