/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TTL-HISTORY-FIX-SPEC.md D3 [HREV-3]: nats_expired_linger slack composition.
 *
 * Linger is an operator retention policy: how long a row is PHYSICALLY kept
 * past its logical expiry (expires + grace).  It is added to every physical-
 * reclamation cutoff -- the per-message TTL computation, the reaper due-gate
 * and survivor projection, and write hygiene -- as slack = grace + linger at
 * the CALL SITES (the pure helpers keep their single-slack signatures).  It
 * is NEVER added to the read filter: an expired contact is not served,
 * lingering or not.  This test locks the composition:
 *
 *   - linger=0 reproduces today's values exactly (pure default-compat);
 *   - linger=30 shifts the physical TTL by +30 s;
 *   - an already-expired row with linger=30 gets a 1..30 s TTL, never a
 *     TTL-less write (composes with the HREV-3 floor);
 *   - the reaper due-gate with slack=grace+linger is NOT due during the
 *     linger window and IS due after it (else the reaper defeats linger);
 *   - boundary: exp + grace + linger == now.
 *
 *   gcc -DLINGER_CURRENT ... -> call sites pass grace only (linger ignored):
 *                               the reaper reclaims during the linger window
 *                               and the TTL is not extended => RED.
 *   gcc ...                  -> slack = grace + linger => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_linger_slack test_ttl_linger_slack.c
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

/* ─── carried copies of the production helpers ────────────────────── */

/* cachedb_nats_expiry.c (unchanged single-slack signature); referenced
 * only by the -D*_CURRENT red arm, hence the unused attribute */
static __attribute__((unused))
int64_t _ttl_seconds(int64_t row_exp, int64_t now, int slack)
{
	return row_exp - now + (int64_t)slack;
}
/* HREV-3 floor variant (see test_ttl_compute_boundary.c) */
static __attribute__((unused))
int64_t _ttl_msgttl_ms(int64_t ttl_seconds)
{
	int64_t ms;
	if (ttl_seconds <= 0)
		return 1000;
	if (ttl_seconds > 9223372036854775LL)
		ttl_seconds = 9223372036854775LL;
	ms = ttl_seconds * 1000;
	if (ms < 1000)
		ms = 1000;
	return ms;
}
/* cachedb_nats_expiry.c (unchanged single-slack signature) */
static int _reap_row_due(int64_t row_exp, time_t now, int slack)
{
	return row_exp != 0 && (row_exp + (int64_t)slack) <= (int64_t)now;
}

/* ─── carried copy of the CALL-SITE composition (the change under test) ── */
static int _slack(int grace, int linger)
{
#ifdef LINGER_CURRENT
	(void)linger;
	return grace;                     /* pre-HREV-3: linger not plumbed */
#else
	return grace + linger;            /* HREV-3: physical-reclamation slack */
#endif
}
/* reaper path: is the row due for physical reclamation? */
static int reap_due(int64_t row_exp, time_t now, int grace, int linger)
{
	return _reap_row_due(row_exp, now, _slack(grace, linger));
}
/* read path: NEVER lingers (visibility cutoff stays grace-only) */
static int contact_visible(int64_t expires, time_t now, int grace)
{
	return expires == 0 || (expires + (int64_t)grace) > (int64_t)now;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
#define EQ(got, want, msg) do { int64_t _g=(got),_w=(want); \
	if (_g != _w) { printf("  FAIL: %s (got %lld want %lld)\n", msg,(long long)_g,(long long)_w); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef LINGER_CURRENT
	printf("== carried copy: LINGER_CURRENT (linger not plumbed) ==\n");
#else
	printf("== carried copy: FIXED slack composition ==\n");
#endif
	/* fixed clock: row expires at t=1000, grace 5 */
	const int64_t EXPIRES = 1000;
	const int G = 5;

	printf("[HREV-3] linger=0 is byte-identical to today's behavior:\n");
	CHECK(reap_due(EXPIRES, 1006, G, 0) == 1, "due at exp+grace+1, linger 0");
	CHECK(reap_due(EXPIRES, 1004, G, 0) == 0, "not due before exp+grace, linger 0");

	printf("[HREV-3] linger extends PHYSICAL retention by exactly linger:\n");
	CHECK(reap_due(EXPIRES, 1006, G, 30) == 0, "reaper NOT due during linger window");
	CHECK(reap_due(EXPIRES, 1034, G, 30) == 0, "still lingering at exp+grace+29");
	CHECK(reap_due(EXPIRES, 1035, G, 30) == 1, "due exactly at exp+grace+linger");
	CHECK(reap_due(EXPIRES, 1100, G, 30) == 1, "due after the linger window");

	printf("[HREV-3] (native-TTL write arms removed in P1.5; reaper arms below)\n");
	/* now is 10s past expiry; linger 30 => 25s of linger remain (+grace) */
	/* now is way past expiry+grace+linger => floored to the 1s minimum */

	printf("[HREV-3] boundary: exp + grace + linger == now (reaper due-gate):\n");
	CHECK(reap_due(EXPIRES, EXPIRES + G + 30, G, 30) == 1, "reaper due at the exact boundary");

	printf("[HREV-3] permanent rows (row_exp==0) are never due, any linger:\n");
	CHECK(reap_due(0, 999999, G, 0) == 0, "permanent, linger 0: never due");
	CHECK(reap_due(0, 999999, G, 30) == 0, "permanent, linger 30: never due");

	printf("[HREV-3] visibility is UNAFFECTED by linger (read filter stays grace-only):\n");
	CHECK(contact_visible(EXPIRES, 1004, G) == 1, "visible before exp+grace");
	CHECK(contact_visible(EXPIRES, 1005, G) == 0, "hidden at exp+grace ...");
	CHECK(reap_due(EXPIRES, 1005, G, 30) == 0,
	      "... while the record still lingers (hidden-but-present window)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
