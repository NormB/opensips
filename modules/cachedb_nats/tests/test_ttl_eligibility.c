/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P5 / TTL-SOLUTION-SPEC.md §5 [REV-6 / F6]: native per-key TTL eligibility.
 *
 * A single per-message TTL encodes ONE expiry (the earliest, row_exp = min).
 * If a row holds a long-lived contact beside a short-lived one, a min-derived
 * TTL would tombstone the WHOLE row — dropping the still-live contact (data
 * loss, not a missed optimization).  So set MsgTTL on a write IFF all of:
 *   1. row_exp != 0 (no permanent contact in the row), and
 *   2. the row holds exactly ONE contact, OR every contact shares the SAME
 *      expires (min == max, so the single TTL is correct for all).
 * Otherwise (mixed-expiry, any permanent, or empty row) -> no MsgTTL; plain CAS
 * write + reaper.  Re-evaluated on every write, so a row gains/loses its TTL as
 * it shrinks to / grows from a single (or uniform) contact set.
 *
 *   gcc -DTTLELIG_CURRENT ... -> naive: TTL whenever there is a contact
 *                               (ignores permanent + mixed-expiry) => RED.
 *   gcc ...                  -> the FIXED eligibility => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Tier-2 e2e (a mixed-expiry row's
 * long-lived contact survives past the short one's expiry) vs production.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_eligibility test_ttl_eligibility.c
 */
#include <stdio.h>
#include <stdint.h>

/* ─── carried copy of the production helper (cachedb_nats_ttl.c) ─── */
static int _ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry)
{
#ifdef TTLELIG_CURRENT
	return n_contacts >= 1;   /* naive: TTL whenever a contact exists */
#else
	if (n_contacts < 1)
		return 0;             /* empty row => no TTL */
	if (row_exp == 0)
		return 0;             /* a permanent contact => never auto-expire */
	return (n_contacts == 1) || all_same_expiry;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef TTLELIG_CURRENT
	printf("== carried copy: TTLELIG_CURRENT (naive) ==\n");
#else
	printf("== carried copy: FIXED eligibility ==\n");
#endif

	printf("[REV-6/F6] eligible rows (single, or uniform-expiry):\n");
	CHECK(_ttl_eligible(1000, 1, 0) == 1, "single contact => TTL eligible");
	CHECK(_ttl_eligible(1000, 3, 1) == 1, "multi but all-same-expiry => eligible");
	CHECK(_ttl_eligible(5000000000LL, 1, 0) == 1, "single, post-2038 row_exp => eligible");

	printf("[REV-6/F6] INELIGIBLE rows (the data-loss guards):\n");
	CHECK(_ttl_eligible(1000, 2, 0) == 0, "multi mixed-expiry => NO TTL (would tombstone live contact)");
	CHECK(_ttl_eligible(1000, 5, 0) == 0, "5 contacts mixed => NO TTL");
	CHECK(_ttl_eligible(0, 1, 0) == 0, "row_exp==0 (permanent present) => NO TTL");
	CHECK(_ttl_eligible(0, 3, 1) == 0, "permanent wins even over all-same => NO TTL");
	CHECK(_ttl_eligible(1000, 0, 1) == 0, "empty row => NO TTL");
	CHECK(_ttl_eligible(1000, 0, 0) == 0, "empty row (no flags) => NO TTL");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
