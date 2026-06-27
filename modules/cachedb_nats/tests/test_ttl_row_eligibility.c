/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 Stage 2 [§5]: the per-message-TTL eligibility inputs that
 * _row_finalize_metadata() now exposes (row_exp / n_contacts / all_same) over
 * the contact expiry array, fed to _ttl_eligible().  A row gets a TTL only when
 * it is a single contact OR all contacts share one expiry -- otherwise a
 * min-expiry TTL would expire longer-lived siblings early (the reaper handles
 * mixed-expiry rows instead).
 *
 *   gcc -DELIG_CURRENT ... -> a wrong all_same that ignores mismatches (always 1),
 *                             so a mixed-expiry row is wrongly eligible => RED.
 *   gcc ...                -> the fixed extraction => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_row_eligibility test_ttl_row_eligibility.c
 */
#include <stdio.h>
#include <stdint.h>

/* carried copy: _ttl_eligible (cachedb_nats_ttl.c) */
static int _ttl_eligible(int64_t row_exp, int n_contacts, int all_same)
{
	(void)row_exp;
	if (n_contacts < 1)
		return 0;
	return (n_contacts == 1) || all_same;
}

/* carried copy: the all_same/row_exp extraction added to _row_finalize_metadata */
static void extract(const int64_t *exps, int n,
	int64_t *row_exp, int *n_contacts, int *all_same)
{
	int i, same = 1;
	int64_t mn = 0;
	for (i = 0; i < n; i++)
		if (i == 0 || exps[i] < mn) mn = exps[i];
#ifndef ELIG_CURRENT
	for (i = 1; i < n; i++)
		if (exps[i] != exps[0]) { same = 0; break; }
#endif
	*row_exp = (n > 0) ? mn : 0;
	*n_contacts = n;
	*all_same = (n <= 1) ? 1 : same;
}

static int fails = 0;
static void expect(const char *what, int got, int want)
{
	if (got == want) printf("  ok:   %-44s => %s\n", what, want ? "ELIGIBLE" : "not");
	else { printf("  FAIL: %-44s => %s (want %s)\n", what,
		got ? "ELIGIBLE":"not", want ? "ELIGIBLE":"not"); fails++; }
}

static int elig(const int64_t *e, int n)
{
	int64_t rx; int nc, as;
	extract(e, n, &rx, &nc, &as);
	return _ttl_eligible(rx, nc, as);
}

int main(void)
{
	int64_t one[]      = {1000};
	int64_t same3[]    = {1000, 1000, 1000};
	int64_t mixed2[]   = {1000, 2000};
	int64_t mixed3[]   = {1000, 1000, 2000};

	printf("[§5] per-message-TTL row eligibility:\n");
	expect("single contact",            elig(one, 1),    1);
	expect("3 contacts, same expiry",   elig(same3, 3),  1);
	expect("2 contacts, mixed expiry",  elig(mixed2, 2), 0);
	expect("3 contacts, one different", elig(mixed3, 3), 0);
	expect("no contacts",               elig(one, 0),    0);

	if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
	printf("\n=== ALL PASS (fails=0) ===\n");
	return 0;
}
