/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the consumer process matched its proc_sub_state_t by
 * handle ID STRING (find_sub_by_id) in ensure_subscription_for_handle, and
 * tear_down_retired_subs resolved the handle with
 * nats_registry_lookup_weak(&ss->id).  IDs are reused: unbind "X" then
 * rebind "X" before the teardown tick produces two distinct handles with
 * the same id.  ensure_subscription then found the OLD handle's sub for
 * the new handle (so the new handle never got its own subscription and
 * delivery wedged -- the old sub kept pushing into a ring no worker
 * reads), and the id-keyed teardown resolved to the live new handle
 * (retire==0), so the old retired handle was never torn down or reaped.
 *
 * Fix: match by handle IDENTITY, not id string -- find_sub_by_index(
 * h->index) for reconcile, and ss->h_ref for teardown.  Handle indices are
 * unique among live + retired-not-yet-reaped handles, so the old and new
 * "X" handles are told apart.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_sub_identity_match test_sub_identity_match.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
	char line[2048];
	int hits = 0, seen_marker = 0, in_body = 0;
	char marker[256];
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen_marker = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			if (strchr(line, ';')) { seen_marker = 0; continue; }
			if (strchr(line, '{')) { in_body = 1; continue; }
			continue;
		}
		if (strstr(line, marker)) {
			seen_marker = 1;
			if (strchr(line, ';')) seen_marker = 0;
			else if (strchr(line, '{')) { in_body = 1; seen_marker = 0; }
		}
	}
	fclose(f);
	return hits;
}

int main(void)
{
	/* After the proc-TU split, ensure_subscription_for_handle
	 * lives in the sub-config TU; the teardown stays in the proc TU. */
	const char *src = "../nats_consumer_proc.c";
	const char *sub = "../nats_sub_config.c";

	/* reconcile path keys on handle index, not id string. */
	ASSERT(grep_in_function(sub, "ensure_subscription_for_handle",
		"find_sub_by_index") >= 1,
		"ensure_subscription_for_handle matches by handle index");
	ASSERT(grep_in_function(sub, "ensure_subscription_for_handle",
		"find_sub_by_id") == 0,
		"ensure_subscription_for_handle no longer matches by id string");

	/* teardown resolves the specific handle via ss->h_ref, not a
	 * (reusable) id lookup. */
	ASSERT(grep_in_function(src, "tear_down_retired_subs",
		"ss->h_ref") >= 1,
		"tear_down_retired_subs resolves the handle via ss->h_ref (identity)");
	ASSERT(grep_in_function(src, "tear_down_retired_subs",
		"lookup_weak") == 0,
		"tear_down_retired_subs no longer resolves the handle by id string");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
