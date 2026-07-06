/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P4.5] Drain-timeout merge decision.  The shared shutdown drain
 * timeout is one pool value fed by a modparam in each module; the old
 * setter max-merged against the 5000 ms DEFAULT, so an operator's
 * explicit lower value (e.g. drain_timeout_ms=2000 for fast restarts)
 * was silently ignored.  Contract now:
 *
 *   - the FIRST explicit value replaces the default outright (an
 *     operator's choice out-ranks the built-in default, including
 *     below it),
 *   - across MULTIPLE explicit registrants the max wins (the longest
 *     configured shutdown grace, order-independent) -- and the setter
 *     WARNs when a lower explicit value is discarded (locked by the
 *     source pattern below).
 *
 * Drives nats_pool_drain_timeout_decide() from ../nats_pool.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_pool.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[2048];
	int found = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { found = 1; break; }
	fclose(f);
	return found;
}

int main(void)
{
	/* first explicit value replaces the default -- even BELOW it */
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 2000) == 2000,
		"first explicit 2000 beats the 5000 default (honored below)");
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 9000) == 9000,
		"first explicit 9000 beats the default upward too");
	CHECK(nats_pool_drain_timeout_decide(5000, 0, 0) == 0,
		"first explicit 0 (no drain) is an operator's call");

	/* subsequent explicit registrants: max wins, order-independent */
	CHECK(nats_pool_drain_timeout_decide(2000, 1, 8000) == 8000,
		"second registrant raising the grace wins");
	CHECK(nats_pool_drain_timeout_decide(8000, 1, 3000) == 8000,
		"second registrant lowering is out-ranked (max merge)");
	CHECK(nats_pool_drain_timeout_decide(4000, 1, 4000) == 4000,
		"equal explicit values are a no-op");

	/* the setter WARNs when an explicit lower value is discarded */
	CHECK(file_contains("../nats_pool.c", "nats_pool_drain_timeout_decide"),
		"the setter routes through the decide helper");
	{
		FILE *f = fopen("../nats_pool.c", "r");
		char buf[65536];
		size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
		const char *setter;
		if (f) fclose(f);
		buf[n] = '\0';
		setter = strstr(buf, "int nats_pool_drain_timeout_setter");
		CHECK(setter && strstr(setter, "LM_WARN") != NULL,
			"the setter WARNs on a discarded lower explicit value");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
