/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for two resource-bound guards:
 *   - ring_capacity at bind time was validated as a power of two >= 2 but
 *     had NO upper cap, so a single MI bind could request up to 2^31 slots
 *     (~17.7 KB each ≈ 38 TB of SHM).  Now capped at NATS_RING_CAPACITY_MAX
 *     (65536, ~1.2 GB).
 *   - the ASYNC nats_fetch with timeout_ms <= 0 set no deadline, so the
 *     resume param held the handle's pending_ops reference and ticked a
 *     1 ms timerfd forever if no message arrived.  Now rejected.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_bind_bounds test_bind_bounds.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
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
	const char *parse = "../nats_handle_parse.c";
	const char *fetch = "../nats_fetch.c";

	ASSERT(file_contains(parse, "NATS_RING_CAPACITY_MAX"),
		"ring_capacity has an upper cap constant");
	ASSERT(file_contains(parse, "ring_capacity > NATS_RING_CAPACITY_MAX"),
		"bind rejects an over-cap ring_capacity");

	ASSERT(grep_in_function(fetch, "w_nats_fetch_async", "tmo <= 0") >= 1,
		"async fetch rejects a non-positive timeout");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
