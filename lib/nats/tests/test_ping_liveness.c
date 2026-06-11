/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the pool connect options set no ping interval, so cnats
 * used its ~2-minute default x 2 missed pings (~4 minutes) to detect a
 * black-holed broker (a network drop with no RST).  Publishes run inline
 * in SIP workers, so until that detection trips, workers block/buffer.
 * Fix: set a short ping interval + max-pings-out so the dead link is
 * declared in ~20 s.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_ping_liveness test_ping_liveness.c
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

int main(void)
{
	const char *pool = "../nats_pool.c";
	const char *def  = "../nats_dl_table.def";

	ASSERT(file_contains(pool, "natsOptions_SetPingInterval"),
		"pool sets a ping interval for liveness probing");
	ASSERT(file_contains(pool, "natsOptions_SetMaxPingsOut"),
		"pool sets max-pings-out");
	ASSERT(file_contains(def, "natsOptions_SetPingInterval") &&
	       file_contains(def, "natsOptions_SetMaxPingsOut"),
		"ping options are in the dl symbol table");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
