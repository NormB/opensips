/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Single-owner test for the script-level NATS request/reply function.
 *
 * History: cachedb_nats once exported a script function named
 * "nats_request" (blocking sync request/reply) that collided with the
 * nats_consumer module's route-restricted export of the same name.  A
 * first fix renamed cachedb's export to "nats_cdb_request", but that
 * left a duplicate implementation and a duplicate GLOBAL SYMBOL
 * (w_nats_request) defined in two modules designed to co-load.  P0.3
 * removed cachedb_nats's copy entirely: nats_consumer's nats_request
 * is strictly more capable (headers + async) and is the single owner.
 *
 * This test asserts the deletion held:
 *   - cachedb_nats exports NO request/reply script function;
 *   - cachedb_nats defines NO w_nats_request symbol;
 *   - the deleted function's tuning modparams went with it;
 *   - nats_consumer still exports "nats_request" (the owner).
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_nats_request_rename test_nats_request_rename.c
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
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	/* cachedb_nats's copy is gone -- script export and symbol */
	ASSERT(!file_contains("../cachedb_nats.c", "\"nats_cdb_request\""),
		"cachedb_nats no longer exports nats_cdb_request");
	ASSERT(!file_contains("../cachedb_nats.c", "w_nats_request"),
		"cachedb_nats.c has no w_nats_request reference");
	ASSERT(!file_contains("../cachedb_nats_native.c", "w_nats_request"),
		"cachedb_nats_native.c no longer defines w_nats_request");
	ASSERT(!file_contains("../cachedb_nats_native.h", "w_nats_request"),
		"cachedb_nats_native.h no longer declares w_nats_request");

	/* the deleted function's tuning modparams went with it */
	ASSERT(!file_contains("../cachedb_nats.c", "nats_request_max_reply"),
		"nats_request_max_reply modparam removed");
	ASSERT(!file_contains("../cachedb_nats.c",
		"nats_request_default_timeout_ms"),
		"nats_request_default_timeout_ms modparam removed");

	/* nats_consumer remains the single owner of nats_request */
	ASSERT(file_contains("../../nats_consumer/nats_consumer.c",
		"\"nats_request\""),
		"nats_consumer still exports nats_request (single owner)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
