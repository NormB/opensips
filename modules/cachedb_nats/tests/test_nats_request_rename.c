/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: cachedb_nats exported a script function named
 * "nats_request" with ALL_ROUTES -- a blocking synchronous NATS
 * request/reply (up to a 30s timeout) callable from request_route, where
 * it wedges a SIP worker.  It also collided by name with the
 * nats_consumer module's own (route-restricted) "nats_request".
 *
 * Fix: rename cachedb's export to "nats_cdb_request" (de-conflict) and
 * drop ALL_ROUTES for a mask that excludes the SIP request path, matching
 * nats_consumer's sync-RPC policy.
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
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return 0; }
	char line[2048];
	int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Return 1 if, within `span` lines after the line registering command
 * `cmd` (matched as `{"cmd",`), the text `needle` appears. */
static int near_registration(const char *path, const char *cmd,
	const char *needle, int span)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	char marker[128];
	snprintf(marker, sizeof(marker), "{\"%s\",", cmd);
	int countdown = -1, hit = 0;
	while (fgets(line, sizeof(line), f)) {
		if (countdown < 0 && strstr(line, marker))
			countdown = span;
		if (countdown >= 0) {
			if (strstr(line, needle)) { hit = 1; break; }
			if (countdown-- == 0) countdown = -1;
		}
	}
	fclose(f);
	return hit;
}

int main(void)
{
	const char *src = "../cachedb_nats.c";

	ASSERT(!file_contains(src, "{\"nats_request\","),
		"cachedb_nats no longer exports 'nats_request' (collision gone)");
	ASSERT(file_contains(src, "{\"nats_cdb_request\","),
		"cachedb_nats exports the renamed 'nats_cdb_request'");

	/* The renamed export must NOT be ALL_ROUTES, and must carry a
	 * SIP-request-path-excluding mask (ONREPLY/LOCAL/STARTUP/TIMER/EVENT). */
	ASSERT(!near_registration(src, "nats_cdb_request", "ALL_ROUTES", 8),
		"nats_cdb_request is not callable from ALL_ROUTES");
	ASSERT(near_registration(src, "nats_cdb_request", "ONREPLY_ROUTE", 8),
		"nats_cdb_request uses a restricted (non-request-path) route mask");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
