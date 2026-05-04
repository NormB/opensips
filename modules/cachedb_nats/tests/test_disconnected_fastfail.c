/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-4b regression test: hot-path NATS calls (w_nats_request,
 * nats_evi_raise, w_nats_publish) must check nats_pool_is_connected()
 * before invoking the cnats blocking call.  The pool's nats_pool_get()
 * returns a live natsConnection pointer even when the underlying
 * connection is disconnected -- cnats lets the request hang until
 * reconnect or timeout, which is "head-of-line" blocking on a SIP
 * worker.
 *
 * The fix: each hot-path function calls nats_pool_is_connected() and
 * returns -1 immediately if the pool is not connected.  Test asserts
 * the call is present at every relevant site.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_disconnected_fastfail test_disconnected_fastfail.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* count occurrences of @needle inside a function definition named
 * @fn_name.  Scans all matches of "@fn_name(" -- forward
 * declarations end with a line containing ";" before the first '{'
 * line, so we skip those by only entering the body when we hit '{'.
 * Function ends at a '}' in column 0. */
static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	int seen_marker = 0;   /* awaiting body */
	int in_body = 0;
	char marker[256];
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') {
				in_body = 0;
				seen_marker = 0;
				continue;
			}
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			/* awaiting either ';' (decl, abort) or '{' (body) */
			if (strchr(line, ';')) { seen_marker = 0; continue; }
			if (strchr(line, '{')) { in_body = 1; continue; }
			continue;
		}
		if (strstr(line, marker)) {
			seen_marker = 1;
			/* same-line ';' means forward decl */
			if (strchr(line, ';')) seen_marker = 0;
			else if (strchr(line, '{')) {
				in_body = 1;
				seen_marker = 0;
			}
		}
	}
	fclose(f);
	return hits;
}

int main(void)
{
	int n;

	n = grep_in_function("../cachedb_nats_native.c", "w_nats_request",
		"nats_pool_is_connected");
	ASSERT(n >= 1,
		"w_nats_request checks nats_pool_is_connected before request");

	n = grep_in_function(
		"../../event_nats/event_nats.c",
		"nats_evi_raise",
		"nats_pool_is_connected");
	ASSERT(n >= 1,
		"nats_evi_raise checks nats_pool_is_connected before publish");

	n = grep_in_function(
		"../../event_nats/event_nats.c",
		"w_nats_publish",
		"nats_pool_is_connected");
	ASSERT(n >= 1,
		"w_nats_publish checks nats_pool_is_connected before publish");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
