/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_pool_get_server_info() returned the connected URL
 * straight from natsConnection_GetConnectedUrl() with no redaction.  That
 * string is surfaced to MI clients (event_nats/nats_stats.c mi_nats_status)
 * and can carry "user:pass@host" credentials -- a password disclosure to
 * any MI caller.  The reconnect log path already redacts (nats_redact_url);
 * this function did not.
 *
 * Fix: run nats_redact_url() over the URL before returning it.
 *
 * Source-pattern test (run from the tests/ directory; reads
 * ../nats_pool.c): assert nats_pool_get_server_info() applies
 * nats_redact_url to the connected URL.  (nats_redact_url's own
 * correctness is covered by test_redact_url.)
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_server_info_redact test_server_info_redact.c
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
	const char *src = "../nats_pool.c";

	ASSERT(grep_in_function(src, "nats_pool_get_server_info",
		"nats_redact_url") >= 1,
		"nats_pool_get_server_info redacts the URL before returning it");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
