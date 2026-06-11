/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: event_nats child_init() returned -1 when it could not
 * obtain a NATS connection / JetStream context from the pool at startup.
 * A child_init that returns -1 is fatal to the OpenSIPS instance, so a
 * NATS broker that is merely down at boot took the ENTIRE SIP server with
 * it -- an eventing sidecar outage became a total call-processing outage.
 *
 * Fix: degrade instead of abort.  When the connection (or JS context)
 * cannot be obtained, log a warning and return 0.  The producer's publish
 * path already fails cleanly on a NULL connection (nats_producer.c: the
 * `!_nc` guard bumps the `failed` stat and returns -1), so the SIP server
 * boots and processes calls; only NATS event publishing is unavailable.
 *
 * This is a source-pattern test (same shape as
 * cachedb_nats/tests/test_disconnected_fastfail.c): it asserts that
 * child_init no longer contains a fatal `return -1` and instead degrades
 * with a warning + `return 0`.  Run from the tests/ directory (reads
 * ../event_nats.c).
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_child_init_degrade test_child_init_degrade.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Count occurrences of @needle inside the function body named @fn_name.
 * Skips the forward declaration; a body ends at a '}' in column 0. */
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
	const char *src = "../event_nats.c";

	/* child_init must NOT abort the worker (return -1) when the broker is
	 * unreachable at boot -- that is fatal to the whole instance. */
	ASSERT(grep_in_function(src, "child_init", "return -1") == 0,
		"child_init contains no fatal 'return -1' (degrades instead)");

	/* It must degrade: return 0 on the connection/JS-failure paths. */
	ASSERT(grep_in_function(src, "child_init", "return 0") >= 1,
		"child_init returns 0 (degraded) on failure paths");

	/* And it must log a warning so the degradation is visible to operators. */
	ASSERT(grep_in_function(src, "child_init", "LM_WARN") >= 1,
		"child_init logs LM_WARN when degrading");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
