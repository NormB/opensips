/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_consumer_proc_main() returned early (bare
 * `return;`) when it could not obtain the NATS connection / JetStream
 * context at startup.  This dedicated process returning is an unexpected
 * child exit, which is fatal to the whole OpenSIPS instance -- so a NATS
 * broker that was merely down at boot took the entire SIP server with it.
 *
 * Fix: retry until the broker is reachable instead of returning.  The
 * process stays alive (calls keep flowing elsewhere) and the consumer
 * starts once the broker comes up.  nats_pool_get() re-attempts its
 * bounded internal connect on each call while the connection is unset, so
 * repeated calls are safe; the retry sleep is interrupted by SIGTERM on
 * shutdown.
 *
 * Source-pattern test (run from the tests/ directory; reads
 * ../nats_consumer_proc.c):
 *   - the main loop function must NOT contain a bare `return;` bail-out
 *     on the pool-unavailable path, and
 *   - it must retry (a sleep-based wait loop) instead.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_consumer_proc_boot_retry \
 *       test_consumer_proc_boot_retry.c
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
	const char *src = "../nats_consumer_proc.c";

	/* No bare `return;` bail-out: returning from this dedicated process
	 * is fatal to the instance. */
	ASSERT(grep_in_function(src, "nats_consumer_proc_main", "return;") == 0,
		"nats_consumer_proc_main has no fatal bare 'return;' bail-out");

	/* It still acquires the connection... */
	ASSERT(grep_in_function(src, "nats_consumer_proc_main",
		"nats_pool_get()") >= 1,
		"nats_consumer_proc_main still acquires the NATS connection");

	/* ...but retries (sleep-based wait) instead of giving up. */
	ASSERT(grep_in_function(src, "nats_consumer_proc_main", "sleep(") >= 1,
		"nats_consumer_proc_main retries with a wait instead of exiting");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
