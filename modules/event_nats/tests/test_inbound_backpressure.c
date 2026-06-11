/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the event_nats inbound message callback
 * (nats_msg_handler) did three separate shm_malloc()s per message (event
 * struct + subject + data) and dispatched an IPC job with NO in-flight
 * cap and NO payload-size limit.  A publish flood -- especially of large
 * messages -- exhausts SHM and saturates the worker IPC queue, and the
 * per-message allocator lock traffic is the dominant cost at high event
 * rates (PERF_NOTES identifies SHM allocator locking as the top
 * bottleneck).
 *
 * Fix:
 *   - one combined shm_malloc (event struct + subject + data in a single
 *     block, freed with a single shm_free),
 *   - reject oversized payloads (NATS_EVENT_MAX_DATA), and
 *   - bound the number of in-flight events with a shared SHM gauge,
 *     dropping (and counting) when the high-water mark is reached.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_inbound_backpressure test_inbound_backpressure.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Count occurrences of @needle inside the body of function @fn_name. */
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
	const char *src = "../event_nats_sub.c";

	/* Exactly one combined allocation per message (was 3). */
	ASSERT(grep_in_function(src, "nats_msg_handler", "shm_malloc") == 1,
		"nats_msg_handler does a single combined shm_malloc per message");

	/* Reject oversized payloads. */
	ASSERT(grep_in_function(src, "nats_msg_handler", "NATS_EVENT_MAX_DATA") >= 1,
		"nats_msg_handler rejects oversized payloads (NATS_EVENT_MAX_DATA)");

	/* Bound the number of in-flight events. */
	ASSERT(grep_in_function(src, "nats_msg_handler", "NATS_EVENT_MAX_INFLIGHT") >= 1,
		"nats_msg_handler bounds in-flight events (NATS_EVENT_MAX_INFLIGHT)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
