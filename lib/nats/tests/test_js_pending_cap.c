/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Regression test: nats_pool_get_js() initialised jsOptions and set only
 * the PublishAsync ack handler, leaving PublishAsync.MaxPending at 0 --
 * which cnats treats as UNLIMITED in-flight async publishes.  When
 * JetStream is connected but degraded (leader election, disk pressure)
 * the fast-fail never trips (the connection is still up), so every event
 * queues inside cnats in every SIP worker until the process runs out of
 * memory, while the "published" counter keeps incrementing.
 *
 * Fix: cap PublishAsync.MaxPending and set a small StallWait so
 * js_PublishAsync returns an error (counted as a drop by the producer's
 * existing `failed` stat) instead of growing memory without bound.
 *
 * Source-pattern test (run from the tests/ directory; reads
 * ../nats_pool.c): assert nats_pool_get_js() sets PublishAsync.MaxPending.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_js_pending_cap test_js_pending_cap.c
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

	ASSERT(grep_in_function(src, "nats_pool_get_js",
		"PublishAsync.MaxPending") >= 1,
		"nats_pool_get_js caps PublishAsync.MaxPending (bounded in-flight)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
