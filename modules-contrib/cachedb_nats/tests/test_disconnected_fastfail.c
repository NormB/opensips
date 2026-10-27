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
 * Source test of the event_nats publish path while disconnected.
 *
 * A request (request/reply) on a disconnected connection waits for the
 * reconnect or its timeout, so the request paths fast-fail on
 * nats_pool_is_connected() (nats_consumer's test_request_fastfail).
 * A publish does not wait: while libnats reconnects it appends the
 * message to its reconnect buffer and returns, and sends the buffer
 * after the reconnect; a full buffer refuses the publish with
 * NATS_INSUFFICIENT_BUFFER, which the producer counts.  So the event_nats
 * publish path must NOT drop a message because the pool is disconnected
 * -- that dropped every event published during an outage.  The
 * behaviour is tested end to end by
 * modules-contrib/event_nats/tests/test_publish_during_disconnect.sh.
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

	/* (cachedb_nats's request/reply function was removed —
	 * nats_consumer owns nats_request and has its own fast-fail test,
	 * test_request_fastfail.) */

	/* nats_evi_raise and w_nats_publish share the publish path via
	 * nats_publish_checked().  Assert it does not drop on a disconnected
	 * pool and that both callers route through it. */
	n = grep_in_function(
		"../../event_nats/event_nats.c",
		"nats_publish_checked",
		"nats_pool_is_connected");
	ASSERT(n == 0,
		"nats_publish_checked does not drop a publish while disconnected");

	n = grep_in_function(
		"../../event_nats/event_nats.c",
		"nats_evi_raise",
		"nats_publish_checked");
	ASSERT(n >= 1,
		"nats_evi_raise publishes via the checked helper");

	n = grep_in_function(
		"../../event_nats/event_nats.c",
		"w_nats_publish",
		"nats_publish_checked");
	ASSERT(n >= 1,
		"w_nats_publish publishes via the checked helper");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
