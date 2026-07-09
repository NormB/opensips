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
 * Regression test: nats_consumer.c registers nats_request
 * with ALL_ROUTES, allowing the script to call this synchronous,
 * worker-blocking function from request_route.  A single 30-second
 * timeout there stalls the SIP UDP worker entirely.
 *
 * Fix: replace ALL_ROUTES with a route mask that excludes the
 * synchronous SIP-processing routes (REQUEST_ROUTE, FAILURE_ROUTE,
 * BRANCH_ROUTE, ERROR_ROUTE).  The function remains callable from
 * ONREPLY_ROUTE | LOCAL_ROUTE | STARTUP_ROUTE | TIMER_ROUTE |
 * EVENT_ROUTE -- contexts that either don't own a SIP UDP worker
 * (startup, timer, event) or already accept blocking semantics
 * (onreply, local).
 *
 * Test: pattern-match the route mask string used at the
 * nats_request cmd_export site.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_request_route_restriction test_request_route_restriction.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *read_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	rewind(f);
	char *buf = malloc(sz + 1);
	if (!buf) { fclose(f); return NULL; }
	fread(buf, 1, sz, f);
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

int main(void)
{
	char *src = read_file("../nats_consumer.c");
	ASSERT(src != NULL, "open ../nats_consumer.c");
	if (!src) return 1;

	/* find the "{ \"nats_request\", " entry and capture the next
	 * 600 chars -- enough to span the multi-line cmd_export entry,
	 * including the route mask which sits after the param-array
	 * "{0, 0, 0}}," close. */
	const char *p = strstr(src, "\"nats_request\"");
	ASSERT(p != NULL, "found \"nats_request\" cmd_export entry");
	if (!p) { free(src); return 1; }

	int len = (int)strlen(p);
	if (len > 600) len = 600;
	char snippet[700];
	memcpy(snippet, p, len);
	snippet[len] = '\0';

	int has_all = strstr(snippet, "ALL_ROUTES") != NULL;
	ASSERT(!has_all,
		"nats_request entry no longer uses ALL_ROUTES");

	ASSERT(strstr(snippet, "REQUEST_ROUTE") == NULL,
		"nats_request entry excludes REQUEST_ROUTE");
	ASSERT(strstr(snippet, "FAILURE_ROUTE") == NULL,
		"nats_request entry excludes FAILURE_ROUTE");
	ASSERT(strstr(snippet, "BRANCH_ROUTE") == NULL,
		"nats_request entry excludes BRANCH_ROUTE");

	ASSERT(strstr(snippet, "STARTUP_ROUTE") != NULL,
		"nats_request entry includes STARTUP_ROUTE");
	ASSERT(strstr(snippet, "TIMER_ROUTE") != NULL,
		"nats_request entry includes TIMER_ROUTE");
	ASSERT(strstr(snippet, "LOCAL_ROUTE") != NULL,
		"nats_request entry includes LOCAL_ROUTE");

	free(src);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
