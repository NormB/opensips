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
 * Regression test: the script-facing RPC functions checked only that the
 * subject was non-empty and within NATS_RING_SUBJECT_MAX -- they did NOT
 * reject CR/LF, spaces or wildcards.  A SIP-derived subject containing
 * "\r\n" injects raw commands onto the line-oriented NATS wire
 * ("PUB <subject>\r\n"), and a space/'*'/'>' corrupts the framing.
 *
 * Fix: run nats_validate_publish_subject() on the subject in
 *   - w_nats_request        (sync, nats_rpc.c)
 *   - w_nats_request_async  (async, nats_rpc_async.c)
 *   - w_nats_reply          (the reply-to subject, nats_rpc.c)
 * (The validator's own correctness is covered by
 * lib/nats/tests/test_validate_publish_subject.)
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_rpc_subject_validation \
 *       test_rpc_subject_validation.c
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
	const char *rpc   = "../nats_rpc.c";
	const char *async = "../nats_rpc_async.c";
	const char *needle = "nats_validate_publish_subject";

	ASSERT(grep_in_function(rpc, "w_nats_request", needle) >= 1,
		"w_nats_request validates the subject");
	ASSERT(grep_in_function(async, "w_nats_request_async", needle) >= 1,
		"w_nats_request_async validates the subject");
	ASSERT(grep_in_function(rpc, "w_nats_reply", needle) >= 1,
		"w_nats_reply validates the reply-to subject");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
