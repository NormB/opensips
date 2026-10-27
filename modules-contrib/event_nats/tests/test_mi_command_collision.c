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
 * Regression test: event_nats and nats_consumer both registered MI
 * commands named "nats_consumer_list" / _info / _create / _delete with
 * DIFFERENT semantics (event_nats: JetStream consumer admin;
 * nats_consumer: bound-handle listing).  Loading both modules registers
 * two commands of the same name -- an MI registration conflict and an
 * operator-facing ambiguity.
 *
 * Fix: rename event_nats's JetStream-admin set to nats_js_consumer_*
 * (mirroring its existing nats_stream_* family), leaving the
 * nats_consumer module the sole owner of the nats_consumer_* names.
 *
 * Source-pattern test; run from the event_nats tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_mi_command_collision test_mi_command_collision.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* True if @path contains @needle on any line. */
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

int main(void)
{
	const char *en = "../event_nats.c";

	/* event_nats must no longer register the colliding command names. */
	ASSERT(!file_contains(en, "{ \"nats_consumer_list\""),
		"event_nats does not register 'nats_consumer_list'");
	ASSERT(!file_contains(en, "{ \"nats_consumer_info\""),
		"event_nats does not register 'nats_consumer_info'");
	ASSERT(!file_contains(en, "{ \"nats_consumer_create\""),
		"event_nats does not register 'nats_consumer_create'");
	ASSERT(!file_contains(en, "{ \"nats_consumer_delete\""),
		"event_nats does not register 'nats_consumer_delete'");

	/* ...and uses the de-conflicted nats_js_consumer_* names instead. */
	ASSERT(file_contains(en, "{ \"nats_js_consumer_list\""),
		"event_nats registers 'nats_js_consumer_list'");
	ASSERT(file_contains(en, "{ \"nats_js_consumer_info\""),
		"event_nats registers 'nats_js_consumer_info'");
	ASSERT(file_contains(en, "{ \"nats_js_consumer_create\""),
		"event_nats registers 'nats_js_consumer_create'");
	ASSERT(file_contains(en, "{ \"nats_js_consumer_delete\""),
		"event_nats registers 'nats_js_consumer_delete'");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
