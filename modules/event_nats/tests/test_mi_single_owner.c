/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Single-owner test for the JetStream observability MI commands.
 *
 * The defect (P0.3): both event_nats and cachedb_nats registered MI
 * commands named nats_stream_list / nats_stream_info.  mi/mi.c rejects
 * the duplicate registration and sr_module.c only LM_ERRs, so whichever
 * module loaded FIRST silently owned the command — while both docbooks
 * documented their own (different!) variants.  The duplicated global
 * handler symbols (mi_nats_stream_list/_info in two modules) were also
 * an ODR hazard for modules designed to co-load.
 *
 * Resolution: cachedb_nats_kvobs.c owns the read-only JS observability
 * MI (its variants have filter/pagination/format support); event_nats
 * keeps only its MUTATING admin commands (stream create/delete/purge,
 * consumer create/delete, msg get/delete) plus account_info.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build: gcc -g -O0 -Wall -o test_mi_single_owner test_mi_single_owner.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	const char *EN  = "../event_nats.c";
	const char *EJS = "../nats_jetstream.c";
	const char *EJH = "../nats_jetstream.h";
	const char *CN  = "../../cachedb_nats/cachedb_nats.c";

	/* event_nats must NOT register the observability commands... */
	ASSERT(!file_contains(EN, "\"nats_stream_list\""),
		"event_nats does not register MI nats_stream_list");
	ASSERT(!file_contains(EN, "\"nats_stream_info\""),
		"event_nats does not register MI nats_stream_info");

	/* ...and must not define/declare the duplicate handler symbols */
	ASSERT(!file_contains(EJS, "mi_nats_stream_list"),
		"nats_jetstream.c does not define mi_nats_stream_list");
	ASSERT(!file_contains(EJS, "mi_nats_stream_info"),
		"nats_jetstream.c does not define mi_nats_stream_info");
	ASSERT(!file_contains(EJH, "mi_nats_stream_list"),
		"nats_jetstream.h does not declare mi_nats_stream_list");
	ASSERT(!file_contains(EJH, "mi_nats_stream_info"),
		"nats_jetstream.h does not declare mi_nats_stream_info");

	/* the mutating admin commands stay with event_nats */
	ASSERT(file_contains(EN, "\"nats_stream_create\""),
		"event_nats keeps MI nats_stream_create");
	ASSERT(file_contains(EN, "\"nats_stream_delete\""),
		"event_nats keeps MI nats_stream_delete");
	ASSERT(file_contains(EN, "\"nats_stream_purge\""),
		"event_nats keeps MI nats_stream_purge");
	ASSERT(file_contains(EN, "\"nats_account_info\""),
		"event_nats keeps MI nats_account_info");

	/* cachedb_nats owns the observability commands */
	ASSERT(file_contains(CN, "\"nats_stream_list\""),
		"cachedb_nats registers MI nats_stream_list (owner)");
	ASSERT(file_contains(CN, "\"nats_stream_info\""),
		"cachedb_nats registers MI nats_stream_info (owner)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
