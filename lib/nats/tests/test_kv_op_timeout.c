/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_pool_get_js() left jsOptions.Wait at 0, so every
 * JetStream / KV operation inherited cnats's default 5 s request timeout.
 * On the usrloc hot path (a KV op per REGISTER) a slow-but-connected
 * broker would block a SIP worker for up to 5 s, far above any
 * per-REGISTER budget, with no way for the operator to tune it.
 *
 * Fix: a configurable nats_pool_kv_op_timeout_ms global (set via a module
 * modparam, e.g. cachedb_nats "kv_op_timeout_ms") is plumbed into
 * jsOptions.Wait.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_kv_op_timeout test_kv_op_timeout.c
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
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	const char *pool = "../nats_pool.c";
	const char *poolh = "../nats_pool.h";

	ASSERT(file_contains(pool, "nats_pool_kv_op_timeout_ms"),
		"nats_pool defines the kv-op timeout global");
	ASSERT(file_contains(poolh, "nats_pool_kv_op_timeout_ms"),
		"nats_pool.h exports the kv-op timeout global");
	ASSERT(grep_in_function(pool, "nats_pool_get_js", "jsOpts.Wait") >= 1,
		"nats_pool_get_js sets jsOpts.Wait from the configurable timeout");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
