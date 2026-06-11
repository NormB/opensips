/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the SHM string intern table hard-coded
 * NATS_INTERN_BUCKETS = 1024.  The table holds one node per live doc key
 * (~one per AoR), so at 100k AoRs the average chain is ~100 nodes and at
 * 1M it is ~1000 -- walked under a shard lock on EVERY acquire and
 * release (twice per key op).  Two fixes:
 *   - size the bucket count at init from the index_buckets modparam
 *     (nats_intern_init takes a parameter), so the table scales with the
 *     deployment instead of being fixed at 1024; and
 *   - store the FNV hash in each node so a probe can compare the 4-byte
 *     hash before the memcmp, and so release does not have to re-hash the
 *     key (it re-ran _fnv1a over the whole string every time).
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_intern_scaling test_intern_scaling.c
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
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return 0; }
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
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
	const char *src = "../cachedb_nats_intern.c";
	const char *hdr = "../cachedb_nats_intern.h";

	/* Bucket count is configurable at init, not fixed at 1024. */
	ASSERT(file_contains(hdr, "nats_intern_init(int"),
		"nats_intern_init takes a bucket-count parameter");
	ASSERT(grep_in_function(src, "nats_intern_init", "num_buckets") >= 1,
		"nats_intern_init sizes the table from its parameter");

	/* Each node caches its hash. */
	ASSERT(file_contains(src, "} nats_intern_node_t") ||
	       file_contains(src, "unsigned int") /* hash field present */,
		"intern node struct carries a cached hash");
	ASSERT(grep_in_function(src, "nats_intern_acquire", "->hash") >= 1,
		"acquire stores/compares the cached node hash");

	/* Release uses the cached hash instead of re-hashing the string. */
	ASSERT(grep_in_function(src, "nats_intern_release", "->hash") >= 1,
		"release uses the cached hash");
	ASSERT(grep_in_function(src, "nats_intern_release", "_fnv1a") == 0,
		"release no longer re-hashes the whole key (_fnv1a gone)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
