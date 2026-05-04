/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-2a regression test: tls_skip_verify must default to 0 (verify)
 * in event_nats so unconfigured deployments do not silently accept
 * MITM-vulnerable TLS connections.  Earlier code shipped with the
 * default = 1 (skip), which meant every untouched event_nats config
 * was insecure.
 *
 * cachedb_nats already defaults to 0; this test enforces parity.
 *
 * The test also asserts that mod_init emits an LM_WARN when
 * skip_verify ends up enabled (whether by explicit modparam or by
 * accident).
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_tls_default test_tls_default.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) hits++;
	fclose(f);
	return hits;
}

int main(void)
{
	/* CASE 1: event_nats default is 0 (verify) */
	int hits_default_zero = grep_count(
		"../event_nats.c",
		"int nats_tls_skip_verify = 0;");
	int hits_default_one  = grep_count(
		"../event_nats.c",
		"int nats_tls_skip_verify = 1;");
	ASSERT(hits_default_zero == 1,
		"event_nats.c declares nats_tls_skip_verify = 0");
	ASSERT(hits_default_one == 0,
		"event_nats.c does NOT declare nats_tls_skip_verify = 1");

	/* CASE 2: cachedb_nats default is 0 (already) */
	int cachedb_zero = grep_count(
		"../../cachedb_nats/cachedb_nats.c",
		"int   tls_skip_verify = 0;");
	ASSERT(cachedb_zero == 1,
		"cachedb_nats.c keeps tls_skip_verify = 0 (parity)");

	/* CASE 3: mod_init emits LM_WARN when skip_verify is in effect */
	int warn_hits = grep_count(
		"../event_nats.c",
		"NATS TLS server certificate verification is DISABLED");
	ASSERT(warn_hits >= 1,
		"event_nats mod_init has LM_WARN when skip_verify is on");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
