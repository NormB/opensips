/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-2b regression test: silent TLS downgrade must require explicit
 * operator opt-in via tls_allow_downgrade=1.  By default, any tls://
 * URL configured against a TLS-less nats.c build must hard-fail at
 * pool registration rather than silently rewriting URLs to nats://.
 *
 * The test is structural: it asserts the new field exists, the default
 * is 0 (fail-safe), the production source has the LM_ERR path, and
 * both wrapper modules surface the modparam.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_tls_downgrade_policy test_tls_downgrade_policy.c
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
	/* CASE 1: nats_tls_opts struct exposes allow_downgrade */
	int hdr_field = grep_count(
		"../nats_pool.h", "int allow_downgrade;");
	ASSERT(hdr_field >= 1,
		"nats_pool.h declares 'int allow_downgrade'");

	/* CASE 2: pool_cfg holds the policy bit */
	int cfg_field = grep_count(
		"../nats_pool.c", "tls.allow_downgrade");
	ASSERT(cfg_field >= 1, "nats_pool.c references tls.allow_downgrade");

	/* CASE 3: pool_cfg refuses to downgrade by default — LM_ERR + abort */
	int err_path = grep_count(
		"../nats_pool.c",
		"refusing to downgrade tls:// to plaintext");
	ASSERT(err_path >= 1,
		"nats_pool.c has LM_ERR refusing silent downgrade");

	/* CASE 4: event_nats exposes tls_allow_downgrade modparam */
	int evt_param = grep_count(
		"../../../modules/event_nats/event_nats.c",
		"\"tls_allow_downgrade\"");
	ASSERT(evt_param >= 1,
		"event_nats exposes tls_allow_downgrade modparam");
	int evt_default = grep_count(
		"../../../modules/event_nats/event_nats.c",
		"int nats_tls_allow_downgrade = 0;");
	ASSERT(evt_default == 1,
		"event_nats default tls_allow_downgrade=0 (fail-safe)");

	/* CASE 5: cachedb_nats exposes tls_allow_downgrade modparam */
	int cdb_param = grep_count(
		"../../../modules/cachedb_nats/cachedb_nats.c",
		"\"tls_allow_downgrade\"");
	ASSERT(cdb_param >= 1,
		"cachedb_nats exposes tls_allow_downgrade modparam");
	int cdb_default = grep_count(
		"../../../modules/cachedb_nats/cachedb_nats.c",
		"int   tls_allow_downgrade = 0;");
	ASSERT(cdb_default == 1,
		"cachedb_nats default tls_allow_downgrade=0 (fail-safe)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
