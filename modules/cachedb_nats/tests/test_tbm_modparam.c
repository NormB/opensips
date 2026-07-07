/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Wiring test: the kv_ttl_below_marker operator knob.
 *
 *   kv_ttl_below_marker (int, default 0)
 *     When 1, bucket creation requests the fork nats-server's
 *     allow_msg_ttl_below_marker stream option so per-key TTLs shorter
 *     than LimitMarkerTTL are honored on History>1 buckets (the
 *     TTL-HISTORY rollback root cause).  Stock servers reject the
 *     unknown field at create; the pool probes that rejection (retry
 *     without the flag) and latches UNSUPPORTED with a loud WARN --
 *     expiry then remains reaper-only, exactly as without the knob.
 *
 * Structural: modparam registered with default-0 storage, init passes
 * the request to the pool before the first bucket use, the probe
 * outcome is surfaced at startup, and the docbook README documents the
 * parameter.
 *
 * Build: gcc -g -O0 -Wall -o test_tbm_modparam test_tbm_modparam.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
	buf[n] = '\0';
	fclose(f);
	return buf;
}

int main(void)
{
	char *src = slurp("../cachedb_nats.c");
	ASSERT(src != NULL, "can read ../cachedb_nats.c");
	if (src) {
		ASSERT(strstr(src, "int kv_ttl_below_marker = 0;") != NULL,
			"knob storage exists with default 0");
		ASSERT(strstr(src, "{\"kv_ttl_below_marker\", INT_PARAM,") != NULL,
			"modparam registered as INT_PARAM");
		ASSERT(strstr(src, "nats_pool_kv_request_ttl_below_marker") != NULL,
			"init passes the request to the pool");
		ASSERT(strstr(src, "nats_pool_kv_ttl_below_marker_state") != NULL,
			"probe outcome surfaced from the pool state");
		free(src);
	}

	{
		char *doc = slurp("../doc/cachedb_nats_admin.xml");
		if (!doc)
			doc = slurp("../doc/cachedb_nats.xml");
		ASSERT(doc != NULL, "can read the docbook admin doc");
		if (doc) {
			ASSERT(strstr(doc, "kv_ttl_below_marker") != NULL,
				"docbook documents kv_ttl_below_marker");
			free(doc);
		}
	}

	fprintf(stderr, "%s (%d failure(s))\n", g_fails ? "RED" : "GREEN", g_fails);
	return g_fails ? 1 : 0;
}
