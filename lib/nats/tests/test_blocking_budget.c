/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.2] The SIP-worker blocking budget, lib side:
 *
 *   - nats_pool_kv_op_timeout_ms ships a NON-ZERO default (the usrloc
 *     update path is two synchronous KV round-trips per REGISTER; the
 *     cnats library default of 5 s meant ~10 s worst case per attempt),
 *   - the startup connect loop fails FAST on non-transient statuses
 *     (TLS material / credentials / malformed options) instead of
 *     burning max_reconnect x sleep in every process's child_init;
 *     reachability problems still take the degraded-start path.
 *
 * Source-pattern (the connect loop needs a live broker + broken TLS to
 * drive behaviorally; the TLS smoke covers that end to end).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long n;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (buf) { fread(buf, 1, n, f); buf[n] = '\0'; }
	fclose(f);
	return buf;
}

int main(void)
{
	char *pool = slurp("../nats_pool.c");

	ASSERT(pool != NULL, "read ../nats_pool.c");
	if (!pool) return 1;

	ASSERT(strstr(pool, "int nats_pool_kv_op_timeout_ms = 1000;") != NULL,
		"kv op timeout ships a non-zero default (1000 ms)");
	ASSERT(strstr(pool, "s == NATS_SSL_ERROR") != NULL &&
	       strstr(pool, "s == NATS_CONNECTION_AUTH_FAILED") != NULL &&
	       strstr(pool, "s == NATS_INVALID_ARG") != NULL,
		"connect loop classifies the non-transient statuses");
	ASSERT(strstr(pool, "not retrying") != NULL,
		"non-transient connect failure fails the boot (no retry burn)");

	free(pool);
	printf("\n=== %s (fails=%d) ===\n",
		g_fails ? "FAILURES" : "ALL PASS", g_fails);
	return g_fails ? 1 : 0;
}
