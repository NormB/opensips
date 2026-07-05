/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.6] Small hot-path policies, consumer side:
 *
 *   - the async fetch/batch RESUME PARAMS never leave the allocating
 *     worker (allocated in w_nats_fetch_async / w_nats_fetch_batch,
 *     freed by that worker's own resume), so they belong in pkg, not
 *     shm: no global shm-lock round-trip per async fetch, bounded by
 *     -M, leaks visible to pkg stats.  The rpc_async equivalent (the
 *     call wrap) has always been pkg,
 *
 *   - the request_id_header modparam is a config constant, yet the
 *     RPC start paths strlen()'d it once per request; its length is
 *     computed once at mod_init (nats_request_id_header_len).
 *
 * Structural test (source patterns).
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
	FILE *f = fopen(path, "r");
	char *buf;
	long n;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		fclose(f); free(buf); return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
}

static int count(const char *hay, const char *needle)
{
	int c = 0;
	const char *p = hay;
	while (hay && (p = strstr(p, needle)) != NULL) {
		c++;
		p += strlen(needle);
	}
	return c;
}

int main(void)
{
	char *fetch = slurp("../nats_fetch.c");
	char *rpc   = slurp("../nats_rpc.c");
	char *rpca  = slurp("../nats_rpc_async.c");
	char *mod   = slurp("../nats_consumer.c");

	ASSERT(fetch && rpc && rpca && mod, "production sources readable");
	if (!fetch || !rpc || !rpca || !mod)
		return 1;

	/* ── worker-local resume params are pkg, not shm ─────────── */
	ASSERT(count(fetch, "shm_malloc(") == 0,
		"nats_fetch.c allocates no shm (resume params are worker-local)");
	ASSERT(count(fetch, "shm_free(") == 0,
		"nats_fetch.c frees no shm");
	ASSERT(count(fetch, "pkg_malloc(") >= 2,
		"fetch + batch resume params allocated via pkg");

	/* ── request_id_header length cached at mod_init ─────────── */
	ASSERT(count(mod, "nats_request_id_header_len") >= 1,
		"nats_consumer.c computes nats_request_id_header_len");
	ASSERT(count(rpc, "strlen(nats_request_id_header)") == 0,
		"sync RPC start path no longer strlen()s the header name");
	ASSERT(count(rpca, "strlen(nats_request_id_header)") == 0,
		"async RPC start path no longer strlen()s the header name");

	free(fetch); free(rpc); free(rpca); free(mod);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
