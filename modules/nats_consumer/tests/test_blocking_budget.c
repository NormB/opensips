/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.2] The SIP-worker blocking budget, consumer side:
 *
 *   - the sync-fetch wait loop actually RE-CHECKS the connection it
 *     sliced its waits for (a worker no longer sits out the full
 *     timeout against a dead broker),
 *   - the DELIVERING resume path has a terminal bound: past
 *     deadline + NATS_RPC_DELIVERING_GRACE_US the worker stops
 *     polling and surfaces -2 -- WITHOUT freeing the slot under the
 *     consumer's pin (the [P2.2] orphan reaper reclaims it).
 *
 * Source-pattern (both paths need a dying broker / dying delivery
 * thread to drive behaviorally; the outage e2e covers the fetch case).
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

/* body of the named function (brace-matched) */
static char *fn_body(const char *src, const char *name)
{
	const char *p = strstr(src, name);
	const char *b, *q;
	int depth = 0;
	char *out;
	if (!p) return NULL;
	b = strchr(p, '{');
	if (!b) return NULL;
	for (q = b; *q; q++) {
		if (*q == '{') depth++;
		else if (*q == '}' && --depth == 0) break;
	}
	out = malloc(q - b + 2);
	memcpy(out, b, q - b + 1);
	out[q - b + 1] = '\0';
	return out;
}

int main(void)
{
	char *fetch = slurp("../nats_fetch.c");
	char *async = slurp("../nats_rpc_async.c");

	ASSERT(fetch && async, "read production TUs");
	if (!fetch || !async) return 1;

	ASSERT(strstr(fetch, "if (!nats_pool_is_connected())") != NULL &&
	       strstr(fetch, "broker down mid-wait") != NULL,
		"sync-fetch wait loop bails when the broker is down");

	{
		char *resume = fn_body(async, "static int resume_nats_request_slot");
		ASSERT(resume != NULL, "resume body found");
		if (resume) {
			ASSERT(strstr(resume, "NATS_RPC_DELIVERING_GRACE_US") != NULL,
				"DELIVERING poll has a terminal bound");
			/* the give-up path must NOT free the slot under the pin */
			{
				char *g = strstr(resume, "NATS_RPC_DELIVERING_GRACE_US");
				char *ret = g ? strstr(g, "return -2;") : NULL;
				ASSERT(ret != NULL, "bounded DELIVERING wait surfaces -2");
				if (g && ret) {
					char save = *ret; *ret = '\0';
					ASSERT(strstr(g, "nats_rpc_slot_free") == NULL,
						"slot NOT freed under the consumer's pin "
						"(orphan reaper owns it)");
					*ret = save;
				}
			}
			free(resume);
		}
	}

	free(fetch); free(async);
	printf("\n=== %s (fails=%d) ===\n",
		g_fails ? "FAILURES" : "ALL PASS", g_fails);
	return g_fails ? 1 : 0;
}
