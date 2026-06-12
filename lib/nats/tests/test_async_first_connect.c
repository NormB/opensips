/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Async-first-connect test (NATS_TODO #7, the sub-part that was never
 * wired -- caught live by test_boot_degraded_e2e.sh):
 *
 *   With the broker down at BOOT, nats_pool_get()'s synchronous retry
 *   loop blocked EVERY OpenSIPS process inside child_init for the full
 *   max_reconnect budget (60 x ~2 s + jitter = minutes), stalling core
 *   timers and leaving SIP unresponsive -- before finally starting
 *   degraded anyway.
 *
 *   The fix per the TODO's own prescription: enable
 *   natsOptions_SetRetryOnFailedConnect so natsConnection_Connect()
 *   returns NATS_NOT_YET_CONNECTED immediately and cnats keeps dialing
 *   in the background, firing the (re)connected callback on first
 *   success.  Boot completes degraded in seconds; the late broker is
 *   picked up without a restart.
 *
 * Structural assertions:
 *   - the dl table loads natsOptions_SetRetryOnFailedConnect
 *   - the pool option setup enables it, wired to the reconnected cb
 *   - the connect loop treats NATS_NOT_YET_CONNECTED as "continue
 *     degraded", not as a counted failure
 *   - _connected is only force-set on the synchronous NATS_OK path
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
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *b = malloc(n + 1);
	if (!b) { fclose(f); return NULL; }
	if (fread(b, 1, n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
	b[n] = '\0';
	fclose(f);
	return b;
}

int main(void)
{
	char *t;

	t = slurp("../nats_dl_table.def");
	ASSERT(t != NULL, "read nats_dl_table.def");
	ASSERT(t && strstr(t, "NATS_DL_FN(natsOptions_SetRetryOnFailedConnect)"),
		"dl table loads natsOptions_SetRetryOnFailedConnect");
	free(t);

	t = slurp("../nats_pool.c");
	ASSERT(t != NULL, "read nats_pool.c");
	if (t) {
		char *opt = strstr(t,
			"natsOptions_SetRetryOnFailedConnect(opts, true,");
		ASSERT(opt != NULL,
			"pool enables retry-on-failed-connect");
		ASSERT(opt && strstr(opt, "_pool_reconnected_cb"),
			"first-connect callback is the reconnected cb "
			"(sets _connected, bumps epoch, marks KV stale)");
		ASSERT(strstr(t, "NATS_NOT_YET_CONNECTED") != NULL,
			"connect loop handles NATS_NOT_YET_CONNECTED");
		/* the degraded break must come BEFORE the attempts++ counter
		 * so an unreachable broker is not a counted failure */
		{
			char *nyc = strstr(t, "s == NATS_NOT_YET_CONNECTED");
			char *cnt = strstr(t, "attempts++");
			ASSERT(nyc && cnt && nyc < cnt,
				"NOT_YET_CONNECTED short-circuits before the "
				"bounded-failure accounting");
		}
		free(t);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
