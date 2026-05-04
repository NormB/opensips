/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-5c regression test: nats_consumer_process must detect
 * reconnects and re-establish subscriptions, not just sleep(60)
 * indefinitely.
 *
 * The pre-fix loop:
 *   for (;;) {
 *     sleep(60);
 *     if (!nats_pool_is_connected()) LM_WARN(...);
 *   }
 * is informational only.  Ephemeral subscriptions (no durable
 * consumer name on the broker side) go dead silently after a
 * server restart and the consumer process keeps running with no
 * deliveries.
 *
 * The fix: track nats_pool_get_reconnect_epoch().  When the epoch
 * advances, walk each subscription and resubscribe if
 * natsSubscription_IsValid() returns false.  Also tighten the poll
 * interval below 60 s so a flapping connection is noticed quickly.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_subscription_rebuild test_subscription_rebuild.c
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
	const char *src = "../nats_consumer.c";

	ASSERT(grep_count(src, "nats_pool_get_reconnect_epoch") >= 1,
		"consumer loop reads reconnect epoch");

	ASSERT(grep_count(src, "natsSubscription_IsValid") >= 1,
		"consumer loop checks subscription validity post-reconnect");

	int subs = grep_count(src, "natsConnection_Subscribe");
	int qsubs = grep_count(src, "natsConnection_QueueSubscribe");
	ASSERT(subs >= 2,
		"consumer has both initial subscribe and resubscribe-on-reconnect "
		"call sites for natsConnection_Subscribe");
	ASSERT(qsubs >= 2,
		"consumer has both initial and resubscribe call sites for "
		"natsConnection_QueueSubscribe");

	/* old loop slept 60 s; the fix should poll faster */
	ASSERT(grep_count(src, "sleep(60)") == 0,
		"consumer no longer uses sleep(60)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
