/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_consumer_process must detect
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

/*
 * Extract the body (between the outermost braces) of a top-level
 * function `funcname` from `path`.  Returns a malloc'd NUL-terminated
 * string the caller must free, or NULL if not found.  Brace-counts so
 * nested blocks are included.
 */
static char *extract_func_body(const char *path, const char *funcname)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[n] = '\0';

	/* find the definition: "funcname(" followed (later) by '{' before
	 * any ';' (skips the forward declaration). */
	char *p = buf;
	char *body = NULL;
	size_t flen = strlen(funcname);
	while ((p = strstr(p, funcname)) != NULL) {
		char *q = p + flen;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '(') { p += flen; continue; }
		char *brace = q;
		while (*brace && *brace != '{' && *brace != ';') brace++;
		if (*brace != '{') { p += flen; continue; }  /* a decl/proto */
		/* brace-count from here */
		int depth = 0;
		char *s = brace;
		for (; *s; s++) {
			if (*s == '{') depth++;
			else if (*s == '}') { depth--; if (depth == 0) { s++; break; } }
		}
		size_t blen = (size_t)(s - brace);
		body = malloc(blen + 1);
		if (body) { memcpy(body, brace, blen); body[blen] = '\0'; }
		break;
	}
	free(buf);
	return body;
}

int main(void)
{
	const char *src = "../event_nats_sub.c";

	/* [P2.8] the epoch idiom moved behind lib/nats/nats_epoch.h; the
	 * loop tags its sub set and re-checks via the wrapper. */
	ASSERT(grep_count(src, "nats_epoch_save") >= 1 &&
	       grep_count(src, "nats_epoch_current") >= 1,
		"consumer loop tracks the reconnect epoch via nats_epoch");

	ASSERT(grep_count(src, "natsSubscription_IsValid") >= 1,
		"consumer loop checks subscription validity post-reconnect");

	/* The initial subscribe loop and the reconnect resubscribe loop both go
	 * through the shared subscribe_one() helper (P3-66 consolidation), so
	 * the raw Subscribe/QueueSubscribe calls live once inside the helper and
	 * subscribe_one() is invoked from both paths. */
	ASSERT(grep_count(src, "natsConnection_Subscribe") >= 1,
		"consumer subscribes via natsConnection_Subscribe (in subscribe_one)");
	ASSERT(grep_count(src, "natsConnection_QueueSubscribe") >= 1,
		"consumer queue-subscribes via natsConnection_QueueSubscribe "
		"(in subscribe_one)");
	ASSERT(grep_count(src, "subscribe_one(") >= 3,
		"subscribe_one() defined once and called from both the initial and "
		"resubscribe-on-reconnect paths");

	/* old loop slept 60 s; the fix should poll faster */
	ASSERT(grep_count(src, "sleep(60)") == 0,
		"consumer no longer uses sleep(60)");

	/* Regression (connect-fail must not exit the proc): nats_consumer_process
	 * is a proc_export entry.  Returning from it raises SIGCHLD in the
	 * attendant and shuts the whole instance down, so on a broker-down
	 * startup it must retry, never return.  Assert the function body
	 * contains no `return;` and retries pool_get in a loop. */
	{
		char *body = extract_func_body(src, "nats_consumer_process");
		ASSERT(body != NULL, "found nats_consumer_process body");
		if (body) {
			ASSERT(strstr(body, "return;") == NULL,
				"nats_consumer_process never returns (proc_export "
				"entry: a return SIGCHLDs the instance)");
			ASSERT(strstr(body, "while (!nc)") != NULL,
				"consumer retries nats_pool_get on connect failure "
				"instead of returning");
			free(body);
		}
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
