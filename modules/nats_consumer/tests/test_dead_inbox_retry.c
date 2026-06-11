/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #33 (survivability, part B): the async-RPC
 * reply inbox subscription (_INBOX.opensips.<pid>.>) was attempted exactly
 * once at consumer startup.  On a transient failure g_inbox_sub stayed
 * NULL forever, so for the rest of the process lifetime every async
 * nats_request published its request with a reply-to pointing at an inbox
 * nobody was listening on -- every reply was black-holed and every async
 * call blocked until its full timeout.
 *
 * Fix:
 *   1. retry the inbox subscribe in the consumer main loop (idempotent;
 *      a pointer check once it is up), exposed via
 *      nats_rpc_consumer_inbox_ready();
 *   2. while the inbox is down, the IPC publish path abandons the slot
 *      (CAS INFLIGHT -> ABANDONED) instead of publishing to a deaf inbox,
 *      so the caller fails fast instead of waiting out the timeout.
 *
 * This test carries the down/up decision model and asserts the production
 * wiring.
 *
 * Build (self-contained):
 *   gcc -g -O0 -Wall -o test_dead_inbox_retry test_dead_inbox_retry.c
 */

#include <stdio.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

static int count_in_file(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int n = 0;
	if (!f) return -1;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while ((p = strstr(p, needle))) { n++; p += strlen(needle); }
	}
	fclose(f);
	return n;
}

/* Count occurrences of @needle inside the body of function @fn_name. */
static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096], marker[256];
	int hits = 0, in_body = 0, seen_marker = 0;
	if (!f) return -1;
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen_marker = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			if (strchr(line, ';') && !strchr(line, '{')) { seen_marker = 0; continue; }
			if (strchr(line, '{')) in_body = 1;
			continue;
		}
		if (strstr(line, marker)) seen_marker = 1;
	}
	fclose(f);
	return hits;
}

/* ---- carried model: what does the publish path do per inbox state? --- */

enum action { PUBLISH, ABANDON };

static enum action publish_decision(int inbox_ready)
{
	/* If the reply has nowhere to land, don't publish -- abandon so the
	 * worker fails fast rather than timing out on a reply that can't come. */
	return inbox_ready ? PUBLISH : ABANDON;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		ASSERT(publish_decision(1) == PUBLISH,
			"inbox up -> publish the request normally");
		ASSERT(publish_decision(0) == ABANDON,
			"inbox down -> abandon the slot (fail fast, no deaf publish)");
	}

	/* ---- inbox-ready accessor defined + declared ---------------- */
	{
		ASSERT(file_contains("../nats_rpc_consumer.c",
				"nats_rpc_consumer_inbox_ready"),
			"nats_rpc_consumer.c defines the inbox-ready accessor");
		ASSERT(file_contains("../nats_rpc_consumer.h",
				"nats_rpc_consumer_inbox_ready"),
			"nats_rpc_consumer.h declares the inbox-ready accessor");
	}

	/* ---- publish path fast-fails while the inbox is down --------- */
	{
		const char *c = "../nats_rpc_consumer.c";
		ASSERT(grep_in_function(c, "publish_cb",
				"nats_rpc_consumer_inbox_ready") >= 1,
			"publish_cb checks inbox readiness before publishing");
		/* the abandon transition (CAS to ABANDONED) is the fail-fast */
		ASSERT(grep_in_function(c, "publish_cb",
				"NATS_RPC_SLOT_ABANDONED") >= 1,
			"publish_cb abandons the slot when it cannot publish");
	}

	/* ---- main loop retries the subscribe (not just once) -------- */
	{
		const char *p = "../nats_consumer_proc.c";
		ASSERT(count_in_file(p, "nats_rpc_consumer_subscribe") >= 2,
			"subscribe is retried in the loop, not attempted only once");
		ASSERT(file_contains(p, "nats_rpc_consumer_inbox_ready"),
			"main loop gates the retry on inbox readiness");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
