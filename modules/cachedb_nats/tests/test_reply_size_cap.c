/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-3c regression test: w_nats_request() must enforce a maximum
 * reply size before pkg_malloc'ing the response buffer.
 *
 * The bug: reply_len = natsMsg_GetDataLength(reply) is peer-controlled
 * (any NATS client subscribed to the inbox can answer).  Allocating
 * pkg_malloc(reply_len + 1) without an upper bound lets a single
 * malicious / misbehaving responder exhaust per-worker pkg memory.
 *
 * The fix:
 *   1. cachedb_nats exposes a modparam `nats_request_max_reply`
 *      with a sensible default (65536 bytes).
 *   2. w_nats_request rejects when reply_len > nats_request_max_reply
 *      (or reply_len < 0), destroys the reply natsMsg, and returns -1.
 *
 * The test is structural (source presence) plus a unit check on the
 * boundary arithmetic.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_reply_size_cap test_reply_size_cap.c
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

/* mirror the production guard's arithmetic */
static int reply_size_ok(int reply_len, int max_reply)
{
	if (reply_len < 0) return 0;
	if (reply_len > max_reply) return 0;
	return 1;
}

int main(void)
{
	/* CASE 1: modparam declared with default 65536 */
	int default_decl = grep_count(
		"../cachedb_nats.c",
		"int   nats_request_max_reply = 65536;");
	ASSERT(default_decl == 1,
		"cachedb_nats.c default nats_request_max_reply=65536");

	int param_export = grep_count(
		"../cachedb_nats.c",
		"\"nats_request_max_reply\"");
	ASSERT(param_export == 1,
		"cachedb_nats.c exports nats_request_max_reply modparam");

	/* CASE 2: cap check is present in w_nats_request */
	int cap_check = grep_count(
		"../cachedb_nats_native.c",
		"reply_len > nats_request_max_reply");
	ASSERT(cap_check >= 1,
		"cachedb_nats_native.c enforces reply_len > max cap");

	int neg_check = grep_count(
		"../cachedb_nats_native.c",
		"reply_len < 0");
	ASSERT(neg_check >= 1,
		"cachedb_nats_native.c guards against negative reply_len");

	/* CASE 3: arithmetic boundary cases */
	ASSERT(reply_size_ok(0, 65536) == 1,         "0-byte reply allowed");
	ASSERT(reply_size_ok(65536, 65536) == 1,     "exactly-cap reply allowed");
	ASSERT(reply_size_ok(65537, 65536) == 0,     "over-cap reply rejected");
	ASSERT(reply_size_ok(-1, 65536) == 0,        "negative reply rejected");
	ASSERT(reply_size_ok(1<<30, 65536) == 0,     "huge reply rejected");
	ASSERT(reply_size_ok(1, 0) == 0,             "max=0 rejects everything > 0");
	ASSERT(reply_size_ok(0, 0) == 1,             "max=0 still allows empty");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
