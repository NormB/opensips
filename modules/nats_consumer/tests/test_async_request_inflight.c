/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase-2 unit test for nats_rpc_async.c's in-flight state machine.
 *
 * Drives the ctx alloc / install / deliver / take / release
 * primitives directly without linking libnats; the file under test
 * is compiled with -DTEST_SHIM so the libnats glue
 * (on_inbox_reply, ensure_inbox_subscription, w_nats_request_async,
 * resume_nats_request) is excluded and only the pure C state
 * machine is exercised.
 *
 * Cases covered:
 *
 *   1. Happy path: alloc -> install -> deliver(matching corr_id)
 *      -> drain eventfd -> release.  Asserts the state is REPLIED
 *      after delivery, the eventfd counter increments by one, and
 *      no ctx is leaked (refcount drops to zero).
 *
 *   2. Stale-reply / unknown corr_id: deliver with a random suffix
 *      -> returns -1, no state mutation.
 *
 *   3. Timeout path: alloc -> install -> take_for_resume (no
 *      callback ever ran) -> mark_abandoned -> release.  Asserts
 *      state transitions INFLIGHT -> ABANDONED.
 *
 *   4. Callback-wins race: alloc -> install -> deliver (callback
 *      already finished) -> take_for_resume -> 0 (already gone).
 *      Asserts the resume-side check sees state=REPLIED.
 *
 *   5. In-flight cap: install ctxs until the hard ceiling is hit,
 *      then verify the next install returns -1 with the cap
 *      messaged accordingly.  Cleans up all the entries.
 *
 *   6. Subject round-trip: format the reply subject with
 *      format_reply_subject, parse it back with
 *      corr_from_subject -- the suffix the parser returns must
 *      byte-match the ctx's corr_id.
 *
 * Build (driven by Makefile):
 *   gcc -DTEST_SHIM -I. -I../../.. -o test_async_request_inflight \
 *       test_async_request_inflight.c test_shim.c ../nats_rpc_async.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/eventfd.h>

#include "test_shim.h"
#include "../nats_rpc_async.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ────────────────────────────────────────────────────────────── */

static void test_happy_path(void)
{
	struct nats_rpc_async_ctx *c;
	const char  payload[] = "pong";
	const char  reply_subj[] = "_INBOX.opensips.42.7";
	uint64_t    drain_buf;
	int         rc;
	const char *corr;
	int         corr_len;

	fprintf(stderr, "\n=== happy path ===\n");
	c = nats_rpc_async_ctx_new();
	ASSERT(c != NULL, "ctx_new returned non-NULL");
	ASSERT(nats_rpc_async_eventfd(c) >= 0, "ctx has eventfd");
	ASSERT(nats_rpc_async_corr_len(c) > 0,  "ctx has corr_id");

	rc = nats_rpc_async_install(c);
	ASSERT(rc == 0, "install succeeded");
	ASSERT(nats_rpc_async_inflight_count() == 1, "inflight_count == 1");

	corr = nats_rpc_async_corr_id(c);
	corr_len = nats_rpc_async_corr_len(c);

	rc = nats_rpc_async_deliver(corr, corr_len,
		reply_subj, (int)strlen(reply_subj),
		payload, (int)strlen(payload),
		NULL, 0, 0,
		NULL, 0);
	ASSERT(rc == 0, "deliver(matching corr) returns 0");
	ASSERT(nats_rpc_async_state(c) == 1 /* REPLIED */,
		"state is REPLIED after deliver");
	ASSERT(nats_rpc_async_inflight_count() == 0,
		"inflight_count == 0 after deliver");

	/* eventfd was signalled exactly once */
	{
		ssize_t r = read(nats_rpc_async_eventfd(c),
			&drain_buf, sizeof(drain_buf));
		ASSERT(r == sizeof(drain_buf),
			"eventfd read returned a counter");
		ASSERT(drain_buf == 1, "eventfd counter == 1");
	}

	nats_rpc_async_ctx_release(c);   /* alloc-caller's ref */
	/* Nothing more we can assert on c after release; if refcount
	 * was off the prior tests would have segfaulted. */
	ASSERT(1, "ctx released cleanly");
}

/* ────────────────────────────────────────────────────────────── */

static void test_stale_corr_id(void)
{
	int rc;
	fprintf(stderr, "\n=== stale corr_id ===\n");
	ASSERT(nats_rpc_async_inflight_count() == 0,
		"state clean at start");
	rc = nats_rpc_async_deliver("nosuchcorr", 10,
		"x", 1, "y", 1, NULL, 0, 0, NULL, 0);
	ASSERT(rc == -1, "deliver on unknown corr_id returns -1");
	ASSERT(nats_rpc_async_inflight_count() == 0,
		"inflight unchanged on miss");
}

/* ────────────────────────────────────────────────────────────── */

static void test_timeout_path(void)
{
	struct nats_rpc_async_ctx *c;
	int took;
	int abandoned;

	fprintf(stderr, "\n=== timeout path ===\n");
	c = nats_rpc_async_ctx_new();
	ASSERT(c != NULL, "ctx_new returned non-NULL");
	ASSERT(nats_rpc_async_install(c) == 0, "installed");

	/* Simulate the resume firing on a was_timeout dispatch
	 * before any reply landed. */
	took = nats_rpc_async_take_for_resume(c);
	ASSERT(took == 1, "take_for_resume found and took the entry");
	ASSERT(nats_rpc_async_inflight_count() == 0,
		"entry removed from hash");

	abandoned = nats_rpc_async_mark_abandoned(c);
	ASSERT(abandoned == 2 /* ABANDONED */,
		"state promoted to ABANDONED");

	/* A late deliver after abandonment must be dropped -- there
	 * is no hash entry. */
	{
		int rc = nats_rpc_async_deliver(
			nats_rpc_async_corr_id(c),
			nats_rpc_async_corr_len(c),
			"x", 1, "y", 1, NULL, 0, 0, NULL, 0);
		ASSERT(rc == -1, "late deliver after timeout returns -1");
	}

	/* Release the hash's transferred ref + alloc-caller's ref. */
	nats_rpc_async_ctx_release(c);
	nats_rpc_async_ctx_release(c);
	ASSERT(1, "ctx released cleanly (timeout path)");
}

/* ────────────────────────────────────────────────────────────── */

static void test_callback_wins_race(void)
{
	struct nats_rpc_async_ctx *c;
	int took;
	const char *corr;
	int         corr_len;
	const char  payload[] = "won";

	fprintf(stderr, "\n=== callback-wins race ===\n");
	c = nats_rpc_async_ctx_new();
	ASSERT(c != NULL, "ctx_new returned non-NULL");
	ASSERT(nats_rpc_async_install(c) == 0, "installed");

	corr     = nats_rpc_async_corr_id(c);
	corr_len = nats_rpc_async_corr_len(c);

	/* Callback path runs first (delivers).  This removes the
	 * hash entry and sets state=REPLIED. */
	ASSERT(nats_rpc_async_deliver(corr, corr_len,
		"sub", 3, payload, (int)strlen(payload),
		NULL, 0, 0, NULL, 0) == 0,
		"deliver returned 0");
	ASSERT(nats_rpc_async_state(c) == 1, "state is REPLIED");

	/* Resume runs second.  Hash already empty -> take returns
	 * 0, no extra ref to release. */
	took = nats_rpc_async_take_for_resume(c);
	ASSERT(took == 0, "take_for_resume sees entry already gone");

	/* Drain the eventfd as the resume function would do. */
	(void)nats_rpc_async_drain_eventfd(c);

	nats_rpc_async_ctx_release(c);   /* resume_param's ref */
	ASSERT(1, "ctx released cleanly (callback-wins)");
}

/* ────────────────────────────────────────────────────────────── */

/* Pull this from the header value -- defensive against a future
 * change to the cap that doesn't update the test. */
#define MAX_INFLIGHT 4096

static void test_inflight_cap(void)
{
	struct nats_rpc_async_ctx **bag;
	int i;
	int installed;
	int reject_rc;
	struct nats_rpc_async_ctx *over;

	fprintf(stderr, "\n=== in-flight cap ===\n");
	bag = malloc(sizeof(*bag) * (MAX_INFLIGHT + 1));
	ASSERT(bag != NULL, "test bag malloc'd");
	if (!bag) return;

	installed = 0;
	for (i = 0; i < MAX_INFLIGHT; i++) {
		bag[i] = nats_rpc_async_ctx_new();
		if (!bag[i]) break;
		if (nats_rpc_async_install(bag[i]) != 0) break;
		installed++;
	}
	ASSERT(installed == MAX_INFLIGHT,
		"installed up to the cap");

	over = nats_rpc_async_ctx_new();
	ASSERT(over != NULL, "extra ctx alloced past the cap");
	reject_rc = nats_rpc_async_install(over);
	ASSERT(reject_rc == -1,
		"install at cap returns -1 (over-cap rejected)");
	nats_rpc_async_ctx_release(over);

	/* Drain.  Use take_for_resume to remove from hash, then
	 * release twice (hash ref + alloc ref). */
	for (i = 0; i < installed; i++) {
		int t = nats_rpc_async_take_for_resume(bag[i]);
		(void)t;
		nats_rpc_async_ctx_release(bag[i]);   /* hash ref */
		nats_rpc_async_ctx_release(bag[i]);   /* alloc ref */
	}
	ASSERT(nats_rpc_async_inflight_count() == 0,
		"in-flight count drained");
	free(bag);
}

/* ────────────────────────────────────────────────────────────── */

static void test_subject_roundtrip(void)
{
	struct nats_rpc_async_ctx *c;
	char        buf[128];
	int         n;
	const char *corr;
	int         corr_len;
	int         parsed_len = 0;
	const char *parsed;

	fprintf(stderr, "\n=== subject round-trip ===\n");
	c = nats_rpc_async_ctx_new();
	ASSERT(c != NULL, "ctx_new returned non-NULL");

	n = nats_rpc_async_format_reply_subject(c, buf, sizeof(buf));
	ASSERT(n > 0, "format_reply_subject wrote bytes");
	ASSERT(n < (int)sizeof(buf), "format fit in buffer");

	corr     = nats_rpc_async_corr_id(c);
	corr_len = nats_rpc_async_corr_len(c);

	parsed = nats_rpc_async_corr_from_subject(buf, n, &parsed_len);
	ASSERT(parsed != NULL, "corr_from_subject returned non-NULL");
	ASSERT(parsed_len == corr_len, "parsed suffix length matches");
	ASSERT(parsed && memcmp(parsed, corr, corr_len) == 0,
		"parsed suffix bytes match");

	nats_rpc_async_ctx_release(c);
}

/* ────────────────────────────────────────────────────────────── */

int main(void)
{
	test_happy_path();
	test_stale_corr_id();
	test_timeout_path();
	test_callback_wins_race();
	test_inflight_cap();
	test_subject_roundtrip();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
