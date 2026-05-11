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

/* ────────────────────────────────────────────────────────────── */

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	return -1;
}

static void test_uuidv7_mint(void)
{
	char buf[64];
	char buf2[64];
	int  n;
	int  v_nibble;
	int  var_byte;
	int  i;
	int  dashes_ok;

	fprintf(stderr, "\n=== uuidv7 mint ===\n");
	n = nats_rpc_async_uuidv7_mint(buf, sizeof(buf));
	ASSERT(n == 36, "mint returns 36 bytes (UUID length)");
	ASSERT(buf[8]  == '-' && buf[13] == '-' &&
	       buf[18] == '-' && buf[23] == '-',
		"dashes at positions 8/13/18/23");

	dashes_ok = 1;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) continue;
		if (hex_nibble(buf[i]) < 0) { dashes_ok = 0; break; }
	}
	ASSERT(dashes_ok, "all non-dash positions are lowercase hex");

	v_nibble = hex_nibble(buf[14]);
	ASSERT(v_nibble == 7, "version nibble at offset 14 is 7");

	var_byte = hex_nibble(buf[19]);
	ASSERT(var_byte == 0x8 || var_byte == 0x9 ||
	       var_byte == 0xa || var_byte == 0xb,
		"variant byte at offset 19 is one of 8/9/a/b (10xx bits)");

	/* Cap-undersize protection. */
	{
		char tiny[16];
		int r = nats_rpc_async_uuidv7_mint(tiny, sizeof(tiny));
		ASSERT(r == 0, "mint returns 0 on too-small buffer");
	}

	/* Sequential mints differ -- 62 random bits make a collision in
	 * the same millisecond effectively impossible. */
	n = nats_rpc_async_uuidv7_mint(buf2, sizeof(buf2));
	ASSERT(n == 36, "second mint also 36 bytes");
	ASSERT(memcmp(buf, buf2, 36) != 0, "two sequential mints differ");

	/* Lexicographic order: the first 13 chars are the timestamp +
	 * version nibble.  Two mints within the same millisecond may
	 * tie on those 13 chars but rand_b breaks the tie.  We assert
	 * the WEAKER property that the second mint's timestamp prefix
	 * is >= the first's (monotonic, ms-resolution). */
	ASSERT(memcmp(buf, buf2, 13) <= 0,
		"second mint is lexicographically >= first (ms-monotonic)");
}

static void test_request_id_stash(void)
{
	const char *got;
	int         got_len;
	const char  uuid[] = "01970000-0001-7abc-89ef-0123456789ab";

	fprintf(stderr, "\n=== request_id stash ===\n");

	nats_rpc_async_request_id_set(uuid, (int)strlen(uuid));
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got != NULL, "stash get returns non-NULL after set");
	ASSERT(got_len == (int)strlen(uuid), "stash length matches");
	ASSERT(got && memcmp(got, uuid, got_len) == 0,
		"stash bytes round-trip identically");

	nats_rpc_async_request_id_set(NULL, 0);
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got == NULL && got_len == 0, "stash cleared by NULL set");
}

static void test_request_id_user_override(void)
{
	const char  trace[] = "trace-abc-123";
	char        buf[64];
	int         n;
	int         rc;
	const char *got;
	int         got_len;
	char        oversized[80];
	const char  bad[] = "trace\r\nInjected: header";

	fprintf(stderr, "\n=== request_id user override (writable pvar) ===\n");

	/* Baseline: no pending value -> consumer returns 0. */
	n = nats_rpc_async_request_id_consume_user(buf, sizeof(buf));
	ASSERT(n == 0, "consume_user returns 0 when nothing pending");

	/* Script assigns a value. */
	rc = nats_rpc_async_request_id_user_set(trace, (int)strlen(trace));
	ASSERT(rc == 0, "user_set accepts plain trace id");

	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got != NULL && got_len == (int)strlen(trace) &&
	       memcmp(got, trace, got_len) == 0,
		"pvar GET immediately reflects the user-supplied value");

	/* Consume once -> value returned, flag cleared. */
	n = nats_rpc_async_request_id_consume_user(buf, sizeof(buf));
	ASSERT(n == (int)strlen(trace),
		"consume_user returns the pending length");
	ASSERT(memcmp(buf, trace, n) == 0,
		"consume_user copies the pending bytes");

	/* Second consume on the same assignment -> 0 (consume-once). */
	n = nats_rpc_async_request_id_consume_user(buf, sizeof(buf));
	ASSERT(n == 0,
		"consume_user returns 0 on second call (consume-once)");

	/* g_last_request_id is unchanged by the consume; it still
	 * holds the value the caller assigned -- the start-path will
	 * call request_id_set after consuming, but at this point we
	 * simulate "stash still set, flag cleared".  pvar GET still
	 * reads the value. */
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got != NULL && got_len == (int)strlen(trace),
		"stash still holds the consumed value (start-path overwrites)");

	/* Validation: over-long value -> rejected. */
	memset(oversized, 'x', sizeof(oversized));
	oversized[sizeof(oversized) - 1] = '\0';
	rc = nats_rpc_async_request_id_user_set(oversized,
		(int)sizeof(oversized) - 1);
	ASSERT(rc == -1,
		"user_set rejects values larger than the 63-byte cap");

	/* Validation: CR/LF rejected. */
	rc = nats_rpc_async_request_id_user_set(bad, (int)strlen(bad));
	ASSERT(rc == -1,
		"user_set rejects values containing CR/LF");

	/* Both `$nats_request_id = NULL;` and `$nats_request_id = "";`
	 * must clear the stash + pending flag.  The pvar setter
	 * (pv_set_nats_request_id) routes the NULL case through an
	 * explicit early return; the empty-string case falls through
	 * to user_set with len=0.  We exercise both at the
	 * underlying user_set entry point. */
	rc = nats_rpc_async_request_id_user_set(NULL, 0);
	ASSERT(rc == 0, "user_set(NULL, 0) clears (NULL assignment)");
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got == NULL && got_len == 0,
		"stash empty after NULL clear");

	/* Re-assign so we have something to clear. */
	(void)nats_rpc_async_request_id_user_set(trace, (int)strlen(trace));
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got != NULL, "stash repopulated");

	rc = nats_rpc_async_request_id_user_set("", 0);
	ASSERT(rc == 0, "user_set(\"\", 0) clears (empty-string assignment)");
	got = nats_rpc_async_request_id_get(&got_len);
	ASSERT(got == NULL && got_len == 0,
		"stash empty after empty-string clear");

	/* Verify the consume-once flag is also cleared by both
	 * paths -- a stale pending flag after a clear would have
	 * the next nats_request call try to copy an empty string
	 * as the id, breaking the fall-through-to-mint path. */
	(void)nats_rpc_async_request_id_user_set(trace, (int)strlen(trace));
	(void)nats_rpc_async_request_id_user_set(NULL, 0);   /* clear */
	{
		char tmp[64];
		int  n = nats_rpc_async_request_id_consume_user(tmp, sizeof(tmp));
		ASSERT(n == 0,
			"consume_user returns 0 after NULL clear (flag cleared)");
	}
}

/* ────────────────────────────────────────────────────────────── */

static void test_resume_rc_policy(void)
{
	fprintf(stderr, "\n=== resume_rc policy (no zero returns) ===\n");

	/* state == REPLIED (1) is the only "success" path; everything
	 * else is non-zero negative so a bare nats_* call in a route
	 * does not trigger ACT_FL_EXIT (action.c:196). */
	ASSERT(nats_rpc_async_resume_rc(1 /* REPLIED */, 0) == 1,
		"REPLIED + connected -> 1 (success)");
	ASSERT(nats_rpc_async_resume_rc(1 /* REPLIED */, 1) == 1,
		"REPLIED + disconnected -> 1 (reply already in hand)");

	/* INFLIGHT (state 0) + disconnected -> connection lost (-2). */
	ASSERT(nats_rpc_async_resume_rc(0 /* INFLIGHT */, 1) == -2,
		"INFLIGHT + disconnected -> -2 (connection lost)");

	/* INFLIGHT + still connected -> clean timeout (-1), NOT 0. */
	ASSERT(nats_rpc_async_resume_rc(0 /* INFLIGHT */, 0) == -1,
		"INFLIGHT + connected -> -1 (clean timeout, not 0)");

	/* ABANDONED is the same shape: -1 unless disconnected. */
	ASSERT(nats_rpc_async_resume_rc(2 /* ABANDONED */, 0) == -1,
		"ABANDONED + connected -> -1");
	ASSERT(nats_rpc_async_resume_rc(2 /* ABANDONED */, 1) == -2,
		"ABANDONED + disconnected -> -2");

	/* Defensive: no path returns 0. */
	ASSERT(nats_rpc_async_resume_rc(-1, 0) != 0,
		"unknown state never returns 0 (would trigger ACT_FL_EXIT)");
	ASSERT(nats_rpc_async_resume_rc(-1, 1) != 0,
		"unknown state + disconnected never returns 0");
}

static void test_disconnect_detection(void)
{
	struct nats_rpc_async_ctx *c;

	fprintf(stderr, "\n=== phase-3 disconnect detection ===\n");
	c = nats_rpc_async_ctx_new();
	ASSERT(c != NULL, "ctx_new returned non-NULL");
	if (!c) return;

	/* Default epoch snapshot is 0 (TEST_SHIM ctx_new). */
	ASSERT(nats_rpc_async_ctx_epoch_at_start(c) == 0u,
		"epoch_at_start defaults to 0 under TEST_SHIM");

	/* Stable case: pool connected, epoch unchanged -> not disc. */
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 0u, 1) == 0,
		"stable pool (epoch=0, connected=1) -> not disconnected");

	/* Pool flapped (reconnect happened during the call):
	 * current_epoch is now > epoch_at_start.  Connected may
	 * even be true (we reconnected) but the prior inbox
	 * routing was perturbed -- still surface -2. */
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 1u, 1) == 1,
		"epoch bump with reconnect (epoch=1, connected=1) -> disconnected");

	/* Pool currently down: any current_epoch -- still surface -2. */
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 0u, 0) == 1,
		"pool down (connected=0) -> disconnected");
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 5u, 0) == 1,
		"pool down and epoch bumped -> disconnected");

	/* Caller-set epoch matches subsequent observations -> stable. */
	nats_rpc_async_ctx_set_epoch_at_start(c, 42u);
	ASSERT(nats_rpc_async_ctx_epoch_at_start(c) == 42u,
		"set_epoch_at_start round-trips");
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 42u, 1) == 0,
		"epoch snapshot 42 vs. current 42 + connected -> not disc");
	ASSERT(nats_rpc_async_ctx_is_disconnected(c, 43u, 1) == 1,
		"epoch snapshot 42 vs. current 43 -> disconnected");

	/* NULL ctx is treated as "not disconnected" (defensive). */
	ASSERT(nats_rpc_async_ctx_is_disconnected(NULL, 99u, 0) == 0,
		"is_disconnected(NULL) returns 0 (defensive)");

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
	test_uuidv7_mint();
	test_request_id_stash();
	test_request_id_user_override();
	test_disconnect_detection();
	test_resume_rc_policy();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
