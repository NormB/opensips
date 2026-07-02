/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TTL-HISTORY-FIX-SPEC.md D6 [HREV-6]: mod_init validation of the new
 * operator parameters.  A bad value must refuse startup (fail loudly at boot,
 * never misbehave silently at runtime):
 *
 *   _linger_guard(linger)        0 ok / -1 refuse.  Range 0..86400: negative
 *                                is meaningless; > 1 day is almost certainly
 *                                a typo'd epoch pasted into the config.
 *   _marker_ttl_guard(secs)      0 ok / -1 refuse.  Minimum 1 (the server's
 *                                floor for marker TTLs); 0/negative would ask
 *                                for markers that never/instantly vanish.
 *   _reap_interval_guard(interval, unsafe_ttl_only, native_ttl)
 *                                EXTENDED [D6]: with the reaper off
 *                                (interval<=0), nats_unsafe_ttl_only=1 only
 *                                suffices while the native-TTL path is still
 *                                on.  nats_native_ttl=0 AND reaper off leaves
 *                                NO expiry mechanism at all -> always refused.
 *
 *   gcc -DGUARDS_CURRENT ... -> pre-HREV-6: no linger/marker guards (any value
 *                               accepted) and the 2-arg reap guard (the
 *                               no-mechanism combo boots) => RED.
 *   gcc ...                  -> the guards => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_modparam_guards test_modparam_guards.c
 */
#include <stdio.h>

/* ─── carried copies of the production helpers (cachedb_nats_ttl.c /
 *     cachedb_nats_reaper.c) ─────────────────────────────────────── */

static int _linger_guard(int linger)
{
#ifdef GUARDS_CURRENT
	(void)linger; return 0;                    /* no guard */
#else
	return (linger >= 0 && linger <= 86400) ? 0 : -1;
#endif
}

static int _marker_ttl_guard(int marker_ttl)
{
#ifdef GUARDS_CURRENT
	(void)marker_ttl; return 0;                /* no guard */
#else
	return (marker_ttl >= 1) ? 0 : -1;
#endif
}

static int _reap_interval_guard(int interval, int unsafe_ttl_only,
	int native_ttl)
{
#ifdef GUARDS_CURRENT
	(void)native_ttl;                          /* pre-D6 2-arg semantics */
	if (interval > 0)
		return 0;
	return unsafe_ttl_only ? 0 : -1;
#else
	if (interval > 0)
		return 0;
	/* reaper off: with native TTL also off there is NO expiry mechanism
	 * left -- refused unconditionally, the ack flag cannot bless it. */
	if (!native_ttl)
		return -1;
	return unsafe_ttl_only ? 0 : -1;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef GUARDS_CURRENT
	printf("== carried copy: GUARDS_CURRENT (pre-HREV-6) ==\n");
#else
	printf("== carried copy: FIXED guards ==\n");
#endif

	printf("[D6] nats_expired_linger range 0..86400:\n");
	CHECK(_linger_guard(0) == 0, "0 (default, reclaim ASAP) => ok");
	CHECK(_linger_guard(30) == 0, "30 => ok");
	CHECK(_linger_guard(86400) == 0, "86400 (1 day, the ceiling) => ok");
	CHECK(_linger_guard(-1) == -1, "-1 => refused");
	CHECK(_linger_guard(86401) == -1, "86401 => refused (typo'd epoch)");
	CHECK(_linger_guard(-2147483647) == -1, "INT_MIN-ish => refused");

	printf("[D6] kv_marker_ttl minimum 1 s:\n");
	CHECK(_marker_ttl_guard(30) == 0, "30 (default) => ok");
	CHECK(_marker_ttl_guard(1) == 0, "1 (the server floor) => ok");
	CHECK(_marker_ttl_guard(0) == -1, "0 => refused");
	CHECK(_marker_ttl_guard(-5) == -1, "negative => refused");

	printf("[D6] extended reap guard: no-mechanism combo always refused:\n");
	CHECK(_reap_interval_guard(30, 0, 1) == 0, "reaper on, ttl on => ok");
	CHECK(_reap_interval_guard(30, 0, 0) == 0, "reaper on, ttl OFF => ok (reaper covers)");
	CHECK(_reap_interval_guard(0, 1, 1) == 0, "reaper off + ack, ttl on => ok (pre-D6 contract kept)");
	CHECK(_reap_interval_guard(0, 0, 1) == -1, "reaper off, no ack => refused (pre-D6 contract kept)");
	CHECK(_reap_interval_guard(0, 1, 0) == -1,
	      "reaper off + ack BUT native ttl off => refused (no mechanism left)");
	CHECK(_reap_interval_guard(0, 0, 0) == -1, "everything off, no ack => refused");
	CHECK(_reap_interval_guard(-1, 1, 0) == -1, "negative interval + ttl off => refused");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
