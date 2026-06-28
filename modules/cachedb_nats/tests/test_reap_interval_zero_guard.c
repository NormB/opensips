/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P9 / ADVERSARIAL-ANALYSIS.md F2 [PREV-26 / REV-2]: nats_reap_interval == 0
 * (reaper-off, TTL-only) is NOT a supported configuration.
 *
 * The reaper is the authoritative expiry mechanism; native per-message TTL is an
 * opportunistic optimization that the server is NOT guaranteed to honor across
 * updates (#6959/#1994 — proven LIVE on 2.11.10 in the P8 e2e).  So a config
 * that turns the reaper off must be REFUSED at startup, unless the operator
 * explicitly acknowledges the risk with nats_unsafe_ttl_only=1 (which logs an
 * LM_WARN quoting #6959/#1994).  Default is reaper-authoritative.
 *
 *   _reap_interval_guard(interval, unsafe_ttl_only): 0 = ok to start, -1 = refuse.
 *
 *   gcc -DRIVAL_CURRENT ... -> no guard (interval 0 silently accepted) => RED.
 *   gcc ...                -> the FIXED guard => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_interval_zero_guard test_reap_interval_zero_guard.c
 */
#include <stdio.h>

/* ─── carried copy of the production helper (cachedb_nats_reaper.c) ─── */
static int _reap_interval_guard(int interval, int unsafe_ttl_only)
{
#ifdef RIVAL_CURRENT
	(void)interval; (void)unsafe_ttl_only; return 0;   /* no guard */
#else
	if (interval > 0)
		return 0;                       /* a real reaper interval: ok */
	/* interval <= 0 means reaper-off: refuse unless explicitly acked. */
	return unsafe_ttl_only ? 0 : -1;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef RIVAL_CURRENT
	printf("== carried copy: RIVAL_CURRENT (no guard) ==\n");
#else
	printf("== carried copy: FIXED interval guard ==\n");
#endif

	printf("[REV-2/PREV-26] a real reaper interval starts:\n");
	CHECK(_reap_interval_guard(30, 0) == 0, "interval 30 => ok");
	CHECK(_reap_interval_guard(1, 0) == 0, "interval 1 => ok");

	printf("[REV-2/PREV-26] reaper-off (interval<=0) is REFUSED by default:\n");
	CHECK(_reap_interval_guard(0, 0) == -1, "interval 0, no ack => REFUSED");
	CHECK(_reap_interval_guard(-1, 0) == -1, "negative interval, no ack => refused");

	printf("[REV-2] reaper-off allowed ONLY with the explicit unsafe ack:\n");
	CHECK(_reap_interval_guard(0, 1) == 0, "interval 0 + nats_unsafe_ttl_only=1 => allowed (with WARN)");
	CHECK(_reap_interval_guard(30, 1) == 0, "a real interval is unaffected by the ack");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
