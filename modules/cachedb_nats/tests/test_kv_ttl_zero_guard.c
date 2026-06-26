/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P7 / SPEC.md §5.3 [REV-7] + TTL-SOLUTION-SPEC.md §6 [TREV-8]: the kv_ttl==0
 * startup guard and the per-message-TTL capability latch.
 *
 * [REV-7] kv_ttl (bucket MaxAge) MUST be 0.  A non-zero bucket TTL becomes
 * stream MaxAge, which takes precedence over per-message TTL and would (a) cap
 * our per-key TTL and (b) SILENTLY EXPIRE PERMANENT CONTACTS (expires==0),
 * violating "a permanent contact is never reaped".  cachedb_nats refuses to
 * start (or LM_WARNs loudly) when usrloc owns the bucket and kv_ttl != 0.
 *
 * [TREV-8] Capability is operational, "by attempt": SUPPORTED once the
 * js_UpdateStream that sets AllowMsgTTL succeeds and no JSMessageTTLDisabledErr
 * (10166) has been seen on a runtime publish; a 10166 latches UNSUPPORTED for
 * the connection (plain CAS + reaper, no per-write error spam); a reconnect
 * re-probes (a failover may land on a different server version / config).
 *
 *   gcc -DGUARD_CURRENT ... -> no guard (kv_ttl ignored) + latch never sticks
 *                             => RED.
 *   gcc ...                -> the FIXED guard + latch => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proofs are the e2e (AllowMsgTTL reads back true on a
 * real ≥2.11 server; a <2.11 / disabled server latches off + falls back).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_ttl_zero_guard test_kv_ttl_zero_guard.c
 */
#include <stdio.h>

/* ─── carried copies of the production helpers (cachedb_nats_ttl.c) ─ */

/* 0 = ok (kv_ttl is 0); -1 = reject (non-zero bucket TTL would expire
 * permanent contacts).  Negative kv_ttl is also rejected (invalid). */
static int _kv_ttl_guard(int kv_ttl)
{
#ifdef GUARD_CURRENT
	(void)kv_ttl; return 0;   /* today: no guard */
#else
	return (kv_ttl == 0) ? 0 : -1;
#endif
}

enum ttl_cap { TTL_CAP_UNPROBED = 0, TTL_CAP_SUPPORTED = 1, TTL_CAP_UNSUPPORTED = 2 };
enum ttl_cap_event { TTL_EV_SETUP_OK = 0, TTL_EV_SETUP_FAIL = 1,
                     TTL_EV_SAW_10166 = 2, TTL_EV_RECONNECT = 3 };

static int _ttl_cap_next(int cur, int ev)
{
#ifdef GUARD_CURRENT
	(void)cur; return TTL_CAP_SUPPORTED;   /* today: assume supported, never latch off */
#else
	if (ev == TTL_EV_RECONNECT)
		return TTL_CAP_UNPROBED;            /* re-probe on reconnect */
	if (ev == TTL_EV_SAW_10166 || ev == TTL_EV_SETUP_FAIL)
		return TTL_CAP_UNSUPPORTED;         /* latch off for the connection */
	/* TTL_EV_SETUP_OK */
	if (cur == TTL_CAP_UNSUPPORTED)
		return TTL_CAP_UNSUPPORTED;         /* stay latched until a reconnect */
	return TTL_CAP_SUPPORTED;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef GUARD_CURRENT
	printf("== carried copy: GUARD_CURRENT (no guard, no latch) ==\n");
#else
	printf("== carried copy: FIXED guard + latch ==\n");
#endif

	printf("[REV-7] kv_ttl==0 guard (protects permanent contacts):\n");
	CHECK(_kv_ttl_guard(0) == 0, "kv_ttl==0 => accepted");
	CHECK(_kv_ttl_guard(30) == -1, "kv_ttl==30 => REJECTED (bucket MaxAge expires permanent contacts)");
	CHECK(_kv_ttl_guard(1) == -1, "kv_ttl==1 => rejected");
	CHECK(_kv_ttl_guard(-5) == -1, "negative kv_ttl => rejected (invalid)");

	printf("[TREV-8] capability latch transitions:\n");
	CHECK(_ttl_cap_next(TTL_CAP_UNPROBED, TTL_EV_SETUP_OK) == TTL_CAP_SUPPORTED,
	      "UNPROBED + AllowMsgTTL setup ok => SUPPORTED");
	CHECK(_ttl_cap_next(TTL_CAP_UNPROBED, TTL_EV_SETUP_FAIL) == TTL_CAP_UNSUPPORTED,
	      "setup fail => UNSUPPORTED (fall back to reaper)");
	CHECK(_ttl_cap_next(TTL_CAP_SUPPORTED, TTL_EV_SAW_10166) == TTL_CAP_UNSUPPORTED,
	      "a runtime 10166 latches SUPPORTED -> UNSUPPORTED");
	CHECK(_ttl_cap_next(TTL_CAP_UNSUPPORTED, TTL_EV_SETUP_OK) == TTL_CAP_UNSUPPORTED,
	      "stays latched UNSUPPORTED without a reconnect");
	CHECK(_ttl_cap_next(TTL_CAP_UNSUPPORTED, TTL_EV_RECONNECT) == TTL_CAP_UNPROBED,
	      "reconnect re-probes (UNSUPPORTED -> UNPROBED)");
	CHECK(_ttl_cap_next(TTL_CAP_SUPPORTED, TTL_EV_RECONNECT) == TTL_CAP_UNPROBED,
	      "reconnect re-probes even from SUPPORTED (failover may differ)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
