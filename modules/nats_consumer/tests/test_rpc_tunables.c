/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the async-RPC slot-pool size (NATS_RPC_SLOT_COUNT, 64)
 * and the per-call timerfd poll interval (1 ms) were compile-time
 * constants.  The slot count caps system-wide async nats_request
 * concurrency (~1.3k req/s @ 50 ms RTT) and the 1 ms poll sets a latency
 * floor plus a fixed timer-wakeup rate -- neither tunable by operators.
 * Fix: promote both to modparams (async_rpc_slots / async_rpc_poll_ms),
 * each clamped to a sane range.
 *
 * Carries the two clamps and checks the production wiring.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_rpc_tunables test_rpc_tunables.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* carried clamps */
static int clamp_slots(int n) { if (n < 1) n = 1; if (n > 65536) n = 65536; return n; }
static long poll_ns(int ms)   { if (ms < 1) ms = 1; if (ms > 1000) ms = 1000; return (long)ms * 1000000L; }

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}

int main(void)
{
	/* slot-count clamp */
	ASSERT(clamp_slots(64) == 64,    "default slot count passes through");
	ASSERT(clamp_slots(0) == 1,      "slot count floored at 1");
	ASSERT(clamp_slots(-5) == 1,     "negative slot count floored at 1");
	ASSERT(clamp_slots(1 << 20) == 65536, "slot count capped at 65536");

	/* poll-interval clamp */
	ASSERT(poll_ns(1) == 1000000L,   "1 ms -> 1e6 ns");
	ASSERT(poll_ns(0) == 1000000L,   "sub-1ms floored to 1 ms");
	ASSERT(poll_ns(5) == 5000000L,   "5 ms honored");
	ASSERT(poll_ns(99999) == 1000000000L, "poll capped at 1000 ms");

	/* production wiring */
	{
		const char *cons  = "../nats_consumer.c";
		const char *slot  = "../nats_rpc_slot.c";
		const char *async = "../nats_rpc_async.c";
		ASSERT(file_contains(cons, "async_rpc_slots") &&
		       file_contains(cons, "async_rpc_poll_ms"),
			"both async-RPC modparams are registered");
		ASSERT(file_contains(slot, "nats_rpc_slot_count"),
			"slot init uses the runtime slot count");
		ASSERT(file_contains(async, "nats_rpc_async_poll_ms"),
			"timerfd arm uses the runtime poll interval");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
