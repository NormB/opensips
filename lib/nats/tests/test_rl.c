/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.7] nats_rl_pass() -- the one-per-interval log gate behind the
 * outage logging policy (rate-limited WARN on repeat + DBG per call).
 * Pure decision helper, header-only; this locks its contract:
 *
 *   - first call on a zeroed slot passes (and stamps),
 *   - calls within the interval are blocked,
 *   - a call at/after slot+interval passes and re-stamps,
 *   - interval <= 0 means "no limiting" (always pass),
 *   - a clock that jumps BACKWARDS re-arms the gate instead of
 *     silencing the site until the clock catches back up,
 *   - slots are independent.
 */

#include <stdio.h>
#include <time.h>

#include "../nats_rl.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);            } \
} while (0)

int main(void)
{
	time_t a = 0, b = 0;

	/* first call passes and stamps */
	CHECK(nats_rl_pass(&a, 1000, 30) == 1, "first call passes");
	CHECK(a == 1000, "first call stamps the slot");

	/* within the interval: blocked, stamp untouched */
	CHECK(nats_rl_pass(&a, 1001, 30) == 0, "t+1 is blocked");
	CHECK(nats_rl_pass(&a, 1029, 30) == 0, "t+interval-1 is blocked");
	CHECK(a == 1000, "blocked calls do not re-stamp");

	/* at the interval boundary: passes and re-stamps */
	CHECK(nats_rl_pass(&a, 1030, 30) == 1, "t+interval passes");
	CHECK(a == 1030, "pass re-stamps to now");

	/* interval <= 0 disables limiting entirely */
	CHECK(nats_rl_pass(&a, 1031, 0) == 1, "interval 0 always passes");
	CHECK(nats_rl_pass(&a, 1031, -5) == 1, "negative interval always passes");

	/* clock jumping backwards re-arms rather than silencing the
	 * site until wall time catches back up to the stale stamp */
	a = 5000;
	CHECK(nats_rl_pass(&a, 4000, 30) == 1, "backwards clock re-arms");
	CHECK(a == 4000, "backwards pass re-stamps to the new now");

	/* independent slots */
	a = 0; b = 0;
	CHECK(nats_rl_pass(&a, 100, 30) == 1 && nats_rl_pass(&b, 100, 30) == 1,
		"slots are independent (both first-pass)");
	CHECK(nats_rl_pass(&a, 110, 30) == 0 && nats_rl_pass(&b, 130, 30) == 1,
		"one slot blocked does not block the other");

	fprintf(stderr, "\ntests: %s (fails=%d)\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails ? 1 : 0;
}
