/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * [Tier-4] Event-driven-ish disconnect cancellation for async
 * nats_request: an INFLIGHT slot whose connection epoch was lost must
 * surface -2 on the NEXT guard tick (async_rpc_poll_ms, default 100 ms),
 * not after the full request timeout.  A request published on a dead
 * connection is orphaned even if the pool reconnects -- its inbox and
 * the consumer subscription died with the connection -- so waiting out
 * timeout_ms only delays the script's failover decision.
 *
 * The cancellation must use the SAME INFLIGHT -> ABANDONED CAS guard as
 * the timeout path: if the consumer wins the race (DELIVERING/DELIVERED),
 * keep polling and deliver the reply -- never drop an at-the-wire reply.
 *
 * Carries the resume decision ladder and locks the production wiring.
 *
 * Build: gcc -g -O0 -Wall -o test_rpc_disconnect_cancel \
 *            test_rpc_disconnect_cancel.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, label) do { \
	if (cond) fprintf(stderr, "  ok: %s\n", (label)); \
	else { fprintf(stderr, "  FAIL: %s\n", (label)); g_fails++; } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	long n; char *buf; size_t got;
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) exit(1);
	got = fread(buf, 1, n, f);
	buf[got] = '\0';
	fclose(f);
	return buf;
}

/* ── carried model: the INFLIGHT branch of the resume ladder ─────── */

enum verdict { CONTINUE, DONE_TIMEOUT /* -1 */, DONE_DISC /* -2 */ };

/* mirrors resume_nats_request_slot()'s INFLIGHT handling:
 *   epoch lost  -> try abandon now; CAS win = -2, CAS loss = continue
 *   past deadline -> try abandon; CAS win = disc ? -2 : -1, loss = continue
 *   otherwise   -> continue */
static enum verdict inflight_verdict(int epoch_lost, int past_deadline,
	int cas_wins)
{
	if (epoch_lost) {
		if (!cas_wins) return CONTINUE;
		return DONE_DISC;
	}
	if (past_deadline) {
		if (!cas_wins) return CONTINUE;
		return DONE_TIMEOUT;
	}
	return CONTINUE;
}

int main(void)
{
	/* ---- model -------------------------------------------------- */
	{
		ASSERT(inflight_verdict(1, 0, 1) == DONE_DISC,
			"epoch lost mid-flight cancels on the next tick (-2)");
		ASSERT(inflight_verdict(1, 1, 1) == DONE_DISC,
			"epoch lost at deadline still reports -2, not -1");
		ASSERT(inflight_verdict(1, 0, 0) == CONTINUE,
			"consumer winning the CAS keeps the reply (no drop)");
		ASSERT(inflight_verdict(0, 1, 1) == DONE_TIMEOUT,
			"plain deadline without disconnect stays -1");
		ASSERT(inflight_verdict(0, 0, 1) == CONTINUE,
			"healthy in-flight call keeps polling");
	}

	/* ---- production wiring locks --------------------------------- */
	{
		char *s = slurp("../nats_rpc_async.c");
		char *inflight = strstr(s, "state == INFLIGHT")
			? strstr(s, "state == INFLIGHT")
			: strstr(s, "INFLIGHT.  Check");
		ASSERT(inflight != NULL, "INFLIGHT branch located");
		if (inflight) {
			char *epoch = strstr(inflight, "nats_epoch_lost");
			char *deadline = strstr(inflight, "deadline_us");
			ASSERT(epoch && deadline && epoch < deadline,
				"epoch checked BEFORE the deadline gate (per-tick cancel)");
			ASSERT(strstr(inflight, "nats_rpc_slot_abandon") != NULL,
				"cancel path goes through the abandon CAS");
		}
		free(s);
	}

	/* ---- documented budget --------------------------------------- */
	{
		char *s = slurp("../doc/nats_consumer_admin.xml");
		ASSERT(strstr(s, "next guard tick") != NULL
		    || strstr(s, "one poll tick") != NULL,
			"admin doc states the sub-second cancellation budget");
		free(s);
	}

	if (g_fails == 0) { fprintf(stderr, "=== ALL PASS ===\n"); return 0; }
	fprintf(stderr, "=== FAILS=%d ===\n", g_fails);
	return 1;
}
