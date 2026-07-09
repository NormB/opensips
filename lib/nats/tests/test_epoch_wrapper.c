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
 * [P2.8] nats_epoch.h -- the epoch-tagged handle idiom.  Truth table
 * over a scripted pool (epoch counter + connected flag):
 *
 *   - save/current: a tag is current until the epoch bumps,
 *   - snapshot/adopt: the REFRESH protocol -- adopting a snapshot taken
 *     BEFORE a mid-refresh reconnect leaves the tag STALE (the P0.1
 *     non-latching property: the next check refreshes again; adopting
 *     a re-read epoch would wedge),
 *   - lost: stale OR disconnected, current AND connected is not lost.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_epoch_wrapper
 *            test_epoch_wrapper.c
 */
#include <stdio.h>

/* scripted pool: the header declares these and we define them */
static int g_epoch, g_connected = 1;
int nats_pool_get_reconnect_epoch(void) { return g_epoch; }
int nats_pool_is_connected(void) { return g_connected; }

#include "../nats_epoch.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

int main(void)
{
	nats_epoch_t e;

	printf("[P2.8] save/current across a reconnect:\n");
	nats_epoch_save(&e);
	CHECK(nats_epoch_current(&e), "fresh tag is current");
	g_epoch++;                            /* broker reconnects */
	CHECK(!nats_epoch_current(&e), "tag stale after the epoch bump");
	nats_epoch_save(&e);
	CHECK(nats_epoch_current(&e), "re-save catches up");

	printf("[P2.8] refresh protocol: snapshot-before-acquire (P0.1):\n");
	{
		int snap = nats_epoch_snapshot();
		g_epoch++;                        /* reconnect lands MID-refresh */
		/* ... handle acquired here (from the old connection) ... */
		nats_epoch_adopt(&e, snap);
		CHECK(!nats_epoch_current(&e),
			"adopting the pre-acquire snapshot leaves the tag STALE "
			"(next call refreshes again -- never wedges)");
	}

	printf("[P2.8] lost = stale OR disconnected:\n");
	nats_epoch_save(&e);
	CHECK(!nats_epoch_lost(&e), "current + connected: not lost");
	g_connected = 0;
	CHECK(nats_epoch_lost(&e), "disconnected: lost even while current");
	g_connected = 1;
	g_epoch++;
	CHECK(nats_epoch_lost(&e), "reconnected since the tag: lost");

	printf("\n=== %s (fails=%d) ===\n",
		g_fails ? "FAILURES" : "ALL PASS", g_fails);
	return g_fails ? 1 : 0;
}
