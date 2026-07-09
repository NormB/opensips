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
 * Regression test: the pool connect options set a fixed reconnect wait
 * with no jitter, and the startup retry loop slept a fixed
 * reconnect_wait.  With N worker processes, a broker restart makes all of
 * them reconnect in lockstep -- a thundering herd that hammers the broker
 * every reconnect_wait.  Fix: enable cnats reconnect jitter and add a
 * per-process jitter to the startup retry sleep.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_reconnect_jitter test_reconnect_jitter.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}

int main(void)
{
	const char *pool = "../nats_pool.c";

	ASSERT(file_contains(pool, "natsOptions_SetReconnectJitter"),
		"pool enables cnats reconnect jitter");
	ASSERT(file_contains("../nats_dl_table.def", "natsOptions_SetReconnectJitter"),
		"SetReconnectJitter is in the dl symbol table");
	/* The startup retry sleep is jittered per process (PID-derived). */
	ASSERT(file_contains(pool, "getpid() % (unsigned)span") ||
	       file_contains(pool, "% (unsigned)span"),
		"startup retry sleep adds a per-process jitter");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
