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
 * Watcher teardown policy lock: the disconnect path must DESTROY the
 * claimed watcher handle, not leak it.
 *
 * History: cachedb_nats_watch.c used to skip kvWatcher_Destroy() when
 * the broker was down ("nats.c's I/O thread may be cleaning up the same
 * internal structures -- destroying here causes double-free") and count
 * the skip in `watcher_handle_leaks`.  The fear was refuted by a live
 * spike (design repo code/tests/watcher_destroy_spike.c: 10 SIGKILL
 * broker-flap cycles, Stop+Destroy on a disconnected connection with
 * the reconnect thread live, ASan-clean on the pinned libnats).  Under
 * a flapping broker the old skip accumulated one handle per cycle in a
 * long-lived process.
 *
 * This test locks the fixed policy in the source: the teardown block
 * must call kvWatcher_Destroy() unconditionally after Stop, and must
 * NOT increment watcher_handle_leaks (the counter stays as an MI/stat
 * surface, expected 0, so dashboards and alert rules keep working).
 *
 * Build:  gcc -g -O0 -Wall -o test_watcher_destroy_policy \
 *             test_watcher_destroy_policy.c
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
	long n;
	char *buf;
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf || fread(buf, 1, n, f) != (size_t)n) exit(1);
	buf[n] = '\0';
	fclose(f);
	return buf;
}

int main(void)
{
	char *w = slurp("../cachedb_nats_watch.c");
	const char *claim, *destroy, *inc;

	/* the claim-once teardown still exists ... */
	claim = strstr(w, "atomic_exchange(&_watcher, NULL)");
	ASSERT(claim != NULL, "claim-once teardown block present");

	/* ... and within it, Destroy follows Stop unconditionally: no
	 * connectivity gate between them, no leak-counter arm. */
	if (claim) {
		destroy = strstr(claim, "kvWatcher_Destroy");
		ASSERT(destroy != NULL, "teardown destroys the claimed handle");
		if (destroy) {
			char *gate = strstr(claim, "nats_pool_is_connected");
			ASSERT(gate == NULL || gate > destroy,
				"destroy is NOT gated on broker connectivity");
		}
		inc = strstr(claim, "NATS_CDB_STATS_INC(watcher_handle_leaks)");
		ASSERT(inc == NULL || inc > claim + 4000,
			"teardown does not count an intentional leak");
	}

	free(w);
	if (g_fails == 0) { fprintf(stderr, "=== ALL PASS ===\n"); return 0; }
	fprintf(stderr, "=== FAILS=%d ===\n", g_fails);
	return 1;
}
