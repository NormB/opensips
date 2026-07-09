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
 * [P3.3] The reaper's O(bucket) pass (kvStore_Keys + per-key Get + CAS)
 * and the periodic index resync must NOT run in the shared OpenSIPS
 * timer process: at scale a single pass stalls usrloc/tm/dialog timers
 * system-wide for its full duration.  Both jobs now run in a dedicated
 * "NATS Reaper" module process (proc_export_t, same pattern as the KV
 * watcher), scheduled by the header-inline nats_cdb_proc_sched helper.
 *
 * Structural part: greps the production wiring -- no register_timer for
 * reaper/resync remains, the proc entry exists unconditionally, the proc
 * main lives in cachedb_nats_expiry.c and arms the parent-death guard.
 *
 * Behavioral part: drives nats_cdb_proc_sched_due() directly --
 * interval gating, disabled jobs (0 / negative interval), stamp
 * advancement, no catch-up bursts after a stall, job independence.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../cachedb_nats_expiry.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	/* ── structural: the shared-timer registrations are GONE ───── */
	ASSERT(!file_contains("../cachedb_nats.c", "\"nats_cdb_reaper\""),
		"no register_timer(nats_cdb_reaper) in the shared timer proc");
	ASSERT(!file_contains("../cachedb_nats.c", "\"nats_cdb_resync\""),
		"no register_timer(nats_cdb_resync) in the shared timer proc");

	/* ── structural: the dedicated proc replaces them ───────────── */
	ASSERT(file_contains("../cachedb_nats.c", "NATS Reaper"),
		"proc_export entry for the dedicated reaper process");
	ASSERT(file_contains("../cachedb_nats.c",
			"nats_cdb_reaper_proc_main"),
		"proc entry points at nats_cdb_reaper_proc_main");
	ASSERT(file_contains("../cachedb_nats_expiry.c",
			"nats_cdb_reaper_proc_main"),
		"reaper proc main lives in cachedb_nats_expiry.c");
	ASSERT(file_contains("../cachedb_nats_expiry.c",
			"nats_cdb_dedicated_proc_guard"),
		"reaper proc arms the shared parent-death guard");
	ASSERT(file_contains("../cachedb_nats_watch.c",
			"PR_SET_PDEATHSIG"),
		"the parent-death guard (PDEATHSIG) lives in the shared helper");
	ASSERT(file_contains("../cachedb_nats_expiry.c",
			"nats_cdb_periodic_resync"),
		"the periodic resync job is hosted by the reaper proc");
	ASSERT(file_contains("../cachedb_nats_watch.c",
			"nats_cdb_dedicated_proc_guard"),
		"the watcher proc uses the same shared guard helper");

	/* ── behavioral: the due-scheduler contract ─────────────────── */
	{
		nats_cdb_proc_sched_t sc;
		int reap, resync;

		/* seeded "now" -- nothing due before one full interval */
		memset(&sc, 0, sizeof(sc));
		sc.last_reap = sc.last_resync = 1000;
		nats_cdb_proc_sched_due(&sc, 1000 + 29, 30, 60, &reap, &resync);
		ASSERT(reap == 0 && resync == 0,
			"nothing fires before one full interval");

		nats_cdb_proc_sched_due(&sc, 1000 + 30, 30, 60, &reap, &resync);
		ASSERT(reap == 1 && resync == 0,
			"reap fires at its interval; resync (longer) does not");
		ASSERT(sc.last_reap == 1030,
			"a fired job advances its own stamp to now");
		ASSERT(sc.last_resync == 1000,
			"an idle job's stamp is untouched");

		nats_cdb_proc_sched_due(&sc, 1000 + 60, 30, 60, &reap, &resync);
		ASSERT(reap == 1 && resync == 1,
			"both fire when both intervals have elapsed");

		/* a long stall (proc blocked in a slow pass) must yield ONE
		 * run on the next check, not a catch-up burst */
		nats_cdb_proc_sched_due(&sc, 1060 + 500, 30, 60, &reap, &resync);
		ASSERT(reap == 1 && resync == 1, "due after a long stall");
		nats_cdb_proc_sched_due(&sc, 1060 + 501, 30, 60, &reap, &resync);
		ASSERT(reap == 0 && resync == 0,
			"no catch-up burst: stamps reset to now, not to now-k*iv");

		/* interval <= 0 disables a job entirely */
		sc.last_reap = sc.last_resync = 0;
		nats_cdb_proc_sched_due(&sc, 99999, 0, -5, &reap, &resync);
		ASSERT(reap == 0 && resync == 0,
			"interval <= 0 disables the job (0 and negative)");

		/* jobs are independent: resync-only configuration */
		sc.last_reap = sc.last_resync = 2000;
		nats_cdb_proc_sched_due(&sc, 2100, 0, 60, &reap, &resync);
		ASSERT(reap == 0 && resync == 1,
			"resync fires alone when the reaper is disabled");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
