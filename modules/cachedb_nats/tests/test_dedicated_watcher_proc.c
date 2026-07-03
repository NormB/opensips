/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Dedicated-watcher wiring test: the KV watcher runs ONLY as a
 * dedicated OpenSIPS child process (proc_export_t), never as a pthread
 * inside the rank-1 SIP worker.
 *
 * The deleted in-worker pthread mode was a default-on use-after-free:
 * the watcher pthread called nats_pool_get_kv() concurrently with the
 * worker's main thread, but the pool's _kv_cache[]/_kv_stale/_js state
 * is written as process-single-threaded — after any reconnect one
 * thread could kvStore_Destroy() a cached handle while the other was
 * inside kvStore_Get() on it.  The dedicated-process variant has none
 * of these races (its process runs exactly one thread against the
 * pool), so it is now the only mode and the dedicated_watcher_proc
 * modparam is gone.
 *
 * This test is structural -- it greps the production source for the
 * single-mode wiring and for the ABSENCE of the pthread path.
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
	/* The two-mode knob is GONE: no modparam, no global. */
	ASSERT(!file_contains("../cachedb_nats.c",
		"\"dedicated_watcher_proc\""),
		"dedicated_watcher_proc modparam removed");
	ASSERT(!file_contains("../cachedb_nats.c",
		"nats_dedicated_watcher_proc"),
		"nats_dedicated_watcher_proc global removed");

	/* proc_export_t entry pointing at the dedicated proc main */
	ASSERT(file_contains("../cachedb_nats.c",
		"proc_export_t"),
		"proc_export_t declared in cachedb_nats.c");
	ASSERT(file_contains("../cachedb_nats.c",
		"NATS Watcher"),
		"proc name string \"NATS Watcher\" present");
	ASSERT(file_contains("../cachedb_nats.c",
		"nats_watcher_proc_main"),
		"dedicated proc main referenced from cachedb_nats.c");

	/* mod_init wires exports.procs whenever there is something to
	 * watch — the watcher serves E_NATS_KV_CHANGE always and feeds the
	 * FTS index only when the optional cachedb_nats_fts module is
	 * bound (P1.2 split). */
	ASSERT(file_contains("../cachedb_nats.c",
		"if (kv_watch_count > 0)"),
		"mod_init gates exports.procs on kv_watch only");
	ASSERT(file_contains("../cachedb_nats.c",
		"exports.procs ="),
		"mod_init assigns exports.procs at runtime");

	/* The in-worker pthread path is GONE. */
	ASSERT(!file_contains("../cachedb_nats.c",
		"nats_watch_start"),
		"child_init no longer spawns the watcher pthread");
	ASSERT(!file_contains("../cachedb_nats_watch.c",
		"pthread_create"),
		"cachedb_nats_watch.c contains no pthread_create");
	ASSERT(!file_contains("../cachedb_nats.c",
		"nats_watch_stop"),
		"destroy() no longer joins a watcher pthread");

	/* The dedicated proc main lives in cachedb_nats_watch.c */
	ASSERT(file_contains("../cachedb_nats_watch.c",
		"void nats_watcher_proc_main"),
		"nats_watcher_proc_main defined in cachedb_nats_watch.c");

	/* Header export so cachedb_nats.c can see the symbol */
	ASSERT(file_contains("../cachedb_nats_watch.h",
		"nats_watcher_proc_main"),
		"nats_watcher_proc_main declared in cachedb_nats_watch.h");

	/* Orphan-on-parent-death protection: the dedicated proc must
	 * arm PR_SET_PDEATHSIG so the kernel reaps it if the master
	 * OpenSIPS aborts (e.g., a sibling module's pre-fork hook fails)
	 * after our fork has already returned.  Without this, an aborted
	 * startup leaves a stale watcher orphaned to PID 1, racing the
	 * next startup.  Use SIGKILL not SIGTERM: OpenSIPS's core
	 * SIGTERM handler does graceful cleanup that needs the parent
	 * alive, so SIGTERM under PDEATHSIG hangs.  SIGKILL is
	 * uncatchable. */
	ASSERT(file_contains("../cachedb_nats_watch.c",
		"PR_SET_PDEATHSIG, SIGKILL"),
		"watcher arms PR_SET_PDEATHSIG with SIGKILL (uncatchable)");
	ASSERT(file_contains("../cachedb_nats_watch.c",
		"getppid() == 1"),
		"watcher polls getppid in loop as belt-and-suspenders "
		"backstop for the rare case where PDEATHSIG didn't arm");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
