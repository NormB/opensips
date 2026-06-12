/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Watcher hygiene test (NATS_TODO #71):
 *
 *   1. The _watch_patterns pointer array must be allocated/freed with
 *      OpenSIPS's pkg_malloc/pkg_free, not the raw libc malloc/free.
 *      The array is only ever touched on the owning process's main
 *      thread (before pthread_create / after pthread_join, or in the
 *      single-threaded dedicated watcher proc), so pkg memory -- which
 *      gives OpenSIPS's accounting/debug instrumentation -- is correct
 *      and thread-safe here.  The caller at cachedb_nats.c already uses
 *      pkg_malloc for the array it hands in; this matches it.
 *
 *   2. The dedicated watcher proc (nats_watcher_proc_main) is forked by
 *      mod_init ONLY when kv_watch_count > 0, so the _num_patterns == 0
 *      ("no kv_watch patterns configured") logging branch is dead code.
 *      It must be removed.
 *
 * Structural test: greps the production source.  No raw malloc(/free(
 * may survive in cachedb_nats_watch.c (comment prose is skipped), and
 * the dead logging branch's distinctive string must be gone.
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

/* True if the line is a C comment line (first non-space char is '*',
 * or it carries a /​* or // marker) -- such lines are prose, not code. */
static int is_comment_line(const char *line)
{
	const char *p = line;
	while (*p == ' ' || *p == '\t') p++;
	if (*p == '*') return 1;
	if (strstr(line, "/*") || strstr(line, "//")) return 1;
	return 0;
}

/* Count code lines that call `fn(` without a pkg_/shm_ prefix -- i.e.
 * raw libc malloc(/free(.  Comment lines are skipped so that prose like
 * "race -> free(): invalid" does not false-match. */
static int count_raw_calls(const char *path, const char *fn)
{
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
	char line[2048];
	char tok[64];
	int n = 0;
	snprintf(tok, sizeof(tok), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (is_comment_line(line)) continue;
		const char *hit = line;
		while ((hit = strstr(hit, tok)) != NULL) {
			/* preceded by [A-Za-z0-9_]  => pkg_/shm_/foo_ prefix */
			int raw = 1;
			if (hit != line) {
				char c = hit[-1];
				if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				    (c >= '0' && c <= '9') || c == '_')
					raw = 0;
			}
			if (raw) n++;
			hit += 1;
		}
	}
	fclose(f);
	return n;
}

int main(void)
{
	const char *W = "../cachedb_nats_watch.c";

	/* (1) pkg memory for the patterns array, both code paths. */
	ASSERT(file_contains(W, "pkg_malloc(num_patterns * sizeof(char *))"),
		"nats_watch_start uses pkg_malloc for _watch_patterns");
	ASSERT(file_contains(W, "pkg_malloc((kv_watch_count + 1) * sizeof(char *))"),
		"nats_watcher_proc_main uses pkg_malloc for patterns");
	ASSERT(file_contains(W, "pkg_free(_watch_patterns)"),
		"_watch_patterns released with pkg_free");

	/* No raw libc malloc/free may survive in the watcher TU. */
	ASSERT(count_raw_calls(W, "malloc") == 0,
		"no raw malloc( in cachedb_nats_watch.c");
	ASSERT(count_raw_calls(W, "free") == 0,
		"no raw free( in cachedb_nats_watch.c");

	/* pkg_malloc needs mem/mem.h. */
	ASSERT(file_contains(W, "mem/mem.h"),
		"cachedb_nats_watch.c includes mem/mem.h for pkg_malloc");

	/* (2) the unreachable _num_patterns == 0 logging branch is gone. */
	ASSERT(!file_contains(W, "no kv_watch patterns configured"),
		"dead _num_patterns==0 logging branch removed from proc main");
	ASSERT(file_contains(W, "watcher proc: watching"),
		"reachable 'watcher proc: watching N pattern(s)' log retained");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
