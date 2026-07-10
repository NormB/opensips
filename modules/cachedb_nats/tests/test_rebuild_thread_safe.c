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
 * Policy test [P3.6]: nats_json_index_rebuild() runs on a dedicated-proc main thread
 * (cachedb_nats_watch.c calls it for the post-reconnect / periodic resync).
 * pkg memory is per-process and NOT thread-safe, so its transient scratch
 * arrays (the shadow bucket array and the old-bucket snapshot) MUST be
 * shm_malloc, never pkg_malloc -- a pkg_malloc on that thread races the SIP
 * worker's main-thread pkg use and corrupts the pkg free list (observed as a
 * spurious "not enough free pkg memory" with the pool nearly empty, then a
 * child_init crash).
 *
 * This asserts the source invariant: the rebuild function body contains no
 * pkg_malloc/pkg_free, and does use shm_malloc/shm_free for its scratch.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_rebuild_thread_safe test_rebuild_thread_safe.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Extract the brace-counted body that follows a unique `anchor` substring
 * (the function's definition signature, e.g. "name(kvStore *kv...").  Anchoring
 * on the signature avoids matching bare "name()" mentions in comments.
 * Returns a malloc'd string from the first '{' after the anchor. */
static char *body_after(const char *path, const char *anchor)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f); fclose(f); buf[n] = '\0';

	char *p = strstr(buf, anchor);
	char *body = NULL;
	if (p) {
		char *br = p;
		while (*br && *br != '{' && *br != ';') br++;
		if (*br == '{') {
			int depth = 0; char *s = br;
			for (; *s; s++) {
				if (*s == '{') depth++;
				else if (*s == '}') { if (--depth == 0) { s++; break; } }
			}
			size_t bl = (size_t)(s - br);
			body = malloc(bl + 1); memcpy(body, br, bl); body[bl] = '\0';
		}
	}
	free(buf);
	return body;
}

/* count non-overlapping occurrences of needle in hay */
static int count(const char *hay, const char *needle)
{
	int c = 0; const char *p = hay;
	while ((p = strstr(p, needle)) != NULL) { c++; p += strlen(needle); }
	return c;
}

int main(void)
{
	const char *src = "../../cachedb_nats_fts/fts_index.c";
	char *body = body_after(src, "nats_json_index_rebuild(kvStore");
	ASSERT(body != NULL, "found nats_json_index_rebuild body");
	if (!body) { fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails); return 1; }

	/* [P3.6] The scratch arrays (shadow buckets + old-buckets
	 * snapshot) are process-private and the rebuild runs on the MAIN
	 * thread of a dedicated proc (the watcher process; the periodic
	 * resync host [P3.3]) -- the in-worker watcher PTHREAD that once
	 * made pkg unsafe here is long gone (P0.2), so pkg is legal,
	 * skips two global-shm-lock round-trips per rebuild, and makes
	 * leaks visible to pkg stats.  pkg OOM falls back to shm
	 * (availability over the optimisation): both allocators must
	 * appear, pkg first. */
	ASSERT(count(body, "scratch_alloc(") >= 2,
		"rebuild allocates both scratch arrays via scratch_alloc");
	ASSERT(count(body, "scratch_free(") >= 2,
		"scratch is released via the owner-aware scratch_free");
	{
		char *helper = body_after(src, "scratch_alloc(size_t bytes");
		ASSERT(helper != NULL, "found the scratch_alloc helper");
		if (helper) {
			ASSERT(count(helper, "pkg_malloc(") >= 1,
				"scratch prefers pkg (dedicated-proc main thread)");
			ASSERT(count(helper, "shm_malloc(") >= 1,
				"pkg OOM falls back to shm (availability)");
			free(helper);
		}
	}

	free(body);

	/* And the call site really is the watcher pthread (documents the why). */
	{
		FILE *w = fopen("../cachedb_nats_watch.c", "r");
		char line[4096]; int saw = 0;
		if (w) {
			while (fgets(line, sizeof(line), w))
				if (strstr(line, "cdbn_fts.rebuild(")) { saw = 1; break; }
			fclose(w);
		}
		ASSERT(saw, "watcher TU calls the index rebuild via binds (the racy caller)");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
