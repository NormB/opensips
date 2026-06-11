/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_json_index_rebuild() runs on the watcher pthread
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
	const char *src = "../cachedb_nats_json.c";
	char *body = body_after(src, "nats_json_index_rebuild(kvStore");
	ASSERT(body != NULL, "found nats_json_index_rebuild body");
	if (!body) { fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails); return 1; }

	/* The invariant: no pkg on the watcher-pthread rebuild path. */
	ASSERT(count(body, "pkg_malloc(") == 0,
		"rebuild uses no pkg_malloc (watcher-pthread thread-safety)");
	ASSERT(count(body, "pkg_free(") == 0,
		"rebuild uses no pkg_free (watcher-pthread thread-safety)");

	/* It must still allocate its scratch -- via shm (thread-safe). */
	ASSERT(count(body, "shm_malloc(") >= 2,
		"rebuild allocates shadow + old-bucket scratch via shm_malloc");
	ASSERT(count(body, "shm_free(") >= 2,
		"rebuild releases its scratch via shm_free");

	free(body);

	/* And the call site really is the watcher pthread (documents the why). */
	{
		FILE *w = fopen("../cachedb_nats_watch.c", "r");
		char line[4096]; int saw = 0;
		if (w) {
			while (fgets(line, sizeof(line), w))
				if (strstr(line, "nats_json_index_rebuild(")) { saw = 1; break; }
			fclose(w);
		}
		ASSERT(saw, "watcher TU calls nats_json_index_rebuild (the racy caller)");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
