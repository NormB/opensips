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
 * Regression test: cachedb_nats_watch.c used the result of
 * nats_dl.kvEntry_Key() directly in strlen() / strncmp() /
 * nats_json_index_*() without guarding against a NULL return.  libnats
 * can return NULL for a malformed / header-only KV entry; a NULL key
 * then crashes strlen / strncmp.  There are three call sites:
 *
 *   - raise_kv_change_event(): HAVE_EVI path  (key -> strlen, memcpy)
 *   - raise_kv_change_event(): non-EVI path   (key -> LM_DBG %s)
 *   - the watcher event loop:   key -> strncmp / index add/remove
 *
 * The fix adds a NULL check at each site (early return / continue).
 *
 * These sites run on the libnats callback / watcher thread and can't be
 * unit-isolated without linking the whole module, so this is a
 * structural test: it locates each kvEntry_Key() call site in the
 * production source and asserts a NULL guard (`if (!key)`) appears
 * within a small window after it.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_watch_null_key_guard test_watch_null_key_guard.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Read the whole file into a heap buffer (NUL-terminated). */
static char *slurp(const char *path, long *len_out)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
	buf[n] = '\0';
	fclose(f);
	if (len_out) *len_out = n;
	return buf;
}

/* Return non-zero if every occurrence of kvEntry_Key( assigned into a
 * `key` variable is followed (within `window` bytes) by an `if (!key)`
 * guard.  Returns the number of guarded sites via *guarded and total
 * sites via *total. */
static void scan_guards(const char *src, int window, int *guarded, int *total)
{
	const char *p = src;
	const char *needle = "kvEntry_Key(entry)";
	*guarded = 0;
	*total = 0;
	while ((p = strstr(p, needle))) {
		const char *site = p;
		p += strlen(needle);
		(*total)++;
		/* search a window after the site for the NULL guard */
		{
			char saved;
			char *cut;
			const char *seg = site;
			long remaining = (long)strlen(seg);
			long win = remaining < window ? remaining : window;
			cut = (char *)(seg + win);
			saved = *cut;
			*cut = '\0';
			if (strstr(seg, "if (!key)"))
				(*guarded)++;
			*cut = saved;
		}
	}
}

int main(void)
{
	long len;
	char *src = slurp("../cachedb_nats_watch.c", &len);
	int guarded = 0, total = 0;

	ASSERT(src != NULL, "read cachedb_nats_watch.c");
	if (!src) goto done;

	scan_guards(src, 600, &guarded, &total);

	fprintf(stderr, "  kvEntry_Key(entry) sites: total=%d guarded=%d\n",
		total, guarded);

	/* Both call sites (EVI dispatch + index update; the third lived in
	 * the dead non-EVI fallback arm removed with the always-true
	 * HAVE_EVI guards, P1.4) must be present and guarded.  (If a
	 * future refactor adds another, this asserts it is guarded too.) */
	ASSERT(total >= 2, "both kvEntry_Key(entry) call sites present");
	ASSERT(guarded == total,
		"every kvEntry_Key(entry) call site has an 'if (!key)' NULL guard");

	free(src);
done:
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
