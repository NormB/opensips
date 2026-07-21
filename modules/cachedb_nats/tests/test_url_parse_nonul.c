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
 * Regression test [P0.9]: the mod_init cachedb_url -> nats_url rewrite
 * must not run libc strstr() over the URL.
 *
 * Core cachedb_store_url() (cachedb/cachedb.c) allocates exactly
 * sizeof(struct cachedb_url) + len and never writes a trailing NUL, so
 * nats_cdb_urls->url.s is NOT NUL-terminated.  The rewrite in
 * cachedb_nats.c did strstr(url.s, "://"): for a configured cachedb_url
 * that happens to lack "://" the scan reads past the pkg allocation —
 * an out-of-bounds read.  (A normal URL contains "://", which bounds
 * the scan — which is why this stayed latent.)
 *
 * Fix: use the counted core helper str_strstr(&url, "://") instead.
 *
 * This test:
 *   1. exercises a carried copy of the FIXED bounded parse against
 *      heap buffers allocated to the EXACT string length (no NUL, no
 *      slack) — under ASan any overread trips immediately;
 *      adversarial shapes: no "://" at all, separator at the very end,
 *      partial separator truncated by the length, 1-byte and 0-byte
 *      URLs, trailing-slash stripping;
 *   2. source-pattern: asserts production cachedb_nats.c performs the
 *      rewrite via str_strstr and no longer calls strstr on the URL.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_url_parse_nonul \
 *            test_url_parse_nonul.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ── carried copy of the FIXED parse (mirrors cachedb_nats.c) ────── */

/* counted substring search — the shape of core ut.h str_strstr */
static char *bounded_strstr(const char *s, int len,
	const char *needle, int nlen)
{
	int i;
	if (!s || len <= 0 || nlen <= 0 || nlen > len)
		return NULL;
	for (i = 0; i <= len - nlen; i++)
		if (memcmp(s + i, needle, nlen) == 0)
			return (char *)(s + i);
	return NULL;
}

/* Rewrite "nats:group://h1:4222,h2:4223/" -> "nats://h1:4222,h2:4223".
 * Returns 1 and fills @out on success, 0 when the URL is unparseable
 * (caller falls back to the default).  @url is NOT NUL-terminated. */
static int url_rewrite(const char *url, int url_len,
	char *out, size_t out_sz)
{
	char *hosts_start = bounded_strstr(url, url_len, "://", 3);
	int hlen;

	if (!hosts_start)
		return 0;
	hosts_start += 3;
	hlen = url_len - (int)(hosts_start - url);
	while (hlen > 0 && hosts_start[hlen - 1] == '/')
		hlen--;
	if (hlen <= 0 || hlen >= (int)out_sz - 8)
		return 0;
	snprintf(out, out_sz, "nats://%.*s", hlen, hosts_start);
	return 1;
}

/* heap buffer of EXACTLY len bytes — no NUL terminator, no slack;
 * ASan red-zones start at s[len] */
static char *exact_dup(const char *lit)
{
	int len = (int)strlen(lit);
	char *s = malloc(len > 0 ? len : 1);
	memcpy(s, lit, len);
	return s;
}

/* ── source-pattern: production uses the counted search ─────────── */

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
	char out[512];
	char *u;

	/* 1. THE DEFECT SHAPE — URL without "://": the scan must stop at
	 * url.len, not run into the red zone hunting for a NUL */
	u = exact_dup("nats:no-separator-here");
	ASSERT(url_rewrite(u, (int)strlen("nats:no-separator-here"),
		out, sizeof(out)) == 0,
		"URL without :// is rejected without overread");
	free(u);

	/* partial separator truncated by the length: ":/" then end */
	u = exact_dup("nats:group:/");
	ASSERT(url_rewrite(u, 12, out, sizeof(out)) == 0,
		"separator truncated by len is not matched (no overread)");
	free(u);

	/* separator at the very end: empty host list */
	u = exact_dup("nats://");
	ASSERT(url_rewrite(u, 7, out, sizeof(out)) == 0,
		"empty host part after :// is rejected");
	free(u);

	/* boundary sizes */
	u = exact_dup("n");
	ASSERT(url_rewrite(u, 1, out, sizeof(out)) == 0, "1-byte URL rejected");
	ASSERT(url_rewrite(u, 0, out, sizeof(out)) == 0, "0-len URL rejected");
	free(u);

	/* 2. the happy path still parses */
	u = exact_dup("nats:group1://host1:4222,host2:4223/");
	ASSERT(url_rewrite(u, 36, out, sizeof(out)) == 1 &&
		strcmp(out, "nats://host1:4222,host2:4223") == 0,
		"group URL rewritten, trailing slash stripped");
	free(u);

	u = exact_dup("nats://192.0.2.31:4222");
	ASSERT(url_rewrite(u, (int)strlen("nats://192.0.2.31:4222"),
		out, sizeof(out)) == 1 &&
		strcmp(out, "nats://192.0.2.31:4222") == 0,
		"plain URL passes through");
	free(u);

	/* 3. production wiring: counted search, not libc strstr */
	ASSERT(file_contains("../cachedb_nats.c", "str_strstr"),
		"cachedb_nats.c rewrites the URL via str_strstr");
	ASSERT(!file_contains("../cachedb_nats.c", "strstr(p, \"://\")"),
		"cachedb_nats.c no longer strstr()s the non-NUL URL");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
