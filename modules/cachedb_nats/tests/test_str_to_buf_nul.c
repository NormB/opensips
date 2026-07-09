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
 * Regression: nats_str_to_buf (lib/nats/nats_str.h) is the shared str->C-string
 * chokepoint for the generic cachedb_nats write paths (nats_cache_set,
 * w_nats_kv_put, nats_cache_map_set).  It guarded negative and oversize lengths
 * but NOT an embedded NUL: it copied the NUL-bearing value and NUL-terminated,
 * and the downstream kvStore_PutString (a C-string API) then silently truncated
 * the stored value at the embedded NUL -- so set("a\0b") stored "a" and a later
 * get returned "a" (silent data loss).  The usrloc row path is unaffected (it
 * uses length-aware natsMsg_Create), and keys never legitimately contain NUL.
 *
 * Fix: nats_str_to_buf rejects a value containing an embedded NUL (memchr),
 * consistent with the module's fail-closed reject-at-write hygiene.
 *
 * Models the accept/reject decision:
 *   -DSIMULATE_NO_NUL_CHECK -> no NUL guard -> embedded-NUL value accepted
 *                              (and would truncate downstream) -> assertion FAILS.
 *   (default)               -> embedded NUL rejected -> ALL PASS.
 * plus a source-wiring assertion.
 *
 * Build: gcc -g -O0 -Wall -o test_str_to_buf_nul test_str_to_buf_nul.c
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
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Model of nats_str_to_buf's accept/reject decision (s may contain embedded
 * NULs; len is the authoritative byte count). Returns 0 on success, -1 reject. */
static int str_to_buf(const char *s, int len, char *buf, int bufsize)
{
	if (len < 0) return -1;
	if (!s || len <= 0) { buf[0] = '\0'; return 0; }
	if (len >= bufsize) return -1;
#ifndef SIMULATE_NO_NUL_CHECK
	if (memchr(s, '\0', (size_t)len)) return -1;   /* embedded NUL -> reject */
#endif
	memcpy(buf, s, len);
	buf[len] = '\0';
	return 0;
}

int main(void)
{
	char buf[64];

	ASSERT(str_to_buf("abc", 3, buf, sizeof(buf)) == 0 && strcmp(buf, "abc") == 0,
		"a clean value is accepted verbatim");

	/* "a\0b" -- 3 bytes with an embedded NUL. */
	ASSERT(str_to_buf("a\0b", 3, buf, sizeof(buf)) == -1,
		"a value with an embedded NUL is REJECTED (not silently truncated)");

	ASSERT(str_to_buf(NULL, 0, buf, sizeof(buf)) == 0 && buf[0] == '\0',
		"a NULL/empty value yields an empty string");
	ASSERT(str_to_buf("x", -1, buf, sizeof(buf)) == -1,
		"a negative length is rejected");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../../../lib/nats/nats_str.h";
		ASSERT(file_contains(src, "memchr(s->s, '\\0'"),
			"nats_str_to_buf rejects an embedded NUL via memchr");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
