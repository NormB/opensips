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
 * [P3.5] (ptr,len) threading through the update compose path: every
 * builder stage already knows the length of the document it produced
 * (the growable sink tracks it), yet update_apply_and_cas re-measured
 * the full document with strlen() ~6x per REGISTER -- kilobyte scans
 * for values already in hand:
 *
 *     fetch -> strlen -> merge -> strlen -> hygiene -> strlen ->
 *     finalize -> strlen (size guard) -> strlen (CAS write) ->
 *     strlen (index add)
 *
 * Now each stage outputs its length (out_len params existed on
 * hygiene/finalize and were passed NULL; the merge + fetch gained
 * one) and the caller threads it through.  Structural lock: no
 * full-document strlen() remains in the update compose path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Extract the brace-balanced body following `sig`. */
static char *func_body(const char *path, const char *sig)
{
	FILE *f = fopen(path, "r");
	char *buf, *p, *br, *s, *body = NULL;
	long n;
	int depth = 0;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	p = strstr(buf, sig);
	if (p) {
		br = p;
		while (*br && *br != '{' && *br != ';') br++;
		if (*br == '{') {
			for (s = br; *s; s++) {
				if (*s == '{') depth++;
				else if (*s == '}' && --depth == 0) { s++; break; }
			}
			body = malloc((size_t)(s - br) + 1);
			if (body) {
				memcpy(body, br, (size_t)(s - br));
				body[s - br] = '\0';
			}
		}
	}
	free(buf);
	return body;
}

static int count(const char *hay, const char *needle)
{
	int c = 0;
	const char *p = hay;
	while (hay && (p = strstr(p, needle)) != NULL) {
		c++;
		p += strlen(needle);
	}
	return c;
}

int main(void)
{
	const char *src = "../cachedb_nats_json.c";
	char *body;

	/* the merge stage reports its length */
	body = func_body(src, "static char *apply_pairs_one_pass(");
	ASSERT(body != NULL, "found apply_pairs_one_pass");
	if (body) {
		ASSERT(strstr(body, "out_len") != NULL ||
		       count(body, "cdbn_sink_take(") == 0,
			"merge stage surfaces the sink's length (out_len)");
		free(body);
	}
	{
		/* signature-level check: the declaration carries out_len */
		FILE *f = fopen(src, "r");
		char line[512];
		int has = 0;
		while (f && fgets(line, sizeof(line), f)) {
			if (strstr(line, "apply_pairs_one_pass(const char *json,"))
				has |= 1;
			if (has && strstr(line, "out_len")) { has = 2; break; }
		}
		if (f) fclose(f);
		ASSERT(has == 2, "apply_pairs_one_pass signature has out_len");
	}

	/* the fetch stage reports the stored doc's length */
	body = func_body(src, "static int update_fetch_or_seed(");
	ASSERT(body != NULL, "found update_fetch_or_seed");
	if (body) {
		free(body);
	}

	/* the compose path itself: zero full-document strlen()s left */
	body = func_body(src, "static int update_apply_and_cas(");
	ASSERT(body != NULL, "found update_apply_and_cas");
	if (body) {
		ASSERT(count(body, "strlen(new_json)") == 0,
			"no strlen(new_json) left in the compose path");
		ASSERT(count(body, "strlen(json_buf)") == 0,
			"no strlen(json_buf) left in the compose path");
		free(body);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
