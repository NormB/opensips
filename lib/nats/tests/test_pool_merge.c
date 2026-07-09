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
 * Coverage for TODO #74: the pool server-URL parse/merge (the comma
 * tokenizer factored in P3-61 into _append_server_urls) had no unit test.
 * It tokenizes a comma-separated URL string, trims whitespace, skips URLs
 * already present (dedup), detects tls://, and either hard-errors or
 * warn-skips when it would exceed the server cap.
 *
 * This carries a faithful model of that loop and exercises the tricky
 * cases (whitespace/empty tokens, within-string + cross-registration dedup,
 * tls detection, hard vs soft overflow), then asserts the production wiring.
 *
 * Build (self-contained):
 *   gcc -g -O0 -fsanitize=address -Wall -o test_pool_merge test_pool_merge.c
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
	if (!f) { fprintf(stderr, "  (cannot open %s)\n", path); return 0; }
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* ---- carried model of _append_server_urls ------------------------- */

#define MAX_SERVERS 4
struct cfg { char *servers[MAX_SERVERS]; int cnt; int use_tls; };

/* returns servers added, or -1 on hard overflow */
static int append_urls(struct cfg *c, const char *url, int hard_overflow)
{
	const char *p = url, *tok;
	int len, i, added = 0;
	while (*p) {
		while (*p == ',' || *p == ' ' || *p == '\t') p++;
		if (!*p) break;
		tok = p;
		while (*p && *p != ',') p++;
		len = (int)(p - tok);
		while (len > 0 && (tok[len-1] == ' ' || tok[len-1] == '\t')) len--;
		if (len <= 0) continue;
		for (i = 0; i < c->cnt; i++)
			if ((int)strlen(c->servers[i]) == len &&
			    strncmp(c->servers[i], tok, len) == 0) break;
		if (i < c->cnt) continue;                 /* duplicate */
		if (c->cnt >= MAX_SERVERS) {
			if (hard_overflow) return -1;
			continue;                             /* soft: warn-skip */
		}
		c->servers[c->cnt] = strndup(tok, len);
		if (len >= 6 && strncmp(c->servers[c->cnt], "tls://", 6) == 0)
			c->use_tls = 1;
		c->cnt++;
		added++;
	}
	return added;
}

static void free_cfg(struct cfg *c) { int i; for (i=0;i<c->cnt;i++) free(c->servers[i]); }

int main(void)
{
	/* ---- tokenize + trim + empty tokens ------------------------ */
	{
		struct cfg c = {0};
		ASSERT(append_urls(&c, " nats://h1:4222 , , nats://h2:4222 ,", 1) == 2,
			"trims whitespace + skips empty tokens (2 servers)");
		ASSERT(c.cnt == 2 && strcmp(c.servers[0], "nats://h1:4222") == 0 &&
			strcmp(c.servers[1], "nats://h2:4222") == 0,
			"both URLs parsed exactly");
		ASSERT(c.use_tls == 0, "no tls detected for nats://");
		free_cfg(&c);
	}

	/* ---- within-string + cross-registration dedup -------------- */
	{
		struct cfg c = {0};
		ASSERT(append_urls(&c, "nats://h1,nats://h1,nats://h2", 1) == 2,
			"within-string duplicate deduped (2, not 3)");
		ASSERT(append_urls(&c, "nats://h2,nats://h3", 0) == 1,
			"second registration adds only the new server");
		ASSERT(c.cnt == 3, "3 unique servers across two registrations");
		free_cfg(&c);
	}

	/* ---- tls detection ----------------------------------------- */
	{
		struct cfg c = {0};
		append_urls(&c, "nats://h1,tls://h2", 1);
		ASSERT(c.use_tls == 1, "tls:// in the list sets use_tls");
		free_cfg(&c);
	}

	/* ---- hard vs soft overflow --------------------------------- */
	{
		struct cfg c = {0};
		ASSERT(append_urls(&c, "a,b,c,d,e", 1) == -1,
			"hard overflow (initial parse) returns -1");
		free_cfg(&c);

		struct cfg c2 = {0};
		append_urls(&c2, "a,b,c,d", 0);          /* fill to cap */
		ASSERT(append_urls(&c2, "e,f", 0) == 0,
			"soft overflow (merge) warn-skips, adds 0");
		ASSERT(c2.cnt == MAX_SERVERS, "cap respected on soft overflow");
		free_cfg(&c2);
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *p = "../nats_pool.c";
		ASSERT(file_contains(p, "_append_server_urls"),
			"pool defines the shared tokenizer helper");
		ASSERT(file_contains(p, "_append_server_urls(url, 1"),
			"initial parse uses hard overflow");
		ASSERT(file_contains(p, "_append_server_urls(url, 0"),
			"merge path uses soft overflow");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
