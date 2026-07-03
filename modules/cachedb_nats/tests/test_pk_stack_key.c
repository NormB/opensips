/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the PK fast-path query did two heap allocations per
 * usrloc read (a malloc for the percent-encoded value + a pkg_malloc for
 * the prefixed target key), for keys that are typically well under 100
 * bytes.  Fix: build the target key into a 512-byte stack buffer, falling
 * back to the heap only for the rare long key (_pk_target_key).
 *
 * This carries a copy of the build/encode logic and verifies it produces
 * the correct "<prefix><percent-encoded value>" and only heap-allocates
 * when the result exceeds the stack buffer; plus a source-pattern check
 * that the production query path uses it (no per-read pkg_malloc).
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_pk_stack_key test_pk_stack_key.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static const char *g_prefix = "json_";

static int kv_char_safe(unsigned char c)
{
	if ((c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z')) return 1;
	switch (c) { case '-': case '_': case '/': case '\\': case '.': return 1; }
	return 0;
}

/* carried copy of _pk_target_key */
static char *pk_target_key(const char *val, int val_len,
	char *stackbuf, int stackcap, int *heap)
{
	static const char hex[] = "0123456789ABCDEF";
	int plen = (g_prefix && *g_prefix) ? (int)strlen(g_prefix) : 0;
	int max_total = plen + val_len * 3 + 1;
	char *buf; int i, w;
	*heap = 0;
	if (max_total <= stackcap) buf = stackbuf;
	else { buf = malloc(max_total); if (!buf) return NULL; *heap = 1; }
	if (plen) memcpy(buf, g_prefix, plen);
	w = plen;
	for (i = 0; i < val_len; i++) {
		unsigned char c = (unsigned char)val[i];
		if (c != '=' && kv_char_safe(c)) buf[w++] = (char)c;
		else { buf[w++]='='; buf[w++]=hex[(c>>4)&0xF]; buf[w++]=hex[c&0xF]; }
	}
	buf[w] = '\0';
	return buf;
}

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	char stk[512]; int heap;

	/* Typical AoR: safe chars pass through, stays on the stack. */
	{
		char *k = pk_target_key("sip:alice@biloxi", 16, stk, sizeof(stk), &heap);
		/* '@' and ':' are unsafe -> percent-encoded */
		ASSERT(k == stk && heap == 0, "typical key built on the stack (no malloc)");
		ASSERT(strcmp(k, "json_sip=3Aalice=40biloxi") == 0,
			"prefix + correct percent-encoding");
	}

	/* All-safe value. */
	{
		char *k = pk_target_key("abc-123_x", 9, stk, sizeof(stk), &heap);
		ASSERT(heap == 0 && strcmp(k, "json_abc-123_x") == 0,
			"all-safe value passes through verbatim");
	}

	/* Long value that overflows the stack buffer -> heap. */
	{
		char big[600]; int i;
		for (i = 0; i < 600; i++) big[i] = '@';   /* each encodes to 3 bytes */
		char *k = pk_target_key(big, 600, stk, sizeof(stk), &heap);
		ASSERT(heap == 1, "oversized key falls back to the heap");
		ASSERT((int)strlen(k) == 5 + 600 * 3, "heap key fully encoded");
		free(k);
	}

	/* Production wiring: the PK query path uses the stack-buffer helper. */
	{
		const char *json = "../cachedb_nats_json.c";
		ASSERT(file_contains(json, "_pk_target_key"),
			"json defines the stack-buffer PK key helper");
		/* the PK branch now lives in the _query_pk_fast_path helper
		 * extracted from nats_cache_query (the design notes decomposition) */
		ASSERT(grep_in_function(json, "_query_pk_fast_path", "_pk_target_key") >= 1,
			"PK query path uses the stack-buffer key build");
		ASSERT(grep_in_function(json, "_query_pk_fast_path", "pkg_malloc(plen + enc") == 0,
			"PK query path no longer pkg_mallocs the target key");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
