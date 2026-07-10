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
 * Regression guards for two lib/nats memory-safety fixes whose failure
 * paths are not deterministically reproducible from a unit test (an
 * internal stat/read TOCTOU, and a >16-distinct-bucket runtime state):
 *
 *   1. nats_ca_dir.c -- the read pass must bound every fread to the
 *      budget computed in the sizing pass, so a .pem that grows between
 *      the two stat() calls cannot overflow the concat buffer.
 *   2. nats_pool.c::nats_pool_get_kv -- when the per-process KV handle
 *      cache is full it must destroy the freshly-created handle and
 *      return NULL, NOT hand back an uncached handle that leaks on every
 *      subsequent call (callers never kvStore_Destroy()).
 *   3. nats_pool.c -- GetConnectedUrl call sites must init the buffer so
 *      a non-OK status can't leave nats_redact_url() reading uninit
 *      stack.
 *
 * Source-structure assertions (function-scoped) against the production
 * source.  Behavioural / no-regression coverage for nats_ca_dir is
 * provided by the ASan-built test_nats_ca_dir.
 *
 * Self-contained; run from the tests/ directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *extract_func_body(const char *path, const char *funcname)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[n] = '\0';

	char *p = buf, *body = NULL;
	size_t flen = strlen(funcname);
	while ((p = strstr(p, funcname)) != NULL) {
		char *q = p + flen;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '(') { p += flen; continue; }
		char *brace = q;
		while (*brace && *brace != '{' && *brace != ';') brace++;
		if (*brace != '{') { p += flen; continue; }
		int depth = 0; char *s = brace;
		for (; *s; s++) {
			if (*s == '{') depth++;
			else if (*s == '}') { depth--; if (depth == 0) { s++; break; } }
		}
		size_t blen = (size_t)(s - brace);
		body = malloc(blen + 1);
		if (body) { memcpy(body, brace, blen); body[blen] = '\0'; }
		break;
	}
	free(buf);
	return body;
}

int main(void)
{
	char *body;

	/* 1. ca_dir: bounded read */
	body = extract_func_body("../nats_ca_dir.c", "nats_load_ca_directory");
	ASSERT(body != NULL, "found nats_load_ca_directory body");
	if (body) {
		ASSERT(strstr(body, "fread(p, 1, st.st_size, f)") == NULL,
			"ca_dir no longer freads the raw (TOCTOU) stat size");
		ASSERT(strstr(body, "budget") != NULL,
			"ca_dir bounds the read to the sizing-pass budget");
		free(body);
	}

	/* 2. nats_pool_get_kv: cache-full must destroy + return NULL */
	body = extract_func_body("../nats_pool.c", "nats_pool_get_kv");
	ASSERT(body != NULL, "found nats_pool_get_kv body");
	if (body) {
		ASSERT(strstr(body, "will not be cached") == NULL,
			"kvStore cache-full no longer returns an uncached (leaking) handle");
		ASSERT(strstr(body, "kvStore_Destroy(kv)") != NULL,
			"kvStore cache-full destroys the freshly-created handle");
		free(body);
	}

	/* 3. GetConnectedUrl buffer init */
	body = extract_func_body("../nats_pool.c", "pool_reconnected_cb");
	ASSERT(body != NULL, "found pool_reconnected_cb body");
	if (body) {
		ASSERT(strstr(body, "url[0] = '\\0'") != NULL,
			"reconnect cb inits url before GetConnectedUrl");
		free(body);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
