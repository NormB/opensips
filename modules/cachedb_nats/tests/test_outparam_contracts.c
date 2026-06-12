/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Out-param contract test (follow-up to the 040_broker_bounce fix):
 * a backend failure return must never leave a caller-owned out-param
 * in a state the caller's failure path cannot handle.
 *
 *   - raw_query(con, query, reply, expected_kv_no, reply_no): the
 *     dispatcher has many early -1 returns (bad query, oom, broker
 *     down).  Callers like core_cmds.c initialize num_rows themselves
 *     today, but the API contract does not require them to -- the
 *     backend must zero *reply and *reply_no at entry so every failure
 *     return leaves them deterministic.
 *
 *   - get(con, attr, val): on -1 callers must not free val->s (they
 *     check rc first), but a deterministic val = {NULL,0} at entry
 *     turns a caller bug from a garbage-pointer free into a clean
 *     NULL, and makes the miss (-2) / empty (0) paths uniform.
 *
 * Structural test: greps the production sources for the entry-point
 * initialization preceding the first failure-return.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *func_body(const char *path, const char *sig)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	char line[4096];
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int in = 0;
	while (fgets(line, sizeof(line), f)) {
		if (!in && strstr(line, sig)) in = 1;
		if (in) {
			size_t l = strlen(line);
			if (len + l + 1 > cap) {
				cap = (cap ? cap * 2 : 8192) + l;
				buf = realloc(buf, cap);
				if (!buf) { fclose(f); return NULL; }
			}
			memcpy(buf + len, line, l + 1);
			len += l;
			if (strcmp(line, "}\n") == 0 || strcmp(line, "}") == 0)
				break;
		}
	}
	fclose(f);
	return buf;
}

/* offset of first occurrence, or -1 */
static long pos_of(const char *body, const char *needle)
{
	const char *p = strstr(body, needle);
	return p ? (long)(p - body) : -1;
}

int main(void)
{
	char *body;

	/* --- raw_query dispatcher zeroes its out-params at entry --- */
	body = func_body("../cachedb_nats_native.c",
		"int nats_cache_raw_query_impl(cachedb_con *con");
	ASSERT(body != NULL, "found nats_cache_raw_query body");
	if (body) {
		long z_reply  = pos_of(body, "*reply = NULL");
		long z_n      = pos_of(body, "*reply_no = 0");
		long fail1    = pos_of(body, "return -1");
		ASSERT(z_reply >= 0, "raw_query NULLs *reply at entry");
		ASSERT(z_n >= 0, "raw_query zeroes *reply_no at entry");
		ASSERT(z_reply >= 0 && fail1 >= 0 && z_reply < fail1,
			"*reply = NULL precedes the first failure return");
		ASSERT(z_n >= 0 && fail1 >= 0 && z_n < fail1,
			"*reply_no = 0 precedes the first failure return");
		free(body);
	}

	/* --- get() leaves a deterministic val on every path --- */
	body = func_body("../cachedb_nats_dbase.c",
		"int nats_cache_get(cachedb_con *con");
	ASSERT(body != NULL, "found nats_cache_get body");
	if (body) {
		/* the NULL-val parameter guard legitimately precedes the
		 * zeroing (a NULL val cannot be zeroed); anchor on the first
		 * failure-return AFTER the parameter guard instead. */
		long z_val = pos_of(body, "val->s = NULL");
		long gate  = pos_of(body, "null NATS connection");
		ASSERT(z_val >= 0 && gate >= 0 && z_val < gate,
			"get() zeroes *val before any post-guard failure return");
		free(body);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
