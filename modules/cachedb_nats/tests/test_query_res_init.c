/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the broker-outage REGISTER segfault caught by
 * sip_e2e case 040_broker_bounce:
 *
 *   usrloc's cdb_load_urecord (modules/usrloc/udomain.c) declares a
 *   stack cdb_res_t WITHOUT initializing it and calls
 *   cdb_free_rows(&res) on ANY query failure.  The cachedb query()
 *   contract therefore requires the backend to cdb_res_init(res)
 *   BEFORE every failure return.  nats_cache_query's broker-down
 *   fast-fail (and the NULL-ncon guard) returned -1 before the init,
 *   so a REGISTER arriving during an outage made usrloc walk a
 *   garbage list head -> SIGSEGV in the SIP worker -> whole instance
 *   shutdown.
 *
 * Structural assertion: within nats_cache_query's body, the
 * cdb_res_init(res) call must appear BEFORE the fast-fail
 * (nats_con_refresh_kv) gate, and no `return -1` may sit between the
 * null-parameter guard and the init.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Slurp the body of a function (from its definition line to the first
 * line that is exactly "}"). */
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

int main(void)
{
	char *body = func_body("../cachedb_nats_json.c",
		"int nats_cache_query(cachedb_con *con");
	ASSERT(body != NULL, "found nats_cache_query body");
	if (!body) goto out;

	char *init = strstr(body, "cdb_res_init(res)");
	char *gate = strstr(body, "nats_con_refresh_kv");
	ASSERT(init != NULL, "nats_cache_query initializes the result set");
	ASSERT(gate != NULL, "nats_cache_query keeps the fast-fail gate");
	ASSERT(init && gate && init < gate,
		"cdb_res_init(res) runs BEFORE the broker-down fast-fail "
		"(usrloc cdb_free_rows()s the res on ANY failure)");

	/* No -1 return may occur between the null guard and the init:
	 * count `return -1` occurrences before the init -- exactly one is
	 * allowed (the !con || !res null-parameter guard, where res may
	 * itself be NULL and cannot be initialized). */
	if (init) {
		int early_fails = 0;
		char *p = body;
		while ((p = strstr(p, "return -1")) != NULL && p < init) {
			early_fails++;
			p++;
		}
		ASSERT(early_fails <= 1,
			"only the NULL-res guard may fail before cdb_res_init");
	}

	free(body);

	/* Same contract for the map_get surface (cachedb_nats_native.c):
	 * init before the fast-fail / NULL-ncon failure returns. */
	body = func_body("../cachedb_nats_native.c",
		"int nats_cache_map_get(cachedb_con *con");
	ASSERT(body != NULL, "found nats_cache_map_get body");
	if (body) {
		char *init2 = strstr(body, "cdb_res_init(res)");
		char *gate2 = strstr(body, "nats_con_refresh_kv");
		ASSERT(init2 && gate2 && init2 < gate2,
			"map_get: cdb_res_init(res) runs BEFORE the fast-fail gate");
		free(body);
	}
out:
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
