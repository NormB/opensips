/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Structural test: the reaper tick in cachedb_nats_expiry.c must
 * enumerate the bucket through nats_kv_enum_live_values() (one
 * value-carrying watch pass) and must NOT use the old
 * kvStore_Keys() + per-key kvStore_Get() pattern -- the O(bucket)
 * synchronous GET storm measured at 27-88 ms REGISTER p99/max
 * collateral on the 30k-AoR bench (2026-07-07).
 *
 * Also locks the house NULL-key guard (see test_watch_null_key_guard):
 * the per-entry callback reads kvEntry_Key() and must guard the NULL
 * return before using it.
 *
 * Build: gcc -g -O0 -Wall -o test_reap_enum_wiring test_reap_enum_wiring.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *slurp(const char *path)
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
	return buf;
}

/* count non-comment occurrences is overkill here: the old calls were
 * real code, and after the rewire only prose may mention them.  We
 * therefore match the call spelling `nats_dl.<fn>(` which cannot
 * appear in a comment in this codebase's style. */
static int count(const char *hay, const char *needle)
{
	int n = 0;
	const char *p = hay;
	while ((p = strstr(p, needle))) { n++; p += strlen(needle); }
	return n;
}

int main(void)
{
	char *src = slurp("../cachedb_nats_expiry.c");
	if (!src) { fprintf(stderr, "cannot read ../cachedb_nats_expiry.c\n"); return 1; }

	ASSERT(strstr(src, "#include \"cachedb_nats_reap_enum.h\"") != NULL,
		"expiry.c includes cachedb_nats_reap_enum.h");
	ASSERT(count(src, "nats_kv_enum_live_values(") >= 1,
		"reaper tick enumerates via nats_kv_enum_live_values()");
	ASSERT(count(src, "nats_dl.kvStore_Keys(") == 0,
		"no kvStore_Keys() enumeration left");
	/* The reap SWEEP must issue zero per-key Gets (the watch pass carries
	 * values).  The only allowed kvStore_Get in this TU is the TTL
	 * canary's single one-shot verdict read (_ttl_canary_check) -- one
	 * key, once per process lifetime, not O(bucket). */
	{
		int gets = count(src, "nats_dl.kvStore_Get(");
		const char *canary = strstr(src, "_ttl_canary_check");
		ASSERT(gets <= 1, "at most one kvStore_Get in the TU");
		if (gets == 1) {
			ASSERT(canary != NULL
			       && strstr(canary, "nats_dl.kvStore_Get(") != NULL,
				"the single kvStore_Get is the canary verdict read");
		} else {
			ASSERT(gets == 0,
				"no per-key kvStore_Get() left (zero GET storm)");
		}
	}
	ASSERT(count(src, "kvKeysList") == 0,
		"kvKeysList plumbing removed");

	/* NULL-key guard on the watch-pass callback (house rule: libnats
	 * may return NULL for a malformed / header-only entry). */
	{
		const char *site = strstr(src, "kvEntry_Key(");
		ASSERT(site != NULL, "callback reads the entry key");
		if (site) {
			char win[400];
			size_t n = strlen(site);
			if (n > sizeof(win) - 1) n = sizeof(win) - 1;
			memcpy(win, site, n); win[n] = '\0';
			ASSERT(strstr(win, "if (!key)") != NULL,
				"NULL-key guard within reach of kvEntry_Key()");
		}
	}

	free(src);
	fprintf(stderr, "%s (%d failure(s))\n", g_fails ? "RED" : "GREEN", g_fails);
	return g_fails ? 1 : 0;
}
