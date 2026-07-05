/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.6] Config constants are strlen()'d once, at mod_init -- not per
 * REGISTER.  fts_json_prefix was measured on every usrloc read, write
 * and watch event (kilobyte-scale traffic multiplies the waste);
 * fts_json_prefix_len is computed by mod_init next to the modparam
 * and the hot TUs consume the cached value.
 *
 * Structural test (source patterns).
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
	FILE *f = fopen(path, "r");
	char *buf;
	long n;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		fclose(f); free(buf); return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
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
	char *mod   = slurp("../cachedb_nats.c");
	char *js    = slurp("../cachedb_nats_json.c");
	char *ser   = slurp("../cachedb_nats_json_ser.c");
	char *watch = slurp("../cachedb_nats_watch.c");

	ASSERT(mod && js && ser && watch, "production sources readable");
	if (!mod || !js || !ser || !watch)
		return 1;

	ASSERT(count(mod, "fts_json_prefix_len") >= 2,
		"cachedb_nats.c defines + stamps fts_json_prefix_len at init");
	ASSERT(count(js, "strlen(fts_json_prefix)") == 0,
		"json TU no longer strlen()s the prefix per operation");
	ASSERT(count(ser, "strlen(fts_json_prefix)") == 0,
		"json_ser TU no longer strlen()s the prefix per operation");
	ASSERT(count(watch, "strlen(fts_json_prefix)") == 0,
		"watch TU no longer strlen()s the prefix per event");
	ASSERT(count(js, "fts_json_prefix_len") >= 1,
		"json TU consumes the cached length");

	free(mod); free(js); free(ser); free(watch);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
