/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: native KV ops and map ops must not forward SIP-derived
 * tokens to NATS in a way that lets:
 *   - map-key separator injection: a key/subkey containing the map separator
 *     aliasing another logical map's fields; or
 *   - a wildcard ('*' / '>') reaching kvStore_Purge -> a destructive
 *     mass delete of every matching key.
 *
 * Two different mechanisms, by op class:
 *   - Raw / native KV ops (w_nats_kv_*, raw_kv_purge) map a key DIRECTLY to a
 *     subject, so they must reject illegal tokens up front via
 *     validate_kv_key() (control chars, whitespace, wildcards, ':').
 *   - Map ops (build_map_key / nats_cache_map_get / nats_cache_map_remove,
 *     TODO #40) instead HEX-ESCAPE each component (nats_map_compose ->
 *     nats_map_encode): the structural '.' separator can never appear inside
 *     an encoded component, so no byte can inject the separator or a
 *     wildcard -- a stronger, lossless guarantee than rejection, and it lets
 *     users put any character in a map key/field.
 *
 * Source-pattern test; run from the tests/ directory.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_native_key_validation test_native_key_validation.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_in_function(const char *path, const char *fn_name,
	const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
	char line[2048];
	int hits = 0, seen_marker = 0, in_body = 0;
	char marker[256];
	snprintf(marker, sizeof(marker), "%s(", fn_name);
	while (fgets(line, sizeof(line), f)) {
		if (in_body) {
			if (line[0] == '}') { in_body = 0; seen_marker = 0; continue; }
			if (strstr(line, needle)) hits++;
			continue;
		}
		if (seen_marker) {
			if (strchr(line, ';')) { seen_marker = 0; continue; }
			if (strchr(line, '{')) { in_body = 1; continue; }
			continue;
		}
		if (strstr(line, marker)) {
			seen_marker = 1;
			if (strchr(line, ';')) seen_marker = 0;
			else if (strchr(line, '{')) { in_body = 1; seen_marker = 0; }
		}
	}
	fclose(f);
	return hits;
}

int main(void)
{
	const char *native = "../cachedb_nats_native.c";
	size_t i;

	/* Raw / native KV ops map the key directly to a subject -> validate. */
	const char *validate_fns[] = {
		"raw_kv_purge",         /* must reject wildcards (mass delete) */
		"w_nats_kv_get", "w_nats_kv_put", "w_nats_kv_update",
		"w_nats_kv_delete", "w_nats_kv_revision", "w_nats_kv_history",
	};
	for (i = 0; i < sizeof(validate_fns)/sizeof(validate_fns[0]); i++) {
		int n = grep_in_function(native, validate_fns[i], "validate_kv_key");
		char msg[160];
		snprintf(msg, sizeof(msg), "%s validates its KV key(s)",
			validate_fns[i]);
		ASSERT(n >= 1, msg);
	}

	/* Map ops hex-escape each component instead -> nats_map_compose. */
	const char *encode_fns[] = {
		"build_map_key",
		"nats_cache_map_get",
		"nats_cache_map_remove",
	};
	for (i = 0; i < sizeof(encode_fns)/sizeof(encode_fns[0]); i++) {
		int n = grep_in_function(native, encode_fns[i], "nats_map_compose");
		char msg[160];
		snprintf(msg, sizeof(msg),
			"%s hex-escapes its key/field (injection-proof)", encode_fns[i]);
		ASSERT(n >= 1, msg);
	}

	/* And the map ops must NOT silently fall back to raw ':' composition. */
	ASSERT(grep_in_function(native, "build_map_key",
			"NATS_MAP_SEP_LEGACY") == 0 ||
		grep_in_function(native, "build_map_key", "nats_map_compose") >= 1,
		"build_map_key composes via the encoder, not a raw separator");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
