/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for TODO #40 migration: nats_map_migrate rewrites legacy
 * ':' separated map keys into the new '.' separated hex-escaped format.
 *
 * Invariants under test (carried model):
 *   - a key is "legacy" iff it contains ':' (validate_kv_key forbids ':' in
 *     non-map keys, so any ':' key is a legacy map entry);
 *   - the split is on the FIRST ':' -> map-key + field (field keeps any
 *     further ':' as data, which the encoder escapes);
 *   - the migrated key contains NO raw ':' (the encoder escapes it), so a
 *     second migration pass is a no-op -> idempotent.
 *
 * Plus source-pattern assertions on the production handler + registration.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_map_migrate test_map_migrate.c
 */

#include <stdio.h>
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

/* ─── carried model of the migration rewrite ──────────────────── */

static int _safe(unsigned char c)
{
	if ((c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z')) return 1;
	switch (c) { case '-': case '_': case '/': case '\\': return 1; }
	return 0;
}
static void enc(const char *in, int n, char *out)
{
	static const char hx[] = "0123456789ABCDEF";
	int i, p = 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];
		if (_safe(c)) out[p++] = (char)c;
		else { out[p++]='='; out[p++]=hx[c>>4]; out[p++]=hx[c&15]; }
	}
	out[p] = '\0';
}

/* returns 1 and writes the migrated key if @k is legacy; 0 otherwise. */
static int migrate_one(const char *k, char *out)
{
	const char *colon = strchr(k, ':');
	char ek[256], ef[256];
	if (!colon)
		return 0;                       /* not a legacy map key */
	enc(k, (int)(colon - k), ek);       /* map-key (before first ':') */
	enc(colon + 1, (int)strlen(colon + 1), ef);  /* field (after) */
	sprintf(out, "%s.%s", ek, ef);
	return 1;
}

int main(void)
{
	char out[512];

	/* ---- model: which keys migrate, and to what ---------------- */
	{
		ASSERT(migrate_one("m:f", out) == 1 && strcmp(out, "m.f") == 0,
			"simple 'm:f' -> 'm.f'");
		ASSERT(migrate_one("m:s:f", out) == 1 && strcmp(out, "m.s=3Af") == 0,
			"'m:s:f' splits on first ':' -> 'm.s=3Af'");
		ASSERT(migrate_one("json_user@host", out) == 0,
			"non-map key (no ':') is not migrated");
		ASSERT(migrate_one("plain", out) == 0,
			"plain key is not migrated");
	}

	/* ---- model: idempotency (a migrated key never re-migrates) -- */
	{
		const char *legacy[] = { "m:f", "m:s:f", "a.b:c", "x:y:z:w" };
		int i, ok = 1;
		for (i = 0; i < 4; i++) {
			char once[512], twice[512];
			if (!migrate_one(legacy[i], once)) { ok = 0; break; }
			/* migrated key has no raw ':' so the second pass is a no-op */
			if (strchr(once, ':')) { ok = 0; break; }
			if (migrate_one(once, twice) != 0) { ok = 0; break; }
		}
		ASSERT(ok, "migrated keys carry no ':' and never re-migrate (idempotent)");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *n = "../cachedb_nats_native.c";
		ASSERT(file_contains(n, "mi_nats_map_migrate"),
			"native defines mi_nats_map_migrate");
		ASSERT(file_contains(n, "strchr(k, NATS_MAP_SEP_LEGACY)"),
			"migrate splits legacy keys on the legacy ':' separator");
		ASSERT(file_contains(n, "nats_map_compose(newkey"),
			"migrate recomposes via the hex-escaping encoder");
		ASSERT(file_contains("../cachedb_nats.c", "\"nats_map_migrate\""),
			"nats_map_migrate MI command registered");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
