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
 * Registration MI enumeration [IMPROVEMENT Tier-2]: _reg_scan_bucket()
 * must enumerate via the shared value-carrying watch pass
 * (nats_kv_enum_live_values, the renamed reaper enumerator), NOT via
 * kvStore_Keys() + one kvStore_Get() per AoR.  The Keys+Get pattern
 * issues O(bucket) synchronous round trips; on the 30k-AoR bench it
 * dragged REGISTER p99/max from ~1 ms to 27-88 ms while a sweep
 * overlapped traffic -- and nats_reg_summary/list are exactly the
 * commands an operator runs mid-incident.
 *
 * Locks:
 *   1. production _reg_scan_bucket() body: calls the shared
 *      enumerator; contains NO kvStore_Keys / kvStore_Get,
 *   2. reg.c includes the shared enumerator header,
 *   3. the shared enumerator keeps IgnoreDeletes (live keys only --
 *      the Keys() parity the MI counters rely on),
 *   4. carried model of the per-entry glue: prefix filter -> keys
 *      counted after match only; empty value (defensive marker) keeps
 *      keys count but adds no row; malformed row -> other; good row ->
 *      rows/contacts totals; callback abort propagates.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reg_scan_enum
 *            test_reg_scan_enum.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, label) do { \
	if (cond) fprintf(stderr, "  ok: %s\n", (label)); \
	else { fprintf(stderr, "  FAIL: %s\n", (label)); g_fails++; } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	long n;
	char *buf;
	if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
	fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf || fread(buf, 1, n, f) != (size_t)n) exit(1);
	buf[n] = '\0';
	fclose(f);
	return buf;
}

/* drop /'*' ... '*'/ comments in place: the locks below assert on CALLS,
 * and an explanatory comment naming the replaced calls must not trip them */
static void strip_comments(char *s)
{
	char *c;
	while ((c = strstr(s, "/*")) != NULL) {
		char *e = strstr(c + 2, "*/");
		if (!e) { *c = '\0'; break; }
		memset(c, ' ', (size_t)(e + 2 - c));
	}
}

/* slice out one function body: from its definition line to the first
 * line that is exactly "}" */
static char *fn_body(const char *file, const char *def)
{
	char *s = slurp(file), *b, *e;
	strip_comments(s);
	b = strstr(s, def);
	if (!b) { free(s); return NULL; }
	e = strstr(b, "\n}");
	if (e) e[1] = '\0';
	return s;	/* caller frees; body starts at def within s */
}

/* ── carried model of the per-entry enumeration glue ─────────────── */

struct model_tot { long keys, rows, other; long contacts; };

/* mirrors the new _reg_enum_cb() decision ladder: prefix filter first
 * (uncounted on mismatch), key counted on match, empty value skipped
 * (defensive delete-marker parity), row parse -> rows/other. */
static int model_entry(const char *key, const char *val, int parse_ok,
	int n_contacts, const char *prefix, struct model_tot *t, int cb_rc)
{
	if (prefix && *prefix &&
	    strncmp(key, prefix, strlen(prefix)) != 0)
		return 0;
	t->keys++;
	if (!val || !*val)
		return 0;
	if (!parse_ok) { t->other++; return 0; }
	t->rows++;
	t->contacts += n_contacts;
	return cb_rc;	/* MI row callback verdict propagates */
}

int main(void)
{
	/* ---- production wiring locks -------------------------------- */
	{
		char *s = fn_body("../cachedb_nats_reg.c",
			"static int _reg_scan_bucket(");
		char *body = s ? strstr(s, "static int _reg_scan_bucket(") : NULL;
		ASSERT(body != NULL, "_reg_scan_bucket present");
		if (body) {
			ASSERT(strstr(body, "nats_kv_enum_live_values") != NULL,
				"scan uses the shared value-carrying enumerator");
			ASSERT(strstr(body, "kvStore_Keys") == NULL,
				"scan issues no kvStore_Keys");
			ASSERT(strstr(body, "kvStore_Get") == NULL,
				"scan issues no per-key kvStore_Get");
		}
		free(s);
	}
	{
		char *s = slurp("../cachedb_nats_reg.c");
		ASSERT(strstr(s, "cachedb_nats_reap_enum.h") != NULL,
			"reg.c includes the shared enumerator header");
		free(s);
	}
	{
		char *s = slurp("../cachedb_nats_reap_enum.c");
		ASSERT(strstr(s, "IgnoreDeletes = true") != NULL,
			"shared enumerator keeps live-keys-only parity");
		ASSERT(strstr(s, "nats_kv_enum_live_values") != NULL,
			"enumerator carries its shared (non-reaper) name");
		free(s);
	}

	/* ---- carried glue model ------------------------------------- */
	{
		struct model_tot t; memset(&t, 0, sizeof(t));
		int rc = 0;
		rc |= model_entry("usrloc.alice", "{...}", 1, 2, "usrloc.", &t, 0);
		rc |= model_entry("other.bob",    "{...}", 1, 1, "usrloc.", &t, 0);
		rc |= model_entry("usrloc.carol", "",      1, 0, "usrloc.", &t, 0);
		rc |= model_entry("usrloc.dave",  "junk",  0, 0, "usrloc.", &t, 0);
		ASSERT(rc == 0, "model pass completes");
		ASSERT(t.keys == 3, "prefix mismatch not counted; matches are");
		ASSERT(t.rows == 1 && t.contacts == 2, "one good row, contacts kept");
		ASSERT(t.other == 1, "malformed row counted as other");

		memset(&t, 0, sizeof(t));
		ASSERT(model_entry("usrloc.x", "{}", 1, 1, "usrloc.", &t, -1) == -1,
			"row-callback abort propagates out of the pass");

		/* no prefix configured: everything counts */
		memset(&t, 0, sizeof(t));
		model_entry("anything", "{}", 1, 1, "", &t, 0);
		ASSERT(t.keys == 1, "empty prefix filters nothing");
	}

	if (g_fails == 0) { fprintf(stderr, "=== ALL PASS ===\n"); return 0; }
	fprintf(stderr, "=== FAILS=%d ===\n", g_fails);
	return 1;
}
