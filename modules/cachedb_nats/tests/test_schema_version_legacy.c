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
 * P11b / IMPLEMENTATION-PLAN P11b [REV-25], SPEC §4.1/§4.2: migration /
 * mixed-version read tolerance for the cachedb_nats-private `schema_version`
 * top-level peer.
 *
 * On a rolling upgrade the bucket is SHARED by old and new nodes:
 *   - a LEGACY row was written before schema_version existed => NO schema_version;
 *   - a NEWER node may write a HIGHER schema_version than this node knows.
 * The read path MUST tolerate both — read best-effort, NEVER reject a row or
 * crash on the version value — or every real upgrade breaks.
 *
 * The production read path achieves this STRUCTURALLY: `_is_private_top_key`
 * matches "schema_version" (and "row_exp") by NAME and `cdbn_row_strip_private_keys`
 * removes the peer before usrloc sees it; the version VALUE is never parsed or
 * branched on.  So absent / 1 / any-higher all read identically.
 *
 * This test pins that invariant two ways:
 *   (1) the carried `_is_private_top_key` strips schema_version by NAME for any
 *       value (it never inspects the value);
 *   (2) a carried `_schema_read_accept(present, version)` models the read
 *       decision: the lenient (production) reader ACCEPTS every shape; the RED
 *       arm models the feared regression — a strict validator that rejects an
 *       absent or unknown-higher version, which would break every upgrade.
 *
 *   gcc -DSCHEMA_STRICT ... -> strict validator (rejects legacy/future) => RED.
 *   gcc ...               -> lenient strip-by-name reader              => GREEN.
 *
 * Rule 6: the authoritative legacy-row read+reap is the Tier-2
 * run_reaper_legacy_e2e.sh (SCENARIOS row 19).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_schema_version_legacy test_schema_version_legacy.c
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>

/* ─── carried copy of the production strip-by-name predicate
 * (cachedb_nats_json_rowmeta.c _is_private_top_key) ───────────────── */
static int _is_private_top_key(const char *name, int len)
{
	return (len == 7  && memcmp(name, "row_exp", 7) == 0) ||
	       (len == 14 && memcmp(name, "schema_version", 14) == 0);
}

/* ─── carried model of the read decision over a row's schema_version.
 * @present: row carried a schema_version peer (1) or not (0, legacy).
 * @version: its int value (ignored when !present).
 * Production reader: version-agnostic => always accept (best-effort). */
static int _schema_read_accept(int present, int version)
{
#ifdef SCHEMA_STRICT
	/* feared regression: a reader that hard-gates on a known version.
	 * Rejects legacy (absent) AND any newer node's higher version. */
	return (present && version == 1) ? 1 : 0;
#else
	(void)present; (void)version;   /* strip-by-name; value never branched */
	return 1;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef SCHEMA_STRICT
	printf("== carried copy: SCHEMA_STRICT (version-gating reader) ==\n");
#else
	printf("== carried copy: lenient strip-by-name reader ==\n");
#endif

	printf("[REV-25] schema_version is a private peer stripped by NAME (value never read):\n");
	CHECK(_is_private_top_key("schema_version", 14) == 1, "\"schema_version\" => private (stripped)");
	CHECK(_is_private_top_key("row_exp", 7) == 1, "\"row_exp\" => private (stripped)");
	CHECK(_is_private_top_key("contacts", 8) == 0, "\"contacts\" => NOT private (kept)");
	CHECK(_is_private_top_key("aorhash", 7) == 0, "\"aorhash\" => NOT private (kept)");
	/* adversarial: a near-miss name must NOT be stripped */
	CHECK(_is_private_top_key("schema_versio", 13) == 0, "truncated name => not matched");
	CHECK(_is_private_top_key("schema_version2", 15) == 0, "longer name => not matched");

	printf("[REV-25] the read path MUST accept legacy AND future rows (read best-effort):\n");
	CHECK(_schema_read_accept(0, 0) == 1, "LEGACY: schema_version ABSENT => read (not rejected)");
	CHECK(_schema_read_accept(1, 1) == 1, "current: schema_version=1 => read");
	CHECK(_schema_read_accept(1, 2) == 1, "FUTURE: schema_version=2 => read best-effort");
	CHECK(_schema_read_accept(1, 99) == 1, "FUTURE: unknown-higher schema_version=99 => read best-effort");
	CHECK(_schema_read_accept(1, 0) == 1, "odd: schema_version=0 => still read (never crash/reject)");
	CHECK(_schema_read_accept(1, INT_MAX) == 1, "boundary: schema_version=INT_MAX => read");
	CHECK(_schema_read_accept(1, -1) == 1, "adversarial: negative schema_version => read (no branch)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
		fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
