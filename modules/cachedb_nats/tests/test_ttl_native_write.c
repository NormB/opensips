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
 * Native per-key TTL row writes, gated on the kv_ttl_below_marker probe.
 *
 * P1.5a deleted the TTL-carrying write path because (a) TTLs were lost on
 * plain updates (nats-io #1994/#6959), (b) history-keeping buckets rolled
 * back to older revisions on expiry, and (c) the capability latch needed
 * its own probe layer.  All three are now solved: every row write goes
 * through the single CAS helper and re-asserts the TTL (§2.0), the fork
 * nats-server honors below-marker TTLs on History>1 buckets, and the
 * kv_ttl_below_marker modparam probe answers "is that server here?".
 * This test locks the resurrection:
 *
 *   - the pure helpers (carried copies below, matrix-tested):
 *     cdbn_ttl_eligible(row_exp, n_contacts, all_same): TTL only for a
 *       non-empty, non-permanent row whose contacts all share one expiry;
 *     cdbn_ttl_seconds(row_exp, now, grace): remaining life + physical slack;
 *     cdbn_ttl_msgttl_ms(secs): ms with the server's 1 s minimum floored so an
 *       already-expired row still self-expires (RC-6);
 *   - structural: the helpers live in cachedb_nats_expiry.c; the row-write
 *     helper gates on kv_ttl_below_marker + probe state SUPPORTED and
 *     derives the TTL; nats_kv_put_row carries it (CreateWithTTL on the
 *     create path, jsPubOptions.MsgTTL on the CAS path); the registration
 *     writer passes the row metadata (f_row_exp/f_n_contacts/f_all_same)
 *     and the reaper survivor-write passes its projection outputs;
 *   - the canary: when the probe latched SUPPORTED, the reaper proc writes
 *     a short-TTL canary key and verifies it actually died -- broker truth
 *     beats config truth; a surviving canary downgrades the pool latch
 *     (nats_pool_kv_ttl_below_marker_mark_broken) with a WARN and expiry
 *     falls back to reaper-only.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_native_write test_ttl_native_write.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

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

/* ─── carried copies of the pure helpers (cachedb_nats_expiry.c) ──── */
static int cdbn_ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry)
{
	if (n_contacts < 1)
		return 0;             /* empty row => no TTL */
	if (row_exp == 0)
		return 0;             /* a permanent contact => never auto-expire */
	return (n_contacts == 1) || all_same_expiry;
}

static int64_t cdbn_ttl_seconds(int64_t row_exp, int64_t now, int grace)
{
	return row_exp - now + (int64_t)grace;
}

static int64_t cdbn_ttl_msgttl_ms(int64_t ttl_seconds)
{
	int64_t ms;
	if (ttl_seconds <= 0)
		return 1000;
	if (ttl_seconds > 9223372036854775LL)
		ttl_seconds = 9223372036854775LL;
	ms = ttl_seconds * 1000;
	if (ms < 1000)
		ms = 1000;
	return ms;
}

int main(void)
{
	printf("== carried-copy helper matrix ==\n");
	CHECK(cdbn_ttl_eligible(0, 1, 1) == 0, "permanent row (row_exp 0): no TTL");
	CHECK(cdbn_ttl_eligible(100, 0, 1) == 0, "empty row: no TTL");
	CHECK(cdbn_ttl_eligible(100, 1, 0) == 1, "single contact: eligible");
	CHECK(cdbn_ttl_eligible(100, 3, 1) == 1, "uniform multi-contact: eligible");
	CHECK(cdbn_ttl_eligible(100, 3, 0) == 0,
		"mixed-expiry multi-contact: NO TTL (reaper handles it)");
	CHECK(cdbn_ttl_seconds(1000, 900, 5) == 105, "remaining life + slack");
	CHECK(cdbn_ttl_msgttl_ms(30) == 30000, "30 s => 30000 ms");
	CHECK(cdbn_ttl_msgttl_ms(1) == 1000, "1 s => 1000 ms");
	CHECK(cdbn_ttl_msgttl_ms(0) == 1000,
		"already expired at write: floored to 1 s, still self-expires");
	CHECK(cdbn_ttl_msgttl_ms(-50) == 1000, "long past expiry: floored to 1 s");

	printf("== structural: helpers + gate + TTL-carrying put ==\n");
	{
		char *src = slurp("../cachedb_nats_expiry.c");
		CHECK(src != NULL, "can read ../cachedb_nats_expiry.c");
		if (src) {
			CHECK(strstr(src, "int cdbn_ttl_eligible(") != NULL,
				"cdbn_ttl_eligible defined");
			CHECK(strstr(src, "int64_t cdbn_ttl_msgttl_ms(") != NULL,
				"cdbn_ttl_msgttl_ms defined");
			CHECK(strstr(src, "nats_pool_kv_ttl_below_marker_state() == 1")
					!= NULL,
				"row write gated on the probe latch");
			CHECK(strstr(src, "kv_ttl_below_marker") != NULL,
				"row write gated on the modparam");
			CHECK(strstr(src, "kvStore_CreateWithTTL") != NULL,
				"create path carries the TTL (CreateWithTTL)");
			CHECK(strstr(src, "o.MsgTTL") != NULL,
				"CAS path re-asserts the TTL (jsPubOptions.MsgTTL)");
			CHECK(strstr(src, "ttl_canary") != NULL,
				"canary machinery present");
			CHECK(strstr(src, "nats_pool_kv_ttl_below_marker_mark_broken")
					!= NULL,
				"surviving canary downgrades the pool latch");
			free(src);
		}
	}

	printf("== structural: callers pass the row metadata ==\n");
	{
		char *src = slurp("../cachedb_nats_json.c");
		CHECK(src != NULL, "can read ../cachedb_nats_json.c");
		if (src) {
			CHECK(strstr(src, "f_row_exp, f_n_contacts, f_all_same") != NULL,
				"registration writer passes row metadata");
			free(src);
		}
	}

	printf("== structural: dl table has the TTL create ==\n");
	{
		char *def = slurp("../../../lib/nats/nats_dl_table.def");
		CHECK(def != NULL, "can read nats_dl_table.def");
		if (def) {
			CHECK(strstr(def, "NATS_DL_FN(kvStore_CreateWithTTL)") != NULL,
				"kvStore_CreateWithTTL resolvable at runtime");
			free(def);
		}
	}

	printf("%s (%d failure(s))\n", fails ? "RED" : "GREEN", fails);
	return fails ? 1 : 0;
}
