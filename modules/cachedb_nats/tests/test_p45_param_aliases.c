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
 * [P4.5] Operator-facing naming convergence.  The same knob carried a
 * different name in each sibling module -- `reconnect_wait` here and
 * in event_nats vs `reconnect_wait_ms` in nats_consumer;
 * `nats_drain_timeout_ms` (event_nats) vs `cdb_drain_timeout_ms`
 * (cachedb_nats), which MERGE into one shared pool value, so the two
 * names were actively misleading.  And cachedb_nats prefixed five of
 * its own knobs with a redundant `nats_`
 * (modparam("cachedb_nats", "nats_cas_retries", ...)).
 *
 * Contract: one canonical name per knob, `_ms` unit suffix where the
 * unit is milliseconds, old names kept as working aliases (existing
 * configs keep loading).  Locked per module table:
 *
 *   canonical                 alias (kept)
 *   reconnect_wait_ms         reconnect_wait        (event, cachedb)
 *   drain_timeout_ms          nats_drain_timeout_ms (event)
 *   drain_timeout_ms          cdb_drain_timeout_ms  (cachedb)
 *   cas_retries               nats_cas_retries
 *   reap_grace                nats_reap_grace
 *   reap_interval             nats_reap_interval
 *   expired_linger            nats_expired_linger
 *   max_value_size            nats_max_value_size
 *
 * (`nats_url` keeps its name everywhere: it names NATS itself and is
 * the one shared spelling across all three modules.)
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
	fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
}

static void both(const char *src, const char *canon, const char *alias,
	const char *label)
{
	char msg[192], canon_q[96], alias_q[96];

	snprintf(canon_q, sizeof(canon_q), "\"%s\"", canon);
	snprintf(alias_q, sizeof(alias_q), "\"%s\"", alias);
	snprintf(msg, sizeof(msg), "%s: canonical %s registered", label, canon);
	ASSERT(src && strstr(src, canon_q) != NULL, msg);
	snprintf(msg, sizeof(msg), "%s: alias %s still accepted", label, alias);
	ASSERT(src && strstr(src, alias_q) != NULL, msg);
}

int main(void)
{
	char *cdb  = slurp("../cachedb_nats.c");
	char *ev   = slurp("../../event_nats/event_nats.c");
	char *cons = slurp("../../nats_consumer/nats_consumer.c");

	ASSERT(cdb && ev && cons, "all three module sources readable");
	if (!cdb || !ev || !cons)
		return 1;

	/* reconnect wait: _ms canonical everywhere */
	both(ev,  "reconnect_wait_ms", "reconnect_wait", "event_nats");
	both(cdb, "reconnect_wait_ms", "reconnect_wait", "cachedb_nats");
	ASSERT(strstr(cons, "\"reconnect_wait_ms\"") != NULL,
		"nats_consumer already carries the canonical name");

	/* drain timeout: one name for the ONE shared pool value */
	both(ev,  "drain_timeout_ms", "nats_drain_timeout_ms", "event_nats");
	both(cdb, "drain_timeout_ms", "cdb_drain_timeout_ms", "cachedb_nats");

	/* cachedb's redundant nats_ prefix dropped (aliases kept) */
	both(cdb, "cas_retries",    "nats_cas_retries",    "cachedb_nats");
	both(cdb, "reap_grace",     "nats_reap_grace",     "cachedb_nats");
	both(cdb, "reap_interval",  "nats_reap_interval",  "cachedb_nats");
	both(cdb, "expired_linger", "nats_expired_linger", "cachedb_nats");
	both(cdb, "max_value_size", "nats_max_value_size", "cachedb_nats");

	free(cdb); free(ev); free(cons);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
