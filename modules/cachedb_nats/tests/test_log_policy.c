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
 * [P3.7] Outage / hot-path logging policy, cachedb_nats side:
 *
 *   - a broker outage must be VISIBLE: the KV-op disconnect fast-fail
 *     (13 sites, all DBG -- invisible in production) gains ONE shared
 *     rate-limited WARN helper (nats_cdb_disconnected_warn, gated by
 *     lib/nats nats_rl_pass) used by both the dbase refresh choke
 *     point and the native kv_* entry guards,
 *
 *   - the primary usrloc write path must not fail silently: a
 *     nats_kv_put_row CAS-publish failure logs the libnats status
 *     text + jsErrCode + bucket/key (previously zero diagnostics),
 *
 *   - the watcher's per-expiry MaxAge-tombstone line moves INFO ->
 *     DBG: at scale it fires once per expired registration on the
 *     watcher hot path (its sibling delete/purge branch was already
 *     DBG "to avoid log spam"),
 *
 *   - the kv_history 8 KB truncation is no longer silent: the caller
 *     gets a rate-limited WARN when the JSON was clamped.
 *
 * Structural test (source patterns), mirroring the suite's other
 * policy locks.
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

static int contains(const char *buf, const char *needle)
{
	return buf && strstr(buf, needle) != NULL;
}

int main(void)
{
	char *dbase  = slurp("../cachedb_nats_dbase.c");
	char *native = slurp("../cachedb_nats_native.c");
	char *expiry = slurp("../cachedb_nats_expiry.c");
	char *watch  = slurp("../cachedb_nats_watch.c");

	ASSERT(dbase && native && expiry && watch, "production sources readable");
	if (!dbase || !native || !expiry || !watch)
		return 1;

	/* ── shared rate-limited disconnect WARN ─────────────────── */
	ASSERT(contains(dbase, "void nats_cdb_disconnected_warn"),
		"dbase defines the shared disconnect-warn helper");
	ASSERT(contains(dbase, "nats_rl_pass("),
		"the helper is gated by nats_rl_pass (rate-limited)");
	ASSERT(contains(native, "nats_cdb_disconnected_warn("),
		"native kv_* guards call the shared helper");

	/* ── usrloc row-write failures carry libnats detail ──────── */
	{
		const char *fn = strstr(expiry, "enum ttl_outcome nats_kv_put_row(");
		ASSERT(fn != NULL, "found nats_kv_put_row");
		if (fn) {
			const char *end = strstr(fn, "\n}\n");
			size_t len = end ? (size_t)(end - fn) : strlen(fn);
			char *body = malloc(len + 1);
			memcpy(body, fn, len);
			body[len] = '\0';
			ASSERT(contains(body, "natsStatus_GetText"),
				"put_row failure logs the libnats status text");
			ASSERT(contains(body, "jsErrCode") &&
			       contains(body, "LM_ERR("),
				"put_row failure LM_ERRs with the jsErrCode");
			free(body);
		}
	}

	/* ── watcher tombstone line demoted to DBG ───────────────── */
	ASSERT(!contains(watch, "LM_INFO(\"watcher: MaxAge tombstone"),
		"per-expiry tombstone line is no longer INFO");
	ASSERT(contains(watch, "LM_DBG(\"watcher: MaxAge tombstone"),
		"per-expiry tombstone line is DBG (hot path)");

	/* ── kv_history truncation is not silent ─────────────────── */
	ASSERT(contains(native, "truncated") &&
	       contains(native, "NATS_HISTORY_BUF"),
		"kv_history knows its truncation bound");
	{
		const char *fn = strstr(native, "int w_nats_kv_history(");
		ASSERT(fn != NULL, "found w_nats_kv_history");
		if (fn) {
			ASSERT(strstr(fn, "nats_rl_pass(") != NULL,
				"kv_history truncation WARN is rate-limited");
		}
	}

	free(dbase); free(native); free(expiry); free(watch);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
