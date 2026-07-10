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
 * [P3.5] Hot-path allocator policy: the JSON compose/serialize/rowmeta
 * TUs ran on raw libc malloc/free.  Every context that touches them is
 * a single-threaded OpenSIPS process (SIP worker main thread, the
 * dedicated watcher/reaper procs), so pkg is legal -- and unlike libc,
 * pkg is bounded by -M, visible to pkg stats / DBG_MALLOC, and stops
 * interleaving the per-REGISTER JSON churn with cnats's own heap
 * traffic on the same arena.
 *
 * Locked here (with comments/strings stripped before counting, since
 * the prose says "caller frees" everywhere):
 *
 *   - cachedb_nats_json.c, _json_ser.c, _json_rowmeta.c: zero bare
 *     malloc/realloc/calloc/free tokens (pkg_* / shm_* only),
 *   - the cross-TU consumers of their buffers follow the contract:
 *     expiry.c's reaper projection (proj/tmp/sink) and reg.c's
 *     cdbn_pk_target_key heap arm free with pkg_free.
 *
 * Out of scope (cold MI paths, self-contained libc pairs): kvobs.c
 * match arrays, reg.c's MI snapshot ctx/rows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Load a file with comments and string/char literals blanked out, so
 * token counting sees only code. */
static char *slurp_code(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf, *o;
	long n;
	long i;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	buf[n] = '\0';
	fclose(f);

	o = buf;
	for (i = 0; i < n; ) {
		if (buf[i] == '/' && i + 1 < n && buf[i+1] == '*') {
			while (i + 1 < n && !(buf[i] == '*' && buf[i+1] == '/')) {
				o[i] = ' '; i++;
			}
			if (i + 1 < n) { o[i] = ' '; o[i+1] = ' '; i += 2; }
		} else if (buf[i] == '/' && i + 1 < n && buf[i+1] == '/') {
			while (i < n && buf[i] != '\n') { o[i] = ' '; i++; }
		} else if (buf[i] == '"' || buf[i] == '\'') {
			char q = buf[i];
			o[i] = ' '; i++;
			while (i < n && buf[i] != q) {
				if (buf[i] == '\\' && i + 1 < n) { o[i] = ' '; i++; }
				o[i] = ' '; i++;
			}
			if (i < n) { o[i] = ' '; i++; }
		} else {
			i++;
		}
	}
	return buf;
}

/* Count bare `name(` tokens: not preceded by an identifier char (so
 * pkg_free / shm_free / scratch_free / test_shm_malloc don't match). */
static int bare_calls(const char *code, const char *name)
{
	int c = 0;
	size_t nl = strlen(name);
	const char *p = code;
	while ((p = strstr(p, name)) != NULL) {
		int pre_ok = (p == code) ||
			(!isalnum((unsigned char)p[-1]) && p[-1] != '_');
		if (pre_ok && p[nl] == '(')
			c++;
		p += nl;
	}
	return c;
}

static void check_tu_clean(const char *path, const char *label)
{
	char *code = slurp_code(path);
	char msg[160];
	if (!code) {
		snprintf(msg, sizeof(msg), "%s: readable", label);
		ASSERT(0, msg);
		return;
	}
	snprintf(msg, sizeof(msg), "%s: no bare malloc/calloc/realloc", label);
	ASSERT(bare_calls(code, "malloc") == 0 &&
	       bare_calls(code, "calloc") == 0 &&
	       bare_calls(code, "realloc") == 0, msg);
	snprintf(msg, sizeof(msg), "%s: no bare free", label);
	ASSERT(bare_calls(code, "free") == 0, msg);
	free(code);
}

int main(void)
{
	check_tu_clean("../cachedb_nats_json.c", "json TU");
	check_tu_clean("../cachedb_nats_json_ser.c", "json_ser TU");
	check_tu_clean("../cachedb_nats_json_rowmeta.c", "json_rowmeta TU");

	/* cross-TU consumers follow the pkg contract */
	{
		char *code = slurp_code("../cachedb_nats_expiry.c");
		ASSERT(code != NULL, "expiry TU readable");
		if (code) {
			ASSERT(bare_calls(code, "malloc") == 0 &&
			       bare_calls(code, "free") == 0,
				"expiry TU: reaper projection buffers are pkg");
			free(code);
		}
	}
	{
		char *code = slurp_code("../cachedb_nats_reg.c");
		ASSERT(code != NULL, "reg TU readable");
		if (code) {
			ASSERT(strstr(code, "pkg_free(key)") != NULL,
				"reg TU: cdbn_pk_target_key heap arm freed via pkg");
			free(code);
		}
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
