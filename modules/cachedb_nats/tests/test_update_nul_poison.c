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
 * Regression: the usrloc update/merge CAS path (cachedb_nats_json.c) fetched a
 * stored doc via kvEntry_ValueString + kvEntry_ValueLen (data_len), copied
 * data_len bytes, but then _update_apply_and_cas recomputed the length with
 * strlen(json_buf) -- discarding data_len.  A stored doc containing an embedded
 * NUL (a poison value from a hostile/foreign broker writer, or from the generic
 * *String set path) is truncated by strlen at the NUL: the single-pass merge
 * parses only the prefix, appends its own closing brace, and CAS-writes back a
 * structurally-valid but TRUNCATED document -- silently dropping every contact
 * after the NUL.  The read/query path already rejects a raw NUL via
 * _json_parse_guard; the update path did not.
 *
 * Fix: _update_fetch_or_seed fails closed when the fetched doc contains an
 * embedded NUL (strlen(json_buf) != data_len), so a poison doc is never merged
 * or laundered into a valid-looking short doc.
 *
 * Models the fetch length decision:
 *   -DSIMULATE_STRLEN_BUG -> measure with strlen -> truncated length returned.
 *   (default)             -> reject when strlen != data_len -> -1 (fail closed).
 * plus a source-wiring assertion.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_update_nul_poison \
 *       test_update_nul_poison.c
 */

#include <stdio.h>
#include <stdlib.h>
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
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Model of the fetch step: @data/@data_len is the broker-supplied doc
 * (data_len is the authoritative kvEntry_ValueLen).  Copies it NUL-terminated
 * and decides the length the merge will operate on.  Returns that length, or
 * -1 to reject (fail closed) a poison doc. */
static int fetch_doc_len(const char *data, int data_len)
{
	char *json_buf = malloc(data_len + 1);
	int rc;
	memcpy(json_buf, data, data_len);
	json_buf[data_len] = '\0';
#ifdef SIMULATE_STRLEN_BUG
	rc = (int)strlen(json_buf);          /* truncates at an embedded NUL */
#else
	if ((int)strlen(json_buf) != data_len)
		rc = -1;                         /* embedded NUL -> fail closed */
	else
		rc = (int)strlen(json_buf);
#endif
	free(json_buf);
	return rc;
}

int main(void)
{
	/* A clean doc: full length, accepted either way. */
	{
		const char clean[] = "{\"aor\":\"alice\"}";
		ASSERT(fetch_doc_len(clean, (int)sizeof(clean) - 1)
				== (int)sizeof(clean) - 1,
			"clean doc: full length preserved");
	}

	/* A poison doc with an embedded NUL between two contacts.  data_len
	 * spans the WHOLE doc; strlen would stop at the NUL and drop contact
	 * "b".  The fix rejects it (fail closed). */
	{
		const char poison[] =
			"{\"contacts\":{\"a\":1}\0,\"b\":2}";     /* NUL mid-doc */
		int data_len = (int)sizeof(poison) - 1;        /* includes bytes after NUL */
		int truncated = (int)strlen(poison);           /* prefix only */
		ASSERT(truncated < data_len, "poison doc: strlen prefix < full data_len");
		ASSERT(fetch_doc_len(poison, data_len) == -1,
			"poison doc with embedded NUL is REJECTED (not truncated/merged)");
	}

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../cachedb_nats_json.c";
		ASSERT(file_contains(src, "strlen(json_buf) != data_len"),
			"_update_fetch_or_seed fails closed on strlen(json_buf) != data_len");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
