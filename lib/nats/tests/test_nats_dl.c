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
 */

/*
 * test_nats_dl.c -- Phase 1 unit test for the libnats function-
 * pointer table.
 *
 * Build:
 *   make -C lib/nats/tests test_nats_dl
 *
 * Run:
 *   ./lib/nats/tests/test_nats_dl
 *
 * Verifies:
 *   1. nats_dl_load(NULL) populates the table from the default search.
 *   2. nats_dl_is_loaded() reflects loaded state.
 *   3. nats_dl_path() returns a non-NULL diagnostic path.
 *   4. Indirect call through the table works (natsStatus_GetText is
 *      a pure libnats function with deterministic output, perfect
 *      for a smoke test that doesn't need a broker).
 *   5. nats_dl_unload() releases cleanly and is_loaded becomes false.
 *   6. nats_dl_load() is idempotent (second call returns 0 without
 *      reloading, table still populated).
 *   7. Explicit-path load works: nats_dl_load("libnats.so") explicitly.
 *   8. Bad path fails gracefully: nats_dl_load("/nonexistent/libnats")
 *      returns -1 and is_loaded stays false.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Stub the OpenSIPS log macros so this unit test can link without
 * pulling in the full core.  In a real OpenSIPS process the dprint
 * implementation comes from the binary; we don't have that here.
 */
#define LM_INFO(...)  fprintf(stderr, "[INFO] " __VA_ARGS__)
#define LM_ERR(...)   fprintf(stderr, "[ERR ] " __VA_ARGS__)
#define LM_WARN(...)  fprintf(stderr, "[WARN] " __VA_ARGS__)
#define LM_DBG(...)   ((void)0)

#include "../nats_dl.h"

static int g_fails;

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s (cond: %s)\n", msg, #cond); \
		g_fails++; \
	} else { \
		fprintf(stderr, "PASS: %s\n", msg); \
	} \
} while (0)

#define ASSERT_EQ_INT(a, b, msg) do { \
	int _a = (a), _b = (b); \
	if (_a != _b) { \
		fprintf(stderr, "FAIL: %s (got %d, want %d)\n", msg, _a, _b); \
		g_fails++; \
	} else { \
		fprintf(stderr, "PASS: %s\n", msg); \
	} \
} while (0)

#define ASSERT_NOT_NULL(ptr, msg) do { \
	if ((ptr) == NULL) { \
		fprintf(stderr, "FAIL: %s (got NULL)\n", msg); \
		g_fails++; \
	} else { \
		fprintf(stderr, "PASS: %s\n", msg); \
	} \
} while (0)

int main(void)
{
	const char *path;
	const char *txt;

	fprintf(stderr, "==== nats_dl unit test ====\n");

	/* Phase 1.1: pre-load state */
	ASSERT_TRUE(!nats_dl_is_loaded(), "is_loaded false before any load");
	ASSERT_TRUE(nats_dl_path() == NULL, "path NULL before any load");

	/* Phase 1.2: default-search load */
	ASSERT_EQ_INT(nats_dl_load(NULL), 0, "default search load succeeds");
	ASSERT_TRUE(nats_dl_is_loaded(), "is_loaded true after load");
	path = nats_dl_path();
	ASSERT_NOT_NULL(path, "path non-NULL after load");
	if (path)
		fprintf(stderr, "      loaded: '%s'\n", path);

	/* Phase 1.3: indirect call through the table — natsStatus_GetText
	 * is a pure function with deterministic output for known statuses.
	 * NATS_OK is always 0; its text is "OK". */
	ASSERT_NOT_NULL(nats_dl.natsStatus_GetText, "natsStatus_GetText pointer non-NULL");
	if (nats_dl.natsStatus_GetText) {
		txt = nats_dl.natsStatus_GetText(NATS_OK);
		ASSERT_NOT_NULL(txt, "natsStatus_GetText(NATS_OK) returns non-NULL");
		if (txt)
			ASSERT_TRUE(strcmp(txt, "OK") == 0, "natsStatus_GetText(NATS_OK) == 'OK'");
	}

	/* Phase 1.4: spot-check a few other expected pointers */
	ASSERT_NOT_NULL(nats_dl.natsConnection_Connect, "natsConnection_Connect populated");
	ASSERT_NOT_NULL(nats_dl.natsOptions_Create,     "natsOptions_Create populated");
	ASSERT_NOT_NULL(nats_dl.kvStore_Get,            "kvStore_Get populated");
	ASSERT_NOT_NULL(nats_dl.jsCtx_Destroy,          "jsCtx_Destroy populated");
	ASSERT_NOT_NULL(nats_dl.kvWatchOptions_Init,    "kvWatchOptions_Init populated");

	/* Phase 1.5: idempotent load */
	ASSERT_EQ_INT(nats_dl_load(NULL), 0, "second load is no-op (idempotent)");
	ASSERT_TRUE(nats_dl_is_loaded(), "still loaded after idempotent call");

	/* Phase 1.6: unload, then re-load with the same SONAME explicitly.
	 * Capturing the path before unload guarantees we pass a SONAME we
	 * know dlopen can find on this host (whatever the default search
	 * picked first time).  Hard-coding "libnats.so" would fail when
	 * /usr/local/lib isn't on the default ld.so search path; the
	 * dynamically discovered SONAME sidesteps that environment issue. */
	{
		char saved_path[256] = {0};
		if (path)
			snprintf(saved_path, sizeof(saved_path), "%s", path);
		nats_dl_unload();
		ASSERT_TRUE(!nats_dl_is_loaded(), "is_loaded false after unload");
		ASSERT_TRUE(nats_dl_path() == NULL, "path NULL after unload");

		ASSERT_EQ_INT(nats_dl_load(saved_path), 0,
		              "explicit-path load with the previously-discovered SONAME succeeds");
		ASSERT_TRUE(nats_dl_is_loaded(), "is_loaded true after explicit load");
		nats_dl_unload();
	}

	/* Phase 1.8: bad path fails closed */
	ASSERT_EQ_INT(nats_dl_load("/nonexistent/libnats.so.999"), -1,
	              "bad explicit path returns -1");
	ASSERT_TRUE(!nats_dl_is_loaded(), "is_loaded stays false after bad load");
	ASSERT_TRUE(nats_dl_path() == NULL, "path stays NULL after bad load");

	fprintf(stderr, "==== %s (failures: %d) ====\n",
	        g_fails == 0 ? "ALL PASS" : "SOME FAIL", g_fails);
	return g_fails == 0 ? 0 : 1;
}
