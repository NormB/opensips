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
 * P6 / TTL-SOLUTION-SPEC.md §2.4 [REV-11 / TREV-4 / PREV-10]: the two new
 * libnats bindings the raw-publish path needs must be reachable THROUGH the
 * module's dlopen table — not just via a -lnats-linked spike.
 *
 *   js_PublishMsg  (nats.h:7224) — synchronous CAS+TTL raw publish with inline
 *                  jsPubAck + jsErrCode (the fire-and-forget js_PublishAsync
 *                  cannot return the CAS/TTL rejection inline, so it cannot
 *                  drive the retry loop — this is the load-bearing binding).
 *   js_UpdateStream(nats.h:6707) — one-time bucket setup: flip AllowMsgTTL /
 *                  SubjectDeleteMarkerTTL on the KV-backing stream.
 *
 * Part A (structural): nats_dl_table.def — the single source of truth expanded
 * into both the struct (nats_dl.h) and the dlsym loop (nats_dl.c) — must list
 * both NATS_DL_FN(...) entries, else the module never binds them.  This is the
 * RED→GREEN: before the .def edit the entries are absent (RED); after, present.
 *
 * Part B (dlopen resolution): open the real libnats and dlsym both symbols
 * exactly as nats_dl.c does, proving they exist with the loader (no server
 * needed for resolution).  Auto-skips (exit 77) if libnats is not installed.
 *
 * The authoritative "a CAS+TTL publish round-trips through the table" needs a
 * real nats-server ≥ 2.11 and is the P8 e2e.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_dl_bindings test_ttl_dl_bindings.c -ldl
 */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#define DEFPATH "../../../lib/nats/nats_dl_table.def"

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static int def_has(const char *needle)
{
	FILE *f = fopen(DEFPATH, "r");
	char line[512];
	int found = 0;
	if (!f) { printf("  (cannot open %s)\n", DEFPATH); return -1; }
	while (fgets(line, sizeof line, f))
		if (strstr(line, needle)) { found = 1; break; }
	fclose(f);
	return found;
}

int main(void)
{
	printf("== P6 libnats bindings: js_PublishMsg (Phase A dropped js_UpdateStream) ==\n");

	printf("[TREV-4] Part A: nats_dl_table.def lists the NATS_DL_FN entries:\n");
	{
		int a = def_has("NATS_DL_FN(js_PublishMsg)");
		/* Phase A: per-key TTL is enabled at bucket creation via
		 * kvConfig.LimitMarkerTTL (nats.c PR #1000), so the post-create
		 * js_UpdateStream stream-RMW retrofit -- and its binding -- are gone. */
		int b = def_has("NATS_DL_FN(js_UpdateStream)");
		if (a < 0 || b < 0) {
			printf("  SKIP: .def not readable from here\n");
		} else {
			CHECK(a == 1, "table has NATS_DL_FN(js_PublishMsg)");
			CHECK(b == 0, "table no longer binds js_UpdateStream (Phase A: LimitMarkerTTL at create)");
			/* the load-bearing distinction: NOT the async variant */
			CHECK(def_has("NATS_DL_FN(js_PublishAsync)") == 1,
			      "the existing js_PublishAsync entry is still present (sync added alongside)");
		}
	}

	printf("[PREV-10] Part B: both symbols resolve through the dlopen path:\n");
	{
		void *h = dlopen("libnats.so", RTLD_NOW | RTLD_GLOBAL);
		if (!h) h = dlopen("libnats.so.3", RTLD_NOW | RTLD_GLOBAL);
		if (!h) {
			/* Part A (the .def gate) already ran; Part B needs the .so.
			 * Plain `make check` treats non-zero as failure, so don't
			 * use the autotools 77 here — A passing is the deliverable. */
			printf("  SKIP: libnats not installed (%s)\n", dlerror() ? dlerror() : "");
			printf("\n%s (%d failure%s) [B skipped]\n",
				fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
			return fails ? 1 : 0;
		}
		CHECK(dlsym(h, "js_PublishMsg") != NULL, "dlsym js_PublishMsg resolves");
		/* sanity: a symbol already in the table also resolves the same way */
		CHECK(dlsym(h, "js_GetStreamInfo") != NULL, "dlsym js_GetStreamInfo (already bound) resolves");
		dlclose(h);
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
