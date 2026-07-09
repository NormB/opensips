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
 * [P4.1/P4.3/P4.7] lib/nats documentation truth-lock.  The README is
 * the subsystem's entry-point document and it TAUGHT WRONG BEHAVIOR:
 * a boxed claim that nats_consumer never registers with the pool (it
 * self-registers with a localhost fallback), "first registrant wins"
 * (the pool merges server lists), and a file table omitting the
 * entire dlopen shim.  The pool's callback doctrine likewise banned
 * shm_malloc from cnats threads while event_nats ships exactly that
 * pattern (shm + ipc_dispatch_rpc), and two comments described
 * cross-process invariants their per-process statics cannot provide.
 *
 * Docs drift silently; these pattern checks pin the corrected claims
 * to the source of truth.
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

int main(void)
{
	char *readme = slurp("../README.md");
	char *pool   = slurp("../nats_pool.c");

	ASSERT(readme && pool, "README.md + nats_pool.c readable");
	if (!readme || !pool)
		return 1;

	/* ── P4.1: the README no longer teaches wrong behavior ──────── */
	ASSERT(strstr(readme, "does NOT call nats_pool_register") == NULL,
		"false standalone-consumer claim is gone");
	ASSERT(strstr(readme, "first registrant wins") == NULL &&
	       strstr(readme, "The first registrant wins") == NULL,
		"false first-registrant-wins claim is gone");
	ASSERT(strstr(readme, "merge") != NULL,
		"README documents the merge-union registration semantics");
	ASSERT(strstr(readme, "self-register") != NULL,
		"README states every module (incl. nats_consumer) self-registers");
	ASSERT(strstr(readme, "nats_dl.c") != NULL &&
	       strstr(readme, "nats_ca_dir.c") != NULL &&
	       strstr(readme, "nats_str.h") != NULL &&
	       strstr(readme, "nats_epoch.h") != NULL &&
	       strstr(readme, "nats_rl.h") != NULL,
		"file table covers the dlopen shim + helper headers");
	ASSERT(strstr(readme, "nats_pool_register(const char *url, "
			"const char *module") != NULL,
		"README shows the real nats_pool_register signature");

	/* ── P4.7: the allocator & string policy lives in the README ── */
	ASSERT(strstr(readme, "Allocator policy") != NULL ||
	       strstr(readme, "allocator policy") != NULL,
		"README carries the allocator policy section");
	ASSERT(strstr(readme, "ipc_dispatch_rpc") != NULL,
		"policy names the foreign-thread handoff pattern");

	/* ── P4.3: the pool doctrine sanctions shm + ipc from callbacks ── */
	{
		const char *doc = strstr(pool, "nats.c callbacks (run on nats.c");
		ASSERT(doc != NULL, "found the callback doctrine block");
		if (doc) {
			char head[4000];
			size_t n = strlen(doc) < sizeof(head) - 1
				? strlen(doc) : sizeof(head) - 1;
			memcpy(head, doc, n);
			head[n] = '\0';
			ASSERT(strstr(head, "ipc_dispatch_rpc") != NULL,
				"doctrine sanctions shm_malloc + ipc_dispatch_rpc");
			ASSERT(strstr(head, "DBG_MALLOC") != NULL,
				"doctrine carries the DBG_MALLOC/SHM_EXTRA_STATS caveat");
			ASSERT(strstr(head, "shm_malloc, shm_free") == NULL,
				"shm_* no longer listed as will-crash");
		}
	}

	/* ── P4.3: the stale cross-process claims are gone ──────────── */
	ASSERT(strstr(pool, "rewrite tls:// URLs to nats://") == NULL,
		"pool_cfg comment no longer describes the removed URL rewrite");
	ASSERT(strstr(pool, "the first child process") == NULL,
		"_tls_probed comment no longer claims a cross-process guard");

	free(readme);
	free(pool);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
