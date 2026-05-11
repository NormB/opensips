/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 1 skeleton test for the async nats_request entry point.
 *
 * Verifies that the dual-registration plumbing is in place without
 * requiring a running broker or a libnats link:
 *   1. acmds[] in nats_consumer.c registers an entry named
 *      "nats_request" wired to w_nats_request_async.
 *   2. The sync entry in cmds[] still carries its restrictive route
 *      mask -- regression guard against accidentally widening sync
 *      access while adding the async surface.
 *   3. nats_rpc.h declares w_nats_request_async with the acmd
 *      signature (struct sip_msg *, async_ctx *, ...).
 *   4. nats_rpc_async.c defines w_nats_request_async, sets
 *      async_status = ASYNC_SYNC on the fall-through path, and falls
 *      through to the sync w_nats_request body.
 *
 * Source-pattern style, no link dependency on opensips core or
 * libnats; equivalent to test_request_route_restriction.c.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_async_request_skeleton test_async_request_skeleton.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *read_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	rewind(f);
	char *buf = malloc(sz + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

/* Locate the acmds[] block in nats_consumer.c.  We search forward
 * from a unique anchor ("static const acmd_export_t acmds[]") and
 * return a pointer into the source covering enough chars to span
 * every entry plus the sentinel. */
static const char *find_acmds_block(const char *src)
{
	const char *p = strstr(src, "static const acmd_export_t acmds[]");
	if (!p) return NULL;
	return p;
}

int main(void)
{
	char *src     = read_file("../nats_consumer.c");
	char *hdr     = read_file("../nats_rpc.h");
	char *impl    = read_file("../nats_rpc_async.c");

	ASSERT(src  != NULL, "open ../nats_consumer.c");
	ASSERT(hdr  != NULL, "open ../nats_rpc.h");
	ASSERT(impl != NULL, "open ../nats_rpc_async.c");
	if (!src || !hdr || !impl) {
		free(src); free(hdr); free(impl);
		return 1;
	}

	/* (1) acmds[] contains a "nats_request" -> w_nats_request_async entry */
	{
		const char *acmds = find_acmds_block(src);
		ASSERT(acmds != NULL, "located acmds[] block");
		if (acmds) {
			const char *q = strstr(acmds, "\"nats_request\"");
			ASSERT(q != NULL,
				"acmds[] entry \"nats_request\" present");
			if (q) {
				size_t look = strlen(q);
				if (look > 300) look = 300;
				char snip[320];
				memcpy(snip, q, look);
				snip[look] = '\0';
				ASSERT(strstr(snip, "w_nats_request_async") != NULL,
					"acmds[] nats_request wired to w_nats_request_async");
			}
		}
	}

	/* (2) cmds[] sync entry still carries the restrictive mask */
	{
		const char *cmds = strstr(src, "static const cmd_export_t cmds[]");
		ASSERT(cmds != NULL, "located cmds[] block");
		if (cmds) {
			const char *q = strstr(cmds, "\"nats_request\"");
			ASSERT(q != NULL, "cmds[] entry \"nats_request\" present");
			if (q) {
				size_t look = strlen(q);
				if (look > 600) look = 600;
				char snip[700];
				memcpy(snip, q, look);
				snip[look] = '\0';
				ASSERT(strstr(snip, "ALL_ROUTES") == NULL,
					"sync entry does not use ALL_ROUTES");
				ASSERT(strstr(snip, "STARTUP_ROUTE") != NULL,
					"sync entry still includes STARTUP_ROUTE");
				ASSERT(strstr(snip, "TIMER_ROUTE") != NULL,
					"sync entry still includes TIMER_ROUTE");
				ASSERT(strstr(snip, "REQUEST_ROUTE") == NULL,
					"sync entry still excludes REQUEST_ROUTE");
			}
		}
	}

	/* (3) nats_rpc.h declares w_nats_request_async with the acmd shape */
	{
		ASSERT(strstr(hdr, "int w_nats_request_async(") != NULL,
			"header declares w_nats_request_async");
		ASSERT(strstr(hdr, "async_ctx *ctx") != NULL,
			"header takes async_ctx *");
		ASSERT(strstr(hdr, "#include \"../../async.h\"") != NULL,
			"header includes async.h");
	}

	/* (4) phase-1 body: calls w_nats_request and sets ASYNC_SYNC */
	{
		ASSERT(strstr(impl, "int w_nats_request_async(") != NULL,
			"impl defines w_nats_request_async");
		ASSERT(strstr(impl, "w_nats_request(msg") != NULL,
			"impl delegates to w_nats_request (phase-1 fall-through)");
		ASSERT(strstr(impl, "ASYNC_SYNC") != NULL,
			"impl reports ASYNC_SYNC after sync completion");
	}

	free(src); free(hdr); free(impl);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
