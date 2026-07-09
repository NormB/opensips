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
 * Dual-registration / state-machine skeleton test for the async
 * nats_request entry point.
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
 *   4. nats_rpc_async.c defines w_nats_request_async with the SHM
 *      slot + worker -> consumer IPC + timerfd-poll wiring.
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

	/* (2) cmds[] sync entry still carries the restrictive mask by
	 * default.  The table itself is NO LONGER const after option-B
	 * (the allow_sync_anywhere setter mutates flags in
	 * place); however the literal route mask in source must still
	 * exclude REQUEST_ROUTE / FAILURE_ROUTE / BRANCH_ROUTE so that
	 * the default behaviour is safe. */
	{
		const char *cmds = strstr(src, "cmd_export_t cmds[]");
		ASSERT(cmds != NULL, "located cmds[] block");
		ASSERT(strstr(src, "static const cmd_export_t cmds[]") == NULL,
			"cmds[] no longer declared const (option-B mutation site)");
		if (cmds) {
			const char *q = strstr(cmds, "\"nats_request\"");
			ASSERT(q != NULL, "cmds[] entry \"nats_request\" present");
			if (q) {
				size_t look = strlen(q);
				if (look > 700) look = 700;
				char snip[720];
				memcpy(snip, q, look);
				snip[look] = '\0';
				ASSERT(strstr(snip, "ALL_ROUTES") == NULL,
					"sync entry literal mask is not ALL_ROUTES "
					"(opt-in widens at runtime)");
				ASSERT(strstr(snip, "STARTUP_ROUTE") != NULL,
					"sync entry still includes STARTUP_ROUTE");
				ASSERT(strstr(snip, "TIMER_ROUTE") != NULL,
					"sync entry still includes TIMER_ROUTE");
				ASSERT(strstr(snip, "REQUEST_ROUTE") == NULL,
					"sync entry still excludes REQUEST_ROUTE by default");
			}
		}
	}

	/* (3) option-B opt-in: allow_sync_anywhere modparam +
	 * setter that widens cmds[].flags to ALL_ROUTES. */
	{
		ASSERT(strstr(src, "allow_sync_anywhere") != NULL,
			"params[] exposes allow_sync_anywhere");
		ASSERT(strstr(src, "nats_request_allow_sync_setter") != NULL,
			"setter callback nats_request_allow_sync_setter present");
		ASSERT(strstr(src, "USE_FUNC_PARAM") != NULL,
			"modparam registered with USE_FUNC_PARAM (setter callback)");
		ASSERT(strstr(src, "cmds[i].flags = ALL_ROUTES") != NULL,
			"setter widens nats_request entry to ALL_ROUTES on opt-in");
	}

	/* (3b) UUIDv7 correlation: $nats_request_id pvar +
	 * request_id_header modparam + default header name + the
	 * writable-pvar setter that routes NULL through the early-
	 * return clear path. */
	{
		ASSERT(strstr(src, "nats_request_id") != NULL,
			"$nats_request_id pvar registered in mod_pvars[]");
		ASSERT(strstr(src, "pv_get_nats_request_id") != NULL,
			"pvar getter pv_get_nats_request_id wired");
		ASSERT(strstr(src, "pv_set_nats_request_id") != NULL,
			"pvar setter pv_set_nats_request_id wired (writable)");
		ASSERT(strstr(src, "\"request_id_header\"") != NULL,
			"request_id_header modparam declared");
		ASSERT(strstr(src, "\"X-Request-Id\"") != NULL,
			"default header name is X-Request-Id");
	}

	/* (4) nats_rpc.h declares w_nats_request_async with the acmd shape */
	{
		ASSERT(strstr(hdr, "int w_nats_request_async(") != NULL,
			"header declares w_nats_request_async");
		ASSERT(strstr(hdr, "async_ctx *ctx") != NULL,
			"header takes async_ctx *");
		ASSERT(strstr(hdr, "#include \"../../async.h\"") != NULL,
			"header includes async.h");
	}

	/* (5) consumer-process-routed transport impl: SHM slot claim +
	 * worker -> consumer IPC enqueue + worker-private timerfd
	 * resume poll.  The hash table / subscription / on_inbox_reply
	 * code is still present in the source -- consumed by the
	 * consumer-side reply path. */
	{
		ASSERT(strstr(impl, "int w_nats_request_async(") != NULL,
			"impl defines w_nats_request_async");
		ASSERT(strstr(impl, "nats_rpc_async_uuidv7_mint") != NULL,
			"impl still mints per-call UUIDv7");
		ASSERT(strstr(impl, "nats_rpc_async_request_id_set") != NULL,
			"impl still stashes the request id for $nats_request_id");
		ASSERT(strstr(impl, "nats_rpc_slot_claim()") != NULL,
			"impl claims an SHM slot from the pool");
		ASSERT(strstr(impl, "nats_rpc_slot_publish") != NULL,
			"impl transitions slot CLAIMED -> INFLIGHT before IPC");
		ASSERT(strstr(impl, "ipc_send_rpc(ipc_dst, nats_rpc_ipc_on_publish") != NULL,
			"impl sends the packed slot/gen over core IPC to the "
			"consumer proc [P2.1]");
		ASSERT(strstr(impl, "nats_rpc_ipc_pack(slot->slot_idx") != NULL,
			"impl packs {slot_idx, generation} into the IPC param");
		ASSERT(strstr(impl, "timerfd_create") != NULL,
			"impl creates a worker-private timerfd for the resume "
			"poll");
		ASSERT(strstr(impl, "ctx->resume_f") != NULL &&
		       strstr(impl, "resume_nats_request_slot") != NULL,
			"impl wires resume_nats_request_slot on async_ctx");
		ASSERT(strstr(impl, "= tfd;") != NULL,
			"impl hands the timerfd to the reactor via async_status");
		/* The superseded per-worker inbox machine (hash table,
		 * on_inbox_reply, ensure_inbox_subscription) was DELETED
		 * in P1.1 -- assert it stays gone (running a libnats
		 * subscription on a SIP worker crashes libnats 3.x on
		 * aarch64; the slot transport replaced it). */
		ASSERT(strstr(impl, "static void on_inbox_reply") == NULL,
			"superseded on_inbox_reply stays deleted");
		ASSERT(strstr(impl, "static int ensure_inbox_subscription") == NULL,
			"superseded ensure_inbox_subscription stays deleted");
	}

	free(src); free(hdr); free(impl);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
