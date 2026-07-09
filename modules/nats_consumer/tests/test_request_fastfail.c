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
 * Broker-down fast-fail test for the RPC request paths:
 *
 *   - SYNC w_nats_request: natsConnection_RequestMsg on an
 *     already-disconnected pool cannot succeed -- cnats buffers the
 *     publish and the call blocks the OpenSIPS process (timer/event
 *     route!) for the FULL caller timeout before returning.  The
 *     function must check nats_pool_is_connected() and fail fast
 *     BEFORE the blocking call.
 *
 *   - ASYNC w_nats_request_async: submitting while disconnected
 *     claims an RPC slot that is guaranteed to burn its entire
 *     timeout (the IPC publish lands on a dead connection), wasting
 *     a slice of the bounded slot pool per call during an outage.
 *     The submit path must fail fast BEFORE claiming the slot.
 *
 * Structural test: in each function the connectivity check must
 * precede the blocking call / slot claim.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *func_body(const char *path, const char *sig)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	char line[4096];
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int in = 0;
	while (fgets(line, sizeof(line), f)) {
		if (!in && strstr(line, sig)) in = 1;
		if (in) {
			size_t l = strlen(line);
			if (len + l + 1 > cap) {
				cap = (cap ? cap * 2 : 8192) + l;
				buf = realloc(buf, cap);
				if (!buf) { fclose(f); return NULL; }
			}
			memcpy(buf + len, line, l + 1);
			len += l;
			if (strcmp(line, "}\n") == 0 || strcmp(line, "}") == 0)
				break;
		}
	}
	fclose(f);
	return buf;
}

static long pos_of(const char *body, const char *needle)
{
	const char *p = strstr(body, needle);
	return p ? (long)(p - body) : -1;
}

int main(void)
{
	char *body;

	/* --- sync request: fast-fail before the blocking RequestMsg --- */
	body = func_body("../nats_rpc.c",
		"int w_nats_request(struct sip_msg *msg");
	ASSERT(body != NULL, "found w_nats_request body");
	if (body) {
		long chk = pos_of(body, "nats_pool_is_connected()");
		long blk = pos_of(body, "nats_dl.natsConnection_RequestMsg(");
		ASSERT(chk >= 0, "sync request checks pool connectivity");
		ASSERT(chk >= 0 && blk >= 0 && chk < blk,
			"connectivity fast-fail precedes the blocking RequestMsg");
		free(body);
	}

	/* --- async request: fast-fail before the slot claim --- */
	body = func_body("../nats_rpc_async.c",
		"int w_nats_request_async(struct sip_msg *msg");
	ASSERT(body != NULL, "found w_nats_request_async body");
	if (body) {
		long chk = pos_of(body, "nats_pool_is_connected()");
		long slt = pos_of(body, "nats_rpc_slot_claim()");
		ASSERT(chk >= 0, "async request checks pool connectivity");
		ASSERT(chk >= 0 && slt >= 0 && chk < slt,
			"connectivity fast-fail precedes the slot claim");
		free(body);
	}

	/* --- subscription builds gate on connectivity ---
	 * ensure_subscription_for_handle must not fire js_AddConsumer /
	 * js_PullSubscribe at a disconnected pool: each attempt burns a
	 * full JetStream request timeout per handle per reconcile tick,
	 * and racing the background first-connect mid-call crashed the
	 * consumer proc inside cnats (caught by test_boot_degraded_e2e:
	 * SIGSEGV in js_PullSubscribe at the moment the late broker
	 * arrived).  While disconnected the handles simply stay pending;
	 * the reconnect epoch bump rebuilds them against a live conn. */
	body = func_body("../nats_sub_config.c",
		"int ensure_subscription_for_handle(nats_handle_t *h)");
	ASSERT(body != NULL, "found ensure_subscription_for_handle body");
	if (body) {
		long chk = pos_of(body, "nats_pool_is_connected()");
		long sub = pos_of(body, "build_consumer_config");
		ASSERT(chk >= 0, "ensure gates on pool connectivity");
		ASSERT(chk >= 0 && sub >= 0 && chk < sub,
			"connectivity gate precedes the consumer-config build");
		free(body);
	}

	/* --- [P3.7] outage logging policy on the fast-fail sites ---
	 * A broker outage used to WARN once PER REQUEST from every SIP
	 * worker (log flood at exactly the moment the box is unhappy).
	 * Policy: rate-limited WARN (nats_rl_pass gate) + DBG per call. */
	body = func_body("../nats_rpc.c",
		"int w_nats_request(struct sip_msg *msg");
	if (body) {
		ASSERT(pos_of(body, "nats_rl_pass(") >= 0,
			"sync fast-fail WARN is rate-limited (nats_rl_pass)");
		ASSERT(pos_of(body, "LM_DBG(\"nats_request: NATS disconnected") >= 0,
			"sync fast-fail keeps a per-call DBG");
		free(body);
	}
	body = func_body("../nats_rpc_async.c",
		"int w_nats_request_async(struct sip_msg *msg");
	if (body) {
		ASSERT(pos_of(body, "nats_rl_pass(") >= 0,
			"async fast-fail WARN is rate-limited (nats_rl_pass)");
		free(body);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
