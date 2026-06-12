/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
