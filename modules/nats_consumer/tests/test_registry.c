/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * test_registry.c -- unit tests for nats_handle_registry.
 * Uses the pthread shim; no opensips core required.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "test_shim.h"
#include "../nats_handle_registry.h"

static int tests_run  = 0;
static int tests_fail = 0;

#define CHECK(cond) do { \
	tests_run++; \
	if (!(cond)) { \
		fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		tests_fail++; \
	} \
} while (0)

static str dup_str(const char *s)
{
	str r;
	r.len = (int)strlen(s);
	r.s = (char *)malloc(r.len);
	memcpy(r.s, s, r.len);
	return r;
}

static nats_handle_t *mk_handle(const char *id, const char *stream,
		const char *durable)
{
	nats_handle_t *h = (nats_handle_t *)malloc(sizeof(*h));
	memset(h, 0, sizeof(*h));
	h->id      = dup_str(id);
	h->stream  = dup_str(stream);
	h->durable = dup_str(durable);
	h->type    = NATS_CONSUMER_DURABLE;
	return h;
}

/* ── test cases ──────────────────────────────────────────────── */

static void test_init_destroy_empty(void)
{
	int rc = nats_registry_init(16);
	CHECK(rc == 0);
	CHECK(nats_registry_count() == 0);
	nats_registry_destroy();
	CHECK(nats_registry_count() == 0);
}

static void test_bind_lookup_single(void)
{
	nats_handle_t *h;
	str key;
	nats_handle_t *found;

	CHECK(nats_registry_init(16) == 0);

	h = mk_handle("orders", "ORDERS", "dispatcher");
	CHECK(nats_registry_bind(h) == 0);
	CHECK(nats_registry_count() == 1);

	key = dup_str("orders");
	found = nats_registry_lookup(&key);
	CHECK(found != NULL);
	CHECK(found->stream.len == 6);
	CHECK(memcmp(found->stream.s, "ORDERS", 6) == 0);
	free(key.s);

	nats_registry_destroy();
}

static void test_bind_two(void)
{
	nats_handle_t *h1, *h2, *found;
	str k1, k2;

	CHECK(nats_registry_init(16) == 0);

	h1 = mk_handle("alpha", "S1", "d1");
	h2 = mk_handle("beta",  "S2", "d2");
	CHECK(nats_registry_bind(h1) == 0);
	CHECK(nats_registry_bind(h2) == 0);
	CHECK(nats_registry_count() == 2);

	k1 = dup_str("alpha");
	k2 = dup_str("beta");
	found = nats_registry_lookup(&k1);
	CHECK(found && found->stream.len == 2 &&
		memcmp(found->stream.s, "S1", 2) == 0);
	found = nats_registry_lookup(&k2);
	CHECK(found && found->stream.len == 2 &&
		memcmp(found->stream.s, "S2", 2) == 0);
	free(k1.s); free(k2.s);

	nats_registry_destroy();
}

static void test_bind_duplicate(void)
{
	nats_handle_t *h1, *h2;

	CHECK(nats_registry_init(16) == 0);

	h1 = mk_handle("dup", "S", "d");
	h2 = mk_handle("dup", "S2", "d2");

	CHECK(nats_registry_bind(h1) == 0);
	CHECK(nats_registry_bind(h2) == -1);
	CHECK(nats_registry_count() == 1);

	/* caller retains ownership of h2 on duplicate */
	nats_handle_free(h2);

	nats_registry_destroy();
}

static void test_unbind_missing(void)
{
	str key;

	CHECK(nats_registry_init(16) == 0);

	key = dup_str("nope");
	CHECK(nats_registry_unbind(&key) == -1);
	free(key.s);
	CHECK(nats_registry_count() == 0);

	nats_registry_destroy();
}

static void test_unbind_existing(void)
{
	nats_handle_t *h1, *h2, *found;
	str k1;

	CHECK(nats_registry_init(16) == 0);

	h1 = mk_handle("one", "S", "d");
	h2 = mk_handle("two", "S", "d");
	CHECK(nats_registry_bind(h1) == 0);
	CHECK(nats_registry_bind(h2) == 0);
	CHECK(nats_registry_count() == 2);

	k1 = dup_str("one");
	CHECK(nats_registry_unbind(&k1) == 0);
	CHECK(nats_registry_count() == 1);

	found = nats_registry_lookup(&k1);
	CHECK(found == NULL);
	free(k1.s);

	nats_registry_destroy();
}

struct foreach_ctx {
	int count;
	int stop_after;
	char seen[8][32];
};

static int foreach_count_cb(nats_handle_t *h, void *u)
{
	struct foreach_ctx *c = (struct foreach_ctx *)u;
	if (c->count < 8) {
		int n = h->id.len < 31 ? h->id.len : 31;
		memcpy(c->seen[c->count], h->id.s, n);
		c->seen[c->count][n] = '\0';
	}
	c->count++;
	if (c->stop_after > 0 && c->count >= c->stop_after)
		return 42;
	return 0;
}

static void test_foreach(void)
{
	struct foreach_ctx ctx;
	int rc;

	CHECK(nats_registry_init(16) == 0);

	CHECK(nats_registry_bind(mk_handle("a", "S", "d")) == 0);
	CHECK(nats_registry_bind(mk_handle("b", "S", "d")) == 0);
	CHECK(nats_registry_bind(mk_handle("c", "S", "d")) == 0);

	memset(&ctx, 0, sizeof(ctx));
	rc = nats_registry_foreach(foreach_count_cb, &ctx);
	CHECK(rc == 0);
	CHECK(ctx.count == 3);

	/* early stop */
	memset(&ctx, 0, sizeof(ctx));
	ctx.stop_after = 2;
	rc = nats_registry_foreach(foreach_count_cb, &ctx);
	CHECK(rc == 42);
	CHECK(ctx.count == 2);

	nats_registry_destroy();
}

/* Binding past NATS_REGISTRY_MAX_HANDLES returns -3. */
static void test_bind_cap_exceeded(void)
{
	int i, rc;
	nats_handle_t *h;
	char id[32];
	int bound_ok = 0;
	int rejected = 0;

	CHECK(nats_registry_init(16) == 0);

	/* Bind up to and past the cap; exactly one bind attempt past the
	 * cap should return -3. */
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES + 1; i++) {
		snprintf(id, sizeof(id), "cap%d", i);
		h = mk_handle(id, "S", "d");
		rc = nats_registry_bind(h);
		if (rc == 0) {
			bound_ok++;
		} else if (rc == -3) {
			rejected++;
			nats_handle_free(h); /* caller retains on failure */
		} else {
			/* unexpected */
			nats_handle_free(h);
		}
	}
	CHECK(bound_ok == NATS_REGISTRY_MAX_HANDLES);
	CHECK(rejected == 1);

	nats_registry_destroy();
}

/* Unbind while pending_ops > 0 succeeds: the handle is marked
 * retired, dropped from its bucket so lookups miss, and parked on
 * the retire list until the consumer process tears the subscription
 * down and the reaper drains it.  A subsequent nats_registry_reap()
 * without sub_torn_down keeps the handle parked (no crash). */
static void test_unbind_retires_while_in_use(void)
{
	nats_handle_t *h, *found;
	nats_handle_t *weak;
	str key;

	CHECK(nats_registry_init(16) == 0);

	h = mk_handle("busy", "S", "d");
	CHECK(nats_registry_bind(h) == 0);

	/* Simulate a worker holding the handle across an async op. */
	nats_handle_pending_inc(h);

	key = dup_str("busy");
	/* Unbind returns 0 even with pending_ops > 0 -- the handle is
	 * retired, not freed yet. */
	CHECK(nats_registry_unbind(&key) == 0);

	/* Normal lookup misses a retired handle. */
	found = nats_registry_lookup(&key);
	CHECK(found == NULL);

	/* Weak lookup still finds it on the retire list so the consumer
	 * process can do cleanup.  retire flag must be set. */
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == h);
	CHECK(__atomic_load_n(&weak->retire, __ATOMIC_SEQ_CST) == 1);

	/* Reap without sub_torn_down: handle stays parked. */
	nats_registry_reap();
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == h);

	/* Simulate consumer-process teardown + pending release. */
	__atomic_store_n(&weak->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	/* Still pending, still parked. */
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == h);

	nats_handle_pending_dec(h);
	/* Both flags set + pending == 0 -> reap frees it. */
	nats_registry_reap();
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == NULL);

	free(key.s);
	nats_registry_destroy();
}

/* Unbind without pending_ops retires instantly; reap frees the
 * handle once the consumer process signals sub_torn_down. */
static void test_unbind_retire_flow(void)
{
	nats_handle_t *h, *weak;
	str key;

	CHECK(nats_registry_init(16) == 0);

	h = mk_handle("clean", "S", "d");
	CHECK(nats_registry_bind(h) == 0);

	key = dup_str("clean");
	CHECK(nats_registry_unbind(&key) == 0);

	/* Off the bucket, on the retire list. */
	CHECK(nats_registry_lookup(&key) == NULL);
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == h);
	CHECK(__atomic_load_n(&weak->retire, __ATOMIC_SEQ_CST) == 1);

	/* Before sub_torn_down, reap is a no-op for this handle. */
	nats_registry_reap();
	CHECK(nats_registry_lookup_weak(&key) == h);

	__atomic_store_n(&weak->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	CHECK(nats_registry_lookup_weak(&key) == NULL);

	free(key.s);
	nats_registry_destroy();
}

/* Every bind assigns a fresh monotonic index so the ack token
 * packing is stable for the handle's lifetime. */
static void test_bind_index_assignment(void)
{
	nats_handle_t *a, *b, *c;
	int rc;

	CHECK(nats_registry_init(16) == 0);

	a = mk_handle("xi1", "S", "d");
	b = mk_handle("xi2", "S", "d");
	c = mk_handle("xi3", "S", "d");

	rc = nats_registry_bind(a); CHECK(rc == 0);
	rc = nats_registry_bind(b); CHECK(rc == 0);
	rc = nats_registry_bind(c); CHECK(rc == 0);

	/* indices must be distinct and strictly monotonic by bind order. */
	CHECK(a->index != b->index);
	CHECK(b->index != c->index);
	CHECK(a->index != c->index);
	CHECK(b->index > a->index);
	CHECK(c->index > b->index);

	/* bounded below MAX_HANDLES cap. */
	CHECK(a->index < NATS_REGISTRY_MAX_HANDLES);
	CHECK(b->index < NATS_REGISTRY_MAX_HANDLES);
	CHECK(c->index < NATS_REGISTRY_MAX_HANDLES);

	nats_registry_destroy();
}

int main(void)
{
	test_init_destroy_empty();
	test_bind_lookup_single();
	test_bind_two();
	test_bind_duplicate();
	test_unbind_missing();
	test_unbind_existing();
	test_foreach();
	test_bind_index_assignment();
	test_bind_cap_exceeded();
	test_unbind_retires_while_in_use();
	test_unbind_retire_flow();

	fprintf(stderr, "tests: %d run, %d failed\n", tests_run, tests_fail);
	return tests_fail == 0 ? 0 : 1;
}
