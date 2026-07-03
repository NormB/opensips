/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Regression test: nats_registry_bind() must validate BEFORE it
 * allocates the per-handle SHM ring.
 *
 * The defect: the ring (up to ~1.2 GB at the maximum ring_capacity)
 * was allocated before the duplicate-id check, so every rejected
 * duplicate `nats_consumer_bind` MI call churned a giant SHM
 * alloc/free pair — an SHM fragmentation / DoS surface reachable from
 * the management interface.
 *
 * Contract asserted here (via the test_shim counting ring fakes):
 *   - a successful bind creates exactly one ring;
 *   - a REJECTED duplicate bind creates NO ring (and frees none —
 *     nothing was allocated);
 *   - a bind refused for handle-cap exhaustion (-3) creates NO ring;
 *   - a bind rejected for an invalid id (-2) creates NO ring;
 *   - unbind + reap still destroys exactly the rings that were created.
 *
 * Build (see Makefile): links ../nats_handle_registry.c under -DTEST_SHIM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_shim.h"
#include "../nats_handle_registry.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

static str dup_str(const char *s)
{
	str r;
	r.len = (int)strlen(s);
	r.s = (char *)malloc(r.len);
	memcpy(r.s, s, r.len);
	return r;
}

static nats_handle_t *mk_handle(const char *id)
{
	nats_handle_t *h = (nats_handle_t *)malloc(sizeof(*h));
	memset(h, 0, sizeof(*h));
	h->id      = dup_str(id);
	h->stream  = dup_str("S");
	h->durable = dup_str("d");
	h->type    = NATS_CONSUMER_DURABLE;
	return h;
}

int main(void)
{
	int rc, before;

	CHECK(nats_registry_init(64) == 0, "registry init");

	/* 1. a successful bind creates exactly one ring */
	test_ring_creates = test_ring_destroys = 0;
	rc = nats_registry_bind(mk_handle("keep"));
	CHECK(rc == 0, "bind 'keep' succeeds");
	CHECK(test_ring_creates == 1, "successful bind creates one ring");

	/* 2. THE DEFECT — a rejected duplicate bind must not touch the
	 * ring allocator at all */
	{
		nats_handle_t *dup = mk_handle("keep");
		before = test_ring_creates;
		rc = nats_registry_bind(dup);
		CHECK(rc == -1, "duplicate bind rejected (-1)");
		CHECK(test_ring_creates == before,
			"REJECTED duplicate bind allocates NO ring");
		nats_handle_free(dup);
	}

	/* 3. invalid handle (empty id): validation rejects before any
	 * allocation */
	{
		nats_handle_t *bad = mk_handle("x");
		free(bad->id.s);
		bad->id.s = NULL;
		bad->id.len = 0;
		before = test_ring_creates;
		rc = nats_registry_bind(bad);
		CHECK(rc == -2, "empty-id bind rejected (-2)");
		CHECK(test_ring_creates == before,
			"invalid-id bind allocates NO ring");
		/* bad has no id; free the pieces directly */
		free(bad->stream.s); free(bad->durable.s); free(bad);
	}

	/* 4. cap exhaustion (-3): fill the index space, then one more */
	{
		char idbuf[32];
		int i, ok = 1;
		for (i = 1; i < NATS_REGISTRY_MAX_HANDLES; i++) {
			snprintf(idbuf, sizeof(idbuf), "h%04d", i);
			if (nats_registry_bind(mk_handle(idbuf)) != 0) {
				ok = 0;
				break;
			}
		}
		CHECK(ok, "filled the registry to the cap");
		{
			nats_handle_t *over = mk_handle("overflow");
			before = test_ring_creates;
			rc = nats_registry_bind(over);
			CHECK(rc == -3, "bind past the cap refused (-3)");
			CHECK(test_ring_creates == before,
				"cap-refused bind allocates NO ring");
			nats_handle_free(over);
		}
	}

	/* 5. unbind + reap destroys the one ring 'keep' owns */
	{
		str key = { "keep", 4 };
		nats_handle_t *w;
		int destroys_before = test_ring_destroys;
		CHECK(nats_registry_unbind(&key) == 0, "unbind 'keep'");
		w = nats_registry_lookup_weak(&key);
		if (w)
			__atomic_store_n(&w->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		nats_registry_reap();
		CHECK(test_ring_destroys == destroys_before + 1,
			"reaping the unbound handle destroys its ring");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
