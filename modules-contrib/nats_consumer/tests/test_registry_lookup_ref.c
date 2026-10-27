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
 * Regression test: nats_registry_lookup() drops the bucket lock before
 * returning, so a borrowed handle could be retired (MI unbind) and reaped
 * (consumer process) between the lookup and the caller's first
 * nats_handle_pending_inc().  The fetch paths dereferenced the handle in
 * that window -- a use-after-free.
 *
 * Fix: nats_registry_lookup_ref() takes the pending_ops reference WHILE
 * still holding the bucket read lock.  retire() needs the bucket WRITE
 * lock to unlink, so it cannot run concurrently; once the reference is
 * held the reaper (which only frees at pending_ops==0) defers the free.
 *
 * This test drives the real registry (../nats_handle_registry.c) and
 * proves the borrowed handle survives a retire + reap until the reference
 * is released:
 *
 *   -DSIMULATE_PREFIX_BUG -> use plain lookup() with no reference: the
 *                            reaper frees the handle while we still hold
 *                            it (lookup_weak returns NULL) -> the
 *                            "survives reap" assertion FAILS.  In
 *                            production this is the use-after-free.
 *   (default)             -> lookup_ref(): handle stays parked until the
 *                            reference is dropped -> ALL PASS.
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

/* The lookup the fetch path performs before dereferencing the handle. */
static nats_handle_t *borrow(const str *id)
{
#ifdef SIMULATE_PREFIX_BUG
	/* Pre-fix: lookup then a separate inc, with a reap-able window in
	 * between.  Model the worst case: the reaper runs in that window
	 * (here, the test runs reap before we would have inc'd), so the
	 * borrowed pointer is never protected. */
	return nats_registry_lookup(id);
#else
	/* Fixed: the reference is taken atomically under the bucket lock. */
	return nats_registry_lookup_ref(id);
#endif
}

int main(void)
{
	nats_handle_t *h, *b, *weak;
	str key;

	CHECK(nats_registry_init(16) == 0, "registry init");

	h = mk_handle("worker-handle");
	CHECK(nats_registry_bind(h) == 0, "bind handle");

	key = dup_str("worker-handle");

	/* A worker borrows the handle to start a fetch. */
	b = borrow(&key);
	CHECK(b == h, "borrow returns the handle");

#ifndef SIMULATE_PREFIX_BUG
	CHECK(nats_handle_pending_get(h) == 1,
		"lookup_ref took a pending_ops reference under the lock");
#endif

	/* Concurrent MI unbind retires the handle; the consumer process then
	 * tears the subscription down and the reaper runs -- all while the
	 * worker still holds its borrowed pointer. */
	CHECK(nats_registry_unbind(&key) == 0, "unbind retires the handle");
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();

	/* THE contract: because the worker holds a reference, the reaper must
	 * NOT have freed the handle -- it is still parked on the retire list.
	 * Under the pre-fix borrow (no reference) the reaper frees it here,
	 * and the worker's next dereference would be a use-after-free. */
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == h, "borrowed handle survives retire+reap (no UAF)");

#ifndef SIMULATE_PREFIX_BUG
	/* Safe to dereference while the reference is held. */
	CHECK(__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST) == 1,
		"handle is marked retiring but still alive");

	/* Worker finishes: release the reference, then the reaper frees it. */
	nats_handle_pending_dec(h);
	nats_registry_reap();
	CHECK(nats_registry_lookup_weak(&key) == NULL,
		"handle is freed once the reference is released");
#endif

	free(key.s);
	nats_registry_destroy();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
