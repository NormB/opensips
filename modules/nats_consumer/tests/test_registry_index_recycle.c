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
 * Regression test: nats_registry_bind() allocated the per-handle index
 * from a monotonic counter BEFORE the duplicate check, and never
 * reclaimed it.  So every bind attempt -- including a duplicate that is
 * rejected, or a bind that fails later -- burned one index.  After
 * NATS_REGISTRY_MAX_HANDLES (256) cumulative attempts the counter
 * exceeded the cap and ALL future binds failed with -3, permanently
 * disabling binding even though few (or zero) handles were actually
 * live.  Reachable by anyone with MI access (repeat-bind the same id).
 *
 * Fix: allocate the index only after the duplicate check succeeds, from a
 * recyclable free bitmap, and release it when the handle is reaped.
 *
 * This test drives the real registry (../nats_handle_registry.c under the
 * SHM shim):
 *   A) many duplicate binds of one id must NOT consume indices -- a full
 *      complement of distinct handles still binds afterward.
 *   B) indices are recycled: after binding to the cap and reaping, the
 *      cap's worth of fresh handles binds again.
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

/* Reap a handle to completion: unbind, simulate consumer teardown, reap. */
static void unbind_and_reap(const char *id)
{
	str key = dup_str(id);
	nats_handle_t *w = nats_registry_lookup_weak(&key);
	(void)nats_registry_unbind(&key);
	w = nats_registry_lookup_weak(&key);
	if (w)
		__atomic_store_n(&w->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	nats_registry_reap();
	free(key.s);
}

static void test_duplicate_binds_dont_exhaust(void)
{
	int i, ok;
	char idbuf[32];

	CHECK(nats_registry_init(64) == 0, "registry init");

	/* One live handle. */
	CHECK(nats_registry_bind(mk_handle("keep")) == 0, "bind 'keep'");

	/* Hammer duplicate binds far past the index cap. */
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES * 4; i++) {
		nats_handle_t *dup = mk_handle("keep");
		int rc = nats_registry_bind(dup);
		if (rc != -1) {
			fprintf(stderr, "FAIL: duplicate bind #%d returned %d "
				"(want -1)\n", i, rc);
			g_fails++;
		}
		nats_handle_free(dup);   /* caller still owns h on duplicate */
	}

	/* The duplicates must not have burned any index: a full complement of
	 * DISTINCT handles (cap minus the one live 'keep') still binds. */
	ok = 1;
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES - 1; i++) {
		snprintf(idbuf, sizeof(idbuf), "h%d", i);
		if (nats_registry_bind(mk_handle(idbuf)) != 0) { ok = 0; break; }
	}
	CHECK(ok, "distinct handles still bind after many duplicate attempts");

	nats_registry_destroy();
}

static void test_indices_recycled_on_reap(void)
{
	int i, ok;
	char idbuf[32];

	CHECK(nats_registry_init(64) == 0, "registry init (recycle)");

	/* Fill to the cap. */
	ok = 1;
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES; i++) {
		snprintf(idbuf, sizeof(idbuf), "a%d", i);
		if (nats_registry_bind(mk_handle(idbuf)) != 0) { ok = 0; break; }
	}
	CHECK(ok, "bind up to the cap succeeds");

	/* One more must be refused (cap reached). */
	{
		nats_handle_t *over = mk_handle("overflow");
		CHECK(nats_registry_bind(over) == -3, "bind past the cap is refused");
		nats_handle_free(over);
	}

	/* Reap them all, returning their indices to the free pool. */
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES; i++) {
		snprintf(idbuf, sizeof(idbuf), "a%d", i);
		unbind_and_reap(idbuf);
	}

	/* A fresh cap's worth must bind again (indices recycled). */
	ok = 1;
	for (i = 0; i < NATS_REGISTRY_MAX_HANDLES; i++) {
		snprintf(idbuf, sizeof(idbuf), "b%d", i);
		if (nats_registry_bind(mk_handle(idbuf)) != 0) { ok = 0; break; }
	}
	CHECK(ok, "cap's worth of fresh handles binds after reap (recycled)");

	nats_registry_destroy();
}

int main(void)
{
	test_duplicate_binds_dont_exhaust();
	test_indices_recycled_on_reap();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
