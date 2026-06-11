/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: the consumer process set a handle's sub_torn_down flag
 * (which lets nats_registry_reap free it) ONLY in tear_down_retired_subs,
 * which walks g_subs.  A handle bound and then unbound BEFORE the consumer
 * ever built a subscription has no g_subs entry, so its sub_torn_down was
 * never set, the reaper never freed it, and its ring (allocated at bind)
 * leaked for the process lifetime.
 *
 * Fix: add nats_registry_foreach_retired() and have the consumer walk the
 * retire list, marking any retired handle with no proc-sub state as
 * sub_torn_down so the reaper can free it.
 *
 * This test drives the real registry (../nats_handle_registry.c under the
 * SHM shim): it confirms foreach_retired enumerates a retired handle, and
 * that marking it sub_torn_down lets reap free it.
 *   -DSIMULATE_PREFIX_BUG -> skip the marking (pre-fix): the never-subbed
 *                            handle stays parked forever -> FAIL.
 *   (default)             -> mark + reap frees it -> ALL PASS.
 * Plus a source-pattern check that the consumer wires foreach_retired in.
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
	str r; r.len = (int)strlen(s);
	r.s = (char *)malloc(r.len); memcpy(r.s, s, r.len); return r;
}
static nats_handle_t *mk_handle(const char *id)
{
	nats_handle_t *h = calloc(1, sizeof(*h));
	h->id = dup_str(id); h->stream = dup_str("S"); h->durable = dup_str("d");
	h->type = NATS_CONSUMER_DURABLE; return h;
}

static int count_cb(nats_handle_t *h, void *user)
{
	(void)h; (*(int *)user)++; return 0;
}
#ifndef SIMULATE_PREFIX_BUG
static int mark_cb(nats_handle_t *h, void *user)
{
	(void)user;
	__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
	return 0;
}
#endif

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

int main(void)
{
	nats_handle_t *h, *weak;
	str key;
	int n;

	CHECK(nats_registry_init(16) == 0, "registry init");

	h = mk_handle("never-subbed");
	CHECK(nats_registry_bind(h) == 0, "bind handle");

	/* Unbind before any subscription is built -> retired, parked, but no
	 * g_subs entry would ever exist for it. */
	key = dup_str("never-subbed");
	CHECK(nats_registry_unbind(&key) == 0, "unbind retires the handle");

	/* foreach_retired must enumerate it. */
	n = 0;
	nats_registry_foreach_retired(count_cb, &n);
	CHECK(n == 1, "foreach_retired enumerates the retired handle");

#ifndef SIMULATE_PREFIX_BUG
	/* Consumer marks never-subscribed retired handles torn down. */
	nats_registry_foreach_retired(mark_cb, NULL);
#endif

	/* Reap.  The handle must now be freed (it would otherwise leak). */
	nats_registry_reap();
	weak = nats_registry_lookup_weak(&key);
	CHECK(weak == NULL,
		"never-subscribed retired handle is reaped (ring no longer leaks)");

	free(key.s);
	nats_registry_destroy();

	/* The consumer process must actually wire the retire-list walk in. */
	CHECK(file_contains("../nats_consumer_proc.c",
		"nats_registry_foreach_retired"),
		"consumer process walks the retire list to mark orphans");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
