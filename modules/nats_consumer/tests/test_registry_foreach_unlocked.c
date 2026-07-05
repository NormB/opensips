/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P3.4] nats_registry_foreach_unlocked(): the reconcile pass runs
 * JetStream network calls (js_AddConsumer / js_PullSubscribe, seconds
 * each against a slow broker) per handle -- doing that inside
 * nats_registry_foreach()'s global+bucket read locks lets one slow
 * reconcile stall every SIP-worker fetch lookup (rwlock writer
 * priority: a queued unbind blocks all new readers).  The unlocked
 * variant snapshots the live handles under the locks (taking a
 * pending_ops pin on each), drops ALL locks, then visits each pinned
 * handle lock-free.
 *
 * Contract locked here (drives the REAL ../nats_handle_registry.c):
 *   - every live handle is visited exactly once, pinned (pending_ops
 *     > 0) for the duration of its callback, all pins released after,
 *   - the callback runs with NO registry locks held: it may call
 *     nats_registry_unbind()/reap() -- instant deadlock under the
 *     locked foreach ("Must not call registry_bind/unbind from within
 *     cb"),
 *   - a handle retired mid-walk (by an earlier callback) is still
 *     visited with valid memory (the pin defers reap; ASan enforces
 *     no-UAF) and its retire flag is visible to the callback,
 *   - reap during the walk never frees a pinned handle; after the
 *     walk (pins gone) the same handle IS reapable,
 *   - early-stop (cb returns non-zero) returns that rc AND still
 *     releases every remaining pin,
 *   - empty registry / NULL cb are safe no-ops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_shim.h"
#include "../../../str.h"
#include "../nats_handle_registry.h"

static int tests_run, tests_fail;
#define CHECK(cond, label) do { \
	tests_run++; \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); tests_fail++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);               } \
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
	h->durable = dup_str("D");
	h->type    = NATS_CONSUMER_DURABLE;
	return h;
}

/* ── visit recorder ──────────────────────────────────────────── */

#define MAX_VISITS 16
static struct {
	nats_handle_t *h;
	int pending_at_visit;
	int retire_at_visit;
} g_visits[MAX_VISITS];
static int g_nvisits;

static int record_cb(nats_handle_t *h, void *user)
{
	(void)user;
	if (g_nvisits < MAX_VISITS) {
		g_visits[g_nvisits].h = h;
		g_visits[g_nvisits].pending_at_visit =
			__atomic_load_n(&h->pending_ops, __ATOMIC_SEQ_CST);
		g_visits[g_nvisits].retire_at_visit =
			__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST);
		g_nvisits++;
	}
	return 0;
}

static int visits_of(nats_handle_t *h)
{
	int i, n = 0;
	for (i = 0; i < g_nvisits; i++)
		if (g_visits[i].h == h)
			n++;
	return n;
}

/* ── unbind-from-cb (deadlocks under the locked foreach) ─────── */

static str g_unbind_target_id;
static int unbind_self_cb(nats_handle_t *h, void *user)
{
	(void)user;
	if (h->id.len == g_unbind_target_id.len &&
	    memcmp(h->id.s, g_unbind_target_id.s, h->id.len) == 0) {
		/* Mark torn-down first so the handle is reap-eligible the
		 * moment its pin drops, then unbind + reap FROM THE CB --
		 * the no-locks proof.  The pin we run under must keep the
		 * handle alive through the rest of this callback. */
		__atomic_store_n(&h->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		nats_registry_unbind(&h->id);
		nats_registry_reap();
		/* Still alive under the pin: this deref is the ASan probe. */
		CHECK(h->id.s[0] != '\0', "pinned handle survives reap from cb");
		CHECK(__atomic_load_n(&h->retire, __ATOMIC_SEQ_CST) == 1,
			"unbind from cb marks retire");
	}
	return 0;
}

/* cb that unbinds a DIFFERENT handle (one not yet visited). */
static int unbind_other_cb(nats_handle_t *h, void *user)
{
	nats_handle_t *other = (nats_handle_t *)user;
	record_cb(h, NULL);
	if (h != other &&
	    __atomic_load_n(&other->retire, __ATOMIC_SEQ_CST) == 0) {
		__atomic_store_n(&other->sub_torn_down, 1, __ATOMIC_SEQ_CST);
		nats_registry_unbind(&other->id);
	}
	return 0;
}

static int stop_on_second_cb(nats_handle_t *h, void *user)
{
	int *n = (int *)user;
	(void)h;
	return ++(*n) == 2 ? 42 : 0;
}

int main(void)
{
	nats_handle_t *a, *b, *c;

	/* ── empty / NULL safety ─────────────────────────────────── */
	CHECK(nats_registry_foreach_unlocked(record_cb, NULL) == 0,
		"foreach_unlocked before init is a 0 no-op");
	CHECK(nats_registry_init(16) == 0, "registry init");
	CHECK(nats_registry_foreach_unlocked(NULL, NULL) == 0,
		"NULL cb is a 0 no-op");
	CHECK(nats_registry_foreach_unlocked(record_cb, NULL) == 0,
		"empty registry walk returns 0");
	CHECK(g_nvisits == 0, "empty registry visits nothing");

	a = mk_handle("h.a");
	b = mk_handle("h.b");
	c = mk_handle("h.c");
	CHECK(nats_registry_bind(a) == 0, "bind a");
	CHECK(nats_registry_bind(b) == 0, "bind b");
	CHECK(nats_registry_bind(c) == 0, "bind c");

	/* ── pinned visits, exactly once each, pins released ─────── */
	g_nvisits = 0;
	CHECK(nats_registry_foreach_unlocked(record_cb, NULL) == 0,
		"walk over 3 live handles returns 0");
	CHECK(g_nvisits == 3, "3 handles -> 3 visits");
	CHECK(visits_of(a) == 1 && visits_of(b) == 1 && visits_of(c) == 1,
		"each handle visited exactly once");
	{
		int i, all_pinned = 1, none_left = 1;
		for (i = 0; i < g_nvisits; i++)
			if (g_visits[i].pending_at_visit < 1)
				all_pinned = 0;
		CHECK(all_pinned, "every visit ran under a pending_ops pin");
		if (__atomic_load_n(&a->pending_ops, __ATOMIC_SEQ_CST) ||
		    __atomic_load_n(&b->pending_ops, __ATOMIC_SEQ_CST) ||
		    __atomic_load_n(&c->pending_ops, __ATOMIC_SEQ_CST))
			none_left = 0;
		CHECK(none_left, "all pins released after the walk");
	}

	/* ── early-stop still releases every pin ─────────────────── */
	{
		int n = 0;
		CHECK(nats_registry_foreach_unlocked(stop_on_second_cb, &n)
				== 42, "early-stop rc is surfaced");
		CHECK(__atomic_load_n(&a->pending_ops, __ATOMIC_SEQ_CST) == 0 &&
		      __atomic_load_n(&b->pending_ops, __ATOMIC_SEQ_CST) == 0 &&
		      __atomic_load_n(&c->pending_ops, __ATOMIC_SEQ_CST) == 0,
			"early-stop releases the remaining pins");
	}

	/* ── retire-mid-walk: a later handle unbound by an earlier cb
	 *    is still visited on valid memory ─────────────────────── */
	g_nvisits = 0;
	CHECK(nats_registry_foreach_unlocked(unbind_other_cb, c) == 0,
		"walk where an early cb unbinds a later handle");
	CHECK(visits_of(c) == 1,
		"the mid-walk-retired handle is still visited (pinned)");
	nats_registry_reap();

	/* ── unbind + reap from INSIDE the cb (no-locks proof) ───── */
	{
		/* stable copy: after the post-walk reap frees b, b->id.s is
		 * gone -- the lookup below must not read freed memory. */
		char idbuf[8];
		memcpy(idbuf, b->id.s, b->id.len);
		g_unbind_target_id.s = idbuf;
		g_unbind_target_id.len = b->id.len;
		CHECK(nats_registry_foreach_unlocked(unbind_self_cb, NULL) == 0,
			"cb that unbinds+reaps its own handle completes (no deadlock)");
		nats_registry_reap();
		CHECK(nats_registry_lookup(&g_unbind_target_id) == NULL,
			"the cb-unbound handle is gone after the walk's pins drop");
	}

	nats_registry_destroy();

	fprintf(stderr, "\ntests: %d run, %d failed\n", tests_run, tests_fail);
	return tests_fail ? 1 : 0;
}
