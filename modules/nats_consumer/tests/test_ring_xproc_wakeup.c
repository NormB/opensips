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
 * Regression test: the per-handle SHM ring used to carry an eventfd
 * whose raw integer was stored in shared memory by nats_ring_create()
 * (running in the MI-bind process, post-fork).  nats_ring_push() runs in
 * the *consumer* process and nats_ring_destroy() can run in yet another
 * process; in those processes that integer maps to an entirely unrelated
 * descriptor (a libnats TCP socket, a timerfd, ...).  So every
 * empty->non-empty edge write()'d 8 bytes into a foreign fd and destroy
 * close()'d an arbitrary fd -- cross-process fd corruption.
 *
 * The cross-process wakeup never actually rode the eventfd: workers
 * always blocked on the SHM futex (wake_seq / nats_ring_wait), and the
 * fetch paths fetched the fd only to discard it.  The fix removes the
 * eventfd entirely.
 *
 * Contract asserted here:
 *   1. nats_ring_create() exposes NO process-local fd: nats_ring_eventfd()
 *      returns < 0.  There is therefore nothing a foreign process can
 *      corrupt or leak.
 *   2. Cross-process (here: cross-thread) wakeup works through the futex:
 *      a waiter blocked on an empty ring is woken by a push and observes
 *      the message, well within its timeout budget.
 *
 * RED/GREEN: against the pre-fix code, assertion (1) FAILS because
 * nats_ring_eventfd() returns a real fd >= 0.
 *
 * Build (mirrors test_ring): TEST_SHIM + ../nats_ring.c, -pthread.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

#include "../nats_ring.h"

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* ── (1) no process-local fd is exposed ──────────────────────────── */

static void test_no_eventfd(void)
{
	nats_ring_t *r = nats_ring_create(8);
	CHECK(r != NULL, "ring created");

	/* The cross-process corruption vector is gone: there is no fd to
	 * write to from a foreign process or to leak on a flapping bind. */
	CHECK(nats_ring_eventfd(r) < 0,
		"ring exposes no process-local eventfd (corruption vector removed)");

	/* A push on the empty->non-empty edge must not crash or touch any
	 * descriptor; it simply bumps the futex word. */
	CHECK(nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "s",
			.subject_len = 1,
			.data = "x",
			.data_len = 1,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 1,
		}) == 0,
		"edge push succeeds without an fd");

	nats_ring_destroy(r);
}

/* ── (2) futex wakeup delivers the message ───────────────────────── */

struct waiter_arg {
	nats_ring_t      *r;
	atomic_int        woke_with_msg;
	long              elapsed_ms;
};

static void *waiter_thread(void *p)
{
	struct waiter_arg *a = p;
	nats_ring_slot_t   slot;
	long start = now_ms();
	int waited = 0;
	const int budget = 5000;   /* generous; we expect to wake far sooner */

	while (waited < budget) {
		if (nats_ring_pop(a->r, &slot) == 0) {
			atomic_store(&a->woke_with_msg, 1);
			break;
		}
		/* Block on the SHM futex until a producer bumps wake_seq. */
		nats_ring_wait(a->r, budget - waited);
		waited = (int)(now_ms() - start);
	}
	a->elapsed_ms = now_ms() - start;
	return NULL;
}

static void test_futex_wakeup(void)
{
	nats_ring_t      *r = nats_ring_create(8);
	struct waiter_arg a;
	pthread_t         th;

	CHECK(r != NULL, "ring created for futex wakeup");
	a.r = r;
	atomic_init(&a.woke_with_msg, 0);
	a.elapsed_ms = -1;

	pthread_create(&th, NULL, waiter_thread, &a);

	/* Let the waiter reach the futex wait on the empty ring, then push. */
	usleep(50 * 1000);
	CHECK(nats_ring_push(r, &(nats_ring_msg_t){
			.subject = "evt",
			.subject_len = 3,
			.data = "hello",
			.data_len = 5,
			.stream_seq = 0,
			.consumer_seq = 0,
			.delivered = 0,
			.pending = 0,
			.timestamp_ns = 0,
			.ack_token = 42,
		}) == 0,
		"producer push (empty->non-empty edge)");

	pthread_join(th, NULL);

	CHECK(atomic_load(&a.woke_with_msg) == 1,
		"waiter woke via futex and popped the message");
	CHECK(a.elapsed_ms >= 0 && a.elapsed_ms < 2000,
		"waiter woke promptly (not by timeout)");

	nats_ring_destroy(r);
}

int main(void)
{
	test_no_eventfd();
	test_futex_wakeup();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
