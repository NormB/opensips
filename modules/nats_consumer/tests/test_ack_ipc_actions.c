/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * [P2.1] Worker acks ride core IPC: the ACTION is the ipc_send_rpc
 * function identity (nats_ack_ipc_on_ack / _nak / _term / _in_progress
 * / _ack_next, param = the 64-bit ack token verbatim) and only
 * NAK_DELAY -- the one action that cannot fit token+delay in a pointer
 * -- carries a small SHM payload the handler frees.  This test drives
 * the PRODUCTION handlers (../nats_consumer_proc.c + ../nats_msg_ref.c)
 * against a recording nats_dl table and asserts, per action:
 *
 *   - the right JetStream call is made on the right natsMsg,
 *   - the msg-ref is redeemed and the message destroyed afterwards --
 *     EXCEPT in_progress, which must re-stash the msg under the SAME
 *     token (a later ack must still find it),
 *   - ack_next sets the per-handle refill hint, observable (and
 *     cleared) via nats_ack_next_take(),
 *   - a stale token (already released) makes no JetStream call,
 *   - nak_delay converts ms -> ns and frees its SHM payload (ASan),
 *   - every handler bumps the drained stat; the sent/dropped stats
 *     count from the worker-side helper.
 *
 * Build: linked with the production TUs (see ACKIPC_SRCS in Makefile),
 * ASan on.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <nats/nats.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../lib/nats/nats_dl.h"
#include "../../../lib/nats/nats_pool.h"
#include "../nats_handle_registry.h"
#include "../nats_consumer_proc.h"
#include "../nats_consumer_proc_internal.h"
#include "../nats_ack.h"
#include "../nats_ack_ipc.h"

/* ── core seams (same shape as test_orphan_msg_ref_purge.c) ─────── */

static int test_log_level = L_INFO;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	(void)level; (void)facility; (void)module; (void)func;
	(void)stderr_fmt; (void)syslog_fmt; (void)format;
}

void *mem_block = NULL;
void *shm_block = NULL;

static void *test_blk_malloc(void *blk, unsigned long size)
{ (void)blk; return malloc(size); }
static void *test_blk_realloc(void *blk, void *p, unsigned long size)
{ (void)blk; return realloc(p, size); }
static void test_blk_free(void *blk, void *p)
{ (void)blk; free(p); }
static unsigned long test_blk_size(void *blk) { (void)blk; return 1 << 24; }
static unsigned long test_blk_rused(void *blk) { (void)blk; return 0; }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_blk_malloc;
void (*gen_pkg_free)(void *blk, void *p) = test_blk_free;
void *(*gen_shm_malloc)(void *blk, unsigned long size) = test_blk_malloc;
void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size)
	= test_blk_realloc;
void (*gen_shm_free)(void *blk, void *p) = test_blk_free;
unsigned long (*gen_shm_get_size)(void *blk) = test_blk_size;
unsigned long (*gen_shm_get_rused)(void *blk) = test_blk_rused;

static gen_lock_t test_mem_lock;
gen_lock_t *mem_lock = &test_mem_lock;
int shm_use_global_lock = 1;
long event_shm_threshold = 0;
static long _event_last;
static int _event_pending;
long *event_shm_last = &_event_last;
int *event_shm_pending = &_event_pending;
void shm_event_raise(long used, long size, long perc)
{ (void)used; (void)size; (void)perc; }

int nats_consumer_fetch_batch = 10;
int nats_consumer_fetch_timeout_ms = 1000;
int nats_consumer_poison_max_deliver = 0;

int nats_pool_is_connected(void) { return 0; }
natsConnection *nats_pool_get(void) { return NULL; }
jsCtx *nats_pool_get_js(void) { return NULL; }
int nats_pool_get_reconnect_epoch(void) { return 0; }
int nats_rpc_consumer_subscribe(void) { return 0; }
int nats_rpc_consumer_inbox_ready(void) { return 1; }
struct process_table *pt = NULL;
void ipc_handle_job(int fd) { (void)fd; }

/* ── recording nats_dl table ────────────────────────────────────── */

nats_dl_funcs_t nats_dl;

static struct {
	int ack, ack_sync, nak, nak_delay, term, in_progress, destroy;
	const natsMsg *last;
	int64_t last_delay_ns;
} rec;

static natsStatus r_ack(natsMsg *m, jsOptions *o)
{ (void)o; rec.ack++; rec.last = m; return 0; }
static natsStatus r_ack_sync(natsMsg *m, jsOptions *o, jsErrCode *e)
{ (void)o; (void)e; rec.ack_sync++; rec.last = m; return 0; }
static natsStatus r_nak(natsMsg *m, jsOptions *o)
{ (void)o; rec.nak++; rec.last = m; return 0; }
static natsStatus r_nak_delay(natsMsg *m, int64_t ns, jsOptions *o)
{ (void)o; rec.nak_delay++; rec.last = m; rec.last_delay_ns = ns; return 0; }
static natsStatus r_term(natsMsg *m, jsOptions *o)
{ (void)o; rec.term++; rec.last = m; return 0; }
static natsStatus r_in_progress(natsMsg *m, jsOptions *o)
{ (void)o; rec.in_progress++; rec.last = m; return 0; }
static void r_destroy(natsMsg *m)
{ rec.destroy++; rec.last = m; }
static const char *r_text(natsStatus s) { (void)s; return ""; }

static void dl_install(void)
{
	memset(&nats_dl, 0, sizeof(nats_dl));
	nats_dl.natsMsg_Ack          = r_ack;
	nats_dl.natsMsg_AckSync      = r_ack_sync;
	nats_dl.natsMsg_Nak          = r_nak;
	nats_dl.natsMsg_NakWithDelay = r_nak_delay;
	nats_dl.natsMsg_Term         = r_term;
	nats_dl.natsMsg_InProgress   = r_in_progress;
	nats_dl.natsMsg_Destroy      = r_destroy;
	nats_dl.natsStatus_GetText   = r_text;
}

/* ── harness ────────────────────────────────────────────────────── */

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

#define H_IDX 3
#define CAP   8

static int fake1, fake2;

static uint64_t stash(natsMsg *m)
{
	int ok = 0;
	uint64_t tok = store_msg_ref(H_IDX, CAP, 30000, m, &ok);
	if (!ok) { fprintf(stderr, "FATAL: store_msg_ref failed\n"); exit(1); }
	return tok;
}

static void *tok_param(uint64_t tok)
{
	return (void *)(uintptr_t)tok;
}

int main(void)
{
	uint64_t tok;
	uint64_t drained0;

	dl_install();
	CHECK(nats_ack_ipc_stats_init() == 0, "ack IPC stats block allocated");
	drained0 = nats_ack_ipc_drained_total();

	printf("[P2.1] plain ack: JetStream Ack + destroy + ref released:\n");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_ack(0, tok_param(tok));
	CHECK(rec.ack == 1 && rec.last == (natsMsg *)&fake1,
		"natsMsg_Ack called on the stashed message");
	CHECK(rec.destroy == 1, "message destroyed after the ack");
	CHECK(release_msg_ref(tok) == NULL, "ref slot redeemed (token now stale)");
	CHECK(nats_ack_ipc_drained_total() == drained0 + 1,
		"drained stat bumped");

	printf("[P2.1] stale token: no JetStream call at all:\n");
	nats_ack_ipc_on_ack(0, tok_param(tok));
	CHECK(rec.ack == 1 && rec.destroy == 1,
		"replayed token is a no-op (no double ack/destroy)");

	printf("[P2.1] nak / term route to their JetStream calls:\n");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_nak(0, tok_param(tok));
	CHECK(rec.nak == 1, "natsMsg_Nak called");
	tok = stash((natsMsg *)&fake2);
	nats_ack_ipc_on_term(0, tok_param(tok));
	CHECK(rec.term == 1 && rec.last == (natsMsg *)&fake2,
		"natsMsg_Term called on the right message");
	CHECK(rec.destroy == 3, "both messages destroyed");

	printf("[P2.1] ack_next: AckSync + per-handle refill hint:\n");
	CHECK(nats_ack_next_take(H_IDX) == 0, "refill hint starts clear");
	tok = stash((natsMsg *)&fake1);
	nats_ack_ipc_on_ack_next(0, tok_param(tok));
	CHECK(rec.ack_sync == 1, "natsMsg_AckSync called (broker-confirmed)");
	CHECK(nats_ack_next_take(H_IDX) == 1, "refill hint set for the handle");
	CHECK(nats_ack_next_take(H_IDX) == 0, "take() clears the hint");

	printf("[P3.6] ack_next AckSync budget: a burst degrades to async Ack:\n");
	{
		/* Each AckSync is a full broker round-trip executed serially
		 * inside the consumer's IPC drain; a worker-side burst of
		 * nats_ack_next() used to head-of-line-block every other ack
		 * and the fetch sweep behind N x RTT.  Budget: the first
		 * NATS_ACK_SYNC_PER_TICK_MAX per tick stay synchronous (the
		 * broker has definitively seen them before the refill pull),
		 * the rest degrade to async Ack -- same at-least-once
		 * semantics, no serial RTT pileup.  The consumer loop resets
		 * the budget each iteration via nats_ack_ipc_tick_reset(). */
		int sync0, ack0, i;

		nats_ack_ipc_tick_reset();
		sync0 = rec.ack_sync; ack0 = rec.ack;
		for (i = 0; i < NATS_ACK_SYNC_PER_TICK_MAX + 2; i++) {
			tok = stash((natsMsg *)&fake1);
			nats_ack_ipc_on_ack_next(0, tok_param(tok));
		}
		CHECK(rec.ack_sync == sync0 + NATS_ACK_SYNC_PER_TICK_MAX,
			"burst: first NATS_ACK_SYNC_PER_TICK_MAX acks are AckSync");
		CHECK(rec.ack == ack0 + 2,
			"burst: past the budget the ack degrades to async Ack");
		CHECK(nats_ack_next_take(H_IDX) == 1,
			"refill hint still set by the degraded acks");
		(void)nats_ack_next_take(H_IDX);

		nats_ack_ipc_tick_reset();
		tok = stash((natsMsg *)&fake1);
		nats_ack_ipc_on_ack_next(0, tok_param(tok));
		CHECK(rec.ack_sync == sync0 + NATS_ACK_SYNC_PER_TICK_MAX + 1,
			"tick reset restores the AckSync budget");
		(void)nats_ack_next_take(H_IDX);
	}

	printf("[P2.1] in_progress: keeps the message alive under the SAME token:\n");
	tok = stash((natsMsg *)&fake2);
	{
		int destroys_before = rec.destroy;
		nats_ack_ipc_on_in_progress(0, tok_param(tok));
		CHECK(rec.in_progress == 1, "natsMsg_InProgress called");
		CHECK(rec.destroy == destroys_before,
			"message NOT destroyed (still pending)");
		CHECK(release_msg_ref(tok) == (natsMsg *)&fake2,
			"same token still redeems the message afterwards");
	}

	printf("[P2.1] nak_delay: SHM payload, ms->ns, freed by the handler (ASan):\n");
	tok = stash((natsMsg *)&fake1);
	{
		nats_ack_nak_delay_t *d = shm_malloc(sizeof(*d));
		d->token = tok;
		d->delay_ms = 1500;
		nats_ack_ipc_on_nak_delay(0, d);
		CHECK(rec.nak_delay == 1 && rec.last_delay_ns == 1500000000LL,
			"NakWithDelay called with 1500ms as nanoseconds");
	}

	printf("[P2.1] sent/dropped counters (worker-side helper):\n");
	{
		uint64_t s0 = nats_ack_ipc_enqueued_total();
		uint64_t d0 = nats_ack_ipc_dropped_total();
		nats_ack_ipc_count_sent(1);
		nats_ack_ipc_count_sent(0);
		CHECK(nats_ack_ipc_enqueued_total() == s0 + 1 &&
		      nats_ack_ipc_dropped_total() == d0 + 1,
			"count_sent(1)/count_sent(0) land in sent/dropped");
		/* 1 sent vs 6 drained in this test: depth must floor at 0,
		 * never wrap (sent - drained is momentarily "negative" when
		 * the consumer observes the pipe ahead of the counter). */
		CHECK(nats_ack_ipc_depth() == 0,
			"depth floors at 0 when drained >= sent");
	}

	purge_msg_ref_row(H_IDX);
	nats_ack_ipc_stats_destroy();

	printf("\n=== %s (fails=%d) ===\n",
		g_fails ? "FAILURES" : "ALL PASS", g_fails);
	return g_fails ? 1 : 0;
}
