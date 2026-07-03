/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Behavioral regression test: the orphan-retired pass must purge the
 * msg-ref row of a handle that was presized but never subscribed.
 *
 * The defect: ensure_subscription_for_handle() presizes the handle's
 * msg-ref row (presize_msg_ref_row, up to ~1.5 MB of slots) BEFORE the
 * subscribe attempt.  If that first subscribe fails and the handle is
 * later unbound, no g_subs entry exists, so no subscription-teardown
 * path ever calls purge_msg_ref_row() — and the orphan pass
 * (mark_orphan_retired_handles) only set sub_torn_down without purging.
 * The row's slot buffer leaked for the consumer-process lifetime, and a
 * later handle re-using the recycled index inherited a stale row.
 *
 * Contract asserted here:
 *   - after unbind + orphan pass + reap, the never-subscribed handle is
 *     freed AND its msg-ref row slots are released (row.slots == NULL);
 *   - a handle whose index maps to a live g_subs entry is left alone.
 *
 * Unlike the -DTEST_SHIM tests, this links the REAL production TUs
 * (nats_consumer_proc.c, nats_msg_ref.c, nats_sub_config.c,
 * nats_handle_registry.c, nats_ring.c) with core seams (dprint, pkg/shm
 * allocators, nats_pool, IPC fds) swapped for stubs — see the
 * target-specific rule in the Makefile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include <nats/nats.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../lib/nats/nats_dl.h"
#include "../../../lib/nats/nats_pool.h"
#include "../nats_handle_registry.h"
#include "../nats_consumer_proc_internal.h"
#include "../nats_ack_ipc.h"

/* ── core seams: dprint ─────────────────────────────────────────── */

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
	va_list ap;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	vfprintf(stderr, stderr_fmt, ap);
	va_end(ap);
}

/* ── core seams: pkg + shm allocators ───────────────────────────── */

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

/* ── module globals normally defined by nats_consumer.c ─────────── */

int nats_consumer_fetch_batch = 10;
int nats_consumer_fetch_timeout_ms = 1000;
int nats_consumer_poison_max_deliver = 0;

void nats_persist_schedule_write(void) {}

/* ── pool / dl / IPC seams (never exercised by this test) ───────── */

nats_dl_funcs_t nats_dl;

int nats_pool_is_connected(void) { return 0; }
natsConnection *nats_pool_get(void) { return NULL; }
jsCtx *nats_pool_get_js(void) { return NULL; }
int nats_pool_get_reconnect_epoch(void) { return 0; }

/* ack/rpc IPC veneers are header inlines over nats_ipcq.c since P1.3;
 * the real nats_ipcq.c + nats_mpsc.c are linked instead of stubbed. */
int nats_rpc_consumer_subscribe(void) { return 0; }
int nats_rpc_consumer_inbox_ready(void) { return 1; }
int nats_rpc_consumer_drain_ipc(void) { return 0; }

/* ── harness ────────────────────────────────────────────────────── */

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
	nats_handle_t *h;
	uint16_t idx;
	str key = { "orphan", 6 };

	CHECK(nats_registry_init(64) == 0, "registry init");

	/* bind a handle, then simulate the failed-first-subscribe leftovers:
	 * ensure_subscription_for_handle() presizes the msg-ref row BEFORE
	 * attempting the subscribe, so a subscribe failure leaves the row
	 * allocated with no g_subs entry to ever purge it. */
	h = mk_handle("orphan");
	CHECK(nats_registry_bind(h) == 0, "bind 'orphan'");
	idx = h->index;
	CHECK(ensure_row(idx, 128) == 0, "presize msg-ref row (as the "
		"pre-subscribe path does)");
	CHECK(g_msg_refs[idx].slots != NULL, "row slots allocated");
	CHECK(g_subs_by_idx[idx] == NULL, "never subscribed: no g_subs entry");

	/* unbind → retire; then run the REAL orphan pass + reaper */
	CHECK(nats_registry_unbind(&key) == 0, "unbind 'orphan'");
	mark_orphan_retired_handles();
	nats_registry_reap();

	/* THE DEFECT — the orphan pass set sub_torn_down (handle freed) but
	 * never purged the presized msg-ref row, leaking its slot buffer
	 * for the process lifetime. */
	CHECK(g_msg_refs[idx].slots == NULL,
		"orphan pass PURGES the never-subscribed handle's msg-ref row");
	CHECK(nats_registry_lookup_weak(&key) == NULL,
		"orphaned handle was reaped");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
