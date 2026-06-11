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
 */

/*
 * nats_rpc_slot.c -- SHM slot allocator for the
 * consumer-process-routed async nats_request transport.  See
 * nats_rpc_slot.h for the architecture / wake-mechanism rationale.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
#else
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#endif

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <stdatomic.h>

#include "nats_rpc_slot.h"

/*
 * SHM array of slots.  Allocated in nats_rpc_slot_init() from
 * within the OpenSIPS main process pre-fork; the SHM page is
 * mapped by every child via the standard OpenSIPS shm_mem
 * mechanism so workers and the consumer process share one view.
 *
 * The eventfds inside each slot are created in main as well, so
 * fork() carries them into every child's fd table at the same
 * numeric fd value (POSIX file-descriptor inheritance).  Workers
 * write to slot->wake_fd to wake themselves on the empty -> non-
 * empty edge (handled in the resume function); the consumer
 * process writes to the same fd to deliver replies.
 */
static nats_rpc_slot_t *g_slots;
static uint32_t         g_slot_total;

/* Runtime slot-pool size (modparam "async_rpc_slots"); defaults to the
 * compile-time NATS_RPC_SLOT_COUNT.  Caps system-wide in-flight async
 * nats_request calls -- raise it (with RLIMIT_NOFILE headroom) for higher
 * async-RPC throughput. */
int nats_rpc_slot_count = NATS_RPC_SLOT_COUNT;

/* Round-robin allocation hint.  Atomic to keep claim contention
 * low under bursts -- producers start their scan at different
 * offsets so they tend to claim disjoint slots on the first
 * probe. */
static _Atomic uint32_t g_alloc_hint;

/* Lazy advisory counter for telemetry. */
static _Atomic uint32_t g_inflight_count;

/* ── init / destroy ──────────────────────────────────────────── */

int nats_rpc_slot_init(void)
{
	uint32_t i;
	size_t   bytes;

	if (g_slots) {
		LM_WARN("nats_rpc_slot_init: already initialised\n");
		return 0;
	}

	/* Clamp the (modparam-tunable) slot count to a sane range. */
	if (nats_rpc_slot_count < 1)
		nats_rpc_slot_count = 1;
	if (nats_rpc_slot_count > 65536)
		nats_rpc_slot_count = 65536;

	bytes = (size_t)nats_rpc_slot_count * sizeof(nats_rpc_slot_t);
	g_slots = (nats_rpc_slot_t *)shm_malloc(bytes);
	if (!g_slots) {
		LM_ERR("nats_rpc_slot_init: shm_malloc(%zu bytes) failed\n",
			bytes);
		return -1;
	}
	memset(g_slots, 0, bytes);

	for (i = 0; i < (uint32_t)nats_rpc_slot_count; i++) {
		nats_rpc_slot_t *s = &g_slots[i];
		s->slot_idx = i;
		atomic_store_explicit(&s->state, NATS_RPC_SLOT_FREE,
			memory_order_relaxed);
	}

	g_slot_total = (uint32_t)nats_rpc_slot_count;
	atomic_store_explicit(&g_alloc_hint, 0, memory_order_relaxed);
	atomic_store_explicit(&g_inflight_count, 0, memory_order_relaxed);

	LM_INFO("nats_rpc_slot: %u slots allocated (%zu KB SHM); "
		"wake mechanism is per-call worker-private timerfd "
		"polling\n",
		(unsigned)nats_rpc_slot_count,
		bytes / 1024);
	return 0;
}

void nats_rpc_slot_destroy(void)
{
	if (!g_slots)
		return;
	shm_free(g_slots);
	g_slots = NULL;
	g_slot_total = 0;
}

/* ── claim / publish / abandon / free ────────────────────────── */

nats_rpc_slot_t *nats_rpc_slot_claim(void)
{
	uint32_t start, i;

	if (!g_slots)
		return NULL;

	start = atomic_fetch_add_explicit(&g_alloc_hint, 1,
		memory_order_relaxed) % g_slot_total;

	for (i = 0; i < g_slot_total; i++) {
		uint32_t idx = (start + i) % g_slot_total;
		nats_rpc_slot_t *s = &g_slots[idx];
		int expected = NATS_RPC_SLOT_FREE;
		if (atomic_compare_exchange_strong_explicit(
				&s->state, &expected, NATS_RPC_SLOT_CLAIMED,
				memory_order_acquire,
				memory_order_relaxed)) {
			atomic_fetch_add_explicit(&g_inflight_count, 1,
				memory_order_relaxed);
			/* Bump the per-claim generation.  Only the CAS
			 * winner writes it for this claim, so the
			 * relaxed RMW is safe; it is published to the
			 * consumer via the CLAIMED -> INFLIGHT release in
			 * nats_rpc_slot_publish().  A reply echoing a
			 * previous claim's generation is rejected by
			 * on_inbox_reply. */
			atomic_fetch_add_explicit(&s->generation, 1,
				memory_order_relaxed);
			/* Zero out the carry-over reply / outbound fields
			 * so a recycled slot looks pristine to the next
			 * caller.  state, slot_idx, wake_fd, epoch are
			 * left as-is (slot_idx + wake_fd are immutable;
			 * epoch is overwritten by the caller). */
			s->corr_id_len            = 0;
			s->corr_id[0]             = '\0';
			s->out_subject_len        = 0;
			s->out_data_len           = 0;
			s->out_headers_len        = 0;
			s->reply_subject_len      = 0;
			s->reply_data_len         = 0;
			s->reply_headers_len      = 0;
			s->reply_headers_truncated = 0;
			s->reply_to_len           = 0;
			s->reply_has_reply_to     = 0;
			return s;
		}
	}
	return NULL;   /* full */
}

int nats_rpc_slot_publish(nats_rpc_slot_t *s)
{
	int expected = NATS_RPC_SLOT_CLAIMED;
	if (!s) return -1;
	if (!atomic_compare_exchange_strong_explicit(
			&s->state, &expected, NATS_RPC_SLOT_INFLIGHT,
			memory_order_release,
			memory_order_relaxed)) {
		LM_ERR("nats_rpc_slot_publish: slot %u not in CLAIMED "
			"state (observed %d)\n",
			s->slot_idx, expected);
		return -1;
	}
	return 0;
}

int nats_rpc_slot_abandon(nats_rpc_slot_t *s)
{
	int expected = NATS_RPC_SLOT_INFLIGHT;
	if (!s) return -1;
	(void)atomic_compare_exchange_strong_explicit(
			&s->state, &expected, NATS_RPC_SLOT_ABANDONED,
			memory_order_acq_rel,
			memory_order_acquire);
	/* expected now holds the observed-before value.  If the CAS
	 * succeeded the new state is ABANDONED; if it failed
	 * (typically because the consumer already wrote DELIVERED)
	 * the observed value is the live state and we return it. */
	return expected == NATS_RPC_SLOT_INFLIGHT
		? NATS_RPC_SLOT_ABANDONED
		: expected;
}

void nats_rpc_slot_free(nats_rpc_slot_t *s)
{
	if (!s) return;
	atomic_store_explicit(&s->state, NATS_RPC_SLOT_FREE,
		memory_order_release);
	atomic_fetch_sub_explicit(&g_inflight_count, 1,
		memory_order_relaxed);
}

/* ── lookup / accessors ──────────────────────────────────────── */

nats_rpc_slot_t *nats_rpc_slot_lookup(uint32_t slot_idx)
{
	if (!g_slots || slot_idx >= g_slot_total) return NULL;
	{
		nats_rpc_slot_t *s = &g_slots[slot_idx];
		int st = atomic_load_explicit(&s->state, memory_order_acquire);
		if (st == NATS_RPC_SLOT_FREE) return NULL;
		return s;
	}
}

uint32_t nats_rpc_slot_inflight_count(void)
{
	return atomic_load_explicit(&g_inflight_count, memory_order_relaxed);
}

uint32_t nats_rpc_slot_total_count(void)
{
	return g_slot_total;
}
