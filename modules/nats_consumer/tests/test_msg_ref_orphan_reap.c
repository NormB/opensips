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
 * Regression test: the consumer process's msg-ref table reserves a slot
 * per pulled message (store_msg_ref, in_use=1) and frees it only when the
 * worker acks (release_msg_ref).  If a SIP worker dies after popping a
 * message but before acking, its slot stays in_use forever -- the natsMsg
 * leaks and, once the per-handle table fills, store_msg_ref reports "full"
 * and the handle stops delivering.
 *
 * Fix: stamp each slot with its claim time and reap slots older than a TTL
 * (the broker has long since redelivered the message, so the original ack
 * would be rejected anyway), destroying the natsMsg and freeing the slot.
 *
 * This mirrors the slot lifecycle (same pattern as test_msg_ref_teardown)
 * and adds the orphan reaper.
 *   -DSIMULATE_PREFIX_BUG -> no reaper: the orphaned slot's msg leaks
 *                            (live count stays > 0) -> assertions FAIL.
 *   (default)             -> reaper reclaims the orphan; a fresh slot is
 *                            left alone -> ALL PASS.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_msg_ref_orphan_reap \
 *       test_msg_ref_orphan_reap.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int g_live_msgs;
typedef struct fake_msg { int alive; } fake_msg;

static fake_msg *fake_msg_create(void)
{
	fake_msg *m = malloc(sizeof(*m));
	if (m) { m->alive = 1; g_live_msgs++; }
	return m;
}
static void fake_msg_destroy(fake_msg *m)
{
	if (!m) return;
	if (m->alive) g_live_msgs--;
	free(m);
}

/* Mirror of msg_ref_slot_t with the new claimed_at_us field. */
typedef struct {
	fake_msg  *msg;
	uint16_t   generation;
	uint16_t   in_use;
	long long  claimed_at_us;
} t_slot;

typedef struct {
	uint32_t capacity;
	t_slot  *slots;
	uint32_t next_slot;
} t_row;

static int t_store(t_row *row, uint32_t cap, fake_msg *m, long long now_us)
{
	uint32_t i, start;
	if (!row->slots) {
		row->slots = calloc(cap, sizeof(t_slot));
		if (!row->slots) return -1;
		row->capacity = cap;
	}
	start = row->next_slot;
	for (i = 0; i < row->capacity; i++) {
		uint32_t idx = (start + i) % row->capacity;
		t_slot *s = &row->slots[idx];
		if (!s->in_use) {
			s->msg = m; s->in_use = 1;
			s->generation = (uint16_t)(s->generation + 1);
			s->claimed_at_us = now_us;            /* THE fix: stamp claim */
			row->next_slot = (idx + 1) % row->capacity;
			return (int)idx;
		}
	}
	return -1;
}

static fake_msg *t_release(t_row *row, uint32_t idx)
{
	t_slot *s = &row->slots[idx];
	fake_msg *m;
	if (!s->in_use) return NULL;
	m = s->msg; s->msg = NULL; s->in_use = 0;
	return m;
}

/* Mirror of the orphan reaper: reclaim in_use slots older than ttl_us. */
static int t_reap(t_row *row, long long now_us, long long ttl_us)
{
#ifdef SIMULATE_PREFIX_BUG
	(void)row; (void)now_us; (void)ttl_us;
	return 0;                                  /* pre-fix: no reaper */
#else
	int reaped = 0;
	uint32_t i;
	if (!row->slots) return 0;
	for (i = 0; i < row->capacity; i++) {
		t_slot *s = &row->slots[i];
		if (s->in_use && (now_us - s->claimed_at_us) > ttl_us) {
			fake_msg_destroy(s->msg);
			s->msg = NULL; s->in_use = 0;
			s->generation = (uint16_t)(s->generation + 1);
			reaped++;
		}
	}
	return reaped;
#endif
}

int main(void)
{
	const long long TTL = 120LL * 1000000LL;   /* 120s in us */
	t_row row; memset(&row, 0, sizeof(row));

	/* A worker pulls a message (T=0) then dies without acking. */
	int idx = t_store(&row, 4, fake_msg_create(), 0);
	ASSERT(idx >= 0, "store reserves a slot");
	ASSERT(g_live_msgs == 1, "one message outstanding");

	/* Long after the TTL, the orphan must be reclaimed. */
	int n = t_reap(&row, TTL + 1, TTL);
	ASSERT(n == 1, "orphan slot older than TTL is reaped");
	ASSERT(g_live_msgs == 0, "orphaned natsMsg is destroyed (no leak)");
	ASSERT(!row.slots[idx].in_use, "reaped slot is free for reuse");

	/* A fresh slot within the TTL must NOT be reaped. */
	int idx2 = t_store(&row, 4, fake_msg_create(), 1000LL * 1000000LL);
	ASSERT(idx2 >= 0 && g_live_msgs == 1, "second message stored");
	n = t_reap(&row, 1000LL * 1000000LL + TTL / 2, TTL);   /* age = TTL/2 */
	ASSERT(n == 0, "fresh slot (within TTL) is not reaped");
	ASSERT(g_live_msgs == 1, "fresh message left intact");

	/* Normal ack releases it (and the caller destroys the msg). */
	fake_msg *m = t_release(&row, idx2);
	ASSERT(m != NULL, "release returns the message");
	fake_msg_destroy(m);
	ASSERT(g_live_msgs == 0, "released message destroyed normally");

	free(row.slots);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
