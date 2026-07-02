/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression: the msg-ref ack token packs (handle_idx, slot_idx, generation)
 * where the 16-bit generation only disambiguates slot reuse WITHIN one row
 * incarnation.  When a handle is unbound its ref row is freed
 * (purge_msg_ref_row) and a later bind of the SAME index calloc's a fresh row
 * with all generations reset to 0.  A worker that popped a message before the
 * unbind still holds an ack token from the OLD incarnation; if the reused index
 * lands a new message at the same slot with a colliding generation, the stale
 * ack redeems the NEW incarnation's message -> a cross-handle mis-ack (one
 * message wrongly acked/terminated, no memory corruption).
 *
 * Fix: persist a per-index generation seed across the row free.  purge saves
 * (max slot generation + 1) into g_row_gen_seed[idx]; ensure_row seeds every
 * slot of a re-allocated row from it, so a new incarnation's generations are
 * strictly greater than any generation a stale token could carry.
 *
 * Models ensure_row / store / purge / release:
 *   -DSIMULATE_NO_EPOCH -> generations reset to 0 on reuse -> the stale token
 *                          from incarnation 1 redeems incarnation 2's message
 *                          -> the "no mis-ack" assertion FAILS.
 *   (default)           -> seed persists -> the stale token is rejected.
 * plus a source-wiring assertion on the real nats_msg_ref.c.
 *
 * Build: cc -g -O0 -Wall -o test_msg_ref_gen_epoch test_msg_ref_gen_epoch.c
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

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* Mirror of msg_ref_slot_t / msg_ref_row_t (the fields the token depends on). */
typedef struct { int msg_id; uint16_t generation; uint16_t in_use; } t_slot;
typedef struct { uint32_t capacity; t_slot *slots; uint32_t next_slot; } t_row;

/* One handle index's row + its persistent generation seed. */
static t_row     g_row;
static uint16_t  g_seed;         /* persists across row free (the fix) */

static void t_ensure_row(uint32_t cap)
{
	uint32_t i;
	if (g_row.slots) return;
	g_row.slots = calloc(cap, sizeof(t_slot));
	g_row.capacity = cap;
	g_row.next_slot = 0;
#ifndef SIMULATE_NO_EPOCH
	for (i = 0; i < cap; i++)
		g_row.slots[i].generation = g_seed;   /* seed from the persistent value */
#else
	(void)i;                                   /* buggy: generations stay 0 */
#endif
}

/* Returns a packed token (slot<<16 | generation); stashes msg_id. */
static uint32_t t_store(uint32_t cap, int msg_id)
{
	uint32_t i;
	t_ensure_row(cap);
	for (i = 0; i < g_row.capacity; i++) {
		uint32_t idx = (g_row.next_slot + i) % g_row.capacity;
		t_slot *s = &g_row.slots[idx];
		if (!s->in_use) {
			s->msg_id = msg_id;
			s->in_use = 1;
			s->generation = (uint16_t)(s->generation + 1);
			g_row.next_slot = (idx + 1) % g_row.capacity;
			return (idx << 16) | s->generation;
		}
	}
	return 0;
}

/* Redeem a token: returns the msg_id if slot in_use and generation matches. */
static int t_release(uint32_t token)
{
	uint32_t idx = token >> 16;
	uint16_t gen = token & 0xFFFF;
	t_slot *s;
	if (!g_row.slots || idx >= g_row.capacity) return -1;
	s = &g_row.slots[idx];
	if (!s->in_use || s->generation != gen) return -1;
	return s->msg_id;
}

/* Purge (unbind): save the seed, then free the row. */
static void t_purge(void)
{
	uint32_t i;
	uint16_t maxg = 0;
	if (g_row.slots) {
		for (i = 0; i < g_row.capacity; i++)
			if (g_row.slots[i].generation > maxg)
				maxg = g_row.slots[i].generation;
		free(g_row.slots);
	}
	g_seed = (uint16_t)(maxg + 1);            /* persists across the free */
	g_row.slots = NULL; g_row.capacity = 0; g_row.next_slot = 0;
}

int main(void)
{
	uint32_t stale_token, new_token;

	memset(&g_row, 0, sizeof(g_row));
	g_seed = 0;

	/* Incarnation 1: bind index, store one message at slot 0 (gen 1). */
	stale_token = t_store(4, /*msg_id=*/1001);
	ASSERT(t_release(stale_token) == 1001, "incarnation-1 token redeems its own message");
	/* re-stash so the slot is in_use with a live token again (the worker
	 * popped it and holds the token but has NOT acked yet). */
	memset(&g_row, 0, sizeof(g_row)); g_seed = 0;
	stale_token = t_store(4, 1001);           /* slot 0, gen 1, still un-acked */

	/* Unbind index 1 -> purge (frees the row, saves the seed). */
	t_purge();

	/* Incarnation 2: SAME index rebound, one message at slot 0. */
	new_token = t_store(4, /*msg_id=*/2002);

	/* THE CONTRACT: the stale incarnation-1 token must NOT redeem
	 * incarnation-2's message. */
	ASSERT(t_release(stale_token) != 2002,
		"stale token from incarnation 1 does NOT mis-ack incarnation 2's message");
	/* the new token still works for its own message. */
	ASSERT(t_release(new_token) == 2002,
		"incarnation-2 token redeems its own message");

	/* ---- production wiring ---------------------------------------- */
	{
		const char *src = "../nats_msg_ref.c";
		ASSERT(file_contains(src, "g_row_gen_seed"),
			"nats_msg_ref.c persists a per-index generation seed");
		ASSERT(file_contains(src, "g_row_gen_seed[handle_idx]"),
			"ensure_row / purge key the seed by handle_idx");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
