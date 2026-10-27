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
 * Regression test for the msg-ref leak in tear_down_retired_subs()
 * (nats_consumer_proc.c).
 *
 * Bug: when a handle is unbound while messages have been pushed to its
 * ring but not yet acked, the outstanding natsMsg* live in the
 * process-local g_msg_refs[handle_idx].slots[*].msg table.  They are
 * normally released + destroyed on the ack-drain path
 * (release_msg_ref + nats_dl.natsMsg_Destroy).  The retire teardown
 * destroyed the subscription and freed the proc_sub_state_t strings but
 * never walked g_msg_refs[handle_idx] -- so every in-use natsMsg AND the
 * calloc'd slots buffer leaked.  Because handle_idx is monotonic and
 * never reused, the row stayed orphaned for the process lifetime.
 *
 * Fix: tear_down_retired_subs now scans g_msg_refs[ss->handle_idx],
 * natsMsg_Destroy's every in-use slot, frees the row's slots buffer, and
 * zeroes the row.
 *
 * This test proves both halves:
 *   (1) behavioural -- a faithful re-implementation of the msg-ref row
 *       lifecycle (mirroring ensure_row / store_msg_ref / release_msg_ref
 *       and the new teardown walk) shows that, after teardown, every
 *       outstanding message is destroyed exactly once and the slots
 *       buffer is freed.  A control using the OLD (no-walk) teardown
 *       leaks both.
 *   (2) source-structure -- the real tear_down_retired_subs body in
 *       ../nats_consumer_proc.c walks g_msg_refs, calls natsMsg_Destroy
 *       on in-use slots, and free()s the row.
 *
 * Self-contained; run from the tests/ directory (reads
 * ../nats_consumer_proc.c).  nats_consumer_proc.c itself cannot be
 * compiled under the test shim because it pulls in <nats/nats.h> and the
 * nats_dl libnats glue, so the behavioural half re-implements the row
 * semantics verbatim and the source half pins the assertion to the real
 * function body.
 *
 * Build: cc -g -O0 -Wall -o test_msg_ref_teardown test_msg_ref_teardown.c
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

/* ---- (1) behavioural: msg-ref row lifecycle + teardown walk ---- */

/* Stand-in for libnats' natsMsg.  We count live allocations so the test
 * can prove the teardown destroys every outstanding message exactly
 * once (no leak, no double-free). */
static int g_live_msgs;

typedef struct fake_msg { int alive; } fake_msg;

static fake_msg *fake_msg_create(void)
{
	fake_msg *m = malloc(sizeof(*m));
	if (m) { m->alive = 1; g_live_msgs++; }
	return m;
}

/* Mirror of nats_dl.natsMsg_Destroy semantics for the test. */
static void fake_msg_destroy(fake_msg *m)
{
	if (!m) return;
	if (m->alive) g_live_msgs--;   /* a double-free would underflow */
	free(m);
}

/* Mirror of msg_ref_slot_t / msg_ref_row_t from nats_consumer_proc.c. */
typedef struct {
	fake_msg *msg;
	uint16_t  generation;
	uint16_t  in_use;
} t_slot;

typedef struct {
	uint32_t capacity;     /* 0 == row not allocated yet */
	t_slot  *slots;        /* [capacity] */
	uint32_t next_slot;
} t_row;

/* mirror of ensure_row() */
static int t_ensure_row(t_row *row, uint32_t capacity)
{
	if (row->slots)
		return 0;
	row->slots = calloc(capacity, sizeof(t_slot));
	if (!row->slots)
		return -1;
	row->capacity  = capacity;
	row->next_slot = 0;
	return 0;
}

/* mirror of store_msg_ref(): reserve a slot, stash the msg. */
static int t_store(t_row *row, uint32_t capacity, fake_msg *m)
{
	uint32_t i, start;
	if (t_ensure_row(row, capacity) < 0)
		return -1;
	start = row->next_slot;
	for (i = 0; i < row->capacity; i++) {
		uint32_t idx = (start + i) % row->capacity;
		t_slot *slot = &row->slots[idx];
		if (!slot->in_use) {
			slot->msg        = m;
			slot->in_use     = 1;
			slot->generation = (uint16_t)(slot->generation + 1);
			row->next_slot   = (idx + 1) % row->capacity;
			return (int)idx;
		}
	}
	return -1;   /* full */
}

/* mirror of release_msg_ref() on the ack path (frees one slot). */
static fake_msg *t_release(t_row *row, uint32_t idx)
{
	t_slot *slot;
	fake_msg *m;
	if (!row->slots || idx >= row->capacity)
		return NULL;
	slot = &row->slots[idx];
	if (!slot->in_use)
		return NULL;
	m = slot->msg;
	slot->msg    = NULL;
	slot->in_use = 0;
	return m;
}

/* mirror of the NEW teardown walk added to tear_down_retired_subs(). */
static void t_teardown_fixed(t_row *row)
{
	if (row->slots) {
		uint32_t i;
		for (i = 0; i < row->capacity; i++) {
			t_slot *slot = &row->slots[i];
			if (slot->in_use && slot->msg) {
				fake_msg_destroy(slot->msg);
				slot->msg    = NULL;
				slot->in_use = 0;
			}
		}
		free(row->slots);
	}
	row->slots     = NULL;
	row->capacity  = 0;
	row->next_slot = 0;
}

/* mirror of the OLD (buggy) teardown -- it never touched g_msg_refs. */
static void t_teardown_buggy(t_row *row)
{
	(void)row;   /* leaks both the messages and the slots buffer */
}

static void test_teardown_destroys_outstanding(void)
{
	t_row row = {0};
	int idx_acked, idx_outstanding;
	fake_msg *m0, *m1, *m2;

	g_live_msgs = 0;

	/* Three messages pushed to the ring => three live natsMsgs in the
	 * row.  One is later acked (released + destroyed normally); two
	 * remain outstanding at unbind time. */
	m0 = fake_msg_create();
	m1 = fake_msg_create();
	m2 = fake_msg_create();
	ASSERT(g_live_msgs == 3, "three messages created");

	idx_acked       = t_store(&row, 4, m0);
	idx_outstanding = t_store(&row, 4, m1);
	(void)t_store(&row, 4, m2);
	ASSERT(idx_acked >= 0 && idx_outstanding >= 0, "slots reserved");

	/* Worker acks m0 -> released + destroyed via the ack path. */
	fake_msg_destroy(t_release(&row, (uint32_t)idx_acked));
	ASSERT(g_live_msgs == 2, "acked message destroyed; two still outstanding");

	/* Handle is unbound: the FIXED teardown must destroy the two
	 * outstanding messages AND free the slots buffer. */
	t_teardown_fixed(&row);
	ASSERT(g_live_msgs == 0,
		"FIXED teardown destroys every outstanding natsMsg (no leak)");
	ASSERT(row.slots == NULL && row.capacity == 0,
		"FIXED teardown frees + zeroes the row");
}

static void test_buggy_teardown_leaks_control(void)
{
	t_row row = {0};
	fake_msg *m0, *m1;

	g_live_msgs = 0;
	m0 = fake_msg_create();
	m1 = fake_msg_create();
	(void)t_store(&row, 4, m0);
	(void)t_store(&row, 4, m1);
	ASSERT(g_live_msgs == 2, "control: two outstanding messages");

	/* The original code path: teardown does nothing to the row. */
	t_teardown_buggy(&row);
	ASSERT(g_live_msgs == 2,
		"control: OLD teardown leaks the outstanding messages "
		"(this is the bug the fix repairs)");
	ASSERT(row.slots != NULL,
		"control: OLD teardown leaks the slots buffer");

	/* clean up the deliberately-leaked control so the test itself is
	 * leak-free under valgrind/ASan. */
	t_teardown_fixed(&row);
	ASSERT(g_live_msgs == 0, "control cleanup destroys the leaked messages");
}

/* ---- (2) source-structure assertions on the real function ---- */

static char *extract_func_body(const char *path, const char *funcname)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[n] = '\0';

	char *p = buf, *body = NULL;
	size_t flen = strlen(funcname);
	while ((p = strstr(p, funcname)) != NULL) {
		char *q = p + flen;
		/* Require a word boundary before the name so a search for
		 * "proc_fetch_batch" does not match inside "eff_fetch_batch". */
		if (p != buf) {
			char c = p[-1];
			if (c == '_' || (c >= 'a' && c <= 'z') ||
			    (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				p += flen;
				continue;
			}
		}
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '(') { p += flen; continue; }
		char *brace = q;
		while (*brace && *brace != '{' && *brace != ';') brace++;
		if (*brace != '{') { p += flen; continue; }
		int depth = 0; char *s = brace;
		for (; *s; s++) {
			if (*s == '{') depth++;
			else if (*s == '}') { depth--; if (depth == 0) { s++; break; } }
		}
		size_t blen = (size_t)(s - brace);
		body = malloc(blen + 1);
		if (body) { memcpy(body, brace, blen); body[blen] = '\0'; }
		break;
	}
	free(buf);
	return body;
}

static void test_source_structure(void)
{
	/* The purge walk lives in a shared helper purge_msg_ref_row()
	 * (nats_msg_ref.c) so EVERY subscription-destroy site reuses the same
	 * teardown -- destroying outstanding natsMsg* whose msg->sub is about
	 * to be freed.  A site that destroys the sub but skips the purge leaves
	 * a dangling msg->sub for a later ack to deref (UAF). */
	char *purge = extract_func_body("../nats_msg_ref.c", "purge_msg_ref_row");

	ASSERT(purge != NULL, "found purge_msg_ref_row body in nats_msg_ref.c");
	if (purge) {
		ASSERT(strstr(purge, "g_msg_refs[") != NULL,
			"purge walks the handle's msg-ref row g_msg_refs[handle_idx]");
		ASSERT(strstr(purge, "natsMsg_Destroy") != NULL,
			"purge destroys outstanding natsMsg* via natsMsg_Destroy");
		ASSERT(strstr(purge, "->in_use") != NULL,
			"purge only destroys in-use slots");
		ASSERT(strstr(purge, "free(row->slots)") != NULL,
			"purge frees the row's slots buffer");
		ASSERT(strstr(purge, "row->slots") != NULL &&
		       strstr(purge, "NULL") != NULL,
			"purge zeroes the row (slots pointer cleared)");
		free(purge);
	}

	/* All THREE subscription-destroy sites must invoke the purge helper so
	 * a later ack of an outstanding natsMsg can never deref a freed sub. */
	{
		const char *src = "../nats_consumer_proc.c";
		const char *sites[] = {
			"tear_down_retired_subs",   /* retire teardown */
			"proc_fetch_batch",             /* vanished/GC'd consumer destroy */
			"nats_consumer_proc_main",  /* reconnect-epoch sub refresh */
		};
		size_t i;
		for (i = 0; i < sizeof(sites) / sizeof(sites[0]); i++) {
			char msg[256];
			char *body = extract_func_body(src, sites[i]);
			ASSERT(body != NULL, sites[i]);
			if (body) {
				snprintf(msg, sizeof(msg),
					"%s calls purge_msg_ref_row after destroying the sub",
					sites[i]);
				ASSERT(strstr(body, "purge_msg_ref_row") != NULL, msg);
				free(body);
			}
		}
	}
}

int main(void)
{
	test_teardown_destroys_outstanding();
	test_buggy_teardown_leaks_control();
	test_source_structure();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
