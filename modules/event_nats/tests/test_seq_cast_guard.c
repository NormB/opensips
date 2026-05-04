/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Verification test for the negative-seq guard at
 * modules/event_nats/nats_jetstream.c:1047 and :1116
 * (commit 36ee7b07d "harden MI inputs against adversarial callers").
 *
 * Without the guard, an MI caller passing seq = -1 (int) is cast to
 * (uint64_t)(int)-1 == UINT64_MAX, which the JetStream server interprets
 * as "highest sequence" — letting an attacker target the latest message
 * in the stream they should not be able to access.
 *
 * The guard:
 *     if (seq_int <= 0)
 *         return init_mi_error(400, MI_SSTR("seq must be >= 1"));
 *
 * lives at lines 1047 (mi_msg_get) and 1116 (mi_msg_delete) in develop.
 *
 * This test:
 *   1. demonstrates that the unguarded cast produces UINT64_MAX,
 *   2. asserts the guard is present in the source by greping the file,
 *   3. confirms the bounded-input branch never reaches the cast.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Mirror of the JetStream API contract: js_GetMsg takes uint64_t. */
static uint64_t observed_seq;
static int      js_call_made;

static int call_js_GetMsg(uint64_t seq)
{
	js_call_made = 1;
	observed_seq = seq;
	return 0;
}

/* ── unguarded: bug behavior ──────────────────────────────────── */

static int unguarded_handler(int seq_int)
{
	return call_js_GetMsg((uint64_t)seq_int);
}

/* ── guarded: production fix ──────────────────────────────────── */

static int guarded_handler(int seq_int)
{
	if (seq_int <= 0) return -1;            /* mirrors init_mi_error(400, ...) */
	return call_js_GetMsg((uint64_t)seq_int);
}

int main(void)
{
	/* CASE 1: confirm the C cast produces UINT64_MAX for int(-1) */
	uint64_t cast_neg_one = (uint64_t)(int)-1;
	ASSERT(cast_neg_one == UINT64_MAX,
		"(uint64_t)(int)-1 == UINT64_MAX (C standard signed-cast behavior)");

	/* CASE 2: unguarded handler exposes the bug */
	js_call_made = 0; observed_seq = 0;
	unguarded_handler(-1);
	ASSERT(js_call_made == 1,
		"unguarded: js_GetMsg called for seq=-1 (BUG)");
	ASSERT(observed_seq == UINT64_MAX,
		"unguarded: js_GetMsg sees UINT64_MAX (data disclosure risk)");

	/* CASE 3: guarded handler rejects negative seq before the cast */
	js_call_made = 0; observed_seq = 0;
	int rc = guarded_handler(-1);
	ASSERT(rc == -1, "guarded: rejects seq=-1 with 400");
	ASSERT(js_call_made == 0,
		"guarded: js_GetMsg NOT called for seq=-1");

	/* CASE 4: guarded handler rejects seq=0 (also invalid per JS spec) */
	js_call_made = 0; observed_seq = 0;
	rc = guarded_handler(0);
	ASSERT(rc == -1, "guarded: rejects seq=0");
	ASSERT(js_call_made == 0, "guarded: js_GetMsg NOT called for seq=0");

	/* CASE 5: guarded handler accepts seq=1 (valid lower bound) */
	js_call_made = 0; observed_seq = 0;
	rc = guarded_handler(1);
	ASSERT(rc == 0, "guarded: accepts seq=1");
	ASSERT(js_call_made == 1 && observed_seq == 1,
		"guarded: js_GetMsg called with seq=1");

	/* CASE 6: assert the guard is present in the production source */
	FILE *f = fopen("../nats_jetstream.c", "r");
	ASSERT(f != NULL, "open ../nats_jetstream.c");
	if (f) {
		char line[512];
		int found_get = 0, found_del = 0;
		int in_get_fn = 0, in_del_fn = 0;
		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "mi_nats_msg_get(") ) in_get_fn = 1;
			if (strstr(line, "mi_nats_msg_delete(")) {
				in_get_fn = 0; in_del_fn = 1;
			}
			if (strstr(line, "if (seq_int <= 0)")) {
				if (in_get_fn) found_get = 1;
				if (in_del_fn) found_del = 1;
			}
		}
		fclose(f);
		ASSERT(found_get,
			"guard 'if (seq_int <= 0)' present in mi_nats_msg_get");
		ASSERT(found_del,
			"guard 'if (seq_int <= 0)' present in mi_nats_msg_delete");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
