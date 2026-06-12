/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TU-split test (NATS_TODO #60, nats_consumer half):
 *
 *   nats_consumer_proc.c (2220 lines) is split into three focused TUs:
 *     - nats_msg_ref.c         — process-local natsMsg ref table
 *                                (store / release / orphan reap)
 *     - nats_sub_config.c      — subscription config + lifecycle
 *                                (CSV parsing, ensure_subscription,
 *                                reconcile)
 *     - nats_consumer_proc.c   — the consumer proc main loop
 *                                (fetch sweep, ack drain, teardown)
 *   with nats_consumer_proc_internal.h carrying the cross-TU private
 *   declarations (proc_sub_state_t, msg-ref types, shared globals).
 *
 * Structural test: asserts each TU owns its section, the monolith no
 * longer carries the moved code, and every TU is under a line cap so
 * the split cannot silently regress into a new monolith.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

static int line_count(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	int n = 0, c;
	while ((c = fgetc(f)) != EOF)
		if (c == '\n') n++;
	fclose(f);
	return n;
}

int main(void)
{
	const char *REF = "../nats_msg_ref.c";
	const char *SUB = "../nats_sub_config.c";
	const char *PRC = "../nats_consumer_proc.c";
	const char *INT = "../nats_consumer_proc_internal.h";

	/* --- msg-ref TU owns the natsMsg ref table --- */
	ASSERT(file_contains(REF, "uint64_t store_msg_ref"),
		"msg-ref TU defines store_msg_ref");
	ASSERT(file_contains(REF, "natsMsg *release_msg_ref"),
		"msg-ref TU defines release_msg_ref");
	ASSERT(file_contains(REF, "int reap_orphan_msg_refs(void)"),
		"msg-ref TU defines reap_orphan_msg_refs");
	ASSERT(file_contains(REF, "msg_ref_row_t g_msg_refs["),
		"msg-ref TU owns the g_msg_refs table");

	/* --- sub-config TU owns subscription configuration --- */
	ASSERT(file_contains(SUB, "int ensure_subscription_for_handle(nats_handle_t *h)"),
		"sub-config TU defines ensure_subscription_for_handle");
	ASSERT(file_contains(SUB, "int reconcile_subs_cb(nats_handle_t *h, void *user)"),
		"sub-config TU defines reconcile_subs_cb");
	ASSERT(file_contains(SUB, "static int parse_backoff_csv"),
		"sub-config TU owns the backoff CSV parser");
	ASSERT(file_contains(SUB, "static int parse_filters_csv"),
		"sub-config TU owns the filters CSV parser");

	/* --- the proc loop stays in nats_consumer_proc.c --- */
	ASSERT(file_contains(PRC, "void nats_consumer_proc_main(int rank)"),
		"proc main stays in nats_consumer_proc.c");
	ASSERT(file_contains(PRC, "static int pull_one_batch"),
		"fetch sweep stays in nats_consumer_proc.c");
	ASSERT(file_contains(PRC, "static void tear_down_retired_subs(void)"),
		"retired-sub teardown stays in nats_consumer_proc.c");

	/* --- and the monolith no longer carries the moved sections --- */
	ASSERT(!file_contains(PRC, "uint64_t store_msg_ref"),
		"msg-ref table moved out of nats_consumer_proc.c");
	ASSERT(!file_contains(PRC, "parse_backoff_csv(const str *csv"),
		"CSV parsing moved out of nats_consumer_proc.c");
	ASSERT(!file_contains(PRC, "} proc_sub_state_t;"),
		"proc_sub_state_t moved out of nats_consumer_proc.c");

	/* --- shared private surface lives in the internal header --- */
	ASSERT(file_contains(INT, "} proc_sub_state_t;"),
		"internal header carries proc_sub_state_t");
	ASSERT(file_contains(INT, "} msg_ref_row_t;"),
		"internal header carries msg_ref_row_t");
	ASSERT(file_contains(INT, "extern proc_sub_state_t *g_subs;"),
		"internal header exposes g_subs");

	/* --- the split actually shrank things; cap each TU --- */
	int n_ref = line_count(REF), n_sub = line_count(SUB),
	    n_prc = line_count(PRC);
	fprintf(stderr, "  (lines: msg_ref=%d sub_config=%d proc=%d)\n",
		n_ref, n_sub, n_prc);
	ASSERT(n_ref > 0 && n_ref < 400, "msg-ref TU under 400 lines");
	ASSERT(n_sub > 0 && n_sub < 1000, "sub-config TU under 1000 lines");
	ASSERT(n_prc > 0 && n_prc < 1400, "proc TU under 1400 lines");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
