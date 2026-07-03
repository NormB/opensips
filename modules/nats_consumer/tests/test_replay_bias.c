/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: when a durable JetStream consumer vanished (deleted /
 * GC'd server-side) and was recreated, ensure_subscription_for_handle()
 * re-applied the configured deliver_policy verbatim.  With
 * deliver_policy=all that meant the recreated consumer replayed the ENTIRE
 * stream from sequence 1 -- a flood proportional to stream size, dumped
 * onto the worker ring.  Fix: track the high-water delivered stream
 * sequence per sub (survives the rebuild) and, on a rebuild that would
 * replay-from-start, WARN and bias the recreate to resume just past it.
 *
 * Carries the bias decision and checks the production wiring.
 *   -DSIMULATE_PREFIX_BUG -> no bias (always replay) -> the rebuild
 *                            assertions FAIL.
 *   (default)             -> rebuild-from-all biases to start_seq -> PASS.
 *
 * Build:
 *   gcc -g -O0 -Wall -o test_replay_bias test_replay_bias.c
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

enum { POL_ALL, POL_NEW, POL_LAST, POL_BY_SEQ };

/* carried copy of the recreate bias decision. *out_seq is meaningful only
 * when the returned policy is POL_BY_SEQ. */
static int replay_bias(int is_rebuild, uint64_t last_seq, int policy,
	uint64_t *out_seq)
{
	*out_seq = 0;
#ifndef SIMULATE_PREFIX_BUG
	if (is_rebuild && last_seq > 0 && policy == POL_ALL) {
		*out_seq = last_seq + 1;
		return POL_BY_SEQ;
	}
#else
	(void)is_rebuild; (void)last_seq;
#endif
	return policy;
}

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return 0;
	char line[2048]; int hit = 0;
	while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) { hit = 1; break; }
	fclose(f); return hit;
}
static int grep_in_function(const char *path, const char *fn, const char *needle)
{
	FILE *f = fopen(path, "r"); if (!f) return -1;
	char line[2048]; int hits=0, seen=0, in=0; char m[256];
	snprintf(m, sizeof(m), "%s(", fn);
	while (fgets(line, sizeof(line), f)) {
		if (in) { if (line[0]=='}'){in=0;seen=0;continue;} if (strstr(line,needle)) hits++; continue; }
		if (seen) { if (strchr(line,';')){seen=0;continue;} if (strchr(line,'{')){in=1;continue;} continue; }
		if (strstr(line,m)) { seen=1; if (strchr(line,';')) seen=0; else if (strchr(line,'{')){in=1;seen=0;} }
	}
	fclose(f); return hits;
}

int main(void)
{
	uint64_t seq;

	/* rebuild of a from-start consumer that has delivered: bias to resume */
	ASSERT(replay_bias(1, 100, POL_ALL, &seq) == POL_BY_SEQ && seq == 101,
		"rebuild + deliver_all + delivered -> resume at last_seq+1");

	/* first build (not a rebuild): no bias, honour deliver_all */
	ASSERT(replay_bias(0, 0, POL_ALL, &seq) == POL_ALL,
		"first build keeps deliver_all (initial drain is intended)");

	/* rebuild but nothing delivered yet: no bias */
	ASSERT(replay_bias(1, 0, POL_ALL, &seq) == POL_ALL,
		"rebuild with nothing delivered keeps deliver_all");

	/* rebuild of a non-replay policy: untouched */
	ASSERT(replay_bias(1, 100, POL_NEW, &seq) == POL_NEW,
		"rebuild of deliver_new is not rewritten");

	/* production wiring */
	{
		/* After the proc-TU split: the sub-state typedef (and
		 * its last_stream_seq field) lives in the internal header;
		 * ensure_subscription_for_handle in the sub-config TU. */
		const char *p = "../nats_consumer_proc_internal.h";
		const char *sub = "../nats_sub_config.c";
		ASSERT(file_contains(p, "last_stream_seq"),
			"sub state tracks the high-water stream sequence");
		/* the config matrix (and the bias) now lives in the
		 * build_consumer_config helper extracted from
		 * ensure_subscription_for_handle */
		ASSERT(grep_in_function(sub, "build_consumer_config",
			"js_DeliverByStartSequence") >= 1,
			"recreate biases deliver_all to start-sequence");
		ASSERT(grep_in_function(sub, "build_consumer_config",
			"NATS_DELIVER_ALL") >= 1,
			"bias is gated on deliver_policy=all");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
