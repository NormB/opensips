/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Silent message loss after a stream re-create (found by
 * test_reconnect.sh, which had been failing as an unread "environment
 * baseline" -- the failure was REAL):
 *
 * The rebuild path's anti-replay bias recreates a vanished durable
 * with DeliverByStartSequence(last_stream_seq + 1) so a
 * deliver_policy=all consumer does not replay the whole stream.  But
 * the watermark is only meaningful for the SAME stream incarnation:
 * if the broker lost the stream since we last delivered (restart on
 * memory storage, operator rm + re-create, backup restore), sequences
 * restart at 1 and the stale resume point SILENTLY SKIPS every new
 * message until the new sequence grows past the old watermark.
 *
 * Fix contract, locked here:
 *
 *   - the successful-subscribe path stamps the stream incarnation
 *     (jsStreamInfo.Created, ns since epoch) on the proc-sub state;
 *   - the rebuild bias applies ONLY when the current stream's Created
 *     matches the stamped incarnation (nats_rebuild_bias_stale());
 *   - on mismatch the watermark is dropped (WARN) and the recreate
 *     falls back to the configured deliver policy -- replay-from-
 *     start is CORRECT for a recreated stream;
 *   - unknown incarnations (either side 0: pre-fix state, or
 *     GetStreamInfo failed) keep the old bias behavior.
 *
 * The end-to-end behavior is pinned by tests/test_reconnect.sh
 * (publish -> broker restart wipes the memory-storage stream ->
 * re-create stream -> publish again -> delivered counter must grow).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nats_consumer_proc_internal.h"

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long n;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
	buf = malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	buf[n] = '\0';
	fclose(f);
	return buf;
}

int main(void)
{
	/* ── the pure incarnation decision ───────────────────────── */
	ASSERT(nats_rebuild_bias_stale(1000, 2000) == 1,
		"different Created => stream recreated => watermark stale");
	ASSERT(nats_rebuild_bias_stale(2000, 1000) == 1,
		"backwards Created is also a different incarnation");
	ASSERT(nats_rebuild_bias_stale(1500, 1500) == 0,
		"same Created => same incarnation => bias valid");
	ASSERT(nats_rebuild_bias_stale(0, 1500) == 0,
		"no stamped incarnation (pre-fix state) keeps the old bias");
	ASSERT(nats_rebuild_bias_stale(1500, 0) == 0,
		"unknown current incarnation (info failed) keeps the old bias");
	ASSERT(nats_rebuild_bias_stale(0, 0) == 0,
		"both unknown keeps the old bias");

	/* ── production wiring ───────────────────────────────────── */
	{
		char *src = slurp("../nats_sub_config.c");
		ASSERT(src != NULL, "nats_sub_config.c readable");
		if (src) {
			ASSERT(strstr(src, "nats_rebuild_bias_stale(") != NULL,
				"the rebuild bias consults the incarnation check");
			ASSERT(strstr(src, "js_GetStreamInfo") != NULL,
				"the current stream incarnation is fetched");
			ASSERT(strstr(src, "stream_created_ns") != NULL,
				"the subscribe path stamps the incarnation");
			free(src);
		}
	}
	{
		char *hdr = slurp("../nats_consumer_proc_internal.h");
		ASSERT(hdr && strstr(hdr, "stream_created_ns") != NULL,
			"proc-sub state carries the stamped incarnation");
		free(hdr);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
