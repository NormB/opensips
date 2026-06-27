/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TU-split test (NATS_TODO #60, cachedb_nats half):
 *
 *   cachedb_nats_json.c (3597 lines) is split into focused TUs:
 *     - cachedb_nats_json_index.c   — search index, revmap, build/rebuild
 *     - cachedb_nats_json_ser.c     — JSON escape, sink, dict serializer,
 *                                     KV key encoding, seed-doc builder
 *     - cachedb_nats_json_rowmeta.c — usrloc row metadata: row_exp /
 *                                     schema_version denormalization (P2)
 *     - cachedb_nats_json.c         — cachedb query() + update() callbacks
 *   with cachedb_nats_json_internal.h carrying the cross-TU private
 *   declarations (json_sink_t, parse helpers, shard-lock inlines).
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
	const char *IDX = "../cachedb_nats_json_index.c";
	const char *SER = "../cachedb_nats_json_ser.c";
	const char *RM  = "../cachedb_nats_json_rowmeta.c";
	const char *QU  = "../cachedb_nats_json.c";
	const char *INT = "../cachedb_nats_json_internal.h";

	/* --- index TU owns index lifecycle + revmap --- */
	ASSERT(file_contains(IDX, "int nats_json_index_init(void)"),
		"index TU defines nats_json_index_init");
	ASSERT(file_contains(IDX, "int nats_json_index_rebuild(kvStore *kv"),
		"index TU defines nats_json_index_rebuild");
	ASSERT(file_contains(IDX, "static void nats_rev_put"),
		"index TU owns the doc-key reverse map");
	ASSERT(file_contains(IDX, "void nats_json_index_destroy(void)"),
		"index TU defines nats_json_index_destroy");

	/* --- serializer TU owns escape/sink/encode --- */
	ASSERT(file_contains(SER, "_sink_emit_cdb_dict"),
		"ser TU owns the cdb-dict sink serializer");
	ASSERT(file_contains(SER, "char *_kv_encode_key"),
		"ser TU owns _kv_encode_key");
	ASSERT(file_contains(SER, "char *_build_seed_doc"),
		"ser TU owns _build_seed_doc");

	/* --- rowmeta TU owns the usrloc row-metadata denormalization --- */
	ASSERT(file_contains(RM, "char *_row_finalize_metadata"),
		"rowmeta TU owns _row_finalize_metadata");
	ASSERT(file_contains(RM, "static int64_t _row_exp_min"),
		"rowmeta TU owns _row_exp_min");

	/* --- query+update remain in cachedb_nats_json.c --- */
	ASSERT(file_contains(QU, "int nats_cache_query(cachedb_con *con"),
		"query callback stays in cachedb_nats_json.c");
	ASSERT(file_contains(QU, "int nats_cache_update(cachedb_con *con"),
		"update callback stays in cachedb_nats_json.c");

	/* --- and the monolith no longer carries the moved sections --- */
	ASSERT(!file_contains(QU, "int nats_json_index_init(void)"),
		"index lifecycle moved out of cachedb_nats_json.c");
	ASSERT(!file_contains(QU, "} json_sink_t;"),
		"sink type moved out of cachedb_nats_json.c");
	ASSERT(!file_contains(QU, "static void nats_rev_put"),
		"revmap moved out of cachedb_nats_json.c");
	ASSERT(!file_contains(QU, "char *_row_finalize_metadata"),
		"row metadata moved out of cachedb_nats_json.c");

	/* --- shared private surface lives in the internal header --- */
	ASSERT(file_contains(INT, "} json_sink_t;"),
		"internal header carries json_sink_t");
	ASSERT(file_contains(INT, "extern nats_search_idx *g_idx;"),
		"internal header exposes g_idx to the query/update TU");
	ASSERT(file_contains(INT, "static inline void _idx_lock_shard"),
		"internal header carries the shard-lock inlines");

	/* --- the split actually shrank things; cap each TU --- */
	int n_idx = line_count(IDX), n_ser = line_count(SER),
	    n_rm = line_count(RM), n_qu = line_count(QU);
	fprintf(stderr, "  (lines: index=%d ser=%d rowmeta=%d query+update=%d)\n",
		n_idx, n_ser, n_rm, n_qu);
	ASSERT(n_idx > 0 && n_idx < 2100, "index TU under 2100 lines");
	ASSERT(n_ser > 0 && n_ser < 800, "ser TU under 800 lines");
	/* rowmeta owns all 7 P2 row-semantic transforms (row_exp, NUL reject,
	 * last_mod int64, poison classify, private-key strip, write hygiene, cseq
	 * ordering).  Cap 900 (raised from the initial 800 as P2 filled it out) —
	 * still far under the query+update TU's 1600 and the index TU's 2100, so it
	 * remains a real anti-monolith guard; if it approaches the cap again, split
	 * read-side vs write-side transforms into two TUs. */
	ASSERT(n_rm > 0 && n_rm < 900, "rowmeta TU under 900 lines");
	/* Cap 1650 (raised from 1600 for the P8 R4 empty-value-marker re-create
	 * branch in _update_fetch_or_seed).  P8's TTL write/activation logic lives
	 * in cachedb_nats_ttl_put.c, NOT here, to keep this TU bounded. */
	ASSERT(n_qu > 0 && n_qu < 1650, "query+update TU under 1650 lines");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
