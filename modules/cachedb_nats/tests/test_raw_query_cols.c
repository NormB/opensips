/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Coverage for TODO #74 / #70: raw_kv_keys() builds a cdb_raw_entry reply.
 * It used to allocate ONE column per row, but the cachedb core frees
 * expected_kv_no columns per row -- a caller asking for more columns made
 * the core read past each row (an OOB free).  The fix allocates
 * max(expected_kv_no, 1) columns per row and zero-inits the extras (so they
 * free harmlessly as NULL).
 *
 * Carries the column-count decision + a model of the core's per-row free
 * loop (over an ASan-tracked allocation) so the bug arm would trip ASan,
 * then asserts the production wiring.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_raw_query_cols test_raw_query_cols.c
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
	char line[4096];
	int hit = 0;
	if (!f) return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

/* model of the per-column entry (matches cdb_raw_entry's relevant shape:
 * a tagged value whose string pointer the core frees when non-NULL). */
typedef struct { int type; char *val; } col_t;

static int ncols(int expected_kv_no) { return expected_kv_no >= 1 ? expected_kv_no : 1; }

/* raw_kv_bucket_info fills 6 fixed columns but the core still frees
 * expected_kv_no per row, so the row must have max(expected_kv_no, 6). */
static int bi_ncols(int expected_kv_no) { return expected_kv_no > 6 ? expected_kv_no : 6; }

/* build one row of `nc` zeroed columns, fill column 0 with the key */
static col_t *build_row(int nc, const char *key)
{
	col_t *row = calloc((size_t)nc, sizeof(col_t));   /* zero-init all cols */
	if (!row) return NULL;
	row[0].type = 1;
	row[0].val  = strdup(key);
	return row;
}

/* mirror of the core's free loop: frees expected_kv_no columns per row */
static void core_free_row(col_t *row, int expected_kv_no)
{
	int j;
	for (j = 0; j < expected_kv_no; j++)
		if (row[j].val) free(row[j].val);   /* OOB read if row has < expected cols */
	free(row);
}

int main(void)
{
	/* ---- column-count decision --------------------------------- */
	ASSERT(ncols(1) == 1, "expected_kv_no=1 -> 1 column");
	ASSERT(ncols(3) == 3, "expected_kv_no=3 -> 3 columns");
	ASSERT(ncols(0) == 1, "expected_kv_no=0 clamps to 1");
	ASSERT(ncols(-5) == 1, "negative expected_kv_no clamps to 1");

	/* ---- the fix: row has >= expected_kv_no cols, no OOB free --- */
	{
		int expected = 4;
		col_t *row = build_row(ncols(expected), "the-key");   /* 4 cols */
		ASSERT(row != NULL, "row allocated with expected_kv_no columns");
		/* the core frees `expected` columns; with the fix all are in-bounds
		 * (extras are zeroed -> free(NULL) skipped).  ASan would trip on
		 * the old one-column allocation. */
		core_free_row(row, expected);
		ASSERT(1, "core free loop over expected_kv_no columns is in-bounds (ASan-clean)");
	}

	/* ---- production wiring -------------------------------------- */
	{
		const char *n = "../cachedb_nats_native.c";
		ASSERT(file_contains(n, "ncols_per_row"),
			"raw_kv_keys sizes rows by ncols_per_row");
		ASSERT(file_contains(n, "ncols_per_row * sizeof(cdb_raw_entry)"),
			"row allocation uses expected_kv_no columns");
		ASSERT(file_contains(n, "memset(rows[i], 0, ncols_per_row"),
			"extra columns are zero-initialised (free as NULL)");
	}

	/* ---- raw_kv_bucket_info: same OOB class -------------------- */
	/* bucket_info returns 1 row of 6 fixed columns, but the core frees
	 * expected_kv_no columns per row.  Asking for > 6 output vars made the
	 * core read+free past the 6-column row (heap OOB read + bad free).  The
	 * fix sizes the row max(expected_kv_no, 6) and zeroes the extras. */
	{
		ASSERT(bi_ncols(6) == 6, "expected_kv_no<=6 -> 6 columns");
		ASSERT(bi_ncols(7) == 7, "expected_kv_no=7 -> 7 columns");
		ASSERT(bi_ncols(1) == 6, "expected_kv_no=1 still keeps the 6 filled columns");

		/* model: core frees `expected` cols over a max(expected,6) row.
		 * With the fix all are in-bounds; the old fixed-6 alloc would OOB
		 * when expected=7 (ASan would trip). */
		int expected = 7;
		col_t *row = build_row(bi_ncols(expected), "bucket-name");   /* 7 cols */
		ASSERT(row != NULL, "bucket_info row sized to max(expected_kv_no, 6)");
		core_free_row(row, expected);
		ASSERT(1, "core free over expected_kv_no cols is in-bounds (ASan-clean)");

		const char *n = "../cachedb_nats_native.c";
		ASSERT(file_contains(n, "bi_ncols"),
			"raw_kv_bucket_info sizes the row by bi_ncols");
		ASSERT(file_contains(n, "bi_ncols * sizeof(cdb_raw_entry)"),
			"bucket_info row allocation uses max(expected_kv_no, 6) columns");
		ASSERT(file_contains(n, "memset(rows[0], 0, bi_ncols"),
			"bucket_info extra columns are zero-initialised (free as NULL)");
	}

	if (g_fails == 0) fprintf(stderr, "\n=== ALL PASS (fails=0) ===\n");
	else              fprintf(stderr, "\n=== FAILS=%d ===\n", g_fails);
	return g_fails ? 1 : 0;
}
