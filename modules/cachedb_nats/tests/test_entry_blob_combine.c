/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Structural wiring test for the single-allocation index-entry
 * blob.  Cuts _get_or_create_entry_in's 3 shm_mallocs (entry
 * struct + field_value + keys[] array) into one combined blob,
 * with the keys[] inline until it grows past NATS_IDX_KEYS_INLINE
 * and is replaced by a separate allocation.
 *
 * Asserts:
 *  - The struct gained the keys_inline flag and the
 *    NATS_IDX_KEYS_INLINE macro
 *  - _get_or_create_entry_in does ONE shm_malloc, with field_value
 *    and keys[] both pointer-arithmetic'd into the same blob
 *  - The keys[] grow path detects keys_inline=1, allocates a fresh
 *    array, copies the inline contents, clears the flag
 *  - _free_entry skips the separate shm_free for the inline case
 *  - The single-blob shm_free covers the entry + field_value +
 *    inline keys
 *
 * RED-prove: sed '/keys_inline = 1/d' the production source ->
 * test reports 1 fail; restore -> 0 fail.
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
	char line[4096];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	/* Header: NATS_IDX_KEYS_INLINE macro + keys_inline field */
	ASSERT(file_contains("../cachedb_nats_json.h",
		"NATS_IDX_KEYS_INLINE"),
		"NATS_IDX_KEYS_INLINE macro defined in header");
	ASSERT(file_contains("../cachedb_nats_json.h",
		"int keys_inline"),
		"nats_idx_entry struct has keys_inline flag");

	/* Single-alloc layout in _get_or_create_entry_in.  The blob is
	 * the size of the entry struct + field_value bytes + inline
	 * keys[] slots, all in one shm_malloc. */
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"size_t blob_sz"),
		"_get_or_create_entry_in computes a single blob size");
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"shm_malloc(blob_sz)"),
		"_get_or_create_entry_in does ONE shm_malloc for the blob");

	/* The blob's three regions are pointer-arithmetic'd, NOT
	 * separately shm_malloc'd. */
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"e->field_value  = blob + entry_sz"),
		"field_value points into the blob (pointer arithmetic)");
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"e->keys         = (char **)(blob + entry_sz + fv_sz)"),
		"keys[] points into the blob (pointer arithmetic)");
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"e->keys_inline  = 1"),
		"keys_inline flag set to 1 on initial blob allocation");

	/* The grow path in _entry_add_key handles inline -> external. */
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"e->keys_inline  = 0"),
		"_entry_add_key clears keys_inline when growing");
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"if (e->keys_inline)"),
		"_entry_add_key branches on keys_inline at grow site");

	/* _free_entry conditionally frees keys[]. */
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"if (!e->keys_inline && e->keys)"),
		"_free_entry skips keys[] free when still inline");

	/* The old multi-shm_malloc layout is gone -- exactly one
	 * shm_malloc in _get_or_create_entry_in.  This catches a
	 * regression where someone accidentally re-introduces a
	 * separate allocation for field_value or keys.  The check
	 * counts shm_malloc lines between the function header and
	 * its return point; one is the blob alloc, anything more
	 * is a regression. */
	{
		FILE *f = fopen("../cachedb_nats_json_index.c", "r");
		char line[4096];
		int in_func = 0;
		int mallocs_in_func = 0;
		while (f && fgets(line, sizeof(line), f)) {
			if (strstr(line, "_get_or_create_entry_in(nats_search_idx"))
				in_func = 1;
			if (in_func) {
				if (strstr(line, "shm_malloc("))
					mallocs_in_func++;
				/* Stop at next top-level function boundary */
				if (mallocs_in_func > 0 &&
				    strstr(line, "/* The thin wrapper"))
					break;
				if (mallocs_in_func > 0 && strstr(line, "static "))
					break;
			}
		}
		if (f) fclose(f);
		ASSERT(mallocs_in_func == 1,
		       "_get_or_create_entry_in does exactly one shm_malloc");
	}

	/* The intern table is still wired -- the blob change must
	 * not have accidentally broken the intern integration. */
	ASSERT(file_contains("../cachedb_nats_json_index.c",
		"nats_intern_acquire"),
		"intern integration preserved");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
