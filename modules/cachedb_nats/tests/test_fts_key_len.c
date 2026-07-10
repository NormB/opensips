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
 * [P3.5 residue] Behavioural (ASan, REAL TUs): the FTS write-side entry
 * points take an explicit key LENGTH — no strlen on the hot path, and a
 * key need not be NUL-terminated.  Every key handed to the index here
 * is a heap slice of EXACTLY key_len bytes with no terminator: if any
 * production path still runs strlen()/str*cpy() over the key, ASan
 * trips heap-buffer-overflow and the test fails.
 *
 * Contracts:
 *   - add/remove_by_revmap/remove/remove_fields accept (key, key_len)
 *     slices; indexing is by VALUE (a different buffer with the same
 *     bytes removes what another added);
 *   - re-adding the same sliced key stays idempotent (count == 1);
 *   - remove_fields with the old JSON removes the targeted entries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include <nats/nats.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../lib/nats/nats_dl.h"
#include "../../cachedb_nats_fts/fts_index.h"
#include "../../cachedb_nats_fts/fts_intern.h"

/* ── core seams: dprint ─────────────────────────────────────────── */

static int test_log_level = L_ERR;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	(void)level; (void)facility; (void)module; (void)func;
	(void)stderr_fmt; (void)syslog_fmt; (void)format;
}

/* ── core seams: pkg + shm allocators (single-threaded test) ────── */

void *mem_block = NULL;
void *shm_block = NULL;

static void *test_blk_malloc(void *blk, unsigned long size)
{ (void)blk; return malloc(size); }
static void *test_blk_realloc(void *blk, void *p, unsigned long size)
{ (void)blk; return realloc(p, size); }
static void test_blk_free(void *blk, void *p)
{ (void)blk; free(p); }
static unsigned long test_blk_size(void *blk) { (void)blk; return 1 << 24; }
static unsigned long test_blk_rused(void *blk) { (void)blk; return 0; }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_blk_malloc;
void (*gen_pkg_free)(void *blk, void *p) = test_blk_free;
void *(*gen_shm_malloc)(void *blk, unsigned long size) = test_blk_malloc;
void *(*gen_shm_realloc)(void *blk, void *p, unsigned long size)
	= test_blk_realloc;
void (*gen_shm_free)(void *blk, void *p) = test_blk_free;
unsigned long (*gen_shm_get_size)(void *blk) = test_blk_size;
unsigned long (*gen_shm_get_rused)(void *blk) = test_blk_rused;

static gen_lock_t test_mem_lock;
gen_lock_t *mem_lock = &test_mem_lock;
int shm_use_global_lock = 1;
long event_shm_threshold = 0;
static long _event_last;
static int _event_pending;
long *event_shm_last = &_event_last;
int *event_shm_pending = &_event_pending;
void shm_event_raise(long used, long size, long perc)
{ (void)used; (void)size; (void)perc; }

#include "../../../cachedb/cachedb_dict.h"
int cdb_json_to_dict(const char *json, cdb_dict_t *out,
	void (*unescape)(char *inout))
{ (void)json; (void)out; (void)unescape; return -1; }

/* build/rebuild are not driven here, but the TU references nats_dl. */
nats_dl_funcs_t nats_dl;

/* ── harness ────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* An exactly-sized, NON-NUL-terminated heap copy: one byte past
 * key_len is unallocated, so any strlen over it trips ASan. */
static char *key_slice(const char *s, int *out_len)
{
	int n = (int)strlen(s);
	char *p = malloc(n);
	memcpy(p, s, n);
	*out_len = n;
	return p;
}

int main(void)
{
	const char *doc  = "{\"aor\":\"alice@example.com\",\"domain\":\"example.com\"}";
	const char *doc2 = "{\"aor\":\"bob@example.com\",\"domain\":\"example.com\"}";
	int dlen = (int)strlen(doc), d2len = (int)strlen(doc2);
	char *k1, *k1b, *k2;
	int k1_len, k1b_len, k2_len;

	/* The intern table must be live: without it, acquire falls back
	 * to per-call strdup and the pointer-compare removal paths can
	 * never match (production initialises it in mod_init). */
	ASSERT(nats_intern_init(64) == 0, "intern init");
	ASSERT(nats_json_index_init() == 0, "index init");

	k1  = key_slice("json_doc.alice", &k1_len);
	k1b = key_slice("json_doc.alice", &k1b_len);   /* same bytes, other buf */
	k2  = key_slice("json_doc.bob", &k2_len);

	/* add via non-terminated slices */
	ASSERT(nats_json_index_add(k1, k1_len, doc, dlen) == 0,
		"add(sliced key) indexes without a terminator");
	ASSERT(nats_json_index_count() == 1, "count 1 after first add");

	ASSERT(nats_json_index_add(k1, k1_len, doc, dlen) == 0,
		"re-add same sliced key succeeds");
	ASSERT(nats_json_index_count() == 1, "idempotent: count still 1");

	ASSERT(nats_json_index_add(k2, k2_len, doc2, d2len) == 0,
		"second sliced key indexes");
	ASSERT(nats_json_index_count() == 2, "count 2 after second add");

	/* revmap fast delete by VALUE: a different buffer, same bytes */
	ASSERT(nats_json_index_remove_by_revmap(k1b, k1b_len) == 0,
		"remove_by_revmap(other buffer, same bytes) hits");
	ASSERT(nats_json_index_count() == 1, "count 1 after revmap remove");
	ASSERT(nats_json_index_remove_by_revmap(k1b, k1b_len) == -1,
		"second revmap remove misses (already gone)");

	/* targeted remove_fields with the OLD json, then the full-walk
	 * remove as the fallback contract */
	ASSERT(nats_json_index_remove_fields(k2, k2_len, doc2, d2len) == 0,
		"remove_fields(sliced key) succeeds");
	ASSERT(nats_json_index_remove(k2, k2_len) == 0,
		"remove(sliced key) full walk is clean after remove_fields");
	ASSERT(nats_json_index_count() == 0, "index empty at the end");

	free(k1); free(k1b); free(k2);
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
