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
 * [P5.4] Behavioural (ASan+LSan, REAL TUs): the single-allocation
 * index-entry blob and its inline->external keys[] growth, exercised
 * through the production fts_index.c (replaces the file_contains()
 * source-pattern version of this test).
 *
 * The layout being locked: get_or_create_entry_in packs the entry
 * struct + field_value + an inline keys[NATS_IDX_KEYS_INLINE] array
 * into ONE shm blob; entry_add_key migrates keys[] to a separate
 * allocation when it grows past the inline capacity; free_entry must
 * free the external keys[] and must NOT free the inline one (an
 * interior pointer).  None of that is directly visible through the
 * API -- but under ASan/LSan every way to get it wrong is fatal:
 *   - freeing the inline keys[] => invalid free (interior pointer);
 *   - leaking the external keys[] on free => LSan leak at exit;
 *   - losing the inline contents on growth => the migrated keys are
 *     no longer removable and the count/refcount contracts go red;
 *   - a second allocation per entry that free_entry doesn't know
 *     about => LSan leak.
 *
 * Both arms share one identical single-field JSON so every doc key
 * lands in the SAME field entry:
 *   - sub-threshold arm: 3 keys (keys[] stays inline), then index
 *     destroy -- a wrong shm_free of the inline array aborts;
 *   - growth arm: NATS_IDX_KEYS_INLINE+4 keys (forces the inline ->
 *     external migration), every key then removed one by one via
 *     revmap -- each hit proves the migrated array kept the early
 *     inline keys; the final counts prove the entry and the interned
 *     keys were fully freed.
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

/* one identical single-field doc => every key shares ONE field entry */
static const char *doc = "{\"domain\":\"example.com\"}";

static void add_keys(int n, const char *prefix)
{
	int i, dlen = (int)strlen(doc), ok = 1;
	char msg[64];
	for (i = 0; i < n; i++) {
		char key[32];
		snprintf(key, sizeof(key), "%s%02d", prefix, i);
		if (nats_json_index_add(key, (int)strlen(key), doc,
				dlen) != 0)
			ok = 0;
	}
	snprintf(msg, sizeof(msg), "%d keys added into the shared entry", n);
	ASSERT(ok && nats_json_index_count() == n, msg);
	snprintf(msg, sizeof(msg), "%d doc keys interned", n);
	ASSERT(nats_intern_size() == n, msg);
}

int main(void)
{
	int i;
	const int grow_n = NATS_IDX_KEYS_INLINE + 4;

	ASSERT(nats_intern_init(64) == 0, "intern init");

	/* ── sub-threshold arm: keys[] stays inline ──────────────────── */
	ASSERT(nats_json_index_init() == 0, "index init (inline arm)");
	add_keys(3, "inline_");
	/* destroy while inline: a free of the interior inline keys[]
	 * pointer aborts under ASan; a missed blob free leaks */
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0,
	       "inline-arm destroy released every interned key");

	/* ── growth arm: force inline -> external migration ──────────── */
	ASSERT(nats_json_index_init() == 0, "index init (growth arm)");
	add_keys(grow_n, "grow_");

	/* every key -- including the early ones that lived in the inline
	 * array before migration -- must still be attached and removable */
	for (i = 0; i < grow_n; i++) {
		char key[32];
		snprintf(key, sizeof(key), "grow_%02d", i);
		if (nats_json_index_remove_by_revmap(key,
				(int)strlen(key)) != 0) {
			fprintf(stderr, "FAIL: key %s lost across the "
				"inline->external migration\n", key);
			g_fails++;
		}
	}
	ASSERT(nats_json_index_count() == 0,
	       "all keys removed after growth (none lost in migration)");
	ASSERT(nats_intern_size() == 0,
	       "entry fully freed: every interned key released");

	/* removing the last key freed the entry (and its external keys[]
	 * -- LSan catches it at exit if not); a fresh add still works */
	ASSERT(nats_json_index_add("post", 4, doc, (int)strlen(doc)) == 0,
	       "index still serviceable after entry teardown");
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0, "final destroy is clean");

	nats_intern_destroy();
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
