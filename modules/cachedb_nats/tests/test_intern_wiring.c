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
 * [P5.4] Behavioural (ASan, REAL TUs): the index<->intern wiring,
 * exercised through the production fts_index.c + fts_intern.c
 * (replaces the file_contains() source-pattern version of this
 * test).  The optimisation this locks: the doc key is interned ONCE
 * per document, however many field entries reference it -- if
 * entry_add_key ever regresses to per-field strdup, the size/refcount
 * contracts here go red.
 *
 * Contracts:
 *   - init-required degrade: with no intern table, an index add
 *     interns nothing (the gotcha production avoids by initialising
 *     the table in the FTS module's mod_init -- that lifecycle hook
 *     itself is exercised end-to-end by sip_e2e cases 030/120/140,
 *     which fail hard if mod_init stops initialising the table);
 *   - one intern node per doc key, not per indexed field;
 *   - the index's references are intern references: removing the doc
 *     releases ALL of them (refcount returns to probe-only);
 *   - duplicate add of the same doc does not leak references;
 *   - index destroy with live docs releases every interned key.
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

int main(void)
{
	/* two indexed string fields -> two field entries per doc */
	const char *doc = "{\"aor\":\"alice@example.com\",\"domain\":\"example.com\"}";
	int dlen = (int)strlen(doc);
	const char *key = "json_doc.alice";
	int klen = (int)strlen(key);
	char *probe;
	int rc_with_index;

	/* ── init-required degrade: no intern table, nothing interned ── */
	ASSERT(nats_json_index_init() == 0, "index init (no intern table yet)");
	(void)nats_json_index_add(key, klen, doc, dlen);
	ASSERT(nats_intern_size() == 0,
	       "without nats_intern_init, an index add interns nothing");
	nats_json_index_destroy();

	/* ── production wiring: intern table first (mod_init order) ──── */
	ASSERT(nats_intern_init(64) == 0, "intern init");
	ASSERT(nats_json_index_init() == 0, "index re-init");

	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0, "doc indexed");
	ASSERT(nats_json_index_count() == 1, "index holds one doc");
	ASSERT(nats_intern_size() == 1,
	       "ONE intern node per doc key, not one per indexed field");

	probe = nats_intern_acquire(key, klen);
	ASSERT(probe != NULL, "probe acquire of the live doc key");
	rc_with_index = nats_intern_refcount(probe);
	ASSERT(rc_with_index >= 3,
	       "index holds interned references (>=2 field entries + probe)");

	/* duplicate add must not leak references */
	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0, "doc re-added");
	ASSERT(nats_intern_refcount(probe) == rc_with_index,
	       "re-adding the same doc leaks no intern references");
	ASSERT(nats_intern_size() == 1, "still one intern node after re-add");

	/* removing the doc releases every index-held reference */
	ASSERT(nats_json_index_remove_by_revmap(key, klen) == 0, "doc removed");
	ASSERT(nats_intern_refcount(probe) == 1,
	       "remove released ALL index references (probe-only left)");
	nats_intern_release(probe);
	ASSERT(nats_intern_size() == 0, "intern table empty after remove");

	/* index destroy with live docs releases interned keys too */
	ASSERT(nats_json_index_add(key, klen, doc, dlen) == 0,
	       "doc indexed again before destroy");
	ASSERT(nats_intern_size() == 1, "interned again");
	nats_json_index_destroy();
	ASSERT(nats_intern_size() == 0,
	       "index destroy released every interned key");

	nats_intern_destroy();
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
