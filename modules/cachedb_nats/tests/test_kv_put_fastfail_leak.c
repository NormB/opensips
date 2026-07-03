/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Behavioral regression tests for the w_nats_kv_put / w_nats_kv_update
 * fast-fail paths and the w_nats_kv_get pvar-set contract.
 *
 * Defect 1 (pkg leak): values >= NATS_NATIVE_VAL_BUF (4096) are
 * pkg_malloc'd into a heap buffer BEFORE the disconnected fast-fail
 * check, and that check did a bare `return -1` without freeing — leaking
 * up to payload size per call for the whole duration of a broker outage.
 * Contract: a disconnected put/update must return -1 with ZERO
 * outstanding pkg allocations (the connectivity gate runs before any
 * copy, as w_nats_request already does).
 *
 * Defect 2 (ignored pv_set_value): w_nats_kv_get ignored the return of
 * pv_set_value(), so a failed pvar write still returned 1 (success) and
 * the script read a STALE value as if it were fresh.  Contract: if the
 * value pvar cannot be set, w_nats_kv_get returns -1.
 *
 * Like test_kv_epoch_refresh.c, this compiles and links the REAL
 * production TU (../cachedb_nats_native.c); the process seams (dprint,
 * pkg allocator, nats_pool, the nats_dl libnats function table,
 * pv_set_value) are swapped for instrumented fakes.  The pkg fakes keep
 * a live-allocation balance — the "pkg-stats delta" assertions below.
 * The binary is also ASan'd, so a leaked buffer additionally trips
 * LeakSanitizer at exit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../pvar.h"
#include "../../../mi/mi.h"
#include "../../../lib/nats/nats_dl.h"
#include "../../../lib/nats/nats_pool.h"
#include "../cachedb_nats_native.h"
#include "../cachedb_nats_dbase.h"
#include "../cachedb_nats_ttl.h"

/* ── core seams: dprint ─────────────────────────────────────────── */

static int test_log_level = L_DBG;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	vfprintf(stderr, stderr_fmt, ap);
	va_end(ap);
}

/* ── core seams: pkg allocator with live-balance accounting ────── */

void *mem_block = NULL;

static long pkg_live;      /* outstanding allocations               */
static long pkg_allocs;    /* total allocation calls (copy detector) */

static void *test_pkg_malloc(void *blk, unsigned long size)
{ (void)blk; pkg_live++; pkg_allocs++; return malloc(size); }
static void test_pkg_free(void *blk, void *p)
{ (void)blk; if (p) pkg_live--; free(p); }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_pkg_malloc;
void (*gen_pkg_free)(void *blk, void *p) = test_pkg_free;

/* ── module globals normally defined by other TUs ───────────────── */

char *kv_bucket = "testbucket";
int kv_replicas = 1;
int kv_history = 1;
int kv_ttl = 0;

int validate_kv_key(const str *s)
{ return (s && s->s && s->len > 0) ? 0 : -1; }
int nats_con_refresh_kv(nats_cachedb_con *ncon)
{ (void)ncon; return 0; }

/* MI plumbing: referenced by the raw-query MI paths, never reached */
mi_response_t *init_mi_result_object(mi_item_t **obj_out)
{ (void)obj_out; return NULL; }
mi_response_t *init_mi_error_extra(int code, const char *msg, int msg_len,
	const char *details, int details_len)
{ (void)code; (void)msg; (void)msg_len; (void)details; (void)details_len;
  return NULL; }
void free_mi_response(mi_response_t *response) { (void)response; }
int add_mi_number(mi_item_t *to, char *name, int name_len, double value)
{ (void)to; (void)name; (void)name_len; (void)value; return 0; }

/* ── controllable fakes: nats_pool ──────────────────────────────── */

static int fake_connected = 1;
static kvStore *fake_kv = (kvStore *)0x1001;
static int get_kv_calls;

int nats_pool_is_connected(void) { return fake_connected; }
kvStore *nats_pool_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl)
{
	(void)bucket; (void)replicas; (void)history; (void)ttl;
	get_kv_calls++;
	return fake_kv;
}
natsConnection *nats_pool_get(void) { return NULL; }
jsCtx *nats_pool_get_js(void) { return (jsCtx *)0x2001; }

/* ── controllable fake: nats_kv_put_row (the CAS write path) ────── */

static enum ttl_outcome fake_put_row_outcome = TTL_DONE;
static int put_row_calls;

enum ttl_outcome nats_kv_put_row(jsCtx *js, kvStore *kv,
	const char *bucket, const char *key,
	const char *json, int json_len,
	int got_entry, uint64_t entry_rev, uint64_t *out_rev)
{
	(void)js; (void)kv; (void)bucket; (void)key; (void)json;
	(void)json_len; (void)got_entry; (void)entry_rev;
	put_row_calls++;
	if (out_rev) *out_rev = 7;
	return fake_put_row_outcome;
}

/* ── controllable fakes: the nats_dl libnats table ──────────────── */

nats_dl_funcs_t nats_dl;

#define FAKE_ENTRY ((kvEntry *)0x3001)
static const char *fake_entry_val = "fresh-value";

static natsStatus fake_kvStore_Get(kvEntry **e, kvStore *kv, const char *k)
{ (void)kv; (void)k; *e = FAKE_ENTRY; return NATS_OK; }
static natsStatus fake_kvStore_PutString(uint64_t *rev, kvStore *kv,
	const char *k, const char *v)
{ (void)kv; (void)k; (void)v; if (rev) *rev = 3; return NATS_OK; }
static const char *fake_kvEntry_ValueString(const kvEntry *e)
{ (void)e; return fake_entry_val; }
static int fake_kvEntry_ValueLen(const kvEntry *e)
{ (void)e; return (int)strlen(fake_entry_val); }
static uint64_t fake_kvEntry_Revision(const kvEntry *e)
{ (void)e; return 42; }
static void fake_kvEntry_Destroy(kvEntry *e) { (void)e; }
static const char *fake_natsStatus_GetText(natsStatus s)
{ (void)s; return "fake-status"; }

/* ── controllable fake: pv_set_value ────────────────────────────── */

static int pv_rc = 0;          /* forced return of pv_set_value      */
static int pv_calls;

int pv_set_value(struct sip_msg *msg, pv_spec_p sp, int op, pv_value_t *value)
{
	(void)msg; (void)sp; (void)op; (void)value;
	pv_calls++;
	return pv_rc;
}

/* ── harness ────────────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

#define DUMMY_MSG  ((struct sip_msg *)0x4001)
#define DUMMY_SPEC ((pv_spec_t *)0x5001)

int main(void)
{
	str bucket = { "b", 1 };
	str key = { "k1", 2 };
	str bigval, smallval;
	int rc, expected_rev = 1;

	/* install the libnats fakes into the dl table */
	nats_dl.kvStore_Get = fake_kvStore_Get;
	nats_dl.kvStore_PutString = fake_kvStore_PutString;
	nats_dl.kvEntry_ValueString = fake_kvEntry_ValueString;
	nats_dl.kvEntry_ValueLen = fake_kvEntry_ValueLen;
	nats_dl.kvEntry_Revision = fake_kvEntry_Revision;
	nats_dl.kvEntry_Destroy = fake_kvEntry_Destroy;
	nats_dl.natsStatus_GetText = fake_natsStatus_GetText;

	/* an 8 KB value — forces the pkg_malloc'd copy path (>= 4096) */
	bigval.len = 8192;
	bigval.s = malloc(bigval.len);
	memset(bigval.s, 'x', bigval.len);
	smallval.s = "small";
	smallval.len = 5;

	/* 1. THE LEAK — disconnected fast-fail with a >4 KB value must not
	 * leave a pkg allocation behind (put) */
	fake_connected = 0;
	pkg_live = 0; pkg_allocs = 0;
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &bigval);
	ASSERT(rc == -1, "disconnected kv_put returns -1");
	ASSERT(pkg_live == 0,
		"disconnected kv_put leaves ZERO outstanding pkg allocations");
	ASSERT(pkg_allocs == 0,
		"disconnected kv_put does not even copy the value (gate first)");

	/* 2. same for update */
	pkg_live = 0; pkg_allocs = 0;
	rc = w_nats_kv_update(DUMMY_MSG, &bucket, &key, &bigval, &expected_rev);
	ASSERT(rc == -1, "disconnected kv_update returns -1");
	ASSERT(pkg_live == 0,
		"disconnected kv_update leaves ZERO outstanding pkg allocations");
	ASSERT(pkg_allocs == 0,
		"disconnected kv_update does not even copy the value (gate first)");

	/* 3. small (stack-buffer) values on the same path: still -1, still
	 * no pkg traffic */
	pkg_live = 0; pkg_allocs = 0;
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &smallval);
	ASSERT(rc == -1 && pkg_live == 0,
		"disconnected kv_put with small value: -1, no pkg delta");

	/* 4. connected happy paths keep working and stay balanced */
	fake_connected = 1;
	pkg_live = 0;
	rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &bigval);
	ASSERT(rc == 1, "connected kv_put (8 KB) succeeds");
	ASSERT(pkg_live == 0, "connected kv_put frees its heap copy");

	put_row_calls = 0;
	pkg_live = 0;
	rc = w_nats_kv_update(DUMMY_MSG, &bucket, &key, &bigval, &expected_rev);
	ASSERT(rc == 1 && put_row_calls == 1, "connected kv_update succeeds");
	ASSERT(pkg_live == 0, "connected kv_update frees its heap copy");

	/* 4b. empty value: no allocation on any arm */
	{
		str empty = { NULL, 0 };
		pkg_live = 0; pkg_allocs = 0;
		rc = w_nats_kv_put(DUMMY_MSG, &bucket, &key, &empty);
		ASSERT(rc == 1 && pkg_live == 0,
			"connected kv_put with empty value: ok, no pkg delta");
	}

	/* 5. IGNORED pv_set_value — a failed pvar write must fail the get.
	 * The fake entry delivers a value, but the pvar layer rejects it:
	 * returning 1 here hands the script a STALE $var as fresh. */
	pv_rc = -1;
	pv_calls = 0;
	pkg_live = 0;
	rc = w_nats_kv_get(DUMMY_MSG, &bucket, &key, DUMMY_SPEC, NULL);
	ASSERT(pv_calls == 1, "kv_get attempted the pvar write");
	ASSERT(rc == -1, "kv_get returns -1 when the value pvar set fails");
	ASSERT(pkg_live == 0, "kv_get failure path stays pkg-balanced");

	/* 6. pvar write succeeding: get succeeds and stays balanced */
	pv_rc = 0;
	pkg_live = 0;
	rc = w_nats_kv_get(DUMMY_MSG, &bucket, &key, DUMMY_SPEC, NULL);
	ASSERT(rc == 1, "kv_get succeeds when the pvar set succeeds");
	ASSERT(pkg_live == 0, "kv_get success path stays pkg-balanced");

	free(bigval.s);
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
