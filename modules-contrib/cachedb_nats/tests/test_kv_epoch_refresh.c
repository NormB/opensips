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
 * Behavioral regression test: nats_con_refresh_kv() must NOT latch the
 * reconnect epoch when the KV handle refresh fails.
 *
 * The defect: after a reconnect bumps the pool epoch, a *transient*
 * nats_pool_get_kv() failure (broker still settling) left the code
 * assigning ncon->kv_epoch = epoch BEFORE checking the result.  The next
 * call then saw epoch == kv_epoch and short-circuited "still valid" with
 * ncon->kv == NULL — permanently, until the *next* reconnect.  For usrloc
 * that is one worker silently failing every cachedb op (dropping all
 * registrations it handles) indefinitely.
 *
 * Contract asserted here:
 *   - a failed refresh returns -1 AND leaves the connection retryable:
 *     the next call must call nats_pool_get_kv() again;
 *   - once the pool recovers, the next refresh returns 0 with a fresh,
 *     non-NULL handle;
 *   - refresh NEVER returns 0 while ncon->kv is NULL;
 *   - steady state (same epoch, valid handle) does not hit the pool;
 *   - disconnected pool fast-fails without hitting the pool.
 *
 * Unlike the source-pattern tests in this directory, this test compiles
 * and links the REAL production TU (../cachedb_nats_dbase.c) and swaps
 * only the process seams: the nats_pool_* functions, the dprint/pkg-mem
 * core globals, and the module-parameter globals normally defined by
 * cachedb_nats.c.  See the target-specific rule in the Makefile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../nats/nats_dl.h"
#include "../../nats/nats_pool.h"
#include "../../nats/nats_validate.h"
#include "../cachedb_nats.h"
#include "../cachedb_nats_dbase.h"
#include "../cachedb_nats_stats.h"
#include "../../nats/tests/nats_bind_test.h"  /* nats_api -> the fakes */

/* ── core seams: dprint ─────────────────────────────────────────── */

static int test_log_level = L_DBG;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;

int dp_my_pid(void) { return 0; }

/* how many times the refresh failure was logged */
static int refresh_err_logs = 0;

void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	if (strstr(stderr_fmt, "failed to refresh KV handle"))
		refresh_err_logs++;
	va_start(ap, format);
	vfprintf(stderr, stderr_fmt, ap);
	va_end(ap);
}

/* ── core seams: pkg allocator (fn-pointer globals from mem/mem.h) ── */

void *mem_block = NULL;

static void *test_pkg_malloc(void *blk, unsigned long size)
{ (void)blk; return malloc(size); }
static void test_pkg_free(void *blk, void *p)
{ (void)blk; free(p); }

void *(*gen_pkg_malloc)(void *blk, unsigned long size) = test_pkg_malloc;
void (*gen_pkg_free)(void *blk, void *p) = test_pkg_free;

/* ── module globals normally defined by cachedb_nats.c ──────────── */

char *kv_bucket = "testbucket";
int kv_replicas = 1;
int kv_history = 1;
int kv_ttl = 0;
int nats_cas_retries = 3;
nats_cdb_stats_t *nats_cdb_stats = NULL;   /* stats macros no-op on NULL */
void nats_cas_backoff_sleep(int attempt) { (void)attempt; }

/* libnats fn-pointer table: never dereferenced by refresh_kv */
nats_dl_funcs_t nats_dl;

/* other TU link deps the refresh path never reaches */
int nats_validate(const char *s, int len, nats_validate_mode_t mode)
{ (void)s; (void)len; (void)mode; return 0; }
/* the connection constructor the module hands the cachedb core */
static void *(*g_new_con)(struct cachedb_id *);
cachedb_con *cachedb_do_init(str *url, void *(*new_con)(struct cachedb_id *))
{ (void)url; g_new_con = new_con; return NULL; }
void cachedb_do_close(cachedb_con *con, void (*free_con)(cachedb_pool_con *))
{ (void)con; (void)free_con; }

/* ── controllable fake nats_pool ────────────────────────────────── */

static int fake_connected = 1;
static int fake_epoch = 0;
static kvStore *fake_kv_ret = NULL;   /* what get_kv returns next */
static int get_kv_calls = 0;

/* a process connects on its first nats_pool_get() (when the broker is
 * up): until then nats_pool_is_connected() is 0 */
static int fake_broker_up = 1;
static int get_calls = 0;
int nats_pool_is_connected(void) { return fake_connected; }
natsConnection *nats_pool_get(void)
{
	get_calls++;
	if (!fake_broker_up)
		return NULL;
	fake_connected = 1;
	return (natsConnection *)0x2001;
}
int nats_pool_get_reconnect_epoch(void) { return fake_epoch; }
kvStore *nats_pool_get_kv(const char *bucket, int replicas, int history,
	int64_t ttl)
{
	(void)bucket; (void)replicas; (void)history; (void)ttl;
	get_kv_calls++;
	return fake_kv_ret;
}

/* opaque fake handles — never dereferenced, identity only */
#define H1 ((kvStore *)0x1001)
#define H2 ((kvStore *)0x1002)
#define H3 ((kvStore *)0x1003)

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

int main(void)
{
	nats_cachedb_con con;
	int rc;

	/* 0. NULL connection is rejected */
	ASSERT(nats_con_refresh_kv(NULL) == -1, "NULL ncon returns -1");

	/* 1. steady state: same epoch, valid handle — no pool traffic */
	memset(&con, 0, sizeof(con));
	con.kv = H1;
	con.kv_epoch.seen = 5;   /* epoch tag struct */
	fake_epoch = 5;
	fake_connected = 1;
	get_kv_calls = 0;
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == 0, "steady state returns 0");
	ASSERT(con.kv == H1, "steady state keeps handle");
	ASSERT(get_kv_calls == 0, "steady state does not hit the pool");

	/* 2. disconnected: fast-fail, no pool traffic */
	fake_connected = 0;
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == -1, "disconnected returns -1");
	ASSERT(get_kv_calls == 0, "disconnected does not hit the pool");
	fake_connected = 1;

	/* 3. clean reconnect: epoch bumped, pool delivers a fresh handle */
	fake_epoch = 6;
	fake_kv_ret = H2;
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == 0, "successful refresh returns 0");
	ASSERT(con.kv == H2, "successful refresh installs fresh handle");
	ASSERT(get_kv_calls == 1, "successful refresh hits the pool once");
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == 0 && get_kv_calls == 1,
		"epoch adopted on success — next call is a no-op");

	/* 4. THE DEFECT — transient refresh failure must not latch the epoch.
	 * Reconnect bumps epoch to 7; the pool transiently fails (returns
	 * NULL), then recovers.  The connection must retry and recover too. */
	fake_epoch = 7;
	fake_kv_ret = NULL;                      /* transient pool failure  */
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == -1, "failed refresh returns -1");

	fake_kv_ret = H3;                        /* pool recovered          */
	get_kv_calls = 0;
	rc = nats_con_refresh_kv(&con);
	ASSERT(get_kv_calls == 1,
		"call after failed refresh RETRIES the pool (no epoch latch)");
	ASSERT(rc == 0, "refresh after pool recovery returns 0");
	ASSERT(con.kv == H3, "refresh after pool recovery installs handle");

	/* 5. persistent failure: every call keeps returning -1 — never
	 * 0 with a NULL handle */
	fake_epoch = 8;
	fake_kv_ret = NULL;
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == -1, "persistent failure: first call -1");
	rc = nats_con_refresh_kv(&con);
	ASSERT(rc == -1 || con.kv != NULL,
		"persistent failure: NEVER 0 with NULL handle");
	ASSERT(rc == -1, "persistent failure: second call still -1");

	/* 6. a failure that lasts (no JetStream, the bucket refused) is
	 * met by every cache operation of every worker: it is logged at
	 * most once per 30 s, not once per operation */
	{
		int i, all_failed = 1;

		for (i = 0; i < 50; i++)
			if (nats_con_refresh_kv(&con) != -1)
				all_failed = 0;
		ASSERT(all_failed, "persistent failure: every call still -1");
		ASSERT(refresh_err_logs == 1,
			"persistent failure: logged once, not per call");
	}

	/* 7. a process that has not connected yet -- the attendant before
	 * the fork, where b2b_entities and b2b_logic restore their state
	 * from mod_init -- connects when it opens a cachedb connection,
	 * and the connection gets its KV handle */
	{
		struct cachedb_id id;
		nats_cachedb_con *c;
		str url = str_init("nats://127.0.0.1:4222/");

		memset(&id, 0, sizeof id);
		nats_cachedb_init(&url);
		ASSERT(g_new_con != NULL, "the module hands its constructor to the core");

		fake_connected = 0; fake_broker_up = 1; fake_kv_ret = H1;
		get_calls = get_kv_calls = 0;
		c = g_new_con ? g_new_con(&id) : NULL;
		ASSERT(c != NULL, "not connected yet: the connection is created");
		ASSERT(get_calls == 1, "not connected yet: it connects first");
		ASSERT(c && c->kv == H1 && get_kv_calls == 1,
			"not connected yet: the connection gets its KV handle");
		free(c);

		/* 8. the broker down at that moment: the connection is still
		 * created, without a handle (degraded start); the operations
		 * get it once connected */
		fake_connected = 0; fake_broker_up = 0;
		get_calls = get_kv_calls = 0;
		c = g_new_con ? g_new_con(&id) : NULL;
		ASSERT(c != NULL && c->kv == NULL && get_kv_calls == 0,
			"broker down: created without a KV handle");
		free(c);
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
