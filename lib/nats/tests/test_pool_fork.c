/*
 * Copyright (C) 2026 Summit-2026 / cachedb_nats contributors
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
 * test_pool_fork.c -- a pool connection opened before fork() must not
 * reach the children.
 *
 * nats.c is not fork-safe: its connection and library threads exist only
 * in the process that started them.  A module that uses NATS from
 * mod_init (b2b_entities restores its state there, through cachedb_nats)
 * made the attendant connect; every forked worker then inherited a
 * connection handle without the threads behind it, and each request
 * timed out.  The pool must close the connection and the library in the
 * parent right before fork(), so a child connects on its own.
 *
 * Links the REAL ../nats_pool.c against a fake libnats table that counts
 * calls; forks for real.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../../../dprint.h"
#include "../../../mem/mem.h"
#include "../../../mem/shm_mem.h"
#include "../../../sr_module.h"
#include "../nats_dl.h"
#include "../nats_pool.h"

/* ── core seams ─────────────────────────────────────────────────── */

static int test_log_level = L_WARN;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;
int dp_my_pid(void) { return getpid(); }
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

/* shm allocator: plain malloc (one process owns the pool config) */
void *shm_block = NULL;
gen_lock_t *mem_lock = NULL;
int shm_use_global_lock = 0;
long event_shm_threshold = 0;
long *event_shm_last = NULL;
int *event_shm_pending = NULL;
static void *t_shm_malloc(void *blk, unsigned long size) { (void)blk; return malloc(size); }
static void t_shm_free(void *blk, void *p) { (void)blk; free(p); }
static unsigned long t_shm_size(void *blk) { (void)blk; return 1UL << 30; }
static unsigned long t_shm_rused(void *blk) { (void)blk; return 0; }
void *(*gen_shm_malloc)(void *blk, unsigned long size) = t_shm_malloc;
void (*gen_shm_free)(void *blk, void *p) = t_shm_free;
unsigned long (*gen_shm_get_size)(void *blk) = t_shm_size;
unsigned long (*gen_shm_get_rused)(void *blk) = t_shm_rused;
void shm_event_raise(long used, long size, long perc)
{ (void)used; (void)size; (void)perc; }

/* no tls_mgm; the libnats table is filled by main() */
cmd_function find_export(const char *name, int flags)
{ (void)name; (void)flags; return NULL; }
int nats_dl_load(const char *path) { (void)path; return 0; }
int nats_dl_supports_srv(void) { return 0; }
const char *nats_dl_path(void) { return "fake"; }

/* ── fake libnats: counters, fake handles ────────────────────────── */

static int n_open, n_connect, n_conn_destroy, n_js_destroy, n_close_wait;
static int fake_obj;   /* any non-NULL address */

static natsStatus f_nats_Open(int64_t s) { (void)s; n_open++; return NATS_OK; }
static natsStatus f_OptCreate(natsOptions **o) { *o = (natsOptions *)&fake_obj; return NATS_OK; }
static void f_OptDestroy(natsOptions *o) { (void)o; }
static natsStatus f_ok_cb(natsOptions *o, void *cb, void *cl) { (void)o; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_ok_int(natsOptions *o, int v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_ok_i64(natsOptions *o, int64_t v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_ok_bool(natsOptions *o, bool v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_retry(natsOptions *o, bool r, void *cb, void *cl)
{ (void)o; (void)r; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_jitter(natsOptions *o, int64_t a, int64_t b)
{ (void)o; (void)a; (void)b; return NATS_OK; }
static natsStatus f_servers(natsOptions *o, const char **s, int n)
{ (void)o; (void)s; (void)n; return NATS_OK; }
static natsStatus f_Connect(natsConnection **nc, natsOptions *o)
{ (void)o; n_connect++; *nc = (natsConnection *)(intptr_t)(0x1000 + getpid()); return NATS_OK; }
static natsStatus f_ConnUrl(natsConnection *nc, char *buf, size_t len)
{ (void)nc; snprintf(buf, len, "nats://fake:4222"); return NATS_OK; }
static const char *f_GetText(natsStatus s) { (void)s; return "fake"; }
static const char *f_ErrStack(char *b, size_t l) { (void)b; (void)l; return ""; }
static void f_Sleep(int64_t ms) { (void)ms; }
static natsStatus f_JetStream(jsCtx **js, natsConnection *nc, jsOptions *o)
{ (void)nc; (void)o; *js = (jsCtx *)&fake_obj; return NATS_OK; }
static natsStatus f_jsOptInit(jsOptions *o) { memset(o, 0, sizeof *o); return NATS_OK; }
static void f_jsDestroy(jsCtx *js) { (void)js; n_js_destroy++; }
static void f_ConnDestroy(natsConnection *nc) { (void)nc; n_conn_destroy++; }
static natsStatus f_DrainTimeout(natsConnection *nc, int64_t t) { (void)nc; (void)t; return NATS_OK; }
static natsStatus f_CloseAndWait(int64_t t) { (void)t; n_close_wait++; return NATS_OK; }
static natsStatus f_PubOptInit(jsPubOptions *o) { memset(o, 0, sizeof *o); return NATS_OK; }
static natsStatus f_PubAsyncComplete(jsCtx *js, jsPubOptions *o) { (void)js; (void)o; return NATS_OK; }

nats_dl_funcs_t nats_dl;

static int g_fails;
#define ASSERT(c, m) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", m); g_fails++; } \
	else fprintf(stderr, "  ok: %s\n", m); } while (0)

/* the child reports its view through its exit status, one bit per check */
int main(void)
{
	natsConnection *nc;
	pid_t pid;
	int st, epoch0;

	nats_dl.nats_Open = f_nats_Open;
	nats_dl.natsOptions_Create = f_OptCreate;
	nats_dl.natsOptions_Destroy = f_OptDestroy;
	nats_dl.natsOptions_SetDisconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetReconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetMaxPingsOut = (void *)f_ok_int;
	nats_dl.natsOptions_SetMaxReconnect = (void *)f_ok_int;
	nats_dl.natsOptions_SetNoRandomize = (void *)f_ok_bool;
	nats_dl.natsOptions_SetPingInterval = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectWait = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectJitter = (void *)f_jitter;
	nats_dl.natsOptions_SetRetryOnFailedConnect = (void *)f_retry;
	nats_dl.natsOptions_SetSecure = (void *)f_ok_bool;
	nats_dl.natsOptions_SetServers = (void *)f_servers;
	nats_dl.natsConnection_Connect = f_Connect;
	nats_dl.natsConnection_GetConnectedUrl = (void *)f_ConnUrl;
	nats_dl.natsStatus_GetText = f_GetText;
	nats_dl.nats_GetLastErrorStack = (void *)f_ErrStack;
	nats_dl.nats_Sleep = f_Sleep;
	nats_dl.natsConnection_JetStream = f_JetStream;
	nats_dl.jsOptions_Init = f_jsOptInit;
	nats_dl.jsCtx_Destroy = f_jsDestroy;
	nats_dl.natsConnection_Destroy = f_ConnDestroy;
	nats_dl.natsConnection_DrainTimeout = f_DrainTimeout;
	nats_dl.nats_CloseAndWait = f_CloseAndWait;
	nats_dl.jsPubOptions_Init = f_PubOptInit;
	nats_dl.js_PublishAsyncComplete = f_PubAsyncComplete;

	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0) {
		fprintf(stderr, "FAIL: register\n");
		return 1;
	}

	fprintf(stderr, "a connection opened before fork (mod_init):\n");
	nc = nats_pool_get();
	ASSERT(nc != NULL && n_connect == 1, "parent connected");
	ASSERT(nats_pool_get_js() != NULL, "parent JetStream context");
	epoch0 = nats_pool_get_reconnect_epoch();

	pid = fork();
	if (pid == 0) {
		/* the child: nothing inherited, connects on its own */
		int bad = 0;
		n_connect = 0; n_open = 0;
		if (nats_pool_is_connected()) bad |= 1;
		nc = nats_pool_get();
		if (!nc || n_connect != 1) bad |= 2;
		if (n_open != 1) bad |= 4;   /* the library re-opened in the child */
		/* a worker (process_no > 0) that forks, e.g. exec(), keeps its
		 * connection: only the attendant's pre-fork one is closed */
		process_no = 3;
		n_conn_destroy = 0; n_close_wait = 0;
		{
			pid_t g = fork();
			int gst;
			if (g == 0)
				_exit(0);
			waitpid(g, &gst, 0);
		}
		if (n_conn_destroy != 0 || n_close_wait != 0) bad |= 8;
		if (nats_pool_get() != nc || n_connect != 1) bad |= 16;
		_exit(bad);
	}
	waitpid(pid, &st, 0);
	ASSERT(WIFEXITED(st) && (WEXITSTATUS(st) & 1) == 0,
		"child: not connected on arrival (no inherited connection)");
	ASSERT(WIFEXITED(st) && (WEXITSTATUS(st) & 2) == 0,
		"child: nats_pool_get() opens its own connection");
	ASSERT(WIFEXITED(st) && (WEXITSTATUS(st) & 4) == 0,
		"child: the nats.c library is opened again in the child");
	ASSERT(WIFEXITED(st) && (WEXITSTATUS(st) & 8) == 0,
		"worker fork (process_no > 0): its connection is left alone");
	ASSERT(WIFEXITED(st) && (WEXITSTATUS(st) & 16) == 0,
		"worker keeps using the same connection afterwards");
	ASSERT(n_conn_destroy == 1 && n_js_destroy == 1,
		"parent destroyed its connection and JetStream context before fork");
	ASSERT(n_close_wait == 1, "parent closed the nats.c library before fork");
	ASSERT(nats_pool_get_reconnect_epoch() != epoch0,
		"reconnect epoch bumped (cached KV handles get refreshed)");
	ASSERT(!nats_pool_is_connected(), "parent no longer connected");

	fprintf(stderr, "a fork with nothing open does nothing:\n");
	pid = fork();
	if (pid == 0)
		_exit(0);
	waitpid(pid, &st, 0);
	ASSERT(n_conn_destroy == 1 && n_close_wait == 1,
		"no second teardown");

	fprintf(stderr, "\n%s (%d failure%s)\n", g_fails ? "FAILED" : "PASSED",
		g_fails, g_fails == 1 ? "" : "s");
	return g_fails ? 1 : 0;
}
