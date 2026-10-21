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
 * test_pool_connect_opts.c -- what the shared pool asks libnats for at
 * connect time: the no_randomize modparam (server order) and DNS SRV
 * server URLs (nats+srv:// and tls+srv://), which are refused unless the
 * loaded libnats can resolve them -- a libnats without SRV support would
 * dial the domain itself.
 *
 * Links the REAL ../nats_pool.c against a fake libnats table that
 * records the options it receives.
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
const char *nats_dl_path(void) { return "fake"; }

/* the libnats capability probe, controlled per scenario */
static int fake_supports_srv;
int nats_dl_supports_srv(void) { return fake_supports_srv; }

/* ── fake libnats: records what the connect path asked for ───────── */

static int fake_obj;   /* any non-NULL address */
static int last_no_randomize = -1;   /* -1: SetNoRandomize not called */
static int last_secure = -1;         /* -1: SetSecure not called */
static char last_servers[512];

static natsStatus f_nats_Open(int64_t s) { (void)s; return NATS_OK; }
static natsStatus f_OptCreate(natsOptions **o) { *o = (natsOptions *)&fake_obj; return NATS_OK; }
static void f_OptDestroy(natsOptions *o) { (void)o; }
static natsStatus f_ok_cb(natsOptions *o, void *cb, void *cl) { (void)o; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_ok_int(natsOptions *o, int v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_ok_i64(natsOptions *o, int64_t v) { (void)o; (void)v; return NATS_OK; }
static natsStatus f_secure(natsOptions *o, bool v) { (void)o; last_secure = v ? 1 : 0; return NATS_OK; }
static natsStatus f_no_randomize(natsOptions *o, bool v) { (void)o; last_no_randomize = v ? 1 : 0; return NATS_OK; }
static natsStatus f_retry(natsOptions *o, bool r, void *cb, void *cl)
{ (void)o; (void)r; (void)cb; (void)cl; return NATS_OK; }
static natsStatus f_jitter(natsOptions *o, int64_t a, int64_t b)
{ (void)o; (void)a; (void)b; return NATS_OK; }
static natsStatus f_servers(natsOptions *o, const char **s, int n)
{
	int i;
	(void)o;
	last_servers[0] = '\0';
	for (i = 0; i < n; i++) {
		if (i)
			strncat(last_servers, ",", sizeof(last_servers) - strlen(last_servers) - 1);
		strncat(last_servers, s[i], sizeof(last_servers) - strlen(last_servers) - 1);
	}
	return NATS_OK;
}
static int n_connect;
static natsStatus f_Connect(natsConnection **nc, natsOptions *o)
{ (void)o; n_connect++; *nc = (natsConnection *)(intptr_t)(0x1000 + getpid()); return NATS_OK; }
static natsStatus f_ConnUrl(natsConnection *nc, char *buf, size_t len)
{ (void)nc; snprintf(buf, len, "nats://fake:4222"); return NATS_OK; }
static const char *f_GetText(natsStatus s) { (void)s; return "fake"; }
static const char *f_ErrStack(char *b, size_t l) { (void)b; (void)l; return ""; }
static void f_Sleep(int64_t ms) { (void)ms; }

nats_dl_funcs_t nats_dl;

static int g_fails;
#define ASSERT(c, m) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", m); g_fails++; } \
	else fprintf(stderr, "  ok: %s\n", m); } while (0)

static void fill_table(void)
{
	nats_dl.nats_Open = f_nats_Open;
	nats_dl.natsOptions_Create = f_OptCreate;
	nats_dl.natsOptions_Destroy = f_OptDestroy;
	nats_dl.natsOptions_SetDisconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetReconnectedCB = (void *)f_ok_cb;
	nats_dl.natsOptions_SetMaxPingsOut = (void *)f_ok_int;
	nats_dl.natsOptions_SetMaxReconnect = (void *)f_ok_int;
	nats_dl.natsOptions_SetNoRandomize = (void *)f_no_randomize;
	nats_dl.natsOptions_SetPingInterval = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectWait = (void *)f_ok_i64;
	nats_dl.natsOptions_SetReconnectJitter = (void *)f_jitter;
	nats_dl.natsOptions_SetRetryOnFailedConnect = (void *)f_retry;
	nats_dl.natsOptions_SetSecure = (void *)f_secure;
	nats_dl.natsOptions_SetServers = (void *)f_servers;
	nats_dl.natsConnection_Connect = f_Connect;
	nats_dl.natsConnection_GetConnectedUrl = (void *)f_ConnUrl;
	nats_dl.natsStatus_GetText = f_GetText;
	nats_dl.nats_GetLastErrorStack = (void *)f_ErrStack;
	nats_dl.nats_Sleep = f_Sleep;
}

/* Each scenario runs in its own child, so it starts from a pristine pool
 * (nothing registered, no connection, default modparams). */
typedef int (*scenario_f)(void);

static void run(const char *name, scenario_f f)
{
	pid_t pid;
	int st;

	pid = fork();
	if (pid == 0)
		_exit(f() ? 0 : 1);
	waitpid(pid, &st, 0);
	ASSERT(WIFEXITED(st) && WEXITSTATUS(st) == 0, name);
}

/* ── no_randomize ───────────────────────────────────────────────── */

static int s_default_randomizes(void)
{
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && last_no_randomize == 0;
}

static int s_no_randomize_set(void)
{
	if (nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)1) != 0)
		return 0;
	if (nats_pool_register("nats://127.0.0.1:4222,nats://127.0.0.1:4223",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && last_no_randomize == 1;
}

static int s_no_randomize_zero(void)
{
	if (nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)0) != 0)
		return 0;
	if (nats_pool_register("nats://127.0.0.1:4222", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && last_no_randomize == 0;
}

static int s_no_randomize_rejects(void)
{
	return nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)2) == -1
		&& nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)-1) == -1
		&& nats_pool_no_randomize_setter(STR_PARAM, (void *)"1") == -1
		&& nats_pool_no_randomize == 0;
}

static int s_no_randomize_or_merge(void)
{
	/* one module asks for it, another leaves it off: the shared
	 * connection keeps the requested order */
	return nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)1) == 0
		&& nats_pool_no_randomize_setter(INT_PARAM, (void *)(long)0) == 0
		&& nats_pool_no_randomize == 1;
}

/* ── SRV URLs ───────────────────────────────────────────────────── */

static int s_srv_unsupported(void)
{
	fake_supports_srv = 0;
	return nats_pool_register("nats+srv://example.test", "test", 2000, 3) == -1;
}

static int s_srv_unsupported_any_case(void)
{
	fake_supports_srv = 0;
	return nats_pool_register("NATS+SRV://example.test", "test", 2000, 3) == -1;
}

static int s_srv_unsupported_in_list(void)
{
	fake_supports_srv = 0;
	return nats_pool_register("nats://127.0.0.1:4222, tls+srv://example.test",
		"test", 2000, 3) == -1;
}

static int s_srv_unsupported_merge(void)
{
	fake_supports_srv = 0;
	if (nats_pool_register("nats://127.0.0.1:4222", "first", 2000, 3) != 0)
		return 0;
	return nats_pool_register("nats+srv://example.test", "second", 2000, 3) == -1;
}

static int s_srv_supported(void)
{
	fake_supports_srv = 1;
	if (nats_pool_register("nats+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(last_servers, "nats+srv://example.test") == 0
		&& last_secure == -1;
}

static int s_tls_srv_is_tls(void)
{
	fake_supports_srv = 1;
	if (nats_pool_register("tls+srv://example.test", "test", 2000, 3) != 0)
		return 0;
	/* no tls_mgm in this harness: the connect fails after SetSecure */
	(void)nats_pool_get();
	return last_secure == 1;
}

static int s_tls_srv_upper_is_tls(void)
{
	fake_supports_srv = 1;
	if (nats_pool_register("TLS+SRV://example.test", "test", 2000, 3) != 0)
		return 0;
	(void)nats_pool_get();
	return last_secure == 1;
}

static int s_srv_port_corrected(void)
{
	/* a port or path is dropped with a warning, startup goes on */
	fake_supports_srv = 1;
	if (nats_pool_register("nats+srv://u:p@example.test:4222/x", "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(last_servers, "nats+srv://u:p@example.test") == 0;
}

static int s_srv_corrected_in_list(void)
{
	fake_supports_srv = 1;
	if (nats_pool_register("nats://127.0.0.1:4222,tls+srv://example.test/x",
	    "test", 2000, 3) != 0)
		return 0;
	(void)nats_pool_get();
	return strcmp(last_servers, "nats://127.0.0.1:4222,tls+srv://example.test") == 0;
}

static int s_srv_corrected_merge(void)
{
	fake_supports_srv = 1;
	if (nats_pool_register("nats://127.0.0.1:4222", "first", 2000, 3) != 0)
		return 0;
	if (nats_pool_register("nats+srv://example.test:1", "second", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(last_servers, "nats://127.0.0.1:4222,nats+srv://example.test") == 0;
}

static int s_srv_corrected_dedup(void)
{
	/* the corrected URL is a duplicate of one already listed */
	fake_supports_srv = 1;
	if (nats_pool_register("nats+srv://example.test,nats+srv://example.test:4222",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(last_servers, "nats+srv://example.test") == 0;
}

static int s_srv_unusable_skipped(void)
{
	/* no usable domain: skipped with a warning, the other servers stay */
	fake_supports_srv = 1;
	if (nats_pool_register("nats://127.0.0.1:4222,nats+srv://exa mple.test",
	    "test", 2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL
		&& strcmp(last_servers, "nats://127.0.0.1:4222") == 0;
}

static int s_srv_unusable_only(void)
{
	/* nothing usable left: startup goes on, NATS stays unavailable */
	fake_supports_srv = 1;
	if (nats_pool_register("nats+srv://exa%41mple.test", "test", 2000, 3) != 0)
		return 0;
	n_connect = 0;
	return nats_pool_get() == NULL && nats_pool_get() == NULL && n_connect == 0;
}

static int s_not_srv_needs_nothing(void)
{
	fake_supports_srv = 0;
	if (nats_pool_register("nats+srvx://example.test:4222,tls+srv:/x", "test",
	    2000, 3) != 0)
		return 0;
	return nats_pool_get() != NULL && last_secure == -1;
}

int main(void)
{
	fill_table();

	fprintf(stderr, "no_randomize:\n");
	run("default: the server list is randomized", s_default_randomizes);
	run("no_randomize=1: libnats keeps the configured order", s_no_randomize_set);
	run("no_randomize=0: randomized", s_no_randomize_zero);
	run("values other than 0/1 and non-integers are rejected", s_no_randomize_rejects);
	run("any module asking for it turns it on (OR merge)", s_no_randomize_or_merge);

	fprintf(stderr, "SRV URLs:\n");
	run("nats+srv:// refused when libnats lacks SRV support", s_srv_unsupported);
	run("the scheme check is case-insensitive", s_srv_unsupported_any_case);
	run("an SRV URL anywhere in the list is refused", s_srv_unsupported_in_list);
	run("an SRV URL in a later registration is refused", s_srv_unsupported_merge);
	run("nats+srv:// passed to libnats when supported", s_srv_supported);
	run("tls+srv:// turns TLS on", s_tls_srv_is_tls);
	run("TLS+SRV:// turns TLS on", s_tls_srv_upper_is_tls);
	run("look-alike schemes are not SRV URLs", s_not_srv_needs_nothing);
	run("port / path of an SRV URL dropped, startup goes on", s_srv_port_corrected);
	run("corrected SRV URL among other servers", s_srv_corrected_in_list);
	run("corrected SRV URL in a later registration", s_srv_corrected_merge);
	run("corrected SRV URL that duplicates another is merged", s_srv_corrected_dedup);
	run("SRV URL without a usable domain skipped, others kept", s_srv_unusable_skipped);
	run("only unusable SRV URLs: startup goes on, no connection", s_srv_unusable_only);

	fprintf(stderr, "\n%s (%d failure%s)\n", g_fails ? "FAILED" : "PASSED",
		g_fails, g_fails == 1 ? "" : "s");
	return g_fails ? 1 : 0;
}
