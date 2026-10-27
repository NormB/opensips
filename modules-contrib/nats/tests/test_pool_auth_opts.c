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
 * test_pool_auth_opts.c -- the credentials the shared pool hands libnats
 * at connect time, from the user, password, token, creds_file, nkey and
 * nkey_seed_file modparams: one libnats call per method, nothing without
 * them, a refused startup for an incomplete, ambiguous or unreadable
 * set, a refused connection when libnats rejects them, and no secret in
 * the log.
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
/* everything logged by the scenario (each runs in its own child) */
static char g_log[8192];
void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap, ap2;
	size_t used;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	va_copy(ap2, ap);
	vfprintf(stderr, stderr_fmt, ap);
	used = strlen(g_log);
	vsnprintf(g_log + used, sizeof(g_log) - used, stderr_fmt, ap2);
	va_end(ap2);
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

/* ── fake libnats: records what the connect path asked for ───────── */

static int fake_obj;   /* any non-NULL address */
static int last_no_randomize = -1;   /* -1: SetNoRandomize not called */
static int last_secure = -1;         /* -1: SetSecure not called */
static char last_servers[512];
/* credential calls */
static int n_auth_calls;
static char a_user[64], a_pw[64], a_token[64], a_creds[256], a_creds_seed[256],
	a_nkey[64], a_seed[256];
static natsStatus auth_status = NATS_OK;
static void cp(char *d, const char *s) { snprintf(d, 64, "%s", s ? s : "(null)"); }
static void cpl(char *d, const char *s) { snprintf(d, 256, "%s", s ? s : "(null)"); }
static natsStatus f_userinfo(natsOptions *o, const char *u, const char *p)
{ (void)o; n_auth_calls++; cp(a_user, u); cp(a_pw, p); return auth_status; }
static natsStatus f_token(natsOptions *o, const char *t)
{ (void)o; n_auth_calls++; cp(a_token, t); return auth_status; }
static natsStatus f_creds(natsOptions *o, const char *f, const char *s)
{ (void)o; n_auth_calls++; cpl(a_creds, f); cpl(a_creds_seed, s); return auth_status; }
static natsStatus f_nkey(natsOptions *o, const char *k, const char *f)
{ (void)o; n_auth_calls++; cp(a_nkey, k); cpl(a_seed, f); return auth_status; }

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
	nats_dl.natsOptions_SetReconnectBufSize = (void *)f_ok_int;
	nats_dl.natsOptions_SetRetryOnFailedConnect = (void *)f_retry;
	nats_dl.natsOptions_SetSecure = (void *)f_secure;
	nats_dl.natsOptions_SetServers = (void *)f_servers;
	nats_dl.natsOptions_SetUserInfo = (void *)f_userinfo;
	nats_dl.natsOptions_SetToken = (void *)f_token;
	nats_dl.natsOptions_SetUserCredentialsFromFiles = (void *)f_creds;
	nats_dl.natsOptions_SetNKeyFromSeed = (void *)f_nkey;
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

/* ── helpers ────────────────────────────────────────────────────── */

static char creds_path[64] = "/tmp/natsauthXXXXXX";
static char seed_path[64] = "/tmp/natsseedXXXXXX";

static int set(int (*setter)(unsigned int, void *), const char *v)
{
	return setter(STR_PARAM, (void *)v);
}

static int reg(const char *url)
{
	return nats_pool_register(url, "test", 2000, 3);
}

/* ── scenarios ──────────────────────────────────────────────────── */

static int s_none(void)
{
	return reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 0 && !nats_pool_auth_configured();
}

static int s_userpass(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_password_setter, "pa55word") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 1 && !strcmp(a_user, "alice") &&
		!strcmp(a_pw, "pa55word") && nats_pool_auth_configured();
}

static int s_token(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 1 && !strcmp(a_token, "t0ken");
}

static int s_creds(void)
{
	return set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 1 && !strcmp(a_creds, creds_path) &&
		!strcmp(a_creds_seed, "(null)");
}

static int s_nkey(void)
{
	return set(nats_pool_auth_nkey_setter, "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4") == 0 &&
		set(nats_pool_auth_nkey_seed_file_setter, seed_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 1 && !strncmp(a_nkey, "UDXU4RCS", 8) &&
		!strcmp(a_seed, seed_path);
}

static int s_user_alone(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		reg("nats://127.0.0.1:4222") == -1 &&
		strstr(g_log, "user and password must be set together");
}

static int s_seed_alone(void)
{
	return set(nats_pool_auth_nkey_seed_file_setter, seed_path) == 0 &&
		reg("nats://127.0.0.1:4222") == -1;
}

static int s_two_methods(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == -1 && strstr(g_log, "set only one");
}

static int s_url_and_modparam(void)
{
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://u:s3cr3t@127.0.0.1:4222") == -1 &&
		strstr(g_log, "both in a server URL and") && !strstr(g_log, "s3cr3t");
}

static int s_url_and_modparam_merge(void)
{
	/* a later module's URL with user info is refused too */
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 &&
		nats_pool_register("nats://u:p@127.0.0.1:4223", "second", 2000, 3) == -1;
}

static int s_url_only(void)
{
	/* credentials only in the URL: as before, no libnats auth call */
	return reg("nats://u:p@127.0.0.1:4222") == 0 && nats_pool_get() != NULL &&
		n_auth_calls == 0;
}

static int s_creds_missing(void)
{
	return set(nats_pool_auth_creds_file_setter, "/nonexistent/x.creds") == 0 &&
		reg("nats://127.0.0.1:4222") == -1 &&
		strstr(g_log, "/nonexistent/x.creds");
}

static int s_seed_unreadable(void)
{
	return set(nats_pool_auth_nkey_setter, "UABC") == 0 &&
		set(nats_pool_auth_nkey_seed_file_setter, "/nonexistent/s.nk") == 0 &&
		reg("nats://127.0.0.1:4222") == -1;
}

static int s_setter_merge(void)
{
	return set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_user_setter, "bob") == -1 &&
		set(nats_pool_auth_token_setter, "") == -1 &&
		nats_pool_auth_token_setter(INT_PARAM, (void *)(long)5) == -1;
}

static int s_libnats_refuses(void)
{
	/* fail closed: no connection without the credentials */
	auth_status = NATS_INVALID_ARG;
	return set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() == NULL &&
		n_connect == 0;
}

static int s_no_secret_logged(void)
{
	int ok = set(nats_pool_auth_user_setter, "alice") == 0 &&
		set(nats_pool_auth_password_setter, "pa55word") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && !strstr(g_log, "pa55word");
}

static int s_plaintext_warn(void)
{
	int ok = set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && strstr(g_log, "in plain text") && !strstr(g_log, "t0ken");
}

static int s_tls_no_plaintext_warn(void)
{
	/* no tls_mgm in this harness: the connect fails at the TLS setup,
	 * after the check */
	(void)(set(nats_pool_auth_token_setter, "t0ken") == 0 &&
		reg("tls://127.0.0.1:4222") == 0);
	(void)nats_pool_get();
	return !strstr(g_log, "in plain text");
}

static int s_nkey_no_plaintext_warn(void)
{
	int ok = set(nats_pool_auth_creds_file_setter, creds_path) == 0 &&
		reg("nats://127.0.0.1:4222") == 0 && nats_pool_get() != NULL;
	return ok && !strstr(g_log, "in plain text");
}

int main(void)
{
	int fd;

	fd = mkstemp(creds_path);
	if (fd < 0) return 1;
	close(fd);
	fd = mkstemp(seed_path);
	if (fd < 0) { unlink(creds_path); return 1; }
	close(fd);

	fill_table();

	fprintf(stderr, "methods:\n");
	run("no credentials: no libnats auth call", s_none);
	run("user + password: natsOptions_SetUserInfo", s_userpass);
	run("token: natsOptions_SetToken", s_token);
	run("creds_file: natsOptions_SetUserCredentialsFromFiles (chained file)", s_creds);
	run("nkey + nkey_seed_file: natsOptions_SetNKeyFromSeed", s_nkey);
	run("credentials only in the URL: unchanged, no auth call", s_url_only);

	fprintf(stderr, "refused at startup:\n");
	run("user without password", s_user_alone);
	run("nkey_seed_file without nkey", s_seed_alone);
	run("two methods at once", s_two_methods);
	run("credentials in the URL and as modparams (URL not logged)", s_url_and_modparam);
	run("...also when the URL comes from a later module", s_url_and_modparam_merge);
	run("creds_file that cannot be read (path named)", s_creds_missing);
	run("nkey_seed_file that cannot be read", s_seed_unreadable);
	run("setter: same value kept, other value, empty and non-string refused", s_setter_merge);

	fprintf(stderr, "connect:\n");
	run("libnats refuses the credentials: no connection", s_libnats_refuses);
	run("the password is never logged", s_no_secret_logged);
	run("token over plain text: warning, token not logged", s_plaintext_warn);
	run("token over TLS: no plain-text warning", s_tls_no_plaintext_warn);
	run("creds file over plain text: no warning (nothing secret sent)", s_nkey_no_plaintext_warn);

	unlink(creds_path);
	unlink(seed_path);
	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
