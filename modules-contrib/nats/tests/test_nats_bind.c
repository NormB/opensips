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
 * test_nats_bind.c -- binding the nats module's API, as a module that
 * uses it does (nats_bind_mod.h), against the REAL nats module
 * (../nats.c, ../nats_pool.c).  find_export() is faked over the nats
 * module's own cmds[] table, the way the core resolves "load_nats" when
 * nats.so is loaded.
 *
 *   - nats.so not loaded: load_nats_api() and nats_bind_api() fail, and
 *     the log names nats.so.
 *   - load_nats fills every member of struct nats_binds.
 *   - the module's settings of the shared connection (nats_alias_<name>
 *     setters) reach the connection only through nats_bind_api(), once,
 *     with the nats module's own checks (a wrong type fails the bind).
 *
 * Each scenario runs in its own child: the pool setters keep state.
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

/* ── core seams (as in test_pool_auth_opts.c) ─────────────────────── */

static int test_log_level = L_WARN;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int process_no = 0;
int dp_my_pid(void) { return getpid(); }
static char g_log[8192];
void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{
	va_list ap;
	size_t used;
	(void)level; (void)facility; (void)module; (void)func;
	(void)syslog_fmt; (void)format;
	if (!stderr_fmt)
		return;
	va_start(ap, format);
	used = strlen(g_log);
	vsnprintf(g_log + used, sizeof(g_log) - used, stderr_fmt, ap);
	va_end(ap);
}

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

/* the libnats table and loader of nats_dl.c (not linked) */
nats_dl_funcs_t nats_dl;
static nats_dl_funcs_t *const real_dl = &nats_dl;   /* before nats_bind.h */
int nats_dl_load(const char *path) { (void)path; return 0; }
const char *nats_dl_path(void) { return "fake"; }

/* find_export(): what the core finds when nats.so is (not) loaded */
extern struct module_exports exports;   /* ../nats.c */
static int g_nats_loaded;
cmd_function find_export(const char *name, int flags)
{
	const cmd_export_t *c;

	(void)flags;
	if (!g_nats_loaded)
		return NULL;
	for (c = exports.cmds; c && c->name; c++)
		if (strcmp(c->name, name) == 0)
			return c->function;
	return NULL;
}

/* ── the module side: as event_nats.c etc. ────────────────────────── */

#include "../nats_bind_mod.h"

struct nats_binds nats_api;

NATS_ALIAS_SETTER(no_randomize)
NATS_ALIAS_SETTER(user)
NATS_ALIAS_SETTER(password)

/* ── harness ─────────────────────────────────────────────────────── */

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);            } \
} while (0)

/* Run @fn in a child; its CHECK failures become the exit status. */
static void scenario(const char *name, void (*fn)(void))
{
	pid_t pid;
	int st;

	fprintf(stderr, "-- %s\n", name);
	fflush(stderr);
	pid = fork();
	if (pid == 0) {
		g_fails = 0;
		fn();
		_exit(g_fails ? 1 : 0);
	}
	if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) ||
	    WEXITSTATUS(st) != 0) {
		fprintf(stderr, "FAIL: scenario '%s'\n", name);
		g_fails++;
	}
}

/* ── scenarios ───────────────────────────────────────────────────── */

static void s_not_loaded(void)
{
	struct nats_binds b;

	g_nats_loaded = 0;
	CHECK(load_nats_api(&b) == -1, "load_nats_api() fails when nats.so is not loaded");
	g_log[0] = '\0';
	CHECK(nats_bind_api("tmod") == -1, "nats_bind_api() fails when nats.so is not loaded");
	CHECK(strstr(g_log, "tmod: cannot bind the nats module API") &&
		strstr(g_log, "loadmodule \"nats.so\""),
		"the failure names the module and nats.so");
}

static void s_every_member(void)
{
	struct nats_binds b;
	void *slot[sizeof(struct nats_binds) / sizeof(void *)];
	unsigned i, unset = 0;

	/* every member is a pointer: a member added to struct nats_binds
	 * and not filled by load_nats stays NULL here */
	_Static_assert(sizeof(struct nats_binds) % sizeof(void *) == 0,
		"struct nats_binds holds pointers only");
	g_nats_loaded = 1;
	memset(&b, 0, sizeof b);
	CHECK(load_nats_api(&b) == 0, "load_nats_api() binds when nats.so is loaded");
	memcpy(slot, &b, sizeof b);
	for (i = 0; i < sizeof slot / sizeof slot[0]; i++)
		if (!slot[i]) {
			fprintf(stderr, "    member %u of struct nats_binds is NULL\n", i);
			unset++;
		}
	CHECK(unset == 0, "load_nats sets every member of struct nats_binds");
	CHECK(b.dl == real_dl, "dl is the nats module's libnats table");
}

static void s_aliases_forwarded(void)
{
	g_nats_loaded = 1;
	CHECK(nats_alias_no_randomize(INT_PARAM, (void *)1L) == 0, "no_randomize kept");
	CHECK(nats_alias_user(STR_PARAM, "alice") == 0, "user kept");
	CHECK(nats_alias_password(STR_PARAM, "secret") == 0, "password kept");
	CHECK(nats_api.no_randomize == NULL, "nothing reaches the nats module before the bind");

	CHECK(nats_bind_api("tmod") == 0, "nats_bind_api() binds and forwards");
	CHECK(nats_pool_no_randomize == 1, "no_randomize reached the connection");
	CHECK(nats_pool_auth_configured(), "user and password reached the connection");

	/* forwarded once: a second bind applies nothing again (a second
	 * different user would be refused by the pool's setter) */
	CHECK(nats_alias_cnt == 0, "the kept settings are dropped once forwarded");
	CHECK(nats_bind_api("tmod") == 0, "a second bind forwards nothing again");
}

static void s_wrong_type(void)
{
	g_nats_loaded = 1;
	CHECK(nats_alias_no_randomize(STR_PARAM, "yes") == 0,
		"the module keeps the value as given");
	g_log[0] = '\0';
	CHECK(nats_bind_api("tmod") == -1,
		"a value the nats module refuses fails the bind");
	CHECK(strstr(g_log, "no_randomize") != NULL, "the refusal names the parameter");
}

static void s_keep_limit(void)
{
	int i, rc = 0;

	for (i = 0; i < NATS_ALIAS_MAX && rc == 0; i++)
		rc = nats_alias_user(STR_PARAM, "alice");
	CHECK(rc == 0, "NATS_ALIAS_MAX settings are kept");
	g_log[0] = '\0';
	CHECK(nats_alias_user(STR_PARAM, "alice") == -1, "one more is refused");
	CHECK(strstr(g_log, "too many NATS connection settings") != NULL,
		"the refusal is logged");
}

int main(void)
{
	scenario("nats.so not loaded", s_not_loaded);
	scenario("every API member is set", s_every_member);
	scenario("settings forwarded at bind", s_aliases_forwarded);
	scenario("a refused setting fails the bind", s_wrong_type);
	scenario("the kept-settings table is bounded", s_keep_limit);

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
