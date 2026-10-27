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
 * Settings of the shared connection (reconnect_buf_size and the
 * credentials user, password, token, creds_file, nkey, nkey_seed_file) are
 * exported by the nats module through the shared setters, which its
 * set_param() also applies, and by every module that registers the pool
 * through its forwarding setter (nats_alias_<name>, nats_bind_mod.h), never
 * as a module-local int: a module-local value would never reach the
 * connection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", label); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", label);            } \
} while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf;
	long n;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (buf && fread(buf, 1, n, f) != (size_t)n) {
		free(buf);
		buf = NULL;
	}
	if (buf)
		buf[n] = '\0';
	fclose(f);
	return buf;
}

/* @param is exported as "name", with @flags and @setter inside its entry */
static void check_param(const char *src, const char *label, const char *param,
	const char *flags, const char *setter)
{
	char key[128], msg[256];
	const char *p, *end;

	snprintf(key, sizeof key, "\"%s\",", param);
	snprintf(msg, sizeof msg, "%s exports %s via %s", label, param, setter);
	p = src ? strstr(src, key) : NULL;
	end = p ? strchr(p, '}') : NULL;
	CHECK(p && end && strstr(p, flags) && strstr(p, flags) < end &&
		strstr(p, setter) && strstr(p, setter) < end, msg);
}

static const struct {
	const char *param, *flags, *setter;
} shared[] = {
	{"reconnect_buf_size", "INT_PARAM|USE_FUNC_PARAM", "nats_pool_reconnect_buf_size_setter"},
	{"user",           "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_user_setter"},
	{"password",       "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_password_setter"},
	{"token",          "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_token_setter"},
	{"creds_file",     "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_creds_file_setter"},
	{"nkey",           "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_nkey_setter"},
	{"nkey_seed_file", "STR_PARAM|USE_FUNC_PARAM", "nats_pool_auth_nkey_seed_file_setter"},
};
#define SHARED_N (sizeof shared / sizeof shared[0])

static void check_module(const char *path, const char *label)
{
	char *src = slurp(path);
	char setter[128], def[128], msg[256];
	unsigned i;

	for (i = 0; i < SHARED_N; i++) {
		snprintf(setter, sizeof setter, "nats_alias_%s", shared[i].param);
		check_param(src, label, shared[i].param, shared[i].flags, setter);
		snprintf(def, sizeof def, "NATS_ALIAS_SETTER(%s)", shared[i].param);
		snprintf(msg, sizeof msg, "%s defines %s", label, setter);
		CHECK(src && strstr(src, def), msg);
	}
	free(src);
}

static void check_nats_module(void)
{
	char *src = slurp("../../../modules-contrib/nats/nats.c");
	const char *tab = src ? strstr(src, "shared_params[] = {") : NULL;
	const char *tab_end = tab ? strstr(tab, "\n};") : NULL;
	char key[128], msg[256];
	const char *p;
	unsigned i;

	for (i = 0; i < SHARED_N; i++) {
		/* the module parameter (params[], after shared_params[]) */
		check_param(src ? strstr(src, "param_export_t params[] = {") : NULL, "nats",
			shared[i].param, shared[i].flags, shared[i].setter);
		/* the set_param() entry */
		snprintf(key, sizeof key, "{\"%s\",", shared[i].param);
		snprintf(msg, sizeof msg, "nats set_param() applies %s via %s",
			shared[i].param, shared[i].setter);
		p = tab ? strstr(tab, key) : NULL;
		CHECK(p && p < tab_end && strstr(p, shared[i].setter) &&
			strstr(p, shared[i].setter) < strchr(p, '}'), msg);
	}
	free(src);
}

int main(void)
{
	check_nats_module();
	check_module("../../../modules-contrib/event_nats/event_nats.c", "event_nats");
	check_module("../../../modules-contrib/cachedb_nats/cachedb_nats.c", "cachedb_nats");
	check_module("../../../modules-contrib/nats_consumer/nats_consumer.c", "nats_consumer");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
