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
 * The no_randomize modparam is one setting of the shared connection, so
 * the nats module exports it through the shared setter
 * (nats_pool_no_randomize_setter) and applies it through set_param(), and
 * every module that registers the pool exports it through its forwarding
 * setter (nats_alias_no_randomize, nats_bind_mod.h), never as a
 * module-local int: a module-local value would never reach the
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

/* "no_randomize" is exported with INT_PARAM|USE_FUNC_PARAM and @setter
 * inside its entry */
static void check_export(const char *src, const char *label, const char *setter)
{
	const char *p, *end;
	char msg[256];

	snprintf(msg, sizeof msg, "%s exports no_randomize via %s", label, setter);
	p = src ? strstr(src, "\"no_randomize\",") : NULL;
	end = p ? strchr(p, '}') : NULL;
	CHECK(p && end && strstr(p, "INT_PARAM|USE_FUNC_PARAM") &&
		strstr(p, "INT_PARAM|USE_FUNC_PARAM") < end &&
		strstr(p, setter) && strstr(p, setter) < end, msg);
}

static void check_module(const char *path, const char *label)
{
	char *src = slurp(path);
	char msg[256];

	check_export(src, label, "nats_alias_no_randomize");
	snprintf(msg, sizeof msg, "%s defines nats_alias_no_randomize", label);
	CHECK(src && strstr(src, "NATS_ALIAS_SETTER(no_randomize)"), msg);
	free(src);
}

static void check_nats_module(void)
{
	char *src = slurp("../../../modules-contrib/nats/nats.c");
	const char *t, *end;

	/* the module parameter (params[], after shared_params[]) */
	check_export(src ? strstr(src, "param_export_t params[] = {") : NULL, "nats",
		"nats_pool_no_randomize_setter");
	/* set_param() table: the forwarded value reaches the same setter */
	t = src ? strstr(src, "shared_params[] = {") : NULL;
	end = t ? strstr(t, "\n};") : NULL;
	t = t ? strstr(t, "{\"no_randomize\",") : NULL;
	CHECK(t && end && t < end && strstr(t, "nats_pool_no_randomize_setter") &&
		strstr(t, "nats_pool_no_randomize_setter") < strchr(t, '}'),
		"nats set_param() applies no_randomize via nats_pool_no_randomize_setter");
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
