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
 * Settings of the shared connection (reconnect_buf_size) must be
 * exported by every module that registers the pool, through the shared
 * setter, never as a module-local int: a module-local value would never
 * reach the connection.
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

static void check_module(const char *path, const char *label)
{
	char *src = slurp(path);

	check_param(src, label, "reconnect_buf_size", "INT_PARAM|USE_FUNC_PARAM",
		"nats_pool_reconnect_buf_size_setter");
	free(src);
}

int main(void)
{
	check_module("../../../modules/event_nats/event_nats.c", "event_nats");
	check_module("../../../modules/cachedb_nats/cachedb_nats.c", "cachedb_nats");
	check_module("../../../modules/nats_consumer/nats_consumer.c", "nats_consumer");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
