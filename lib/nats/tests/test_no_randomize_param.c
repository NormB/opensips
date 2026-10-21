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
 * every module that registers the pool must export it through the shared
 * setter (nats_pool_no_randomize_setter), never as a module-local int:
 * a module-local value would never reach the connection.
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

static void check_module(const char *path, const char *label)
{
	char *src = slurp(path);
	const char *p;
	char msg[256];

	snprintf(msg, sizeof msg, "%s exports no_randomize via the shared setter", label);
	p = src ? strstr(src, "\"no_randomize\",") : NULL;
	CHECK(p && strstr(p, "INT_PARAM|USE_FUNC_PARAM") &&
		strstr(p, "nats_pool_no_randomize_setter") &&
		strstr(p, "nats_pool_no_randomize_setter") < strchr(p, '}'), msg);
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
