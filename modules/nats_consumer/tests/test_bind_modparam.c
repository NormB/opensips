/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 */

/*
 * Owner decision 3 wiring test: config-declared handle binds replace
 * file persistence.
 *
 *   - nats_consumer exports a `bind` modparam (repeatable): each value
 *     is the same config grammar nats_consumer_bind() takes, queued at
 *     parse time and bound in mod_init right after the registry comes
 *     up.  A bad or duplicate declarative bind FAILS mod_init (config
 *     errors must not boot half-configured).
 *   - The nats_persist layer (~1,100 lines + a writer pthread) is
 *     DELETED: with binds declarative in the .cfg there is nothing to
 *     rehydrate.  Runtime MI binds remain available but are ephemeral
 *     (documented).
 *
 * Source-pattern test; run from the tests/ directory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[2048];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) { found = 1; break; }
	}
	fclose(f);
	return found;
}

int main(void)
{
	const char *C = "../nats_consumer.c";
	const char *R = "../nats_handle_registry.c";

	/* the declarative bind modparam */
	ASSERT(file_contains(C, "\"bind\""),
		"bind modparam declared");
	ASSERT(file_contains(C, "set_bind_param"),
		"bind modparam queues configs via a USE_FUNC_PARAM handler");
	ASSERT(file_contains(C, "bind_one_config"),
		"script bind and mod_init share one bind core");

	/* persistence is gone */
	ASSERT(!file_contains(C, "nats_persist"),
		"nats_consumer.c no longer references nats_persist");
	ASSERT(!file_contains(C, "\"persist_handles\""),
		"persist_handles modparam removed");
	ASSERT(!file_contains(C, "\"persist_path\""),
		"persist_path modparam removed");
	ASSERT(!file_contains(R, "nats_persist_schedule_write"),
		"registry no longer schedules persistence writes");
	ASSERT(fopen("../nats_persist.c", "r") == NULL,
		"nats_persist.c deleted");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
