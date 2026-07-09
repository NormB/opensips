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
 * Regression test: nats_consumer must publish a heartbeat
 * that an external watchdog can read.  Without it, a wedged or
 * crashed consumer process leaves SIP workers blocked on the SHM
 * ring's eventfd forever.
 *
 * Tests:
 *   1. Source pattern: SHM struct declared, init/destroy hooks,
 *      tick called in the main loop, MI handler exposed.
 *   2. Functional: stale-detection arithmetic with simulated
 *      tick advancement.
 *
 * Build:
 *   gcc -g -O0 -Wall -pthread -o test_consumer_heartbeat test_consumer_heartbeat.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static int grep_count(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char line[1024];
	int hits = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) hits++;
	fclose(f);
	return hits;
}

/* mirror of the production stale-detection arithmetic */
static int is_stale(long long now_us, long long last_us, long long threshold_ms)
{
	if (last_us <= 0) return 1;
	if (now_us < last_us) return 1;
	return ((now_us - last_us) / 1000LL) > threshold_ms;
}

int main(void)
{
	/* CASE 1: SHM struct + lifecycle hooks declared in the header */
	ASSERT(grep_count("../nats_consumer_proc.h",
		"nats_consumer_heartbeat_t") >= 1,
		"nats_consumer_proc.h declares nats_consumer_heartbeat_t");
	ASSERT(grep_count("../nats_consumer_proc.h",
		"nats_consumer_hb_init") >= 1,
		"nats_consumer_proc.h exports nats_consumer_hb_init");
	ASSERT(grep_count("../nats_consumer_proc.h",
		"nats_consumer_hb_destroy") >= 1,
		"nats_consumer_proc.h exports nats_consumer_hb_destroy");

	/* CASE 2: tick is bumped inside the consumer-process main loop */
	ASSERT(grep_count("../nats_consumer_proc.c",
		"nats_consumer_hb_tick") >= 2,
		"nats_consumer_proc.c calls nats_consumer_hb_tick "
		"(definition + at least one call site in the loop)");

	/* CASE 3: MI handler exposed */
	ASSERT(grep_count("../nats_mi.h",
		"mi_consumer_health") >= 1,
		"nats_mi.h declares mi_consumer_health");
	ASSERT(grep_count("../nats_mi.c",
		"nats_consumer_health") >= 1,
		"nats_mi.c registers nats_consumer_health MI command");

	/* CASE 4: stale detection arithmetic */
	{
		long long now_us = 100 * 1000 * 1000LL;   /* 100 s */
		ASSERT(is_stale(now_us, 99 * 1000 * 1000LL, 5000) == 0,
			"1s-old tick is fresh under 5s threshold");
		ASSERT(is_stale(now_us, 90 * 1000 * 1000LL, 5000) == 1,
			"10s-old tick is stale under 5s threshold");
		ASSERT(is_stale(now_us, 0, 5000) == 1,
			"never-ticked is stale");
		ASSERT(is_stale(now_us, now_us + 1000, 5000) == 1,
			"future tick is stale (clock anomaly)");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
