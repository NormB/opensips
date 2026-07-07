/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * nats_cdb_reap_first_jitter(): deterministic first-fire stagger for
 * the reaper.  Every instance of a multi-proxy deployment boots its
 * reaper with the same nats_reap_interval; without a per-instance
 * offset they all start their first O(bucket) pass at the same
 * uptime and hammer the broker together.  The helper derives a
 * bounded, deterministic offset from a seed (the pid):
 *
 *   - range: 0 <= jitter <= interval / 4 (the first pass is late by
 *     at most a quarter interval; expiry timing barely moves),
 *   - deterministic: same (interval, seed) -> same jitter (restart
 *     stability, reproducible tests),
 *   - spread: different seeds actually produce different offsets
 *     (a constant 0 would defeat the point -- locked below),
 *   - degenerate intervals (<= 3 s) return 0 (a quarter of nothing
 *     is nothing; also covers the reap_interval zero-guard rejects),
 *   - adversarial seeds (0, 1, UINT_MAX) stay in range.
 *
 * Also structural: nats_cdb_reaper_proc_main() must actually apply
 * the jitter to its first-fire stamp.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reap_first_jitter
 *            test_reap_first_jitter.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "../cachedb_nats_expiry.h"

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
	buf[n] = '\0';
	fclose(f);
	return buf;
}

int main(void)
{
	unsigned int seed;
	int iv, j, distinct;
	int seen[128];

	printf("== bounds: 0 <= jitter <= interval/4, many seeds/intervals ==\n");
	{
		int ok = 1;
		int ivs[] = { 4, 5, 10, 30, 60, 120, 3600 };
		size_t k;
		for (k = 0; k < sizeof(ivs)/sizeof(ivs[0]); k++) {
			for (seed = 0; seed < 5000; seed++) {
				j = nats_cdb_reap_first_jitter(ivs[k], seed);
				if (j < 0 || j > ivs[k] / 4) { ok = 0; break; }
			}
		}
		CHECK(ok, "jitter always within [0, interval/4]");
	}

	printf("== determinism ==\n");
	CHECK(nats_cdb_reap_first_jitter(30, 12345)
	      == nats_cdb_reap_first_jitter(30, 12345),
	      "same (interval, seed) -> same jitter");

	printf("== spread: different seeds produce different offsets ==\n");
	iv = 30;   /* the default reap interval: jitter range 0..7 */
	memset(seen, 0, sizeof(seen));
	distinct = 0;
	for (seed = 1; seed <= 100; seed++) {
		j = nats_cdb_reap_first_jitter(iv, seed);
		if (j >= 0 && j < 128 && !seen[j]) { seen[j] = 1; distinct++; }
	}
	CHECK(distinct >= 3,
	      "at least 3 distinct offsets over 100 seeds (interval 30)");

	printf("== degenerate intervals ==\n");
	CHECK(nats_cdb_reap_first_jitter(0, 42) == 0, "interval 0 -> 0");
	CHECK(nats_cdb_reap_first_jitter(1, 42) == 0, "interval 1 -> 0");
	CHECK(nats_cdb_reap_first_jitter(3, 42) == 0, "interval 3 -> 0");
	CHECK(nats_cdb_reap_first_jitter(-30, 42) == 0, "negative interval -> 0");

	printf("== adversarial seeds stay in range ==\n");
	CHECK(nats_cdb_reap_first_jitter(30, 0) >= 0
	      && nats_cdb_reap_first_jitter(30, 0) <= 7, "seed 0 in range");
	CHECK(nats_cdb_reap_first_jitter(30, UINT_MAX) >= 0
	      && nats_cdb_reap_first_jitter(30, UINT_MAX) <= 7,
	      "seed UINT_MAX in range");

	printf("== wiring: reaper proc applies the jitter to first fire ==\n");
	{
		char *src = slurp("../cachedb_nats_expiry.c");
		CHECK(src != NULL, "can read ../cachedb_nats_expiry.c");
		if (src) {
			const char *proc = strstr(src, "void nats_cdb_reaper_proc_main");
			CHECK(proc != NULL
			      && strstr(proc, "nats_cdb_reap_first_jitter(") != NULL,
			      "nats_cdb_reaper_proc_main() applies first-fire jitter");
			free(src);
		}
	}

	printf("%s (%d failure(s))\n", fails ? "RED" : "GREEN", fails);
	return fails ? 1 : 0;
}
