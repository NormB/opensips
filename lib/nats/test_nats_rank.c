/*
 * test_nats_rank.c — Unit test for nats_pool_should_init().
 *
 * Build standalone:
 *   make -C lib/nats test-rank
 *
 * Run:
 *   lib/nats/test_nats_rank
 */

#include <stdio.h>
#include <stdlib.h>
#include "nats_pool.h"
#include "../../sr_module.h"

struct rank_case {
	int rank;
	int expected;
	const char *label;
};

static const struct rank_case cases[] = {
	{ PROC_MAIN,      0, "PROC_MAIN (0, attendant)" },
	{ PROC_TIMER,     0, "PROC_TIMER (-1)" },
	{ PROC_MODULE,    1, "PROC_MODULE (-2, HTTPD/MI)" },
	{ PROC_TCP_MAIN,  0, "PROC_TCP_MAIN (-4, TLS holder)" },
	{ -3,             0, "rank -3 (module-exported)" },
	{ -5,             0, "rank -5 (module-exported)" },
	{ -100,           0, "rank -100 (module-exported)" },
	{ 1,              1, "rank 1 (first SIP worker)" },
	{ 2,              1, "rank 2" },
	{ 4,              1, "rank 4" },
	{ 8,              1, "rank 8" },
	{ 16,             1, "rank 16" },
	{ 32,             1, "rank 32" },
};

int main(void)
{
	int failures = 0;
	size_t i;
	const size_t n = sizeof(cases) / sizeof(cases[0]);

	for (i = 0; i < n; i++) {
		int got = nats_pool_should_init(cases[i].rank);
		if (got != cases[i].expected) {
			fprintf(stderr,
				"FAIL: %s (rank=%d): expected %d, got %d\n",
				cases[i].label, cases[i].rank,
				cases[i].expected, got);
			failures++;
		} else {
			fprintf(stdout, "ok: %s\n", cases[i].label);
		}
	}

	if (failures) {
		fprintf(stderr, "\n%d of %zu cases failed\n", failures, n);
		return 1;
	}
	fprintf(stdout, "\nAll %zu cases passed\n", n);
	return 0;
}
