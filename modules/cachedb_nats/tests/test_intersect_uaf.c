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
 * Regression test for the use-after-free in nats_cache_query at
 * modules/cachedb_nats/cachedb_nats_json.c:1011-1035.
 *
 * The bug: qry_intersect_keys returns pointers aliased into argument @a.
 * The caller frees @a's strings, then strdup's from the now-dangling
 * pointers in the result.  This file builds a faithful reproducer of
 * that exact pattern, runs both the buggy and fixed versions, and
 * fails the test if either: the buggy version doesn't trip ASAN,
 * or the fixed version does.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -o test_intersect_uaf \
 *       test_intersect_uaf.c
 *
 * Run:
 *   ./test_intersect_uaf
 *   echo "exit=$?"   # 0 = both arms behaved as expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/* ─── exact copy of qry_intersect_keys from cachedb_nats_json.c:845 ─── */

static int qry_intersect_keys(char **a, int a_count,
	char **b, int b_count,
	char ***out_keys, int *out_count)
{
	int i, j, n = 0;
	char **result;
	int alloc = (a_count < b_count) ? a_count : b_count;

	if (alloc == 0) {
		*out_keys = NULL;
		*out_count = 0;
		return 0;
	}

	result = malloc(sizeof(char *) * alloc);
	if (!result)
		return -1;

	for (i = 0; i < a_count; i++) {
		for (j = 0; j < b_count; j++) {
			if (strcmp(a[i], b[j]) == 0) {
				result[n++] = a[i];
				break;
			}
		}
	}

	*out_keys = result;
	*out_count = n;
	return 0;
}

/* ─── buggy: mirrors nats_cache_query lines 1011-1035 ─────────── */

static int run_buggy(void)
{
	/* Step 1: simulate first-iteration result — match_keys is strdup'd
	 * copies of the index's key list. */
	const char *src_a[] = {"call/123", "call/456", "call/789"};
	const char *src_b[] = {"call/456", "call/789", "call/999"};
	int a_count = 3;
	int b_count = 3;

	char **match_keys = malloc(sizeof(char *) * a_count);
	for (int k = 0; k < a_count; k++)
		match_keys[k] = strdup(src_a[k]);
	int match_count = a_count;

	/* Step 2: simulate next iteration — qry_intersect_keys returns aliases
	 * into match_keys.  Caller frees match_keys[k] BEFORE strdup'ing
	 * from new_keys[k] (which aliases match_keys[k]). */
	char **e_keys = malloc(sizeof(char *) * b_count);
	for (int k = 0; k < b_count; k++)
		e_keys[k] = (char *)src_b[k];

	char **new_keys = NULL;
	int new_count = 0;
	if (qry_intersect_keys(match_keys, match_count, e_keys, b_count,
			&new_keys, &new_count) < 0) {
		fprintf(stderr, "buggy: intersect alloc failed\n");
		return -1;
	}

	/* free old match_keys[k] */
	for (int k = 0; k < match_count; k++)
		free(match_keys[k]);
	free(match_keys);

	/* swap and strdup — strdup reads from FREED memory here */
	match_keys = new_keys;
	match_count = new_count;
	for (int k = 0; k < match_count; k++) {
		char *dup = strdup(match_keys[k]);   /* UAF read */
		if (!dup) { return -1; }
		match_keys[k] = dup;
	}

	/* cleanup (after strdup so the test reaches the dup loop) */
	for (int k = 0; k < match_count; k++)
		free(match_keys[k]);
	free(match_keys);
	free(e_keys);
	return 0;
}

/* ─── fixed: strdup BEFORE freeing match_keys[k] ─────────────── */

static int run_fixed(void)
{
	const char *src_a[] = {"call/123", "call/456", "call/789"};
	const char *src_b[] = {"call/456", "call/789", "call/999"};
	int a_count = 3;
	int b_count = 3;

	char **match_keys = malloc(sizeof(char *) * a_count);
	for (int k = 0; k < a_count; k++)
		match_keys[k] = strdup(src_a[k]);
	int match_count = a_count;

	char **e_keys = malloc(sizeof(char *) * b_count);
	for (int k = 0; k < b_count; k++)
		e_keys[k] = (char *)src_b[k];

	char **new_keys = NULL;
	int new_count = 0;
	if (qry_intersect_keys(match_keys, match_count, e_keys, b_count,
			&new_keys, &new_count) < 0) {
		fprintf(stderr, "fixed: intersect alloc failed\n");
		return -1;
	}

	/* FIX: strdup the intersection results FIRST, while match_keys is
	 * still live.  Then free match_keys. */
	char **dups = malloc(sizeof(char *) * (new_count > 0 ? new_count : 1));
	for (int k = 0; k < new_count; k++) {
		dups[k] = strdup(new_keys[k]);   /* read from LIVE memory */
		if (!dups[k]) { return -1; }
	}
	free(new_keys);

	for (int k = 0; k < match_count; k++)
		free(match_keys[k]);
	free(match_keys);

	match_keys = dups;
	match_count = new_count;

	for (int k = 0; k < match_count; k++)
		free(match_keys[k]);
	free(match_keys);
	free(e_keys);
	return 0;
}

/* ─── harness: run each arm in a child so ASAN failure of buggy
 *     does not abort fixed.  Buggy must exit non-zero (ASAN abort);
 *     fixed must exit zero. ──────────────────────────────────── */

static int run_in_child(int (*fn)(void), const char *name)
{
	pid_t pid = fork();
	if (pid == 0) {
		exit(fn() == 0 ? 0 : 2);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		int rc = WEXITSTATUS(status);
		fprintf(stderr, "[%s] child exited rc=%d\n", name, rc);
		return rc;
	}
	if (WIFSIGNALED(status)) {
		fprintf(stderr, "[%s] child killed by signal %d\n",
			name, WTERMSIG(status));
		return 128 + WTERMSIG(status);
	}
	return -1;
}

int main(void)
{
	int buggy_rc = run_in_child(run_buggy, "buggy");
	int fixed_rc = run_in_child(run_fixed, "fixed");

	int test_pass = 1;
	if (buggy_rc == 0) {
		fprintf(stderr,
		    "FAIL: buggy arm completed cleanly — ASAN must "
		    "have NOT been enabled, or pattern is wrong\n");
		test_pass = 0;
	} else {
		fprintf(stderr, "OK:   buggy arm trapped (rc=%d)\n", buggy_rc);
	}
	if (fixed_rc != 0) {
		fprintf(stderr,
		    "FAIL: fixed arm did not exit cleanly (rc=%d)\n",
		    fixed_rc);
		test_pass = 0;
	} else {
		fprintf(stderr, "OK:   fixed arm clean\n");
	}

	return test_pass ? 0 : 1;
}
