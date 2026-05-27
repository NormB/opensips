/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the async nats_fetch wake mechanism.
 *
 * Bug: w_nats_fetch_async / w_nats_fetch_batch_async registered the
 * ring's eventfd -- created in the MI/main process at bind time, NOT in
 * the SIP worker -- with the worker's reactor (async_status = fd).  That
 * fork-inherited fd refers to an unrelated descriptor in the worker's fd
 * table, so the resume only ever fired on the async-core timeout, never
 * on real message arrival.
 *
 * Fix: each async fetch creates a fresh worker-private timerfd
 * (fetch_arm_timerfd) and registers THAT; the resume polls the ring on
 * each tick, enforces a per-call deadline, and asks the core to close
 * the worker-private fd via ASYNC_DONE_CLOSE_FD.
 *
 * This test has two parts:
 *   (1) behavioural -- build a timerfd with the same parameters
 *       fetch_arm_timerfd uses and prove it actually becomes readable
 *       (the foreign eventfd never did);
 *   (2) source-structure -- assert the async fetch entry points use the
 *       worker-private timerfd and no longer hand the ring eventfd to
 *       the reactor.
 *
 * Self-contained; run from the tests/ directory (reads ../nats_fetch.c).
 * Build: cc -g -O0 -Wall -o test_fetch_async_timerfd test_fetch_async_timerfd.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <poll.h>
#include <unistd.h>
#include <sys/timerfd.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ---- (1) behavioural: the worker-private timerfd actually fires ---- */
static void test_timerfd_fires(void)
{
	struct itimerspec its;
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	ASSERT(tfd >= 0, "timerfd_create succeeds");
	if (tfd < 0) return;

	memset(&its, 0, sizeof(its));
	its.it_value.tv_nsec    = 1000000L;   /* 1 ms, == NATS_FETCH_ASYNC_POLL_NS */
	its.it_interval.tv_nsec = 1000000L;
	ASSERT(timerfd_settime(tfd, 0, &its, NULL) == 0, "timerfd_settime succeeds");

	struct pollfd pfd = { .fd = tfd, .events = POLLIN };
	int pr = poll(&pfd, 1, 200 /* ms */);
	ASSERT(pr == 1 && (pfd.revents & POLLIN),
		"worker-private timerfd becomes readable (wakes the reactor)");

	uint64_t ticks = 0;
	ssize_t r = read(tfd, &ticks, sizeof(ticks));
	ASSERT(r == (ssize_t)sizeof(ticks) && ticks >= 1,
		"timerfd read returns a non-zero expiration count");

	close(tfd);
}

/* ---- (2) source-structure assertions ---- */
static char *extract_func_body(const char *path, const char *funcname)
{
	FILE *f = fopen(path, "r");
	if (!f) return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	char *buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	size_t n = fread(buf, 1, (size_t)sz, f);
	fclose(f);
	buf[n] = '\0';

	char *p = buf, *body = NULL;
	size_t flen = strlen(funcname);
	while ((p = strstr(p, funcname)) != NULL) {
		char *q = p + flen;
		while (*q == ' ' || *q == '\t') q++;
		if (*q != '(') { p += flen; continue; }
		char *brace = q;
		while (*brace && *brace != '{' && *brace != ';') brace++;
		if (*brace != '{') { p += flen; continue; }
		int depth = 0; char *s = brace;
		for (; *s; s++) {
			if (*s == '{') depth++;
			else if (*s == '}') { depth--; if (depth == 0) { s++; break; } }
		}
		size_t blen = (size_t)(s - brace);
		body = malloc(blen + 1);
		if (body) { memcpy(body, brace, blen); body[blen] = '\0'; }
		break;
	}
	free(buf);
	return body;
}

static void check_async_entry(const char *fn)
{
	char label[160];
	char *body = extract_func_body("../nats_fetch.c", fn);
	snprintf(label, sizeof(label), "found %s body", fn);
	ASSERT(body != NULL, label);
	if (!body) return;

	snprintf(label, sizeof(label), "%s creates a worker-private timerfd", fn);
	ASSERT(strstr(body, "fetch_arm_timerfd") != NULL, label);

	snprintf(label, sizeof(label),
		"%s no longer registers the ring eventfd with the reactor", fn);
	ASSERT(strstr(body, "nats_ring_eventfd") == NULL, label);

	snprintf(label, sizeof(label), "%s registers the timerfd (async_status = tfd)", fn);
	ASSERT(strstr(body, "async_status = tfd") != NULL, label);

	free(body);
}

static void check_resume(const char *fn)
{
	char label[160];
	char *body = extract_func_body("../nats_fetch.c", fn);
	snprintf(label, sizeof(label), "found %s body", fn);
	ASSERT(body != NULL, label);
	if (!body) return;
	snprintf(label, sizeof(label),
		"%s closes the worker-private fd (ASYNC_DONE_CLOSE_FD)", fn);
	ASSERT(strstr(body, "ASYNC_DONE_CLOSE_FD") != NULL, label);
	free(body);
}

int main(void)
{
	test_timerfd_fires();
	check_async_entry("w_nats_fetch_async");
	check_async_entry("w_nats_fetch_batch_async");
	check_resume("resume_nats_fetch");
	check_resume("resume_nats_fetch_batch");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
