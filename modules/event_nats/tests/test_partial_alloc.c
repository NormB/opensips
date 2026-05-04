/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the partial-allocation silent drop in
 * modules/event_nats/nats_consumer.c:nats_msg_handler.
 *
 * Bug: when shm_malloc for evt->subject succeeds but shm_malloc for
 *      evt->data fails (or vice versa), the event is dispatched to the
 *      worker with one of the two fields silently NULL.  The script
 *      sees $param(subject) (or data) as undefined with no error.
 *      Worse, on the *first* allocation failure the message is dropped
 *      cleanly, so observability is inconsistent.
 *
 * Fix:  all-or-nothing.  If any required field fails to allocate,
 *       drop the message and free any partial state.  No silent
 *       partial dispatch.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_partial_alloc \
 *       test_partial_alloc.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/* ─── controlled allocator ─────────────────────────────────────── */

typedef struct {
	int call_count;       /* total alloc calls */
	int fail_after;       /* fail starting at this call (1-indexed); 0 = never */
	int total_freed;      /* successful free() calls */
	int outstanding;      /* allocs minus frees */
} alloc_ctrl_t;

static alloc_ctrl_t G_ctrl;

static void *test_shm_malloc(size_t n)
{
	G_ctrl.call_count++;
	if (G_ctrl.fail_after > 0 && G_ctrl.call_count >= G_ctrl.fail_after)
		return NULL;
	void *p = malloc(n);
	if (p) G_ctrl.outstanding++;
	return p;
}

static void test_shm_free(void *p)
{
	if (p) {
		free(p);
		G_ctrl.outstanding--;
		G_ctrl.total_freed++;
	}
}

static void ctrl_reset(int fail_after)
{
	memset(&G_ctrl, 0, sizeof(G_ctrl));
	G_ctrl.fail_after = fail_after;
}

/* ─── stand-in event struct (mirrors nats_ipc_event_t) ────────── */

typedef struct {
	int   event_id;
	char *subject;
	int   subject_len;
	char *data;
	int   data_len;
} ipc_event_t;

/* dispatch records — the caller observes whether dispatch was attempted
 * and what fields were carried */
static int g_dispatch_attempts;
static int g_dispatch_subject_null;
static int g_dispatch_data_null;

static int test_ipc_dispatch(ipc_event_t *evt)
{
	g_dispatch_attempts++;
	if (!evt->subject) g_dispatch_subject_null++;
	if (!evt->data)    g_dispatch_data_null++;
	return 0;   /* dispatch always "succeeds" — we test the partial-alloc
	             * path, not the dispatch-failure path. */
}

/* ─── BUGGY: copy of current nats_msg_handler logic ──────────── */

static void buggy_handler(int event_id,
	const char *subject, int subject_len,
	const char *data,    int data_len)
{
	ipc_event_t *evt = test_shm_malloc(sizeof(*evt));
	if (!evt) return;
	memset(evt, 0, sizeof(*evt));
	evt->event_id = event_id;

	if (subject_len > 0) {
		evt->subject = test_shm_malloc(subject_len + 1);
		if (evt->subject) {
			memcpy(evt->subject, subject, subject_len);
			evt->subject[subject_len] = '\0';
			evt->subject_len = subject_len;
		}
	}

	if (data && data_len > 0) {
		evt->data = test_shm_malloc(data_len + 1);
		if (evt->data) {
			memcpy(evt->data, data, data_len);
			evt->data[data_len] = '\0';
			evt->data_len = data_len;
		}
	}

	if (test_ipc_dispatch(evt) < 0) {
		if (evt->subject) test_shm_free(evt->subject);
		if (evt->data)    test_shm_free(evt->data);
		test_shm_free(evt);
	}
}

/* ─── FIXED: all-or-nothing semantics ────────────────────────── */

static void fixed_handler(int event_id,
	const char *subject, int subject_len,
	const char *data,    int data_len)
{
	ipc_event_t *evt = test_shm_malloc(sizeof(*evt));
	if (!evt) return;
	memset(evt, 0, sizeof(*evt));
	evt->event_id = event_id;

	if (subject_len > 0) {
		evt->subject = test_shm_malloc(subject_len + 1);
		if (!evt->subject) {
			test_shm_free(evt);
			return;
		}
		memcpy(evt->subject, subject, subject_len);
		evt->subject[subject_len] = '\0';
		evt->subject_len = subject_len;
	}

	if (data && data_len > 0) {
		evt->data = test_shm_malloc(data_len + 1);
		if (!evt->data) {
			if (evt->subject) test_shm_free(evt->subject);
			test_shm_free(evt);
			return;
		}
		memcpy(evt->data, data, data_len);
		evt->data[data_len] = '\0';
		evt->data_len = data_len;
	}

	if (test_ipc_dispatch(evt) < 0) {
		if (evt->subject) test_shm_free(evt->subject);
		if (evt->data)    test_shm_free(evt->data);
		test_shm_free(evt);
		return;
	}
	/* On dispatch success, IPC handler owns evt and frees later.
	 * For test we free here since there is no real handler. */
	if (evt->subject) test_shm_free(evt->subject);
	if (evt->data)    test_shm_free(evt->data);
	test_shm_free(evt);
}

/* ─── assertions ──────────────────────────────────────────────── */

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* Run the buggy demonstration in a child so its known leaks (the bug
 * itself) don't fail the parent harness. */
static int run_buggy_demo(void)
{
	const char *subject = "call.123";
	const char *data    = "hello";
	int slen = (int)strlen(subject);
	int dlen = (int)strlen(data);
	int local_fails = 0;
#define BASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "[buggy] FAIL: %s\n", msg); local_fails++; } \
	else         { fprintf(stderr, "[buggy]   ok: %s\n", msg);                } \
} while (0)

	ctrl_reset(3);   /* alloc 1 = evt OK, 2 = subject OK, 3 = data FAIL */
	g_dispatch_attempts = g_dispatch_subject_null = g_dispatch_data_null = 0;
	buggy_handler(1, subject, slen, data, dlen);
	BASSERT(g_dispatch_attempts == 1,
		"dispatches event despite partial alloc failure");
	BASSERT(g_dispatch_subject_null == 0, "subject non-NULL");
	BASSERT(g_dispatch_data_null == 1, "data NULL — silent drop of payload");

	ctrl_reset(2);   /* alloc 1 = evt OK, 2 = subject FAIL */
	g_dispatch_attempts = g_dispatch_subject_null = g_dispatch_data_null = 0;
	buggy_handler(1, subject, slen, data, dlen);
	BASSERT(g_dispatch_attempts == 1,
		"dispatches even when subject alloc fails");
	BASSERT(g_dispatch_subject_null == 1, "subject NULL");
#undef BASSERT
	/* Disable LSan exit-on-leak inside this child: we expect the buggy
	 * code to leak, that is the bug.  Use _exit so atexit/LSan-finalizers
	 * run as little as possible — but LSan still scans on _exit, so set
	 * the env up front in main. */
	return local_fails == 0 ? 0 : 1;
}

int main(void)
{
	const char *subject = "call.123";
	const char *data    = "hello";
	int slen = (int)strlen(subject);
	int dlen = (int)strlen(data);

	/* CASE A+B (buggy): isolated child so its leaks don't fail us */
	pid_t pid = fork();
	if (pid == 0) {
		/* Suppress LSan output / non-zero exit for known buggy leaks */
		setenv("ASAN_OPTIONS", "detect_leaks=0", 1);
		_exit(run_buggy_demo());
	}
	int status = 0;
	waitpid(pid, &status, 0);
	int buggy_rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	ASSERT(buggy_rc == 0, "buggy arm: assertions about bug behavior hold");

	/* CASE A (fixed): data alloc fails after subject succeeds */
	fprintf(stderr, "\n[fixed] data-alloc fails after subject succeeds\n");
	ctrl_reset(3);
	g_dispatch_attempts = g_dispatch_subject_null = g_dispatch_data_null = 0;
	fixed_handler(1, subject, slen, data, dlen);
	ASSERT(g_dispatch_attempts == 0,
		"fixed does NOT dispatch on partial alloc failure");
	ASSERT(G_ctrl.outstanding == 0,
		"fixed: no leak after partial alloc failure");

	/* CASE B (fixed): subject alloc fails */
	fprintf(stderr, "\n[fixed] subject-alloc fails first\n");
	ctrl_reset(2);
	g_dispatch_attempts = g_dispatch_subject_null = g_dispatch_data_null = 0;
	fixed_handler(1, subject, slen, data, dlen);
	ASSERT(g_dispatch_attempts == 0,
		"fixed: drops on subject alloc failure");
	ASSERT(G_ctrl.outstanding == 0,
		"fixed: no leak on subject alloc failure");

	/* CASE C (fixed): happy path */
	fprintf(stderr, "\n[fixed] all allocs succeed — happy path\n");
	ctrl_reset(0);
	g_dispatch_attempts = g_dispatch_subject_null = g_dispatch_data_null = 0;
	fixed_handler(1, subject, slen, data, dlen);
	ASSERT(g_dispatch_attempts == 1, "fixed: dispatches happy-path");
	ASSERT(g_dispatch_subject_null == 0, "fixed: subject populated");
	ASSERT(g_dispatch_data_null == 0,    "fixed: data populated");
	ASSERT(G_ctrl.outstanding == 0,      "fixed: no leak happy path");

	fprintf(stderr, "\n=== %s ===\n", g_fails == 0 ? "ALL PASS" : "FAILURES");
	return g_fails == 0 ? 0 : 1;
}
