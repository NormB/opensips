/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test for the persistence dirty-flag cross-process bug.
 *
 * Bug: nats_persist_schedule_write() is called from nats_registry_bind/
 * unbind, which run in SIP workers and the MI process.  The "dirty"
 * flag + the writer pthread lived in a process-local static (g_state),
 * created in mod_init pre-fork.  After fork every process had its own
 * copy with init_done=1 but no writer thread, so a worker's
 * schedule_write set the worker's PRIVATE dirty flag and signalled a
 * condvar nobody waited on -- the attendant's writer never saw it and
 * runtime binds/unbinds were silently not persisted.
 *
 * Fix: the dirty/dirty_ms flags now live in an shm_malloc'd struct
 * (g_shared), allocated pre-fork so every child shares ONE copy; the
 * attendant's writer polls it each tick.
 *
 * This test proves both halves:
 *   (1) behavioural -- a forked child's store to a MAP_SHARED atomic is
 *       visible to the parent (the mechanism the fix relies on), while a
 *       store to process-PRIVATE memory is NOT (the original bug class);
 *   (2) source-structure -- nats_persist.c allocates the dirty flag in
 *       SHM and schedule_write / writer_main use that shared flag rather
 *       than a process-local field.
 *
 * Self-contained; run from the tests/ directory (reads ../nats_persist.c).
 * Build: cc -g -O0 -Wall -o test_persist_cross_process test_persist_cross_process.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ---- (1) behavioural: shared vs private cross-fork visibility ---- */
static void test_cross_process_visibility(void)
{
	/* positive: MAP_SHARED (what shm_malloc gives in production) */
	_Atomic int *shared = mmap(NULL, sizeof(*shared),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT(shared != MAP_FAILED, "mmap shared atomic");
	if (shared == MAP_FAILED) return;
	atomic_store(shared, 0);

	pid_t pid = fork();
	ASSERT(pid >= 0, "fork");
	if (pid == 0) {
		/* child == a 'SIP worker' calling schedule_write */
		atomic_store(shared, 1);
		_exit(0);
	}
	int st;
	waitpid(pid, &st, 0);
	ASSERT(atomic_load(shared) == 1,
		"child's store to a SHARED dirty flag IS seen by the parent "
		"(writer would pick it up)");

	/* negative control: process-PRIVATE memory (the old g_state.dirty) */
	_Atomic int *private_flag = malloc(sizeof(*private_flag));
	ASSERT(private_flag != NULL, "malloc private atomic");
	if (private_flag) {
		atomic_store(private_flag, 0);
		pid = fork();
		if (pid == 0) {
			atomic_store(private_flag, 1);   /* sets the child's copy */
			_exit(0);
		}
		waitpid(pid, &st, 0);
		ASSERT(atomic_load(private_flag) == 0,
			"child's store to PRIVATE memory is NOT seen by the parent "
			"(the original lost-write bug)");
		free(private_flag);
	}

	munmap(shared, sizeof(*shared));
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

static int file_contains(const char *path, const char *needle)
{
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char line[1024];
	int hit = 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle)) { hit = 1; break; }
	fclose(f);
	return hit;
}

static void test_source_structure(void)
{
	const char *src = "../nats_persist.c";
	char *sw, *wm;

	ASSERT(file_contains(src, "shm_malloc(sizeof(*g_shared))"),
		"dirty flag is allocated in SHM (shared across fork)");

	sw = extract_func_body(src, "nats_persist_schedule_write");
	ASSERT(sw != NULL, "found nats_persist_schedule_write body");
	if (sw) {
		ASSERT(strstr(sw, "persist_mark_dirty") != NULL,
			"schedule_write marks the SHM dirty flag");
		ASSERT(strstr(sw, "g_state.dirty") == NULL,
			"schedule_write no longer uses a process-local dirty flag");
		free(sw);
	}

	wm = extract_func_body(src, "writer_main");
	ASSERT(wm != NULL, "found writer_main body");
	if (wm) {
		ASSERT(strstr(wm, "g_shared->dirty") != NULL,
			"writer polls the SHM dirty flag");
		ASSERT(strstr(wm, "g_state.dirty") == NULL,
			"writer no longer reads a process-local dirty flag");
		free(wm);
	}
}

int main(void)
{
	test_cross_process_visibility();
	test_source_structure();

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
