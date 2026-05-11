/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Regression test: nats_persist.c::slurp_file must enforce
 * an upper bound on the bytes it allocates.
 *
 * The bug: slurp_file calls fseek/ftell to size the persist file,
 * then malloc(sz + 1).  An attacker (or a misconfigured operator)
 * who can make $persist_path point at a large file -- via symlink
 * to /var/log/<huge>, /sys/<pseudo>, etc. -- causes mod_init to
 * allocate the entire file into heap before parsing.
 *
 * The fix: NATS_PERSIST_MAX_FILE_BYTES (10 MiB by default) -- bigger
 * than any sane persist state, smaller than typical log/dump files.
 * If ftell exceeds the cap, slurp_file logs and returns NULL.
 *
 * The test exercises an inline copy of slurp_file's logic against a
 * real temp file, both buggy (no cap) and fixed (with cap).
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_slurp_file_cap test_slurp_file_cap.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* The cap that the production fix introduces.  Mirrored here to keep
 * the test independent of any header. */
#define MAX_FILE_BYTES (10L * 1024 * 1024)

/* ─── inline copy of slurp_file *with* the fix ─────────────────── */

static char *slurp_file_fixed(const char *path, int *out_missing,
	long max_bytes)
{
	FILE *f; char *buf; long sz;
	*out_missing = 0;
	f = fopen(path, "rb");
	if (!f) { if (errno == ENOENT) *out_missing = 1; return NULL; }
	if (fseek(f, 0, SEEK_END) < 0) { fclose(f); return NULL; }
	sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	if (sz > max_bytes) {
		fprintf(stderr, "slurp_file: %s exceeds cap (%ld > %ld)\n",
			path, sz, max_bytes);
		fclose(f); return NULL;
	}
	rewind(f);
	buf = (char *)malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf); fclose(f); return NULL;
	}
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

/* ─── inline copy of slurp_file *without* the fix (for control) ─── */

static char *slurp_file_buggy(const char *path, int *out_missing)
{
	FILE *f; char *buf; long sz;
	*out_missing = 0;
	f = fopen(path, "rb");
	if (!f) { if (errno == ENOENT) *out_missing = 1; return NULL; }
	if (fseek(f, 0, SEEK_END) < 0) { fclose(f); return NULL; }
	sz = ftell(f);
	if (sz < 0) { fclose(f); return NULL; }
	rewind(f);
	buf = (char *)malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf); fclose(f); return NULL;
	}
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

/* ─── helper: write @bytes bytes of '.' to a temp file, return path ── */

static char *make_temp_file(long bytes)
{
	static char tmp[128];
	int rc;
	int fd;
	long i;
	char chunk[4096];

	snprintf(tmp, sizeof(tmp), "/tmp/test_slurp_%d.dat", (int)getpid());
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) { perror("open"); return NULL; }
	memset(chunk, '.', sizeof(chunk));
	for (i = 0; i + (long)sizeof(chunk) <= bytes;
	     i += (long)sizeof(chunk)) {
		if (write(fd, chunk, sizeof(chunk)) != (ssize_t)sizeof(chunk)) {
			perror("write"); close(fd); return NULL;
		}
	}
	if (i < bytes) {
		if (write(fd, chunk, (size_t)(bytes - i)) !=
		    (ssize_t)(bytes - i)) {
			perror("write tail"); close(fd); return NULL;
		}
	}
	rc = close(fd);
	if (rc < 0) { perror("close"); return NULL; }
	return tmp;
}

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

int main(void)
{
	char *p, *buf;
	int missing;

	/* CASE 1: small file — both arms accept */
	p = make_temp_file(1024);
	if (!p) return 99;
	buf = slurp_file_buggy(p, &missing);
	ASSERT(buf != NULL && !missing, "buggy: 1 KB file accepted");
	free(buf);
	buf = slurp_file_fixed(p, &missing, MAX_FILE_BYTES);
	ASSERT(buf != NULL && !missing, "fixed: 1 KB file accepted");
	free(buf);
	unlink(p);

	/* CASE 2: at-cap file — fixed accepts */
	p = make_temp_file(MAX_FILE_BYTES);
	if (!p) return 99;
	buf = slurp_file_fixed(p, &missing, MAX_FILE_BYTES);
	ASSERT(buf != NULL && !missing, "fixed: at-cap file accepted");
	free(buf);
	unlink(p);

	/* CASE 3: over-cap file — fixed rejects, buggy accepts */
	p = make_temp_file(MAX_FILE_BYTES + 1024);
	if (!p) return 99;
	buf = slurp_file_fixed(p, &missing, MAX_FILE_BYTES);
	ASSERT(buf == NULL, "fixed: over-cap file rejected");
	buf = slurp_file_buggy(p, &missing);
	ASSERT(buf != NULL,
		"buggy: over-cap file accepted (allocates ~10 MB) -- demonstrates the bug");
	free(buf);
	unlink(p);

	/* CASE 4: missing file flagged */
	{
		const char *no_such = "/tmp/test_slurp_nonexistent_xyz";
		buf = slurp_file_fixed(no_such, &missing, MAX_FILE_BYTES);
		ASSERT(buf == NULL && missing == 1,
			"fixed: missing file -> NULL + out_missing=1");
	}

	/* CASE 5: production source has the cap */
	{
		FILE *f = fopen("../nats_persist.c", "r");
		ASSERT(f != NULL, "open ../nats_persist.c");
		if (f) {
			char line[1024];
			int found_const = 0, found_check = 0;
			while (fgets(line, sizeof(line), f)) {
				if (strstr(line, "NATS_PERSIST_MAX_FILE_BYTES") &&
				    strstr(line, "10"))
					found_const = 1;
				if (strstr(line, "sz > NATS_PERSIST_MAX_FILE_BYTES"))
					found_check = 1;
			}
			fclose(f);
			ASSERT(found_const,
				"nats_persist.c defines NATS_PERSIST_MAX_FILE_BYTES");
			ASSERT(found_check,
				"nats_persist.c checks sz > cap");
		}
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
