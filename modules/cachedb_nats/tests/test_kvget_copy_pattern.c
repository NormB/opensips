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
 * Defensive-pattern test for w_nats_kv_get.
 *
 * Bug claim: w_nats_kv_get sets a pvar from a pointer into kvEntry's
 *            internal buffer, then destroys the entry.  If pv_set_value
 *            were to store the pointer rather than copy, the pvar would
 *            hold a dangling pointer.
 *
 * Reality:   every current OpenSIPS pvar setter copies PV_VAL_STR data
 *            (verified: pv_set_avp -> new_avp memcpy, pv_set_scriptvar
 *            -> set_var_value memcpy, pv_set_dsturi -> set_dst_uri
 *            memcpy).  The current code is not a UAF today.
 *
 * Why fix:   defensive consistency.  w_nats_request uses an explicit
 *            pkg_malloc + memcpy + pv_set + pkg_free pattern.  Mirroring
 *            it in w_nats_kv_get keeps both functions resilient if any
 *            future module-level pvar setter forgets to copy.
 *
 * Test:      simulate a worst-case "non-copying setter" (it stashes the
 *            pointer).  With the buggy pattern, the stashed pointer is
 *            dangling once the source buffer is destroyed.  With the
 *            fixed pattern, the value is freed in a controlled way and
 *            we never read a dangling pointer.
 *
 * Build:     gcc -g -O0 -fsanitize=address -Wall -o test_kvget_copy_pattern \
 *                test_kvget_copy_pattern.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/* ─── stand-ins ───────────────────────────────────────────────── */

/* "kvEntry" with an internal buffer */
typedef struct {
	char *internal_buf;
	int   len;
} kvEntry_t;

static kvEntry_t *fake_kvStore_Get(const char *value)
{
	kvEntry_t *e = malloc(sizeof(*e));
	e->len = (int)strlen(value);
	e->internal_buf = malloc(e->len + 1);
	memcpy(e->internal_buf, value, e->len);
	e->internal_buf[e->len] = '\0';
	return e;
}

static const char *fake_kvEntry_ValueString(kvEntry_t *e) { return e->internal_buf; }
static int         fake_kvEntry_ValueLen(kvEntry_t *e)    { return e->len; }
static void        fake_kvEntry_Destroy(kvEntry_t *e)
{
	free(e->internal_buf);
	free(e);
}

/* "Non-copying setter" — represents the worst case: it just stashes
 * the pointer (and length) the caller passed in.  Any subsequent read
 * is at the mercy of the source buffer staying alive. */

typedef struct { const char *s; int len; } pv_val_t;
static pv_val_t G_stashed;
static int      fake_pv_set_value_no_copy(const char *s, int len)
{
	G_stashed.s = s;
	G_stashed.len = len;
	return 0;
}

/* ─── BUGGY: current w_nats_kv_get pattern (paraphrased) ─────── */

static int buggy_kv_get(const char *key, const char **out_observed_value)
{
	kvEntry_t *entry = fake_kvStore_Get(key);
	const char *entry_val = fake_kvEntry_ValueString(entry);
	int entry_len = fake_kvEntry_ValueLen(entry);

	fake_pv_set_value_no_copy(entry_val, entry_len);

	fake_kvEntry_Destroy(entry);   /* ← the source buffer is now freed */

	/* Caller subsequently reads the stashed pvar.  This is the moment
	 * of truth: the read happens AFTER the source is destroyed. */
	*out_observed_value = G_stashed.s;
	return 0;
}

/* ─── FIXED: w_nats_request-style copy-then-destroy ──────────── */

static int fixed_kv_get(const char *key, char **out_owned_copy)
{
	kvEntry_t *entry = fake_kvStore_Get(key);
	const char *entry_val = fake_kvEntry_ValueString(entry);
	int entry_len = fake_kvEntry_ValueLen(entry);

	/* malloc + memcpy a worker-owned copy BEFORE destroying entry */
	char *copy = malloc(entry_len + 1);
	if (!copy) {
		fake_kvEntry_Destroy(entry);
		return -1;
	}
	memcpy(copy, entry_val, entry_len);
	copy[entry_len] = '\0';

	fake_kvEntry_Destroy(entry);

	/* Set pvar from copy.  In OpenSIPS the setter copies internally;
	 * if any future setter doesn't, the copy lives until the caller
	 * frees it (controlled lifetime). */
	fake_pv_set_value_no_copy(copy, entry_len);

	*out_owned_copy = copy;
	return 0;
}

/* ─── arms ──────────────────────────────────────────────────── */

static int run_buggy(void)
{
	const char *observed = NULL;
	buggy_kv_get("k1", &observed);
	/* Read the stashed pvar.  This is the dangling-pointer scenario. */
	if (observed == NULL) return 99;
	/* reading observed[0] under ASAN should report heap-use-after-free */
	volatile char ch = observed[0];
	(void)ch;
	return 0;
}

static int run_fixed(void)
{
	char *copy = NULL;
	fixed_kv_get("k1", &copy);
	if (!copy) return 99;
	/* Read the stashed pointer (which equals copy) — it is alive. */
	if (G_stashed.s != copy) return 98;
	volatile char ch = copy[0];
	(void)ch;
	free(copy);
	return 0;
}

static int run_in_child(int (*fn)(void), const char *name)
{
	pid_t pid = fork();
	if (pid == 0) exit(fn() == 0 ? 0 : 2);
	int status = 0;
	waitpid(pid, &status, 0);
	int rc = WIFEXITED(status) ? WEXITSTATUS(status) :
	         WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
	fprintf(stderr, "[%s] rc=%d\n", name, rc);
	return rc;
}

int main(void)
{
	int buggy_rc = run_in_child(run_buggy, "buggy");
	int fixed_rc = run_in_child(run_fixed, "fixed");

	int pass = 1;
	if (buggy_rc == 0) {
		fprintf(stderr,
		    "FAIL: buggy arm completed cleanly under ASAN — "
		    "non-copying setter scenario was not realized\n");
		pass = 0;
	} else {
		fprintf(stderr, "OK:   buggy arm trapped (rc=%d)\n", buggy_rc);
	}
	if (fixed_rc != 0) {
		fprintf(stderr, "FAIL: fixed arm rc=%d\n", fixed_rc);
		pass = 0;
	} else {
		fprintf(stderr, "OK:   fixed arm clean\n");
	}
	return pass ? 0 : 1;
}
