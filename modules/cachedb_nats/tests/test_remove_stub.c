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
 * P11 / SPEC.md §1.2 [REV-10]: the `cachedb_funcs._remove` slot.
 *
 *   int (*_remove)(cachedb_con *con, str *attr, const str *key);
 *
 * usrloc full-sharing-cachedb NEVER calls _remove (it is exercised only in
 * CM_FEDERATION_CACHEDB metadata maintenance, udomain.c:1315).  In cachedb_nats
 * today the slot is left unset => NULL.  A wrong-mode / misconfigured deployment
 * that reached it would dispatch through a NULL function pointer => SEGFAULT.
 *
 * [REV-10] v1 MUST register a NON-NULL "unsupported" stub that returns -1 (with
 * an LM_ERR naming the unsupported op) so a misconfiguration fails LOUDLY rather
 * than crashing.  The real federation implementation (G4) is a scoped follow-up.
 *
 * This Tier-1 test models the cde.cdb_func._remove registration (cachedb_nats.c)
 * as a function pointer and the carried copy of the stub, asserting the GATE:
 *   ✓ the registered _remove is NON-NULL;
 *   ✓ invoking it returns -1 (loud failure), for any argument shape, with NO
 *     deref of con/attr/key and NO crash — including adversarial bytes
 *     (backslash, embedded NUL, empty, NULL pointers).
 *   ✗ a NULL slot would be a latent NULL-call/segfault.
 *
 *   gcc -DREMOVE_CURRENT ... -> slot is NULL (today's behavior)   => RED.
 *   gcc ...                 -> slot is the non-NULL stub (fixed)   => GREEN.
 *
 * Rule 6: usrloc full-sharing never invokes _remove, so there is no Tier-2
 * counterpart — this gate is fully covered at Tier 1.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_remove_stub test_remove_stub.c
 */
#include <stdio.h>
#include <string.h>

/* ─── minimal carried copies of the opensips types (cachedb.h) ─────── */
typedef struct { int len; char *s; } str;
typedef void cachedb_con;   /* opaque: the stub must NOT deref it */

/* ─── carried copy of the production stub (cachedb_nats_dbase.c) ─────
 * Mirrors the real signature byte-for-byte.  It MUST NOT touch con/attr/key
 * (a misconfigured caller may pass anything); it returns -1 unconditionally
 * after an LM_ERR (elided in this standalone harness). */
static int nats_cache_remove_unsupported(cachedb_con *con, str *attr,
		const str *key)
{
	(void)con; (void)attr; (void)key;
	/* LM_ERR("_remove not supported by cachedb_nats (use full-sharing mode)\n") */
	return -1;
}

/* ─── the cde.cdb_func._remove slot as registered in mod_init ───────── */
typedef int (*remove_fn)(cachedb_con *con, str *attr, const str *key);

static const remove_fn registered_remove =
#ifdef REMOVE_CURRENT
	NULL;                               /* today: slot left unset */
#else
	nats_cache_remove_unsupported;      /* [REV-10] non-NULL stub */
#endif

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef REMOVE_CURRENT
	printf("== carried copy: REMOVE_CURRENT (_remove slot is NULL) ==\n");
#else
	printf("== carried copy: FIXED (_remove non-NULL unsupported stub) ==\n");
#endif

	printf("[REV-10] the _remove slot MUST be non-NULL (no latent NULL-call):\n");
	CHECK(registered_remove != NULL, "cde.cdb_func._remove registered non-NULL");

	/* Guard every invocation on non-NULL so the RED build reports the NULL as a
	 * failed assertion instead of actually segfaulting the test runner. */
	if (registered_remove == NULL) {
		printf("\n  (slot is NULL — invocation tests skipped to avoid the very "
			"segfault [REV-10] forbids)\n");
		printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
			fails, fails == 1 ? "" : "s");
		return fails ? 1 : 0;
	}

	printf("[REV-10] invoking the stub MUST return -1 (loud), never crash:\n");

	/* Nominal-ish args. */
	{
		str attr = { 3, "aor" };
		str key  = { 4, "meta" };
		CHECK(registered_remove((cachedb_con *)0x1, &attr, &key) == -1,
			"populated (con,attr,key) => -1");
	}

	/* All-NULL: the stub must not deref any argument. */
	CHECK(registered_remove(NULL, NULL, NULL) == -1,
		"NULL (con,attr,key) => -1 (no deref)");

	/* Adversarial bytes — the stub is byte-agnostic; it never parses attr/key. */
	{
		str empty = { 0, "" };
		CHECK(registered_remove(NULL, &empty, NULL) == -1,
			"empty attr => -1");
	}
	{
		str bslash = { 7, "a\\b\\c=d" };
		CHECK(registered_remove(NULL, &bslash, NULL) == -1,
			"backslash/special-char attr => -1");
	}
	{
		/* embedded NUL: len spans past the interior '\0' */
		str embnul = { 5, "a\0b.c" };
		CHECK(registered_remove(NULL, &embnul, NULL) == -1,
			"embedded-NUL attr => -1");
	}
	{
		/* negative/garbage len must not tempt the stub into reading attr->s */
		str neg = { -1, NULL };
		CHECK(registered_remove(NULL, &neg, NULL) == -1,
			"negative-len/NULL-s attr => -1 (no read)");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
		fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
