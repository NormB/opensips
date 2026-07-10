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
 * P2.6 / SPEC.md §3.2 §4.2-step-3 [REV-18 / REV-35]: the cdb_row_t handed back
 * to usrloc must be exactly {contacts, aorhash}.  `row_exp` and `schema_version`
 * are cachedb_nats-PRIVATE top-level peers (reaper/expiry + mixed-version
 * metadata); usrloc must never see them.  They are stripped at row assembly —
 * top-level peers, not members of any contact subdict, so the strip is a
 * top-level walk, not a per-contact one.
 *
 * This Tier-1 exercises the real intrusive-list surgery with the SAME list.h
 * primitives the production strip uses (list_for_each_safe / list_del), so ASan
 * catches a use-after-free / skipped-node / leak in the removal loop.  A minimal
 * `tpair` mirrors cdb_pair_t {key.name, val.type, list}.
 *
 *   gcc -DSTRIP_CURRENT ... -> today: no strip (private keys reach usrloc) => RED.
 *   gcc ...                 -> the FIXED strip => GREEN.
 *
 * Rule 6: the AUTHORITATIVE byte-exact {contacts,aorhash}/15-field round-trip is
 * the Tier-2 test_contact_roundtrip / test_usrloc_*_e2e vs production read path.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_strip_private_keys test_strip_private_keys.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../lib/list.h"   /* the real intrusive list (standalone) */

/* minimal mirror of cdb_pair_t: enough to drive the strip surgery. */
struct tpair {
	const char *name;
	int         name_len;
	int         val_type;     /* stands in for CDB_INT32 etc. */
	struct list_head list;
};

static struct tpair *mk(const char *name, int val_type)
{
	struct tpair *p = malloc(sizeof *p);
	p->name = name;
	p->name_len = (int)strlen(name);
	p->val_type = val_type;
	return p;
}

/* ─── carried copy of the production predicate (rowmeta TU) ──────── */
static int is_private_top_key(const char *name, int len)
{
	return (len == 7  && memcmp(name, "row_exp", 7) == 0) ||
	       (len == 14 && memcmp(name, "schema_version", 14) == 0);
}

/* carried copy of the strip surgery (mirrors cdbn_row_strip_private_keys). */
static void strip(struct list_head *dict)
{
#ifndef STRIP_CURRENT
	struct list_head *pos, *tmp;
	list_for_each_safe(pos, tmp, dict) {
		struct tpair *p = list_entry(pos, struct tpair, list);
		if (is_private_top_key(p->name, p->name_len)) {
			list_del(&p->list);
			free(p);
		}
	}
#else
	(void)dict;   /* today: nothing stripped — private keys reach usrloc */
	(void)is_private_top_key;
#endif
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static int has_key(struct list_head *dict, const char *name)
{
	struct list_head *pos;
	list_for_each(pos, dict) {
		struct tpair *p = list_entry(pos, struct tpair, list);
		if (p->name_len == (int)strlen(name) &&
		    memcmp(p->name, name, p->name_len) == 0)
			return 1;
	}
	return 0;
}
static int count(struct list_head *dict)
{
	int n = 0; struct list_head *pos;
	list_for_each(pos, dict) n++;
	return n;
}
static void free_all(struct list_head *dict)
{
	struct list_head *pos, *tmp;
	list_for_each_safe(pos, tmp, dict)
		free(list_entry(pos, struct tpair, list));
}

int main(void)
{
#ifdef STRIP_CURRENT
	printf("== carried copy: STRIP_CURRENT (no strip) ==\n");
#else
	printf("== carried copy: FIXED strip ==\n");
#endif

	/* a realistic read-assembled row: {contacts, aorhash} + the private peers,
	 * with the private peers interleaved (head, middle, tail) to catch a
	 * surgery bug that only triggers at a list boundary. */
	struct list_head dict;
	struct tpair *t;
	INIT_LIST_HEAD(&dict);
	list_add_tail(&(t = mk("schema_version", 0))->list, &dict); /* private @ head */
	list_add_tail(&(t = mk("contacts", 3))->list, &dict);       /* CDB_DICT */
	list_add_tail(&(t = mk("row_exp", 0))->list, &dict);        /* private @ middle */
	list_add_tail(&(t = mk("aorhash", 0))->list, &dict);
	(void)t;

	CHECK(count(&dict) == 4, "pre-strip: 4 top-level keys");

	strip(&dict);

	printf("[REV-18/35] private peers stripped, public shape preserved:\n");
	CHECK(!has_key(&dict, "row_exp"), "row_exp stripped");
	CHECK(!has_key(&dict, "schema_version"), "schema_version stripped");
	CHECK(has_key(&dict, "contacts"), "contacts retained");
	CHECK(has_key(&dict, "aorhash"), "aorhash retained");
	CHECK(count(&dict) == 2, "exactly {contacts, aorhash} remain");

	free_all(&dict);

	/* tail-position private key + a non-private 'expires'-prefixed name must
	 * NOT be mistaken for a private peer (substring/length guard). */
	struct list_head d2;
	INIT_LIST_HEAD(&d2);
	list_add_tail(&mk("contacts", 3)->list, &d2);
	list_add_tail(&mk("aorhash", 0)->list, &d2);
	list_add_tail(&mk("row_exposure", 0)->list, &d2);  /* NOT row_exp */
	list_add_tail(&mk("schema", 0)->list, &d2);        /* NOT schema_version */
	list_add_tail(&mk("schema_version", 0)->list, &d2);/* private @ tail */
	strip(&d2);
	printf("[REV-18] precise name match (no false strip):\n");
	CHECK(has_key(&d2, "row_exposure"), "'row_exposure' NOT stripped (prefix, not row_exp)");
	CHECK(has_key(&d2, "schema"), "'schema' NOT stripped (prefix, not schema_version)");
	CHECK(!has_key(&d2, "schema_version"), "tail-position schema_version stripped");
	CHECK(count(&d2) == 4, "only schema_version removed: contacts+aorhash+row_exposure+schema");
	free_all(&d2);

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
