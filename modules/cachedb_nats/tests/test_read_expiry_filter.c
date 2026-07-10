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
 * P4 / SPEC.md §4.2 [REV-3 / REV-1 / REV-26]: read-side expiry filter.
 *
 * On query(), each contact in the row is filtered before usrloc sees it:
 *   - expires == 0  (permanent)            -> ALWAYS emitted;
 *   - expires != 0 && expires + S <= now   -> OMITTED (S = nats_reap_grace);
 *   - absent / unparseable expires         -> treated EXPIRED, omitted
 *                                             (fail-closed: never serve an
 *                                             unparseable binding) [REV-26];
 *   - else (live)                          -> emitted.
 * G2 is defense-in-depth atop usrloc's own VALID_CONTACT re-check; with no
 * in-memory copy the reaper is the sole *physical* cleanup, so the read MUST
 * perform ZERO writes — no inline purge/CAS (asserted by the Tier-2 e2e).  If
 * every contact is filtered the row is returned with an empty contacts dict.
 *
 * _omit_contact(has_expires, expires, now, grace): the per-contact decision
 * (1 = omit).  The surgery below removes omitted contacts from a list with the
 * SAME list.h primitives the production filter uses, so ASan catches a UAF /
 * skipped-node / leak in the removal loop.
 *
 *   gcc -DREADFILT_CURRENT ... -> today: no read filter (_omit_contact always 0)
 *                               => RED (expired/absent contacts still served).
 *   gcc ...                   -> the FIXED filter => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is test_usrloc_read_expiry_e2e.sh (expired
 * contact omitted, ZERO writes on read) vs production.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_read_expiry_filter test_read_expiry_filter.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../../../lib/list.h"

/* ─── carried copy of the production decision (rowmeta TU) ───────── */
static int contact_is_expired(int64_t expires, long now, int grace)
{
	return expires != 0 && (expires + (int64_t)grace) <= (int64_t)now;
}
static int _omit_contact(int has_expires, int64_t expires, long now, int grace)
{
#ifdef READFILT_CURRENT
	(void)has_expires; (void)expires; (void)now; (void)grace;
	(void)contact_is_expired; return 0;
#else
	if (!has_expires)
		return 1;                  /* fail-closed: unparseable => expired */
	return contact_is_expired(expires, now, grace);
#endif
}

/* minimal mirror of a parsed contact pair. */
struct tcontact {
	const char *id;
	int         has_expires;
	int64_t     expires;
	struct list_head list;
};
static struct tcontact *mk(const char *id, int has, int64_t exp)
{
	struct tcontact *c = malloc(sizeof *c);
	c->id = id; c->has_expires = has; c->expires = exp;
	return c;
}
/* carried copy of the filter surgery (mirrors cdbn_row_filter_expired_contacts). */
static void filter(struct list_head *contacts, long now, int grace)
{
	struct list_head *pos, *tmp;
	list_for_each_safe(pos, tmp, contacts) {
		struct tcontact *c = list_entry(pos, struct tcontact, list);
		if (_omit_contact(c->has_expires, c->expires, now, grace)) {
			list_del(&c->list);
			free(c);
		}
	}
}

/* ─── assertions ─────────────────────────────────────────────── */
static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)
static int has_id(struct list_head *d, const char *id)
{
	struct list_head *pos;
	list_for_each(pos, d) if (strcmp(list_entry(pos, struct tcontact, list)->id, id) == 0) return 1;
	return 0;
}
static int count(struct list_head *d)
{ int n = 0; struct list_head *pos; list_for_each(pos, d) n++; return n; }
static void free_all(struct list_head *d)
{ struct list_head *pos, *tmp; list_for_each_safe(pos, tmp, d) free(list_entry(pos, struct tcontact, list)); }

int main(void)
{
	const long now = 1000;
	const int S = 5;

#ifdef READFILT_CURRENT
	printf("== carried copy: READFILT_CURRENT (no read filter) ==\n");
#else
	printf("== carried copy: FIXED read filter ==\n");
#endif

	printf("[REV-3/1] per-contact decision (now=1000, S=5):\n");
	CHECK(_omit_contact(1, 2000, now, S) == 0, "future expiry => emitted");
	CHECK(_omit_contact(1, 996, now, S) == 0, "996+5>1000 => live, emitted (within skew)");
	CHECK(_omit_contact(1, 995, now, S) == 1, "995+5==1000 boundary => omitted");
	CHECK(_omit_contact(1, 900, now, S) == 1, "900+5<=1000 => expired, omitted");
	CHECK(_omit_contact(1, 0, now, S) == 0, "expires==0 (permanent) => ALWAYS emitted");
	CHECK(_omit_contact(0, 0, now, S) == 1, "absent expires => fail-closed, omitted");

	printf("[REV-3] filter surgery keeps live+permanent, drops expired+absent:\n");
	{
		struct list_head d; INIT_LIST_HEAD(&d);
		list_add_tail(&mk("live", 1, 2000)->list, &d);      /* keep */
		list_add_tail(&mk("expired", 1, 900)->list, &d);    /* drop */
		list_add_tail(&mk("perm", 1, 0)->list, &d);         /* keep */
		list_add_tail(&mk("noexp", 0, 0)->list, &d);        /* drop (fail-closed) */
		list_add_tail(&mk("boundary", 1, 995)->list, &d);   /* drop (==) */
		filter(&d, now, S);
		CHECK(has_id(&d, "live") && has_id(&d, "perm"), "live + permanent kept");
		CHECK(!has_id(&d, "expired"), "expired omitted");
		CHECK(!has_id(&d, "noexp"), "absent-expires omitted (fail-closed)");
		CHECK(!has_id(&d, "boundary"), "boundary expires+S==now omitted");
		CHECK(count(&d) == 2, "exactly the 2 live/permanent contacts remain");
		free_all(&d);
	}

	printf("[REV-35] all-expired row => empty contacts (not an error):\n");
	{
		struct list_head d; INIT_LIST_HEAD(&d);
		list_add_tail(&mk("a", 1, 100)->list, &d);
		list_add_tail(&mk("b", 0, 0)->list, &d);
		filter(&d, now, S);
		CHECK(count(&d) == 0, "every contact expired => empty contacts dict");
		free_all(&d);
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
