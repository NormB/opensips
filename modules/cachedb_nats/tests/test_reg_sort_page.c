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
 * Registration-observability MI [OBS]: nats_reg_list ordering + pagination.
 *
 *   sort=aor       lexicographic on the decoded AoR (the stable default)
 *   sort=expiry    soonest non-permanent expiry first; rows with NO
 *                  expiring contact (permanent-only) sort LAST ascending
 *                  (sentinel INT64_MAX), so "what dies next" tops the list
 *   sort=contacts  stored-contact count
 *   sort=last_mod  most-recent contact modification
 *   desc=1         reverses; ties then break by AoR both ways (stable,
 *                  deterministic pagination across repeated calls)
 *
 *   cdbn_reg_page(total, limit, offset): window clamps -- offset past the end
 *   yields an empty page, never an error; count never exceeds the remainder.
 *
 *   gcc -DREGS_CURRENT ... -> comparator ignores the sort key (insertion
 *                             order leaks out) and pagination has no
 *                             end-clamp => RED.
 *   gcc ...                -> the FIXED ordering/paging => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_reg_sort_page test_reg_sort_page.c
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ─── carried copies (cachedb_nats_reg.c) ─────────────────────────── */

enum reg_sortkey { REG_SORT_AOR = 0, REG_SORT_EXPIRY = 1,
                   REG_SORT_CONTACTS = 2, REG_SORT_LAST_MOD = 3 };

struct reg_row_sum {
	const char *aor; int aor_len;
	int n_contacts;
	int64_t soonest_exp;        /* INT64_MAX when nothing expires */
	int64_t last_mod;
};

static int _aor_cmp(const struct reg_row_sum *a, const struct reg_row_sum *b)
{
	int n = a->aor_len < b->aor_len ? a->aor_len : b->aor_len;
	int c = memcmp(a->aor, b->aor, n);
	if (c)
		return c;
	return a->aor_len - b->aor_len;
}

static int cdbn_reg_row_cmp(const struct reg_row_sum *a,
	const struct reg_row_sum *b, int sort, int desc)
{
#ifdef REGS_CURRENT
	(void)a; (void)b; (void)sort; (void)desc;
	return 0;                                   /* no ordering at all */
#else
	int c = 0;
	switch (sort) {
	case REG_SORT_EXPIRY:
		c = a->soonest_exp < b->soonest_exp ? -1 :
		    a->soonest_exp > b->soonest_exp ?  1 : 0;
		break;
	case REG_SORT_CONTACTS:
		c = a->n_contacts - b->n_contacts;
		break;
	case REG_SORT_LAST_MOD:
		c = a->last_mod < b->last_mod ? -1 :
		    a->last_mod > b->last_mod ?  1 : 0;
		break;
	}
	if (c == 0 && sort != REG_SORT_AOR)
		return _aor_cmp(a, b);                  /* tie-break: AoR, ALWAYS asc */
	if (sort == REG_SORT_AOR)
		c = _aor_cmp(a, b);
	return desc ? -c : c;
#endif
}

static void cdbn_reg_page(long total, long limit, long offset,
	long *start, long *count)
{
#ifdef REGS_CURRENT
	*start = offset; *count = limit;            /* no end clamp */
#else
	if (offset >= total) {
		*start = total; *count = 0;             /* past the end: empty page */
		return;
	}
	*start = offset;
	*count = (offset + limit > total) ? total - offset : limit;
#endif
}

/* ─── harness ─────────────────────────────────────────────────────── */

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static int g_sort, g_desc;
static int qcmp(const void *a, const void *b)
{
	return cdbn_reg_row_cmp((const struct reg_row_sum *)a,
	                    (const struct reg_row_sum *)b, g_sort, g_desc);
}
static const char *order(struct reg_row_sum *r, int n, int sort, int desc,
	char *buf)
{
	int i; char *p = buf;
	g_sort = sort; g_desc = desc;
	qsort(r, n, sizeof(*r), qcmp);
	for (i = 0; i < n; i++) {
		memcpy(p, r[i].aor, r[i].aor_len); p += r[i].aor_len;
		if (i + 1 < n) *p++ = ',';
	}
	*p = '\0';
	return buf;
}

int main(void)
{
#ifdef REGS_CURRENT
	printf("== carried copy: REGS_CURRENT (unordered, unclamped) ==\n");
#else
	printf("== carried copy: FIXED ordering + paging ==\n");
#endif
	char buf[256];
	/* c: 2 contacts, dies first; a: permanent-only; b: 1 contact, dies later;
	 * d: same expiry as c (tie) -- deliberately inserted out of order. */
	#define ROWS { \
		{"d@x", 3, 1, 500, 90}, \
		{"a@x", 3, 3, INT64_MAX, 10}, \
		{"c@x", 3, 2, 500, 40}, \
		{"b@x", 3, 1, 900, 70}, \
	}

	printf("[OBS] sort=aor (default) is lexicographic:\n");
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_AOR, 0, buf), "a@x,b@x,c@x,d@x") == 0,
	        "aor asc"); }
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_AOR, 1, buf), "d@x,c@x,b@x,a@x") == 0,
	        "aor desc"); }

	printf("[OBS] sort=expiry: what dies next first; permanent-only LAST:\n");
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_EXPIRY, 0, buf), "c@x,d@x,b@x,a@x") == 0,
	        "expiry asc (c/d tie -> AoR asc; permanent-only a@x last)"); }
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_EXPIRY, 1, buf), "a@x,b@x,c@x,d@x") == 0,
	        "expiry desc reverses the key but ties stay AoR-asc (deterministic)"); }

	printf("[OBS] sort=contacts / sort=last_mod:\n");
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_CONTACTS, 0, buf), "b@x,d@x,c@x,a@x") == 0,
	        "contacts asc (b/d tie at 1 -> AoR asc)"); }
	{ struct reg_row_sum r[] = ROWS;
	  CHECK(strcmp(order(r, 4, REG_SORT_LAST_MOD, 1, buf), "d@x,b@x,c@x,a@x") == 0,
	        "last_mod desc (most recently modified first)"); }

	printf("[OBS] pagination window clamps:\n");
	{
		long s, c;
		cdbn_reg_page(10, 4, 0, &s, &c);
		CHECK(s == 0 && c == 4, "first page: [0,4)");
		cdbn_reg_page(10, 4, 8, &s, &c);
		CHECK(s == 8 && c == 2, "last partial page: count clamps to remainder");
		cdbn_reg_page(10, 4, 10, &s, &c);
		CHECK(c == 0, "offset == total: empty page, not an error");
		cdbn_reg_page(10, 4, 9999, &s, &c);
		CHECK(c == 0, "offset far past the end: empty page");
		cdbn_reg_page(0, 50, 0, &s, &c);
		CHECK(c == 0, "empty result set: empty page");
		cdbn_reg_page(3, 200, 0, &s, &c);
		CHECK(s == 0 && c == 3, "limit larger than total: whole set");
	}

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
