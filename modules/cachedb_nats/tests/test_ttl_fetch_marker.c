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
 * P8 Stage 2 [R4 / TTL-SOLUTION-SPEC §2.2 TREV-2a]: update_fetch_or_seed()'s
 * routing for an empty-value entry.  cnats 3.12 surfaces a server-side MaxAge
 * delete marker as kvStore_Get => NATS_OK with len 0 (NOT NATS_NOT_FOUND).  The
 * fetch path must NOT treat that as an error: it must re-create the AoR OVER the
 * marker -- seed an indexable base doc and CAS at the marker's revision (an
 * UPDATE), since a fresh Create (ExpectNoMessage) is rejected over a marker
 * [REV-27].  Otherwise the first re-REGISTER after any server-side expiry fails.
 *
 *   gcc -DFETCH_CURRENT ... -> today: OK+len0 => ERROR (save fails over marker) => RED.
 *   gcc ...                 -> the FIXED routing (OK+len0+identity => UPDATE)   => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the Stage 3c e2e (let a key TTL-expire on a
 * real >=2.11 server, assert a re-REGISTER succeeds first-attempt).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_fetch_marker test_ttl_fetch_marker.c
 */
#include <stdio.h>

enum gs { GS_OK = 0, GS_NOT_FOUND = 1, GS_OTHER = 2 };
enum fr { FR_CREATE = 0, FR_UPDATE = 1, FR_ERROR = 2 };

/* carried copy of update_fetch_or_seed's routing decision (cachedb_nats_json.c) */
static enum fr fetch_decide(enum gs status, int data_len, int has_identity)
{
	if (status == GS_NOT_FOUND)
		return has_identity ? FR_CREATE : FR_ERROR;   /* first-insert: seed+Create */
	if (status == GS_OTHER)
		return FR_ERROR;                               /* hard Get error */
	/* NATS_OK */
	if (data_len > 0)
		return FR_UPDATE;                              /* live doc: merge + CAS */
#ifdef FETCH_CURRENT
	return FR_ERROR;                                   /* today: "empty document" */
#else
	/* [R4] empty value = MaxAge marker: re-create OVER it via CAS-update at the
	 * marker's revision (needs the filter's string identity to seed). */
	return has_identity ? FR_UPDATE : FR_ERROR;
#endif
}

static int fails = 0;
static const char *NM[] = {"CREATE","UPDATE","ERROR"};
static void expect(const char *what, enum fr got, enum fr want)
{
	if (got == want) printf("  ok:   %-46s => %s\n", what, NM[got]);
	else { printf("  FAIL: %-46s => %s (want %s)\n", what, NM[got], NM[want]); fails++; }
}

int main(void)
{
	printf("[R4] update_fetch_or_seed routing:\n");

	expect("OK, live doc (len>0)",            fetch_decide(GS_OK, 120, 1), FR_UPDATE);
	/* the load-bearing case: empty-value MaxAge marker */
	expect("OK, empty marker (len 0) + identity", fetch_decide(GS_OK, 0, 1), FR_UPDATE);
	expect("OK, empty marker, no identity",   fetch_decide(GS_OK, 0, 0), FR_ERROR);
	expect("NOT_FOUND + identity",            fetch_decide(GS_NOT_FOUND, 0, 1), FR_CREATE);
	expect("NOT_FOUND, no identity",          fetch_decide(GS_NOT_FOUND, 0, 0), FR_ERROR);
	expect("hard Get error",                  fetch_decide(GS_OTHER, 0, 1), FR_ERROR);

	if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
	printf("\n=== ALL PASS (fails=0) ===\n");
	return 0;
}
