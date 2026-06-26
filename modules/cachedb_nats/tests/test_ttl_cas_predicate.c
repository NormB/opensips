/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P5 / TTL-SOLUTION-SPEC.md §2.2 [TREV-2 / TREV-2a / REV-27]: marker-aware CAS
 * predicate for the raw publish.
 *
 *   - kvStore_Get returns an ENTRY (any value_len, including a 0-length
 *     server-side delete marker) -> ExpectLastSubjectSeq = kvEntry_Revision.
 *     An empty-value entry must NOT be treated as "absent".
 *   - kvStore_Get returns NOT_FOUND but the subject still has a head sequence
 *     (a DEL/PURGE marker that kvStore_Get filters out) -> ExpectLastSubjectSeq
 *     = head_seq, NOT ExpectNoMessage (the server rejects ExpectNoMessage over a
 *     marker -> 10071 lockout, [REV-27]).
 *   - genuinely empty subject (NOT_FOUND, no head) -> ExpectNoMessage.
 *
 * [PREV-9] necessary but not sufficient: this tests predicate SELECTION given a
 * fabricated entry/head; the authoritative "re-REGISTER after a real expiry
 * succeeds first-attempt" is the P8 e2e.
 *
 *   gcc -DCASPRED_CURRENT ... -> bug: an empty value / NOT_FOUND is treated as
 *                               absent => ExpectNoMessage => RED.
 *   gcc ...                  -> the FIXED marker-aware predicate => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_cas_predicate test_ttl_cas_predicate.c
 */
#include <stdio.h>
#include <stdint.h>

enum ttl_cas_pred { TTL_CAS_NO_MESSAGE = 0, TTL_CAS_LAST_SEQ = 1 };

/* ─── carried copy of the production helper (cachedb_nats_ttl.c) ─── */
static enum ttl_cas_pred _ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq)
{
#ifdef CASPRED_CURRENT
	/* bug: an empty value is treated as absent. */
	if (got_entry && value_len > 0) { *out_seq = entry_rev; return TTL_CAS_LAST_SEQ; }
	*out_seq = 0; return TTL_CAS_NO_MESSAGE;
#else
	(void)value_len;
	if (got_entry) { *out_seq = entry_rev; return TTL_CAS_LAST_SEQ; }
	if (head_seq > 0) { *out_seq = head_seq; return TTL_CAS_LAST_SEQ; }
	*out_seq = 0; return TTL_CAS_NO_MESSAGE;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
	uint64_t seq;
#ifdef CASPRED_CURRENT
	printf("== carried copy: CASPRED_CURRENT (marker==absent bug) ==\n");
#else
	printf("== carried copy: FIXED predicate ==\n");
#endif

	printf("[TREV-2] a non-empty entry => ExpectLastSubjectSeq=rev:\n");
	CHECK(_ttl_cas_predicate(1, 50, 7, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 7,
	      "non-empty entry => LAST_SEQ at rev 7");

	printf("[TREV-2a] an EMPTY-value entry (marker) => LAST_SEQ, not NoMessage:\n");
	CHECK(_ttl_cas_predicate(1, 0, 7, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 7,
	      "empty-value entry => LAST_SEQ at rev 7 (NOT ExpectNoMessage)");

	printf("[REV-27] NOT_FOUND with a head marker => LAST_SEQ at head:\n");
	CHECK(_ttl_cas_predicate(0, 0, 0, 9, &seq) == TTL_CAS_LAST_SEQ && seq == 9,
	      "NOT_FOUND + head seq 9 => LAST_SEQ at 9 (not ExpectNoMessage)");

	printf("[TREV-2a] genuinely empty subject => ExpectNoMessage:\n");
	CHECK(_ttl_cas_predicate(0, 0, 0, 0, &seq) == TTL_CAS_NO_MESSAGE && seq == 0,
	      "NOT_FOUND + no head => ExpectNoMessage, seq 0");

	printf("adversarial: rev/head at boundary values:\n");
	CHECK(_ttl_cas_predicate(1, 0, UINT64_MAX, 0, &seq) == TTL_CAS_LAST_SEQ && seq == UINT64_MAX,
	      "entry rev UINT64_MAX preserved");
	CHECK(_ttl_cas_predicate(1, 0, 1, 0, &seq) == TTL_CAS_LAST_SEQ && seq == 1,
	      "entry rev 1 (lowest real) => LAST_SEQ");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
