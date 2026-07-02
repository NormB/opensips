/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 Stage 1b [TTL-SOLUTION-SPEC.md §2.2/§2.2.1]: the decision skeleton of
 * nats_kv_put_row() (cachedb_nats_ttl_put.c) -- which branch it takes and which
 * ttl_outcome it returns, given the caller's read state and the (simulated)
 * write status.  The actual js_PublishMsg/kvStore_CreateString glue is proven
 * by the broker e2e (ttl_reassert_proof + Stage 3a); here we lock the routing:
 *
 *   - subject overflow                       -> TTL_FAIL_SAVE   [R11]
 *   - absent entry (NO_MESSAGE)              -> create path
 *       create OK                            -> TTL_DONE
 *       create conn-down                     -> TTL_FAIL_SAVE
 *       create other (key-exists)            -> TTL_RETRY
 *   - present entry (LAST_SEQ)               -> publish path, classified by jerr
 *       publish OK                           -> TTL_DONE
 *       10071 CAS conflict                   -> TTL_RETRY
 *       10166 TTL disabled                   -> TTL_LATCH_OFF
 *       conn-down                            -> TTL_FAIL_SAVE
 *
 * TTL-HISTORY-FIX-SPEC.md D2 [HREV-2] adds the nats_kv_write_row_cas ROUTING
 * on top (the caller of nats_kv_put_row):
 *
 *   - rev == 0 (no prior message; JetStream sequences are 1-based, so 0 is
 *     an unambiguous sentinel)         -> got_entry=0 -> NO_MESSAGE -> the
 *     TTL-carrying create (kvStore_CreateStringWithTTL) -- previously DEAD
 *     CODE because got_entry was hardcoded to 1 [RC-3]
 *   - rev > 0 (live doc or marker rev) -> got_entry=1 -> CAS publish
 *   - nats_native_ttl == 0             -> never the TTL branch, regardless of
 *     the capability latch: legacy path (rev==0 -> CreateString,
 *     rev>0 -> UpdateString)
 *   - cap UNSUPPORTED                  -> same legacy split
 *
 *   gcc -DPUT_CURRENT ... -> a plausible-wrong _pub_status that does NOT special-
 *                            case connection-down (maps timeouts to JS_ERR), so a
 *                            broker-down create returns RETRY (spins) not
 *                            FAIL_SAVE => RED.
 *   gcc -DROWCAS_CURRENT ..-> pre-HREV-2 routing: got_entry hardcoded 1 (a
 *                            rev==0 first insert is CAS-published at seq 0,
 *                            never the TTL-carrying create) and no
 *                            nats_native_ttl check => RED.
 *   gcc ...               -> the fixed mapping/routing => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_put_decision test_ttl_put_decision.c
 */
#include <stdio.h>
#include <stdint.h>

/* ─── carried copies of the cnats status values + the production enums ─── */
typedef enum { NATS_OK = 0, NATS_ERR, NATS_TIMEOUT = 26,
               NATS_CONNECTION_CLOSED = 7, NATS_CONNECTION_DISCONNECTED = 5,
               NATS_NOT_YET_CONNECTED = 8, NATS_OTHER = 99 } natsStatus;

enum ttl_cas_pred { TTL_CAS_NO_MESSAGE = 0, TTL_CAS_LAST_SEQ = 1 };
enum ttl_pub_status { TTL_PUB_OK = 0, TTL_PUB_CONN_DOWN = 1, TTL_PUB_JS_ERR = 2 };
enum ttl_outcome { TTL_DONE = 0, TTL_RETRY = 1, TTL_LATCH_OFF = 2,
                   TTL_ASSERT_BUG = 3, TTL_FAIL_SAVE = 4 };

/* carried copy: _ttl_cas_predicate (cachedb_nats_ttl.c) */
static enum ttl_cas_pred _ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq)
{
	(void)value_len;
	if (got_entry) { *out_seq = entry_rev; return TTL_CAS_LAST_SEQ; }
	if (head_seq > 0) { *out_seq = head_seq; return TTL_CAS_LAST_SEQ; }
	*out_seq = 0; return TTL_CAS_NO_MESSAGE;
}

/* carried copy: _ttl_classify (cachedb_nats_ttl.c) */
static enum ttl_outcome _ttl_classify(enum ttl_pub_status st, int jerr)
{
	if (st == TTL_PUB_OK) return TTL_DONE;
	if (st == TTL_PUB_CONN_DOWN) return TTL_FAIL_SAVE;
	if (jerr == 10071) return TTL_RETRY;
	if (jerr == 10166) return TTL_LATCH_OFF;
	if (jerr == 10165) return TTL_ASSERT_BUG;
	return TTL_FAIL_SAVE;
}

/* carried copy: _pub_status (cachedb_nats_ttl_put.c) */
static enum ttl_pub_status _pub_status(natsStatus s)
{
	if (s == NATS_OK) return TTL_PUB_OK;
#ifndef PUT_CURRENT
	if (s == NATS_TIMEOUT || s == NATS_CONNECTION_CLOSED ||
	    s == NATS_CONNECTION_DISCONNECTED || s == NATS_NOT_YET_CONNECTED)
		return TTL_PUB_CONN_DOWN;
#endif
	return TTL_PUB_JS_ERR;
}

/* carried copy: the decision skeleton of nats_kv_put_row() (no broker calls) */
static enum ttl_outcome put_decision(int subj_ok, int got_entry, int value_len,
	natsStatus create_s, natsStatus pub_s, int pub_jerr)
{
	uint64_t cas = 0;
	enum ttl_cas_pred pred;
	if (!subj_ok)
		return TTL_FAIL_SAVE;                       /* [R11] */
	pred = _ttl_cas_predicate(got_entry, value_len, 7, 0, &cas);
	if (pred == TTL_CAS_NO_MESSAGE) {
		if (create_s == NATS_OK) return TTL_DONE;
		if (_pub_status(create_s) == TTL_PUB_CONN_DOWN) return TTL_FAIL_SAVE;
		return TTL_RETRY;
	}
	return _ttl_classify(_pub_status(pub_s), pub_jerr);
}

/* ─── D2 [HREV-2]: carried copy of the nats_kv_write_row_cas ROUTING ───
 * Which write primitive the row write resolves to, given the read revision,
 * the TTL master switch and the capability latch.  (The outcome mapping of
 * the chosen primitive is covered by put_decision above.) */
enum row_route {
	ROUTE_TTL_CREATE = 0,   /* kvStore_CreateStringWithTTL (NO_MESSAGE)   */
	ROUTE_TTL_PUBLISH = 1,  /* js_PublishMsg CAS w/ MsgTTL (LAST_SEQ)     */
	ROUTE_LEGACY_CREATE = 2,/* kvStore_CreateString (no TTL support)      */
	ROUTE_LEGACY_UPDATE = 3,/* kvStore_UpdateString (no TTL support)      */
};
enum ttl_cap { TTL_CAP_UNPROBED = 0, TTL_CAP_SUPPORTED = 1,
               TTL_CAP_UNSUPPORTED = 2 };

static enum row_route write_row_cas_route(uint64_t rev, int native_ttl,
	enum ttl_cap cap)
{
	uint64_t cas = 0;
#ifdef ROWCAS_CURRENT
	(void)native_ttl;                    /* pre-D6: no master switch */
	if (cap == TTL_CAP_SUPPORTED) {
		/* pre-HREV-2: got_entry hardcoded to 1 */
		return _ttl_cas_predicate(1, 0, rev, 0, &cas) == TTL_CAS_NO_MESSAGE
			? ROUTE_TTL_CREATE : ROUTE_TTL_PUBLISH;
	}
	return ROUTE_LEGACY_UPDATE;          /* pre-HREV-2: Update only */
#else
	if (native_ttl && cap == TTL_CAP_SUPPORTED) {
		/* HREV-2: got_entry derived from the rev==0 sentinel */
		return _ttl_cas_predicate(rev != 0, 0, rev, 0, &cas)
				== TTL_CAS_NO_MESSAGE
			? ROUTE_TTL_CREATE : ROUTE_TTL_PUBLISH;
	}
	return rev == 0 ? ROUTE_LEGACY_CREATE : ROUTE_LEGACY_UPDATE;
#endif
}

static int fails = 0;
static const char *NM[] = {"DONE","RETRY","LATCH_OFF","ASSERT_BUG","FAIL_SAVE"};
static void expect(const char *what, enum ttl_outcome got, enum ttl_outcome want)
{
	if (got == want) printf("  ok:   %-42s => %s\n", what, NM[got]);
	else { printf("  FAIL: %-42s => %s (want %s)\n", what, NM[got], NM[want]); fails++; }
}

int main(void)
{
	printf("[Stage 1b] nats_kv_put_row decision routing:\n");

	/* R11: a truncated subject is never published -- fail the save */
	expect("subject overflow",
	       put_decision(0, 1, 50, NATS_OK, NATS_OK, 0), TTL_FAIL_SAVE);

	/* absent entry => create path (kvStore_CreateString, no TTL [R3]) */
	expect("absent: create OK",
	       put_decision(1, 0, 0, NATS_OK, NATS_OK, 0), TTL_DONE);
	expect("absent: create broker-down",
	       put_decision(1, 0, 0, NATS_TIMEOUT, NATS_OK, 0), TTL_FAIL_SAVE);
	expect("absent: create key-exists",
	       put_decision(1, 0, 0, NATS_ERR, NATS_OK, 0), TTL_RETRY);

	/* present entry (live OR empty marker) => CAS-publish, classified by jerr */
	expect("present: publish OK",
	       put_decision(1, 1, 80, NATS_OK, NATS_OK, 0), TTL_DONE);
	expect("present empty-marker: publish OK",
	       put_decision(1, 1, 0, NATS_OK, NATS_OK, 0), TTL_DONE);
	expect("present: CAS conflict (10071)",
	       put_decision(1, 1, 80, NATS_OK, NATS_ERR, 10071), TTL_RETRY);
	expect("present: TTL disabled (10166)",
	       put_decision(1, 1, 80, NATS_OK, NATS_ERR, 10166), TTL_LATCH_OFF);
	expect("present: publish broker-down",
	       put_decision(1, 1, 80, NATS_OK, NATS_CONNECTION_CLOSED, 0), TTL_FAIL_SAVE);

	{
		static const char *RN[] = {"TTL_CREATE","TTL_PUBLISH",
		                           "LEGACY_CREATE","LEGACY_UPDATE"};
		enum row_route r;
		printf("[HREV-2] write_row_cas routing (rev==0 sentinel + master switch):\n");

		#define RCHECK(what, got, want) do { r = (got); \
			if (r == (want)) printf("  ok:   %-42s => %s\n", what, RN[r]); \
			else { printf("  FAIL: %-42s => %s (want %s)\n", what, RN[r], RN[want]); fails++; } \
		} while (0)

		RCHECK("first insert (rev=0), TTL supported",
		       write_row_cas_route(0, 1, TTL_CAP_SUPPORTED), ROUTE_TTL_CREATE);
		RCHECK("live doc (rev=7), TTL supported",
		       write_row_cas_route(7, 1, TTL_CAP_SUPPORTED), ROUTE_TTL_PUBLISH);
		RCHECK("marker rev (rev=3), TTL supported",
		       write_row_cas_route(3, 1, TTL_CAP_SUPPORTED), ROUTE_TTL_PUBLISH);
		RCHECK("first insert, nats_native_ttl=0",
		       write_row_cas_route(0, 0, TTL_CAP_SUPPORTED), ROUTE_LEGACY_CREATE);
		RCHECK("live doc, nats_native_ttl=0",
		       write_row_cas_route(7, 0, TTL_CAP_SUPPORTED), ROUTE_LEGACY_UPDATE);
		RCHECK("first insert, cap UNSUPPORTED",
		       write_row_cas_route(0, 1, TTL_CAP_UNSUPPORTED), ROUTE_LEGACY_CREATE);
		RCHECK("live doc, cap UNSUPPORTED",
		       write_row_cas_route(7, 1, TTL_CAP_UNSUPPORTED), ROUTE_LEGACY_UPDATE);
		RCHECK("first insert, cap UNPROBED (transient)",
		       write_row_cas_route(0, 1, TTL_CAP_UNPROBED), ROUTE_LEGACY_CREATE);
		#undef RCHECK
	}

	if (fails) { printf("\nFAILED (%d)\n", fails); return 1; }
	printf("\n=== ALL PASS (fails=0) ===\n");
	return 0;
}
