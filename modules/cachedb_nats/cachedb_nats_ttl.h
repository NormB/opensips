/*
 * Copyright (C) 2025 Summit-2026 / cachedb_nats contributors
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
 */

/*
 * cachedb_nats_ttl.h — pure logic for the native NATS per-key TTL mechanism
 * (TTL-SOLUTION-SPEC.md).  These helpers are broker-less and side-effect-free:
 * eligibility, TTL/unit computation, the marker-aware CAS predicate, and
 * js_PublishMsg outcome classification.  The actual raw-publish wiring (the
 * js_PublishMsg / js_UpdateStream bindings) is added later (P6+); keeping the
 * decision logic pure makes it exhaustively unit-testable without a server.
 */

#ifndef CACHEDB_NATS_TTL_H
#define CACHEDB_NATS_TTL_H

#include <stdint.h>

#define NATS_NS_PER_S 1000000000LL

/* [REV-6/F6] (§5): set a per-message MsgTTL on a write IFF the row has no
 * permanent contact (row_exp != 0) AND it holds exactly one contact, or every
 * contact shares the same expires (min == max).  A min-derived TTL on a
 * mixed-expiry row would tombstone the whole row (data loss), so those are
 * ineligible (plain CAS + reaper). */
int _ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry);

/* (§2.3) ttl_seconds = row_exp - now + grace. */
int64_t _ttl_seconds(int64_t row_exp, int64_t now, int grace);

/* (§2.3 [TREV-12]) jsPubOptions.MsgTTL in milliseconds.  Returns 0 — the
 * "purge signal" (publish NO value, purge the key instead) — when ttl_seconds
 * <= 0, which also avoids the server's MsgTTL < 1000 ms rejection.  Otherwise
 * whole-seconds * 1000 (invariant: result % 1000 == 0), overflow-safe. */
int64_t _ttl_msgttl_ms(int64_t ttl_seconds);

/* (§2.3) stream-config SubjectDeleteMarkerTTL in nanoseconds from seconds. */
int64_t _ttl_marker_ns(int64_t seconds);

/* ---- marker-aware CAS predicate (§2.2 [TREV-2/2a], [REV-27]) ------ */

/* Which JetStream publish precondition to use.  An empty-value entry is a
 * server-side delete marker — it must CAS at its revision, NOT be treated as
 * absent; and a NATS_NOT_FOUND that still has a head sequence (a DEL/PURGE
 * marker filtered by kvStore_Get) must CAS at the head, not use ExpectNoMessage
 * (which the server rejects over a marker, [REV-27]). */
enum ttl_cas_pred {
	TTL_CAS_NO_MESSAGE = 0,   /* ExpectNoMessage — provably empty subject */
	TTL_CAS_LAST_SEQ   = 1,   /* ExpectLastSubjectSeq = *out_seq */
};

/* @got_entry: kvStore_Get returned an entry (any @value_len, incl. 0 marker).
 * @entry_rev: that entry's kvEntry_Revision.  @head_seq: the subject's resolved
 * head sequence when !got_entry (0 if provably empty).  Sets *out_seq. */
enum ttl_cas_pred _ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq);

/* ---- js_PublishMsg outcome classification (§2.2.1 [TREV-13]) ------ */

/* Normalized publish status (the caller maps natsStatus: NATS_OK -> OK,
 * NATS_TIMEOUT/NATS_CONNECTION_CLOSED -> CONN_DOWN, else -> JS_ERR), so this TU
 * stays free of the nats.h status-enum coupling. */
enum ttl_pub_status {
	TTL_PUB_OK        = 0,
	TTL_PUB_CONN_DOWN = 1,
	TTL_PUB_JS_ERR    = 2,
};
enum ttl_outcome {
	TTL_DONE       = 0,   /* committed */
	TTL_RETRY      = 1,   /* CAS conflict (10071) — re-read + retry */
	TTL_LATCH_OFF  = 2,   /* stream lacks AllowMsgTTL (10166) — fall back */
	TTL_ASSERT_BUG = 3,   /* malformed TTL (10165) — the §2.3 guard failed */
	TTL_FAIL_SAVE  = 4,   /* broker down / unknown — non-2xx, client retries */
};
enum ttl_outcome _ttl_classify(enum ttl_pub_status st, int jerr);

/* ---- delete / purge as a publish (§2.5) -------------------------- */
#define NATS_KV_OP_HDR   "KV-Operation"
#define NATS_KV_OP_DEL   "DEL"
#define NATS_KV_OP_PURGE "PURGE"
/* The KV-Operation value for a publish-delete: PURGE (drop history) when
 * @purge, else DEL (tombstone, keep history). */
const char *_ttl_delete_op(int purge);

#endif /* CACHEDB_NATS_TTL_H */
