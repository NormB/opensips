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
 * cachedb_nats_ttl.c — pure logic for the native NATS per-key TTL mechanism
 * (TTL-SOLUTION-SPEC.md §2.3/§5).  Broker-less, side-effect-free; the live
 * raw-publish wiring is added later (P6+).
 */

#include <stdio.h>   /* snprintf */

#include "cachedb_nats_ttl.h"

/* [REV-6/F6] (§5) per-message TTL eligibility. */
int _ttl_eligible(int64_t row_exp, int n_contacts, int all_same_expiry)
{
	if (n_contacts < 1)
		return 0;             /* empty row => no TTL */
	if (row_exp == 0)
		return 0;             /* a permanent contact => never auto-expire */
	return (n_contacts == 1) || all_same_expiry;
}

/* (§2.3) ttl_seconds = row_exp - now + grace. */
int64_t _ttl_seconds(int64_t row_exp, int64_t now, int grace)
{
	return row_exp - now + (int64_t)grace;
}

/* (§2.3 [TREV-12]) MsgTTL in ms; 0 = purge signal. */
int64_t _ttl_msgttl_ms(int64_t ttl_seconds)
{
	int64_t ms;

	if (ttl_seconds <= 0)
		return 0;                              /* purge signal */
	/* overflow-safe: cap before *1000 (real epochs never reach this). */
	if (ttl_seconds > 9223372036854775LL)
		ttl_seconds = 9223372036854775LL;
	ms = ttl_seconds * 1000;
	if (ms < 1000)
		ms = 1000;                             /* clamp to the 1 s minimum */
	return ms;
}

/* (§2.3) SubjectDeleteMarkerTTL (stream config) in ns from whole seconds. */
int64_t _ttl_marker_ns(int64_t seconds)
{
	return seconds * NATS_NS_PER_S;
}

/* (§2.2 [TREV-2/2a], [REV-27]) marker-aware CAS predicate. */
enum ttl_cas_pred _ttl_cas_predicate(int got_entry, int value_len,
	uint64_t entry_rev, uint64_t head_seq, uint64_t *out_seq)
{
	(void)value_len;   /* empty (marker) and non-empty both CAS at the rev */
	if (got_entry) {
		*out_seq = entry_rev;
		return TTL_CAS_LAST_SEQ;
	}
	if (head_seq > 0) {
		/* NOT_FOUND but a DEL/PURGE marker sits at the head — CAS there,
		 * never ExpectNoMessage (the server rejects it over a marker). */
		*out_seq = head_seq;
		return TTL_CAS_LAST_SEQ;
	}
	*out_seq = 0;
	return TTL_CAS_NO_MESSAGE;   /* provably empty subject */
}

/* (§2.2.1 [TREV-13]) js_PublishMsg outcome classification. */
enum ttl_outcome _ttl_classify(enum ttl_pub_status st, int jerr)
{
	if (st == TTL_PUB_OK)
		return TTL_DONE;
	if (st == TTL_PUB_CONN_DOWN)
		return TTL_FAIL_SAVE;            /* down: any jerr is stale/meaningless */
	switch (jerr) {                     /* st == TTL_PUB_JS_ERR */
	case 10071: return TTL_RETRY;       /* JSStreamWrongLastSequenceErr */
	case 10166: return TTL_LATCH_OFF;   /* JSMessageTTLDisabledErr      */
	case 10165: return TTL_ASSERT_BUG;  /* JSMessageTTLInvalidErr       */
	}
	/* an unrecognized JS error => fail the save. */
	return TTL_FAIL_SAVE;
}

/* (§2.5) KV-Operation value for a publish-delete. */
const char *_ttl_delete_op(int purge)
{
	return purge ? NATS_KV_OP_PURGE : NATS_KV_OP_DEL;
}

/* (§5.3 [REV-7]) kv_ttl==0 startup guard. */
int _kv_ttl_guard(int kv_ttl)
{
	return (kv_ttl == 0) ? 0 : -1;
}

/* (§6 [TREV-8]) per-message-TTL capability latch transition. */
enum ttl_cap _ttl_cap_next(enum ttl_cap cur, enum ttl_cap_event ev)
{
	if (ev == TTL_EV_RECONNECT)
		return TTL_CAP_UNPROBED;            /* re-probe on reconnect */
	if (ev == TTL_EV_SAW_10166 || ev == TTL_EV_SETUP_FAIL)
		return TTL_CAP_UNSUPPORTED;         /* latch off for the connection */
	/* TTL_EV_SETUP_OK */
	if (cur == TTL_CAP_UNSUPPORTED)
		return TTL_CAP_UNSUPPORTED;         /* stay latched until a reconnect */
	return TTL_CAP_SUPPORTED;
}

/* (§2.1 [TREV-5]) build "$KV.<bucket>.<key>" — one mapping, three consumers. */
int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen)
{
	int n = snprintf(buf, buflen, "$KV.%s.%s", bucket, key);
	if (n < 0 || n >= buflen)
		return -1;
	return n;
}
