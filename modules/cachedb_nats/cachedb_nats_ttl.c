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
 * cachedb_nats_ttl.c — pure decision logic for the usrloc-row CAS write
 * and the reaper-only expiry model.  (The native per-message-TTL
 * mechanism this file once served was deleted in P1.5: the reaper is
 * the single expiry authority.)  Broker-less, side-effect-free.
 */

#include <stdio.h>   /* snprintf */

#include "cachedb_nats_ttl.h"

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
	if (jerr == 10071)                  /* JSStreamWrongLastSequenceErr */
		return TTL_RETRY;               /* CAS conflict: re-read+retry  */
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

/* [D6/HREV-6] nats_expired_linger range guard: negative is meaningless,
 * > 1 day is almost certainly a typo'd epoch pasted into the config. */
int _linger_guard(int linger)
{
	return (linger >= 0 && linger <= 86400) ? 0 : -1;
}

/* P11b [REV-25 / §5.3 REV-7]: policy for a PRE-EXISTING bucket whose backing
 * stream already carries a non-zero MaxAge (created by an older deployment or
 * another tool — the _kv_ttl_guard modparam check above only stops THIS module
 * from creating one).  A non-zero stream MaxAge expires EVERY key after that
 * age, including PERMANENT contacts (expires==0) — silent registration loss.
 * @maxage_ns: the bound bucket's backing-stream MaxAge in ns.
 * @return 1 => warn (non-zero MaxAge; never silent), 0 => clean (MaxAge==0). */
int _kv_legacy_bucket_maxage_warn(int64_t maxage_ns)
{
	return maxage_ns != 0 ? 1 : 0;
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
