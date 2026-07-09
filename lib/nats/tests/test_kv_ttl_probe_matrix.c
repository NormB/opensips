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
 * TTL-HISTORY-FIX-SPEC.md D1 [HREV-1] / RC-5: the per-message-TTL capability
 * probe decision matrix.
 *
 * Pre-F3, nats_pool_kv_supports_ttl() reported SUPPORTED from AllowMsgTTL +
 * MaxAge==0 alone -- never looking at MaxMsgsPerSubject -- so the module used
 * per-message TTL on history-keeping buckets where a TTL'd head is removed
 * late (~LimitMarkerTTL) and the subject then rolls back to an older revision
 * (verified live on 2.11.10, spec §0 E1/E3).
 *
 * The fixed split: the pool probe stays mechanical (AllowMsgTTL + MaxAge) but
 * REPORTS the stream's MaxMsgsPerSubject via an out-param; the module then
 * applies the single tested history rule (_kv_ttl_history_ok, with the
 * nats_ttl_allow_history override).  This test locks the COMPOSED decision --
 * the only stream shape that yields the TTL fast path without an override is
 * {AllowMsgTTL=1, MaxAge=0, MaxMsgsPerSubject=1}:
 *
 *   gcc -DPROBE_CURRENT ... -> pre-F3 composition (history never consulted):
 *                              a history-keeping bucket probes SUPPORTED
 *                              => RED.
 *   gcc ...                 -> the fixed composition => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_ttl_probe_matrix test_kv_ttl_probe_matrix.c
 */
#include <stdio.h>
#include <stdint.h>

/* ─── carried copy: the pool's mechanical report (nats_pool.c) ────── */
/* @get_failed models js_GetStreamInfo failing (no JS ctx / transient).
 * Returns 1 = AllowMsgTTL usable at stream level, 0 = not, -1 = transient
 * (stay UNPROBED, retry later).  Fills *out_mmps on 0/1. */
static int probe_report(int get_failed, int allow_ttl, int64_t maxage_ns,
	int64_t mmps, int64_t *out_mmps)
{
	if (get_failed)
		return -1;
	if (out_mmps)
		*out_mmps = mmps;
	if (maxage_ns != 0)
		return 0;                  /* [R7 pair] MaxAge overrides TTL */
	return allow_ttl ? 1 : 0;
}

/* ─── carried copy: the module's history rule (cachedb_nats_ttl.c) ── */
static int _kv_ttl_history_ok(int64_t mmps, int allow_history)
{
	if (mmps == 1)
		return 1;
	return allow_history ? 1 : 0;
}

/* ─── the composed probe decision (cachedb_nats_ttl_put.c) ────────── */
static int probe_final(int get_failed, int allow_ttl, int64_t maxage_ns,
	int64_t mmps, int allow_history)
{
	int64_t seen = -1;
	int r = probe_report(get_failed, allow_ttl, maxage_ns, mmps, &seen);
#ifdef PROBE_CURRENT
	(void)allow_history; (void)seen;
	return r;                          /* RC-5: history never consulted */
#else
	if (r == 1 && !_kv_ttl_history_ok(seen, allow_history))
		return 0;                      /* HREV-1: history-keeping => refuse */
	return r;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef PROBE_CURRENT
	printf("== carried copy: PROBE_CURRENT (RC-5, no history gate) ==\n");
#else
	printf("== carried copy: FIXED composed probe ==\n");
#endif

	printf("[HREV-1] the one TTL-safe shape: AllowMsgTTL, MaxAge=0, MMPS=1:\n");
	CHECK(probe_final(0, 1, 0, 1, 0) == 1, "(ttl=1, maxage=0, mmps=1) => SUPPORTED");

	printf("[HREV-1/RC-5] history-keeping streams are refused:\n");
	CHECK(probe_final(0, 1, 0, 5, 0) == 0, "(ttl=1, maxage=0, mmps=5) => refused");
	CHECK(probe_final(0, 1, 0, 2, 0) == 0, "(ttl=1, maxage=0, mmps=2) => refused");
	CHECK(probe_final(0, 1, 0, 0, 0) == 0, "(ttl=1, maxage=0, mmps=0 'unlimited') => refused");

	printf("[R7/REV-25] the pre-existing refusals still hold:\n");
	CHECK(probe_final(0, 0, 0, 1, 0) == 0, "(no AllowMsgTTL) => refused");
	CHECK(probe_final(0, 1, 7, 1, 0) == 0, "(MaxAge!=0) => refused, even at mmps=1");
	CHECK(probe_final(0, 0, 7, 5, 0) == 0, "(everything wrong) => refused");

	printf("[TREV-8] transient probe failure stays UNPROBED (retry later):\n");
	CHECK(probe_final(1, 1, 0, 1, 0) == -1, "GetStreamInfo failed => -1");

	printf("[D6] nats_ttl_allow_history=1 overrides ONLY the history rule:\n");
	CHECK(probe_final(0, 1, 0, 5, 1) == 1, "mmps=5 + override => SUPPORTED (operator's call)");
	CHECK(probe_final(0, 1, 7, 5, 1) == 0, "override does NOT bypass the MaxAge refusal");
	CHECK(probe_final(0, 0, 0, 5, 1) == 0, "override does NOT conjure AllowMsgTTL");
	CHECK(probe_final(1, 1, 0, 5, 1) == -1, "override does NOT mask a transient failure");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
