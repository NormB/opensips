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
 * P5 / TTL-SOLUTION-SPEC.md §2.2.1 [TREV-13]: js_PublishMsg outcome routing.
 *
 *   NATS_OK                              -> DONE (record ack->Sequence as rev)
 *   jerr 10071 (WrongLastSequence)       -> RETRY  (CAS conflict; re-read)
 *   jerr 10166 (MessageTTLDisabled)      -> LATCH_OFF (stream lacks AllowMsgTTL;
 *                                           fall back to plain CAS + reaper)
 *   jerr 10165 (MessageTTLInvalid)       -> ASSERT_BUG (the §2.3 guard failed)
 *   NATS_TIMEOUT / NATS_CONNECTION_CLOSED-> FAIL_SAVE (non-2xx; client retries)
 *
 * The natsStatus return is NATS_ERR for JS rejections, so jsErrCode is what
 * actually distinguishes them — hence js_PublishMsg over the fire-and-forget
 * js_PublishAsync.  The caller normalizes natsStatus to ttl_pub_status so this
 * decision is broker-less.
 *
 *   gcc -DCLASSIFY_CURRENT ... -> naive: any non-OK => RETRY => RED.
 *   gcc ...                   -> the FIXED classifier => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_errcode_classify test_ttl_errcode_classify.c
 */
#include <stdio.h>

enum ttl_pub_status { TTL_PUB_OK = 0, TTL_PUB_CONN_DOWN = 1, TTL_PUB_JS_ERR = 2 };
enum ttl_outcome { TTL_DONE = 0, TTL_RETRY = 1, TTL_LATCH_OFF = 2,
                   TTL_ASSERT_BUG = 3, TTL_FAIL_SAVE = 4 };

/* ─── carried copy of the production helper (cachedb_nats_expiry.c) ─── */
static enum ttl_outcome cdbn_ttl_classify(enum ttl_pub_status st, int jerr)
{
#ifdef CLASSIFY_CURRENT
	(void)jerr;
	return st == TTL_PUB_OK ? TTL_DONE : TTL_RETRY;   /* naive: retry everything */
#else
	if (st == TTL_PUB_OK)
		return TTL_DONE;
	if (st == TTL_PUB_CONN_DOWN)
		return TTL_FAIL_SAVE;        /* down: any jerr is stale/meaningless */
	switch (jerr) {                  /* st == TTL_PUB_JS_ERR */
	case 10071: return TTL_RETRY;
	case 10166: return TTL_LATCH_OFF;
	case 10165: return TTL_ASSERT_BUG;
	}
	return TTL_FAIL_SAVE;
#endif
}

static int fails = 0;
#define EQ(got, want, msg) do { int _g=(got),_w=(want); \
	if (_g != _w) { printf("  FAIL: %s (got %d want %d)\n", msg,_g,_w); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef CLASSIFY_CURRENT
	printf("== carried copy: CLASSIFY_CURRENT (retry-everything) ==\n");
#else
	printf("== carried copy: FIXED classifier ==\n");
#endif

	printf("[TREV-13] outcome routing:\n");
	EQ(cdbn_ttl_classify(TTL_PUB_OK, 0), TTL_DONE, "NATS_OK => DONE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10071), TTL_RETRY, "10071 WrongLastSeq => RETRY");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10166), TTL_LATCH_OFF, "10166 TTLDisabled => LATCH_OFF");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 10165), TTL_ASSERT_BUG, "10165 TTLInvalid => ASSERT_BUG");
	EQ(cdbn_ttl_classify(TTL_PUB_CONN_DOWN, 0), TTL_FAIL_SAVE, "TIMEOUT/CLOSED => FAIL_SAVE");

	printf("[TREV-13] OK ignores any stale jerr; unknown JS error fails the save:\n");
	EQ(cdbn_ttl_classify(TTL_PUB_OK, 10071), TTL_DONE, "OK + stale jerr => still DONE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 99999), TTL_FAIL_SAVE, "unknown JS error => FAIL_SAVE");
	EQ(cdbn_ttl_classify(TTL_PUB_JS_ERR, 0), TTL_FAIL_SAVE, "JS error with no code => FAIL_SAVE");
	EQ(cdbn_ttl_classify(TTL_PUB_CONN_DOWN, 10071), TTL_FAIL_SAVE, "conn down ignores jerr => FAIL_SAVE");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
