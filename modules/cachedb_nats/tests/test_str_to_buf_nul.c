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
 * Behavioural test of nats_str_to_buf (lib/nats/nats_str.h) -- the REAL
 * inline, no carried copy -- the shared str->C-string chokepoint for the
 * generic cachedb_nats write paths (nats_cache_set, w_nats_kv_put,
 * nats_cache_map_set).
 *
 * Locked-in behaviour:
 *   - a clean value copies verbatim, NUL-terminated;
 *   - an embedded NUL is REJECTED (memchr guard): the buffer feeds
 *     C-string NATS key APIs, which would silently truncate -- so
 *     set("a\0b") would store "a" (silent data loss);
 *   - a negative length is rejected (the (size_t) cast would otherwise
 *     turn it into a huge bound and memcpy past the source);
 *   - NULL/empty input yields "" -- but ONLY when the buffer can hold
 *     it: buf_size == 0 must be rejected, NOT written through.  (The
 *     original empty-input path wrote buf[0] before any capacity check,
 *     a one-byte overflow on a zero-size buffer; ASan enforces the
 *     no-write contract here.)
 *   - boundary: buf_size == 1 still yields "" for empty input, and
 *     rejects any non-empty value.
 *
 * Build: pattern rule (ASan) + CORE_DEFS; includes the production header.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../lib/nats/nats_str.h"

/* ── core seams for dprint (LM_ERR in the inline) ──────────────── */
static int test_log_level = 0;
int *log_level = &test_log_level;
char *log_prefix = "";
int log_facility = 0;
char ctime_buf[256];
int dp_my_pid(void) { return 0; }
void dprint(int level, int facility, const char *module, const char *func,
	char *stderr_fmt, char *syslog_fmt, char *format, ...)
{ (void)level; (void)facility; (void)module; (void)func;
  (void)stderr_fmt; (void)syslog_fmt; (void)format; }

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

static str mkstr(const char *s, int len)
{
	str r; r.s = (char *)s; r.len = len; return r;
}

int main(void)
{
	char buf[64];
	str v;

	v = mkstr("abc", 3);
	ASSERT(nats_str_to_buf(&v, buf, sizeof(buf)) == 0 && strcmp(buf, "abc") == 0,
		"a clean value is accepted verbatim");

	/* "a\0b" -- 3 bytes with an embedded NUL. */
	v = mkstr("a\0b", 3);
	ASSERT(nats_str_to_buf(&v, buf, sizeof(buf)) == -1,
		"a value with an embedded NUL is REJECTED (not silently truncated)");

	ASSERT(nats_str_to_buf(NULL, buf, sizeof(buf)) == 0 && buf[0] == '\0',
		"a NULL str yields an empty string");
	v = mkstr(NULL, 0);
	ASSERT(nats_str_to_buf(&v, buf, sizeof(buf)) == 0 && buf[0] == '\0',
		"a NULL/empty value yields an empty string");
	v = mkstr("x", -1);
	ASSERT(nats_str_to_buf(&v, buf, sizeof(buf)) == -1,
		"a negative length is rejected");

	/* exact-fit boundary: len == buf_size - 1 accepted, len == buf_size
	 * rejected */
	{
		char small[4];
		v = mkstr("abc", 3);
		ASSERT(nats_str_to_buf(&v, small, sizeof(small)) == 0 &&
			strcmp(small, "abc") == 0, "len == buf_size-1 fits exactly");
		v = mkstr("abcd", 4);
		ASSERT(nats_str_to_buf(&v, small, sizeof(small)) == -1,
			"len == buf_size overflows and is rejected");
	}

	/* buf_size == 0: MUST be rejected without writing a byte.  The
	 * destination is the very end of a heap block, so any write is a
	 * heap-buffer-overflow under ASan. */
	{
		char *blk = malloc(8);
		ASSERT(blk != NULL, "heap probe allocated");
		ASSERT(nats_str_to_buf(NULL, blk + 8, 0) == -1,
			"buf_size=0 with NULL input rejected, nothing written");
		v = mkstr("", 0);
		ASSERT(nats_str_to_buf(&v, blk + 8, 0) == -1,
			"buf_size=0 with empty input rejected, nothing written");
		v = mkstr("abc", 3);
		ASSERT(nats_str_to_buf(&v, blk + 8, 0) == -1,
			"buf_size=0 with a real value rejected, nothing written");
		free(blk);
	}

	/* buf_size == 1: "" still representable, anything longer rejected. */
	{
		char one[1];
		v = mkstr(NULL, 0);
		ASSERT(nats_str_to_buf(&v, one, 1) == 0 && one[0] == '\0',
			"buf_size=1 holds the empty result");
		v = mkstr("a", 1);
		ASSERT(nats_str_to_buf(&v, one, 1) == -1,
			"buf_size=1 rejects a 1-byte value (no room for the NUL)");
	}

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
