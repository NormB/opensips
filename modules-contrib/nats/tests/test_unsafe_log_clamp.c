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
 * Regression test: the cnats-thread loggers in nats_pool.c build a
 * message with snprintf() into a fixed stack buffer and then hand the
 * snprintf RETURN VALUE to nats_pool_unsafe_log(buf, len), which does
 * write(STDERR, buf, len).  snprintf returns the length it WOULD have
 * written, not the truncated length -- so a broker-controlled string
 * (a JetStream ErrText, or a long reconnect URL) longer than the buffer
 * makes len > sizeof(buf), and write() then reads past the stack buffer,
 * leaking adjacent stack memory to the log.
 *
 * The fix clamps the length to the buffer before logging:
 *   if (len >= (int)sizeof(buf)) len = sizeof(buf) - 1;
 *
 * This test models the build-and-log step and asserts the length handed
 * to the writer never exceeds the buffer.  It is built under ASan (see
 * Makefile), and on the buggy path it actually performs the over-long
 * read the writer would do, so ASan trips on the stack-buffer over-read.
 *
 *   -DSIMULATE_PREFIX_BUG -> no clamp: len exceeds the buffer and the
 *                            modeled write reads out of bounds -> FAIL
 *                            (and ASan stack-buffer-overflow).
 *   (default)             -> clamped: len <= sizeof(buf)-1 -> ALL PASS.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -o test_unsafe_log_clamp \
 *       test_unsafe_log_clamp.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;
#define CHECK(cond, label) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (label)); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", (label)); } \
} while (0)

/* Sink the modeled writer copies into -- a separate heap buffer large
 * enough for a correct (clamped) length.  An unclamped length makes the
 * source read (memcpy from `buf`) run off the 256-byte stack buffer. */
static char g_sink[4096];

/* Models nats_pool.c's "snprintf into buf, then log len bytes" step for a
 * broker-controlled %s argument, returning the length passed to the
 * writer. */
static int build_and_log(const char *broker_text)
{
	char buf[256];
	int len = snprintf(buf, sizeof(buf),
		"NATS JetStream async publish error: %s\n", broker_text);

#ifndef SIMULATE_PREFIX_BUG
	if (len >= (int)sizeof(buf))
		len = (int)sizeof(buf) - 1;
#endif

	if (len > 0) {
		/* Model nats_pool_unsafe_log(buf, len): it reads `len` bytes from
		 * `buf`.  With the clamp this stays in-bounds; without it, this
		 * reads past buf[256] (ASan stack-buffer-overflow). */
		memcpy(g_sink, buf, (size_t)len);
	}
	return len;
}

int main(void)
{
	int len;
	char longtext[1024];

	/* Short input: well within the buffer either way. */
	len = build_and_log("stream not found");
	CHECK(len > 0 && len < 256, "short error logs a sane, in-bounds length");

	/* Broker-controlled over-long input (300+ bytes). */
	memset(longtext, 'A', sizeof(longtext) - 1);
	longtext[sizeof(longtext) - 1] = '\0';
	len = build_and_log(longtext);

	/* The contract: the length handed to write() never exceeds the
	 * 256-byte buffer.  Under the pre-fix code len is ~1035 (the full
	 * formatted length) and the modeled write over-reads the stack. */
	CHECK(len <= 255,
		"over-long broker text is clamped to the buffer (no stack over-read)");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
