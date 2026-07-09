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
 * Regression test for TODO #64: the four NATS subject/key/name validators
 * (publish subject, subscribe filter, stream/consumer name, KV key) were
 * consolidated into one lib/nats nats_validate(s, len, mode) with mode flags.
 * This locks in the per-mode rules so the consolidation can't drift:
 *
 *   PUBLISH_SUBJECT  concrete: no wildcards, no leading/trailing/empty tokens
 *   FILTER_SUBJECT   dots + wildcards ('*','>') allowed
 *   STREAM_NAME      single token: no '.', '*', '>', '/', '\'
 *   KV_KEY           dots allowed; ':' reserved; no wildcards
 * all reject NULL/empty/NUL/control/whitespace.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -Wall -I.. -o test_validate_modes \
 *       test_validate_modes.c ../nats_validate.o
 */

#include <stdio.h>
#include <string.h>

typedef enum {
	NATS_VALIDATE_PUBLISH_SUBJECT = 0,
	NATS_VALIDATE_FILTER_SUBJECT,
	NATS_VALIDATE_STREAM_NAME,
	NATS_VALIDATE_KV_KEY,
} nats_validate_mode_t;

int nats_validate(const char *s, int len, nats_validate_mode_t mode);

static int g_fails;
#define V(want, mode, s, label) do { \
	int got = nats_validate((s), (s) ? (int)strlen(s) : 0, (mode)); \
	if (got != (want)) { \
		fprintf(stderr, "FAIL: %s want=%d got=%d\n", (label), (want), got); \
		g_fails++; \
	} else { \
		fprintf(stderr, "  ok: %s -> %d\n", (label), got); \
	} \
} while (0)

int main(void)
{
	/* common rejections (every mode) */
	nats_validate_mode_t modes[] = { NATS_VALIDATE_PUBLISH_SUBJECT,
		NATS_VALIDATE_FILTER_SUBJECT, NATS_VALIDATE_STREAM_NAME,
		NATS_VALIDATE_KV_KEY };
	int m;
	for (m = 0; m < 4; m++) {
		V(-1, modes[m], "", "empty rejected (all modes)");
		V(-1, modes[m], "a b", "whitespace rejected (all modes)");
		V(-1, modes[m], "a\x01""b", "control rejected (all modes)");
	}

	/* PUBLISH_SUBJECT */
	V(0,  NATS_VALIDATE_PUBLISH_SUBJECT, "call.123.evt", "pub: dotted ok");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, "call.*",       "pub: wildcard rejected");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, "a..b",         "pub: empty token rejected");
	V(-1, NATS_VALIDATE_PUBLISH_SUBJECT, ".a",           "pub: leading dot rejected");
	V(0,  NATS_VALIDATE_PUBLISH_SUBJECT, "a:b",          "pub: ':' allowed");

	/* FILTER_SUBJECT — wildcards + dots allowed */
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "usrloc.>",      "filter: tail wildcard ok");
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "a.*.c",         "filter: token wildcard ok");
	V(0,  NATS_VALIDATE_FILTER_SUBJECT, "a..b",          "filter: tolerant of dots");
	V(-1, NATS_VALIDATE_FILTER_SUBJECT, "a b",           "filter: whitespace rejected");

	/* STREAM_NAME — single token */
	V(0,  NATS_VALIDATE_STREAM_NAME, "MY-STREAM_1", "name: alnum/-/_ ok");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a.b",         "name: dot rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a*",          "name: wildcard rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a/b",         "name: slash rejected");
	V(-1, NATS_VALIDATE_STREAM_NAME, "a\\b",        "name: backslash rejected");

	/* KV_KEY — dots ok, ':' reserved, no wildcards */
	V(0,  NATS_VALIDATE_KV_KEY, "user.1@host",  "kv: dots/@ ok");
	V(0,  NATS_VALIDATE_KV_KEY, "a/b=c",        "kv: slash/equals ok");
	V(-1, NATS_VALIDATE_KV_KEY, "a:b",          "kv: ':' rejected (map sep)");
	V(-1, NATS_VALIDATE_KV_KEY, "a*",           "kv: wildcard rejected");
	V(-1, NATS_VALIDATE_KV_KEY, "a>",           "kv: '>' rejected");

	fprintf(stderr, "\n=== %s (fails=%d) ===\n",
		g_fails == 0 ? "ALL PASS" : "FAILURES", g_fails);
	return g_fails == 0 ? 0 : 1;
}
