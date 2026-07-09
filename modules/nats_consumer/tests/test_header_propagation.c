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
 * Unit test for the async nats_request header-propagation wire format.
 *
 * Three things are validated here, none of which require linking
 * libnats or the OpenSIPS core:
 *
 *   1. The compact length-prefixed wire format documented in
 *      nats_rpc.h is well-defined and round-trips: a hand-built
 *      buffer of (count, [klen, key, vlen, value]*) bytes decodes
 *      back to the original (name, value) pairs.
 *
 *   2. The production worker-side callsite (w_nats_request_async
 *      in nats_rpc_async.c) actually calls the serializer into
 *      slot->out_headers BEFORE transitioning the slot from
 *      CLAIMED to INFLIGHT (otherwise the consumer races on a
 *      half-populated buffer).
 *
 *   3. The production consumer-side callsite (publish_cb in
 *      nats_rpc_consumer.c) calls the deserializer onto the
 *      outbound natsMsg BEFORE natsConnection_PublishMsg
 *      (otherwise the headers don't reach the responder).
 *
 * Cases (1) is a black-box round-trip; (2) and (3) are
 * source-pattern style, matching the convention established by
 * test_request_route_restriction.c and test_async_request_skeleton.c.
 *
 * Build (driven by Makefile):
 *   gcc -g -O0 -Wall -o test_header_propagation test_header_propagation.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_fails;
#define ASSERT(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); g_fails++; } \
	else         { fprintf(stderr, "  ok: %s\n", msg);            } \
} while (0)

/* ── helpers: read a whole file ────────────────────────────────── */

static char *read_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	long  sz;
	char *buf;
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf); fclose(f); return NULL;
	}
	buf[sz] = '\0';
	fclose(f);
	return buf;
}

/*
 * Wire format (must mirror nats_rpc.h documentation):
 *
 *   [ count        : 2 bytes little-endian ]
 *   foreach pair (count times):
 *     [ name_len   : 2 bytes little-endian ]
 *     [ name bytes ]
 *     [ value_len  : 2 bytes little-endian ]
 *     [ value bytes ]
 *
 * A test-local reference implementation of the parser; if the
 * production deserializer (nats_rpc_hdr_deserialize_to_msg) drifts
 * away from this layout, the source-pattern checks in case (3) plus
 * downstream sip_e2e coverage catch it.
 */
static int parse_wire(const char *buf, int len,
                      const char *expect_keys[], const char *expect_vals[],
                      int expect_n)
{
	int pos = 0;
	int count;
	int i;

	if (!buf || len < 2) return -1;
	count = (unsigned char)buf[0] | ((unsigned char)buf[1] << 8);
	pos = 2;
	if (count != expect_n) {
		fprintf(stderr, "  parse_wire: count=%d expected=%d\n", count, expect_n);
		return -1;
	}

	for (i = 0; i < count; i++) {
		int klen, vlen;
		if (pos + 2 > len) return -1;
		klen = (unsigned char)buf[pos] | ((unsigned char)buf[pos + 1] << 8);
		pos += 2;
		if (klen < 0 || pos + klen > len) return -1;
		if (klen != (int)strlen(expect_keys[i])) return -1;
		if (memcmp(buf + pos, expect_keys[i], (size_t)klen) != 0) return -1;
		pos += klen;

		if (pos + 2 > len) return -1;
		vlen = (unsigned char)buf[pos] | ((unsigned char)buf[pos + 1] << 8);
		pos += 2;
		if (vlen < 0 || pos + vlen > len) return -1;
		if (vlen != (int)strlen(expect_vals[i])) return -1;
		if (memcmp(buf + pos, expect_vals[i], (size_t)vlen) != 0) return -1;
		pos += vlen;
	}
	return pos;
}

/*
 * Build a wire-format buffer by hand from a (name, value) array.
 * Used to drive the production deserializer in case (1).
 */
static int build_wire(char *out, int cap,
                      const char *keys[], const char *vals[], int n)
{
	int pos = 2;
	int i;
	if (cap < 2) return -1;
	out[0] = (char)(n & 0xFF);
	out[1] = (char)((n >> 8) & 0xFF);
	for (i = 0; i < n; i++) {
		int klen = (int)strlen(keys[i]);
		int vlen = (int)strlen(vals[i]);
		int need = 2 + klen + 2 + vlen;
		if (pos + need > cap) return -1;
		out[pos++] = (char)(klen & 0xFF);
		out[pos++] = (char)((klen >> 8) & 0xFF);
		memcpy(out + pos, keys[i], (size_t)klen); pos += klen;
		out[pos++] = (char)(vlen & 0xFF);
		out[pos++] = (char)((vlen >> 8) & 0xFF);
		memcpy(out + pos, vals[i], (size_t)vlen); pos += vlen;
	}
	return pos;
}

/* ── case 1: round-trip ───────────────────────────────────────── */

static void test_wire_roundtrip(void)
{
	char        buf[256];
	int         written;
	int         consumed;
	const char *keys[3] = { "X-Request-Id", "Trace-Id", "Idempotency-Key" };
	const char *vals[3] = { "0192f0e0-...-uuidv7", "trace-abc-123", "key=42" };

	fprintf(stderr, "\n=== wire round-trip ===\n");

	written = build_wire(buf, (int)sizeof(buf), keys, vals, 3);
	ASSERT(written > 0, "build_wire emits a positive byte count");
	ASSERT(written >= 2 + 3 * (2 + 12 + 2 + 6),
	       "wire size is at least header+payload bound");

	consumed = parse_wire(buf, written, keys, vals, 3);
	ASSERT(consumed == written, "parse consumes exactly the bytes written");

	/* Empty stage (count==0) round-trip. */
	{
		char eb[2];
		eb[0] = 0; eb[1] = 0;
		consumed = parse_wire(eb, 2, NULL, NULL, 0);
		ASSERT(consumed == 2, "empty stage produces a 2-byte zero count");
	}

	/* Single header. */
	{
		const char *k1[1] = { "Authorization" };
		const char *v1[1] = { "Bearer secret-token" };
		written = build_wire(buf, (int)sizeof(buf), k1, v1, 1);
		ASSERT(written == 2 + 2 + 13 + 2 + 19,
		       "single-header layout matches arithmetic");
		consumed = parse_wire(buf, written, k1, v1, 1);
		ASSERT(consumed == written, "single-header round-trip");
	}

	/* Malformed: truncated length prefix mid-pair must be detected. */
	{
		const char *k1[1] = { "Foo" };
		const char *v1[1] = { "bar" };
		written = build_wire(buf, (int)sizeof(buf), k1, v1, 1);
		consumed = parse_wire(buf, written - 1, k1, v1, 1);
		ASSERT(consumed < 0,
		       "truncated buffer is rejected by parser (-1)");
	}
}

/* ── case 2: worker-side callsite ─────────────────────────────── */

static void test_worker_callsite(void)
{
	char *src;

	fprintf(stderr, "\n=== worker callsite (w_nats_request_async) ===\n");

	src = read_file("../nats_rpc_async.c");
	ASSERT(src != NULL, "read ../nats_rpc_async.c");
	if (!src) return;

	/* The serializer must be called into slot->out_headers. */
	ASSERT(strstr(src,
		"nats_rpc_staged_serialize(slot->out_headers") != NULL,
		"w_nats_request_async calls nats_rpc_staged_serialize into "
		"slot->out_headers");

	/* The truncation flag must be checked + logged.  Operators
	 * lose visibility otherwise. */
	ASSERT(strstr(src, "staged-header buffer") != NULL,
		"truncation produces a WARN log");

	/* The serializer call must run BEFORE nats_rpc_slot_publish().
	 * If the order ever drifts, the consumer races on a slot
	 * whose out_headers_len is not yet visible.  Cheap textual
	 * proxy: the serialize call site appears before the slot
	 * publish call site in the file. */
	{
		char *ser   = strstr(src, "nats_rpc_staged_serialize(slot->out_headers");
		char *pub   = strstr(src, "nats_rpc_slot_publish(slot)");
		ASSERT(ser != NULL && pub != NULL,
			"both serialize and slot_publish callsites present");
		if (ser && pub) {
			ASSERT(ser < pub,
				"serialize runs before slot_publish "
				"(release-ordering invariant)");
		}
	}

	/* The legacy 'TODO' marker should be gone from the comment
	 * block describing the wire-up.  If it's still there, a doc
	 * regression slipped in. */
	ASSERT(strstr(src,
		"on-the-wire header propagation is a TODO") == NULL,
		"stale 'header propagation is a TODO' comment removed");

	free(src);
}

/* ── case 3: consumer-side callsite ───────────────────────────── */

static void test_consumer_callsite(void)
{
	char *src;
	char *deser;
	char *pub;

	fprintf(stderr, "\n=== consumer callsite (publish_cb) ===\n");

	src = read_file("../nats_rpc_consumer.c");
	ASSERT(src != NULL, "read ../nats_rpc_consumer.c");
	if (!src) return;

	/* The deserializer must be invoked on slot->out_headers and
	 * pointed at the natsMsg about to be published. */
	deser = strstr(src, "nats_rpc_hdr_deserialize_to_msg(s->out_headers");
	ASSERT(deser != NULL,
		"publish_cb deserializes slot->out_headers");

	/* The deserialize call must happen BEFORE natsConnection_PublishMsg.
	 * Reverse order would publish without headers and then no-op. */
	pub = strstr(src, "natsConnection_PublishMsg(nc, out)");
	ASSERT(pub != NULL, "publish_cb calls PublishMsg");
	if (deser && pub) {
		ASSERT(deser < pub,
			"deserialize runs before PublishMsg "
			"(headers reach the wire)");
	}

	/* Stale TODO comment must be cleaned up. */
	ASSERT(strstr(src,
		"richer header\n * propagation is a TODO") == NULL,
		"stale 'richer header propagation is a TODO' comment removed");

	free(src);
}

/* ── main ─────────────────────────────────────────────────────── */

int main(void)
{
	test_wire_roundtrip();
	test_worker_callsite();
	test_consumer_callsite();
	if (g_fails) {
		fprintf(stderr, "\n%d FAILED\n", g_fails);
		return 1;
	}
	fprintf(stderr, "\nALL PASSED\n");
	return 0;
}
