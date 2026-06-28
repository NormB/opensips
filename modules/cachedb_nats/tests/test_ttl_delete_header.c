/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P5 / TTL-SOLUTION-SPEC.md §2.5: delete / purge expressed as a publish.
 *
 * A KV delete is a publish carrying the operation header — verified against
 * nats.go jetstream/kv.go: header name "KV-Operation", value "DEL" (tombstone,
 * keep history) or "PURGE" (drop history, rolled up).  Byte-exactness matters:
 * a wrong case / spelling is silently ignored by the server (the publish lands
 * as a normal value, NOT a delete), so the contact would never be removed.
 *
 *   gcc -DDELHDR_CURRENT ... -> wrong op spelling ("DELETE"/"delete") => RED.
 *   gcc ...                 -> byte-exact "DEL"/"PURGE" => GREEN.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_delete_header test_ttl_delete_header.c
 */
#include <stdio.h>
#include <string.h>

#define NATS_KV_OP_HDR   "KV-Operation"
#ifdef DELHDR_CURRENT
#define NATS_KV_OP_DEL   "DELETE"   /* wrong */
#define NATS_KV_OP_PURGE "purge"    /* wrong */
#else
#define NATS_KV_OP_DEL   "DEL"
#define NATS_KV_OP_PURGE "PURGE"
#endif

/* ─── carried copy of the production helper (cachedb_nats_ttl.c) ─── */
static const char *_ttl_delete_op(int purge)
{
	return purge ? NATS_KV_OP_PURGE : NATS_KV_OP_DEL;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef DELHDR_CURRENT
	printf("== carried copy: DELHDR_CURRENT (wrong op spelling) ==\n");
#else
	printf("== carried copy: FIXED byte-exact headers ==\n");
#endif

	printf("[§2.5] KV-Operation header name + values are byte-exact:\n");
	CHECK(strcmp(NATS_KV_OP_HDR, "KV-Operation") == 0, "header name == 'KV-Operation'");
	CHECK(strcmp(_ttl_delete_op(0), "DEL") == 0, "delete op == 'DEL' (tombstone)");
	CHECK(strcmp(_ttl_delete_op(1), "PURGE") == 0, "purge op == 'PURGE' (drop history)");

	printf("[§2.5] case-exact (a wrong case is silently ignored by the server):\n");
	CHECK(strcmp(_ttl_delete_op(0), "del") != 0, "not lowercase 'del'");
	CHECK(strcmp(_ttl_delete_op(0), "DELETE") != 0, "not 'DELETE'");
	CHECK(strcmp(_ttl_delete_op(1), "purge") != 0, "not lowercase 'purge'");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
