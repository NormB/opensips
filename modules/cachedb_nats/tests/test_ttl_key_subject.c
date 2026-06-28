/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P8 / TTL-SOLUTION-SPEC.md §2.1 [TREV-5]: one key→subject mapping, three
 * consumers.  Once we hand-build the JetStream subject for a raw publish, we own
 * the key→subject mapping — and it MUST be byte-identical to what the read path
 * (kvStore_Get) and the watcher derive, or a raw-published value lands on a
 * subject the reader never queries (silent split-brain: REGISTER "succeeds",
 * lookup returns nothing).
 *
 * cnats maps KV key K in bucket B to subject "$KV.<B>.<K>".  K is the already
 * P1-encoded, KV-safe row key (no NATS-reserved bytes), so the subject is a
 * pure concatenation; the escaping correctness is the P1 encoder's job (proven
 * in test_kv_key_validate.c).  nats_kv_key_to_subject() centralizes it.
 *
 *   gcc -DSUBJ_CURRENT ... -> wrong prefix/separator => RED (subject mismatch).
 *   gcc ...               -> the byte-exact "$KV.<bucket>.<key>" => GREEN.
 *
 * Rule 6: the AUTHORITATIVE proof is the round-trip e2e — raw-publish then
 * kvStore_Get the same key and confirm a hit — vs production.
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_ttl_key_subject test_ttl_key_subject.c
 */
#include <stdio.h>
#include <string.h>

/* ─── carried copy of the production helper (cachedb_nats_ttl.c) ─── */
static int nats_kv_key_to_subject(const char *bucket, const char *key,
	char *buf, int buflen)
{
#ifdef SUBJ_CURRENT
	int n = snprintf(buf, buflen, "KV_%s.%s", bucket, key);  /* wrong prefix */
#else
	int n = snprintf(buf, buflen, "$KV.%s.%s", bucket, key);
#endif
	if (n < 0 || n >= buflen)
		return -1;
	return n;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

static const char *subj(const char *bucket, const char *key)
{
	static char buf[512];
	return (nats_kv_key_to_subject(bucket, key, buf, sizeof buf) > 0) ? buf : "<err>";
}

int main(void)
{
#ifdef SUBJ_CURRENT
	printf("== carried copy: SUBJ_CURRENT (wrong subject prefix) ==\n");
#else
	printf("== carried copy: FIXED byte-exact subject ==\n");
#endif

	printf("[TREV-5] subject == \"$KV.<bucket>.<key>\" byte-exact:\n");
	CHECK(strcmp(subj("location", "usrloc.alice=40d"), "$KV.location.usrloc.alice=40d") == 0,
	      "location / usrloc.alice=40d");
	CHECK(strcmp(subj("opensips", "k1"), "$KV.opensips.k1") == 0, "opensips / k1");
	CHECK(strncmp(subj("location", "x"), "$KV.", 4) == 0, "always begins '$KV.'");

	printf("[TREV-5] already-P1-encoded keys (=HH escapes) pass through verbatim:\n");
	CHECK(strcmp(subj("location", "usrloc.a=5Cb=40d"), "$KV.location.usrloc.a=5Cb=40d") == 0,
	      "escaped key (=5C backslash, =40 at) verbatim in subject");
	CHECK(strcmp(subj("location", "usrloc.alice.example.com"), "$KV.location.usrloc.alice.example.com") == 0,
	      "dotted (multi-token) key verbatim");

	printf("[TREV-5] buffer-too-small fails cleanly (no overflow):\n");
	{ char small[8]; CHECK(nats_kv_key_to_subject("location", "averylongkey", small, sizeof small) == -1,
	      "too-small buffer => -1 (not truncated/overflowed)"); }
	{ char tight[20]; int n = nats_kv_key_to_subject("b", "k", tight, sizeof tight);
	  CHECK(n == 7 && strcmp(tight, "$KV.b.k") == 0, "reports the written length (7 = strlen '$KV.b.k')"); }

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails==1?"":"s");
	return fails ? 1 : 0;
}
