/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P11b / IMPLEMENTATION-PLAN P11b [REV-25], SPEC §5.3 [REV-7]: migration policy
 * for a PRE-EXISTING bucket whose backing stream already carries a non-zero
 * MaxAge.
 *
 * The P7 guard `_kv_ttl_guard` (test_kv_ttl_zero_guard.c) refuses a non-zero
 * `kv_ttl` MODPARAM — it stops THIS module from CREATING a MaxAge bucket.  It
 * does NOT cover the migration case: on first deploy against an EXISTING bucket
 * created by an older deployment (or another tool), the bound stream may already
 * have MaxAge != 0.  A non-zero stream MaxAge expires EVERY key after that age,
 * including PERMANENT contacts (expires==0, row_exp==0) — silent registration
 * data loss.  The module binds to existing buckets (nats_pool.c js_KeyValue),
 * so without a check this is silent.
 *
 * `_kv_legacy_bucket_maxage_warn(maxage_ns)` is the policy decision: a bound
 * bucket with a non-zero MaxAge warrants a loud startup WARN naming the
 * permanent-contact-expiry risk + remediation (recreate the bucket MaxAge=0 /
 * kv_ttl=0).  This is the "documented policy, not a silent permanent-contact
 * expiry" the GATE requires; it WARNs rather than refusing start so a generic
 * (non-usrloc) cachedb_nats user who intends a TTL bucket is not broken.
 *
 *   gcc -DLEGACY_BUCKET_CURRENT ... -> no policy (silent accept) => RED.
 *   gcc ...                        -> the FIXED policy           => GREEN.
 *
 * Rule 6: the authoritative proof is the Tier-2
 * run_legacy_maxage_bucket_warn_e2e.sh (plant a MaxAge bucket, boot, assert WARN).
 *
 * Build: gcc -g -O0 -fsanitize=address -Wall -o test_kv_ttl_legacy_bucket test_kv_ttl_legacy_bucket.c
 */
#include <stdio.h>
#include <stdint.h>

#define NATS_NS_PER_S  1000000000LL

/* ─── carried copy of the production policy (cachedb_nats_ttl.c) ──────
 * @maxage_ns: the bound bucket's backing-stream MaxAge in nanoseconds.
 * @return    1 => warn (non-zero MaxAge will expire permanent contacts),
 *            0 => clean (MaxAge==0, the only safe config for a usrloc store). */
static int _kv_legacy_bucket_maxage_warn(int64_t maxage_ns)
{
#ifdef LEGACY_BUCKET_CURRENT
	(void)maxage_ns; return 0;   /* today: bound silently, no policy */
#else
	return maxage_ns != 0 ? 1 : 0;
#endif
}

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } \
	else printf("  ok:   %s\n", msg); } while (0)

int main(void)
{
#ifdef LEGACY_BUCKET_CURRENT
	printf("== carried copy: LEGACY_BUCKET_CURRENT (silent accept) ==\n");
#else
	printf("== carried copy: FIXED legacy-MaxAge policy ==\n");
#endif

	printf("[REV-7/REV-25] MaxAge==0 is the ONLY safe config -> no warn:\n");
	CHECK(_kv_legacy_bucket_maxage_warn(0) == 0, "MaxAge=0 => clean (no warn)");

	printf("[REV-7/REV-25] any non-zero MaxAge would expire permanent contacts -> WARN:\n");
	CHECK(_kv_legacy_bucket_maxage_warn(30LL * NATS_NS_PER_S) == 1, "MaxAge=30s => WARN");
	CHECK(_kv_legacy_bucket_maxage_warn(1) == 1, "MaxAge=1ns (sub-second) => WARN");
	CHECK(_kv_legacy_bucket_maxage_warn(86400LL * NATS_NS_PER_S) == 1, "MaxAge=1d => WARN");
	CHECK(_kv_legacy_bucket_maxage_warn(INT64_MAX) == 1, "MaxAge=INT64_MAX => WARN");
	/* defensive: a negative (corrupt) MaxAge is still non-zero => warn, never silent */
	CHECK(_kv_legacy_bucket_maxage_warn(-1) == 1, "MaxAge=-1 (corrupt) => WARN (never silent)");

	printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED",
		fails, fails == 1 ? "" : "s");
	return fails ? 1 : 0;
}
